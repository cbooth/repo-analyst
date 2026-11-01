import {
  WorkflowEntrypoint,
  type WorkflowEvent,
  type WorkflowStep,
} from "cloudflare:workers";

import type {
  Env,
  AnalysisParams,
  RepoListing,
  RepositorySnapshot,
  TriageResult,
} from "./env";
import { applyVerdicts, buildReport, checkEvidence } from "./analysis";
import { EventWriter } from "./events";
import {
  LLM_CATEGORIES,
  TRUSTED_CATEGORIES,
  type Category,
  type Finding,
  type Synthesis,
  type Verdict,
} from "./findings";
import { pickForVerification } from "./verify";

interface Outcome {
  category: Category;
  findings: Finding[];
  failed: boolean;
}

export class RepoAnalysisWorkflow extends WorkflowEntrypoint<
  Env,
  AnalysisParams & { runId: string }
> {
  async run(
    event: WorkflowEvent<AnalysisParams & { runId: string }>,
    step: WorkflowStep,
  ) {
    const { runId, owner, repo, ref, installationId } =
      event.payload;

    const system = new EventWriter(this.env.DB, runId, "system");

    // Heavy work runs in Durable Objects; see AgentSession.
    const session = (task: string) =>
      this.env.AGENT_SESSION.get(
        this.env.AGENT_SESSION.idFromName(`${runId}:${task}`),
      );

    const update = async (
      status: string,
      extra: {
        commitSha?: string;
        report?: unknown;
        error?: string;
      } = {},
    ) => {
      const now = new Date().toISOString();

      await this.env.DB.prepare(`
        UPDATE analysis_runs
        SET status = ?,
            commit_sha = COALESCE(?, commit_sha),
            report_json = COALESCE(?, report_json),
            error_message = ?,
            updated_at = ?
        WHERE id = ?
      `).bind(
        status,
        extra.commitSha ?? null,
        extra.report === undefined
          ? null
          : JSON.stringify(extra.report),
        extra.error ?? null,
        now,
        runId,
      ).run();
    };

    try {
      await step.do("mark running", async () => {
        await update("running");
        await system.emit(
          "status",
          `Fetching ${owner}/${repo}${ref ? ` @ ${ref}` : ""} from GitHub.`,
        );
      });

      const retries = {
        limit: 3,
        delay: "2 seconds",
        backoff: "exponential",
      } as const;

      // RPC result types don't model plain-data returns, hence the casts.
      const listing = await step.do(
        "list repository",
        { retries },
        () =>
          session("list").listRepository({
            owner,
            repo,
            ref,
            installationId,
          }) as unknown as Promise<RepoListing>,
      );

      await step.do("record pinned commit", async () => {
        await update("analyzing", { commitSha: listing.commitSha });
        await system.emit(
          "status",
          `Pinned to ${listing.commitSha.slice(0, 12)}: ` +
            `${listing.entries.length} candidate files ` +
            `(${listing.excluded} excluded). Triaging.`,
        );
      });

      const triage = await step.do(
        "triage files",
        { retries: { ...retries, limit: 1 } },
        () =>
          session("triage").triage({
            runId,
            listing,
          }) as unknown as Promise<TriageResult>,
      );

      const snapshot = await step.do(
        "fetch selected files",
        { retries },
        () =>
          session("fetch").fetchSnapshot({
            listing,
            triage,
            installationId,
          }) as unknown as Promise<RepositorySnapshot>,
      );

      await step.do("announce agents", async () => {
        await system.emit(
          "status",
          `Read ${snapshot.files.length} files. Starting agents.`,
        );
      });

      // Every agent is a separate durable step running concurrently. A
      // failing agent degrades the report instead of losing the others'.
      const guarded = (
        category: Category,
        retryLimit: number,
        work: () => Promise<Finding[]>,
      ) =>
        step
          .do(
            `agent ${category}`,
            {
              retries: {
                limit: retryLimit,
                delay: "2 seconds",
                backoff: "exponential",
              },
            },
            work,
          )
          .then(
            (findings): Outcome => ({ category, findings, failed: false }),
            async (error: unknown): Promise<Outcome> => {
              await new EventWriter(this.env.DB, runId, category).emit(
                "error",
                `Agent failed: ${
                  error instanceof Error
                    ? error.message.slice(0, 300)
                    : "unknown error"
                }`,
              );
              return { category, findings: [], failed: true };
            },
          );

      const outcomes = await Promise.all([
        ...LLM_CATEGORIES.map((category) =>
          guarded(
            category,
            2,
            () =>
              session(category).analyze({
                runId,
                category,
                snapshot,
              }) as unknown as Promise<Finding[]>,
          )
        ),
        guarded(
          "secrets",
          1,
          () =>
            session("secrets").secrets({
              runId,
              snapshot,
              sensitive: listing.sensitive,
            }) as unknown as Promise<Finding[]>,
        ),
        guarded(
          "dependencies",
          2,
          () =>
            session("dependencies").dependencies({
              runId,
              listing,
              installationId,
            }) as unknown as Promise<Finding[]>,
        ),
      ]);

      const incomplete = outcomes
        .filter((o) => o.failed)
        .map((o) => o.category);

      if (LLM_CATEGORIES.every((c) => incomplete.includes(c))) {
        throw new Error("All analysis agents failed");
      }

      const candidates = await step.do(
        "check evidence",
        async () =>
          checkEvidence(snapshot, outcomes.map((o) => o.findings)),
      );

      // Scanner output is deterministic; only model findings are doubted.
      const trusted = candidates.filter((f) =>
        TRUSTED_CATEGORIES.includes(f.category)
      );
      const modelled = candidates.filter((f) =>
        !TRUSTED_CATEGORIES.includes(f.category)
      );
      const toVerify = pickForVerification(modelled);

      const verdicts = toVerify.length
        ? await step
          .do(
            "verify findings",
            { retries: { ...retries, limit: 1 } },
            () =>
              session("verify").verify({
                runId,
                snapshot,
                findings: toVerify,
              }) as unknown as Promise<Verdict[]>,
          )
          .catch(async (error: unknown) => {
            await new EventWriter(this.env.DB, runId, "verifier").emit(
              "error",
              `Verifier failed: ${
                error instanceof Error
                  ? error.message.slice(0, 300)
                  : "unknown error"
              }. Findings are reported unverified.`,
            );
            return null;
          })
        : [];

      const report = await step.do(
        "build report",
        async () => {
          const { kept, dismissed } = verdicts
            ? applyVerdicts(toVerify, verdicts)
            : { kept: toVerify, dismissed: [] };
          const checked = new Set(toVerify);
          const unchecked = modelled.filter((f) => !checked.has(f));

          return buildReport(
            snapshot,
            [kept, unchecked, trusted],
            incomplete,
            { dismissed, verified: verdicts !== null },
          );
        },
      );

      const synthesis = await step
        .do(
          "synthesize summary",
          { retries: { ...retries, limit: 1 } },
          () =>
            session("synthesis").synthesize({
              runId,
              repoName: `${owner}/${repo}`,
              notes: triage.notes,
              findings: report.findings,
            }) as unknown as Promise<Synthesis | null>,
        )
        .catch(() => null);

      const finalReport = synthesis ? { ...report, synthesis } : report;

      await step.do("persist completed report", async () => {
        await update("completed", {
          commitSha: snapshot.commitSha,
          report: finalReport,
        });
        await system.emit(
          "status",
          `Report complete: ${finalReport.findings.length} finding(s).`,
        );
      });

      return {
        runId,
        status: "completed",
        commitSha: snapshot.commitSha,
        findingCount: finalReport.findings.length,
      };
    } catch (error) {
      const message = error instanceof Error
        ? error.message.slice(0, 1000)
        : "Unknown analysis error";

      await step.do("persist failure", async () => {
        await update("failed", { error: message });
        await system.emit("error", `Run failed: ${message}`);
      });

      throw error;
    }
  }
}
