import { DurableObject } from "cloudflare:workers";

import type {
  Env,
  RepoListing,
  RepositorySnapshot,
  TriageResult,
} from "./env";
import { runSpecialist } from "./agents";
import { checkDependencies } from "./deps";
import { EventWriter } from "./events";
import type {
  Finding,
  LlmCategory,
  Synthesis,
  Verdict,
} from "./findings";
import { fetchFiles, listRepository, maxFilesFor } from "./github";
import { scanSecrets, sensitiveFileFindings } from "./scanners";
import { runTriage } from "./triage";
import { runSynthesis, runVerifier } from "./verify";

/**
 * Hosts the CPU- and subrequest-heavy work. Workflow steps only get 10 ms
 * of CPU on the Free plan, and streaming a reasoning model is thousands
 * of tiny chunks; a Durable Object invocation gets 30 s and its own
 * subrequest budget. One instance per run and task, so work never
 * shares a budget.
 */
export class AgentSession extends DurableObject<Env> {
  listRepository(params: {
    owner: string;
    repo: string;
    ref?: string;
    installationId: number;
  }): Promise<RepoListing> {
    return listRepository(
      this.env,
      params.owner,
      params.repo,
      params.ref,
      params.installationId,
    );
  }

  triage(params: {
    runId: string;
    listing: RepoListing;
  }): Promise<TriageResult> {
    return runTriage(
      this.env,
      params.listing,
      new EventWriter(this.env.DB, params.runId, "triage"),
      params.runId,
      maxFilesFor(this.env),
    );
  }

  async fetchSnapshot(params: {
    listing: RepoListing;
    triage: TriageResult;
    installationId: number;
  }): Promise<RepositorySnapshot> {
    const { listing, triage } = params;
    const { files } = await fetchFiles(
      this.env,
      listing.owner,
      listing.repo,
      triage.selected,
      params.installationId,
    );

    return {
      owner: listing.owner,
      repo: listing.repo,
      commitSha: listing.commitSha,
      files,
      // Everything not read: excluded by filters, unselected, or unreadable.
      skippedFiles: listing.excluded +
        Math.max(0, listing.entries.length - files.length),
      paths: listing.entries.map((e) => e.path),
      assigned: triage.assigned,
    };
  }

  async analyze(params: {
    runId: string;
    category: LlmCategory;
    snapshot: RepositorySnapshot;
  }): Promise<Finding[]> {
    return runSpecialist(
      this.env,
      params.snapshot,
      params.category,
      new EventWriter(this.env.DB, params.runId, params.category),
      params.runId,
    );
  }

  /** Deterministic: no model, no neurons. */
  async secrets(params: {
    runId: string;
    snapshot: RepositorySnapshot;
    sensitive: string[];
  }): Promise<Finding[]> {
    const events = new EventWriter(this.env.DB, params.runId, "secrets");
    await events.emit(
      "status",
      `Started. Scanning ${params.snapshot.files.length} files for secrets.`,
    );
    const findings = [
      ...sensitiveFileFindings(params.sensitive),
      ...scanSecrets(params.snapshot),
    ];
    await events.emit(
      "status",
      `Finished: ${findings.length} potential secret${findings.length === 1 ? "" : "s"} (values are never stored).`,
    );
    return findings;
  }

  dependencies(params: {
    runId: string;
    listing: RepoListing;
    installationId: number;
  }): Promise<Finding[]> {
    return checkDependencies(
      this.env,
      params.listing,
      params.installationId,
      new EventWriter(this.env.DB, params.runId, "dependencies"),
    );
  }

  verify(params: {
    runId: string;
    snapshot: RepositorySnapshot;
    findings: Finding[];
  }): Promise<Verdict[]> {
    return runVerifier(
      this.env,
      params.snapshot,
      params.findings,
      new EventWriter(this.env.DB, params.runId, "verifier"),
      params.runId,
    );
  }

  synthesize(params: {
    runId: string;
    repoName: string;
    notes: string;
    findings: Finding[];
  }): Promise<Synthesis | null> {
    return runSynthesis(
      this.env,
      params.findings,
      params.notes,
      new EventWriter(this.env.DB, params.runId, "synthesis"),
      params.runId,
      params.repoName,
    );
  }
}
