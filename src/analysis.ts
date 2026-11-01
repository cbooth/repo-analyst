import type { RepositorySnapshot } from "./env";
import {
  TRUSTED_CATEGORIES,
  type AnalysisReport,
  type Category,
  type DismissedFinding,
  type Finding,
  type Verdict,
} from "./findings";
import { redactSecrets } from "./security";

// Models are often off by a line or two when citing locations.
const LINE_TOLERANCE = 2;

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

const squash = (text: string) => text.replace(/\s+/g, " ").trim();

const isTrusted = (finding: Finding) =>
  TRUSTED_CATEGORIES.includes(finding.category);

/**
 * Models copy the "12: " line-number prefixes from the prompt and join
 * non-adjacent snippets with "...". Strip the former and require each
 * snippet of the latter to appear.
 */
export function evidenceFragments(evidence: string): string[] {
  return evidence
    .split("\n")
    .map((line) => line.replace(/^\s*\d+:\s?/, ""))
    .join("\n")
    .split(/\.\.\.|…/)
    .map(squash)
    .filter((fragment) => fragment.length >= 8);
}

/**
 * Keeps findings whose quoted evidence really appears near the cited
 * lines, and removes duplicates. Findings from deterministic scanners
 * (secrets, dependencies) are produced by our own code, not a model, so
 * their evidence is masked or synthetic and is not checked against source.
 */
export function checkEvidence(
  snapshot: RepositorySnapshot,
  agentResults: Finding[][],
): Finding[] {
  const linesByFile = new Map(
    snapshot.files.map((file) => [file.path, file.content.split("\n")]),
  );

  const unique = new Map<string, Finding>();

  for (const finding of agentResults.flat()) {
    if (!isTrusted(finding)) {
      const lines = linesByFile.get(finding.file);
      if (!lines) continue;

      const fragments = evidenceFragments(finding.evidence);
      if (fragments.length === 0) continue;

      const actual = squash(
        lines
          .slice(
            Math.max(0, finding.startLine - 1 - LINE_TOLERANCE),
            finding.endLine + LINE_TOLERANCE,
          )
          .join("\n"),
      );

      // Reject findings whose evidence does not match the cited lines.
      if (!fragments.every((fragment) => actual.includes(fragment))) continue;
    }

    const key = [
      finding.category,
      finding.file,
      finding.startLine,
      finding.title.toLowerCase(),
    ].join(":");

    if (!unique.has(key)) unique.set(key, finding);
  }

  return [...unique.values()];
}

/** Applies the verifier's verdicts; `verdict.id` indexes `findings`. */
export function applyVerdicts(
  findings: Finding[],
  verdicts: Verdict[],
): { kept: Finding[]; dismissed: DismissedFinding[] } {
  const byId = new Map(verdicts.map((v) => [v.id, v]));
  const kept: Finding[] = [];
  const dismissed: DismissedFinding[] = [];

  findings.forEach((finding, id) => {
    const verdict = byId.get(id);
    if (!verdict) {
      kept.push(finding);
    } else if (verdict.verdict === "refuted") {
      dismissed.push({
        title: finding.title,
        category: finding.category,
        file: finding.file,
        startLine: finding.startLine,
        reason: verdict.reason,
      });
    } else {
      kept.push({
        ...finding,
        verification: verdict.verdict,
        verifierNote: verdict.reason,
        confidence: verdict.verdict === "uncertain"
          ? Math.round(finding.confidence * 80) / 100
          : finding.confidence,
      });
    }
  });

  return { kept, dismissed };
}

export function buildReport(
  snapshot: RepositorySnapshot,
  agentResults: Finding[][],
  incompleteAgents: Category[] = [],
  extras: { dismissed?: DismissedFinding[]; verified?: boolean } = {},
): AnalysisReport {
  const findings = checkEvidence(snapshot, agentResults)
    .map((finding) => ({
      ...finding,
      title: redactSecrets(finding.title),
      evidence: redactSecrets(finding.evidence),
      explanation: redactSecrets(finding.explanation),
      recommendation: redactSecrets(finding.recommendation),
      verifierNote: finding.verifierNote
        ? redactSecrets(finding.verifierNote)
        : undefined,
    }))
    .sort(
      (a, b) =>
        SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
        b.confidence - a.confidence,
    );

  const dismissed = extras.dismissed ?? [];

  return {
    owner: snapshot.owner,
    repo: snapshot.repo,
    commitSha: snapshot.commitSha,
    filesInspected: snapshot.files.length,
    filesSkipped: snapshot.skippedFiles,
    findings,
    dismissed,
    verified: extras.verified ?? false,
    incompleteAgents,
    summary:
      (findings.length
        ? `Found ${findings.length} evidence-checked findings. Review each item before treating it as a confirmed defect.`
        : "No findings passed evidence validation. This does not establish that the repository is defect-free.") +
      (dismissed.length
        ? ` A second-pass reviewer dismissed ${dismissed.length} candidate${dismissed.length === 1 ? "" : "s"}.`
        : "") +
      (incompleteAgents.length
        ? ` Incomplete: the ${incompleteAgents.join(", ")} agent(s) failed, so those categories are not covered.`
        : ""),
    createdAt: new Date().toISOString(),
  };
}
