export type Category =
  | "security"
  | "correctness"
  | "architecture"
  | "testing"
  | "infrastructure"
  | "secrets"
  | "dependencies";

/** Specialists that read source with a model. */
export const LLM_CATEGORIES = [
  "security",
  "correctness",
  "architecture",
  "testing",
  "infrastructure",
] as const;
export type LlmCategory = (typeof LLM_CATEGORIES)[number];

/** Produced by our own scanners; never by a model. */
export const TRUSTED_CATEGORIES: Category[] = ["secrets", "dependencies"];

export type Severity =
  | "critical"
  | "high"
  | "medium"
  | "low";

export interface Finding {
  title: string;
  category: Category;
  severity: Severity;
  confidence: number;
  file: string;
  startLine: number;
  endLine: number;
  evidence: string;
  explanation: string;
  recommendation: string;
  /** Set by the second-pass reviewer. */
  verification?: "confirmed" | "uncertain";
  verifierNote?: string;
}

export interface Verdict {
  id: number;
  verdict: "confirmed" | "refuted" | "uncertain";
  reason: string;
}

export interface DismissedFinding {
  title: string;
  category: Category;
  file: string;
  startLine: number;
  reason: string;
}

export interface Synthesis {
  overview: string;
  priorities: { action: string; why: string; findingIndexes: number[] }[];
}

export interface AnalysisReport {
  owner: string;
  repo: string;
  commitSha: string;
  filesInspected: number;
  filesSkipped: number;
  findings: Finding[];
  dismissed: DismissedFinding[];
  /** Whether a second-pass reviewer examined the findings. */
  verified: boolean;
  synthesis?: Synthesis;
  incompleteAgents: Category[];
  summary: string;
  createdAt: string;
}

export const MAX_FINDINGS_PER_AGENT = 25;

const categories = new Set<Category>(LLM_CATEGORIES);

const severities = new Set<Severity>([
  "critical", "high", "medium", "low",
]);

/**
 * `forceCategory` is the specialist that produced the output: a model
 * must not be able to label its findings as another agent's, least of
 * all a trusted scanner's.
 */
export function validateFindings(
  input: unknown,
  fileLines: Map<string, number>,
  forceCategory?: Category,
): Finding[] {
  if (!Array.isArray(input)) return [];

  const findings: Finding[] = [];

  for (const raw of input.slice(0, MAX_FINDINGS_PER_AGENT)) {
    if (!raw || typeof raw !== "object") continue;

    const x = raw as Record<string, unknown>;

    if (
      typeof x.title !== "string" ||
      typeof x.file !== "string" ||
      !fileLines.has(x.file) ||
      typeof x.evidence !== "string" ||
      typeof x.explanation !== "string" ||
      typeof x.recommendation !== "string" ||
      (!forceCategory && !categories.has(x.category as Category)) ||
      !severities.has(x.severity as Severity)
    ) {
      continue;
    }

    const maxLine = fileLines.get(x.file)!;
    const startLine = Number(x.startLine);
    // Models often omit endLine for single-line findings.
    const endLine = x.endLine === undefined || x.endLine === null
      ? startLine
      : Number(x.endLine);
    let confidence = Number(x.confidence);
    // Some models answer 85 instead of 0.85.
    if (confidence > 1 && confidence <= 100) confidence /= 100;

    if (
      !Number.isInteger(startLine) ||
      !Number.isInteger(endLine) ||
      startLine < 1 ||
      endLine < startLine ||
      endLine > maxLine ||
      !Number.isFinite(confidence) ||
      confidence < 0 ||
      confidence > 1
    ) {
      continue;
    }

    findings.push({
      title: x.title.slice(0, 200),
      category: forceCategory ?? (x.category as Category),
      severity: x.severity as Severity,
      confidence,
      file: x.file,
      startLine,
      endLine,
      evidence: x.evidence.slice(0, 1500),
      explanation: x.explanation.slice(0, 3000),
      recommendation: x.recommendation.slice(0, 2000),
    });
  }

  return findings;
}