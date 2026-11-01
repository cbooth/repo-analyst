import type { RepositorySnapshot } from "./env";
import type { Finding, Severity } from "./findings";
import { redactSecrets } from "./security";

interface Detector {
  name: string;
  pattern: RegExp;
  confidence: number;
  /** Generic assignments need the value checked for placeholders. */
  generic?: boolean;
}

const DETECTORS: Detector[] = [
  {
    name: "Private key",
    pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
    confidence: 0.95,
  },
  {
    name: "GitHub token",
    pattern: /\bgh[pousr]_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b/,
    confidence: 0.95,
  },
  {
    name: "AWS access key ID",
    pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
    confidence: 0.9,
  },
  {
    name: "Slack token",
    pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/,
    confidence: 0.9,
  },
  {
    name: "API secret key",
    pattern: /\bsk-[A-Za-z0-9_-]{20,}\b/,
    confidence: 0.8,
  },
  {
    name: "JSON Web Token",
    pattern: /\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}\b/,
    confidence: 0.7,
  },
  {
    name: "Hardcoded credential",
    pattern:
      /\b(?:api[_-]?key|secret|token|passw(?:or)?d)["']?\s*[:=]\s*["']([^\s"',;]{12,})["']/i,
    confidence: 0.55,
    generic: true,
  },
];

const PLACEHOLDER =
  /^(your|example|changeme|change_me|placeholder|dummy|sample|test|xxx|\*+|<|\$\{|\{\{|process\.env|env\.|os\.environ|getenv)/i;
const LOW_VALUE_PATH =
  /(^|\/)(tests?|__tests__|fixtures?|examples?|samples?|docs?|testdata)\/|\.(test|spec)\.|\.example$|\.md$/i;
const MAX_FINDINGS = 20;

function entropy(value: string): number {
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const n of counts.values()) {
    const p = n / value.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

/** Looks like a real secret, not a placeholder or a variable name. */
function plausibleSecret(value: string): boolean {
  return !PLACEHOLDER.test(value) && entropy(value) >= 3;
}

function lowered(severity: Severity): Severity {
  return severity === "high" ? "medium" : "low";
}

/** Deterministic secret detection over the files that were fetched. */
export function scanSecrets(snapshot: RepositorySnapshot): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();

  for (const file of snapshot.files) {
    const lowValue = LOW_VALUE_PATH.test(file.path);
    const lines = file.content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.length > 2000) continue;

      for (const detector of DETECTORS) {
        const match = detector.pattern.exec(line);
        if (!match) continue;
        if (detector.generic && !plausibleSecret(match[1] ?? "")) continue;

        const key = `${file.path}:${i}:${detector.name}`;
        if (seen.has(key)) continue;
        seen.add(key);

        const base: Severity = detector.generic ? "medium" : "high";
        const masked = redactSecrets(
          line.replace(match[1] ?? match[0], "[REDACTED]").trim(),
        ).slice(0, 200);

        findings.push({
          title: `${detector.name} committed in source`,
          category: "secrets",
          severity: lowValue ? lowered(base) : base,
          confidence: lowValue ? detector.confidence * 0.7 : detector.confidence,
          file: file.path,
          startLine: i + 1,
          endLine: i + 1,
          evidence: masked,
          explanation:
            "A value matching a secret pattern is stored in the repository. " +
            "Anyone with read access, including forks and clones, has it, and " +
            "removing it later does not remove it from git history.",
          recommendation:
            "Revoke and rotate the credential now, load it from a secret " +
            "store or environment variable, and purge it from history if " +
            "the repository is shared.",
        });
        break;
      }

      if (findings.length >= MAX_FINDINGS) return findings;
    }
  }

  return findings;
}

const EXAMPLE_ENV = /\.(example|sample|template|dist)$/i;

/** Files whose very presence in git is a problem. */
export function sensitiveFileFindings(paths: string[]): Finding[] {
  return paths
    .filter((path) => !EXAMPLE_ENV.test(path))
    .slice(0, MAX_FINDINGS)
    .map((path): Finding => {
      const name = path.split("/").pop() ?? path;
      const maybePublic = /\.pem$/i.test(name) || /\.tfvars$/i.test(name);
      return {
        title: "Sensitive file committed to the repository",
        category: "secrets",
        severity: maybePublic ? "medium" : "high",
        confidence: maybePublic ? 0.5 : 0.75,
        file: path,
        startLine: 1,
        endLine: 1,
        evidence: name,
        explanation:
          `\`${name}\` is a file type that normally holds credentials or ` +
          "private state (keys, environment files, Terraform state). " +
          "Its contents were not read or sent to any model." +
          (maybePublic ? " It may be a public certificate, which is safe." : ""),
        recommendation:
          "If it holds real credentials, rotate them, remove the file from " +
          "history, and add it to .gitignore.",
      };
    });
}
