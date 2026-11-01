import type { Env, RepoEntry, RepoListing } from "./env";
import type { EventWriter } from "./events";
import type { Finding, Severity } from "./findings";
import { fetchTexts } from "./github";

export interface Dep {
  ecosystem: string;
  name: string;
  version: string;
}

const MAX_LOCKFILES = 4;
const MAX_LOCKFILE_BYTES = 3_000_000;
const MAX_QUERIES = 1000;
const MAX_DETAIL_LOOKUPS = 20;
const MAX_FINDINGS = 30;

/* ---------- parsers ---------- */

export function parsePackageLock(text: string): Dep[] {
  const json = JSON.parse(text) as {
    packages?: Record<string, { version?: string; link?: boolean }>;
    dependencies?: Record<string, any>;
  };
  const deps: Dep[] = [];

  if (json.packages) {
    for (const [path, info] of Object.entries(json.packages)) {
      if (!path || info.link || !info.version) continue;
      const name = path.slice(path.lastIndexOf("node_modules/") + 13);
      if (name) deps.push({ ecosystem: "npm", name, version: info.version });
    }
  } else if (json.dependencies) {
    const walk = (tree: Record<string, any>) => {
      for (const [name, info] of Object.entries(tree)) {
        if (typeof info?.version === "string") {
          deps.push({ ecosystem: "npm", name, version: info.version });
        }
        if (info?.dependencies) walk(info.dependencies);
      }
    };
    walk(json.dependencies);
  }
  return deps;
}

export function parseYarnLock(text: string): Dep[] {
  const deps: Dep[] = [];
  let name: string | null = null;

  for (const line of text.split("\n")) {
    if (line && !line.startsWith(" ") && !line.startsWith("#") && line.endsWith(":")) {
      const first = line.slice(0, -1).split(",")[0].trim().replace(/^"|"$/g, "");
      const at = first.lastIndexOf("@");
      name = at > 0 ? first.slice(0, at) : null;
    } else if (name) {
      const m = /^\s+version\s+"?([^"\s]+)"?/.exec(line);
      if (m) {
        deps.push({ ecosystem: "npm", name, version: m[1] });
        name = null;
      }
    }
  }
  return deps;
}

/** Cargo.lock and poetry.lock share the `[[package]]` layout. */
export function parseTomlPackages(
  text: string,
  ecosystem: string,
  registryOnly: boolean,
): Dep[] {
  const deps: Dep[] = [];
  for (const block of text.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const name = /^name\s*=\s*"([^"]+)"/m.exec(block)?.[1];
    const version = /^version\s*=\s*"([^"]+)"/m.exec(block)?.[1];
    const source = /^source\s*=\s*"([^"]+)"/m.exec(block)?.[1];
    if (!name || !version) continue;
    if (registryOnly && !source?.startsWith("registry+")) continue;
    deps.push({ ecosystem, name, version });
  }
  return deps;
}

export function parseGoMod(text: string): Dep[] {
  const deps: Dep[] = [];
  let inBlock = false;

  for (const raw of text.split("\n")) {
    const line = raw.replace(/\/\/.*$/, "").trim();
    if (line.startsWith("require (")) inBlock = true;
    else if (inBlock && line === ")") inBlock = false;
    else {
      const m = inBlock
        ? /^(\S+)\s+v(\S+)$/.exec(line)
        : /^require\s+(\S+)\s+v(\S+)$/.exec(line);
      if (m) deps.push({ ecosystem: "Go", name: m[1], version: m[2] });
    }
  }
  return deps;
}

export function parseRequirements(text: string): Dep[] {
  const deps: Dep[] = [];
  for (const line of text.split("\n")) {
    const m = /^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?==([^\s;#]+)/.exec(line.trim());
    if (m) deps.push({ ecosystem: "PyPI", name: m[1], version: m[2] });
  }
  return deps;
}

export function parseComposerLock(text: string): Dep[] {
  const json = JSON.parse(text) as {
    packages?: { name: string; version: string }[];
    "packages-dev"?: { name: string; version: string }[];
  };
  return [...(json.packages ?? []), ...(json["packages-dev"] ?? [])]
    .filter((p) => p.name && p.version)
    .map((p) => ({
      ecosystem: "Packagist",
      name: p.name,
      version: p.version.replace(/^v/, ""),
    }));
}

export function parseLockfile(path: string, text: string): Dep[] {
  const name = path.split("/").pop() ?? path;
  switch (name) {
    case "package-lock.json":
    case "npm-shrinkwrap.json":
      return parsePackageLock(text);
    case "yarn.lock":
      return parseYarnLock(text);
    case "Cargo.lock":
      return parseTomlPackages(text, "crates.io", true);
    case "poetry.lock":
      return parseTomlPackages(text, "PyPI", false);
    case "go.mod":
      return parseGoMod(text);
    case "requirements.txt":
      return parseRequirements(text);
    case "composer.lock":
      return parseComposerLock(text);
    default:
      return [];
  }
}

/* ---------- OSV ---------- */

interface OsvVuln {
  id: string;
  summary?: string;
  database_specific?: { severity?: string };
  affected?: {
    package?: { name?: string; ecosystem?: string };
    ranges?: { events?: { fixed?: string }[] }[];
  }[];
}

const SEVERITY_ORDER: Severity[] = ["low", "medium", "high", "critical"];

function severityOf(vuln?: OsvVuln): Severity {
  switch (vuln?.database_specific?.severity?.toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "LOW":
      return "low";
    default:
      return "medium";
  }
}

function fixedVersions(vulns: OsvVuln[], dep: Dep): string[] {
  const fixed = new Set<string>();
  for (const vuln of vulns) {
    for (const affected of vuln.affected ?? []) {
      if (affected.package?.name !== dep.name) continue;
      for (const range of affected.ranges ?? []) {
        for (const event of range.events ?? []) {
          if (event.fixed) fixed.add(event.fixed);
        }
      }
    }
  }
  return [...fixed].slice(0, 3);
}

async function osvQuery(deps: Dep[]): Promise<string[][]> {
  const response = await fetch("https://api.osv.dev/v1/querybatch", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      queries: deps.map((d) => ({
        package: { name: d.name, ecosystem: d.ecosystem },
        version: d.version,
      })),
    }),
  });
  if (!response.ok) throw new Error(`OSV query failed (${response.status})`);

  const body = (await response.json()) as {
    results?: { vulns?: { id: string }[] }[];
  };
  return deps.map((_, i) =>
    (body.results?.[i]?.vulns ?? []).map((v) => v.id),
  );
}

async function osvDetails(ids: string[]): Promise<Map<string, OsvVuln>> {
  const details = new Map<string, OsvVuln>();
  for (let i = 0; i < ids.length; i += 6) {
    await Promise.all(
      ids.slice(i, i + 6).map(async (id) => {
        try {
          const response = await fetch(
            `https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`,
          );
          if (response.ok) details.set(id, (await response.json()) as OsvVuln);
        } catch {
          /* severity falls back to "medium" */
        }
      }),
    );
  }
  return details;
}

/** Pure part of the check: turns OSV answers into findings. */
export function buildDependencyFindings(
  deps: Dep[],
  idsPerDep: string[][],
  details: Map<string, OsvVuln>,
  lockfile: (dep: Dep) => { file: string; line: number },
): Finding[] {
  const findings: Finding[] = [];

  deps.forEach((dep, i) => {
    const ids = idsPerDep[i];
    if (!ids?.length) return;

    const vulns = ids.map((id) => details.get(id)).filter(Boolean) as OsvVuln[];
    const severity = vulns.reduce<Severity>(
      (max, v) =>
        SEVERITY_ORDER.indexOf(severityOf(v)) > SEVERITY_ORDER.indexOf(max)
          ? severityOf(v)
          : max,
      vulns.length ? "low" : "medium",
    );
    const fixed = fixedVersions(vulns, dep);
    const where = lockfile(dep);

    findings.push({
      title: `${dep.name}@${dep.version} has ${ids.length} known ${ids.length === 1 ? "vulnerability" : "vulnerabilities"}`,
      category: "dependencies",
      severity,
      confidence: 0.9,
      file: where.file,
      startLine: where.line,
      endLine: where.line,
      evidence: `${dep.name}@${dep.version}`,
      explanation:
        ids
          .slice(0, 3)
          .map((id) => `${id}${details.get(id)?.summary ? `: ${details.get(id)!.summary}` : ""}`)
          .join("; ") +
        (ids.length > 3 ? `; and ${ids.length - 3} more` : "") +
        ". Reachability from this code was not assessed.",
      recommendation:
        (fixed.length
          ? `Upgrade to a fixed version (${fixed.join(", ")}). `
          : "Check the advisories for a fixed version. ") +
        "Run your package manager's audit to confirm it applies.",
    });
  });

  return findings
    .sort(
      (a, b) =>
        SEVERITY_ORDER.indexOf(b.severity) -
        SEVERITY_ORDER.indexOf(a.severity),
    )
    .slice(0, MAX_FINDINGS);
}

/** Looks up locked dependency versions in the OSV database. */
export async function checkDependencies(
  env: Env,
  listing: RepoListing,
  installationId: number,
  events: EventWriter,
): Promise<Finding[]> {
  const files: RepoEntry[] = listing.lockfiles
    .filter((e) => e.size <= MAX_LOCKFILE_BYTES)
    .sort((a, b) => a.path.split("/").length - b.path.split("/").length)
    .slice(0, MAX_LOCKFILES);

  if (!files.length) {
    await events.emit("status", "Finished: no lockfiles or manifests found.");
    return [];
  }

  await events.emit(
    "status",
    `Started. Reading ${files.map((f) => f.path).join(", ")}.`,
  );

  const texts = await fetchTexts(
    env,
    listing.owner,
    listing.repo,
    files,
    installationId,
  );

  const seen = new Map<string, { dep: Dep; path: string }>();
  for (const [path, text] of texts) {
    try {
      for (const dep of parseLockfile(path, text)) {
        const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;
        if (!seen.has(key)) seen.set(key, { dep, path });
      }
    } catch {
      await events.emit("error", `Could not parse ${path}.`);
    }
  }

  const entries = [...seen.values()].slice(0, MAX_QUERIES);
  const deps = entries.map((e) => e.dep);
  if (!deps.length) {
    await events.emit("status", "Finished: no pinned versions to check.");
    return [];
  }

  const idsPerDep = await osvQuery(deps);

  // One advisory per vulnerable package first, then fill remaining lookups.
  const firstIds = idsPerDep.flatMap((ids) => ids.slice(0, 1));
  const restIds = idsPerDep.flatMap((ids) => ids.slice(1));
  const lookups = [...new Set([...firstIds, ...restIds])].slice(
    0,
    MAX_DETAIL_LOOKUPS,
  );
  const details = await osvDetails(lookups);

  const locate = (dep: Dep) => {
    const path = seen.get(`${dep.ecosystem}:${dep.name}@${dep.version}`)!.path;
    const text = texts.get(path) ?? "";
    const index = text.indexOf(dep.name);
    const line = index < 0 ? 1 : text.slice(0, index).split("\n").length;
    return { file: path, line };
  };

  const findings = buildDependencyFindings(deps, idsPerDep, details, locate);
  await events.emit(
    "status",
    `Finished: checked ${deps.length} locked packages, ${findings.length} with known vulnerabilities.`,
  );
  return findings;
}
