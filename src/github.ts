import { Octokit } from "@octokit/rest";
import { createAppAuth } from "@octokit/auth-app";
import type {
  Env,
  RepoEntry,
  RepoListing,
  RepositoryFile,
} from "./env";

const EXCLUDED_DIRS = new Set([
  "node_modules",
  "vendor",
  "dist",
  "build",
  ".git",
  ".next",
  "coverage",
]);

const SENSITIVE_NAME =
  /^(\.env(\..*)?|\.dev\.vars.*|\.npmrc|\.netrc|\.htpasswd|id_(rsa|dsa|ecdsa|ed25519)|.*\.(pem|key|p12|pfx|jks|keystore|tfstate|tfvars)(\.backup)?)$/i;

/** Lockfiles and manifests the dependency check can read. */
const LOCKFILE_NAMES =
  /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|Cargo\.lock|poetry\.lock|go\.mod|requirements\.txt|composer\.lock)$/;

const EXAMPLE_ENV = /\.(example|sample|template|dist)$/i;

const LOCKFILE =
  /^(package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|Cargo\.lock|poetry\.lock|go\.sum|composer\.lock|Gemfile\.lock)$/;

const TEXT_EXTENSIONS = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
  ".py", ".go", ".rs", ".java", ".kt",
  ".cs", ".php", ".rb", ".swift",
  ".json", ".jsonc", ".yaml", ".yml",
  ".toml", ".md", ".mdx", ".txt",
  ".sql", ".sh", ".bash", ".css", ".html",
  ".xml", ".graphql", ".proto",
  ".tf", ".dockerfile",
]);

export function isCandidate(path: string): boolean {
  const segments = path.split("/");
  const name = segments[segments.length - 1] ?? "";

  // Excluded directories apply at any depth, e.g. packages/a/node_modules.
  if (segments.slice(0, -1).some((s) => EXCLUDED_DIRS.has(s))) {
    return false;
  }

  if (SENSITIVE_NAME.test(name) || LOCKFILE.test(name)) {
    return false;
  }

  if (name === "Dockerfile" || name === "Makefile") {
    return true;
  }

  const dot = name.lastIndexOf(".");
  return dot >= 0 &&
    TEXT_EXTENSIONS.has(name.slice(dot).toLowerCase());
}

function decodeBase64(value: string): string {
  const bytes = Uint8Array.from(
    atob(value.replace(/\s/g, "")),
    (c) => c.charCodeAt(0),
  );
  return new TextDecoder("utf-8", {
    fatal: false,
    ignoreBOM: true,
  }).decode(bytes);
}

export async function makeGitHubClient(
  env: Env,
  installationId: number,
): Promise<Octokit> {
  return new Octokit({
    authStrategy: createAppAuth,
    auth: {
      appId: env.GITHUB_APP_ID,
      privateKey: env.GITHUB_APP_PRIVATE_KEY.replace(
        /\\n/g,
        "\n",
      ),
      installationId,
    },
  });
}

function limits(env: Env) {
  const maxFileBytes = Math.max(1024, Number(env.MAX_FILE_BYTES) || 20000);
  return {
    maxFiles: Math.max(1, Number(env.MAX_FILES) || 40),
    maxFileBytes,
    // Workflow step results are limited to 1 MiB once JSON-encoded.
    maxTotalBytes: Math.min(
      500_000,
      Math.max(maxFileBytes, Number(env.MAX_TOTAL_BYTES) || 350000),
    ),
  };
}

function installationOrThrow(env: Env, installationId?: number): number {
  const installation = installationId ??
    Number(env.GITHUB_INSTALLATION_ID);
  if (!Number.isInteger(installation) || installation <= 0) {
    throw new Error("GITHUB_INSTALLATION_ID is not configured");
  }
  return installation;
}

const MAX_LISTED = 2500;

export function maxFilesFor(env: Env) {
  const { maxFiles, maxTotalBytes } = limits(env);
  return { maxFiles, maxTotalBytes };
}

/** Pins a commit and lists candidate files without reading contents. */
export async function listRepository(
  env: Env,
  owner: string,
  repo: string,
  ref?: string,
  installationId?: number,
): Promise<RepoListing> {
  const gh = await makeGitHubClient(
    env,
    installationOrThrow(env, installationId),
  );

  const repoInfo = await gh.rest.repos.get({ owner, repo });
  const resolved = await gh.rest.repos.getCommit({
    owner,
    repo,
    ref: ref || repoInfo.data.default_branch,
  });
  const commitSha = resolved.data.sha;

  const tree = await gh.rest.git.getTree({
    owner,
    repo,
    tree_sha: commitSha,
    recursive: "true",
  });

  if (tree.data.truncated) {
    throw new Error(
      "GitHub returned a truncated tree; narrow the analysis scope.",
    );
  }

  const { maxFileBytes } = limits(env);
  const inExcludedDir = (path: string) =>
    path.split("/").slice(0, -1).some((s) => EXCLUDED_DIRS.has(s));
  const blobs = tree.data.tree.filter(
    (entry) => entry.type === "blob" && entry.path && entry.sha,
  );
  const entries: RepoEntry[] = blobs
    .filter(
      (entry) =>
        isCandidate(entry.path!) && (entry.size ?? 0) <= maxFileBytes,
    )
    .map((entry) => ({
      path: entry.path!,
      size: entry.size ?? 0,
      sha: entry.sha!,
    }))
    .sort(
      (a, b) =>
        a.path.split("/").length - b.path.split("/").length ||
        a.path.localeCompare(b.path),
    )
    .slice(0, MAX_LISTED);

  const sensitive = blobs
    .map((entry) => entry.path!)
    .filter(
      (path) =>
        !inExcludedDir(path) &&
        SENSITIVE_NAME.test(path.split("/").pop() ?? "") &&
        !EXAMPLE_ENV.test(path),
    )
    .slice(0, 50);

  const lockfiles: RepoEntry[] = blobs
    .filter(
      (entry) =>
        !inExcludedDir(entry.path!) && LOCKFILE_NAMES.test(entry.path!),
    )
    .map((entry) => ({
      path: entry.path!,
      size: entry.size ?? 0,
      sha: entry.sha!,
    }));

  return {
    owner,
    repo,
    commitSha,
    entries,
    excluded: blobs.length - entries.length,
    sensitive,
    lockfiles,
  };
}

/** Downloads whole files as text; used for lockfiles above the size cap. */
export async function fetchTexts(
  env: Env,
  owner: string,
  repo: string,
  entries: RepoEntry[],
  installationId?: number,
): Promise<Map<string, string>> {
  const gh = await makeGitHubClient(
    env,
    installationOrThrow(env, installationId),
  );
  const texts = new Map<string, string>();

  for (const entry of entries) {
    try {
      const blob = await gh.rest.git.getBlob({
        owner,
        repo,
        file_sha: entry.sha,
      });
      if (blob.data.encoding === "base64") {
        texts.set(entry.path, decodeBase64(blob.data.content));
      }
    } catch {
      /* unreadable lockfile: skipped */
    }
  }
  return texts;
}

/** Downloads the files triage selected. One GitHub call per file. */
export async function fetchFiles(
  env: Env,
  owner: string,
  repo: string,
  selected: RepoEntry[],
  installationId?: number,
): Promise<{ files: RepositoryFile[]; skippedFiles: number }> {
  const gh = await makeGitHubClient(
    env,
    installationOrThrow(env, installationId),
  );
  const { maxFiles, maxTotalBytes } = limits(env);

  const files: RepositoryFile[] = [];
  let totalBytes = 0;
  let skippedFiles = 0;

  for (const entry of selected) {
    if (files.length >= maxFiles || totalBytes + entry.size > maxTotalBytes) {
      skippedFiles++;
      continue;
    }

    try {
      const blob = await gh.rest.git.getBlob({
        owner,
        repo,
        file_sha: entry.sha,
      });

      if (blob.data.encoding !== "base64") {
        skippedFiles++;
        continue;
      }

      const content = decodeBase64(blob.data.content);

      // Ignore likely binary files despite their extension.
      if (content.includes("\u0000")) {
        skippedFiles++;
        continue;
      }

      files.push({ path: entry.path, content, size: entry.size });
      totalBytes += entry.size;
    } catch {
      // Fail closed on individual unreadable files.
      skippedFiles++;
    }
  }

  return { files, skippedFiles };
}
