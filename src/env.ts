import type { Octokit } from "@octokit/rest";
import type { AgentSession } from "./agent-session";
import type { LlmCategory } from "./findings";

export interface Env {
  AI: Ai;
  REPO_ANALYSIS: Workflow<AnalysisParams & { runId: string }>;
  ASSETS: Fetcher;
  AGENT_SESSION: DurableObjectNamespace<AgentSession>;

  DB: D1Database;

  GITHUB_APP_ID: string;
  GITHUB_APP_PRIVATE_KEY: string;
  GITHUB_INSTALLATION_ID?: string;

  // Machine clients: `Authorization: Bearer <key>`. Humans come via Access.
  ANALYSIS_API_KEY?: string;

  // Cloudflare Access (Zero Trust) application protecting the UI.
  ACCESS_TEAM_DOMAIN?: string;
  ACCESS_POLICY_AUD?: string;

  // Only honoured for requests addressed to localhost.
  DEV_BYPASS_ACCESS?: string;

  AI_MODEL: string;
  MAX_FILES: string;
  MAX_FILE_BYTES: string;
  MAX_TOTAL_BYTES: string;
  MAX_ACTIVE_RUNS?: string;
  NEURON_DAILY_LIMIT?: string;
}

export interface AnalysisParams {
  owner: string;
  repo: string;
  ref?: string;
  installationId: number;
}

export interface RepositoryFile {
  path: string;
  content: string;
  size: number;
}

export interface RepoEntry {
  path: string;
  size: number;
  sha: string;
}

/** Candidate files at a pinned commit, before any content is fetched. */
export interface RepoListing {
  owner: string;
  repo: string;
  commitSha: string;
  entries: RepoEntry[];
  excluded: number;
  /** Committed files that look like credentials (never fetched). */
  sensitive: string[];
  /** Lockfiles and manifests for the dependency check. */
  lockfiles: RepoEntry[];
}

export interface TriageResult {
  selected: RepoEntry[];
  assigned: Record<LlmCategory, string[]>;
  notes: string;
}

export interface RepositorySnapshot {
  owner: string;
  repo: string;
  commitSha: string;
  files: RepositoryFile[];
  skippedFiles: number;
  /** Every candidate path, so agents can tell what exists. */
  paths?: string[];
  /** Files each specialist should read, from triage. */
  assigned?: Partial<Record<LlmCategory, string[]>>;
}

export type EventKind = "status" | "thinking" | "output" | "error";

export interface AgentEvent {
  seq: number;
  agent: string;
  kind: EventKind;
  content: string;
  created_at: string;
}

export type { Octokit };
