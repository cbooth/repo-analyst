import type { AgentEvent, AnalysisParams, Env } from "./env";
import {
  authenticate,
  sameOriginOk,
  withSecurityHeaders,
  type Principal,
} from "./security";

export { AgentSession } from "./agent-session";
export { RepoAnalysisWorkflow } from "./workflow";

const ACTIVE = "('queued', 'running', 'analyzing')";
const STALE_AFTER_MS = 60 * 60 * 1000;
const MAX_EVENTS_PER_POLL = 500;
const UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";

function json(data: unknown, status = 200): Response {
  return Response.json(data, {
    status,
    headers: { "Cache-Control": "no-store" },
  });
}

function validName(value: unknown): value is string {
  return typeof value === "string" &&
    /^[A-Za-z0-9_.-]{1,100}$/.test(value) &&
    value !== "." &&
    value !== "..";
}

function validRef(value: unknown): value is string {
  return typeof value === "string" &&
    /^[A-Za-z0-9_./@+-]{1,255}$/.test(value) &&
    !value.includes("..");
}

async function startRun(
  request: Request,
  env: Env,
): Promise<Response> {
  if (
    !request.headers.get("content-type")?.toLowerCase()
      .startsWith("application/json")
  ) {
    return json({ error: "Content-Type must be application/json" }, 415);
  }

  let body: { owner?: unknown; repo?: unknown; ref?: unknown };
  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid JSON body" }, 400);
  }
  if (!body || typeof body !== "object") {
    return json({ error: "Invalid JSON body" }, 400);
  }

  if (!validName(body.owner) || !validName(body.repo)) {
    return json({ error: "owner and repo must be valid GitHub names" }, 400);
  }

  const ref = typeof body.ref === "string" && body.ref.trim() === ""
    ? undefined
    : body.ref;
  if (ref !== undefined && !validRef(ref)) {
    return json({ error: "Invalid ref" }, 400);
  }

  const installationId = Number(env.GITHUB_INSTALLATION_ID);
  if (!Number.isInteger(installationId) || installationId <= 0) {
    console.error("GITHUB_INSTALLATION_ID is missing or invalid");
    return json({ error: "Server is not configured" }, 503);
  }

  // Bound spend: each run fans out to four model calls.
  const maxActive = Math.max(1, Number(env.MAX_ACTIVE_RUNS) || 3);
  const active = await env.DB.prepare(
    `SELECT COUNT(*) AS n FROM analysis_runs
     WHERE status IN ${ACTIVE} AND created_at > ?`,
  ).bind(new Date(Date.now() - STALE_AFTER_MS).toISOString())
    .first<{ n: number }>();
  if ((active?.n ?? 0) >= maxActive) {
    return json({ error: "Too many active runs; try again shortly" }, 429);
  }

  const runId = crypto.randomUUID();
  const now = new Date().toISOString();

  const params: AnalysisParams & { runId: string } = {
    owner: body.owner,
    repo: body.repo,
    ref,
    installationId,
    runId,
  };

  await env.DB.prepare(`
    INSERT INTO analysis_runs
      (id, owner, repo, requested_ref, status, created_at, updated_at)
    VALUES (?, ?, ?, ?, 'queued', ?, ?)
  `).bind(runId, params.owner, params.repo, ref ?? null, now, now).run();

  try {
    await env.REPO_ANALYSIS.create({ id: runId, params });
  } catch (error) {
    console.error("Workflow start failed", error);
    await env.DB.prepare(`
      UPDATE analysis_runs
      SET status = 'failed', error_message = ?, updated_at = ?
      WHERE id = ?
    `).bind(
      "Could not start Workflow",
      new Date().toISOString(),
      runId,
    ).run();

    return json({ error: "Could not start analysis" }, 503);
  }

  return json({
    runId,
    status: "queued",
    statusUrl: `/api/runs/${runId}`,
  }, 202);
}

async function getUsage(env: Env): Promise<Response> {
  const now = new Date();
  const dayStart = new Date(Date.UTC(
    now.getUTCFullYear(),
    now.getUTCMonth(),
    now.getUTCDate(),
  ));
  const limit = Number(env.NEURON_DAILY_LIMIT) || 10000;

  let used: number | null = null;
  try {
    const row = await env.DB.prepare(
      "SELECT COALESCE(SUM(neurons), 0) AS used FROM ai_usage WHERE created_at >= ?",
    ).bind(dayStart.toISOString()).first<{ used: number }>();
    used = row?.used ?? 0;
  } catch (error) {
    // Table not created yet; the UI shows the meter as unavailable.
    console.warn("usage query failed", error);
  }

  return json({
    used,
    limit,
    resetsAt: new Date(dayStart.getTime() + 86_400_000).toISOString(),
  });
}

async function listRuns(env: Env): Promise<Response> {
  const { results } = await env.DB.prepare(`
    SELECT id, owner, repo, requested_ref, commit_sha, status,
           error_message, created_at, updated_at,
           json_array_length(report_json, '$.findings') AS finding_count
    FROM analysis_runs
    ORDER BY created_at DESC
    LIMIT 50
  `).all();
  return json({ runs: results });
}

async function getRun(env: Env, id: string): Promise<Response> {
  const row = await env.DB.prepare(`
    SELECT id, owner, repo, requested_ref, commit_sha,
           status, report_json, error_message,
           created_at, updated_at
    FROM analysis_runs
    WHERE id = ?
  `).bind(id).first<{
    report_json: string | null;
    [key: string]: unknown;
  }>();

  if (!row) return json({ error: "Run not found" }, 404);

  const { report_json, ...rest } = row;
  return json({
    ...rest,
    report: report_json ? JSON.parse(report_json) : null,
  });
}

async function getEvents(
  env: Env,
  id: string,
  after: number,
): Promise<Response> {
  const run = await env.DB.prepare(
    "SELECT status FROM analysis_runs WHERE id = ?",
  ).bind(id).first<{ status: string }>();
  if (!run) return json({ error: "Run not found" }, 404);

  // Read status first: events written after this point are picked up
  // on the next poll, so a terminal status never hides trailing events.
  const { results } = await env.DB.prepare(`
    SELECT seq, agent, kind, content, created_at
    FROM agent_events
    WHERE run_id = ? AND seq > ?
    ORDER BY seq
    LIMIT ?
  `).bind(id, after, MAX_EVENTS_PER_POLL).all<AgentEvent>();

  return json({
    status: run.status,
    events: results,
    last: results.length ? results[results.length - 1].seq : after,
  });
}

async function route(
  request: Request,
  env: Env,
  principal: Principal,
): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (method === "POST" && !sameOriginOk(request, principal)) {
    return json({ error: "Cross-origin request rejected" }, 403);
  }

  // Redirect target after installing the GitHub App.
  if (path === "/auth" && method === "GET") {
    const installationId = url.searchParams.get("installation_id");
    if (!installationId || !/^\d+$/.test(installationId)) {
      return new Response("Missing or invalid installation_id", {
        status: 400,
      });
    }
    return new Response(
      `GitHub installation detected: ${installationId}. ` +
        "Configure this ID as GITHUB_INSTALLATION_ID in Cloudflare.",
      { headers: { "content-type": "text/plain; charset=utf-8" } },
    );
  }

  // `/analyze` and `/runs/:id` are kept for existing API clients.
  if (method === "POST" && (path === "/analyze" || path === "/api/runs")) {
    return startRun(request, env);
  }

  if (method === "GET" && path === "/api/runs") return listRuns(env);
  if (method === "GET" && path === "/api/usage") return getUsage(env);

  const events = path.match(new RegExp(`^/api/runs/(${UUID})/events$`, "i"));
  if (method === "GET" && events) {
    const after = Number(url.searchParams.get("after") ?? 0);
    return getEvents(
      env,
      events[1].toLowerCase(),
      Number.isInteger(after) && after >= 0 ? after : 0,
    );
  }

  const run = path.match(new RegExp(`^/(?:api/)?runs/(${UUID})$`, "i"));
  if (method === "GET" && run) return getRun(env, run[1].toLowerCase());

  if (path.startsWith("/api/") || path === "/analyze") {
    return json({ error: "Not found" }, 404);
  }

  if (method === "GET" || method === "HEAD") {
    return env.ASSETS.fetch(request);
  }

  return json({ error: "Method not allowed" }, 405);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const principal = await authenticate(request, env);
      if (!principal) {
        return withSecurityHeaders(
          json({ error: "Unauthorized" }, 401),
        );
      }
      return withSecurityHeaders(await route(request, env, principal));
    } catch (error) {
      console.error("Unhandled error", error);
      return withSecurityHeaders(
        json({ error: "Internal error" }, 500),
      );
    }
  },
} satisfies ExportedHandler<Env>;
