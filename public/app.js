// All dynamic text is inserted with textContent: agent output derives from
// untrusted repository content and must never be parsed as HTML.

const LANES = [
  "system", "triage", "security", "correctness", "architecture", "testing",
  "infrastructure", "secrets", "dependencies", "verifier", "synthesis",
];
const TERMINAL = new Set(["completed", "failed"]);
const POLL_MS = 1000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const $ = (id) => document.getElementById(id);

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

let currentId = null;
let cursor = 0;
let lanes = new Map();
let pollTimer = null;
let pollToken = 0;

function setConn(ok, text) {
  const conn = $("conn");
  conn.textContent = text;
  conn.className = "conn " + (ok ? "live" : "bad");
}

function showBanner(message) {
  const banner = $("banner");
  banner.textContent = message;
  banner.hidden = !message;
}

async function api(path, options) {
  let response;
  try {
    response = await fetch(path, {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
      ...options,
    });
  } catch {
    // An expired Access session redirects cross-origin, which fetch
    // reports as a network error.
    setConn(false, "offline");
    showBanner("Cannot reach the server. If your session expired, reload the page.");
    throw new Error("network");
  }

  if (response.status === 401 || response.status === 403) {
    setConn(false, "access denied");
    showBanner("Access denied or session expired. Reload the page to sign in again.");
    throw new Error("denied");
  }

  setConn(true, "live");
  showBanner("");
  return response;
}

/* ---------- neuron meter ---------- */

async function refreshUsage() {
  try {
    const response = await api("/api/usage");
    const { used, limit, resetsAt } = await response.json();
    const meter = $("meter");
    if (used === null) {
      meter.hidden = true;
      return;
    }
    const fraction = Math.min(1, used / limit);
    const bar = $("meter-bar");
    bar.max = limit;
    bar.value = Math.min(used, limit);
    $("meter-text").textContent =
      `Neurons today: ${Math.round(used).toLocaleString()} / ${limit.toLocaleString()}`;
    meter.title =
      "Workers AI spend recorded by this app since tracking began (UTC day). " +
      "Other uses of your account are not counted. Resets " +
      new Date(resetsAt).toLocaleTimeString() + ".";
    meter.classList.toggle("warn", fraction >= 0.7 && fraction < 0.9);
    meter.classList.toggle("bad", fraction >= 0.9);
    meter.hidden = false;
  } catch {
    /* banner already shown */
  }
}

/* ---------- runs list ---------- */

function relativeTime(iso) {
  const seconds = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
  if (seconds < 60) return "just now";
  if (seconds < 3600) return Math.floor(seconds / 60) + "m ago";
  if (seconds < 86400) return Math.floor(seconds / 3600) + "h ago";
  return Math.floor(seconds / 86400) + "d ago";
}

async function refreshRuns() {
  try {
    const response = await api("/api/runs");
    const { runs } = await response.json();
    const list = $("runs");
    list.replaceChildren();
    $("no-runs").hidden = runs.length > 0;

    for (const run of runs) {
      const button = el("button");
      button.type = "button";
      button.setAttribute("aria-current", String(run.id === currentId));
      button.append(
        el("span", "name", `${run.owner}/${run.repo}`),
        el(
          "span",
          "sub",
          `${run.status}${run.finding_count != null ? ` · ${run.finding_count} findings` : ""} · ${relativeTime(run.created_at)}`,
        ),
      );
      button.addEventListener("click", () => selectRun(run.id));
      const item = el("li");
      item.append(button);
      list.append(item);
    }
  } catch {
    /* banner already shown */
  }
}

/* ---------- live feed ---------- */

function buildFeed() {
  const feed = $("feed");
  feed.replaceChildren();
  lanes = new Map();

  for (const name of LANES) {
    const lane = el("section", "lane empty-lane");
    const state = el("span", "state", "idle");
    const header = el("header");
    header.append(el("span", "", name), state);
    const body = el("div", "body");
    lane.append(header, body);
    feed.append(lane);
    lanes.set(name, { lane, state, body, lastKind: null, lastEl: null });
  }
}

function setLaneState(lane, kind, content) {
  let label = "working";
  let cls = "working";
  if (kind === "error") [label, cls] = ["failed", "error"];
  else if (kind === "status" && content.startsWith("Finished")) [label, cls] = ["done", "done"];
  else if (kind === "status" && content.startsWith("Skipped")) [label, cls] = ["skipped", "done"];
  else if (kind === "status" && content.startsWith("Report complete")) [label, cls] = ["done", "done"];

  lane.state.textContent = label;
  lane.lane.classList.remove("working", "done", "error", "empty-lane");
  lane.lane.classList.add(cls);
}

function applyEvent(event) {
  const lane = lanes.get(event.agent);
  if (!lane) return;

  const body = lane.body;
  const stick = body.scrollHeight - body.scrollTop - body.clientHeight < 40;

  const streaming = event.kind === "thinking" || event.kind === "output";
  if (streaming && lane.lastKind === event.kind && lane.lastEl) {
    lane.lastEl.textContent += event.content;
  } else {
    const seg = el("div", "seg " + event.kind, event.content);
    body.append(seg);
    lane.lastEl = seg;
  }
  lane.lastKind = event.kind;

  setLaneState(lane, event.kind, event.content);
  if (stick) body.scrollTop = body.scrollHeight;
}

/* ---------- report ---------- */

function renderReport(run) {
  const box = $("report");
  box.replaceChildren();
  box.className = "card";

  if (run.status === "failed") {
    box.append(el("p", "error", run.error_message || "The run failed."));
    return;
  }
  if (!run.report) {
    box.className = "card muted";
    box.textContent = "Waiting for the agents to finish…";
    return;
  }

  const report = run.report;
  const synthesis = report.synthesis;

  if (synthesis) {
    const overview = el("section", "synthesis");
    overview.append(el("h4", "", "Overview"), el("p", "", synthesis.overview));
    if (synthesis.priorities.length) {
      const list = el("ol", "priorities");
      for (const p of synthesis.priorities) {
        const item = el("li");
        const refs = p.findingIndexes.map((i) => "#" + (i + 1)).join(", ");
        item.append(el("strong", "", p.action));
        if (p.why) item.append(el("span", "", " — " + p.why));
        if (refs) item.append(el("span", "muted", ` (${refs})`));
        list.append(item);
      }
      overview.append(el("h4", "", "Fix first"), list);
    }
    box.append(overview);
  }

  box.append(el("p", "", report.summary));
  box.append(
    el(
      "p",
      "muted",
      `${report.filesInspected} files inspected, ${report.filesSkipped} skipped.` +
        (report.verified ? " Findings were checked by a second-pass reviewer." : ""),
    ),
  );

  report.findings.forEach((f, i) => {
    const item = el("article", "finding");
    const tags = el("div", "tags");
    tags.append(
      el("span", "tag " + f.severity, f.severity),
      el("span", "tag", f.category),
      el("span", "tag", `confidence ${Math.round(f.confidence * 100)}%`),
    );
    if (f.verification) {
      tags.append(el("span", "tag " + f.verification, f.verification));
    }
    const where = el("p");
    where.append(el("code", "", `${f.file}:${f.startLine}${f.endLine !== f.startLine ? "-" + f.endLine : ""}`));
    item.append(
      el("h4", "", `#${i + 1} ${f.title}`),
      tags,
      where,
      el("pre", "", f.evidence),
      el("p", "", f.explanation),
      el("p", "", "Fix: " + f.recommendation),
    );
    if (f.verifierNote) item.append(el("p", "muted", "Reviewer: " + f.verifierNote));
    box.append(item);
  });

  if (report.dismissed && report.dismissed.length) {
    const details = el("details", "dismissed");
    details.append(el("summary", "", `${report.dismissed.length} dismissed by the reviewer`));
    for (const d of report.dismissed) {
      const row = el("p");
      row.append(
        el("strong", "", d.title),
        el("span", "muted", ` — ${d.file}:${d.startLine}. `),
        el("span", "", d.reason),
      );
      details.append(row);
    }
    box.append(details);
  }
}

/* ---------- run selection and polling ---------- */

function renderHead(run) {
  $("run-title").textContent = `${run.owner}/${run.repo}`;
  $("run-meta").textContent =
    `Ref: ${run.requested_ref || "default branch"}` +
    (run.commit_sha ? ` · ${run.commit_sha.slice(0, 12)}` : "") +
    ` · started ${relativeTime(run.created_at)}`;
  setStatus(run.status);
}

function setStatus(status) {
  const badge = $("run-status");
  badge.textContent = status;
  badge.className = "badge " + status;
}

async function selectRun(id) {
  if (!UUID.test(id)) return;

  clearTimeout(pollTimer);
  const token = ++pollToken;
  currentId = id;
  cursor = 0;
  location.hash = id;

  $("empty").hidden = true;
  $("run").hidden = false;
  $("report").className = "card muted";
  $("report").textContent = "Waiting for the agents to finish…";
  buildFeed();

  try {
    const response = await api(`/api/runs/${id}`);
    if (!response.ok) throw new Error("not found");
    const run = await response.json();
    if (token !== pollToken) return;
    renderHead(run);
    renderReport(run);
  } catch {
    if (token !== pollToken) return;
    $("run-title").textContent = "Run not found";
    $("run-meta").textContent = "";
    return;
  }

  poll(token);
  refreshRuns();
}

async function poll(token) {
  if (token !== pollToken) return;

  try {
    const response = await api(`/api/runs/${currentId}/events?after=${cursor}`);
    if (!response.ok) throw new Error("bad response");
    const data = await response.json();
    if (token !== pollToken) return;

    for (const event of data.events) applyEvent(event);
    cursor = data.last;
    setStatus(data.status);

    // A full page means more events are waiting; keep draining.
    const caughtUp = data.events.length < 500;
    if (TERMINAL.has(data.status) && caughtUp) {
      const runResponse = await api(`/api/runs/${currentId}`);
      const run = await runResponse.json();
      if (token !== pollToken) return;
      renderHead(run);
      renderReport(run);
      refreshRuns();
      refreshUsage();
      return;
    }

    pollTimer = setTimeout(() => poll(token), caughtUp ? POLL_MS : 0);
  } catch {
    pollTimer = setTimeout(() => poll(token), 4000);
  }
}

/* ---------- new run form ---------- */

$("new-run").addEventListener("submit", async (submit) => {
  submit.preventDefault();
  const form = submit.currentTarget;
  const button = $("start");
  const error = $("form-error");
  error.hidden = true;
  button.disabled = true;

  const data = new FormData(form);
  const payload = {
    owner: String(data.get("owner")).trim(),
    repo: String(data.get("repo")).trim(),
  };
  const ref = String(data.get("ref") || "").trim();
  if (ref) payload.ref = ref;

  try {
    const response = await api("/api/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(payload),
    });
    const body = await response.json();
    if (!response.ok) {
      error.textContent = body.error || "Could not start the run.";
      error.hidden = false;
      return;
    }
    await selectRun(body.runId);
  } catch {
    /* banner already shown */
  } finally {
    button.disabled = false;
  }
});

/* ---------- boot ---------- */

window.addEventListener("hashchange", () => {
  const id = location.hash.slice(1);
  if (UUID.test(id) && id !== currentId) selectRun(id);
});

refreshRuns();
refreshUsage();
setInterval(refreshRuns, 10000);
setInterval(refreshUsage, 30000);

const initial = location.hash.slice(1);
if (UUID.test(initial)) selectRun(initial);
