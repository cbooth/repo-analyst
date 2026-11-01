CREATE TABLE IF NOT EXISTS analysis_runs (
  id TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  repo TEXT NOT NULL,
  requested_ref TEXT,
  commit_sha TEXT,
  status TEXT NOT NULL,
  report_json TEXT,
  error_message TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_analysis_runs_repo
ON analysis_runs(owner, repo, created_at);

-- Live feed of each agent's reasoning/output, tailed by the UI.
CREATE TABLE IF NOT EXISTS agent_events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  agent TEXT NOT NULL,
  kind TEXT NOT NULL,
  content TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_agent_events_run
ON agent_events(run_id, seq);

CREATE INDEX IF NOT EXISTS idx_analysis_runs_created
ON analysis_runs(created_at);


-- Workers AI spend recorded by this app, for the daily neuron meter.
CREATE TABLE IF NOT EXISTS ai_usage (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  agent TEXT NOT NULL,
  model TEXT NOT NULL,
  neurons REAL NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ai_usage_created
ON ai_usage(created_at);
