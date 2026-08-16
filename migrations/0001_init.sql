
CREATE TABLE IF NOT EXISTS repos (
  id              TEXT PRIMARY KEY,
  name            TEXT NOT NULL,
  github_url      TEXT NOT NULL UNIQUE,
  snyk_project_id TEXT,
  last_scanned_at INTEGER,
  created_at      INTEGER NOT NULL DEFAULT (unixepoch())
);


CREATE TABLE IF NOT EXISTS scan_runs (
  id            TEXT PRIMARY KEY,
  repo_id       TEXT NOT NULL REFERENCES repos(id),
  triggered_by  TEXT NOT NULL,          
  trigger_type  TEXT NOT NULL DEFAULT 'manual', 
  status        TEXT NOT NULL DEFAULT 'queued',  
  started_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  finished_at   INTEGER,
  vuln_count    INTEGER DEFAULT 0,
  error         TEXT
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
  id              TEXT PRIMARY KEY,
  scan_run_id     TEXT NOT NULL REFERENCES scan_runs(id),
  repo_id         TEXT NOT NULL REFERENCES repos(id),
  github_alert_id INTEGER,
  cve             TEXT,
  title           TEXT NOT NULL,
  severity        TEXT NOT NULL,  
  package_name    TEXT NOT NULL,
  from_version    TEXT NOT NULL,
  to_version      TEXT,          
  fixable         INTEGER NOT NULL DEFAULT 0,  
  fix_pr_url      TEXT,
  source          TEXT NOT NULL DEFAULT 'github',
  created_at      INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_vulns_repo      ON vulnerabilities(repo_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity  ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulns_fixable   ON vulnerabilities(fixable);
CREATE INDEX IF NOT EXISTS idx_scans_repo      ON scan_runs(repo_id);
CREATE INDEX IF NOT EXISTS idx_scans_status    ON scan_runs(status);
