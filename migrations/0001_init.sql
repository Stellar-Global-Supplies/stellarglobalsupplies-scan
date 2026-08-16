
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

-- Migration 0004: create code_quality table for GitHub-sourced data
-- Replaces the SonarCloud-oriented 0003 schema intent.
-- The sonar_project_key column is kept for schema compat but now stores
-- the GitHub repo slug (e.g. "stellarglobalsupplies-scan").
 
CREATE TABLE IF NOT EXISTS code_quality (
  id                     TEXT PRIMARY KEY,
  repo_id                TEXT NOT NULL REFERENCES repos(id),
  scan_run_id            TEXT NOT NULL REFERENCES scan_runs(id),
  source                 TEXT NOT NULL DEFAULT 'github_code_scanning',
  sonar_project_key      TEXT NOT NULL DEFAULT '',  
  reliability_rating     TEXT,
  maintainability_rating TEXT,
  security_rating        TEXT,
  code_smells            INTEGER,
  duplicated_lines_pct   REAL,
  complexity             INTEGER,
  cognitive_complexity   INTEGER,
  coverage_pct           REAL,
  lines_of_code          INTEGER,
  security_hotspots      INTEGER,
  technical_debt_mins    INTEGER,
 
  created_at             INTEGER NOT NULL DEFAULT (unixepoch())
);
 
CREATE INDEX IF NOT EXISTS idx_quality_repo    ON code_quality(repo_id);
CREATE INDEX IF NOT EXISTS idx_quality_created ON code_quality(created_at);
 
-- Drop the old SonarCloud column if it exists from migration 0003
-- (safe no-op if column was never added)
-- SQLite doesn't support DROP COLUMN in older versions, so we leave
-- sonar_project_key in place and repurpose it as the GitHub slug field.

-- Migration 0004: create code_quality table for GitHub-sourced data
-- Replaces the SonarCloud-oriented 0003 schema intent.
-- The sonar_project_key column is kept for schema compat but now stores
-- the GitHub repo slug (e.g. "stellarglobalsupplies-scan").
 
CREATE TABLE IF NOT EXISTS code_quality (
  id                     TEXT PRIMARY KEY,
  repo_id                TEXT NOT NULL REFERENCES repos(id),
  scan_run_id            TEXT NOT NULL REFERENCES scan_runs(id),
  source                 TEXT NOT NULL DEFAULT 'github_code_scanning',
  sonar_project_key      TEXT NOT NULL DEFAULT '',   

  reliability_rating     TEXT,
  maintainability_rating TEXT,
  security_rating        TEXT,
 

  code_smells            INTEGER,
  duplicated_lines_pct   REAL,
  complexity             INTEGER,
  cognitive_complexity   INTEGER,
  coverage_pct           REAL,
  lines_of_code          INTEGER,
  security_hotspots      INTEGER,
  technical_debt_mins    INTEGER,
 
  created_at             INTEGER NOT NULL DEFAULT (unixepoch())
);
 
CREATE INDEX IF NOT EXISTS idx_quality_repo    ON code_quality(repo_id);
CREATE INDEX IF NOT EXISTS idx_quality_created ON code_quality(created_at);
 
-- Drop the old SonarCloud column if it exists from migration 0003
-- (safe no-op if column was never added)
-- SQLite doesn't support DROP COLUMN in older versions, so we leave
-- sonar_project_key in place and repurpose it as the GitHub slug field.