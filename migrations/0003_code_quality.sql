-- Add SonarCloud project key to repos table
ALTER TABLE repos ADD COLUMN sonar_project_key TEXT;

CREATE TABLE IF NOT EXISTS code_quality (
  id                     TEXT PRIMARY KEY,
  repo_id                TEXT NOT NULL REFERENCES repos(id),
  scan_run_id            TEXT NOT NULL REFERENCES scan_runs(id),
  source                 TEXT NOT NULL DEFAULT 'sonarcloud',
  sonar_project_key      TEXT NOT NULL,
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

CREATE INDEX IF NOT EXISTS idx_quality_repo   ON code_quality(repo_id);
CREATE INDEX IF NOT EXISTS idx_quality_created ON code_quality(created_at);
