// Each [[secrets_store_secrets]] binding lands directly as a string on env.*
// No .get() call needed — CF resolves them before the Worker runs
export interface Env {
  DB:           D1Database;
  SCAN_QUEUE:   Queue;

  // Secrets — bound individually via [[secrets_store_secrets]] in wrangler.toml
  GITHUB_TOKEN:        string;
  SONARCLOUD_TOKEN:    string;
  SONARCLOUD_ORG:      string;

  // Non-secret vars from [vars]
  FRONTEND_URL: string;
}

export interface Repo {
  id:                string;
  name:              string;
  github_url:        string;
  sonar_project_key: string | null;
  last_scanned_at:   number | null;
  created_at:        number;
}

export interface ScanRun {
  id:           string;
  repo_id:      string;
  triggered_by: string;
  trigger_type: 'manual' | 'cron';
  status:       'queued' | 'scanning' | 'done' | 'failed';
  started_at:   number;
  finished_at:  number | null;
  vuln_count:   number;
  error:        string | null;
}

export interface Vulnerability {
  id:              string;
  scan_run_id:     string;
  repo_id:         string;
  github_alert_id: number | null;
  cve:             string | null;
  title:           string;
  severity:        'critical' | 'high' | 'medium' | 'low';
  package_name:    string;
  from_version:    string;
  to_version:      string | null;
  fixable:         number;
  fix_pr_url:      string | null;
  source:          string;
  created_at:      number;
}

export interface CodeQuality {
  id:                     string;
  repo_id:                string;
  scan_run_id:            string;
  source:                 string;
  sonar_project_key:      string;
  reliability_rating:     string | null;
  maintainability_rating: string | null;
  security_rating:        string | null;
  code_smells:            number | null;
  duplicated_lines_pct:   number | null;
  complexity:             number | null;
  cognitive_complexity:   number | null;
  coverage_pct:           number | null;
  lines_of_code:          number | null;
  security_hotspots:      number | null;
  technical_debt_mins:    number | null;
  created_at:             number;
}

export interface QueueMessage {
  type:            'scan_repo';
  repo_id:         string;
  scan_run_id:     string;
  triggered_by:    string;
}

export interface JWTPayload {
  sub:   string;
  email: string;
  role:  string;
  exp:   number;
  iat:   number;
}
