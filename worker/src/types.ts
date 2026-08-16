// [[secrets_store_secrets]] bindings are NOT plain strings.
// CF resolves them as SecretBinding objects — must call await .get() to read value.
export interface SecretBinding {
  get(): Promise<string>;
}

export interface Env {
  DB:          D1Database;
  SCAN_QUEUE:  Queue;

  // Secrets — bound via [[secrets_store_secrets]] in wrangler.toml
  // Usage: const token = await env.GITHUB_TOKEN.get()
  GITHUB_TOKEN:     SecretBinding;
  SONARCLOUD_TOKEN: SecretBinding;
  SONARCLOUD_ORG:   SecretBinding;
  SNYK_API_TOKEN:   SecretBinding;  // NEW
  SNYK_ORG_ID:      SecretBinding;  // NEW

  // Plain vars from [vars] — still regular strings
  FRONTEND_URL: string;
}

export interface Repo {
  id:                string;
  name:              string;
  github_url:        string;
  snyk_project_id:   string | null;   // populated by POST /api/repos/snyk-sync
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
  snyk_issue_id:   string | null;   // NEW — for fix PR lookup
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