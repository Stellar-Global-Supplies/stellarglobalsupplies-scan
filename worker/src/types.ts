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
  GITHUB_TOKEN: SecretBinding;

  // Plain vars from [vars] — still regular strings
  FRONTEND_URL: string;
}

export interface Repo {
  id:              string;
  name:            string;
  github_url:      string;
  last_scanned_at: number | null;
  created_at:      number;
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
  source:          string;  // 'github_dependabot' | 'github_code_scanning'
  created_at:      number;
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