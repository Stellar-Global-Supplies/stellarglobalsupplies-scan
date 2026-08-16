const API_URL = import.meta.env.VITE_API_URL as string;

async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error);
  }

  return res.json() as Promise<T>;
}

export const api = {
  repos: {
    list: () => req<{ repos: RepoWithStatus[] }>('GET', '/api/repos'),
    syncFromSnyk: () =>
      req<{ synced: number; inserted: number; updated: number; message: string }>(
        'POST', '/api/repos/sync'
      ),
  },

  scans: {
    scanOne: (repoId: string) =>
      req<{ scan_run_id: string; status: string }>('POST', `/api/scans/repo/${repoId}`),
    scanAll: () =>
      req<{ queued: number; skipped: number; message: string }>('POST', '/api/scans/all'),
    status: (scanRunId: string) =>
      req<{ scan: ScanRun }>('GET', `/api/scans/status/${scanRunId}`),
    history: (repoId: string) =>
      req<{ scans: ScanRun[] }>('GET', `/api/scans/repo/${repoId}`),
  },

  vulns: {
    list: (filters?: { severity?: string; fixable?: string; repo_id?: string }) => {
      const params = new URLSearchParams(filters as Record<string, string>).toString();
      return req<{ vulnerabilities: Vulnerability[] }>('GET', `/api/vulns${params ? `?${params}` : ''}`);
    },
    summary: () => req<{ summary: VulnSummary }>('GET', '/api/vulns/summary'),
    fix: (repoId: string, issueIds: string[]) =>
      req<{ pr_url: string; message: string }>('POST', '/api/vulns/fix', {
        repo_id:   repoId,
        issue_ids: issueIds,
      }),
  },

  // NEW — SonarCloud code quality
  quality: {
    all: () => req<{ quality: CodeQuality[] }>('GET', '/api/quality'),
    history: (repoId: string) => req<{ history: CodeQuality[] }>('GET', `/api/quality/${repoId}/history`),
    sync: () => req<{ found: number; synced: number; message: string }>('POST', '/api/quality/sync'),
  },
};

// ── Types ─────────────────────────────────────────────────────────────────────

export interface RepoWithStatus {
  id:               string;
  name:             string;
  github_url:       string;
  snyk_project_id:  string | null;
  sonar_project_key: string | null;
  last_scanned_at:  number | null;
  latest_scan: {
    status:      string;
    finished_at: number | null;
    vuln_count:  number;
  } | null;
}

export interface ScanRun {
  id:           string;
  repo_id:      string;
  triggered_by: string;
  trigger_type: string;
  status:       'queued' | 'scanning' | 'done' | 'failed';
  started_at:   number;
  finished_at:  number | null;
  vuln_count:   number;
  error:        string | null;
}

export interface Vulnerability {
  id:            string;
  scan_run_id:   string;
  repo_id:       string;
  repo_name?:    string;
  snyk_issue_id: string | null;
  cve:           string | null;
  title:         string;
  severity:      'critical' | 'high' | 'medium' | 'low';
  package_name:  string;
  from_version:  string;
  to_version:    string | null;
  fixable:       number;
  fix_pr_url:    string | null;
  source:        string;
  created_at:    number;
}

export interface VulnSummary {
  critical: number;
  high:     number;
  medium:   number;
  low:      number;
}

// NEW
export interface CodeQuality {
  id:                     string;
  repo_id:                string;
  repo_name?:             string;
  scan_run_id:            string;
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
