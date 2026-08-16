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
    // Pull latest repos from GitHub org into D1
    syncFromGitHub: () =>
      req<{ synced: number; inserted: number; updated: number; message: string }>(
        'POST', '/api/repos/sync'
      ),
  },

  scans: {
    scanOne: (repoId: string) =>
      req<{ scan_run_id: string; status: string }>('POST', `/api/scans/repo/${repoId}`),
    scanAll: () =>
      req<{ queued: number; message: string }>('POST', '/api/scans/all'),
    status: (scanRunId: string) =>
      req<{ scan: ScanRun }>('GET', `/api/scans/status/${scanRunId}`),
    history: (repoId: string) =>
      req<{ scans: ScanRun[] }>('GET', `/api/scans/repo/${repoId}`),
  },

  vulns: {
    list: (filters?: { severity?: string; fixable?: string; repo_id?: string; source?: string }) => {
      const params = new URLSearchParams(
        Object.fromEntries(Object.entries(filters ?? {}).filter(([, v]) => v)) as Record<string, string>
      ).toString();
      return req<{ vulnerabilities: Vulnerability[] }>('GET', `/api/vulns${params ? `?${params}` : ''}`);
    },
    summary: () => req<{ summary: VulnSummary }>('GET', '/api/vulns/summary'),
  },
};

// ── Types ─────────────────────────────────────────────────────────────────────

export interface RepoWithStatus {
  id:              string;
  name:            string;
  github_url:      string;
  last_scanned_at: number | null;
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
  id:           string;
  scan_run_id:  string;
  repo_id:      string;
  repo_name?:   string;
  cve:          string | null;
  title:        string;
  severity:     'critical' | 'high' | 'medium' | 'low';
  package_name: string;
  from_version: string;
  to_version:   string | null;
  fixable:      number;
  source:       string;  // 'github_dependabot' | 'github_code_scanning'
  created_at:   number;
}

export interface VulnSummary {
  critical: number;
  high:     number;
  medium:   number;
  low:      number;
}