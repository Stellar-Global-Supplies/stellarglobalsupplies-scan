// GitHub Security API client — free for public repos
// Uses Dependabot Alerts + Code Scanning Alerts

const GITHUB_API = 'https://api.github.com';

function githubHeaders(token: string): HeadersInit {
  return {
    'Authorization': `Bearer ${token}`,
    'Accept':        'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent':    'scan-worker',
  };
}

export interface GitHubRepo {
  name:       string;
  full_name:  string;
  html_url:   string;
  private:    boolean;
}

export interface GitHubDependabotAlert {
  number:     number;
  state:      string;
  severity:   string;
  html_url:   string;
  created_at: string;
  dependency: {
    package: { name: string; ecosystem: string };
    manifest_path: string;
    scope: string;
  };
  security_advisory: {
    ghsa_id: string;
    cve_id: string | null;
    summary: string;
    severity: string;
    vulnerabilities: Array<{
      package: { name: string; ecosystem: string };
      vulnerable_version_range: string;
      first_patched_version: { identifier: string } | null;
    }>;
  } | null;
  security_vulnerability: {
    package: { name: string; ecosystem: string };
    vulnerable_version_range: string;
    first_patched_version: { identifier: string } | null;
  } | null;
}

export interface GitHubCodeScanningAlert {
  number:     number;
  state:      string;
  severity:   string | null;
  html_url:   string;
  created_at: string;
  rule: {
    id:          string;
    name:        string;
    severity:    string | null;
    description: string;
  };
  tool: { name: string };
  most_recent_instance: {
    location: { path: string };
  };
}

// List all repos in an org (public + private if token has access)
export async function fetchOrgRepos(
  org: string,
  token: string
): Promise<GitHubRepo[]> {
  const repos: GitHubRepo[] = [];
  let page = 1;

  while (true) {
    const url = `${GITHUB_API}/orgs/${org}/repos?per_page=100&page=${page}`;
    const res = await fetch(url, { headers: githubHeaders(token) });

    if (!res.ok) throw new Error(`GitHub repos fetch failed: ${res.status} ${await res.text()}`);

    const body = await res.json<GitHubRepo[]>();
    repos.push(...body);

    if (body.length < 100) break;
    page++;
  }

  return repos;
}

// Fetch Dependabot alerts for a repo (dependency vulnerabilities)
export async function fetchDependabotAlerts(
  owner: string,
  repo: string,
  token: string
): Promise<GitHubDependabotAlert[]> {
  const alerts: GitHubDependabotAlert[] = [];
  let page = 1;

  while (true) {
    const url = `${GITHUB_API}/repos/${owner}/${repo}/dependabot/alerts?per_page=100&page=${page}&state=open`;
    const res = await fetch(url, { headers: githubHeaders(token) });

    if (res.status === 404) {
      // Dependabot not enabled or repo not found — normal, skip silently
      break;
    }
    if (res.status === 403 || res.status === 451) {
      // 403 = token lacks security_events scope or Dependabot not enabled at org level
      // 451 = unavailable for legal reasons / GHES restriction
      const body = await res.text();
      throw new Error(`Dependabot alerts blocked (HTTP ${res.status}): ${body}`);
    }
    if (!res.ok) {
      const body = await res.text();
      throw new Error(`Dependabot alerts failed (HTTP ${res.status}): ${body}`);
    }

    const body = await res.json<GitHubDependabotAlert[]>();
    alerts.push(...body);

    if (body.length < 100) break;
    page++;
  }

  return alerts;
}

// Fetch Code Scanning alerts for a repo (SAST vulnerabilities)
export async function fetchCodeScanningAlerts(
  owner: string,
  repo: string,
  token: string
): Promise<GitHubCodeScanningAlert[]> {
  const alerts: GitHubCodeScanningAlert[] = [];
  let page = 1;

  while (true) {
    const url = `${GITHUB_API}/repos/${owner}/${repo}/code-scanning/alerts?per_page=100&page=${page}&state=open`;
    const res = await fetch(url, { headers: githubHeaders(token) });

    if (res.status === 404) {
      // Code scanning not enabled for this repo — normal, skip silently
      break;
    }
    if (res.status === 403 || res.status === 451) {
      // 403 = token lacks security_events scope or Advanced Security not enabled
      // 451 = unavailable for legal reasons / GHES restriction
      const body = await res.text();
      throw new Error(`Code scanning alerts blocked (HTTP ${res.status}): ${body}`);
    }
    if (!res.ok) {
      const body = await res.text();
      throw new Error(`Code scanning alerts failed (HTTP ${res.status}): ${body}`);
    }

    const body = await res.json<GitHubCodeScanningAlert[]>();
    alerts.push(...body);

    if (body.length < 100) break;
    page++;
  }

  return alerts;
}

// Parse a Dependabot alert into our DB shape
export function parseDependabotAlert(alert: GitHubDependabotAlert) {
  const vuln = alert.security_vulnerability ?? alert.security_advisory?.vulnerabilities?.[0] ?? null;
  const advisory = alert.security_advisory;

  return {
    github_alert_id: alert.number,
    cve:            advisory?.cve_id ?? null,
    title:          advisory?.summary ?? `Dependency vulnerability in ${vuln?.package.name ?? 'unknown'}`,
    severity:       (alert.severity ?? advisory?.severity ?? 'medium') as 'critical' | 'high' | 'medium' | 'low',
    package_name:   vuln?.package.name ?? 'unknown',
    from_version:   vuln?.vulnerable_version_range ?? 'unknown',
    to_version:     vuln?.first_patched_version?.identifier ?? null,
    fixable:        vuln?.first_patched_version ? 1 : 0,
    source:         'github_dependabot',
  };
}

// Parse a Code Scanning alert into our DB shape
export function parseCodeScanningAlert(alert: GitHubCodeScanningAlert) {
  return {
    github_alert_id: alert.number,
    cve:            null,
    title:          alert.rule.description || alert.rule.name,
    severity:       (alert.severity ?? alert.rule.severity ?? 'medium') as 'critical' | 'high' | 'medium' | 'low',
    package_name:   alert.rule.name,
    from_version:   alert.most_recent_instance?.location?.path ?? 'unknown',
    to_version:     null,
    fixable:        0,
    source:         'github_code_scanning',
  };
}