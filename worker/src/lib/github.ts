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
// ── Quality data from GitHub REST API ────────────────────────────────────────

export interface GitHubRepoMeta {
  name:              string;
  full_name:         string;
  html_url:          string;
  open_issues_count: number;   // proxy for code_smells
  size:              number;   // KB on disk
  language:          string | null;
  forks_count:       number;
  stargazers_count:  number;
  default_branch:    string;
}

// Fetch basic repo metadata (open issues count, size, language, etc.)
export async function fetchRepoMeta(
  owner: string,
  repo: string,
  token: string
): Promise<GitHubRepoMeta> {
  const res = await fetch(`${GITHUB_API}/repos/${owner}/${repo}`, {
    headers: githubHeaders(token),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Repo meta failed (HTTP ${res.status}): ${body}`);
  }
  return res.json<GitHubRepoMeta>();
}

// Fetch language breakdown → { TypeScript: 12345, JavaScript: 678, ... } (bytes)
// We sum all values to get total lines-of-code proxy (bytes ÷ 35 ≈ lines)
export async function fetchRepoLanguages(
  owner: string,
  repo: string,
  token: string
): Promise<Record<string, number>> {
  const res = await fetch(`${GITHUB_API}/repos/${owner}/${repo}/languages`, {
    headers: githubHeaders(token),
  });
  if (!res.ok) return {};
  return res.json<Record<string, number>>();
}

// ── Derive A–E quality ratings from GitHub alert counts ───────────────────────
//
// Rating logic (thresholds chosen to match SonarCloud's spirit):
//
//  security_rating     ← code scanning alert count (SAST)
//    A = 0 alerts
//    B = 1–2
//    C = 3–5
//    D = 6–10
//    E = 11+
//
//  reliability_rating  ← dependabot critical/high count
//    A = 0
//    B = 1
//    C = 2–3
//    D = 4–6
//    E = 7+
//
//  maintainability_rating ← open issues count (proxy for code debt)
//    A = 0–2
//    B = 3–10
//    C = 11–25
//    D = 26–50
//    E = 51+

function toSecurityRating(codeScanCount: number): string {
  if (codeScanCount === 0)   return 'A';
  if (codeScanCount <= 2)    return 'B';
  if (codeScanCount <= 5)    return 'C';
  if (codeScanCount <= 10)   return 'D';
  return 'E';
}

function toReliabilityRating(critHighDepbotCount: number): string {
  if (critHighDepbotCount === 0) return 'A';
  if (critHighDepbotCount === 1) return 'B';
  if (critHighDepbotCount <= 3)  return 'C';
  if (critHighDepbotCount <= 6)  return 'D';
  return 'E';
}

function toMaintainabilityRating(openIssues: number): string {
  if (openIssues <= 2)  return 'A';
  if (openIssues <= 10) return 'B';
  if (openIssues <= 25) return 'C';
  if (openIssues <= 50) return 'D';
  return 'E';
}

export interface DerivedQualityMetrics {
  reliability_rating:     string;
  maintainability_rating: string;
  security_rating:        string;
  code_smells:            number;   // = open_issues_count
  lines_of_code:          number;   // derived from language bytes ÷ 35
  security_hotspots:      number;   // = code scanning alert count
  technical_debt_mins:    number;   // = open_issues_count × 30 min estimate
  // Fields we can't derive from GitHub free APIs — left null
  duplicated_lines_pct:   null;
  complexity:             null;
  cognitive_complexity:   null;
  coverage_pct:           null;
}

export function deriveQualityMetrics(
  meta:            GitHubRepoMeta,
  languageBytes:   Record<string, number>,
  dependabotAlerts: { severity: string }[],
  codeScanAlerts:   unknown[]
): DerivedQualityMetrics {
  const critHigh = dependabotAlerts.filter(
    a => a.severity === 'critical' || a.severity === 'high'
  ).length;

  const totalBytes  = Object.values(languageBytes).reduce((s, b) => s + b, 0);
  const linesOfCode = Math.round(totalBytes / 35); // bytes ÷ avg chars-per-line

  return {
    reliability_rating:     toReliabilityRating(critHigh),
    maintainability_rating: toMaintainabilityRating(meta.open_issues_count),
    security_rating:        toSecurityRating(codeScanAlerts.length),
    code_smells:            meta.open_issues_count,
    lines_of_code:          linesOfCode,
    security_hotspots:      codeScanAlerts.length,
    technical_debt_mins:    meta.open_issues_count * 30,
    duplicated_lines_pct:   null,
    complexity:             null,
    cognitive_complexity:   null,
    coverage_pct:           null,
  };
}