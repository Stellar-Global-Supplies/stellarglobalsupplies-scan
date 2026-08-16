// Snyk API client
// Free tier on PUBLIC repos: unlimited scans, Snyk Code, Fix PRs — all available

const SNYK_REST = 'https://api.snyk.io/rest';
const SNYK_V1   = 'https://api.snyk.io/v1';
const SNYK_VER  = '2024-01-23';

function headers(token: string): HeadersInit {
  return {
    'Authorization': `token ${token}`,
    'Content-Type':  'application/json',
  };
}

// ── Types ─────────────────────────────────────────────────────────────────────

export interface SnykProject {
  snykProjectId: string;
  name:          string;
  githubUrl:     string;
}

// v1 API issue shape (used by POST /org/:id/project/:id/issues)
export interface SnykIssue {
  issueId:   string;
  pkgName:   string;
  pkgVersion: string;
  issueData: {
    id:          string;
    title:       string;
    severity:    string;
    cvssScore:   number;
    identifiers: { CVE?: string[]; CWE?: string[] };
    isUpgradable: boolean;
    isPatchable:  boolean;
  };
  fixInfo: {
    upgradePaths: Array<{ isUpgradable: boolean; upgradeTo?: string }>;
    isPatchable:  boolean;
    isUpgradable: boolean;
    nearestFixedInVersion?: string;
  };
}

// ── Projects ──────────────────────────────────────────────────────────────────

// Fetch all active projects already in your Snyk org using the v1 API.
// The v1 GET /org/:id/projects endpoint was deprecated and returns 410 Gone.
// The correct call is POST /org/:id/projects (with empty JSON body).
// The REST API (api.snyk.io/rest) returns 403 for legacy API tokens on project
// listing. The v1 POST endpoint works with all token types including legacy tokens.
export async function fetchSnykProjects(
  orgId: string,
  token: string
): Promise<SnykProject[]> {
  // v1 list-projects endpoint — POST with empty body, works with all token types
  // NOTE: GET was deprecated (returns 410); POST is the correct method.
  const url = `${SNYK_V1}/org/${orgId}/projects`;
  const res  = await fetch(url, {
    method:  'POST',
    headers: headers(token),
    body:    JSON.stringify({}),
  });
  if (!res.ok) throw new Error(`Snyk projects fetch failed: ${res.status} ${await res.text()}`);

  const body = await res.json<{
    projects: Array<{
      id:            string;
      name:          string;
      origin:        string;
      remoteRepoUrl?: string;
    }>;
  }>();

  const projects: SnykProject[] = [];

  for (const p of body.projects) {
    // Only keep GitHub-backed projects
    if (p.origin !== 'github') continue;

    // remoteRepoUrl is the canonical GitHub HTTPS URL Snyk stores
    let githubUrl = (p.remoteRepoUrl ?? '').replace(/\.git$/, '');
    if (!githubUrl.includes('github.com')) continue;

    // Normalise SSH → HTTPS just in case
    if (githubUrl.startsWith('git@github.com:')) {
      githubUrl = 'https://github.com/' + githubUrl.slice('git@github.com:'.length);
    }

    // Project name is usually "org/repo:manifest" — strip to just the repo slug
    const repoName = p.name.split(':')[0].split('/').pop() ?? p.name;

    projects.push({ snykProjectId: p.id, name: repoName, githubUrl });
  }

  // Deduplicate by githubUrl — one repo can have multiple Snyk projects
  // (e.g. package.json + Dockerfile). Keep first (root manifest).
  const seen = new Map<string, SnykProject>();
  for (const p of projects) {
    if (!seen.has(p.githubUrl)) seen.set(p.githubUrl, p);
  }
  return [...seen.values()];
}

// ── Issues ────────────────────────────────────────────────────────────────────

// Fetch all open issues for a Snyk project (handles pagination)
export async function fetchSnykIssues(
  orgId: string,
  token: string,
  projectId: string
): Promise<SnykIssue[]> {
  const issues: SnykIssue[] = [];
  // v1 issues endpoint — works with legacy tokens, returns vuln + license issues
  const url = `${SNYK_V1}/org/${orgId}/project/${projectId}/issues`;
  const res  = await fetch(url, {
    method:  'POST',
    headers: headers(token),
    body:    JSON.stringify({ filters: { severities: ['critical','high','medium','low'], types: ['vuln'], ignored: false, patched: false } }),
  });
  if (!res.ok) throw new Error(`Snyk issues fetch failed: ${res.status} ${await res.text()}`);

  const body = await res.json<{ issues: { vulnerabilities: SnykIssue[] } }>();
  issues.push(...(body.issues?.vulnerabilities ?? []));

  return issues;
}

// ── Fix PR ────────────────────────────────────────────────────────────────────

// Trigger a Snyk fix PR on GitHub for one or more issue IDs
// Free on public repos — opens a GitHub PR bumping affected packages
export async function createSnykFixPR(
  orgId: string,
  token: string,
  projectId: string,
  issueIds: string[]
): Promise<{ id: string; url: string }> {
  const res = await fetch(`${SNYK_V1}/org/${orgId}/project/${projectId}/fix`, {
    method:  'POST',
    headers: headers(token),
    body:    JSON.stringify({ type: 'upgrade', issueIds }),
  });
  if (!res.ok) throw new Error(`Snyk fix PR failed: ${res.status} ${await res.text()}`);
  return res.json<{ id: string; url: string }>();
}

// ── Parser ────────────────────────────────────────────────────────────────────

export function parseSnykIssue(issue: SnykIssue) {
  const cve       = issue.issueData.identifiers?.CVE?.[0] ?? null;
  const fixable   = issue.fixInfo.isUpgradable || issue.fixInfo.isPatchable ? 1 : 0;
  const toVersion = issue.fixInfo.nearestFixedInVersion
    ?? issue.fixInfo.upgradePaths?.[0]?.upgradeTo
    ?? null;

  return {
    snyk_issue_id: issue.issueId,
    cve,
    title:        issue.issueData.title,
    severity:     issue.issueData.severity as 'critical' | 'high' | 'medium' | 'low',
    package_name: issue.pkgName,
    from_version: issue.pkgVersion,
    to_version:   toVersion,
    fixable,
    source:       'snyk',
  };
}