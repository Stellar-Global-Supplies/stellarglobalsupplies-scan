// Snyk API client
// Free tier on PUBLIC repos: unlimited scans, Snyk Code, Fix PRs — all available

const SNYK_REST = 'https://api.snyk.io/rest';
const SNYK_V1   = 'https://api.snyk.io/v1';
const SNYK_VER  = '2024-10-15';  // Updated to a stable GA version

function headers(token: string, isRest = false): HeadersInit {
  const base: Record<string, string> = {
    'Authorization': `token ${token}`,
    'Content-Type':  'application/json',
  };
  // REST API also accepts a version header (belt-and-suspenders alongside query param)
  if (isRest) base['snyk-version'] = SNYK_VER;
  return base;
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

// Fetch all active projects in your Snyk org using the REST API.
// The v1 /org/:id/projects endpoint is fully deprecated — returns 410 Gone.
// The REST API uses the same "token <value>" Authorization header.
export async function fetchSnykProjects(
  orgId: string,
  token: string
): Promise<SnykProject[]> {

  const allData: Array<{
    id: string;
    attributes: { name: string; origin: string; remoteRepoUrl?: string };
  }> = [];

  // REST API uses cursor-based pagination via links.next
  let nextUrl: string | null =
    `${SNYK_REST}/orgs/${orgId}/projects?version=${SNYK_VER}&limit=100&status=active`;

  while (nextUrl) {
    const res = await fetch(nextUrl, { headers: headers(token, true) });
    if (!res.ok) throw new Error(`Snyk projects fetch failed: ${res.status} ${await res.text()}`);

    const body = await res.json<{
      data: Array<{
        id: string;
        attributes: { name: string; origin: string; remoteRepoUrl?: string };
      }>;
      links?: { next?: string };
    }>();

    allData.push(...(body.data ?? []));
    nextUrl = body.links?.next ?? null;
  }

  const projects: SnykProject[] = [];

  for (const p of allData) {
    // Only keep GitHub-backed projects
    if (p.attributes.origin !== 'github') continue;

    // remoteRepoUrl is the canonical GitHub HTTPS URL Snyk stores
    let githubUrl = (p.attributes.remoteRepoUrl ?? '').replace(/\.git$/, '');
    if (!githubUrl.includes('github.com')) continue;

    // Normalise SSH → HTTPS just in case
    if (githubUrl.startsWith('git@github.com:')) {
      githubUrl = 'https://github.com/' + githubUrl.slice('git@github.com:'.length);
    }

    // Project name is usually "org/repo:manifest" — strip to just the repo slug
    const repoName = p.attributes.name.split(':')[0].split('/').pop() ?? p.attributes.name;

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
  // v1 issues endpoint — still works with legacy tokens, returns vuln + license issues
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