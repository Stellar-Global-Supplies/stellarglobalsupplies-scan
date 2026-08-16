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

export interface SnykIssue {
  id: string;
  attributes: {
    title:    string;
    severity: string;
    status:   string;
    coordinates: Array<{
      representations: Array<{
        dependency?: { package_name: string; package_version: string };
      }>;
      remedies: Array<{
        type:    string;
        details: { upgrade_package?: { new_version: string } };
      }>;
    }>;
    problems: Array<{ id: string; source: string }>;
  };
}

// ── Projects ──────────────────────────────────────────────────────────────────

// Fetch all active projects already in your Snyk org (handles pagination)
// Since you already have repos in Snyk, no import step needed
export async function fetchSnykProjects(
  orgId: string,
  token: string
): Promise<SnykProject[]> {
  const projects: SnykProject[] = [];
  let url: string | null =
    `${SNYK_REST}/orgs/${orgId}/projects?version=${SNYK_VER}&limit=100&status=active`;

  while (url) {
    const res = await fetch(url, { headers: headers(token) });
    if (!res.ok) throw new Error(`Snyk projects fetch failed: ${res.status} ${await res.text()}`);

    const body = await res.json<{
      data: Array<{
        id: string;
        attributes: {
          name:   string;
          target: { display_name: string; url: string };
        };
      }>;
      links?: { next?: string };
    }>();

    for (const p of body.data) {
      const rawUrl = p.attributes.target?.url ?? '';
      if (!rawUrl.includes('github.com')) continue;  // skip non-GitHub projects

      // Snyk can return SSH URLs like git@github.com:Org/repo.git
      // or HTTPS like https://github.com/Org/repo — normalise to HTTPS.
      let githubUrl = rawUrl.replace(/\.git$/, '');
      if (githubUrl.startsWith('git@github.com:')) {
        githubUrl = 'https://github.com/' + githubUrl.slice('git@github.com:'.length);
      }

      // display_name is usually just the repo name (e.g. "stellarglobalsupplies-ai")
      const repoName = p.attributes.target?.display_name
        ?? p.attributes.name.split(':')[0].split('/').pop()
        ?? p.attributes.name;

      projects.push({
        snykProjectId: p.id,
        name:          repoName,
        githubUrl,
      });
    }

    url = body.links?.next ?? null;
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
  let url: string | null =
    `${SNYK_REST}/orgs/${orgId}/issues?version=${SNYK_VER}&project_id=${projectId}&status=open&limit=100`;

  while (url) {
    const res = await fetch(url, { headers: headers(token) });
    if (!res.ok) throw new Error(`Snyk issues fetch failed: ${res.status} ${await res.text()}`);
    const body = await res.json<{ data: SnykIssue[]; links?: { next?: string } }>();
    issues.push(...body.data);
    url = body.links?.next ?? null;
  }

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
  const coord  = issue.attributes.coordinates?.[0];
  const dep    = coord?.representations?.[0]?.dependency;
  const remedy = coord?.remedies?.[0];
  const cve    = issue.attributes.problems?.find(p => p.source === 'CVE')?.id ?? null;

  return {
    snyk_issue_id: issue.id,
    cve,
    title:        issue.attributes.title,
    severity:     issue.attributes.severity as 'critical' | 'high' | 'medium' | 'low',
    package_name: dep?.package_name  ?? 'unknown',
    from_version: dep?.package_version ?? 'unknown',
    to_version:   remedy?.details?.upgrade_package?.new_version ?? null,
    fixable:      remedy?.type === 'upgrade' ? 1 : 0,
    source:       'snyk',
  };
}