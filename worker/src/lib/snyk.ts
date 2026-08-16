import { SnykIssue, SnykIssuesResponse, SnykFixResponse } from '../types';

const SNYK_REST_BASE = 'https://api.snyk.io/rest';
const SNYK_V1_BASE   = 'https://api.snyk.io/v1';
const SNYK_API_VER   = '2024-01-23';

export interface SnykProject {
  snykProjectId: string;
  name:          string;
  githubUrl:     string;
  repoName:      string;  // short name, e.g. "my-cf-app"
}

// Fetch all active projects already in your Snyk org (handles pagination)
// Replaces the need for seed_repos.sql — works because your repos are already in Snyk
export async function fetchProjects(
  orgId: string,
  token: string
): Promise<SnykProject[]> {
  const projects: SnykProject[] = [];
  let url: string | null =
    `${SNYK_REST_BASE}/orgs/${orgId}/projects` +
    `?version=${SNYK_API_VER}&limit=100&status=active`;

  while (url) {
    const res = await fetch(url, { headers: snykHeaders(token) });
    if (!res.ok) throw new Error(`Snyk projects fetch failed: ${res.status} ${await res.text()}`);

    const body = await res.json<{
      data: Array<{
        id: string;
        attributes: {
          name:   string;
          status: string;
          target: { display_name: string; url: string };
        };
      }>;
      links?: { next?: string };
    }>();

    for (const project of body.data) {
      const githubUrl = project.attributes.target?.url ?? '';
      // Only include GitHub-backed projects (filter out CLI-uploaded ones)
      if (!githubUrl.includes('github.com')) continue;

      // Snyk project name format: "org/repo:path/to/package.json"
      // Extract a clean repo name from the target display_name
      const repoName = project.attributes.target?.display_name
        ?? project.attributes.name.split(':')[0].split('/').pop()
        ?? project.attributes.name;

      projects.push({
        snykProjectId: project.id,
        name:          repoName,
        githubUrl:     githubUrl.replace(/\.git$/, ''),
        repoName,
      });
    }

    url = body.links?.next ?? null;
  }

  // Deduplicate by githubUrl — one repo can have multiple Snyk projects
  // (e.g. package.json + Dockerfile). Keep the first (usually the root manifest).
  const seen = new Map<string, SnykProject>();
  for (const p of projects) {
    if (!seen.has(p.githubUrl)) seen.set(p.githubUrl, p);
  }

  return [...seen.values()];
}

function snykHeaders(token: string): HeadersInit {
  return {
    'Authorization': `token ${token}`,
    'Content-Type':  'application/json',
  };
}

// Fetch all open issues for a Snyk project (handles pagination)
export async function fetchIssues(
  orgId: string,
  token: string,
  projectId: string
): Promise<SnykIssue[]> {
  const issues: SnykIssue[] = [];
  let url: string | null =
    `${SNYK_REST_BASE}/orgs/${orgId}/issues` +
    `?version=${SNYK_API_VER}&project_id=${projectId}&status=open&limit=100`;

  while (url) {
    const res = await fetch(url, { headers: snykHeaders(token) });
    if (!res.ok) throw new Error(`Snyk issues fetch failed: ${res.status} ${await res.text()}`);
    const body = await res.json<SnykIssuesResponse>();
    issues.push(...body.data);
    url = body.links?.next ?? null;
  }

  return issues;
}

// Trigger a fix PR for one or more Snyk issue IDs on a project
export async function createFixPR(
  orgId: string,
  token: string,
  projectId: string,
  issueIds: string[]
): Promise<SnykFixResponse> {
  const res = await fetch(
    `${SNYK_V1_BASE}/org/${orgId}/project/${projectId}/fix`,
    {
      method: 'POST',
      headers: snykHeaders(token),
      body: JSON.stringify({ type: 'upgrade', issueIds }),
    }
  );
  if (!res.ok) throw new Error(`Snyk fix PR failed: ${res.status} ${await res.text()}`);
  return res.json<SnykFixResponse>();
}

// Parse raw Snyk issue into our DB shape
export function parseIssue(issue: SnykIssue) {
  const coord  = issue.attributes.coordinates?.[0];
  const dep    = coord?.representations?.[0]?.dependency;
  const remedy = coord?.remedies?.[0];
  const cve    = issue.attributes.problems?.find(p => p.source === 'CVE')?.id ?? null;

  const fixable   = remedy?.type === 'upgrade' ? 1 : 0;
  const toVersion = remedy?.details?.upgrade_package?.new_version ?? null;

  return {
    snyk_issue_id: issue.id,
    cve,
    title:        issue.attributes.title,
    severity:     issue.attributes.severity as 'critical' | 'high' | 'medium' | 'low',
    package_name: dep?.package_name  ?? 'unknown',
    from_version: dep?.package_version ?? 'unknown',
    to_version:   toVersion,
    fixable,
    source:       'snyk',
  };
}
