import { Hono } from 'hono';
import { Env } from '../types';
import { getAllRepos, getRepo, upsertReposFromGitHub, syncSnykProjectIds } from '../lib/db';
import { fetchOrgRepos } from '../lib/github';
import { fetchSnykProjects } from '../lib/snyk';

const repos = new Hono<{ Bindings: Env }>();

// GET /api/repos
repos.get('/', async (c) => {
  const allRepos = await getAllRepos(c.env.DB);
  const enriched = await Promise.all(
    allRepos.map(async (repo) => {
      const latestScan = await c.env.DB
        .prepare('SELECT status, finished_at, vuln_count FROM scan_runs WHERE repo_id = ? ORDER BY started_at DESC LIMIT 1')
        .bind(repo.id)
        .first<{ status: string; finished_at: number | null; vuln_count: number }>();
      return { ...repo, latest_scan: latestScan ?? null };
    })
  );
  return c.json({ repos: enriched });
});

// GET /api/repos/:id
repos.get('/:id', async (c) => {
  const repo = await getRepo(c.env.DB, c.req.param('id'));
  if (!repo) return c.json({ error: 'Repo not found' }, 404);
  return c.json({ repo });
});

// POST /api/repos/sync — pull all GitHub org repos into D1
repos.post('/sync', async (c) => {
  try {
    const githubToken = await c.env.GITHUB_TOKEN.get();
    const githubRepos = await fetchOrgRepos('Stellar-Global-Supplies', githubToken);

    if (githubRepos.length === 0) {
      return c.json({ message: 'No repos found in GitHub org.', synced: 0 });
    }

    const result = await upsertReposFromGitHub(c.env.DB, githubRepos);
    return c.json({
      synced:   githubRepos.length,
      inserted: result.inserted,
      updated:  result.updated,
      message:  `Synced ${githubRepos.length} repos from GitHub into D1.`,
    });
  } catch (err: unknown) {
    return c.json({ error: err instanceof Error ? err.message : 'Sync failed' }, 500);
  }
});

// POST /api/repos/snyk-sync
// Fetches all existing Snyk projects and matches them to repos in D1
// No import step needed — your repos are already in Snyk
// Free tier on public repos: unlimited
repos.post('/snyk-sync', async (c) => {
  try {
    const [snykToken, snykOrgId] = await Promise.all([
      c.env.SNYK_API_TOKEN.get(),
      c.env.SNYK_ORG_ID.get(),
    ]);

    const snykProjects = await fetchSnykProjects(snykOrgId, snykToken);

    if (snykProjects.length === 0) {
      return c.json({
        message: 'No GitHub-backed projects found in your Snyk org.',
        synced:  0,
      });
    }

    const synced = await syncSnykProjectIds(c.env.DB, snykProjects);
    return c.json({
      found:   snykProjects.length,
      synced,
      message: `Found ${snykProjects.length} Snyk projects, matched ${synced} repos in D1.`,
    });
  } catch (err: unknown) {
    return c.json({ error: err instanceof Error ? err.message : 'Snyk sync failed' }, 500);
  }
});

export default repos;