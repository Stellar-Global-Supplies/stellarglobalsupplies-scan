import { Hono } from 'hono';
import { Env } from '../types';
import { getAllVulnerabilities, getVulnSummary, getRepo, updateFixPRUrlBySnykId } from '../lib/db';
import { createSnykFixPR } from '../lib/snyk';

const vulns = new Hono<{ Bindings: Env }>();

// GET /api/vulns?severity=critical&fixable=true&repo_id=X&source=snyk
vulns.get('/', async (c) => {
  const { severity, fixable, repo_id, source } = c.req.query();
  const data = await getAllVulnerabilities(c.env.DB, { severity, fixable, repo_id, source });
  return c.json({ vulnerabilities: data });
});

// GET /api/vulns/summary
vulns.get('/summary', async (c) => {
  const summary = await getVulnSummary(c.env.DB);
  return c.json({ summary });
});

// POST /api/vulns/fix
// Triggers a Snyk fix PR on GitHub for one or more Snyk issue IDs
// Free on public repos — Snyk opens a PR bumping the affected package
// Body: { repo_id: string, issue_ids: string[] }
vulns.post('/fix', async (c) => {
  const body = await c.req.json<{ repo_id: string; issue_ids: string[] }>();

  if (!body.repo_id || !body.issue_ids?.length) {
    return c.json({ error: 'repo_id and issue_ids are required' }, 400);
  }

  const repo = await getRepo(c.env.DB, body.repo_id);
  if (!repo) return c.json({ error: 'Repo not found' }, 404);

  if (!repo.snyk_project_id) {
    return c.json({
      error: 'This repo has no Snyk project ID. Run POST /api/repos/snyk-sync first.',
    }, 400);
  }

  try {
    const [snykToken, snykOrgId] = await Promise.all([
      c.env.SNYK_API_TOKEN.get(),
      c.env.SNYK_ORG_ID.get(),
    ]);

    // Snyk batches related upgrades — may create 1 PR for multiple issues
    const fix = await createSnykFixPR(snykOrgId, snykToken, repo.snyk_project_id, body.issue_ids);

    // Store the PR URL against each issue so the UI can show it
    await Promise.all(
      body.issue_ids.map(id => updateFixPRUrlBySnykId(c.env.DB, id, fix.url))
    );

    return c.json({ pr_url: fix.url, message: 'Fix PR created on GitHub via Snyk' });
  } catch (err: unknown) {
    return c.json({ error: err instanceof Error ? err.message : 'Fix PR failed' }, 500);
  }
});

export default vulns;