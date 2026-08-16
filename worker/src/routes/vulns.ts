import { Hono } from 'hono';
import { Env, JWTPayload } from '../types';
import { getAllVulnerabilities, getVulnSummary, updateFixPRUrl, getRepo } from '../lib/db';
import { createFixPR } from '../lib/snyk';

const vulns = new Hono<{ Bindings: Env; Variables: { user: JWTPayload } }>();

// GET /api/vulns?severity=critical&fixable=true&repo_id=repo_01
vulns.get('/', async (c) => {
  const { severity, fixable, repo_id } = c.req.query();
  const data = await getAllVulnerabilities(c.env.DB, { severity, fixable, repo_id });
  return c.json({ vulnerabilities: data });
});

// GET /api/vulns/summary
vulns.get('/summary', async (c) => {
  const summary = await getVulnSummary(c.env.DB);
  return c.json({ summary });
});

// POST /api/vulns/fix  body: { repo_id, issue_ids: string[] }
vulns.post('/fix', async (c) => {
  const body = await c.req.json<{ repo_id: string; issue_ids: string[] }>();

  if (!body.repo_id || !body.issue_ids?.length) {
    return c.json({ error: 'repo_id and issue_ids are required' }, 400);
  }

  const repo = await getRepo(c.env.DB, body.repo_id);
  if (!repo)                 return c.json({ error: 'Repo not found' }, 404);
  if (!repo.snyk_project_id) return c.json({ error: 'Repo not imported into Snyk' }, 400);

  try {
    // env.SNYK_ORG_ID and env.SNYK_API_TOKEN are direct strings
    const fix = await createFixPR(
      c.env.SNYK_ORG_ID,
      c.env.SNYK_API_TOKEN,
      repo.snyk_project_id,
      body.issue_ids
    );
    await Promise.all(body.issue_ids.map(id => updateFixPRUrl(c.env.DB, id, fix.url)));
    return c.json({ pr_url: fix.url, message: 'Fix PR created on GitHub' });
  } catch (err: unknown) {
    return c.json({ error: err instanceof Error ? err.message : 'Fix PR failed' }, 500);
  }
});

export default vulns;