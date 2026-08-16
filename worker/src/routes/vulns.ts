import { Hono } from 'hono';
import { Env } from '../types';
import { getAllVulnerabilities, getVulnSummary } from '../lib/db';

const vulns = new Hono<{ Bindings: Env }>();

// GET /api/vulns?severity=critical&fixable=true&repo_id=X&source=github_dependabot
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

// NOTE: automated "fix PR" creation is not available via GitHub Dependabot's API
// the way Snyk offered it. Dependabot opens its own update PRs automatically on
// GitHub's side for alerts it detects — no manual trigger endpoint needed here.

export default vulns;