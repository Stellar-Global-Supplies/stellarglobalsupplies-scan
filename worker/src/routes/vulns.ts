import { Hono } from 'hono';
import { Env } from '../types';
import { getAllVulnerabilities, getVulnSummary } from '../lib/db';

const vulns = new Hono<{ Bindings: Env }>();

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

export default vulns;