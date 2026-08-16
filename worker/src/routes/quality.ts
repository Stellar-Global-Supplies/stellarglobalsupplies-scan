import { Hono } from 'hono';
import { Env } from '../types';
import { getLatestQualityAll, getQualityHistory } from '../lib/db';

const quality = new Hono<{ Bindings: Env }>();

// GET /api/quality — latest quality snapshot for all repos
quality.get('/', async (c) => {
  const data = await getLatestQualityAll(c.env.DB);
  return c.json({ quality: data });
});

// GET /api/quality/:repoId/history
quality.get('/:repoId/history', async (c) => {
  const history = await getQualityHistory(c.env.DB, c.req.param('repoId'));
  return c.json({ history });
});

// NOTE: /api/quality/sync is removed — SonarCloud is no longer used.
// Quality data is now populated automatically during GitHub scans
// via the Dependabot + Code Scanning consumer in queue/consumer.ts.

export default quality;