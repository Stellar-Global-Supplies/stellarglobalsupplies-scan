import { Hono } from 'hono';
import { Env } from '../types';
import { getAllRepos, getRepo, createScanRun } from '../lib/db';

const scans = new Hono<{ Bindings: Env }>();

// POST /api/scans/all — queue a scan for every repo
scans.post('/all', async (c) => {
  try {
    const allRepos = await getAllRepos(c.env.DB);
    if (allRepos.length === 0) {
      return c.json({ queued: 0, message: 'No repos found. Run /api/repos/sync first.' });
    }

    let queued = 0;
    for (const repo of allRepos) {
      const scanRunId = await createScanRun(c.env.DB, repo.id, 'manual-all', 'manual');
      await c.env.SCAN_QUEUE.send({
        type:         'scan_repo',
        repo_id:      repo.id,
        scan_run_id:  scanRunId,
        triggered_by: 'manual-all',
      });
      queued++;
    }

    return c.json({
      queued,
      message: `Queued ${queued} repo(s) for scanning.`,
    });
  } catch (err: unknown) {
    return c.json({ error: err instanceof Error ? err.message : 'Scan all failed' }, 500);
  }
});

// POST /api/scans/repo/:id — queue a scan for a single repo
scans.post('/repo/:id', async (c) => {
  try {
    const repoId = c.req.param('id');
    const repo   = await getRepo(c.env.DB, repoId);
    if (!repo) return c.json({ error: 'Repo not found' }, 404);

    const scanRunId = await createScanRun(c.env.DB, repo.id, 'manual', 'manual');
    await c.env.SCAN_QUEUE.send({
      type:         'scan_repo',
      repo_id:      repo.id,
      scan_run_id:  scanRunId,
      triggered_by: 'manual',
    });

    return c.json({
      scan_run_id: scanRunId,
      status:      'queued',
      message:     `Scan queued for ${repo.name}.`,
    });
  } catch (err: unknown) {
    return c.json({ error: err instanceof Error ? err.message : 'Scan failed' }, 500);
  }
});

// GET /api/scans/status/:scanRunId
scans.get('/status/:scanRunId', async (c) => {
  const row = await c.env.DB
    .prepare('SELECT * FROM scan_runs WHERE id = ?')
    .bind(c.req.param('scanRunId'))
    .first();
  if (!row) return c.json({ error: 'Scan run not found' }, 404);
  return c.json({ scan: row });
});

// GET /api/scans/repo/:id — history for a repo
scans.get('/repo/:id', async (c) => {
  const rows = await c.env.DB
    .prepare('SELECT * FROM scan_runs WHERE repo_id = ? ORDER BY started_at DESC LIMIT 20')
    .bind(c.req.param('id'))
    .all();
  return c.json({ scans: rows.results });
});

export default scans;