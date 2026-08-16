import { Hono } from 'hono';
import { Env, QueueMessage } from '../types';
import { getAllRepos, getRepo, createScanRun, getRecentScans } from '../lib/db';

const scans = new Hono<{ Bindings: Env }>();

// POST /api/scans/repo/:id — scan a single repo
scans.post('/repo/:id', async (c) => {
  const repo = await getRepo(c.env.DB, c.req.param('id'));
  if (!repo) return c.json({ error: 'Repo not found' }, 404);

  const scanRunId = await createScanRun(c.env.DB, repo.id, 'manual', 'manual');

  const msg: QueueMessage = {
    type:            'scan_repo',
    repo_id:         repo.id,
    scan_run_id:     scanRunId,
    triggered_by:    'manual',
  };

  await c.env.SCAN_QUEUE.send(msg);

  return c.json({ scan_run_id: scanRunId, status: 'queued' });
});

// POST /api/scans/all — queue all repos for scanning
scans.post('/all', async (c) => {
  const allRepos = await getAllRepos(c.env.DB);

  const queued: string[] = [];

  for (const repo of allRepos) {
    const scanRunId = await createScanRun(c.env.DB, repo.id, 'manual', 'manual');
    const msg: QueueMessage = {
      type:            'scan_repo',
      repo_id:         repo.id,
      scan_run_id:     scanRunId,
      triggered_by:    'manual',
    };

    await c.env.SCAN_QUEUE.send(msg);
    queued.push(repo.id);
  }

  return c.json({
    queued:  queued.length,
    message: `${queued.length} repos queued for scanning.`,
  });
});

// GET /api/scans/repo/:id — recent scan history for a repo
scans.get('/repo/:id', async (c) => {
  const scansData = await getRecentScans(c.env.DB, c.req.param('id'));
  return c.json({ scans: scansData });
});

// GET /api/scans/status/:scanRunId — poll scan status
scans.get('/status/:scanRunId', async (c) => {
  const run = await c.env.DB
    .prepare('SELECT * FROM scan_runs WHERE id = ?')
    .bind(c.req.param('scanRunId'))
    .first();
  if (!run) return c.json({ error: 'Scan run not found' }, 404);
  return c.json({ scan: run });
});

export default scans;