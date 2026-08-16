import { Hono } from 'hono';
import { Env, JWTPayload, QueueMessage } from '../types';
import { getAllRepos, getRepo, createScanRun, getRecentScans } from '../lib/db';

const scans = new Hono<{ Bindings: Env; Variables: { user: JWTPayload } }>();

// POST /api/scans/repo/:id — scan a single repo
scans.post('/repo/:id', async (c) => {
  const user = c.get('user');
  const repo = await getRepo(c.env.DB, c.req.param('id'));
  if (!repo) return c.json({ error: 'Repo not found' }, 404);

  if (!repo.snyk_project_id) {
    return c.json(
      { error: 'Repo not imported into Snyk yet. Call POST /api/repos/:id/import first.' },
      400
    );
  }

  const scanRunId = await createScanRun(c.env.DB, repo.id, user.sub, 'manual');

  const msg: QueueMessage = {
    type:            'scan_repo',
    repo_id:         repo.id,
    scan_run_id:     scanRunId,
    triggered_by:    user.sub,
    snyk_project_id: repo.snyk_project_id,
  };

  await c.env.SCAN_QUEUE.send(msg);

  return c.json({ scan_run_id: scanRunId, status: 'queued' });
});

// POST /api/scans/all — queue all 30 repos for scanning
scans.post('/all', async (c) => {
  const user     = c.get('user');
  const allRepos = await getAllRepos(c.env.DB);

  const queued: string[] = [];
  const skipped: string[] = [];

  for (const repo of allRepos) {
    if (!repo.snyk_project_id) {
      skipped.push(repo.id);
      continue;
    }

    const scanRunId = await createScanRun(c.env.DB, repo.id, user.sub, 'manual');
    const msg: QueueMessage = {
      type:            'scan_repo',
      repo_id:         repo.id,
      scan_run_id:     scanRunId,
      triggered_by:    user.sub,
      snyk_project_id: repo.snyk_project_id,
    };

    await c.env.SCAN_QUEUE.send(msg);
    queued.push(repo.id);
  }

  return c.json({
    queued:  queued.length,
    skipped: skipped.length,
    message: `${queued.length} repos queued for scanning. ${skipped.length} skipped (not imported into Snyk).`,
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
