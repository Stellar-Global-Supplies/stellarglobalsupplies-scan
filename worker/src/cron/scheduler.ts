import { Env, QueueMessage } from '../types';
import { getAllRepos, createScanRun } from '../lib/db';

// Cron: "0 6,18 * * *" — 06:00 UTC and 18:00 UTC every day
export async function handleCron(env: Env, scheduledTime: Date): Promise<void> {
  console.log(`[Cron] SGS scan starting at ${scheduledTime.toISOString()}`);

  const repos = await getAllRepos(env.DB);

  console.log(`[Cron] ${repos.length} repos eligible`);

  for (const repo of repos) {
    const scanRunId = await createScanRun(env.DB, repo.id, 'cron', 'cron');

    const msg: QueueMessage = {
      type:            'scan_repo',
      repo_id:         repo.id,
      scan_run_id:     scanRunId,
      triggered_by:    'cron',
    };

    await env.SCAN_QUEUE.send(msg);
    console.log(`[Cron] Queued: ${repo.name}`);
  }

  console.log(`[Cron] Done — ${repos.length} repos queued`);
}