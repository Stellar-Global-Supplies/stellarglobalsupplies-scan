import { Env, QueueMessage } from '../types';
import { getAllRepos, createScanRun } from '../lib/db';

// Cron: "0 6,18 * * *" — 06:00 UTC and 18:00 UTC every day
export async function handleCron(env: Env, scheduledTime: Date): Promise<void> {
  console.log(`[Cron] SGS scan starting at ${scheduledTime.toISOString()}`);

  const repos    = await getAllRepos(env.DB);
  const eligible = repos.filter(r => r.snyk_project_id !== null);

  console.log(`[Cron] ${eligible.length} repos eligible / ${repos.length - eligible.length} skipped`);

  for (const repo of eligible) {
    const scanRunId = await createScanRun(env.DB, repo.id, 'cron', 'cron');

    const msg: QueueMessage = {
      type:            'scan_repo',
      repo_id:         repo.id,
      scan_run_id:     scanRunId,
      triggered_by:    'cron',
      snyk_project_id: repo.snyk_project_id!,
    };

    await env.SCAN_QUEUE.send(msg);
    console.log(`[Cron] Queued: ${repo.name}`);
  }

  console.log(`[Cron] Done — ${eligible.length} repos queued`);
}