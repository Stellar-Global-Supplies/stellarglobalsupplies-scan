import { Env, QueueMessage } from '../types';
import { fetchDependabotAlerts, fetchCodeScanningAlerts, parseDependabotAlert, parseCodeScanningAlert } from '../lib/github';
import {
  updateScanStatus,
  insertVulnerabilities,
  touchRepoLastScanned,
  getRepo,
} from '../lib/db';

export async function handleQueue(
  batch: MessageBatch<QueueMessage>,
  env: Env
): Promise<void> {
  // Resolve secrets once per batch — .get() is async for [[secrets_store_secrets]]
  const githubToken = await env.GITHUB_TOKEN.get();

  for (const message of batch.messages) {
    const job = message.body;
    if (job.type !== 'scan_repo') { message.ack(); continue; }

    console.log(`[Queue] Scanning ${job.repo_id} (run: ${job.scan_run_id})`);

    try {
      await updateScanStatus(env.DB, job.scan_run_id, 'scanning');

      const repo = await getRepo(env.DB, job.repo_id);
      if (!repo) throw new Error(`Repo not found: ${job.repo_id}`);

      const url = new URL(repo.github_url);
      const [, owner, repoName] = url.pathname.split('/');

      const allVulns: Array<
        ReturnType<typeof parseDependabotAlert> |
        ReturnType<typeof parseCodeScanningAlert>
      > = [];

      // ── 1. GitHub Dependabot — dependency CVEs (free, public repos) ───────
      try {
        const alerts = await fetchDependabotAlerts(owner, repoName, githubToken);
        allVulns.push(...alerts.map(parseDependabotAlert));
        console.log(`[Queue] Dependabot: ${alerts.length} alerts in ${repo.name}`);
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        console.warn(`[Queue] Dependabot skipped for ${repo.name}: ${msg}`);
      }

      // ── 2. GitHub Code Scanning — SAST (free, public repos) ───────────────
      try {
        const alerts = await fetchCodeScanningAlerts(owner, repoName, githubToken);
        allVulns.push(...alerts.map(parseCodeScanningAlert));
        console.log(`[Queue] Code scanning: ${alerts.length} alerts in ${repo.name}`);
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        console.warn(`[Queue] Code scanning skipped for ${repo.name}: ${msg}`);
      }

      await insertVulnerabilities(env.DB, job.scan_run_id, job.repo_id, allVulns);

      // ── 3. Done ────────────────────────────────────────────────────────────
      await updateScanStatus(env.DB, job.scan_run_id, 'done', { vulnCount: allVulns.length });
      await touchRepoLastScanned(env.DB, job.repo_id);
      message.ack();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Unknown error';
      console.error(`[Queue] Failed ${job.repo_id}: ${msg}`);
      await updateScanStatus(env.DB, job.scan_run_id, 'failed', { error: msg });
      message.retry();
    }
  }
}