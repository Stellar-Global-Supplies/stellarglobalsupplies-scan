import { Env, QueueMessage } from '../types';
import { fetchIssues, parseIssue }   from '../lib/snyk';
import { fetchProjectMetrics }        from '../lib/sonar';
import {
  updateScanStatus,
  insertVulnerabilities,
  insertCodeQuality,
  touchRepoLastScanned,
  getRepo,
} from '../lib/db';

export async function handleQueue(
  batch: MessageBatch<QueueMessage>,
  env: Env
): Promise<void> {
  // env.SNYK_API_TOKEN, env.SNYK_ORG_ID etc. are plain strings —
  // resolved by CF from [[secrets_store_secrets]] before the Worker runs

  for (const message of batch.messages) {
    const job = message.body;
    if (job.type !== 'scan_repo') { message.ack(); continue; }

    console.log(`[Queue] Scanning ${job.repo_id} (run: ${job.scan_run_id})`);

    try {
      await updateScanStatus(env.DB, job.scan_run_id, 'scanning');

      // ── 1. Snyk — dependency CVEs + SAST ──────────────────────────────────
      const snykIssues = await fetchIssues(
        env.SNYK_ORG_ID,
        env.SNYK_API_TOKEN,
        job.snyk_project_id
      );
      const parsed = snykIssues.map(issue => parseIssue(issue));
      await insertVulnerabilities(env.DB, job.scan_run_id, job.repo_id, parsed);
      console.log(`[Queue] Snyk: ${parsed.length} vulns in ${job.repo_id}`);

      // ── 2. SonarCloud — code quality metrics ──────────────────────────────
      const repo = await getRepo(env.DB, job.repo_id);
      if (repo?.sonar_project_key) {
        try {
          const metrics = await fetchProjectMetrics(
            repo.sonar_project_key,
            env.SONARCLOUD_TOKEN
          );
          await insertCodeQuality(
            env.DB,
            job.repo_id,
            job.scan_run_id,
            repo.sonar_project_key,
            metrics
          );
          console.log(`[Queue] SonarCloud: quality saved for ${job.repo_id}`);
        } catch (sonarErr: unknown) {
          // SonarCloud failure doesn't fail the whole scan job
          console.warn(`[Queue] SonarCloud failed for ${job.repo_id}:`, sonarErr);
        }
      }

      // ── 3. Done ────────────────────────────────────────────────────────────
      await updateScanStatus(env.DB, job.scan_run_id, 'done', { vulnCount: parsed.length });
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