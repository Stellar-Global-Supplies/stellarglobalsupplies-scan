import { Env, QueueMessage } from '../types';
import { fetchDependabotAlerts, fetchCodeScanningAlerts, parseDependabotAlert, parseCodeScanningAlert } from '../lib/github';
import { fetchProjectMetrics } from '../lib/sonar';
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
  // env.GITHUB_TOKEN is a plain string — resolved by CF from [[secrets_store_secrets]]

  for (const message of batch.messages) {
    const job = message.body;
    if (job.type !== 'scan_repo') { message.ack(); continue; }

    console.log(`[Queue] Scanning ${job.repo_id} (run: ${job.scan_run_id})`);

    try {
      await updateScanStatus(env.DB, job.scan_run_id, 'scanning');

      const repo = await getRepo(env.DB, job.repo_id);
      if (!repo) throw new Error(`Repo not found: ${job.repo_id}`);

      // Extract owner/repo from github_url
      const url = new URL(repo.github_url);
      const [, owner, repoName] = url.pathname.split('/');

      // ── 1. GitHub Dependabot Alerts — dependency CVEs ─────────────────────
      const dependabotAlerts = await fetchDependabotAlerts(owner, repoName, env.GITHUB_TOKEN);
      const dependabotVulns = dependabotAlerts.map(parseDependabotAlert);

      // ── 2. GitHub Code Scanning Alerts — SAST ─────────────────────────────
      const codeScanningAlerts = await fetchCodeScanningAlerts(owner, repoName, env.GITHUB_TOKEN);
      const codeScanningVulns = codeScanningAlerts.map(parseCodeScanningAlert);

      const allVulns = [...dependabotVulns, ...codeScanningVulns];
      await insertVulnerabilities(env.DB, job.scan_run_id, job.repo_id, allVulns);
      console.log(`[Queue] GitHub: ${allVulns.length} vulns in ${job.repo_id}`);

      // ── 3. SonarCloud — code quality metrics ──────────────────────────────
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

      // ── 4. Done ────────────────────────────────────────────────────────────
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