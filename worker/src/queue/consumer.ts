import { Env, QueueMessage } from '../types';
import { fetchDependabotAlerts, fetchCodeScanningAlerts, parseDependabotAlert, parseCodeScanningAlert } from '../lib/github';
import { fetchSnykIssues, parseSnykIssue } from '../lib/snyk';
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
  // Resolve all secrets once per batch — .get() is async for [[secrets_store_secrets]]
  const [githubToken, snykToken, snykOrgId, sonarToken] = await Promise.all([
    env.GITHUB_TOKEN.get(),
    env.SNYK_API_TOKEN.get(),
    env.SNYK_ORG_ID.get(),
    env.SONARCLOUD_TOKEN.get(),
  ]);

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
        ReturnType<typeof parseCodeScanningAlert> |
        ReturnType<typeof parseSnykIssue>
      > = [];

      // ── 1. GitHub Dependabot — dependency CVEs (free, public repos) ───────
      try {
        const alerts = await fetchDependabotAlerts(owner, repoName, githubToken);
        allVulns.push(...alerts.map(parseDependabotAlert));
        console.log(`[Queue] Dependabot: ${alerts.length} alerts in ${repo.name}`);
      } catch (e) {
        console.warn(`[Queue] Dependabot skipped for ${repo.name}:`, e);
      }

      // ── 2. GitHub Code Scanning — SAST (free, public repos) ───────────────
      try {
        const alerts = await fetchCodeScanningAlerts(owner, repoName, githubToken);
        allVulns.push(...alerts.map(parseCodeScanningAlert));
        console.log(`[Queue] Code scanning: ${alerts.length} alerts in ${repo.name}`);
      } catch (e) {
        console.warn(`[Queue] Code scanning skipped for ${repo.name}:`, e);
      }

      // ── 3. Snyk — dependency CVEs + SAST with Fix PR support ──────────────
      // Free tier on public repos: unlimited scans + Fix PRs
      if (repo.snyk_project_id) {
        try {
          const issues = await fetchSnykIssues(snykOrgId, snykToken, repo.snyk_project_id);
          allVulns.push(...issues.map(parseSnykIssue));
          console.log(`[Queue] Snyk: ${issues.length} issues in ${repo.name}`);
        } catch (e) {
          console.warn(`[Queue] Snyk skipped for ${repo.name}:`, e);
        }
      } else {
        console.log(`[Queue] No snyk_project_id for ${repo.name} — run /api/repos/snyk-sync`);
      }

      await insertVulnerabilities(env.DB, job.scan_run_id, job.repo_id, allVulns);

      // ── 4. SonarCloud — code quality metrics ──────────────────────────────
      if (repo.sonar_project_key) {
        try {
          const metrics = await fetchProjectMetrics(repo.sonar_project_key, sonarToken);
          await insertCodeQuality(env.DB, job.repo_id, job.scan_run_id, repo.sonar_project_key, metrics);
          console.log(`[Queue] SonarCloud: quality saved for ${repo.name}`);
        } catch (e) {
          console.warn(`[Queue] SonarCloud skipped for ${repo.name}:`, e);
        }
      }

      // ── 5. Done ────────────────────────────────────────────────────────────
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