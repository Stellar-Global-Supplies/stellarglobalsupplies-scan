import { Env, QueueMessage } from '../types';
import {
  fetchDependabotAlerts,
  fetchCodeScanningAlerts,
  fetchRepoMeta,
  fetchRepoLanguages,
  deriveQualityMetrics,
  parseDependabotAlert,
  parseCodeScanningAlert,
} from '../lib/github';
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

      // ── 1. Dependabot alerts ───────────────────────────────────────────────
      let dependabotAlerts: Awaited<ReturnType<typeof fetchDependabotAlerts>> = [];
      try {
        dependabotAlerts = await fetchDependabotAlerts(owner, repoName, githubToken);
        console.log(`[Queue] Dependabot: ${dependabotAlerts.length} alerts in ${repo.name}`);
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        console.warn(`[Queue] Dependabot skipped for ${repo.name}: ${msg}`);
      }

      // ── 2. Code scanning alerts ────────────────────────────────────────────
      let codeScanAlerts: Awaited<ReturnType<typeof fetchCodeScanningAlerts>> = [];
      try {
        codeScanAlerts = await fetchCodeScanningAlerts(owner, repoName, githubToken);
        console.log(`[Queue] Code scanning: ${codeScanAlerts.length} alerts in ${repo.name}`);
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        console.warn(`[Queue] Code scanning skipped for ${repo.name}: ${msg}`);
      }

      // ── 3. Repo meta + languages for quality metrics ───────────────────────
      let repoMeta:       Awaited<ReturnType<typeof fetchRepoMeta>>      | null = null;
      let languageBytes:  Awaited<ReturnType<typeof fetchRepoLanguages>>        = {};
      try {
        [repoMeta, languageBytes] = await Promise.all([
          fetchRepoMeta(owner, repoName, githubToken),
          fetchRepoLanguages(owner, repoName, githubToken),
        ]);
        console.log(`[Queue] Repo meta fetched for ${repo.name}: ${repoMeta.open_issues_count} open issues`);
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        console.warn(`[Queue] Repo meta skipped for ${repo.name}: ${msg}`);
      }

      // ── 4. Insert vulnerabilities ──────────────────────────────────────────
      const allVulns = [
        ...dependabotAlerts.map(parseDependabotAlert),
        ...codeScanAlerts.map(parseCodeScanningAlert),
      ];
      await insertVulnerabilities(env.DB, job.scan_run_id, job.repo_id, allVulns);

      // ── 5. Insert code quality snapshot ───────────────────────────────────
      if (repoMeta) {
        const metrics = deriveQualityMetrics(
          repoMeta,
          languageBytes,
          dependabotAlerts.map(a => ({ severity: a.severity })),
          codeScanAlerts,
        );
        await insertCodeQuality(
          env.DB,
          job.scan_run_id,
          job.repo_id,
          repoName,   // GitHub repo slug stored in sonar_project_key column
          metrics,
        );
        console.log(`[Queue] Quality snapshot saved for ${repo.name}: security=${metrics.security_rating} reliability=${metrics.reliability_rating} maintainability=${metrics.maintainability_rating}`);
      }

      // ── 6. Done ────────────────────────────────────────────────────────────
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