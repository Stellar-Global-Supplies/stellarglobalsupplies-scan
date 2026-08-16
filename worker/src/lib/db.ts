import { Repo, ScanRun, Vulnerability, CodeQuality } from '../types';
import { SonarMetrics } from './sonar';

function nanoid(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 20);
}

// ── Repos ─────────────────────────────────────────────────────────────────────

export async function getAllRepos(db: D1Database): Promise<Repo[]> {
  const { results } = await db.prepare('SELECT * FROM repos ORDER BY name').all<Repo>();
  return results;
}

export async function getRepo(db: D1Database, id: string): Promise<Repo | null> {
  return db.prepare('SELECT * FROM repos WHERE id = ?').bind(id).first<Repo>();
}

export async function upsertReposFromGitHub(
  db: D1Database,
  repos: Array<{ name: string; html_url: string }>
): Promise<{ inserted: number; updated: number }> {
  const stmt = db.prepare(`
    INSERT INTO repos (id, name, github_url)
    VALUES (?, ?, ?)
    ON CONFLICT (id)       DO UPDATE SET name = excluded.name, github_url = excluded.github_url
    ON CONFLICT (github_url) DO UPDATE SET name = excluded.name
  `);

  const batch = await Promise.all(repos.map(async r => {
    // Use a SHA-256 digest of the URL for a stable, collision-resistant ID.
    // We take the first 16 hex chars (64 bits of entropy) — far safer than
    // the old btoa approach which collapsed many URLs to the same suffix.
    const urlBytes = new TextEncoder().encode(r.html_url);
    const hashBuf  = await crypto.subtle.digest('SHA-256', urlBytes);
    const hashHex  = Array.from(new Uint8Array(hashBuf))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    const id = 'repo_' + hashHex.slice(0, 16);
    return stmt.bind(id, r.name, r.html_url);
  }));

  if (batch.length > 0) await db.batch(batch);

  const existing = await db.prepare('SELECT COUNT(*) as c FROM repos').first<{ c: number }>();
  const total = existing?.c ?? 0;
  return { inserted: Math.min(repos.length, total), updated: repos.length - Math.min(repos.length, total) };
}

// Match Snyk project IDs to repos by GitHub URL or name
export async function syncSnykProjectIds(
  db: D1Database,
  snykProjects: Array<{ snykProjectId: string; name: string; githubUrl: string }>
): Promise<number> {
  const repos = await getAllRepos(db);
  let synced = 0;
  const stmt  = db.prepare('UPDATE repos SET snyk_project_id = ? WHERE id = ?');
  const batch = [];

  for (const sp of snykProjects) {
    // Also extract the repo slug from the Snyk GitHub URL as a fallback matcher.
    const urlSlug = sp.githubUrl.split('/').pop()?.toLowerCase() ?? '';

    const match = repos.find(r => {
      const rName = r.name.toLowerCase();
      const rUrl  = r.github_url.toLowerCase();
      return (
        rUrl  === sp.githubUrl.toLowerCase() ||
        rName === sp.name.toLowerCase()      ||
        (urlSlug && rName === urlSlug)
      );
    });
    if (match) {
      batch.push(stmt.bind(sp.snykProjectId, match.id));
      synced++;
    }
  }

  if (batch.length > 0) await db.batch(batch);
  return synced;
}

// Sync SonarCloud project keys into repos
export async function syncSonarProjectKeys(
  db: D1Database,
  sonarProjects: Array<{ projectKey: string; name: string; githubUrl: string }>
): Promise<number> {
  const repos = await getAllRepos(db);
  let synced = 0;
  const stmt  = db.prepare('UPDATE repos SET sonar_project_key = ? WHERE id = ?');
  const batch = [];

  for (const sonar of sonarProjects) {
    // Extract bare repo slug from the project key (e.g. "sgs_my-repo" → "my-repo")
    // so we can match even when the display name differs slightly.
    const keySlug = sonar.projectKey.includes('_')
      ? sonar.projectKey.split('_').slice(1).join('_').toLowerCase()
      : sonar.projectKey.toLowerCase();

    const match = repos.find(r => {
      const rName = r.name.toLowerCase();
      const rUrl  = r.github_url.toLowerCase();
      return (
        rUrl  === sonar.githubUrl.toLowerCase() ||
        rName === sonar.name.toLowerCase()      ||
        rName === keySlug
      );
    });
    if (match) {
      batch.push(stmt.bind(sonar.projectKey, match.id));
      synced++;
    }
  }

  if (batch.length > 0) await db.batch(batch);
  return synced;
}

// ── Scan Runs ─────────────────────────────────────────────────────────────────

export async function createScanRun(
  db: D1Database,
  repoId: string,
  triggeredBy: string,
  triggerType: 'manual' | 'cron' = 'manual'
): Promise<string> {
  const id = nanoid();
  await db
    .prepare(`INSERT INTO scan_runs (id, repo_id, triggered_by, trigger_type, status) VALUES (?, ?, ?, ?, 'queued')`)
    .bind(id, repoId, triggeredBy, triggerType)
    .run();
  return id;
}

export async function updateScanStatus(
  db: D1Database,
  scanRunId: string,
  status: ScanRun['status'],
  extra: { vulnCount?: number; error?: string } = {}
): Promise<void> {
  const finished = status === 'done' || status === 'failed' ? 'unixepoch()' : 'NULL';
  await db
    .prepare(`UPDATE scan_runs SET status = ?, vuln_count = COALESCE(?, vuln_count), error = ?, finished_at = ${finished} WHERE id = ?`)
    .bind(status, extra.vulnCount ?? null, extra.error ?? null, scanRunId)
    .run();
}

export async function getRecentScans(db: D1Database, repoId: string): Promise<ScanRun[]> {
  const { results } = await db
    .prepare('SELECT * FROM scan_runs WHERE repo_id = ? ORDER BY started_at DESC LIMIT 10')
    .bind(repoId)
    .all<ScanRun>();
  return results;
}

// ── Vulnerabilities ───────────────────────────────────────────────────────────

export async function insertVulnerabilities(
  db: D1Database,
  scanRunId: string,
  repoId: string,
  vulns: Array<{
    github_alert_id?: number | null | undefined;
    snyk_issue_id?:   string | null | undefined;
    cve:              string | null;
    title:            string;
    severity:         string;
    package_name:     string;
    from_version:     string;
    to_version:       string | null;
    fixable:          number;
    source:           string;
  }>
): Promise<void> {
  if (vulns.length === 0) return;

  const stmt = db.prepare(`
    INSERT INTO vulnerabilities
      (id, scan_run_id, repo_id, github_alert_id, snyk_issue_id, cve, title,
       severity, package_name, from_version, to_version, fixable, source)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  await db.batch(
    vulns.map(v =>
      stmt.bind(
        nanoid(), scanRunId, repoId,
        v.github_alert_id ?? null,
        v.snyk_issue_id   ?? null,
        v.cve, v.title, v.severity,
        v.package_name, v.from_version, v.to_version, v.fixable, v.source
      )
    )
  );
}

export async function getAllVulnerabilities(
  db: D1Database,
  filters: { severity?: string; fixable?: string; repo_id?: string; source?: string }
): Promise<Vulnerability[]> {
  let query = 'SELECT v.*, r.name as repo_name FROM vulnerabilities v JOIN repos r ON v.repo_id = r.id WHERE 1=1';
  const bindings: unknown[] = [];

  if (filters.severity) { query += ' AND v.severity = ?'; bindings.push(filters.severity); }
  if (filters.fixable)  { query += ' AND v.fixable = ?';  bindings.push(filters.fixable === 'true' ? 1 : 0); }
  if (filters.repo_id)  { query += ' AND v.repo_id = ?';  bindings.push(filters.repo_id); }
  if (filters.source)   { query += ' AND v.source = ?';   bindings.push(filters.source); }

  query += ` ORDER BY CASE v.severity
    WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4
  END, v.created_at DESC`;

  const { results } = await db.prepare(query).bind(...bindings).all<Vulnerability>();
  return results;
}

export async function getVulnSummary(db: D1Database) {
  const { results } = await db
    .prepare(`SELECT severity, COUNT(*) as count FROM vulnerabilities WHERE fix_pr_url IS NULL GROUP BY severity`)
    .all<{ severity: string; count: number }>();

  const summary = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const row of results) {
    if (row.severity in summary) (summary as Record<string, number>)[row.severity] = row.count;
  }
  return summary;
}

// Update fix PR URL by Snyk issue ID
export async function updateFixPRUrlBySnykId(
  db: D1Database,
  snykIssueId: string,
  prUrl: string
): Promise<void> {
  await db
    .prepare('UPDATE vulnerabilities SET fix_pr_url = ? WHERE snyk_issue_id = ?')
    .bind(prUrl, snykIssueId)
    .run();
}

// ── Code Quality ──────────────────────────────────────────────────────────────

export async function insertCodeQuality(
  db: D1Database,
  repoId: string,
  scanRunId: string,
  sonarProjectKey: string,
  metrics: SonarMetrics
): Promise<void> {
  await db.prepare(`
    INSERT INTO code_quality (
      id, repo_id, scan_run_id, sonar_project_key,
      reliability_rating, maintainability_rating, security_rating,
      code_smells, duplicated_lines_pct, complexity, cognitive_complexity,
      coverage_pct, lines_of_code, security_hotspots, technical_debt_mins
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    nanoid(), repoId, scanRunId, sonarProjectKey,
    metrics.reliabilityRating, metrics.maintainabilityRating, metrics.securityRating,
    metrics.codeSmells, metrics.duplicatedLinesPct, metrics.complexity,
    metrics.cognitiveComplexity, metrics.coveragePct, metrics.linesOfCode,
    metrics.securityHotspots, metrics.technicalDebtMins
  ).run();
}

export async function getLatestQualityAll(db: D1Database): Promise<(CodeQuality & { repo_name: string })[]> {
  const { results } = await db.prepare(`
    SELECT cq.*, r.name as repo_name
    FROM code_quality cq
    JOIN repos r ON cq.repo_id = r.id
    WHERE cq.id IN (
      SELECT id FROM code_quality cq2
      WHERE cq2.repo_id = cq.repo_id
      ORDER BY created_at DESC
      LIMIT 1
    )
    ORDER BY r.name
  `).all<CodeQuality & { repo_name: string }>();
  return results;
}

export async function getQualityHistory(db: D1Database, repoId: string, limit = 10): Promise<CodeQuality[]> {
  const { results } = await db
    .prepare('SELECT * FROM code_quality WHERE repo_id = ? ORDER BY created_at DESC LIMIT ?')
    .bind(repoId, limit)
    .all<CodeQuality>();
  return results;
}

export async function touchRepoLastScanned(db: D1Database, repoId: string): Promise<void> {
  await db.prepare('UPDATE repos SET last_scanned_at = unixepoch() WHERE id = ?').bind(repoId).run();
}