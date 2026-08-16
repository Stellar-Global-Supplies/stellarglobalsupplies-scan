import { Repo, ScanRun, Vulnerability } from '../types';

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
      (id, scan_run_id, repo_id, github_alert_id, cve, title,
       severity, package_name, from_version, to_version, fixable, source)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  await db.batch(
    vulns.map(v =>
      stmt.bind(
        nanoid(), scanRunId, repoId,
        v.github_alert_id ?? null,
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
  // Only return vulns from the latest *done* scan per repo to prevent duplication
  // when the same repo is re-scanned multiple times.
  let query = `
    SELECT v.*, r.name as repo_name
    FROM vulnerabilities v
    JOIN repos r ON v.repo_id = r.id
    JOIN (
      SELECT repo_id, MAX(finished_at) as max_finished
      FROM scan_runs
      WHERE status = 'done'
      GROUP BY repo_id
    ) latest_scan ON v.repo_id = latest_scan.repo_id
    JOIN scan_runs sr ON v.scan_run_id = sr.id AND sr.finished_at = latest_scan.max_finished
    WHERE 1=1`;
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
  // Count vulns from the latest done scan per repo only (no duplication across re-scans).
  // Count ALL severities regardless of fix_pr_url so the summary reflects real exposure.
  const { results } = await db
    .prepare(`
      SELECT v.severity, COUNT(*) as count
      FROM vulnerabilities v
      JOIN (
        SELECT repo_id, MAX(finished_at) as max_finished
        FROM scan_runs
        WHERE status = 'done'
        GROUP BY repo_id
      ) latest_scan ON v.repo_id = latest_scan.repo_id
      JOIN scan_runs sr ON v.scan_run_id = sr.id AND sr.finished_at = latest_scan.max_finished
      GROUP BY v.severity
    `)
    .all<{ severity: string; count: number }>();

  const summary = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const row of results) {
    if (row.severity in summary) (summary as Record<string, number>)[row.severity] = row.count;
  }
  return summary;
}

export async function touchRepoLastScanned(db: D1Database, repoId: string): Promise<void> {
  await db.prepare('UPDATE repos SET last_scanned_at = unixepoch() WHERE id = ?').bind(repoId).run();
}
// ── Code Quality ──────────────────────────────────────────────────────────────

export interface CodeQualityRow {
  id:                     string;
  repo_id:                string;
  repo_name?:             string;
  scan_run_id:            string;
  source:                 string;
  sonar_project_key:      string;
  reliability_rating:     string | null;
  maintainability_rating: string | null;
  security_rating:        string | null;
  code_smells:            number | null;
  duplicated_lines_pct:   number | null;
  complexity:             number | null;
  cognitive_complexity:   number | null;
  coverage_pct:           number | null;
  lines_of_code:          number | null;
  security_hotspots:      number | null;
  technical_debt_mins:    number | null;
  created_at:             number;
}

export async function insertCodeQuality(
  db:         D1Database,
  scanRunId:  string,
  repoId:     string,
  repoSlug:   string,
  metrics: {
    reliability_rating:     string;
    maintainability_rating: string;
    security_rating:        string;
    code_smells:            number;
    lines_of_code:          number;
    security_hotspots:      number;
    technical_debt_mins:    number;
    duplicated_lines_pct:   number | null;
    complexity:             number | null;
    cognitive_complexity:   number | null;
    coverage_pct:           number | null;
  }
): Promise<void> {
  function nanoid(): string {
    return crypto.randomUUID().replace(/-/g, '').slice(0, 20);
  }
  await db.prepare(`
    INSERT INTO code_quality (
      id, repo_id, scan_run_id, source, sonar_project_key,
      reliability_rating, maintainability_rating, security_rating,
      code_smells, duplicated_lines_pct, complexity, cognitive_complexity,
      coverage_pct, lines_of_code, security_hotspots, technical_debt_mins
    ) VALUES (?, ?, ?, 'github', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    nanoid(), repoId, scanRunId, repoSlug,
    metrics.reliability_rating,
    metrics.maintainability_rating,
    metrics.security_rating,
    metrics.code_smells,
    metrics.duplicated_lines_pct,
    metrics.complexity,
    metrics.cognitive_complexity,
    metrics.coverage_pct,
    metrics.lines_of_code,
    metrics.security_hotspots,
    metrics.technical_debt_mins,
  ).run();
}

export async function getLatestQualityAll(db: D1Database): Promise<CodeQualityRow[]> {
  // Guard: if the code_quality table doesn't exist yet (migration not run),
  // return [] instead of crashing the worker with a D1 error.
  try {
    const { results } = await db.prepare(`
      SELECT cq.*, r.name as repo_name
      FROM code_quality cq
      JOIN repos r ON cq.repo_id = r.id
      JOIN (
        SELECT repo_id, MAX(created_at) as max_created
        FROM code_quality
        GROUP BY repo_id
      ) latest ON cq.repo_id = latest.repo_id AND cq.created_at = latest.max_created
      ORDER BY r.name
    `).all<CodeQualityRow>();
    return results;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    // Table missing — migration not yet applied
    if (msg.includes('no such table')) {
      console.warn('[db] code_quality table not found — run migration 0003. Returning [].');
      return [];
    }
    throw e;
  }
}

export async function getQualityHistory(db: D1Database, repoId: string): Promise<CodeQualityRow[]> {
  try {
    const { results } = await db.prepare(`
      SELECT cq.*, r.name as repo_name
      FROM code_quality cq
      JOIN repos r ON cq.repo_id = r.id
      WHERE cq.repo_id = ?
      ORDER BY cq.created_at DESC
      LIMIT 20
    `).bind(repoId).all<CodeQualityRow>();
    return results;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (msg.includes('no such table')) {
      console.warn('[db] code_quality table not found — run migration 0003. Returning [].');
      return [];
    }
    throw e;
  }
}

export async function syncSonarProjectKeys(
  _db: D1Database,
  _projects: unknown[]
): Promise<number> {
  // Stub — SonarCloud removed. Quality data now comes from GitHub scans.
  console.warn('[db] syncSonarProjectKeys called but SonarCloud is no longer in use');
  return 0;
}