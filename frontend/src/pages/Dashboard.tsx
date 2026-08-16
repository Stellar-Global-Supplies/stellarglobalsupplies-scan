import { useState, useEffect, useCallback } from 'react';
import { supabase } from '../lib/supabase';
import { api, RepoWithStatus, Vulnerability, VulnSummary, CodeQuality } from '../lib/api';
import RepoCard    from '../components/RepoCard';
import VulnTable   from '../components/VulnTable';
import QualityCard from '../components/QualityCard';   // NEW

type Tab = 'repos' | 'vulns' | 'quality';

export default function Dashboard() {
  const [tab,      setTab]      = useState<Tab>('repos');
  const [repos,    setRepos]    = useState<RepoWithStatus[]>([]);
  const [vulns,    setVulns]    = useState<Vulnerability[]>([]);
  const [quality,  setQuality]  = useState<CodeQuality[]>([]);
  const [summary,  setSummary]  = useState<VulnSummary>({ critical:0, high:0, medium:0, low:0 });
  const [loading,  setLoading]  = useState(true);
  const [scanning, setScanning] = useState(false);
  const [syncing,  setSyncing]  = useState(false);
  const [sonarSync, setSonarSync] = useState(false);
  const [error,    setError]    = useState<string | null>(null);

  // Vuln filters
  const [sevFilter,  setSevFilter]  = useState('all');
  const [fixFilter,  setFixFilter]  = useState('all');
  const [repoFilter, setRepoFilter] = useState('all');

  // Quality filters
  const [qualityFilter, setQualityFilter] = useState('all');  // A|B|C|D|E|all

  const loadData = useCallback(async (autoSync = false) => {
    try {
      const [reposRes, summaryRes] = await Promise.all([
        api.repos.list(),
        api.vulns.summary(),
      ]);

      if (reposRes.repos.length === 0 && autoSync) {
        setSyncing(true);
        try {
          await api.repos.syncFromSnyk();
          const refreshed = await api.repos.list();
          setRepos(refreshed.repos);
        } finally {
          setSyncing(false);
        }
      } else {
        setRepos(reposRes.repos);
      }

      setSummary(summaryRes.summary);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load');
    } finally {
      setLoading(false);
    }
  }, []);

  const loadVulns = useCallback(async () => {
    const filters: Record<string, string> = {};
    if (sevFilter  !== 'all') filters.severity = sevFilter;
    if (fixFilter  !== 'all') filters.fixable  = String(fixFilter === 'fixable');
    if (repoFilter !== 'all') filters.repo_id  = repoFilter;
    const res = await api.vulns.list(filters);
    setVulns(res.vulnerabilities);
  }, [sevFilter, fixFilter, repoFilter]);

  const loadQuality = useCallback(async () => {
    const res = await api.quality.all();
    setQuality(res.quality);
  }, []);

  useEffect(() => { loadData(true); }, [loadData]);

  useEffect(() => {
    if (tab === 'vulns')   loadVulns();
    if (tab === 'quality') loadQuality();
  }, [tab, loadVulns, loadQuality]);

  // Poll while scans are active
  useEffect(() => {
    const hasActive = repos.some(r =>
      r.latest_scan?.status === 'queued' || r.latest_scan?.status === 'scanning'
    );
    if (!hasActive) return;
    const timer = setInterval(loadData, 4000);
    return () => clearInterval(timer);
  }, [repos, loadData]);

  async function syncFromSnyk() {
    setSyncing(true);
    try {
      const res = await api.repos.syncFromSnyk();
      await loadData();
      alert(res.message);
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : 'Sync failed');
    } finally {
      setSyncing(false);
    }
  }

  async function syncSonarCloud() {
    setSonarSync(true);
    try {
      const res = await api.quality.sync();
      alert(res.message);
      if (tab === 'quality') await loadQuality();
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : 'SonarCloud sync failed');
    } finally {
      setSonarSync(false);
    }
  }

  async function scanAll() {
    setScanning(true);
    try {
      const res = await api.scans.scanAll();
      alert(res.message);
      await loadData();
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : 'Scan failed');
    } finally {
      setScanning(false);
    }
  }

  async function scanOne(repoId: string) {
    try {
      await api.scans.scanOne(repoId);
      await loadData();
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : 'Scan failed');
    }
  }

  async function fixVuln(repoId: string, issueId: string) {
    try {
      const res = await api.vulns.fix(repoId, [issueId]);
      alert(`Fix PR created: ${res.pr_url}`);
      await loadVulns();
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : 'Fix PR failed');
    }
  }

  async function signOut() {
    await supabase.auth.signOut();
    window.location.href = '/';
  }

  if (loading || syncing) return (
    <div style={s.center}>
      <div style={{ textAlign:'center' }}>
        <div style={{ fontSize:32, marginBottom:12 }}>🛡️</div>
        <p style={{ color:'#888', fontSize:14 }}>
          {syncing ? 'Syncing repositories from Snyk…' : 'Loading…'}
        </p>
      </div>
    </div>
  );

  if (error) return <div style={s.center}><p style={{ color:'red' }}>{error}</p></div>;

  const totalIssues = summary.critical + summary.high + summary.medium + summary.low;

  // Quality filtered list
  const filteredQuality = qualityFilter === 'all'
    ? quality
    : quality.filter(q =>
        q.reliability_rating     === qualityFilter ||
        q.maintainability_rating === qualityFilter ||
        q.security_rating        === qualityFilter
      );

  // Repos missing SonarCloud project key
  const missingsonar = repos.filter(r => !r.sonar_project_key).length;

  return (
    <div style={s.page}>
      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <header style={s.header}>
        <div>
          <div style={s.brandRow}>
            <span style={s.brandIcon}>🛡️</span>
            <div>
              <h1 style={s.title}>Stellar Global Supplies</h1>
              <p style={s.subtitle}>Security & Code Quality · scan.stellarglobalsupplies.com</p>
            </div>
          </div>
        </div>
        <div style={s.headerRight}>
          <button onClick={syncSonarCloud} disabled={sonarSync} style={s.sonarBtn}
            title="Match SonarCloud projects to repos in D1">
            {sonarSync ? '⏳ Syncing…' : '📊 Sync SonarCloud'}
          </button>
          <button onClick={syncFromSnyk} disabled={syncing} style={s.syncBtn}>
            {syncing ? '⏳ Syncing…' : '🔄 Sync from Snyk'}
          </button>
          <button onClick={scanAll} disabled={scanning} style={s.scanAllBtn}>
            {scanning ? '⏳ Queuing…' : '⚡ Scan All'}
          </button>
          <button onClick={signOut} style={s.signOutBtn}>Sign out</button>
        </div>
      </header>

      {/* ── Summary metrics ────────────────────────────────────────────────── */}
      <div style={s.metrics}>
        {([
          { label:'Critical', val: summary.critical, color:'#E24B4A' },
          { label:'High',     val: summary.high,     color:'#EF9F27' },
          { label:'Medium',   val: summary.medium,   color:'#639922' },
          { label:'Low',      val: summary.low,      color:'#378ADD' },
          { label:'Total',    val: totalIssues,       color:'#888'    },
          { label:'Repos',    val: repos.length,      color:'#1B3A6B' },
        ]).map(m => (
          <div key={m.label} style={{ ...s.metricCard, borderLeft:`3px solid ${m.color}` }}>
            <div style={s.metricLabel}>{m.label}</div>
            <div style={{ ...s.metricVal, color: m.color }}>{m.val}</div>
          </div>
        ))}
      </div>

      {/* Cron notice */}
      <div style={s.cronBadge}>
        🕐 Auto-scan: daily 06:00 UTC (Snyk vulns) + 18:00 UTC (Snyk + SonarCloud quality) · Cloudflare cron
      </div>

      {/* ── Tabs ────────────────────────────────────────────────────────────── */}
      <div style={s.tabs}>
        {([
          { key:'repos',   label:`Repositories (${repos.length})` },
          { key:'vulns',   label:`Vulnerabilities (${totalIssues})` },
          { key:'quality', label:`Code Quality (${quality.length})` },
        ] as { key: Tab; label: string }[]).map(t => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            style={tab === t.key ? s.tabActive : s.tab}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* ── Repos tab ───────────────────────────────────────────────────────── */}
      {tab === 'repos' && (
        <>
          {missingsonar > 0 && (
            <div style={s.warnBanner}>
              ⚠ {missingsonar} repo{missingsonar > 1 ? 's' : ''} not linked to SonarCloud yet.
              Click <strong>Sync SonarCloud</strong> above after importing them at{' '}
              <a href="https://sonarcloud.io" target="_blank" rel="noreferrer">sonarcloud.io</a>.
            </div>
          )}
          <div style={s.repoGrid}>
            {repos.map(repo => (
              <RepoCard key={repo.id} repo={repo} onScan={() => scanOne(repo.id)} />
            ))}
          </div>
        </>
      )}

      {/* ── Vulns tab ───────────────────────────────────────────────────────── */}
      {tab === 'vulns' && (
        <>
          <div style={s.filters}>
            <select value={sevFilter}  onChange={e => setSevFilter(e.target.value)}  style={s.select}>
              <option value="all">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <select value={fixFilter}  onChange={e => setFixFilter(e.target.value)}  style={s.select}>
              <option value="all">All issues</option>
              <option value="fixable">Fixable only</option>
              <option value="manual">Manual fix only</option>
            </select>
            <select value={repoFilter} onChange={e => setRepoFilter(e.target.value)} style={s.select}>
              <option value="all">All repos</option>
              {repos.map(r => <option key={r.id} value={r.id}>{r.name}</option>)}
            </select>
            <button onClick={loadVulns} style={s.refreshBtn}>↻ Refresh</button>
          </div>
          <VulnTable vulns={vulns} onFix={fixVuln} />
        </>
      )}

      {/* ── Quality tab ─────────────────────────────────────────────────────── */}
      {tab === 'quality' && (
        <>
          <div style={s.filters}>
            <select value={qualityFilter} onChange={e => setQualityFilter(e.target.value)} style={s.select}>
              <option value="all">All ratings</option>
              <option value="A">A — Excellent</option>
              <option value="B">B — Good</option>
              <option value="C">C — Fair</option>
              <option value="D">D — Poor</option>
              <option value="E">E — Critical</option>
            </select>
            <button onClick={loadQuality} style={s.refreshBtn}>↻ Refresh</button>
            <span style={s.qualityNote}>
              Ratings: A (best) → E (worst) · Powered by SonarCloud
            </span>
          </div>

          {filteredQuality.length === 0 ? (
            <div style={s.emptyQuality}>
              <p>No code quality data yet.</p>
              <p style={{ marginTop:8, color:'#aaa', fontSize:13 }}>
                1. Import your repos at <a href="https://sonarcloud.io" target="_blank" rel="noreferrer">sonarcloud.io</a><br/>
                2. Click <strong>Sync SonarCloud</strong> to link them<br/>
                3. Click <strong>Scan All</strong> to fetch metrics
              </p>
            </div>
          ) : (
            <div style={s.qualityGrid}>
              {filteredQuality.map(q => (
                <QualityCard key={q.id} quality={q} />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}

const s: Record<string, React.CSSProperties> = {
  page:        { maxWidth:1200, margin:'0 auto', padding:'1.5rem 1rem' },
  center:      { minHeight:'100vh', display:'flex', alignItems:'center', justifyContent:'center' },
  header:      { display:'flex', justifyContent:'space-between', alignItems:'flex-start', marginBottom:'1.25rem', flexWrap:'wrap', gap:10 },
  brandRow:    { display:'flex', alignItems:'center', gap:10 },
  brandIcon:   { fontSize:28 },
  headerRight: { display:'flex', gap:8, alignItems:'center', flexWrap:'wrap' },
  title:       { fontSize:20, fontWeight:600, margin:'0 0 2px', color:'#1B3A6B' },
  subtitle:    { fontSize:12, color:'#888', margin:0 },
  sonarBtn:    { padding:'7px 12px', background:'#fff', color:'#1B3A6B', border:'1px solid #1B3A6B', borderRadius:8, fontSize:12, fontWeight:500, cursor:'pointer' },
  syncBtn:     { padding:'7px 12px', background:'#f5f5f0', color:'#555', border:'0.5px solid #ddd', borderRadius:8, fontSize:12, cursor:'pointer' },
  scanAllBtn:  { padding:'7px 14px', background:'#1B3A6B', color:'#fff', border:'none', borderRadius:8, fontSize:12, fontWeight:500, cursor:'pointer' },
  signOutBtn:  { padding:'7px 10px', background:'transparent', border:'0.5px solid #ddd', borderRadius:8, fontSize:12, cursor:'pointer', color:'#888' },
  metrics:     { display:'grid', gridTemplateColumns:'repeat(6,1fr)', gap:8, marginBottom:'1rem' },
  metricCard:  { background:'#fff', border:'0.5px solid #e8e8e0', borderRadius:8, padding:'10px 12px' },
  metricLabel: { fontSize:11, color:'#888', marginBottom:3 },
  metricVal:   { fontSize:20, fontWeight:600 },
  cronBadge:   { background:'#EEF2FF', border:'0.5px solid #C7D2FE', borderRadius:8, padding:'8px 14px', fontSize:12, color:'#3730A3', marginBottom:'1rem' },
  tabs:        { display:'flex', borderBottom:'0.5px solid #e8e8e0', marginBottom:'1rem' },
  tab:         { padding:'8px 18px', background:'none', border:'none', borderBottom:'2px solid transparent', fontSize:13, cursor:'pointer', color:'#888' },
  tabActive:   { padding:'8px 18px', background:'none', border:'none', borderBottom:'2px solid #1B3A6B', fontSize:13, cursor:'pointer', color:'#1B3A6B', fontWeight:600 },
  repoGrid:    { display:'grid', gridTemplateColumns:'repeat(auto-fill,minmax(300px,1fr))', gap:10 },
  qualityGrid: { display:'grid', gridTemplateColumns:'repeat(auto-fill,minmax(320px,1fr))', gap:10 },
  filters:     { display:'flex', gap:8, marginBottom:'1rem', flexWrap:'wrap', alignItems:'center' },
  select:      { padding:'6px 10px', border:'0.5px solid #ddd', borderRadius:8, fontSize:13, background:'#fff', cursor:'pointer' },
  refreshBtn:  { padding:'6px 12px', border:'0.5px solid #ddd', borderRadius:8, fontSize:13, cursor:'pointer', background:'#fff' },
  qualityNote: { fontSize:12, color:'#888', marginLeft:4 },
  warnBanner:  { background:'#FFFBEB', border:'0.5px solid #FDE68A', borderRadius:8, padding:'10px 14px', fontSize:13, color:'#92400E', marginBottom:'1rem' },
  emptyQuality:{ padding:'3rem', textAlign:'center', color:'#888', background:'#fff', borderRadius:10, border:'0.5px solid #e8e8e0', lineHeight:2 },
};
