import { useState, useEffect, useCallback } from 'react';
import { supabase } from '../lib/supabase';
import { api, RepoWithStatus, Vulnerability, VulnSummary, CodeQuality } from '../lib/api';
import RepoCard    from '../components/RepoCard';
import VulnTable   from '../components/VulnTable';
import QualityCard from '../components/QualityCard';

type Tab = 'repos' | 'vulns' | 'quality';

export default function Dashboard() {
  const [tab,      setTab]      = useState<Tab>('repos');
  const [repos,    setRepos]    = useState<RepoWithStatus[]>([]);
  const [vulns,    setVulns]    = useState<Vulnerability[]>([]);
  const [quality,  setQuality]  = useState<CodeQuality[]>([]);
  const [summary,  setSummary]  = useState<VulnSummary>({ critical:0, high:0, medium:0, low:0 });
  const [loading,  setLoading]  = useState(true);
  const [scanning,   setScanning]   = useState(false);
  const [githubSync, setGithubSync] = useState(false);
  const [error,    setError]    = useState<string | null>(null);

  // Vuln filters
  const [sevFilter,    setSevFilter]    = useState('all');
  const [fixFilter,    setFixFilter]    = useState('all');
  const [repoFilter,   setRepoFilter]   = useState('all');
  const [sourceFilter, setSourceFilter] = useState('all');

  const loadData = useCallback(async () => {
    try {
      const [reposRes, summaryRes] = await Promise.all([
        api.repos.list(),
        api.vulns.summary(),
      ]);
      setRepos(reposRes.repos);
      setSummary(summaryRes.summary);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load');
    } finally {
      setLoading(false);
    }
  }, []);

  const loadVulns = useCallback(async () => {
    const filters: Record<string, string> = {};
    if (sevFilter    !== 'all') filters.severity = sevFilter;
    if (fixFilter    !== 'all') filters.fixable  = String(fixFilter === 'fixable');
    if (repoFilter   !== 'all') filters.repo_id  = repoFilter;
    if (sourceFilter !== 'all') filters.source   = sourceFilter;
    const res = await api.vulns.list(filters);
    setVulns(res.vulnerabilities);
  }, [sevFilter, fixFilter, repoFilter, sourceFilter]);

  const loadQuality = useCallback(async () => {
    try {
      const res = await api.quality.list();
      setQuality(res.quality);
    } catch {
      // quality data is optional — don't break the page if unavailable
      setQuality([]);
    }
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  useEffect(() => {
    if (tab === 'vulns')   loadVulns();
    if (tab === 'quality') loadQuality();
  }, [tab, loadVulns, loadQuality]);

  // Poll while scans are active; reload vulns + quality too so tabs stay live
  useEffect(() => {
    const hasActive = repos.some(r =>
      r.latest_scan?.status === 'queued' || r.latest_scan?.status === 'scanning'
    );
    if (!hasActive) return;

    const timer = setInterval(async () => {
      await loadData();
      loadVulns();
      if (tab === 'quality') loadQuality();
    }, 4000);
    return () => clearInterval(timer);
  }, [repos, tab, loadData, loadVulns, loadQuality]);

  async function syncFromGitHub() {
    setGithubSync(true);
    try {
      const res = await api.repos.syncFromGitHub();
      await loadData();
      alert(res.message);
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : 'GitHub sync failed');
    } finally {
      setGithubSync(false);
    }
  }

  async function scanAll() {
    setScanning(true);
    try {
      const res = await api.scans.scanAll();
      await loadData();
      setTab('vulns');
      alert(res.message + '\n\nSwitching to Vulnerabilities tab — results will appear as scans complete.');
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

  async function signOut() {
    await supabase.auth.signOut();
    window.location.href = '/';
  }

  if (loading) return (
    <div style={s.center}>
      <div style={{ textAlign:'center' }}>
        <div style={{ fontSize:32, marginBottom:12 }}>🛡️</div>
        <p style={{ color:'#888', fontSize:14 }}>Loading…</p>
      </div>
    </div>
  );

  if (error) return <div style={s.center}><p style={{ color:'red' }}>{error}</p></div>;

  const totalIssues = summary.critical + summary.high + summary.medium + summary.low;

  return (
    <div style={s.page}>
      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <header style={s.header}>
        <div>
          <div style={s.brandRow}>
            <span style={s.brandIcon}>🛡️</span>
            <div>
              <h1 style={s.title}>Stellar Global Supplies</h1>
              <p style={s.subtitle}>Security Scanning · scan.stellarglobalsupplies.com</p>
            </div>
          </div>
        </div>
        <div style={s.headerRight}>
          <button onClick={syncFromGitHub} disabled={githubSync} style={s.syncBtn}
            title="Pull latest repos from GitHub org into the database">
            {githubSync ? '⏳ Syncing…' : '🐙 Sync GitHub'}
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
        🕐 Auto-scan: daily 06:00 UTC + 18:00 UTC · GitHub Dependabot + Code Scanning · Cloudflare cron
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
        <div style={s.repoGrid}>
          {repos.map(repo => (
            <RepoCard key={repo.id} repo={repo} onScan={() => scanOne(repo.id)} />
          ))}
        </div>
      )}

      {/* ── Vulns tab ───────────────────────────────────────────────────────── */}
      {tab === 'vulns' && (
        <>
          <div style={s.filters}>
            <select value={sevFilter}    onChange={e => setSevFilter(e.target.value)}    style={s.select}>
              <option value="all">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <select value={fixFilter}    onChange={e => setFixFilter(e.target.value)}    style={s.select}>
              <option value="all">All issues</option>
              <option value="fixable">Fixable only</option>
              <option value="manual">Manual fix only</option>
            </select>
            <select value={sourceFilter} onChange={e => setSourceFilter(e.target.value)} style={s.select}>
              <option value="all">All sources</option>
              <option value="github_dependabot">Dependabot</option>
              <option value="github_code_scanning">Code Scanning</option>
            </select>
            <select value={repoFilter}   onChange={e => setRepoFilter(e.target.value)}   style={s.select}>
              <option value="all">All repos</option>
              {repos.map(r => <option key={r.id} value={r.id}>{r.name}</option>)}
            </select>
            <button onClick={loadVulns} style={s.refreshBtn}>↻ Refresh</button>
          </div>
          <VulnTable vulns={vulns} />
        </>
      )}

      {/* ── Quality tab ─────────────────────────────────────────────────────── */}
      {tab === 'quality' && (
        <>
          {quality.length === 0 ? (
            <div style={s.emptyState}>
              <div style={{ fontSize:32, marginBottom:8 }}>📊</div>
              <p style={{ fontWeight:600, marginBottom:4 }}>No code quality data yet</p>
              <p style={{ color:'#aaa', fontSize:13 }}>
                Run a scan to populate quality metrics from GitHub Code Scanning.
              </p>
            </div>
          ) : (
            <div style={s.qualityGrid}>
              {quality.map(q => (
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
  qualityGrid: { display:'grid', gridTemplateColumns:'repeat(auto-fill,minmax(340px,1fr))', gap:10 },
  filters:     { display:'flex', gap:8, marginBottom:'1rem', flexWrap:'wrap', alignItems:'center' },
  select:      { padding:'6px 10px', border:'0.5px solid #ddd', borderRadius:8, fontSize:13, background:'#fff', cursor:'pointer' },
  refreshBtn:  { padding:'6px 12px', border:'0.5px solid #ddd', borderRadius:8, fontSize:13, cursor:'pointer', background:'#fff' },
  emptyState:  { textAlign:'center', padding:'3rem', background:'#fff', border:'0.5px solid #e8e8e0', borderRadius:10, color:'#888' },
};