import { RepoWithStatus } from '../lib/api';

interface Props {
  repo:   RepoWithStatus;
  onScan: () => void;
}

const statusColor: Record<string, string> = {
  done:     '#639922',
  scanning: '#378ADD',
  queued:   '#EF9F27',
  failed:   '#E24B4A',
};

const statusLabel: Record<string, string> = {
  done:     '✓ Done',
  scanning: '⏳ Scanning…',
  queued:   '🕐 Queued',
  failed:   '✗ Failed',
};

function ago(ts: number | null): string {
  if (!ts) return 'Never scanned';
  const diff = Math.floor((Date.now() / 1000) - ts);
  if (diff < 60)   return 'Just now';
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export default function RepoCard({ repo, onScan }: Props) {
  const scan   = repo.latest_scan;
  const status = scan?.status ?? null;
  const color  = status ? (statusColor[status] ?? '#888') : '#ccc';
  const active = status === 'scanning' || status === 'queued';

  return (
    <div style={s.card}>
      <div style={s.top}>
        <div style={{ flex:1, minWidth:0 }}>
          <div style={s.name}>{repo.name}</div>
          <a href={repo.github_url} target="_blank" rel="noreferrer" style={s.url}>
            {repo.github_url.replace('https://github.com/', '')}
          </a>
        </div>
        {status && (
          <span style={{ ...s.statusBadge, color, borderColor: color + '44', background: color + '11' }}>
            {statusLabel[status] ?? status}
          </span>
        )}
      </div>

      <div style={s.meta}>
        <span>Last scan: {ago(repo.last_scanned_at)}</span>
        {scan?.vuln_count !== undefined && scan.vuln_count > 0 && (
          <span style={s.vulnCount}>{scan.vuln_count} issues</span>
        )}
        {!repo.snyk_project_id && (
          <span style={s.notImported}>⚠ Not imported to Snyk</span>
        )}
      </div>

      <button
        onClick={onScan}
        disabled={active || !repo.snyk_project_id}
        style={{
          ...s.btn,
          opacity: (active || !repo.snyk_project_id) ? 0.5 : 1,
          cursor:  (active || !repo.snyk_project_id) ? 'not-allowed' : 'pointer',
        }}
      >
        {active ? 'Scanning…' : '⚡ Scan now'}
      </button>
    </div>
  );
}

const s: Record<string, React.CSSProperties> = {
  card:       { background:'#fff', border:'0.5px solid #e8e8e0', borderRadius:10, padding:'14px 16px' },
  top:        { display:'flex', alignItems:'flex-start', gap:10, marginBottom:8 },
  name:       { fontSize:14, fontWeight:600, color:'#1a1a18', marginBottom:2, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' },
  url:        { fontSize:11, color:'#999', textDecoration:'none' },
  statusBadge:{ fontSize:11, fontWeight:500, padding:'2px 8px', borderRadius:99, border:'0.5px solid', whiteSpace:'nowrap', flexShrink:0 },
  meta:       { display:'flex', gap:10, alignItems:'center', fontSize:12, color:'#888', marginBottom:12, flexWrap:'wrap' },
  vulnCount:  { background:'#FCEBEB', color:'#A32D2D', borderRadius:99, padding:'1px 7px', fontSize:11, fontWeight:500 },
  notImported:{ color:'#EF9F27', fontSize:11 },
  btn:        { width:'100%', padding:'7px 0', background:'#1a1a18', color:'#fff', border:'none', borderRadius:7, fontSize:13, fontWeight:500 },
};
