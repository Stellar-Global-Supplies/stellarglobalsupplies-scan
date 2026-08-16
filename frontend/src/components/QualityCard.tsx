import { CodeQuality } from '../lib/api';

interface Props {
  quality: CodeQuality;
}

const RATING_COLOR: Record<string, { bg: string; color: string; border: string }> = {
  A: { bg: '#E8F5E9', color: '#2E7D32', border: '#A5D6A7' },
  B: { bg: '#E3F2FD', color: '#1565C0', border: '#90CAF9' },
  C: { bg: '#FFF9C4', color: '#F57F17', border: '#FFF176' },
  D: { bg: '#FFE0B2', color: '#E65100', border: '#FFCC80' },
  E: { bg: '#FCEBEB', color: '#A32D2D', border: '#F5C6C6' },
};

function RatingBadge({ rating, label }: { rating: string | null; label: string }) {
  const r     = rating ?? '?';
  const style = RATING_COLOR[r] ?? { bg: '#f0f0e8', color: '#888', border: '#ddd' };
  return (
    <div style={s.ratingWrap}>
      <div style={{ ...s.ratingBadge, background: style.bg, color: style.color, border: `1.5px solid ${style.border}` }}>
        {r}
      </div>
      <div style={s.ratingLabel}>{label}</div>
    </div>
  );
}

function debtLabel(mins: number | null): string {
  if (mins === null) return '—';
  if (mins < 60)    return `${mins}m`;
  if (mins < 480)   return `${Math.round(mins / 60)}h`;
  return `${Math.round(mins / 480)}d`;
}

function ago(ts: number): string {
  const diff = Math.floor((Date.now() / 1000) - ts);
  if (diff < 3600)  return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function sourceLabel(source: string): string {
  if (source === 'github_dependabot')     return 'Dependabot';
  if (source === 'github_code_scanning')  return 'Code Scanning';
  return source;
}

export default function QualityCard({ quality: q }: Props) {
  // sonar_project_key now stores the GitHub repo slug (kept for DB compat)
  const githubUrl = `https://github.com/Stellar-Global-Supplies/${q.sonar_project_key}`;

  return (
    <div style={s.card}>
      <div style={s.header}>
        <div style={s.repoName}>{q.repo_name ?? q.repo_id}</div>
        <a href={githubUrl} target="_blank" rel="noreferrer" style={s.githubLink}>
          GitHub ↗
        </a>
      </div>

      {/* A-E ratings row */}
      <div style={s.ratings}>
        <RatingBadge rating={q.reliability_rating}     label="Reliability"     />
        <RatingBadge rating={q.maintainability_rating} label="Maintainability" />
        <RatingBadge rating={q.security_rating}        label="Security"        />
      </div>

      {/* Numeric metrics grid */}
      <div style={s.metrics}>
        <MetricCell label="Code smells"   value={q.code_smells?.toLocaleString() ?? '—'} />
        <MetricCell label="Duplication"   value={q.duplicated_lines_pct !== null ? `${q.duplicated_lines_pct.toFixed(1)}%` : '—'} />
        <MetricCell label="Complexity"    value={q.complexity?.toLocaleString() ?? '—'} />
        <MetricCell label="Cognitive"     value={q.cognitive_complexity?.toLocaleString() ?? '—'} />
        <MetricCell label="Coverage"      value={q.coverage_pct !== null ? `${q.coverage_pct.toFixed(1)}%` : '—'} />
        <MetricCell label="Lines"         value={q.lines_of_code?.toLocaleString() ?? '—'} />
        <MetricCell label="Hotspots"      value={q.security_hotspots?.toLocaleString() ?? '—'} warn={(q.security_hotspots ?? 0) > 0} />
        <MetricCell label="Tech debt"     value={debtLabel(q.technical_debt_mins)} />
      </div>

      <div style={s.footer}>
        Scanned {ago(q.created_at)} · via {sourceLabel(q.source)}
      </div>
    </div>
  );
}

function MetricCell({ label, value, warn }: { label: string; value: string; warn?: boolean }) {
  return (
    <div style={s.metricCell}>
      <div style={{ ...s.metricVal, color: warn ? '#A32D2D' : '#1a1a18' }}>{value}</div>
      <div style={s.metricLabel}>{label}</div>
    </div>
  );
}

const s: Record<string, React.CSSProperties> = {
  card:        { background:'#fff', border:'0.5px solid #e8e8e0', borderRadius:10, padding:'14px 16px' },
  header:      { display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:12 },
  repoName:    { fontSize:14, fontWeight:600, color:'#1B3A6B', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', maxWidth:200 },
  githubLink:  { fontSize:11, color:'#1B3A6B', textDecoration:'none', whiteSpace:'nowrap' },
  ratings:     { display:'flex', gap:10, marginBottom:12 },
  ratingWrap:  { display:'flex', flexDirection:'column', alignItems:'center', gap:4, flex:1 },
  ratingBadge: { width:36, height:36, borderRadius:8, display:'flex', alignItems:'center', justifyContent:'center', fontSize:18, fontWeight:700 },
  ratingLabel: { fontSize:10, color:'#888', textAlign:'center' as const },
  metrics:     { display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:8, marginBottom:10 },
  metricCell:  { textAlign:'center' as const },
  metricVal:   { fontSize:14, fontWeight:600, color:'#1a1a18' },
  metricLabel: { fontSize:10, color:'#888', marginTop:1 },
  footer:      { fontSize:11, color:'#aaa', borderTop:'0.5px solid #f0f0e8', paddingTop:8, marginTop:4 },
};