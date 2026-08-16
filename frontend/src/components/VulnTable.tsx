import { useState } from 'react';
import { Vulnerability } from '../lib/api';

interface Props {
  vulns:  Vulnerability[];
  onFix:  (repoId: string, issueId: string) => Promise<void>;
}

const SEV_STYLE: Record<string, React.CSSProperties> = {
  critical: { background:'#FCEBEB', color:'#A32D2D', border:'0.5px solid #f5c6c6' },
  high:     { background:'#FAEEDA', color:'#854F0B', border:'0.5px solid #f5d9a0' },
  medium:   { background:'#EAF3DE', color:'#3B6D11', border:'0.5px solid #c5e0a0' },
  low:      { background:'#E6F1FB', color:'#185FA5', border:'0.5px solid #b0d0f0' },
};

export default function VulnTable({ vulns, onFix }: Props) {
  const [fixing, setFixing] = useState<Set<string>>(new Set());

  async function handleFix(repoId: string, issueId: string | null) {
    if (!issueId) return;
    setFixing(prev => new Set(prev).add(issueId));
    try {
      await onFix(repoId, issueId);
    } finally {
      setFixing(prev => { const s = new Set(prev); s.delete(issueId); return s; });
    }
  }

  if (vulns.length === 0) {
    return <div style={s.empty}>No vulnerabilities found for the selected filters.</div>;
  }

  return (
    <div style={s.wrap}>
      <table style={s.table}>
        <thead>
          <tr>
            {['Severity','Title','Package','Repo','CVE','Fix available','Action'].map(h => (
              <th key={h} style={s.th}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {vulns.map(v => {
            const isFixing  = fixing.has(v.snyk_issue_id ?? '');
            const hasPR     = !!v.fix_pr_url;
            return (
              <tr key={v.id} style={{ opacity: hasPR ? 0.5 : 1 }}>
                <td style={s.td}>
                  <span style={{ ...s.sevBadge, ...SEV_STYLE[v.severity] }}>
                    {v.severity.toUpperCase()}
                  </span>
                </td>
                <td style={{ ...s.td, ...s.titleCell }}>
                  <div style={s.vulnTitle}>{v.title}</div>
                </td>
                <td style={s.td}>
                  <code style={s.pkg}>{v.package_name}@{v.from_version}</code>
                  {v.to_version && (
                    <div style={s.toVer}>→ {v.to_version}</div>
                  )}
                </td>
                <td style={s.td}>
                  <span style={s.repoTag}>{v.repo_name ?? v.repo_id}</span>
                </td>
                <td style={s.td}>
                  <span style={s.cve}>{v.cve ?? '—'}</span>
                </td>
                <td style={{ ...s.td, textAlign:'center' }}>
                  {v.fixable ? (
                    <span style={s.fixYes}>✓ Yes</span>
                  ) : (
                    <span style={s.fixNo}>Manual</span>
                  )}
                </td>
                <td style={s.td}>
                  {hasPR ? (
                    <a href={v.fix_pr_url!} target="_blank" rel="noreferrer" style={s.prLink}>
                      View PR ↗
                    </a>
                  ) : v.fixable && v.snyk_issue_id ? (
                    <button
                      onClick={() => handleFix(v.repo_id, v.snyk_issue_id)}
                      disabled={isFixing}
                      style={{ ...s.fixBtn, opacity: isFixing ? 0.5 : 1 }}
                    >
                      {isFixing ? 'Creating…' : '⚡ Fix PR'}
                    </button>
                  ) : (
                    <span style={s.noAction}>—</span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

const s: Record<string, React.CSSProperties> = {
  wrap:      { overflowX:'auto', background:'#fff', border:'0.5px solid #e8e8e0', borderRadius:10 },
  table:     { width:'100%', borderCollapse:'collapse', fontSize:13 },
  th:        { padding:'10px 14px', textAlign:'left', fontSize:11, fontWeight:600, color:'#888', borderBottom:'0.5px solid #e8e8e0', whiteSpace:'nowrap', background:'#fafaf8' },
  td:        { padding:'10px 14px', borderBottom:'0.5px solid #f0f0e8', verticalAlign:'middle' },
  sevBadge:  { fontSize:10, fontWeight:700, padding:'2px 7px', borderRadius:99, whiteSpace:'nowrap' },
  titleCell: { maxWidth:260 },
  vulnTitle: { fontWeight:500, color:'#1a1a18', lineHeight:1.3 },
  pkg:       { fontSize:11, color:'#555', fontFamily:'monospace', display:'block' },
  toVer:     { fontSize:11, color:'#639922', marginTop:2 },
  repoTag:   { fontSize:11, padding:'2px 7px', background:'#f0f0e8', borderRadius:4, color:'#555', whiteSpace:'nowrap' },
  cve:       { fontSize:11, color:'#888', fontFamily:'monospace' },
  fixYes:    { fontSize:11, color:'#3B6D11', fontWeight:500 },
  fixNo:     { fontSize:11, color:'#aaa' },
  fixBtn:    { padding:'4px 10px', background:'#1B3A6B', color:'#fff', border:'none', borderRadius:6, fontSize:11, fontWeight:500, cursor:'pointer', whiteSpace:'nowrap' },
  prLink:    { fontSize:11, color:'#1B3A6B', fontWeight:500, textDecoration:'none' },
  noAction:  { color:'#ccc', fontSize:13 },
  empty:     { padding:'3rem', textAlign:'center', color:'#999', fontSize:14 },
};
