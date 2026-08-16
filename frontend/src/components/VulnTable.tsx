import { Vulnerability } from '../lib/api';

interface Props {
  vulns: Vulnerability[];
}

const SEV_COLOR: Record<string, { bg: string; color: string }> = {
  critical: { bg: '#FCEBEB', color: '#A32D2D' },
  high:     { bg: '#FEF3DC', color: '#7A4B00' },
  medium:   { bg: '#EDF7E1', color: '#2D5A0E' },
  low:      { bg: '#E8F0FB', color: '#1B3A6B' },
};

function ago(ts: number): string {
  const diff = Math.floor((Date.now() / 1000) - ts);
  if (diff < 3600)  return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export default function VulnTable({ vulns }: Props) {
  if (vulns.length === 0) {
    return (
      <div style={s.empty}>
        <p>No vulnerabilities found.</p>
        <p style={{ marginTop: 6, color: '#aaa', fontSize: 13 }}>
          Run a scan on one or more repos to populate this list.
        </p>
      </div>
    );
  }

  return (
    <div style={s.container}>
      <table style={s.table}>
        <thead>
          <tr>
            {['Severity','Repo','Package','Version','CVE','Fixable','Source','Found'].map(h => (
              <th key={h} style={s.th}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {vulns.map(v => {
            const sev = SEV_COLOR[v.severity] ?? { bg: '#f5f5f0', color: '#555' };
            return (
              <tr key={v.id} style={s.tr}>
                <td style={s.td}>
                  <span style={{ ...s.badge, background: sev.bg, color: sev.color }}>
                    {v.severity}
                  </span>
                </td>
                <td style={{ ...s.td, ...s.repoCell }}>{v.repo_name ?? v.repo_id}</td>
                <td style={s.td}><code style={s.code}>{v.package_name}</code></td>
                <td style={s.td}>
                  <span style={s.version}>{v.from_version}</span>
                  {v.to_version && (
                    <span style={s.arrow}> → <span style={s.fixVersion}>{v.to_version}</span></span>
                  )}
                </td>
                <td style={s.td}>
                  {v.cve
                    ? <a href={`https://nvd.nist.gov/vuln/detail/${v.cve}`} target="_blank" rel="noreferrer" style={s.cveLink}>{v.cve}</a>
                    : <span style={s.muted}>—</span>
                  }
                </td>
                <td style={s.td}>
                  {v.fixable === 1
                    ? <span style={s.fixYes}>✓ Yes</span>
                    : <span style={s.muted}>Manual</span>
                  }
                </td>
                <td style={s.td}><span style={s.source}>{v.source.replace('github_', '').replace('_', ' ')}</span></td>
                <td style={s.td}><span style={s.muted}>{ago(v.created_at)}</span></td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

const s: Record<string, React.CSSProperties> = {
  container:   { overflowX: 'auto', background: '#fff', border: '0.5px solid #e8e8e0', borderRadius: 10 },
  table:       { width: '100%', borderCollapse: 'collapse', fontSize: 12 },
  th:          { padding: '10px 12px', textAlign: 'left', color: '#888', fontWeight: 500, borderBottom: '0.5px solid #e8e8e0', whiteSpace: 'nowrap' },
  tr:          { borderBottom: '0.5px solid #f0f0e8' },
  td:          { padding: '9px 12px', verticalAlign: 'middle' },
  repoCell:    { fontWeight: 500, color: '#1a1a18', maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' },
  badge:       { padding: '2px 8px', borderRadius: 99, fontWeight: 600, fontSize: 11 },
  code:        { background: '#f5f5f0', padding: '1px 5px', borderRadius: 4, fontFamily: 'monospace', fontSize: 11 },
  version:     { color: '#555' },
  arrow:       { color: '#aaa' },
  fixVersion:  { color: '#2D5A0E', fontWeight: 500 },
  cveLink:     { color: '#1B3A6B', textDecoration: 'none', fontFamily: 'monospace', fontSize: 11 },
  muted:       { color: '#aaa' },
  fixYes:      { color: '#2D5A0E', fontWeight: 500 },
  source:      { textTransform: 'capitalize' as const, color: '#555' },
  empty:       { padding: '3rem', textAlign: 'center', color: '#888', background: '#fff', borderRadius: 10, border: '0.5px solid #e8e8e0' },
};