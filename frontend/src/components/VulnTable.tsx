// Vulnerability table component
import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { Vulnerability } from '../lib/api';

interface VulnRowProps {
  vulnerability: Vulnerability;
  onEdit: (id: string) => void;
}

export default function VulnTable({ vuln }: VulnRowProps) {
  const { repo_id } = useParams();

  return (
    <div className="table-container">
      <table>
        <thead>
          <tr>
            <th>CVE</th>
            <th>Severity</th>
            <th>Package</th>
            <th>From Version</th>
            <th>To Version</th>
            <th>Fixable</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>{vuln.cve ?? 'N/A'}</td>
            <td>{vuln.severity}</td>
            <td>{vuln.package_name}</td>
            <td>{vuln.from_version}</td>
            <td>{vuln.to_version ?? 'N/A'}</td>
            <td>{vuln.fixable === 1 ? 'Yes' : 'No'}</td>
            <td>
              {/* Fix PR button removed - Free plan limitation */}
              <span>Fix not available on Free plan</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  );
}

interface VulnTableProps {
  vuln: Vulnerability;
}

export default function VulnTableComponent({ vuln }: VulnTableProps) {
  return <VulnRowProps {...vuln} />;
}

const styles: Record<string, React.CSSProperties> = {
  table: { width: '100%', borderCollapse: 'collapse', marginTop: '1rem' },
  th: { border: '1px solid #ddd', padding: '8px', textAlign: 'left', fontSize: '12px', color: '#555' },
  td: { border: '1px solid #ddd', padding: '8px', fontSize: '12px' },
  container: { overflowX: 'auto' },
};