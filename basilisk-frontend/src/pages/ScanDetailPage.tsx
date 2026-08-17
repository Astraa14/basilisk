import React, { useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { getScanDetail } from '../services/api';
import { loadApiKeyFromStorage } from '../services/auth';
import { Scan } from '../types';

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info'] as const;

const ScanDetailPage = () => {
  const { id } = useParams();
  const [scan, setScan] = useState<Scan | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('');

  useEffect(() => {
    const apiKey = loadApiKeyFromStorage();
    const scanId = Number(id);
    if (!apiKey || Number.isNaN(scanId)) {
      setError('Invalid session or scan id.');
      setLoading(false);
      return;
    }
    getScanDetail(scanId, apiKey)
      .then(setScan)
      .catch((err) => { setError(err.response?.data?.detail || 'Failed to load scan detail.'); })
      .finally(() => setLoading(false));
  }, [id]);

  const findings = useMemo(() => {
    if (!scan?.findings) return [];
    let filtered = [...scan.findings];
    if (severityFilter) {
      filtered = filtered.filter((f) => f.severity === severityFilter);
    }
    const order: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
    return filtered.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
  }, [scan, severityFilter]);

  if (loading) {
    return (
      <div className="container py-4 mt-8 flex justify-center">
        <span className="spinner" />
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="container py-4 mt-8">
        <Link to="/dashboard" className="flex items-center gap-2 text-secondary text-sm mb-6">
          <ArrowLeft size={16} /> Back to dashboard
        </Link>
        <div className="card p-6" style={{ color: 'var(--critical)' }}>{error || 'Scan not found'}</div>
      </div>
    );
  }

  return (
    <div className="container py-4 mt-8">
      <Link to="/dashboard" className="flex items-center gap-2 text-secondary text-sm mb-6">
        <ArrowLeft size={16} /> Back to dashboard
      </Link>

      <div className="flex items-center justify-between mb-6" style={{ gap: '1rem', flexWrap: 'wrap' }}>
        <div>
          <h1 className="text-xl text-bold">Scan report</h1>
          <p className="text-secondary text-sm mt-4" style={{ wordBreak: 'break-all' }}>{scan.target_url}</p>
        </div>
        {scan.vulnerable ? <span className="badge badge-high">Vulnerable</span> : <span className="badge badge-safe">Clean</span>}
      </div>

      <div className="mb-8" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '1rem' }}>
        <div className="card p-6">
          <div className="text-secondary text-sm mb-4">Pages</div>
          <div className="text-xl text-bold">{scan.pages_scanned}</div>
        </div>
        <div className="card p-6">
          <div className="text-secondary text-sm mb-4">Forms</div>
          <div className="text-xl text-bold">{scan.forms_found}</div>
        </div>
        <div className="card p-6">
          <div className="text-secondary text-sm mb-4">Mode</div>
          <div className="text-xl text-bold">{scan.mode}</div>
        </div>
        <div className="card p-6">
          <div className="text-secondary text-sm mb-4">Findings</div>
          <div className="text-xl text-bold">{findings.length}</div>
        </div>
        <div className="card p-6">
          <div className="text-secondary text-sm mb-4">When</div>
          <div className="text-sm text-bold">{new Date(scan.created_at).toLocaleString()}</div>
        </div>
      </div>

      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg text-bold">Findings</h2>
        <div className="flex items-center gap-2">
          <label className="text-secondary text-sm">Filter:</label>
          <select
            className="input"
            style={{ width: 'auto', padding: '0.25rem 0.5rem' }}
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
          >
            <option value="">All Severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>
      </div>

      {findings.length === 0 ? (
        <div className="card p-6 text-secondary text-sm">No findings recorded for this run.</div>
      ) : (
        <div className="card" style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)', textAlign: 'left' }}>
                <th style={{ padding: '0.75rem 1rem' }}>Severity</th>
                <th style={{ padding: '0.75rem 1rem' }}>Issue</th>
                <th style={{ padding: '0.75rem 1rem' }}>Target</th>
                <th style={{ padding: '0.75rem 1rem' }}>Description</th>
                <th style={{ padding: '0.75rem 1rem' }}>Type</th>
                <th style={{ padding: '0.75rem 1rem' }}>Payload</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f) => (
                <tr key={f.id} style={{ borderBottom: '1px solid var(--border)', verticalAlign: 'top' }}>
                  <td style={{ padding: '0.75rem 1rem' }}>
                    <span className={`badge badge-${f.severity.toLowerCase()}`}>{f.severity}</span>
                  </td>
                  <td style={{ padding: '0.75rem 1rem' }}>{f.vulnerability}</td>
                  <td style={{ padding: '0.75rem 1rem', maxWidth: 220, wordBreak: 'break-all' }}>{f.target}</td>
                  <td style={{ padding: '0.75rem 1rem', color: 'var(--text-secondary)' }}>{f.description}</td>
                  <td style={{ padding: '0.75rem 1rem' }}>{f.attack_type || '-'}</td>
                  <td style={{ padding: '0.75rem 1rem', maxWidth: 200, wordBreak: 'break-all', color: 'var(--text-secondary)', fontSize: '0.8rem' }}>
                    {f.payload ? <code>{f.payload.slice(0, 60)}{f.payload.length > 60 ? '...' : ''}</code> : '-'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default ScanDetailPage;
