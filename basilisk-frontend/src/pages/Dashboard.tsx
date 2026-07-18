import React, { useEffect, useMemo, useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { Activity, AlertTriangle, Globe, RefreshCw, ShieldAlert, Trash2 } from 'lucide-react';
import { getScans, deleteScan } from '../services/api';
import { loadApiKeyFromStorage } from '../services/auth';
import { Scan } from '../types';

const severityRank = (s: string) => {
  const order: Record<string, number> = {
    Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4,
  };
  return order[s] ?? 9;
};

const PER_PAGE = 20;

const Dashboard = () => {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);

  const apiKey = loadApiKeyFromStorage();

  const fetchScans = useCallback(async (p: number) => {
    if (!apiKey || apiKey.startsWith('bsk_web_session_')) {
      setError('Session expired. Please run basilisk auth again.');
      setLoading(false);
      return;
    }
    setLoading(true);
    setError('');
    try {
      const data = await getScans(apiKey, p, PER_PAGE);
      setScans(data.scans);
      setTotal(data.total);
      setPage(data.page);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load scans. Re-auth with basilisk auth.');
    } finally {
      setLoading(false);
    }
  }, [apiKey]);

  useEffect(() => { fetchScans(1); }, [fetchScans]);

  const handleDelete = async (scanId: number) => {
    if (!apiKey) return;
    try {
      await deleteScan(scanId, apiKey);
      setScans((prev) => prev.filter((s) => s.id !== scanId));
      setTotal((prev) => prev - 1);
    } catch {
      setError('Failed to delete scan.');
    }
  };

  const stats = useMemo(() => {
    const uniqueTargets = new Set(scans.map((s) => s.target_url)).size;
    const vulnerableRuns = scans.filter((s) => s.vulnerable).length;
    const highFindings = scans.reduce((acc, scan) => {
      const count = scan.findings?.filter((f) => f.severity === 'High' || f.severity === 'Critical').length || 0;
      return acc + count;
    }, 0);
    return { totalRuns: scans.length, uniqueTargets, vulnerableRuns, highFindings };
  }, [scans]);

  const totalPages = Math.ceil(total / PER_PAGE);

  if (loading && scans.length === 0) {
    return (
      <div className="container py-4 mt-8 flex justify-center">
        <span className="spinner" />
      </div>
    );
  }

  return (
    <div className="container py-4 mt-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-xl text-bold">Dashboard</h1>
          <p className="text-secondary text-sm mt-4">
            Scan analytics uploaded from your Basilisk CLI.
          </p>
        </div>
        <button className="btn flex items-center gap-2" onClick={() => fetchScans(page)} disabled={loading}>
          <RefreshCw size={16} /> Refresh
        </button>
      </div>

      {error && (
        <div className="card p-6 mb-6 text-sm" style={{ color: 'var(--critical)', borderColor: 'rgba(239,68,68,0.3)' }}>
          {error}
        </div>
      )}

      <div className="mb-8" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem' }}>
        <div className="card p-6">
          <div className="flex items-center gap-2 text-secondary text-sm mb-4"><Activity size={16} /> Total runs</div>
          <div className="text-xl text-bold">{stats.totalRuns}</div>
        </div>
        <div className="card p-6">
          <div className="flex items-center gap-2 text-secondary text-sm mb-4"><Globe size={16} /> Unique URLs</div>
          <div className="text-xl text-bold">{stats.uniqueTargets}</div>
        </div>
        <div className="card p-6">
          <div className="flex items-center gap-2 text-secondary text-sm mb-4"><ShieldAlert size={16} /> Vulnerable runs</div>
          <div className="text-xl text-bold">{stats.vulnerableRuns}</div>
        </div>
        <div className="card p-6">
          <div className="flex items-center gap-2 text-secondary text-sm mb-4"><AlertTriangle size={16} /> High findings</div>
          <div className="text-xl text-bold">{stats.highFindings}</div>
        </div>
      </div>

      {scans.length === 0 ? (
        <div className="card p-6" style={{ textAlign: 'center' }}>
          <Activity size={48} style={{ color: 'var(--text-secondary)', margin: '0 auto 1rem', opacity: 0.5 }} />
          <h2 className="text-lg mb-4">No scans yet</h2>
          <p className="text-secondary text-sm mb-6">Run a scan from your terminal to see it here.</p>
          <code style={{ background: 'var(--bg)', padding: '0.75rem 1rem', borderRadius: '4px', border: '1px solid var(--border)' }}>
            basilisk scan https://example.com
          </code>
        </div>
      ) : (
        <>
          <div className="card" style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)', textAlign: 'left' }}>
                  <th style={{ padding: '0.75rem 1rem' }}>When</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Target</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Mode</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Findings</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Status</th>
                  <th style={{ padding: '0.75rem 1rem' }}></th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => {
                  const findingCount = scan.findings?.length ?? 0;
                  const worst = scan.findings?.length
                    ? [...scan.findings].sort((a, b) => severityRank(a.severity) - severityRank(b.severity))[0].severity
                    : null;
                  return (
                    <tr key={scan.id} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ padding: '0.75rem 1rem', whiteSpace: 'nowrap' }}>
                        <Link to={`/scans/${scan.id}`} style={{ color: 'var(--accent)' }}>
                          {new Date(scan.created_at).toLocaleString()}
                        </Link>
                      </td>
                      <td style={{ padding: '0.75rem 1rem', maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        <Link to={`/scans/${scan.id}`}>{scan.target_url}</Link>
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>{scan.mode}</td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        {findingCount}
                        {worst ? <span className={`badge badge-${worst.toLowerCase()}`} style={{ marginLeft: 8 }}>{worst}</span> : null}
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        {scan.vulnerable ? <span className="badge badge-high">Vulnerable</span> : <span className="badge badge-safe">Clean</span>}
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <button onClick={() => handleDelete(scan.id)} style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: 'var(--text-secondary)' }} title="Delete scan">
                          <Trash2 size={16} />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {totalPages > 1 && (
            <div className="flex items-center justify-center gap-2 mt-6">
              <button className="btn" disabled={page <= 1} onClick={() => fetchScans(page - 1)}>Previous</button>
              <span className="text-secondary text-sm">Page {page} of {totalPages}</span>
              <button className="btn" disabled={page >= totalPages} onClick={() => fetchScans(page + 1)}>Next</button>
            </div>
          )}
        </>
      )}
    </div>
  );
};

export default Dashboard;
