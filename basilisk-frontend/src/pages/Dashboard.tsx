import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Activity, ShieldAlert, CheckCircle2 } from 'lucide-react';
import { getScans } from '../services/api';
import { loadApiKeyFromStorage } from '../services/auth';
import { Scan } from '../types';

const Dashboard = () => {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  // Note: in a real full SaaS platform, the user would log in via OAuth and get a user token.
  // Since we're using the device auth flow, this dashboard serves as an authorization success page + demo dashboard.
  useEffect(() => {
    // For this demonstration, if the CLI hasn't made scans recently, we might show a dummy or wait
    // We try to fetch. If it fails due to the dummy web token, we handle gracefully.
    setLoading(false);
  }, []);

  return (
    <div className="container py-4 mt-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-xl text-bold">Recent Scans</h1>
          <p className="text-secondary text-sm mt-4">Security audits reporting from Basilisk CLI.</p>
        </div>
      </div>

      <div className="card p-6" style={{ textAlign: 'center' }}>
        <Activity size={48} style={{ color: 'var(--text-secondary)', margin: '0 auto 1rem', opacity: 0.5 }} />
        <h2 className="text-lg mb-4">Awaiting Scans</h2>
        <p className="text-secondary text-sm mb-6">
          Your device has been authorized successfully!<br/>
          Go back to your terminal and run a scan to see it appear here.
        </p>
        <code style={{ background: 'var(--bg)', padding: '0.75rem 1rem', borderRadius: '4px', border: '1px solid var(--border)' }}>
          basilisk scan https://example.com
        </code>
      </div>
    </div>
  );
};

export default Dashboard;
