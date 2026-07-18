import React from 'react';
import { Link } from 'react-router-dom';
import { ShieldAlert } from 'lucide-react';

const NotFound = () => {
  return (
    <div className="flex flex-col items-center justify-center p-6" style={{ minHeight: '100vh' }}>
      <ShieldAlert size={64} style={{ color: 'var(--critical)', marginBottom: '1rem' }} />
      <h1 className="text-xl text-bold mb-4">404 - Page Not Found</h1>
      <p className="text-secondary text-sm mb-6">The page you're looking for doesn't exist.</p>
      <Link to="/dashboard" className="btn">Back to Dashboard</Link>
    </div>
  );
};

export default NotFound;
