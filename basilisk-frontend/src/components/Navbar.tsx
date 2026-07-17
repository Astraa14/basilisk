import React from 'react';
import { Shield, LogOut } from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';
import { clearAuth } from '../services/auth';

const Navbar = () => {
  const navigate = useNavigate();

  const handleLogout = () => {
    clearAuth();
    navigate('/auth');
  };

  return (
    <nav style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-card)' }}>
      <div className="container py-4 flex items-center justify-between">
        <Link to="/" className="flex items-center gap-2">
          <Shield size={24} style={{ color: 'var(--accent)' }} />
          <span className="text-xl text-bold" style={{ letterSpacing: '0.05em' }}>BASILISK</span>
        </Link>
        <button className="flex items-center gap-2 text-secondary" onClick={handleLogout} style={{ background: 'transparent', border: 'none', cursor: 'pointer' }}>
          <LogOut size={18} />
          <span>Logout</span>
        </button>
      </div>
    </nav>
  );
};

export default Navbar;
