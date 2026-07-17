import React from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { loadApiKeyFromStorage } from '../services/auth';

const ProtectedRoute = () => {
  const token = loadApiKeyFromStorage();

  if (!token || token.startsWith('bsk_web_session_')) {
    return <Navigate to="/auth" replace />;
  }

  return <Outlet />;
};

export default ProtectedRoute;
