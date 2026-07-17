import React from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { loadApiKeyFromStorage } from '../services/auth';

const ProtectedRoute = () => {
  const token = loadApiKeyFromStorage();

  if (!token) {
    return <Navigate to="/auth" replace />;
  }

  return <Outlet />;
};

export default ProtectedRoute;
