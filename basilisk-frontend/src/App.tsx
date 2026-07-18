import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Navbar from './components/Navbar';
import ProtectedRoute from './components/ProtectedRoute';
import ErrorBoundary from './components/ErrorBoundary';
import AuthPage from './pages/AuthPage';
import Dashboard from './pages/Dashboard';
import ScanDetailPage from './pages/ScanDetailPage';
import NotFound from './pages/NotFound';

const App = () => {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <Routes>
          <Route path="/auth" element={<AuthPage />} />

          <Route element={<><Navbar /><ProtectedRoute /></>}>
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/scans/:id" element={<ScanDetailPage />} />
          </Route>

          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </BrowserRouter>
    </ErrorBoundary>
  );
};

export default App;
