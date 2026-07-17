import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Navbar from './components/Navbar';
import ProtectedRoute from './components/ProtectedRoute';
import AuthPage from './pages/AuthPage';
import Dashboard from './pages/Dashboard';
import ScanDetailPage from './pages/ScanDetailPage';

const App = () => {
  return (
    <BrowserRouter>
      {/* We conditionally render Navbar based on route or just render it always with logic, but for simplicity: */}
      <Routes>
        <Route path="/auth" element={<AuthPage />} />
        
        {/* Protected Routes */}
        <Route element={<><Navbar /><ProtectedRoute /></>}>
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/scans/:id" element={<ScanDetailPage />} />
        </Route>

        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </BrowserRouter>
  );
};

export default App;
