import React from 'react';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Routes, Route, Outlet } from 'react-router-dom';
import ProtectedRoute from './ProtectedRoute';

beforeEach(() => {
  localStorage.clear();
});

test('redirects to auth when no token', () => {
  render(
    <MemoryRouter initialEntries={['/dashboard']}>
      <Routes>
        <Route element={<ProtectedRoute />}>
          <Route path="/dashboard" element={<div>Dashboard Content</div>} />
        </Route>
        <Route path="/auth" element={<div>Auth Page</div>} />
      </Routes>
    </MemoryRouter>
  );
  expect(screen.getByText('Auth Page')).toBeTruthy();
  expect(screen.queryByText('Dashboard Content')).toBeNull();
});

test('renders outlet when token exists', () => {
  localStorage.setItem('basilisk_api_key', 'bsk_test123');
  render(
    <MemoryRouter initialEntries={['/dashboard']}>
      <Routes>
        <Route element={<ProtectedRoute />}>
          <Route path="/dashboard" element={<div>Dashboard Content</div>} />
        </Route>
        <Route path="/auth" element={<div>Auth Page</div>} />
      </Routes>
    </MemoryRouter>
  );
  expect(screen.getByText('Dashboard Content')).toBeTruthy();
  expect(screen.queryByText('Auth Page')).toBeNull();
});
