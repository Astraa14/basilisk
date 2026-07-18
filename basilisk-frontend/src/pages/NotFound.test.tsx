import React from 'react';
import { render, screen } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import NotFound from './NotFound';

test('renders 404 message', () => {
  render(<BrowserRouter><NotFound /></BrowserRouter>);
  expect(screen.getByText('404 - Page Not Found')).toBeTruthy();
  expect(screen.getByText("The page you're looking for doesn't exist.")).toBeTruthy();
});

test('has link back to dashboard', () => {
  render(<BrowserRouter><NotFound /></BrowserRouter>);
  const link = screen.getByText('Back to Dashboard');
  expect(link).toBeTruthy();
  expect(link.getAttribute('href')).toBe('/dashboard');
});
