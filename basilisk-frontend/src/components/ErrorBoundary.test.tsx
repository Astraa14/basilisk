import React from 'react';
import { render, screen } from '@testing-library/react';
import ErrorBoundary from './ErrorBoundary';

const Child = () => <div>Child rendered</div>;
const Broken = () => { throw new Error('Test error'); };

test('renders children when no error', () => {
  render(<ErrorBoundary><Child /></ErrorBoundary>);
  expect(screen.getByText('Child rendered')).toBeTruthy();
});

test('catches error and shows fallback', () => {
  const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
  render(<ErrorBoundary><Broken /></ErrorBoundary>);
  expect(screen.getByText('Something went wrong')).toBeTruthy();
  spy.mockRestore();
});
