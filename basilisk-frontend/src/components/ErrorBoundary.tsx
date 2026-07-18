import React, { Component, ErrorInfo, ReactNode } from 'react';
import { ShieldAlert } from 'lucide-react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('ErrorBoundary caught:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center p-6" style={{ minHeight: '100vh' }}>
          <ShieldAlert size={64} style={{ color: 'var(--critical)', marginBottom: '1rem' }} />
          <h1 className="text-xl text-bold mb-4">Something went wrong</h1>
          <p className="text-secondary text-sm mb-4" style={{ maxWidth: 400, textAlign: 'center' }}>
            {this.state.error?.message || 'An unexpected error occurred.'}
          </p>
          <button
            className="btn"
            onClick={() => { this.setState({ hasError: false, error: null }); window.location.href = '/dashboard'; }}
          >
            Reload Dashboard
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

export default ErrorBoundary;
