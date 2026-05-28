import { Component, type ReactNode } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import DashLayout from './components/DashLayout'
import Dashboard from './pages/Dashboard'
import Scan from './pages/Scan'
import MCPGateway from './pages/MCPGateway'
import Audit from './pages/Audit'
import Settings from './pages/Settings'
import Login from './pages/Login'
import OIDCCallback from './pages/OIDCCallback'

class ErrorBoundary extends Component<{ children: ReactNode }, { hasError: boolean }> {
  constructor(props: { children: ReactNode }) {
    super(props)
    this.state = { hasError: false }
  }

  static getDerivedStateFromError() {
    return { hasError: true }
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: '#06060a', color: '#f5f0e8', fontFamily: 'system-ui, sans-serif',
        }}>
          <div style={{ textAlign: 'center', maxWidth: 420, padding: 32 }}>
            <div style={{ fontSize: 32, marginBottom: 16 }}>⚠</div>
            <h2 style={{ margin: '0 0 8px', fontSize: 20 }}>Something went wrong</h2>
            <p style={{ color: 'rgba(245,240,232,.5)', margin: '0 0 24px', fontSize: 14 }}>
              An unexpected error occurred in the dashboard. Your data is safe.
            </p>
            <button
              style={{
                padding: '10px 24px', background: '#00e5c8', color: '#06060a',
                border: 'none', borderRadius: 4, cursor: 'pointer', fontWeight: 600, fontSize: 14,
              }}
              onClick={() => window.location.reload()}
            >
              Reload Dashboard
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}

export default function App() {
  return (
    <ErrorBoundary>
      <Routes>
        <Route path="/dashboard" element={<DashLayout />}>
          <Route index element={<Dashboard />} />
          <Route path="scan" element={<Scan />} />
          <Route path="mcp" element={<MCPGateway />} />
          <Route path="audit" element={<Audit />} />
          <Route path="settings" element={<Settings />} />
          <Route path="login" element={<Login />} />
          <Route path="auth/callback" element={<OIDCCallback />} />
        </Route>
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </ErrorBoundary>
  )
}
