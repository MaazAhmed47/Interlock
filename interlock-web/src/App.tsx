import { Routes, Route, Navigate } from 'react-router-dom'
import DashLayout from './components/DashLayout'
import Dashboard from './pages/Dashboard'
import Scan from './pages/Scan'
import MCPGateway from './pages/MCPGateway'
import Audit from './pages/Audit'
import Settings from './pages/Settings'
import Login from './pages/Login'
import OIDCCallback from './pages/OIDCCallback'

export default function App() {
  return (
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
  )
}
