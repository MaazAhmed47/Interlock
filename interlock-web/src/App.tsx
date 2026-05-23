import { Routes, Route, Navigate } from 'react-router-dom'
import Landing from './pages/Landing'
import DashLayout from './components/DashLayout'
import Dashboard from './pages/Dashboard'
import Scan from './pages/Scan'
import MCPGateway from './pages/MCPGateway'
import Audit from './pages/Audit'
import Settings from './pages/Settings'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/dashboard" element={<DashLayout />}>
        <Route index element={<Dashboard />} />
        <Route path="scan" element={<Scan />} />
        <Route path="mcp" element={<MCPGateway />} />
        <Route path="audit" element={<Audit />} />
        <Route path="settings" element={<Settings />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
