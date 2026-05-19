import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Landing from './pages/Landing'
import Dashboard from './pages/Dashboard'
import Overview from './features/overview/Overview'
import DriftReview from './features/drift/DriftReview'
import AuditLog from './features/audit/AuditLog'
import Tools from './features/tools/Tools'
import Servers from './features/servers/Servers'
import Policies from './features/policies/Policies'
import Quarantine from './features/quarantine/Quarantine'
import SettingsPage from './features/settings/Settings'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/dashboard" element={<Dashboard />}>
          <Route index element={<Navigate to="drift" replace />} />
          <Route path="overview"   element={<Overview />} />
          <Route path="drift"      element={<DriftReview />} />
          <Route path="audit"      element={<AuditLog />} />
          <Route path="tools"      element={<Tools />} />
          <Route path="servers"    element={<Servers />} />
          <Route path="policies"   element={<Policies />} />
          <Route path="quarantine" element={<Quarantine />} />
          <Route path="settings"   element={<SettingsPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
