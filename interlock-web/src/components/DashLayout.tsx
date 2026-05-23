import { Outlet, NavLink, Link } from 'react-router-dom'
import { LayoutDashboard, ScanLine, Server, BookOpen, Settings, ArrowLeft, Menu, X } from 'lucide-react'
import { useState } from 'react'

const NAV = [
  { to: '/dashboard', label: 'Overview', icon: LayoutDashboard, end: true },
  { to: '/dashboard/scan', label: 'Scan', icon: ScanLine, end: false },
  { to: '/dashboard/mcp', label: 'MCP Gateway', icon: Server, end: false },
  { to: '/dashboard/audit', label: 'Audit Log', icon: BookOpen, end: false },
  { to: '/dashboard/settings', label: 'Settings', icon: Settings, end: false },
]

export default function DashLayout() {
  const [mobileOpen, setMobileOpen] = useState(false)

  return (
    <div className="dash-shell">
      {/* Sidebar */}
      <aside className="dash-sidebar">
        <div className="dash-logo">
          Interlock
          <div className="dash-logo-sub">Security Gateway</div>
        </div>
        <nav className="dash-nav">
          <div className="dash-nav-section">Dashboard</div>
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) => `dash-nav-item${isActive ? ' active' : ''}`}
            >
              <Icon size={15} />{label}
            </NavLink>
          ))}
          <div className="dash-nav-divider" />
          <Link to="/" className="dash-nav-item" style={{ fontSize: 12 }}>
            <ArrowLeft size={13} />Back to site
          </Link>
        </nav>
      </aside>

      {/* Mobile top bar */}
      <div className="dash-mobile-nav">
        <span style={{ fontWeight: 700, fontSize: 16 }}>Interlock</span>
        <button className="btn btn-ghost btn-icon" onClick={() => setMobileOpen(o => !o)}>
          {mobileOpen ? <X size={18} /> : <Menu size={18} />}
        </button>
      </div>

      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          style={{
            position: 'fixed', inset: 0, zIndex: 200,
            background: 'rgba(6,6,8,.97)',
            paddingTop: 52, display: 'flex', flexDirection: 'column',
          }}
        >
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to} to={to} end={end}
              className={({ isActive }) => `dash-nav-item${isActive ? ' active' : ''}`}
              style={{ fontSize: 15, padding: '14px 24px' }}
              onClick={() => setMobileOpen(false)}
            >
              <Icon size={16} />{label}
            </NavLink>
          ))}
          <Link to="/" className="dash-nav-item" style={{ fontSize: 13, padding: '14px 24px' }}
            onClick={() => setMobileOpen(false)}>
            <ArrowLeft size={14} />Back to site
          </Link>
        </div>
      )}

      <div className="dash-content">
        <Outlet />
      </div>
    </div>
  )
}
