import { Outlet, Link, NavLink } from 'react-router-dom'
import { LayoutDashboard, ScanLine, Server, BookOpen, Settings, ArrowLeft, Menu, X, LogIn, LogOut, ShieldCheck } from 'lucide-react'
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { api, hasApiKey, HealthResponse, UsageResponse, MCPServer, MCPTool, AuditEvent, ShadowStats, ScanHistoryEvent, ScanResult, ScanStats, normalizeLayerLabel, DEMO_USAGE, DEMO_MCP_SERVERS, DEMO_MCP_TOOLS, DEMO_DRIFTED_TOOLS, DEMO_AUDIT_EVENTS, DEMO_SCAN_HISTORY, DEMO_SCAN_STATS, DEMO_SHADOW_STATS } from '../api'
import { authDisplayName, clearAuthSession, redirectToOidcLogout, useAuthSession } from '../auth'

const NAV = [
  { to: '/dashboard', label: 'Overview', icon: LayoutDashboard, end: true },
  { to: '/dashboard/scan', label: 'Scan', icon: ScanLine, end: false },
  { to: '/dashboard/mcp', label: 'MCP Gateway', icon: Server, end: false },
  { to: '/dashboard/audit', label: 'Audit Log', icon: BookOpen, end: false },
  { to: '/dashboard/login', label: 'Admin Login', icon: ShieldCheck, end: false },
  { to: '/dashboard/settings', label: 'Settings', icon: Settings, end: false },
]

type DashboardErrors = Partial<Record<'health' | 'usage' | 'servers' | 'tools' | 'drifted' | 'audit' | 'shadow' | 'scanHistory' | 'scanStats', string>>

type DashboardDataContextValue = {
  configured: boolean
  demoMode: boolean
  loaded: boolean
  loading: boolean
  loadingMcp: boolean
  loadingAudit: boolean
  loadingScans: boolean
  lastLoadedAt: string | null
  health: HealthResponse | null
  usage: UsageResponse | null
  servers: MCPServer[]
  tools: MCPTool[]
  drifted: MCPTool[]
  audit: AuditEvent[]
  scanHistory: ScanHistoryEvent[]
  scanStats: ScanStats | null
  shadow: ShadowStats | null
  errors: DashboardErrors
  refreshAll: () => Promise<void>
  refreshMcp: () => Promise<void>
  refreshAudit: () => Promise<void>
  refreshScans: () => Promise<void>
  recordScanResult: (result: ScanResult, endpoint: string) => void
}

const DashboardDataContext = createContext<DashboardDataContextValue | null>(null)

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : 'Request failed'
}

function clearErrors(errors: DashboardErrors, keys: (keyof DashboardErrors)[]) {
  const next = { ...errors }
  keys.forEach(key => delete next[key])
  return next
}

function scanEventFromResult(result: ScanResult, endpoint: string): ScanHistoryEvent {
  const original = result.original_prompt || ''
  return {
    timestamp: new Date().toISOString(),
    is_threat: result.is_threat,
    threat_level: result.threat_level,
    threat_type: result.threat_type,
    reason: result.reason,
    confidence: result.confidence,
    layer_caught: normalizeLayerLabel(result.layer_caught),
    scan_time_ms: result.scan_time_ms,
    risk_score: result.risk_score,
    endpoint,
    prompt_preview: original.length > 80 ? original.slice(0, 80) + '...' : original,
  }
}

function normalizeScanEvents(events: ScanHistoryEvent[]) {
  return events.map(event => ({
    ...event,
    layer_caught: normalizeLayerLabel(event.layer_caught),
  }));
}

function statsFromHistory(history: ScanHistoryEvent[]): ScanStats {
  if (history.length === 0) {
    return { total: 0, threats: 0, safe: 0, critical: 0, block_rate: 0, avg_risk_score: 0, by_level: {} }
  }

  const byLevel: Record<string, number> = {}
  let threats = 0
  let riskTotal = 0
  let riskCount = 0

  history.forEach(event => {
    const level = event.threat_level || 'UNKNOWN'
    byLevel[level] = (byLevel[level] || 0) + 1
    if (event.is_threat) threats += 1
    if (typeof event.risk_score === 'number' && Number.isFinite(event.risk_score)) {
      riskTotal += event.risk_score
      riskCount += 1
    }
  })

  return {
    total: history.length,
    threats,
    safe: history.length - threats,
    critical: byLevel.CRITICAL || 0,
    block_rate: Math.round((threats / history.length) * 1000) / 10,
    avg_risk_score: riskCount > 0 ? Math.round((riskTotal / riskCount) * 10) / 10 : 0,
    by_level: byLevel,
  }
}

function DashboardDataProvider({ children }: { children: ReactNode }) {
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [usage, setUsage] = useState<UsageResponse | null>(null)
  const [servers, setServers] = useState<MCPServer[]>([])
  const [tools, setTools] = useState<MCPTool[]>([])
  const [drifted, setDrifted] = useState<MCPTool[]>([])
  const [audit, setAudit] = useState<AuditEvent[]>([])
  const [scanHistory, setScanHistory] = useState<ScanHistoryEvent[]>([])
  const [scanStats, setScanStats] = useState<ScanStats | null>(null)
  const [shadow, setShadow] = useState<ShadowStats | null>(null)
  const [errors, setErrors] = useState<DashboardErrors>({})
  const [configured, setConfigured] = useState<boolean>(() => hasApiKey())
  const [demoMode, setDemoMode] = useState(false)
  const [loaded, setLoaded] = useState(false)
  const [loading, setLoading] = useState(false)
  const [loadingMcp, setLoadingMcp] = useState(false)
  const [loadingAudit, setLoadingAudit] = useState(false)
  const [loadingScans, setLoadingScans] = useState(false)
  const [lastLoadedAt, setLastLoadedAt] = useState<string | null>(null)

  const loadDemoData = useCallback((healthSnapshot?: HealthResponse | null, healthError?: string) => {
    setDemoMode(true)
    if (healthSnapshot !== undefined) setHealth(healthSnapshot)
    setUsage(DEMO_USAGE)
    setServers(DEMO_MCP_SERVERS)
    setTools(DEMO_MCP_TOOLS)
    setDrifted(DEMO_DRIFTED_TOOLS)
    setAudit(DEMO_AUDIT_EVENTS)
    setScanHistory(DEMO_SCAN_HISTORY)
    setScanStats(DEMO_SCAN_STATS)
    setShadow(DEMO_SHADOW_STATS)
    setErrors(healthError ? { health: healthError } : {})
    setLoaded(true)
    setLoading(false)
    setLoadingMcp(false)
    setLoadingAudit(false)
    setLoadingScans(false)
    setLastLoadedAt(new Date().toISOString())
  }, [])

  const recordScanResult = useCallback((result: ScanResult, endpoint: string) => {
    setScanHistory(prev => {
      const next = [scanEventFromResult(result, endpoint), ...prev].slice(0, 100)
      setScanStats(statsFromHistory(next))
      return next
    })
  }, [])

  const refreshScans = useCallback(async () => {
    const isConfigured = hasApiKey()
    setConfigured(isConfigured)
    if (!isConfigured) {
      loadDemoData()
      return
    }
    setDemoMode(false)
    setLoadingScans(true)
    setErrors(prev => clearErrors(prev, ['scanHistory', 'scanStats']))

    await Promise.all([
      api.scanHistory(100)
        .then(data => setScanHistory(normalizeScanEvents(data.events)))
        .catch(error => setErrors(prev => ({ ...prev, scanHistory: errorMessage(error) }))),
      api.scanStats()
        .then(setScanStats)
        .catch(error => setErrors(prev => ({ ...prev, scanStats: errorMessage(error) }))),
    ])

    setLoadingScans(false)
  }, [loadDemoData])

  const refreshMcp = useCallback(async () => {
    const isConfigured = hasApiKey()
    setConfigured(isConfigured)
    if (!isConfigured) {
      loadDemoData()
      return
    }
    setDemoMode(false)
    setLoadingMcp(true)
    setErrors(prev => clearErrors(prev, ['servers', 'tools', 'drifted']))

    await Promise.all([
      api.mcpServers()
        .then(data => setServers(data.servers))
        .catch(error => setErrors(prev => ({ ...prev, servers: errorMessage(error) }))),
      api.mcpTools()
        .then(data => setTools(data.tools))
        .catch(error => setErrors(prev => ({ ...prev, tools: errorMessage(error) }))),
      api.mcpDrifted()
        .then(data => setDrifted(data.tools))
        .catch(error => setErrors(prev => ({ ...prev, drifted: errorMessage(error) }))),
    ])

    setLoadingMcp(false)
  }, [loadDemoData])

  const refreshAudit = useCallback(async () => {
    const isConfigured = hasApiKey()
    setConfigured(isConfigured)
    if (!isConfigured) {
      loadDemoData()
      return
    }
    setDemoMode(false)
    setLoadingAudit(true)
    setErrors(prev => clearErrors(prev, ['audit']))

    await api.mcpAudit(200)
      .then(data => setAudit(data.events))
      .catch(error => setErrors(prev => ({ ...prev, audit: errorMessage(error) })))

    setLoadingAudit(false)
  }, [loadDemoData])

  const refreshAll = useCallback(async () => {
    const isConfigured = hasApiKey()
    setConfigured(isConfigured)
    setLoading(true)
    setErrors({})

    if (!isConfigured) {
      let healthSnapshot: HealthResponse | null = null
      let healthError = ''
      try {
        healthSnapshot = await api.health()
      } catch (error) {
        healthError = errorMessage(error)
      }
      loadDemoData(healthSnapshot, healthError)
      return
    }

    setDemoMode(false)
    setUsage(null)
    setServers([])
    setTools([])
    setDrifted([])
    setAudit([])
    setScanHistory([])
    setScanStats(null)
    setShadow(null)

    const healthRequest = api.health()
      .then(setHealth)
      .catch(error => setErrors(prev => ({ ...prev, health: errorMessage(error) })))

    await Promise.all([
      healthRequest,
      api.usage()
        .then(setUsage)
        .catch(error => setErrors(prev => ({ ...prev, usage: errorMessage(error) }))),
      api.mcpServers()
        .then(data => setServers(data.servers))
        .catch(error => setErrors(prev => ({ ...prev, servers: errorMessage(error) }))),
      api.mcpTools()
        .then(data => setTools(data.tools))
        .catch(error => setErrors(prev => ({ ...prev, tools: errorMessage(error) }))),
      api.mcpDrifted()
        .then(data => setDrifted(data.tools))
        .catch(error => setErrors(prev => ({ ...prev, drifted: errorMessage(error) }))),
      api.mcpAudit(200)
        .then(data => setAudit(data.events))
        .catch(error => setErrors(prev => ({ ...prev, audit: errorMessage(error) }))),
      api.scanHistory(100)
        .then(data => setScanHistory(normalizeScanEvents(data.events)))
        .catch(error => setErrors(prev => ({ ...prev, scanHistory: errorMessage(error) }))),
      api.scanStats()
        .then(setScanStats)
        .catch(error => setErrors(prev => ({ ...prev, scanStats: errorMessage(error) }))),
      api.shadowStats()
        .then(setShadow)
        .catch(error => setErrors(prev => ({ ...prev, shadow: errorMessage(error) }))),
    ])

    setLoaded(true)
    setLoading(false)
    setLastLoadedAt(new Date().toISOString())
  }, [loadDemoData])

  useEffect(() => {
    if (!loaded && !loading) void refreshAll()
  }, [loaded, loading, refreshAll])

  const value = useMemo<DashboardDataContextValue>(() => ({
    configured,
    demoMode,
    loaded,
    loading,
    loadingMcp,
    loadingAudit,
    loadingScans,
    lastLoadedAt,
    health,
    usage,
    servers,
    tools,
    drifted,
    audit,
    scanHistory,
    scanStats,
    shadow,
    errors,
    refreshAll,
    refreshMcp,
    refreshAudit,
    refreshScans,
    recordScanResult,
  }), [
    configured,
    demoMode,
    loaded,
    loading,
    loadingMcp,
    loadingAudit,
    loadingScans,
    lastLoadedAt,
    health,
    usage,
    servers,
    tools,
    drifted,
    audit,
    scanHistory,
    scanStats,
    shadow,
    errors,
    refreshAll,
    refreshMcp,
    refreshAudit,
    refreshScans,
    recordScanResult,
  ])

  return <DashboardDataContext.Provider value={value}>{children}</DashboardDataContext.Provider>
}

export function useDashboardData() {
  const ctx = useContext(DashboardDataContext)
  if (!ctx) throw new Error('useDashboardData must be used inside DashLayout')
  return ctx
}

function formatRelativeTime(isoString: string): string {
  const diffMs = Date.now() - new Date(isoString).getTime()
  const diffMins = Math.floor(diffMs / 60000)
  if (diffMins < 1) return 'just now'
  if (diffMins === 1) return '1 minute ago'
  if (diffMins < 60) return `${diffMins} minutes ago`
  const diffHours = Math.floor(diffMins / 60)
  return diffHours === 1 ? '1 hour ago' : `${diffHours} hours ago`
}

function DashTopbarStatus() {
  const { lastLoadedAt } = useDashboardData()
  if (!lastLoadedAt) return null
  return (
    <span style={{ fontSize: 11, color: 'var(--dim)', fontFamily: 'var(--font-mono)' }}>
      Last updated: {formatRelativeTime(lastLoadedAt)}
    </span>
  )
}

export default function DashLayout() {
  const [mobileOpen, setMobileOpen] = useState(false)
  const session = useAuthSession()
  const signedInAs = authDisplayName(session)
  const topbarIdentity = session ? 'Interlock Admin' : 'Admin SSO not signed in'

  function handleSignOut() {
    const redirected = redirectToOidcLogout('/dashboard/login')
    if (!redirected) clearAuthSession()
  }

  return (
    <DashboardDataProvider>
      <div className="dash-shell">
        <aside className="dash-sidebar">
          <a href="/" className="dash-logo" aria-label="Interlock landing page">
            Interlock
            <div className="dash-logo-sub">Security Gateway</div>
          </a>
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
            <a href="/" className="dash-nav-item" style={{ fontSize: 12 }}>
              <ArrowLeft size={13} />Back to site
            </a>
          </nav>
          <div className="dash-auth-panel">
            {session ? (
              <>
                <div className="dash-auth-kicker"><ShieldCheck size={12} /> SSO active</div>
                <div className="dash-auth-name" title={signedInAs}>{signedInAs}</div>
                <button className="dash-auth-button" onClick={handleSignOut}><LogOut size={13} />Sign out</button>
              </>
            ) : (
              <NavLink to="/dashboard/login" className="dash-auth-button"><LogIn size={13} />SSO login</NavLink>
            )}
          </div>
        </aside>

        <div className="dash-mobile-nav">
          <a href="/" style={{ fontWeight: 700, fontSize: 16 }}>Interlock</a>
          <button className="btn btn-ghost btn-icon" onClick={() => setMobileOpen(o => !o)} aria-label="Toggle dashboard navigation">
            {mobileOpen ? <X size={18} /> : <Menu size={18} />}
          </button>
        </div>

        {mobileOpen && (
          <div
            style={{
              position: 'fixed', inset: 0, zIndex: 200,
              background: 'rgba(0,0,0,.96)',
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
            <a href="/" className="dash-nav-item" style={{ fontSize: 13, padding: '14px 24px' }}
              onClick={() => setMobileOpen(false)}>
              <ArrowLeft size={14} />Back to site
            </a>
            {session ? (
              <button className="dash-nav-item mobile-auth-action" onClick={() => { handleSignOut(); setMobileOpen(false) }}>
                <LogOut size={14} />Sign out
              </button>
            ) : (
              <NavLink to="/dashboard/login" className="dash-nav-item" style={{ fontSize: 13, padding: '14px 24px' }} onClick={() => setMobileOpen(false)}>
                <LogIn size={14} />SSO login
              </NavLink>
            )}
          </div>
        )}

        <div className="dash-content">
          <div className="dash-topbar">
            <div className="dash-topbar-identity">
              <ShieldCheck size={16} />
              <div>
                <span>Control plane</span>
                <strong title={signedInAs || undefined}>{topbarIdentity}</strong>
                <DashTopbarStatus />
              </div>
            </div>
            <div className="dash-topbar-actions">
              {session ? (
                <>
                  <Link to="/dashboard/audit?view=admin" className="btn btn-cyan btn-sm">Admin Audit</Link>
                  <button className="btn btn-ghost btn-sm" onClick={handleSignOut}><LogOut size={12} />Sign Out</button>
                </>
              ) : (
                <>
                  <Link to="/dashboard/login" className="btn btn-primary btn-sm"><LogIn size={12} />Admin Login</Link>
                  <Link to="/dashboard/settings" className="btn btn-ghost btn-sm">SSO Settings</Link>
                </>
              )}
            </div>
          </div>
          <Outlet />
        </div>
      </div>
    </DashboardDataProvider>
  )
}
