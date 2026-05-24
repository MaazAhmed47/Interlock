import { Outlet, NavLink } from 'react-router-dom'
import { LayoutDashboard, ScanLine, Server, BookOpen, Settings, ArrowLeft, Menu, X } from 'lucide-react'
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { api, hasApiKey, HealthResponse, UsageResponse, MCPServer, MCPTool, AuditEvent, ShadowStats, ScanHistoryEvent, ScanResult, ScanStats } from '../api'

const NAV = [
  { to: '/dashboard', label: 'Overview', icon: LayoutDashboard, end: true },
  { to: '/dashboard/scan', label: 'Scan', icon: ScanLine, end: false },
  { to: '/dashboard/mcp', label: 'MCP Gateway', icon: Server, end: false },
  { to: '/dashboard/audit', label: 'Audit Log', icon: BookOpen, end: false },
  { to: '/dashboard/settings', label: 'Settings', icon: Settings, end: false },
]

type DashboardErrors = Partial<Record<'health' | 'usage' | 'servers' | 'tools' | 'drifted' | 'audit' | 'shadow' | 'scanHistory' | 'scanStats', string>>

type DashboardDataContextValue = {
  configured: boolean
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
    layer_caught: result.layer_caught,
    scan_time_ms: result.scan_time_ms,
    risk_score: result.risk_score,
    endpoint,
    prompt_preview: original.length > 80 ? original.slice(0, 80) + '...' : original,
  }
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
  const [loaded, setLoaded] = useState(false)
  const [loading, setLoading] = useState(false)
  const [loadingMcp, setLoadingMcp] = useState(false)
  const [loadingAudit, setLoadingAudit] = useState(false)
  const [loadingScans, setLoadingScans] = useState(false)
  const [lastLoadedAt, setLastLoadedAt] = useState<string | null>(null)

  const recordScanResult = useCallback((result: ScanResult, endpoint: string) => {
    setScanHistory(prev => {
      const next = [scanEventFromResult(result, endpoint), ...prev].slice(0, 100)
      setScanStats(statsFromHistory(next))
      return next
    })
  }, [])

  const refreshScans = useCallback(async () => {
    if (!hasApiKey()) return
    setLoadingScans(true)
    setErrors(prev => clearErrors(prev, ['scanHistory', 'scanStats']))

    await Promise.all([
      api.scanHistory(100)
        .then(data => setScanHistory(data.events))
        .catch(error => setErrors(prev => ({ ...prev, scanHistory: errorMessage(error) }))),
      api.scanStats()
        .then(setScanStats)
        .catch(error => setErrors(prev => ({ ...prev, scanStats: errorMessage(error) }))),
    ])

    setLoadingScans(false)
  }, [])

  const refreshMcp = useCallback(async () => {
    if (!hasApiKey()) return
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
  }, [])

  const refreshAudit = useCallback(async () => {
    if (!hasApiKey()) return
    setLoadingAudit(true)
    setErrors(prev => clearErrors(prev, ['audit']))

    await api.mcpAudit(200)
      .then(data => setAudit(data.events))
      .catch(error => setErrors(prev => ({ ...prev, audit: errorMessage(error) })))

    setLoadingAudit(false)
  }, [])

  const refreshAll = useCallback(async () => {
    setLoading(true)
    setErrors({})

    const healthRequest = api.health()
      .then(setHealth)
      .catch(error => setErrors(prev => ({ ...prev, health: errorMessage(error) })))

    if (!hasApiKey()) {
      setUsage(null)
      setServers([])
      setTools([])
      setDrifted([])
      setAudit([])
      setScanHistory([])
      setScanStats(null)
      setShadow(null)
      await healthRequest
      setLoaded(true)
      setLoading(false)
      setLastLoadedAt(new Date().toISOString())
      return
    }

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
        .then(data => setScanHistory(data.events))
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
  }, [])

  useEffect(() => {
    if (!loaded && !loading) void refreshAll()
  }, [loaded, loading, refreshAll])

  const value = useMemo<DashboardDataContextValue>(() => ({
    configured: hasApiKey(),
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

export default function DashLayout() {
  const [mobileOpen, setMobileOpen] = useState(false)

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
            <a href="/" className="dash-nav-item" style={{ fontSize: 13, padding: '14px 24px' }}
              onClick={() => setMobileOpen(false)}>
              <ArrowLeft size={14} />Back to site
            </a>
          </div>
        )}

        <div className="dash-content">
          <Outlet />
        </div>
      </div>
    </DashboardDataProvider>
  )
}
