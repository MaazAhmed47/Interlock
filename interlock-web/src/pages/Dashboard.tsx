import { useEffect, useState, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { RefreshCw, ScanLine, Server, Activity } from 'lucide-react'
import { api, hasApiKey, HealthResponse, UsageResponse, MCPTool, AuditEvent, ShadowStats } from '../api'
import MetricCard from '../components/MetricCard'
import StatusBadge from '../components/StatusBadge'
import ErrorCard from '../components/ErrorCard'
import EmptyState from '../components/EmptyState'

export default function Dashboard() {
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [healthErr, setHealthErr] = useState('')
  const [usage, setUsage] = useState<UsageResponse | null>(null)
  const [usageErr, setUsageErr] = useState('')
  const [serverCount, setServerCount] = useState<number | null>(null)
  const [drifted, setDrifted] = useState<MCPTool[]>([])
  const [mcpErr, setMcpErr] = useState('')
  const [audit, setAudit] = useState<AuditEvent[]>([])
  const [auditErr, setAuditErr] = useState('')
  const [shadow, setShadow] = useState<ShadowStats | null>(null)
  const [loading, setLoading] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    setHealthErr('')
    api.health().then(setHealth).catch(e => setHealthErr((e as Error).message))

    if (!hasApiKey()) { setLoading(false); return }

    setUsageErr(''); setMcpErr(''); setAuditErr('')
    await Promise.all([
      api.usage().then(setUsage).catch(e => setUsageErr((e as Error).message)),
      api.mcpServers().then(d => setServerCount(d.servers.length)).catch(() => {}),
      api.mcpDrifted().then(d => setDrifted(d.tools)).catch(e => setMcpErr((e as Error).message)),
      api.mcpAudit(10).then(d => setAudit(d.events)).catch(e => setAuditErr((e as Error).message)),
      api.shadowStats().then(setShadow).catch(() => {}),
    ])
    setLoading(false)
  }, [])

  useEffect(() => { load() }, [load])

  const isOk = health?.status === 'ok'

  return (
    <div className="dash-main">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div className={`status-dot ${healthErr ? 'err' : isOk ? 'ok' : 'loading'}`} />
          <span style={{ fontSize: 13, fontFamily: 'var(--font-mono)', color: 'var(--dim)' }}>
            {healthErr ? 'Backend unreachable' : isOk ? 'Backend online' : 'Checking…'}
          </span>
        </div>
        <button className="btn btn-ghost btn-sm" onClick={load} disabled={loading}>
          <RefreshCw size={12} />Refresh
        </button>
      </div>

      {!hasApiKey() ? (
        <EmptyState />
      ) : (
        <>
          <div className="dash-section-title">Overview</div>
          <div className="metrics-grid">
            {usageErr
              ? <ErrorCard message={usageErr} />
              : <MetricCard
                  label="Usage This Month"
                  value={usage ? usage.used_this_month : '—'}
                  sub={usage ? `of ${usage.monthly_limit || '∞'} · ${usage.plan}` : 'Loading…'}
                />
            }
            <MetricCard label="MCP Servers" value={serverCount ?? '—'} sub="Registered servers" />
            <MetricCard
              label="Drifted / Quarantined"
              value={mcpErr ? '!' : drifted.length}
              sub="Tools needing review"
              accent={drifted.length > 0 ? 'red' : undefined}
            />
            {shadow && (
              <MetricCard
                label="Shadow Threat Rate"
                value={`${Math.round(shadow.threat_rate * 100)}%`}
                sub={`${shadow.total} shadow scans`}
              />
            )}
          </div>

          <div className="dash-section-title">Quick Actions</div>
          <div className="quick-actions">
            <Link to="/dashboard/scan" className="btn btn-ghost"><ScanLine size={13} />Run Prompt Scan</Link>
            <Link to="/dashboard/mcp" className="btn btn-ghost"><Server size={13} />View MCP Gateway</Link>
            <Link to="/dashboard/audit" className="btn btn-ghost"><Activity size={13} />View Audit Log</Link>
          </div>

          <div className="dash-section-title">Recent Audit Decisions</div>
          <div className="card" style={{ padding: 0 }}>
            {auditErr
              ? <div style={{ padding: 16 }}><ErrorCard message={auditErr} onRetry={load} /></div>
              : audit.length === 0
                ? <div style={{ padding: 16 }}><EmptyState message="No audit events yet." showSettingsLink={false} /></div>
                : <div className="table-wrap">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Time</th><th>Server</th><th>Tool</th><th>Role</th><th>Action</th><th>Severity</th>
                        </tr>
                      </thead>
                      <tbody>
                        {audit.slice(0, 10).map((e, i) => (
                          <tr key={e.id ?? i}>
                            <td className="mono dim">{new Date(e.timestamp).toLocaleTimeString()}</td>
                            <td className="mono">{e.server_id}</td>
                            <td className="mono">{e.tool_name}</td>
                            <td className="dim">{e.role || '—'}</td>
                            <td><StatusBadge value={e.action} /></td>
                            <td>{e.drift_severity ? <StatusBadge value={e.drift_severity} /> : <span className="dim">—</span>}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
            }
          </div>
        </>
      )}
    </div>
  )
}
