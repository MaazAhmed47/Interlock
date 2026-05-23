import { useEffect, useState, useCallback } from 'react'
import { RefreshCw } from 'lucide-react'
import { api, hasApiKey, AuditEvent } from '../api'
import StatusBadge from '../components/StatusBadge'
import ErrorCard from '../components/ErrorCard'
import EmptyState from '../components/EmptyState'

const ACTIONS   = ['all', 'allow', 'block', 'monitor', 'quarantine', 'deny']
const SEVERITIES = ['all', 'low', 'medium', 'high', 'critical']

export default function Audit() {
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)
  const [action, setAction] = useState('all')
  const [severity, setSeverity] = useState('all')

  const load = useCallback(async () => {
    if (!hasApiKey()) return
    setLoading(true); setErr('')
    try { setEvents((await api.mcpAudit(200)).events) }
    catch (e) { setErr((e as Error).message) }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])

  const filtered = events.filter(e => {
    if (action !== 'all' && e.action.toLowerCase() !== action) return false
    if (severity !== 'all' && (e.drift_severity || '').toLowerCase() !== severity) return false
    return true
  })

  if (!hasApiKey()) return (
    <div className="dash-main">
      <div className="dash-page-header"><div><h1>Audit Log</h1></div></div>
      <EmptyState />
    </div>
  )

  return (
    <div className="dash-main">
      <div className="dash-page-header">
        <div><h1>Audit Log</h1><p>Every MCP gateway decision — allow, block, monitor, quarantine</p></div>
        <button className="btn btn-ghost btn-sm" onClick={load} disabled={loading}>
          <RefreshCw size={12} />Refresh
        </button>
      </div>

      <div className="filters-row">
        <span style={{ fontSize: 12, color: 'var(--dim)', fontFamily: 'var(--font-mono)' }}>Action:</span>
        <select className="filter-select" value={action} onChange={e => setAction(e.target.value)}>
          {ACTIONS.map(a => <option key={a} value={a}>{a === 'all' ? 'All actions' : a.toUpperCase()}</option>)}
        </select>
        <span style={{ fontSize: 12, color: 'var(--dim)', fontFamily: 'var(--font-mono)' }}>Severity:</span>
        <select className="filter-select" value={severity} onChange={e => setSeverity(e.target.value)}>
          {SEVERITIES.map(s => <option key={s} value={s}>{s === 'all' ? 'All severities' : s.toUpperCase()}</option>)}
        </select>
        <span style={{ fontSize: 12, color: 'var(--dim)' }}>{filtered.length} events</span>
      </div>

      {err && <ErrorCard message={err} onRetry={load} />}

      <div className="card" style={{ padding: 0 }}>
        {filtered.length === 0
          ? <div style={{ padding: 16 }}><EmptyState message="No audit events match the current filter." showSettingsLink={false} /></div>
          : <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Timestamp</th><th>Server</th><th>Tool</th><th>Role</th>
                    <th>Action</th><th>Severity</th><th>Blocked By</th><th>Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((e, i) => (
                    <tr key={e.id ?? i}>
                      <td className="mono dim" style={{ whiteSpace: 'nowrap' }}>
                        {new Date(e.timestamp).toLocaleString()}
                      </td>
                      <td className="mono">{e.server_id}</td>
                      <td className="mono">{e.tool_name}</td>
                      <td className="dim">{e.role || '—'}</td>
                      <td><StatusBadge value={e.action} /></td>
                      <td>{e.drift_severity ? <StatusBadge value={e.drift_severity} /> : <span className="dim">—</span>}</td>
                      <td className="mono dim">{e.blocked_by || '—'}</td>
                      <td className="dim" style={{ maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {e.reason || e.matched_rule || '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
        }
      </div>
    </div>
  )
}
