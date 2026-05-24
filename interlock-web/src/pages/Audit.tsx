import { useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { AuditEvent, ScanHistoryEvent } from '../api'
import { useDashboardData } from '../components/DashLayout'
import StatusBadge from '../components/StatusBadge'
import EmptyState from '../components/EmptyState'

const ACTIONS = ['all', 'allow', 'block', 'monitor', 'quarantine', 'deny']
const SEVERITIES = ['all', 'safe', 'low', 'medium', 'high', 'critical']

type AuditRow = {
  key: string
  timestamp: string
  source: 'scan' | 'mcp'
  actor: string
  target: string
  action: string
  severity: string
  reason: string
  scanTime?: number | null
}

function eventTimestamp(event: AuditEvent) {
  return event.timestamp || event.ts || ''
}

function scanRow(event: ScanHistoryEvent, index: number): AuditRow {
  return {
    key: 'scan-' + index + '-' + event.timestamp,
    timestamp: event.timestamp,
    source: 'scan',
    actor: event.endpoint || '/scan',
    target: event.prompt_preview || '-',
    action: event.is_threat ? 'block' : 'allow',
    severity: event.threat_level || 'SAFE',
    reason: event.reason || event.threat_type || '-',
    scanTime: event.scan_time_ms,
  }
}

function mcpRow(event: AuditEvent, index: number): AuditRow {
  return {
    key: 'mcp-' + (event.id ?? index),
    timestamp: eventTimestamp(event),
    source: 'mcp',
    actor: event.server_id || '-',
    target: event.tool_name || '-',
    action: event.action || '-',
    severity: event.drift_severity || '-',
    reason: event.reason || event.matched_rule || '-',
  }
}

export default function Audit() {
  const { configured, audit, scanHistory, errors, loadingAudit, loadingScans, refreshAudit, refreshScans } = useDashboardData()
  const [action, setAction] = useState('all')
  const [severity, setSeverity] = useState('all')

  const rows = [...scanHistory.map(scanRow), ...audit.map(mcpRow)]
    .sort((a, b) => new Date(b.timestamp || 0).getTime() - new Date(a.timestamp || 0).getTime())

  const filtered = rows.filter(e => {
    if (action !== 'all' && e.action.toLowerCase() !== action) return false
    if (severity !== 'all' && e.severity.toLowerCase() !== severity) return false
    return true
  })

  async function refresh() {
    await Promise.all([refreshAudit(), refreshScans()])
  }

  if (!configured) return (
    <div className="dash-main">
      <div className="dash-page-header"><div><h1>Audit Log</h1></div></div>
      <EmptyState />
    </div>
  )

  return (
    <div className="dash-main">
      <div className="dash-page-header">
        <div><h1>Audit Log</h1><p>Prompt, output, and MCP gateway decisions in one timeline</p></div>
        <button className="btn btn-ghost btn-sm" onClick={refresh} disabled={loadingAudit || loadingScans}>
          <RefreshCw size={12} />{loadingAudit || loadingScans ? 'Loading' : 'Refresh'}
        </button>
      </div>

      {(errors.audit || errors.scanHistory) && (
        <div className="inline-note">
          {errors.audit ? 'MCP audit is unavailable. ' : ''}{errors.scanHistory ? 'Scan history is unavailable.' : ''}
        </div>
      )}

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

      <div className="card" style={{ padding: 0 }}>
        {filtered.length === 0
          ? <div style={{ padding: 16 }}><EmptyState message="No audit events match the current filter. Run a prompt or output scan to populate this timeline." showSettingsLink={false} /></div>
          : <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Timestamp</th><th>Source</th><th>Actor</th><th>Target</th>
                    <th>Action</th><th>Severity</th><th>Scan Time</th><th>Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(e => (
                    <tr key={e.key}>
                      <td className="mono dim" style={{ whiteSpace: 'nowrap' }}>
                        {e.timestamp ? new Date(e.timestamp).toLocaleString() : '-'}
                      </td>
                      <td><StatusBadge value={e.source} /></td>
                      <td className="mono">{e.actor}</td>
                      <td className="mono dim" style={{ maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.target}</td>
                      <td><StatusBadge value={e.action} /></td>
                      <td>{e.severity !== '-' ? <StatusBadge value={e.severity} /> : <span className="dim">-</span>}</td>
                      <td className="mono dim">{e.scanTime != null ? e.scanTime + 'ms' : '-'}</td>
                      <td className="dim" style={{ maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {e.reason}
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
