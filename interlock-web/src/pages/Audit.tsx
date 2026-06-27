import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Download, LockKeyhole, LogIn, Printer, Receipt, RefreshCw, ShieldCheck } from 'lucide-react'
import { AdminAuditEvent, api, AuditEvent, ScanHistoryEvent, SecurityReceipt } from '../api'
import { authDisplayName, beginOidcLogin, useAuthSession } from '../auth'
import { useDashboardData } from '../components/DashLayout'
import ReceiptModal from '../components/ReceiptModal'
import AuditPrintView from '../components/AuditPrintView'
import StatusBadge from '../components/StatusBadge'
import EmptyState from '../components/EmptyState'

const ACTIONS = ['all', 'allow', 'block', 'monitor', 'quarantine', 'deny']
const SEVERITIES = ['all', 'safe', 'low', 'medium', 'high', 'critical']

export type AuditRow = {
  key: string
  timestamp: string
  source: 'scan' | 'mcp'
  actor: string
  target: string
  action: string
  severity: string
  reason: string
  scanTime?: number | null
  auditId?: number
}

function compactCell(value: string, fallback = '-') {
  const normalized = (value || '').replace(/\s+/g, ' ').trim()
  return normalized || fallback
}

function scanReason(event: ScanHistoryEvent) {
  const parts = [event.reason || event.threat_type || '', event.prompt_preview ? `Prompt: ${event.prompt_preview}` : '']
    .map(part => compactCell(part, ''))
    .filter(Boolean)
  return parts.join(' — ') || '-'
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
    target: event.endpoint || '/scan',
    action: event.is_threat ? 'block' : 'allow',
    severity: event.threat_level || 'SAFE',
    reason: scanReason(event),
    scanTime: event.scan_time_ms,
  }
}

// Structural allow/blocklist denies short-circuit before any severity is
// scored, so drift_severity falls back to the literal "none". Don't render that
// as a "NONE" badge — a blocked call must never read as harmless.
function displaySeverity(raw?: string): string {
  const s = (raw || '').toLowerCase()
  return s === '' || s === 'none' || s === 'unknown' ? '-' : (raw as string)
}

function probeOutcomeSummary(event: AuditEvent): string {
  const isEffectivePermissionProbe = event.matched_rule === 'effective_permission_probe' || Boolean(event.probe_id)
  if (!isEffectivePermissionProbe) return ''

  const expectedOutcome = compactCell(String(event.expected_outcome ?? ''), '')
  const observedOutcome = compactCell(String(event.observed_outcome ?? ''), '')
  const expectedStatus = compactCell(String(event.expected_status_code ?? ''), '')
  const observedStatus = compactCell(String(event.observed_status_code ?? ''), '')
  const expected = [expectedOutcome, expectedStatus].filter(Boolean).join('/')
  const observed = [observedOutcome, observedStatus].filter(Boolean).join('/')

  if (!expected && !observed) return ''
  return `Probe ${expected || '?'} -> ${observed || '?'}`
}

function mcpRow(event: AuditEvent, index: number): AuditRow {
  const probeSummary = probeOutcomeSummary(event)
  const reason = [probeSummary, event.reason || event.matched_rule || '-']
    .map(part => compactCell(part, ''))
    .filter(Boolean)
    .join(' — ')

  return {
    key: 'mcp-' + (event.id ?? index),
    timestamp: eventTimestamp(event),
    source: 'mcp',
    actor: compactCell(event.server_id || '-'),
    target: compactCell(event.tool_name || '-'),
    action: event.action || '-',
    severity: displaySeverity(event.drift_severity),
    reason: compactCell(reason || '-'),
    scanTime: typeof event.scan_time_ms === 'number' ? event.scan_time_ms : null,
    auditId: typeof event.id === 'number' ? event.id : undefined,
  }
}

function adminTimestamp(event: AdminAuditEvent) {
  return event.ts || event.timestamp || ''
}

function detailSummary(details?: Record<string, unknown>) {
  if (!details || Object.keys(details).length === 0) return '-'
  return Object.entries(details)
    .slice(0, 3)
    .map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(',') : String(value)}`)
    .join(' | ')
}

export default function Audit() {
  const { configured, demoMode, audit, scanHistory, errors, loadingAudit, loadingScans, refreshAudit, refreshScans } = useDashboardData()
  const [params, setParams] = useSearchParams()
  const [view, setView] = useState<'runtime' | 'admin'>(() => params.get('view') === 'admin' ? 'admin' : 'runtime')
  const [action, setAction] = useState('all')
  const [severity, setSeverity] = useState('all')
  const [adminEvents, setAdminEvents] = useState<AdminAuditEvent[]>([])
  const [adminLoading, setAdminLoading] = useState(false)
  const [adminError, setAdminError] = useState('')
  const [receiptOpen, setReceiptOpen] = useState(false)
  const [receipt, setReceipt] = useState<SecurityReceipt | null>(null)
  const [receiptLoading, setReceiptLoading] = useState(false)
  const [receiptError, setReceiptError] = useState('')
  const [exporting, setExporting] = useState(false)
  const [exportNote, setExportNote] = useState('')
  const [printPreviewOpen, setPrintPreviewOpen] = useState(false)
  const session = useAuthSession()

  function selectView(next: 'runtime' | 'admin') {
    setView(next)
    setParams(next === 'admin' ? { view: 'admin' } : {})
  }

  async function openReceipt(auditId: number) {
    setReceiptOpen(true)
    setReceipt(null)
    setReceiptError('')
    setReceiptLoading(true)
    try {
      setReceipt(await api.receipt(auditId))
    } catch (err) {
      setReceiptError(err instanceof Error ? err.message : 'Could not load receipt.')
    } finally {
      setReceiptLoading(false)
    }
  }

  function closeReceipt() {
    setReceiptOpen(false)
    setReceipt(null)
    setReceiptError('')
  }

  async function exportReceipts(mcpRows: AuditRow[]) {
    setExportNote('')
    const stamps = mcpRows.map(r => r.timestamp).filter(Boolean).sort()
    const from = stamps[0]
    const to = stamps[stamps.length - 1]
    setExporting(true)
    try {
      const batch = await api.exportReceipts(from, to)
      const blob = new Blob([JSON.stringify(batch, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `interlock-receipts-${(from || 'all').slice(0, 10)}-to-${(to || 'all').slice(0, 10)}.json`
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
      setExportNote(`Exported ${batch.count} receipt${batch.count === 1 ? '' : 's'}${batch.chain_verified ? ' — chain verified ✓' : ''}.`)
    } catch (err) {
      setExportNote(err instanceof Error ? err.message : 'Export failed.')
    } finally {
      setExporting(false)
    }
  }

  const rows = [...scanHistory.map(scanRow), ...audit.map(mcpRow)]
    .sort((a, b) => new Date(b.timestamp || 0).getTime() - new Date(a.timestamp || 0).getTime())

  const mcpReceiptRows = rows.filter(r => r.source === 'mcp' && r.auditId != null)

  const filtered = rows.filter(e => {
    if (action !== 'all' && e.action.toLowerCase() !== action) return false
    if (severity !== 'all' && (e.severity || '').toLowerCase() !== severity) return false
    return true
  })
  const blockedEvents = rows.filter(e => ['block', 'deny'].includes(e.action.toLowerCase())).length
  const quarantinedEvents = rows.filter(e => e.action.toLowerCase() === 'quarantine').length
  const allowedEvents = rows.filter(e => e.action.toLowerCase() === 'allow').length
  const adminActors = new Set(adminEvents.map(e => e.actor_label || e.actor_email || e.actor_subject).filter(Boolean)).size
  const adminFailures = adminEvents.filter(e => (e.result || 'success').toLowerCase() !== 'success').length
  const oidcActions = adminEvents.filter(e => e.actor_auth_type === 'oidc').length

  async function loadAdminAudit() {
    if (!session) return
    setAdminLoading(true)
    setAdminError('')
    try {
      const data = await api.adminAudit(session.accessToken, 200)
      setAdminEvents(data.events)
    } catch (err) {
      setAdminError(err instanceof Error ? err.message : 'Admin audit is unavailable.')
    } finally {
      setAdminLoading(false)
    }
  }

  useEffect(() => {
    if (view === 'admin' && session) void loadAdminAudit()
  }, [view, session?.accessToken])

  useEffect(() => {
    if (view !== 'runtime' || receiptOpen || receiptLoading || receipt) return
    const rawReceiptId = params.get('receipt')
    if (!rawReceiptId) return

    const receiptId = Number(rawReceiptId)
    if (!Number.isInteger(receiptId) || receiptId <= 0) return

    void openReceipt(receiptId)
  }, [params, view, receiptOpen, receiptLoading, receipt])

  async function refresh() {
    if (view === 'admin') return loadAdminAudit()
    await Promise.all([refreshAudit(), refreshScans()])
  }

  if (!configured && !demoMode && view === 'runtime') return (
    <div className="dash-main">
      <div className="dash-page-header"><div><h1>Audit Log</h1></div></div>
      <EmptyState />
    </div>
  )

  return (
    <div className="dash-main">
      <div className="dash-page-header">
        <div><h1>Audit Log</h1><p>Runtime decisions and admin control-plane actions in one evidence workspace</p></div>
        <div className="dash-header-actions">
          {view === 'runtime' && (
            <>
              <button
                className="btn btn-cyan btn-sm"
                onClick={() => exportReceipts(mcpReceiptRows)}
                disabled={exporting || mcpReceiptRows.length === 0}
                title={mcpReceiptRows.length === 0 ? 'No tool-call events to export yet' : 'Download tamper-evident receipts as JSON'}
              >
                <Download size={12} />{exporting ? 'Exporting' : 'Export Receipts'}
              </button>
              <button
                className="btn btn-ghost btn-sm"
                onClick={() => setPrintPreviewOpen(true)}
                disabled={rows.length === 0}
                title={rows.length === 0 ? 'No events to print yet' : 'Open a print-friendly view of the full log'}
              >
                <Printer size={12} />Print / Save PDF
              </button>
            </>
          )}
          <button className="btn btn-ghost btn-sm" onClick={refresh} disabled={loadingAudit || loadingScans || adminLoading}>
            <RefreshCw size={12} />{loadingAudit || loadingScans || adminLoading ? 'Loading' : 'Refresh'}
          </button>
        </div>
      </div>

      <div className="segmented-control audit-tabs">
        <button className={view === 'runtime' ? 'active' : ''} onClick={() => selectView('runtime')}>Runtime Decisions</button>
        <button className={view === 'admin' ? 'active' : ''} onClick={() => selectView('admin')}>Admin Audit</button>
      </div>

      {view === 'runtime' ? (
        <>
          {demoMode && <div className="demo-note">Demo audit timeline</div>}

          {exportNote && <div className="inline-note">{exportNote}</div>}

          {(errors.audit || errors.scanHistory) && (
            <div className="inline-note">
              Runtime data could not load.
              {errors.audit ? ` MCP audit: ${errors.audit}.` : ''}
              {errors.scanHistory ? ` Scan history: ${errors.scanHistory}.` : ''}
              {' '}Check the API URL/key in <Link to="/dashboard/settings">Settings</Link>.
            </div>
          )}

          <div className="control-summary-grid">
            <div><span>Total evidence</span><strong>{rows.length}</strong></div>
            <div><span>Blocked / denied</span><strong>{blockedEvents}</strong></div>
            <div><span>Quarantined</span><strong>{quarantinedEvents}</strong></div>
            <div><span>Allowed</span><strong>{allowedEvents}</strong></div>
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
            <span style={{ fontSize: 12, color: 'var(--dim)' }}>{filtered.length} event{filtered.length === 1 ? '' : 's'}</span>
          </div>

          <div className="card glow-card" style={{ padding: 0 }}>
            {(loadingAudit || loadingScans) && filtered.length === 0
              ? <div style={{ padding: 24, textAlign: 'center', color: 'var(--dim)', fontSize: 13, fontFamily: 'var(--font-mono)' }}>
                  Loading audit events...
                </div>
              : filtered.length === 0
                ? <div style={{ padding: 16 }}><EmptyState message="No audit events match the current filter. Run a prompt or output scan to populate this timeline." showSettingsLink={false} /></div>
                : <div className="table-wrap">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Timestamp</th><th>Source</th><th>Actor</th><th>Target</th>
                        <th>Action</th><th>Severity</th><th>Scan Time</th><th>Reason</th><th>Receipt</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filtered.map(e => (
                        <tr key={e.key}>
                          <td className="mono dim" style={{ whiteSpace: 'nowrap' }}>
                            {e.timestamp ? new Date(e.timestamp).toLocaleString() : '-'}
                          </td>
                          <td><StatusBadge value={e.source} /></td>
                          <td className="mono" title={e.actor}>{e.actor}</td>
                          <td className="mono dim audit-cell-target" title={e.target}>{e.target}</td>
                          <td><StatusBadge value={e.action} /></td>
                          <td>{e.severity !== '-' ? <StatusBadge value={e.severity} /> : <span className="dim">-</span>}</td>
                          <td className="mono dim">{e.scanTime != null ? e.scanTime + 'ms' : '-'}</td>
                          <td className="dim audit-cell-reason" title={e.reason}>
                            {e.reason}
                          </td>
                          <td>
                            {e.auditId != null
                              ? <button className="btn btn-ghost btn-sm receipt-row-btn" onClick={() => openReceipt(e.auditId as number)}>
                                  <Receipt size={12} />Receipt
                                </button>
                              : <span className="dim">—</span>}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
            }
          </div>
        </>
      ) : !session ? (
        <div className="auth-required-panel glow-card">
          <div className="auth-state-icon"><LockKeyhole size={22} /></div>
          <h2>Admin audit requires SSO</h2>
          <p>Runtime scans use the customer API key. Control-plane evidence uses your admin identity, so sign in with OIDC to read token issuance, key changes, retention updates, and review actions.</p>
          {adminError && <div className="auth-error">{adminError}</div>}
          <div className="login-actions centered">
            <button className="btn btn-primary" onClick={() => void beginOidcLogin('/dashboard/audit?view=admin').catch(err => setAdminError(err instanceof Error ? err.message : 'Could not start SSO login.'))}><LogIn size={14} />Sign In With SSO</button>
            <Link className="btn btn-ghost" to="/dashboard/settings">Configure SSO</Link>
          </div>
        </div>
      ) : (
        <>
          <div className="admin-auth-strip">
            <ShieldCheck size={16} />
            <div><strong>{authDisplayName(session)}</strong><span>{session.profile.role || 'Backend role mapping'} via OIDC</span></div>
          </div>
          {adminError && <div className="inline-note">{adminError}</div>}
          <div className="control-summary-grid">
            <div><span>Admin events</span><strong>{adminEvents.length}</strong></div>
            <div><span>Actors</span><strong>{adminActors}</strong></div>
            <div><span>OIDC actions</span><strong>{oidcActions}</strong></div>
            <div><span>Failures</span><strong>{adminFailures}</strong></div>
          </div>
          <div className="card glow-card" style={{ padding: 0 }}>
            {adminEvents.length === 0
              ? <div style={{ padding: 16 }}><EmptyState message={adminLoading ? 'Loading admin audit events...' : 'No admin audit events found yet.'} showSettingsLink={false} /></div>
              : <div className="table-wrap">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Timestamp</th><th>Actor</th><th>Role</th><th>Auth</th>
                        <th>Action</th><th>Target</th><th>Result</th><th>Reason / Details</th>
                      </tr>
                    </thead>
                    <tbody>
                      {adminEvents.map(e => (
                        <tr key={(e.id || adminTimestamp(e)) + e.action}>
                          <td className="mono dim" style={{ whiteSpace: 'nowrap' }}>{adminTimestamp(e) ? new Date(adminTimestamp(e)).toLocaleString() : '-'}</td>
                          <td className="mono">{e.actor_label || e.actor_email || e.actor_subject || '-'}</td>
                          <td><StatusBadge value={e.actor_role || '-'} /></td>
                          <td><StatusBadge value={e.actor_auth_type || '-'} /></td>
                          <td className="mono">{e.action}</td>
                          <td className="mono dim" style={{ maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{[e.target_type, e.target_id].filter(Boolean).join(': ') || '-'}</td>
                          <td><StatusBadge value={e.result || 'success'} /></td>
                          <td className="dim" style={{ maxWidth: 320, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.reason || detailSummary(e.details)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
            }
          </div>
        </>
      )}

      {receiptOpen && (
        <ReceiptModal
          receipt={receipt}
          loading={receiptLoading}
          error={receiptError}
          onClose={closeReceipt}
        />
      )}

      {printPreviewOpen && (
        <AuditPrintView
          rows={rows}
          generatedAt={new Date().toLocaleString()}
          onClose={() => setPrintPreviewOpen(false)}
        />
      )}
    </div>
  )
}
