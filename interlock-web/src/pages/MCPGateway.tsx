import { useState } from 'react'
import { RefreshCw, CheckCircle, AlertOctagon } from 'lucide-react'
import { api, MCPTool } from '../api'
import { useDashboardData } from '../components/DashLayout'
import StatusBadge from '../components/StatusBadge'
import ErrorCard from '../components/ErrorCard'
import EmptyState from '../components/EmptyState'

function formatValue(value: unknown) {
  if (Array.isArray(value)) return value.join(', ')
  if (value == null || value === '') return '-'
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

function toolField(tool: MCPTool, key: string) {
  const normalized = tool.normalized_metadata as Record<string, unknown> | undefined
  const rawDefinition = tool.raw_tool_definition as Record<string, unknown> | undefined
  return tool[key] ?? normalized?.[key] ?? rawDefinition?.[key]
}

export default function MCPGateway() {
  const {
    configured,
    demoMode,
    servers,
    tools,
    drifted,
    errors,
    loadingMcp,
    refreshMcp,
  } = useDashboardData()
  const [actionMsg, setActionMsg] = useState<Record<string, string>>({})

  async function doAction(tool: MCPTool, approve: boolean) {
    const k = `${tool.server_id}/${tool.tool_name}`
    if (demoMode) {
      setActionMsg(m => ({ ...m, [k]: 'Demo mode - connect an API key to review tools' }))
      return
    }
    const fn = approve ? api.approveTool : api.quarantineTool
    const msg = approve ? 'Approved' : 'Quarantined'
    const reason = approve ? 'Approved via dashboard' : 'Quarantined via dashboard'
    try {
      await fn(tool.server_id, tool.tool_name, { reviewer: 'operator', reason })
      setActionMsg(m => ({ ...m, [k]: msg }))
      window.setTimeout(() => void refreshMcp(), 800)
    } catch (e) {
      setActionMsg(m => ({ ...m, [k]: `Error: ${(e as Error).message}` }))
    }
  }

  if (!configured && !demoMode) return (
    <div className="dash-main">
      <div className="dash-page-header"><div><h1>MCP Gateway</h1></div></div>
      <EmptyState />
    </div>
  )

  return (
    <div className="dash-main">
      <div className="dash-page-header">
        <div><h1>MCP Gateway</h1><p>Registered servers, tool inventory, and drift review</p></div>
        <button className="btn btn-ghost btn-sm" onClick={refreshMcp} disabled={loadingMcp}>
          <RefreshCw size={12} />{loadingMcp ? 'Loading' : 'Refresh'}
        </button>
      </div>

      {demoMode && <div className="demo-note">Demo MCP inventory</div>}

      <div className="control-summary-grid">
        <div><span>Registered servers</span><strong>{servers.length}</strong></div>
        <div><span>Tool inventory</span><strong>{tools.length}</strong></div>
        <div><span>Review queue</span><strong>{drifted.length}</strong></div>
        <div><span>Control path</span><strong>trust - policy - audit</strong></div>
      </div>

      {errors.servers && servers.length === 0 && <ErrorCard message={`Server registry unavailable: ${errors.servers}`} onRetry={refreshMcp} />}
      {errors.tools && tools.length === 0 && <ErrorCard message={`Tool inventory unavailable: ${errors.tools}`} onRetry={refreshMcp} />}
      {errors.drifted && drifted.length === 0 && <ErrorCard message={`Drift review unavailable: ${errors.drifted}`} onRetry={refreshMcp} />}

      {drifted.length > 0 && (
        <>
          <div className="dash-section-title" style={{ color: 'var(--orange)' }}>
            Drifted / Quarantined - {drifted.length} tool{drifted.length !== 1 ? 's' : ''} need review
          </div>
          <div className="drift-grid" style={{ marginBottom: 28 }}>
            {drifted.map(tool => {
              const k = `${tool.server_id}/${tool.tool_name}`
              const isQ = tool.status === 'quarantined'
              return (
                <div key={k} className={`drift-card${isQ ? ' quarantined' : ''}`}>
                  <div className="drift-card-header">
                    <div>
                      <div className="drift-card-name">{tool.tool_name}</div>
                      <div className="drift-card-server">{tool.server_id}</div>
                    </div>
                    {tool.drift_severity && <StatusBadge value={tool.drift_severity} />}
                  </div>
                  {formatValue(toolField(tool, 'description')) !== '-' && (
                    <div className="drift-card-field" style={{ color: 'rgba(245,240,232,.65)' }}>{formatValue(toolField(tool, 'description'))}</div>
                  )}
                  <div className="drift-card-field"><strong>Effects:</strong> {formatValue(toolField(tool, 'effects'))}</div>
                  <div className="drift-card-field"><strong>Side effect:</strong> {formatValue(toolField(tool, 'side_effect'))}</div>
                  <div className="drift-card-field"><strong>Data classes:</strong> {formatValue(toolField(tool, 'data_classes'))}</div>
                  <div className="drift-card-field"><strong>Drift action:</strong> {formatValue(tool.drift_action)}</div>
                  {actionMsg[k]
                    ? <div style={{ marginTop: 12, fontSize: 12, fontFamily: 'var(--font-mono)', color: actionMsg[k].startsWith('Error') ? 'var(--red)' : 'var(--cyan)' }}>{actionMsg[k]}</div>
                    : <div className="drift-card-actions">
                        <button className="btn btn-cyan btn-sm" onClick={() => doAction(tool, true)} disabled={demoMode}>
                          <CheckCircle size={11} />Approve
                        </button>
                        <button className="btn btn-orange btn-sm" onClick={() => doAction(tool, false)} disabled={demoMode}>
                          <AlertOctagon size={11} />Quarantine
                        </button>
                      </div>
                  }
                </div>
              )
            })}
          </div>
        </>
      )}

      <div className="dash-section-title">Registered Servers</div>
      <div className="card glow-card" style={{ padding: 0, marginBottom: 20 }}>
        {servers.length === 0
          ? <div style={{ padding: 16 }}><EmptyState message={errors.servers ? 'Server registry is unavailable right now.' : 'No MCP servers registered.'} showSettingsLink={false} /></div>
          : <div className="table-wrap">
              <table className="data-table">
                <thead><tr><th>Server ID</th><th>URL</th><th>Trust</th></tr></thead>
                <tbody>
                  {servers.map(s => (
                    <tr key={s.server_id}>
                      <td className="mono">{s.server_id}</td>
                      <td className="mono dim">{formatValue(s.url)}</td>
                      <td>{s.trust_level ? <StatusBadge value={String(s.trust_level)} /> : <span className="dim">{formatValue(s.verified ? 'verified' : 'unknown')}</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
        }
      </div>

      <div className="dash-section-title">All Tools - {tools.length}</div>
      <div className="card glow-card" style={{ padding: 0 }}>
        {tools.length === 0
          ? <div style={{ padding: 16 }}><EmptyState message={errors.tools ? 'Tool inventory is unavailable right now.' : servers.length > 0 ? 'No tools discovered yet. Registered servers are listed above.' : 'No tools discovered yet.'} showSettingsLink={false} /></div>
          : <div className="table-wrap">
              <table className="data-table">
                <thead><tr><th>Server</th><th>Tool</th><th>Status</th><th>Description</th></tr></thead>
                <tbody>
                  {tools.map(t => (
                    <tr key={`${t.server_id}/${t.tool_name}`}>
                      <td className="mono">{t.server_id}</td>
                      <td className="mono">{t.tool_name}</td>
                      <td>{t.status ? <StatusBadge value={t.status} /> : <span className="dim">-</span>}</td>
                      <td className="dim" style={{ maxWidth: 320, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {formatValue(toolField(t, 'description'))}
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
