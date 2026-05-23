import { useEffect, useState, useCallback } from 'react'
import { RefreshCw, CheckCircle, AlertOctagon } from 'lucide-react'
import { api, hasApiKey, MCPServer, MCPTool } from '../api'
import StatusBadge from '../components/StatusBadge'
import ErrorCard from '../components/ErrorCard'
import EmptyState from '../components/EmptyState'

export default function MCPGateway() {
  const [servers, setServers] = useState<MCPServer[]>([])
  const [tools, setTools] = useState<MCPTool[]>([])
  const [drifted, setDrifted] = useState<MCPTool[]>([])
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)
  const [actionMsg, setActionMsg] = useState<Record<string, string>>({})

  const load = useCallback(async () => {
    if (!hasApiKey()) return
    setLoading(true); setErr('')
    try {
      const [s, t, d] = await Promise.all([api.mcpServers(), api.mcpTools(), api.mcpDrifted()])
      setServers(s.servers); setTools(t.tools); setDrifted(d.tools)
    } catch (e) { setErr((e as Error).message) }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])

  async function doAction(tool: MCPTool, approve: boolean) {
    const k = `${tool.server_id}/${tool.tool_name}`
    const fn = approve ? api.approveTool : api.quarantineTool
    const msg = approve ? 'Approved' : 'Quarantined'
    const reason = approve ? 'Approved via dashboard' : 'Quarantined via dashboard'
    try {
      await fn(tool.server_id, tool.tool_name, { reviewer: 'operator', reason })
      setActionMsg(m => ({ ...m, [k]: msg }))
      setTimeout(() => load(), 800)
    } catch (e) {
      setActionMsg(m => ({ ...m, [k]: `Error: ${(e as Error).message}` }))
    }
  }

  if (!hasApiKey()) return (
    <div className="dash-main">
      <div className="dash-page-header"><div><h1>MCP Gateway</h1></div></div>
      <EmptyState />
    </div>
  )

  return (
    <div className="dash-main">
      <div className="dash-page-header">
        <div><h1>MCP Gateway</h1><p>Registered servers, tool inventory, and drift review</p></div>
        <button className="btn btn-ghost btn-sm" onClick={load} disabled={loading}>
          <RefreshCw size={12} />Refresh
        </button>
      </div>

      {err && <ErrorCard message={err} onRetry={load} />}

      {drifted.length > 0 && (
        <>
          <div className="dash-section-title" style={{ color: 'var(--orange)' }}>
            Drifted / Quarantined — {drifted.length} tool{drifted.length !== 1 ? 's' : ''} need review
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
                  {tool.description && (
                    <div className="drift-card-field" style={{ color: 'rgba(245,240,232,.65)' }}>{tool.description}</div>
                  )}
                  {tool.effects    && <div className="drift-card-field"><strong>Effects:</strong> {tool.effects}</div>}
                  {tool.side_effect && <div className="drift-card-field"><strong>Side effect:</strong> {tool.side_effect}</div>}
                  {tool.data_classes && <div className="drift-card-field"><strong>Data classes:</strong> {tool.data_classes}</div>}
                  {tool.drift_action && <div className="drift-card-field"><strong>Drift action:</strong> {tool.drift_action}</div>}
                  {actionMsg[k]
                    ? <div style={{ marginTop: 12, fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--cyan)' }}>{actionMsg[k]}</div>
                    : <div className="drift-card-actions">
                        <button className="btn btn-cyan btn-sm" onClick={() => doAction(tool, true)}>
                          <CheckCircle size={11} />Approve
                        </button>
                        <button className="btn btn-orange btn-sm" onClick={() => doAction(tool, false)}>
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
      <div className="card" style={{ padding: 0, marginBottom: 20 }}>
        {servers.length === 0
          ? <div style={{ padding: 16 }}><EmptyState message="No MCP servers registered." showSettingsLink={false} /></div>
          : <div className="table-wrap">
              <table className="data-table">
                <thead><tr><th>Server ID</th><th>URL</th><th>Trust</th></tr></thead>
                <tbody>
                  {servers.map(s => (
                    <tr key={s.server_id}>
                      <td className="mono">{s.server_id}</td>
                      <td className="mono dim">{(s.url as string) || '—'}</td>
                      <td>{s.trust_level ? <StatusBadge value={String(s.trust_level)} /> : <span className="dim">—</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
        }
      </div>

      <div className="dash-section-title">All Tools — {tools.length}</div>
      <div className="card" style={{ padding: 0 }}>
        {tools.length === 0
          ? <div style={{ padding: 16 }}><EmptyState message="No tools discovered yet." showSettingsLink={false} /></div>
          : <div className="table-wrap">
              <table className="data-table">
                <thead><tr><th>Server</th><th>Tool</th><th>Status</th><th>Description</th></tr></thead>
                <tbody>
                  {tools.map(t => (
                    <tr key={`${t.server_id}/${t.tool_name}`}>
                      <td className="mono">{t.server_id}</td>
                      <td className="mono">{t.tool_name}</td>
                      <td>{t.status ? <StatusBadge value={t.status} /> : <span className="dim">—</span>}</td>
                      <td className="dim" style={{ maxWidth: 320, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {t.description || '—'}
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
