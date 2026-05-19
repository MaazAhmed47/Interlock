import { demoTools, demoDriftedTools, demoAuditEvents, demoServers, demoStats } from './demoData'
import type { McpTool, AuditEvent, McpServer, OverviewStats } from './types'

let _isDemoMode = false
export const isDemoMode = () => _isDemoMode

const BASE = () =>
  (import.meta.env.VITE_INTERLOCK_API_URL ?? localStorage.getItem('interlock_api_url') ?? 'http://localhost:8001').replace(/\/$/, '')

function apiKey() {
  return (
    localStorage.getItem('interlock_api_key') ||
    (import.meta.env.VITE_INTERLOCK_API_KEY as string) ||
    'lf-free-demo-key-123'
  )
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE()}${path}`, {
    headers: { 'x-api-key': apiKey() },
    signal: AbortSignal.timeout(4000),
  })
  if (!res.ok) throw new Error(`${res.status}`)
  return res.json() as Promise<T>
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE()}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': apiKey() },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(4000),
  })
  if (!res.ok) throw new Error(`${res.status}`)
  return res.json() as Promise<T>
}

export async function listDriftedTools(): Promise<McpTool[]> {
  try {
    const data = await get<{ tools: McpTool[] }>('/mcp/tools/drifted')
    _isDemoMode = false
    return data.tools
  } catch {
    _isDemoMode = true
    return structuredClone(demoDriftedTools)
  }
}

export async function listAllTools(): Promise<McpTool[]> {
  try {
    const data = await get<{ tools: McpTool[] }>('/mcp/tools')
    _isDemoMode = false
    return data.tools
  } catch {
    _isDemoMode = true
    return structuredClone(demoTools)
  }
}

export async function listAuditEvents(): Promise<AuditEvent[]> {
  try {
    const data = await get<{ events: AuditEvent[] }>('/mcp/audit')
    _isDemoMode = false
    return data.events
  } catch {
    _isDemoMode = true
    return structuredClone(demoAuditEvents)
  }
}

export async function listServers(): Promise<McpServer[]> {
  try {
    const data = await get<{ servers: McpServer[] }>('/mcp/servers')
    _isDemoMode = false
    return data.servers
  } catch {
    _isDemoMode = true
    return structuredClone(demoServers)
  }
}

export async function getOverviewStats(): Promise<OverviewStats> {
  try {
    const data = await get<OverviewStats>('/mcp/stats')
    _isDemoMode = false
    return data
  } catch {
    _isDemoMode = true
    return { ...demoStats }
  }
}

export async function approveTool(serverId: string, toolName: string): Promise<McpTool> {
  try {
    const data = await post<{ tool: McpTool }>(
      `/mcp/tools/${encodeURIComponent(serverId)}/${encodeURIComponent(toolName)}/approve`,
      { reviewer: 'dashboard', reason: 'Reviewed from Interlock dashboard.' },
    )
    return data.tool
  } catch {
    const t = demoTools.find(t => t.server_id === serverId && t.tool_name === toolName)
    if (!t) throw new Error('Tool not found')
    return { ...t, status: 'active', drift_severity: 'none', drift_action: 'allow', drift_reasons: [], drift_types: [] }
  }
}

export async function quarantineTool(serverId: string, toolName: string): Promise<McpTool> {
  try {
    const data = await post<{ tool: McpTool }>(
      `/mcp/tools/${encodeURIComponent(serverId)}/${encodeURIComponent(toolName)}/quarantine`,
      { reviewer: 'dashboard', reason: 'Quarantined from Interlock dashboard.' },
    )
    return data.tool
  } catch {
    const t = demoTools.find(t => t.server_id === serverId && t.tool_name === toolName)
    if (!t) throw new Error('Tool not found')
    return { ...t, status: 'quarantined', drift_action: 'quarantine' }
  }
}
