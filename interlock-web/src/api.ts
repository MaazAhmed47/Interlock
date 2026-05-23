export const API_URL_KEY = 'interlock_api_url';
export const API_KEY_KEY = 'interlock_api_key';
export const DEFAULT_API_URL =
  (import.meta.env.VITE_INTERLOCK_API_URL as string) || 'https://interlock.onrender.com';

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

function getBaseUrl(): string {
  return localStorage.getItem(API_URL_KEY) || DEFAULT_API_URL;
}

function getApiKey(): string | null {
  return localStorage.getItem(API_KEY_KEY);
}

export function hasApiKey(): boolean {
  return !!getApiKey();
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  requireKey = true,
): Promise<T> {
  const baseUrl = getBaseUrl();
  const apiKey = getApiKey();
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (requireKey && apiKey) headers['x-api-key'] = apiKey;
  if (requireKey && !apiKey) throw new ApiError(401, 'No API key configured.');

  const res = await fetch(`${baseUrl}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    let message = `HTTP ${res.status}`;
    try {
      const data = await res.json() as { detail?: string; message?: string };
      message = data.detail || data.message || message;
    } catch { /* ignore */ }
    throw new ApiError(res.status, message);
  }
  return res.json() as Promise<T>;
}

// ── Response types ───────────────────────────────────────────────────────────

export interface HealthResponse { status: string; service: string; version?: string }

export interface UsageResponse {
  plan: string;
  used_this_month: number;
  monthly_limit: number;
  remaining: number | null;
}

export interface ScanResult {
  is_threat: boolean;
  threat_level: string;
  threat_type: string | null;
  reason: string;
  original_prompt: string;
  safe_to_proceed: boolean;
  confidence: number | null;
  layer_caught: string | null;
  scan_time_ms: number | null;
  risk_score: number | null;
  sanitized_output?: string | null;
  redactions?: string[] | null;
}

export interface MCPServer {
  server_id: string;
  url?: string;
  trust_level?: string;
  tool_count?: number;
  registered?: string;
  [key: string]: unknown;
}

export interface MCPTool {
  server_id: string;
  tool_name: string;
  status?: string;
  description?: string;
  drift_severity?: string;
  drift_action?: string;
  effects?: string;
  side_effect?: string;
  data_classes?: string;
  last_seen?: string;
  [key: string]: unknown;
}

export interface AuditEvent {
  id?: number;
  timestamp: string;
  server_id: string;
  tool_name: string;
  role?: string;
  action: string;
  matched_rule?: string;
  reason?: string;
  blocked_by?: string;
  drift_severity?: string;
  [key: string]: unknown;
}

export interface ShadowStats {
  total: number;
  threats: number;
  threat_rate: number;
  top_threat_type?: string;
  [key: string]: unknown;
}

// ── API methods ──────────────────────────────────────────────────────────────

export const api = {
  health: () => request<HealthResponse>('GET', '/health', undefined, false),
  usage: () => request<UsageResponse>('GET', '/usage'),
  scan: (prompt: string) => request<ScanResult>('POST', '/scan', { prompt }),
  scanOutput: (prompt: string) => request<ScanResult>('POST', '/scan/output', { prompt }),
  shadowStats: () => request<ShadowStats>('GET', '/shadow/stats'),
  mcpServers: () => request<{ servers: MCPServer[] }>('GET', '/mcp/servers'),
  mcpTools: (server_id?: string) =>
    request<{ tools: MCPTool[] }>('GET', `/mcp/tools${server_id ? `?server_id=${encodeURIComponent(server_id)}` : ''}`),
  mcpDrifted: (server_id?: string) =>
    request<{ tools: MCPTool[] }>('GET', `/mcp/tools/drifted${server_id ? `?server_id=${encodeURIComponent(server_id)}` : ''}`),
  approveTool: (server_id: string, tool_name: string, payload: { reviewer?: string; reason?: string }) =>
    request<{ ok: boolean }>('POST', `/mcp/tools/${encodeURIComponent(server_id)}/${encodeURIComponent(tool_name)}/approve`, payload),
  quarantineTool: (server_id: string, tool_name: string, payload: { reviewer?: string; reason?: string }) =>
    request<{ ok: boolean }>('POST', `/mcp/tools/${encodeURIComponent(server_id)}/${encodeURIComponent(tool_name)}/quarantine`, payload),
  mcpAudit: (limit = 100) => request<{ events: AuditEvent[] }>('GET', `/mcp/audit?limit=${limit}`),
  siemProviders: () =>
    request<{ providers: string[]; config_examples: Record<string, unknown> }>('GET', '/siem/providers'),
  roles: () => request<{ roles: Record<string, unknown> }>('GET', '/roles'),
};
