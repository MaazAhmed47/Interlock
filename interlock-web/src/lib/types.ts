export type DriftSeverity = 'none' | 'minor' | 'moderate' | 'high' | 'critical'
export type DriftAction   = 'allow' | 'monitor' | 'deny' | 'quarantine'
export type ToolStatus    = 'active' | 'changed' | 'quarantined'
export type AuditAction   = 'allow' | 'monitor' | 'deny' | 'quarantine'

export interface ToolMetadata {
  effects?: string[]
  side_effect?: string
  data_classes?: string[]
  externality?: string
  identity_mode?: string
  verification_level?: string
  confidence?: number
  source?: string
  warnings?: string[]
}

export interface McpTool {
  server_id: string
  tool_name: string
  description?: string
  status: ToolStatus
  drift_severity: DriftSeverity
  drift_action: DriftAction
  drift_types: string[]
  drift_reasons: string[]
  last_changed?: string | null
  last_seen?: string
  normalized_metadata?: ToolMetadata
}

export interface McpServer {
  id: string
  name: string
  url: string
  trusted: boolean
  tool_count: number
  last_seen: string
}

export interface AuditEvent {
  id: string
  timestamp: string
  server_id: string
  server_name: string
  tool_name: string
  action: AuditAction
  role: string
  matched_rule: string
  reason: string
}

export interface PolicyRule {
  id: string
  description: string
  applies_to: string
  effect: DriftAction
}

export interface OverviewStats {
  mcp_servers: number
  tools_baselined: number
  drift_alerts: number
  blocked_calls: number
  monitored_calls: number
  quarantined_tools: number
}
