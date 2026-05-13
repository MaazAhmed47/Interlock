export type ThreatLevel = 'critical' | 'high' | 'medium' | 'low'
export type ScanLayer  = 'fingerprint' | 'policy' | 'rule' | 'pattern' | 'llm_judge'
export type FailMode   = 'fail_closed' | 'fail_open' | 'fail_open_safe'
export type Plan       = 'free' | 'pro' | 'enterprise'

export interface ScanEvent {
  id: string
  timestamp: string
  prompt_preview: string
  threat_level: ThreatLevel
  layer_caught: ScanLayer
  risk_score: number
  blocked: boolean
  api_key_prefix: string
}

export interface ApiKey {
  id: string
  prefix: string
  label: string
  plan: Plan
  fail_mode: FailMode
  scans_today: number
  rate_limit: number
}

export interface DashboardStats {
  total_scans_today: number
  threats_blocked: number
  avg_scan_ms: number
  active_keys: number
}

export interface McpServer {
  id: string
  name: string
  url: string
  trusted: boolean
  tools_allowed: string[]
  last_seen: string
}

export interface AgentRole {
  id: string
  name: string
  description: string
  allowed_tools: string[]
  blocked_topics: string[]
}
