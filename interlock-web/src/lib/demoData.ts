import type { McpServer, McpTool, AuditEvent, PolicyRule, OverviewStats } from './types'

const now = Date.now()
const ago = (ms: number) => new Date(now - ms).toISOString()
const min = (n: number) => ago(n * 60_000)
const hr  = (n: number) => ago(n * 3_600_000)

export const demoServers: McpServer[] = [
  { id: 'slack-mcp',       name: 'Slack MCP Server',       url: 'mcp://slack.internal:3001',      trusted: true, tool_count: 3, last_seen: min(2)  },
  { id: 'nextcloud-mcp',   name: 'Nextcloud File Server',   url: 'mcp://nextcloud.internal:3002',  trusted: true, tool_count: 2, last_seen: min(8)  },
  { id: 'finance-db-mcp',  name: 'Finance Database Server', url: 'mcp://finance-db.internal:3003', trusted: true, tool_count: 1, last_seen: min(15) },
]

export const demoTools: McpTool[] = [
  {
    server_id: 'slack-mcp', tool_name: 'send_message',
    description: 'Send a message to a Slack channel or user.',
    status: 'active', drift_severity: 'none', drift_action: 'allow',
    drift_types: [], drift_reasons: [], last_seen: min(5),
    normalized_metadata: {
      effects: ['message_send'], side_effect: 'none',
      data_classes: ['message_content'], externality: 'internal',
      verification_level: 'high', confidence: 0.98, source: 'schema_analysis', warnings: [],
    },
  },
  {
    server_id: 'slack-mcp', tool_name: 'export_channel',
    description: 'Export full channel history including attachments.',
    status: 'quarantined', drift_severity: 'critical', drift_action: 'quarantine',
    drift_types: ['effect_added', 'data_class_added'],
    drift_reasons: [
      'Tool gained external_sharing effect — not present in baseline',
      'PII and financial_records data classes added beyond baseline scope',
    ],
    last_changed: min(2),
    normalized_metadata: {
      effects: ['channel_read', 'external_sharing', 'data_export'],
      side_effect: 'write',
      data_classes: ['message_content', 'pii', 'financial_records', 'user_data'],
      externality: 'external', verification_level: 'low',
      confidence: 0.94, source: 'schema_analysis',
      warnings: ['External sharing not in baseline', 'PII data class added', 'Financial data class added'],
    },
  },
  {
    server_id: 'slack-mcp', tool_name: 'read_channel',
    description: 'Read messages from a Slack channel.',
    status: 'active', drift_severity: 'none', drift_action: 'allow',
    drift_types: [], drift_reasons: [], last_seen: min(3),
    normalized_metadata: {
      effects: ['channel_read'], side_effect: 'none',
      data_classes: ['message_content'], externality: 'internal',
      verification_level: 'high', confidence: 0.99, source: 'schema_analysis', warnings: [],
    },
  },
  {
    server_id: 'nextcloud-mcp', tool_name: 'read_file',
    description: 'Read file contents from Nextcloud storage.',
    status: 'changed', drift_severity: 'high', drift_action: 'deny',
    drift_types: ['side_effect_changed', 'effect_added'],
    drift_reasons: [
      'side_effect changed from none to write — behavior exceeds baseline',
      'file_modification effect added, not present in baseline',
    ],
    last_changed: min(8),
    normalized_metadata: {
      effects: ['file_read', 'file_modification'], side_effect: 'write',
      data_classes: ['file_content', 'file_metadata'], externality: 'internal',
      verification_level: 'medium', confidence: 0.87, source: 'schema_analysis',
      warnings: ['Side effect changed: none → write', 'Verification level degraded: high → medium'],
    },
  },
  {
    server_id: 'nextcloud-mcp', tool_name: 'write_file',
    description: 'Write or update a file in Nextcloud storage.',
    status: 'active', drift_severity: 'none', drift_action: 'allow',
    drift_types: [], drift_reasons: [], last_seen: min(10),
    normalized_metadata: {
      effects: ['file_write'], side_effect: 'write',
      data_classes: ['file_content'], externality: 'internal',
      verification_level: 'high', confidence: 0.97, source: 'schema_analysis', warnings: [],
    },
  },
  {
    server_id: 'finance-db-mcp', tool_name: 'query_transactions',
    description: 'Query transaction records from the finance database.',
    status: 'quarantined', drift_severity: 'critical', drift_action: 'quarantine',
    drift_types: ['data_class_added', 'effect_added'],
    drift_reasons: [
      'data_classes expanded to include financial_records, pii, account_numbers beyond baseline',
      'export capability added — not present in baseline schema',
    ],
    last_changed: min(15),
    normalized_metadata: {
      effects: ['db_read', 'data_export'], side_effect: 'none',
      data_classes: ['transaction_records', 'financial_records', 'pii', 'account_numbers'],
      externality: 'internal', verification_level: 'low',
      confidence: 0.96, source: 'schema_analysis',
      warnings: ['Sensitive financial data classes added', 'Export capability not in baseline', 'High-risk schema change detected'],
    },
  },
]

export const demoDriftedTools: McpTool[] = demoTools.filter(t => t.drift_severity !== 'none')

export const demoAuditEvents: AuditEvent[] = [
  { id: 'evt-1', timestamp: min(2),   server_id: 'slack-mcp',      server_name: 'Slack MCP Server',       tool_name: 'export_channel',     action: 'quarantine', role: 'admin_agent',   matched_rule: 'risky_drift_quarantine',   reason: 'Tool gained external sharing and PII data class beyond baseline. Auto-quarantined pending operator review.' },
  { id: 'evt-2', timestamp: min(8),   server_id: 'nextcloud-mcp',  server_name: 'Nextcloud File Server',  tool_name: 'read_file',           action: 'deny',       role: 'readonly_agent', matched_rule: 'side_effect_change_deny',  reason: 'Tool side_effect changed from none to write. Readonly agent denied by policy.' },
  { id: 'evt-3', timestamp: min(15),  server_id: 'finance-db-mcp', server_name: 'Finance Database Server',tool_name: 'query_transactions',   action: 'quarantine', role: 'finance_agent', matched_rule: 'sensitive_data_expansion', reason: 'Financial query tool expanded sensitive data access and gained export capability. Auto-quarantined.' },
  { id: 'evt-4', timestamp: min(31),  server_id: 'slack-mcp',      server_name: 'Slack MCP Server',       tool_name: 'send_message',         action: 'allow',      role: 'support_agent', matched_rule: 'baseline_match',           reason: 'Tool matches baseline. No drift detected. Request allowed.' },
  { id: 'evt-5', timestamp: hr(1),    server_id: 'nextcloud-mcp',  server_name: 'Nextcloud File Server',  tool_name: 'write_file',           action: 'monitor',    role: 'devops_agent',  matched_rule: 'low_confidence_metadata',  reason: 'Tool metadata confidence below threshold. Request monitored with full argument logging.' },
]

export const demoPolicies: PolicyRule[] = [
  { id: 'p1', description: 'readonly_agent cannot use destructive tools',        applies_to: 'readonly_agent', effect: 'deny'       },
  { id: 'p2', description: 'finance_agent cannot export external financial data', applies_to: 'finance_agent',  effect: 'deny'       },
  { id: 'p3', description: 'execute tools require devops_agent or admin_agent',   applies_to: 'execute_tools',  effect: 'deny'       },
  { id: 'p4', description: 'low-confidence metadata triggers monitoring',          applies_to: 'all_agents',     effect: 'monitor'    },
  { id: 'p5', description: 'risky drift is quarantined until operator review',     applies_to: 'all_agents',     effect: 'quarantine' },
  { id: 'p6', description: 'support_agent is limited to read and message tools',   applies_to: 'support_agent',  effect: 'deny'       },
]

export const demoStats: OverviewStats = {
  mcp_servers: 3,
  tools_baselined: 6,
  drift_alerts: 3,
  blocked_calls: 2,
  monitored_calls: 1,
  quarantined_tools: 2,
}
