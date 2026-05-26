interface Props { value: string }

const MAP: Record<string, string> = {
  allow: 'badge-allow', allowed: 'badge-allow',
  block: 'badge-block', blocked: 'badge-block', deny: 'badge-block', denied: 'badge-block',
  monitor: 'badge-monitor', monitored: 'badge-monitor',
  quarantine: 'badge-quarantine', quarantined: 'badge-quarantine',
  safe: 'badge-safe', scan: 'badge-safe', mcp: 'badge-low', active: 'badge-safe', verified: 'badge-safe', review: 'badge-monitor', changed: 'badge-monitor',
  success: 'badge-safe', oidc: 'badge-safe', owner: 'badge-safe', operator: 'badge-monitor', auditor: 'badge-low', security_reviewer: 'badge-monitor', scoped_token: 'badge-monitor', bootstrap: 'badge-critical', failure: 'badge-block', failed: 'badge-block',
  high: 'badge-high', critical: 'badge-critical', medium: 'badge-medium', low: 'badge-low',
}

export default function StatusBadge({ value }: Props) {
  const cls = MAP[value.toLowerCase()] || 'badge-low'
  return <span className={`badge ${cls}`}>{value.toUpperCase()}</span>
}
