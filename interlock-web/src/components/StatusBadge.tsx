interface Props { value: string }

const MAP: Record<string, string> = {
  allow: 'badge-allow', allowed: 'badge-allow',
  block: 'badge-block', blocked: 'badge-block', deny: 'badge-block', denied: 'badge-block',
  monitor: 'badge-monitor', monitored: 'badge-monitor',
  quarantine: 'badge-quarantine', quarantined: 'badge-quarantine',
  safe: 'badge-safe',
  high: 'badge-high', critical: 'badge-critical', medium: 'badge-medium', low: 'badge-low',
}

export default function StatusBadge({ value }: Props) {
  const cls = MAP[value.toLowerCase()] || 'badge-low'
  return <span className={`badge ${cls}`}>{value.toUpperCase()}</span>
}
