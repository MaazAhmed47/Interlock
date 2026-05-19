import { Badge } from '@/components/ui'
import type { DriftAction, DriftSeverity, ToolStatus, AuditAction } from '@/lib/types'

export function ActionBadge({ action }: { action: DriftAction | AuditAction }) {
  const map: Record<string, { color: 'emerald' | 'amber' | 'danger' | 'violet' }> = {
    allow:      { color: 'emerald' },
    monitor:    { color: 'amber'   },
    deny:       { color: 'danger'  },
    quarantine: { color: 'violet'  },
  }
  const { color } = map[action] ?? { color: 'muted' as const }
  return <Badge label={action} color={color} />
}

export function SeverityBadge({ severity }: { severity: DriftSeverity }) {
  const map: Record<DriftSeverity, 'emerald' | 'amber' | 'danger' | 'violet' | 'muted'> = {
    none:     'muted',
    minor:    'amber',
    moderate: 'amber',
    high:     'danger',
    critical: 'danger',
  }
  return <Badge label={severity} color={map[severity]} />
}

export function ToolStatusBadge({ status }: { status: ToolStatus }) {
  const map: Record<ToolStatus, 'emerald' | 'amber' | 'violet'> = {
    active:      'emerald',
    changed:     'amber',
    quarantined: 'violet',
  }
  return <Badge label={status} color={map[status]} />
}
