# Interlock Frontend Rebuild Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Rebuild `interlock-web/` from scratch as a polished React+TypeScript+Vite+Tailwind v4 security console with a landing page at `/` and a full dashboard at `/dashboard/drift` (default).

**Architecture:** React Router v7 with nested routes under `/dashboard/:section`. Feature-based folders under `src/features/`. All API calls in `interlockApi.ts` with automatic demo-data fallback. Dashboard uses a fixed 220px left sidebar + `<Outlet>` for section content.

**Tech Stack:** React 19, TypeScript, Vite, Tailwind v4 (`@tailwindcss/vite`), framer-motion, lucide-react, react-router-dom v7

---

## Task 1: Project cleanup and directory scaffold

**Files:**
- Modify: `package.json` — remove `@supabase/supabase-js`
- Delete: `src/lib/supabase.ts`, `src/lib/types.ts`
- Create dirs: `src/features/{overview,drift,audit,tools,servers,policies,quarantine,settings}/`
- Create dirs: `src/components/{landing,dashboard,ui}/`

- [ ] Remove Supabase from package.json dependencies
- [ ] Delete old lib files
- [ ] Create directory structure with placeholder index files

```bash
cd interlock-web
# Remove supabase from package.json manually (edit file)
# Create feature directories
mkdir -p src/features/overview src/features/drift src/features/audit
mkdir -p src/features/tools src/features/servers src/features/policies
mkdir -p src/features/quarantine src/features/settings
mkdir -p src/components/landing src/components/dashboard src/components/ui
```

- [ ] Commit: `chore: scaffold interlock-web directory structure`

---

## Task 2: Design system — globals.css

**Files:**
- Modify: `src/styles/globals.css`

- [ ] Replace globals.css with new design tokens, Tailwind v4 @theme, font imports, and CSS utilities

Full content of `src/styles/globals.css`:

```css
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
@import "tailwindcss";

@theme inline {
  --color-bg:           #080A09;
  --color-surface:      #101412;
  --color-elevated:     #161B18;
  --color-border:       #27302B;
  --color-ac:           #10B981;
  --color-ac-muted:     #059669;
  --color-warn:         #D6A23A;
  --color-danger:       #D86A4A;
  --color-info:         #7AA2F7;
  --color-quarantine:   #A78BFA;
  --color-tx:           #F4F7F5;
  --color-t2:           #9CA8A2;
  --color-t3:           #6B7670;
  --font-family-sans:   'Inter', sans-serif;
  --font-family-mono:   'JetBrains Mono', monospace;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

html { scroll-behavior: smooth; }

body {
  background: #080A09;
  color: #F4F7F5;
  font-family: 'Inter', sans-serif;
  -webkit-font-smoothing: antialiased;
}

::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: #080A09; }
::-webkit-scrollbar-thumb { background: #27302B; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #3a4a42; }
```

- [ ] Commit: `feat: add design system tokens and globals`

---

## Task 3: Types and demo data

**Files:**
- Create: `src/lib/types.ts`
- Create: `src/lib/demoData.ts`

- [ ] Write `src/lib/types.ts`:

```typescript
export type DriftSeverity = 'none' | 'minor' | 'moderate' | 'high' | 'critical'
export type DriftAction = 'allow' | 'monitor' | 'deny' | 'quarantine'
export type ToolStatus = 'active' | 'changed' | 'quarantined'
export type AuditAction = 'allow' | 'monitor' | 'deny' | 'quarantine'

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
```

- [ ] Write `src/lib/demoData.ts` with realistic seeded state (see spec section 8)

```typescript
import type { McpServer, McpTool, AuditEvent, PolicyRule, OverviewStats } from './types'

export const demoServers: McpServer[] = [
  { id: 'slack-mcp', name: 'Slack MCP Server', url: 'mcp://slack.internal:3001', trusted: true, tool_count: 3, last_seen: new Date(Date.now() - 2 * 60000).toISOString() },
  { id: 'nextcloud-mcp', name: 'Nextcloud File Server', url: 'mcp://nextcloud.internal:3002', trusted: true, tool_count: 2, last_seen: new Date(Date.now() - 8 * 60000).toISOString() },
  { id: 'finance-db-mcp', name: 'Finance Database Server', url: 'mcp://finance-db.internal:3003', trusted: true, tool_count: 1, last_seen: new Date(Date.now() - 15 * 60000).toISOString() },
]

export const demoTools: McpTool[] = [
  {
    server_id: 'slack-mcp', tool_name: 'send_message', status: 'active',
    drift_severity: 'none', drift_action: 'allow', drift_types: [], drift_reasons: [],
    last_seen: new Date(Date.now() - 5 * 60000).toISOString(),
    normalized_metadata: { effects: ['message_send'], side_effect: 'none', data_classes: ['message_content'], externality: 'internal', verification_level: 'high', confidence: 0.98, source: 'schema_analysis', warnings: [] },
  },
  {
    server_id: 'slack-mcp', tool_name: 'export_channel', status: 'quarantined',
    drift_severity: 'critical', drift_action: 'quarantine', drift_types: ['effect_added', 'data_class_added'],
    drift_reasons: ['Tool gained external_sharing effect not present in baseline', 'PII and financial data classes added beyond baseline scope'],
    last_changed: new Date(Date.now() - 2 * 60000).toISOString(),
    normalized_metadata: { effects: ['channel_read', 'external_sharing', 'data_export'], side_effect: 'write', data_classes: ['message_content', 'pii', 'financial_records', 'user_data'], externality: 'external', verification_level: 'low', confidence: 0.94, source: 'schema_analysis', warnings: ['External sharing not in baseline', 'PII data class added', 'Financial data class added'] },
  },
  {
    server_id: 'slack-mcp', tool_name: 'read_channel', status: 'active',
    drift_severity: 'none', drift_action: 'allow', drift_types: [], drift_reasons: [],
    last_seen: new Date(Date.now() - 3 * 60000).toISOString(),
    normalized_metadata: { effects: ['channel_read'], side_effect: 'none', data_classes: ['message_content'], externality: 'internal', verification_level: 'high', confidence: 0.99, source: 'schema_analysis', warnings: [] },
  },
  {
    server_id: 'nextcloud-mcp', tool_name: 'read_file', status: 'changed',
    drift_severity: 'high', drift_action: 'deny', drift_types: ['side_effect_changed', 'effect_added'],
    drift_reasons: ['side_effect changed from none to write — tool behavior exceeds baseline', 'file_modification effect added, not present in baseline'],
    last_changed: new Date(Date.now() - 8 * 60000).toISOString(),
    normalized_metadata: { effects: ['file_read', 'file_modification'], side_effect: 'write', data_classes: ['file_content', 'file_metadata'], externality: 'internal', verification_level: 'medium', confidence: 0.87, source: 'schema_analysis', warnings: ['Side effect changed: none → write', 'Verification level degraded: high → medium'] },
  },
  {
    server_id: 'nextcloud-mcp', tool_name: 'write_file', status: 'active',
    drift_severity: 'none', drift_action: 'allow', drift_types: [], drift_reasons: [],
    last_seen: new Date(Date.now() - 10 * 60000).toISOString(),
    normalized_metadata: { effects: ['file_write'], side_effect: 'write', data_classes: ['file_content'], externality: 'internal', verification_level: 'high', confidence: 0.97, source: 'schema_analysis', warnings: [] },
  },
  {
    server_id: 'finance-db-mcp', tool_name: 'query_transactions', status: 'quarantined',
    drift_severity: 'critical', drift_action: 'quarantine', drift_types: ['data_class_added', 'effect_added'],
    drift_reasons: ['data_classes expanded to include financial_records, pii, account_numbers beyond baseline', 'export capability added — not present in baseline schema'],
    last_changed: new Date(Date.now() - 15 * 60000).toISOString(),
    normalized_metadata: { effects: ['db_read', 'data_export'], side_effect: 'none', data_classes: ['transaction_records', 'financial_records', 'pii', 'account_numbers'], externality: 'internal', verification_level: 'low', confidence: 0.96, source: 'schema_analysis', warnings: ['Sensitive financial data classes added', 'Export capability not in baseline', 'High-risk schema change detected'] },
  },
]

export const demoDriftedTools: McpTool[] = demoTools.filter(t => t.drift_severity !== 'none')

export const demoAuditEvents: AuditEvent[] = [
  { id: 'evt-1', timestamp: new Date(Date.now() - 2 * 60000).toISOString(), server_id: 'slack-mcp', server_name: 'Slack MCP Server', tool_name: 'export_channel', action: 'quarantine', role: 'admin_agent', matched_rule: 'risky_drift_quarantine', reason: 'Tool gained external sharing and PII data class beyond baseline. Auto-quarantined pending operator review.' },
  { id: 'evt-2', timestamp: new Date(Date.now() - 8 * 60000).toISOString(), server_id: 'nextcloud-mcp', server_name: 'Nextcloud File Server', tool_name: 'read_file', action: 'deny', role: 'readonly_agent', matched_rule: 'side_effect_change_deny', reason: 'Tool side_effect changed from none to write. Readonly agent denied by policy.' },
  { id: 'evt-3', timestamp: new Date(Date.now() - 15 * 60000).toISOString(), server_id: 'finance-db-mcp', server_name: 'Finance Database Server', tool_name: 'query_transactions', action: 'quarantine', role: 'finance_agent', matched_rule: 'sensitive_data_expansion', reason: 'Financial query tool expanded sensitive data access and gained export capability. Auto-quarantined.' },
  { id: 'evt-4', timestamp: new Date(Date.now() - 31 * 60000).toISOString(), server_id: 'slack-mcp', server_name: 'Slack MCP Server', tool_name: 'send_message', action: 'allow', role: 'support_agent', matched_rule: 'baseline_match', reason: 'Tool matches baseline. No drift detected. Request allowed.' },
  { id: 'evt-5', timestamp: new Date(Date.now() - 60 * 60000).toISOString(), server_id: 'nextcloud-mcp', server_name: 'Nextcloud File Server', tool_name: 'write_file', action: 'monitor', role: 'devops_agent', matched_rule: 'low_confidence_metadata', reason: 'Tool metadata confidence below threshold. Request monitored with full argument logging.' },
]

export const demoPolicies: PolicyRule[] = [
  { id: 'p1', description: 'readonly_agent cannot use destructive tools', applies_to: 'readonly_agent', effect: 'deny' },
  { id: 'p2', description: 'finance_agent cannot export external financial data', applies_to: 'finance_agent', effect: 'deny' },
  { id: 'p3', description: 'execute tools require devops_agent or admin_agent', applies_to: 'execute_tools', effect: 'deny' },
  { id: 'p4', description: 'low-confidence metadata triggers monitoring', applies_to: 'all_agents', effect: 'monitor' },
  { id: 'p5', description: 'risky drift is quarantined until operator review', applies_to: 'all_agents', effect: 'quarantine' },
  { id: 'p6', description: 'support_agent is limited to read and message tools', applies_to: 'support_agent', effect: 'deny' },
]

export const demoStats: OverviewStats = {
  mcp_servers: 3,
  tools_baselined: 6,
  drift_alerts: 3,
  blocked_calls: 2,
  monitored_calls: 1,
  quarantined_tools: 2,
}
```

- [ ] Commit: `feat: add types and demo data`

---

## Task 4: API layer

**Files:**
- Create: `src/lib/interlockApi.ts`

- [ ] Write `src/lib/interlockApi.ts`:

```typescript
import { demoTools, demoDriftedTools, demoAuditEvents, demoServers, demoStats } from './demoData'
import type { McpTool, AuditEvent, McpServer, OverviewStats } from './types'

let _isDemoMode = false
export const isDemoMode = () => _isDemoMode

const BASE = () =>
  (import.meta.env.VITE_INTERLOCK_API_URL || 'http://localhost:8001').replace(/\/$/, '')

function apiKey() {
  return (
    localStorage.getItem('interlock_api_key') ||
    import.meta.env.VITE_INTERLOCK_API_KEY ||
    'lf-free-demo-key-123'
  )
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE()}${path}`, {
    headers: { 'x-api-key': apiKey() },
    signal: AbortSignal.timeout(4000),
  })
  if (!res.ok) throw new Error(`${res.status}`)
  return res.json()
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE()}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': apiKey() },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(4000),
  })
  if (!res.ok) throw new Error(`${res.status}`)
  return res.json()
}

export async function listDriftedTools(): Promise<McpTool[]> {
  try {
    const data = await get<{ tools: McpTool[] }>('/mcp/tools/drifted')
    _isDemoMode = false
    return data.tools
  } catch {
    _isDemoMode = true
    return [...demoDriftedTools]
  }
}

export async function listAllTools(): Promise<McpTool[]> {
  try {
    const data = await get<{ tools: McpTool[] }>('/mcp/tools')
    _isDemoMode = false
    return data.tools
  } catch {
    _isDemoMode = true
    return [...demoTools]
  }
}

export async function listAuditEvents(): Promise<AuditEvent[]> {
  try {
    const data = await get<{ events: AuditEvent[] }>('/mcp/audit')
    _isDemoMode = false
    return data.events
  } catch {
    _isDemoMode = true
    return [...demoAuditEvents]
  }
}

export async function listServers(): Promise<McpServer[]> {
  try {
    const data = await get<{ servers: McpServer[] }>('/mcp/servers')
    _isDemoMode = false
    return data.servers
  } catch {
    _isDemoMode = true
    return [...demoServers]
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
    return { ...t, status: 'active', drift_severity: 'none', drift_action: 'allow' }
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
```

- [ ] Commit: `feat: add API layer with demo fallback`

---

## Task 5: UI primitives

**Files:**
- Create: `src/components/ui/Button.tsx`
- Create: `src/components/ui/Badge.tsx`
- Create: `src/components/ui/EmptyState.tsx`
- Create: `src/components/ui/LoadingState.tsx`
- Create: `src/components/ui/index.ts`

- [ ] Write `src/components/ui/Button.tsx`:

```tsx
import { type ButtonHTMLAttributes, forwardRef } from 'react'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'ghost' | 'danger-ghost' | 'quarantine-ghost'
  size?: 'sm' | 'md'
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = 'primary', size = 'md', className = '', children, ...props }, ref) => {
    const base = 'inline-flex items-center justify-center gap-1.5 rounded font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#10B981] disabled:opacity-50 disabled:pointer-events-none cursor-pointer'
    const sizes = { sm: 'px-3 py-1.5 text-xs', md: 'px-4 py-2 text-sm' }
    const variants = {
      primary: 'bg-[#10B981] text-[#080A09] hover:bg-[#059669]',
      ghost: 'border border-[#27302B] text-[#9CA8A2] hover:border-[#10B981] hover:text-[#10B981] bg-transparent',
      'danger-ghost': 'border border-[#27302B] text-[#9CA8A2] hover:border-[#D86A4A] hover:text-[#D86A4A] bg-transparent',
      'quarantine-ghost': 'border border-[#27302B] text-[#9CA8A2] hover:border-[#A78BFA] hover:text-[#A78BFA] bg-transparent',
    }
    return (
      <button ref={ref} className={`${base} ${sizes[size]} ${variants[variant]} ${className}`} {...props}>
        {children}
      </button>
    )
  }
)
Button.displayName = 'Button'
```

- [ ] Write `src/components/ui/Badge.tsx`:

```tsx
interface BadgeProps { label: string; color?: 'emerald' | 'amber' | 'danger' | 'violet' | 'muted' }

const colors = {
  emerald: 'bg-[rgba(16,185,129,0.12)] text-[#10B981] border-[rgba(16,185,129,0.25)]',
  amber:   'bg-[rgba(214,162,58,0.12)]  text-[#D6A23A] border-[rgba(214,162,58,0.25)]',
  danger:  'bg-[rgba(216,106,74,0.12)]  text-[#D86A4A] border-[rgba(216,106,74,0.25)]',
  violet:  'bg-[rgba(167,139,250,0.12)] text-[#A78BFA] border-[rgba(167,139,250,0.25)]',
  muted:   'bg-[rgba(156,168,162,0.08)] text-[#6B7670] border-[rgba(156,168,162,0.15)]',
}

export function Badge({ label, color = 'muted' }: BadgeProps) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium border ${colors[color]}`}>
      {label}
    </span>
  )
}
```

- [ ] Write `src/components/ui/EmptyState.tsx`:

```tsx
interface EmptyStateProps { message: string; sub?: string }

export function EmptyState({ message, sub }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center py-20 text-center">
      <div className="w-10 h-10 rounded-full border border-[#27302B] flex items-center justify-center mb-4">
        <span className="w-4 h-4 rounded-full border-2 border-[#6B7670]" />
      </div>
      <p className="text-[#9CA8A2] text-sm font-medium">{message}</p>
      {sub && <p className="text-[#6B7670] text-xs mt-1">{sub}</p>}
    </div>
  )
}
```

- [ ] Write `src/components/ui/LoadingState.tsx`:

```tsx
export function LoadingState() {
  return (
    <div className="flex items-center justify-center py-20">
      <div className="w-6 h-6 border-2 border-[#27302B] border-t-[#10B981] rounded-full animate-spin" />
    </div>
  )
}
```

- [ ] Write `src/components/ui/index.ts`:

```ts
export { Button } from './Button'
export { Badge } from './Badge'
export { EmptyState } from './EmptyState'
export { LoadingState } from './LoadingState'
```

- [ ] Commit: `feat: add UI primitives`

---

## Task 6: StatusBadge + dashboard shell components

**Files:**
- Create: `src/components/dashboard/StatusBadge.tsx`
- Create: `src/components/dashboard/Sidebar.tsx`
- Create: `src/components/dashboard/TopBar.tsx`

- [ ] Write `src/components/dashboard/StatusBadge.tsx`:

```tsx
import { Badge } from '@/components/ui'
import type { DriftAction, DriftSeverity, ToolStatus } from '@/lib/types'

export function ActionBadge({ action }: { action: DriftAction }) {
  const map: Record<DriftAction, { label: string; color: 'emerald' | 'amber' | 'danger' | 'violet' }> = {
    allow:      { label: 'allow',      color: 'emerald' },
    monitor:    { label: 'monitor',    color: 'amber'   },
    deny:       { label: 'deny',       color: 'danger'  },
    quarantine: { label: 'quarantine', color: 'violet'  },
  }
  const { label, color } = map[action]
  return <Badge label={label} color={color} />
}

export function SeverityBadge({ severity }: { severity: DriftSeverity }) {
  const map: Record<DriftSeverity, { color: 'emerald' | 'amber' | 'danger' | 'violet' | 'muted' }> = {
    none:     { color: 'muted'    },
    minor:    { color: 'amber'    },
    moderate: { color: 'amber'    },
    high:     { color: 'danger'   },
    critical: { color: 'danger'   },
  }
  return <Badge label={severity} color={map[severity].color} />
}

export function StatusBadge({ status }: { status: ToolStatus }) {
  const map: Record<ToolStatus, { color: 'emerald' | 'amber' | 'violet' | 'muted' }> = {
    active:      { color: 'emerald' },
    changed:     { color: 'amber'   },
    quarantined: { color: 'violet'  },
  }
  return <Badge label={status} color={map[status].color} />
}
```

- [ ] Write `src/components/dashboard/Sidebar.tsx`:

```tsx
import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard, GitBranch, ScrollText, Wrench,
  Server, ShieldCheck, Lock, Settings, Shield,
} from 'lucide-react'

const NAV = [
  { to: '/dashboard/overview',    icon: LayoutDashboard, label: 'Overview'     },
  { to: '/dashboard/drift',       icon: GitBranch,       label: 'Drift Review' },
  { to: '/dashboard/audit',       icon: ScrollText,      label: 'Audit Log'    },
  { to: '/dashboard/tools',       icon: Wrench,          label: 'Tools'        },
  { to: '/dashboard/servers',     icon: Server,          label: 'Servers'      },
  { to: '/dashboard/policies',    icon: ShieldCheck,     label: 'Policies'     },
  { to: '/dashboard/quarantine',  icon: Lock,            label: 'Quarantine'   },
  { to: '/dashboard/settings',    icon: Settings,        label: 'Settings'     },
]

export function Sidebar() {
  return (
    <aside className="fixed left-0 top-0 h-screen w-[220px] bg-[#101412] border-r border-[#27302B] flex flex-col z-40 shrink-0">
      {/* Logo */}
      <div className="flex items-center gap-2.5 px-5 py-5 border-b border-[#27302B]">
        <div className="w-7 h-7 rounded-md bg-[#10B981] flex items-center justify-center shrink-0">
          <Shield size={14} className="text-[#080A09]" />
        </div>
        <span className="font-semibold text-[#F4F7F5] text-sm tracking-tight">Interlock</span>
      </div>

      {/* Nav */}
      <nav className="flex-1 py-4 px-2 overflow-y-auto">
        <div className="text-[10px] font-mono font-semibold text-[#6B7670] tracking-widest px-3 mb-2 uppercase">Console</div>
        {NAV.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded text-sm transition-colors mb-0.5 ` +
              (isActive
                ? 'text-[#10B981] bg-[rgba(16,185,129,0.08)] border-l-2 border-[#10B981] pl-[10px]'
                : 'text-[#9CA8A2] hover:text-[#F4F7F5] hover:bg-[#161B18]')
            }
          >
            <Icon size={15} className="shrink-0" />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div className="px-4 py-3 border-t border-[#27302B]">
        <span className="text-[10px] font-mono text-[#6B7670]">v0.1.0 · Interlock</span>
      </div>
    </aside>
  )
}
```

- [ ] Write `src/components/dashboard/TopBar.tsx`:

```tsx
import { RefreshCw, AlertCircle } from 'lucide-react'
import { isDemoMode } from '@/lib/interlockApi'

interface TopBarProps {
  title: string
  subtitle?: string
  onRefresh?: () => void
}

export function TopBar({ title, subtitle, onRefresh }: TopBarProps) {
  const demo = isDemoMode()
  return (
    <header className="sticky top-0 z-30 bg-[#101412] border-b border-[#27302B] px-6 py-3 flex items-center justify-between">
      <div>
        <h1 className="text-[#F4F7F5] text-sm font-semibold">{title}</h1>
        {subtitle && <p className="text-[#6B7670] text-xs font-mono mt-0.5">{subtitle}</p>}
      </div>
      <div className="flex items-center gap-3">
        {demo && (
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded border border-[rgba(214,162,58,0.3)] bg-[rgba(214,162,58,0.07)]">
            <AlertCircle size={11} className="text-[#D6A23A]" />
            <span className="text-[#D6A23A] text-xs font-mono">Demo data</span>
          </div>
        )}
        {onRefresh && (
          <button
            onClick={onRefresh}
            className="w-7 h-7 flex items-center justify-center rounded border border-[#27302B] text-[#6B7670] hover:text-[#9CA8A2] hover:border-[#3a4a42] transition-colors"
          >
            <RefreshCw size={13} />
          </button>
        )}
      </div>
    </header>
  )
}
```

- [ ] Commit: `feat: add dashboard shell components`

---

## Task 7: Dashboard page shell + routing

**Files:**
- Modify: `src/pages/Dashboard.tsx`
- Create: `src/App.tsx`
- Modify: `src/main.tsx`

- [ ] Write `src/pages/Dashboard.tsx`:

```tsx
import { Outlet } from 'react-router-dom'
import { Sidebar } from '@/components/dashboard/Sidebar'

export default function Dashboard() {
  return (
    <div className="flex min-h-screen bg-[#080A09]">
      <Sidebar />
      <div className="flex-1 ml-[220px] flex flex-col min-h-screen">
        <Outlet />
      </div>
    </div>
  )
}
```

- [ ] Write `src/App.tsx`:

```tsx
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Landing from './pages/Landing'
import Dashboard from './pages/Dashboard'
import Overview from './features/overview/Overview'
import DriftReview from './features/drift/DriftReview'
import AuditLog from './features/audit/AuditLog'
import Tools from './features/tools/Tools'
import Servers from './features/servers/Servers'
import Policies from './features/policies/Policies'
import Quarantine from './features/quarantine/Quarantine'
import SettingsPage from './features/settings/Settings'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/dashboard" element={<Dashboard />}>
          <Route index element={<Navigate to="drift" replace />} />
          <Route path="overview"   element={<Overview />} />
          <Route path="drift"      element={<DriftReview />} />
          <Route path="audit"      element={<AuditLog />} />
          <Route path="tools"      element={<Tools />} />
          <Route path="servers"    element={<Servers />} />
          <Route path="policies"   element={<Policies />} />
          <Route path="quarantine" element={<Quarantine />} />
          <Route path="settings"   element={<SettingsPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
```

- [ ] Update `src/main.tsx` (remove Supabase import if present):

```tsx
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './styles/globals.css'
import App from './App.tsx'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
```

- [ ] Commit: `feat: add dashboard shell and routing`

---

## Task 8: DriftReview feature — dashboard visual hero

**Files:**
- Create: `src/features/drift/DriftReview.tsx`

This is the most important component. Full implementation:

- [ ] Write `src/features/drift/DriftReview.tsx` — see implementation notes:
  - State: `tools`, `loading`, `error`, `busyKey`, `filterSeverity`, `filterServer`, `search`, `expandedKey`
  - On mount: call `listDriftedTools()`, sort by severity desc
  - Filter by severity, server, and search (tool name)
  - Table: server / tool / severity badge / status badge / what changed (first drift_reason, truncated) / confidence / actions
  - Expanded detail panel below selected row: full metadata inspector (effects, data_classes, warnings, etc.)
  - Approve action: `approveTool()` → optimistic update row to status=active, drift_severity=none
  - Quarantine action: `quarantineTool()` → optimistic update row to status=quarantined
  - TopBar title="Drift Review Queue" subtitle="Tools that have drifted from their baseline"
  - Empty state: "No drift detected. All tools match their baselines."
  - Loading/error states
  - Framer motion: stagger table rows on load, badge transition on action

- [ ] Commit: `feat: add DriftReview feature`

---

## Task 9: AuditLog feature

**Files:**
- Create: `src/features/audit/AuditLog.tsx`

- [ ] Fetch `listAuditEvents()`, display table with columns: Timestamp | Server | Tool | Action | Role | Matched Rule | Reason
- [ ] Action column uses ActionBadge
- [ ] Filters: action type (all/allow/monitor/deny/quarantine), search by tool/server
- [ ] Timestamp formatted: "2 min ago" style relative time
- [ ] TopBar title="Audit Log"
- [ ] Commit: `feat: add AuditLog feature`

---

## Task 10: Overview feature

**Files:**
- Create: `src/features/overview/Overview.tsx`

- [ ] Fetch `getOverviewStats()`, display 6 stat cards in 3-column grid
- [ ] Cards: MCP Servers / Tools Baselined / Drift Alerts / Blocked Calls / Monitored Calls / Quarantined Tools
- [ ] Each card: large number, label, subtle icon
- [ ] Below cards: recent drift summary (top 3 from driftedTools) with link to `/dashboard/drift`
- [ ] TopBar title="Overview"
- [ ] Commit: `feat: add Overview feature`

---

## Task 11: Tools, Servers, Policies features

**Files:**
- Create: `src/features/tools/Tools.tsx`
- Create: `src/features/servers/Servers.tsx`
- Create: `src/features/policies/Policies.tsx`

- [ ] Tools: `listAllTools()`, table with server/tool/status/severity/confidence/effects, expandable metadata row
- [ ] Servers: `listServers()`, table with name/url/trusted/tool_count/last_seen
- [ ] Policies: readable list (not a table) of policy rules with role/effect/description
- [ ] Commit: `feat: add Tools, Servers, Policies features`

---

## Task 12: Quarantine + Settings features

**Files:**
- Create: `src/features/quarantine/Quarantine.tsx`
- Create: `src/features/settings/Settings.tsx`

- [ ] Quarantine: `listDriftedTools()` filtered to status=quarantined, same table as DriftReview with Approve action only
- [ ] Settings: form with API URL (reads/writes localStorage `interlock_api_url`) and API key (reads/writes `interlock_api_key`), save button, demo mode indicator
- [ ] Commit: `feat: add Quarantine and Settings features`

---

## Task 13: Landing page components

**Files:**
- Create: `src/components/landing/Nav.tsx`
- Create: `src/components/landing/Hero.tsx`
- Create: `src/components/landing/Problem.tsx`
- Create: `src/components/landing/HowItWorks.tsx`
- Create: `src/components/landing/Capabilities.tsx`
- Create: `src/components/landing/WorkflowExample.tsx`
- Create: `src/components/landing/BuyerProof.tsx`
- Create: `src/components/landing/LandingCTA.tsx`
- Create: `src/components/landing/Footer.tsx`

- [ ] Nav: logo left, nav links (How it Works, Dashboard), CTA button "Launch Security Console" → `/dashboard/drift`
- [ ] Hero: large Inter 700-800 headline "Control plane for MCP tool security", subheading, two CTAs, SVG architecture diagram (Agents → Interlock → MCP Servers). Use framer-motion stagger entrance.
- [ ] Problem: dark card, concise problem statement, 3-4 bullet points about fragmented MCP security
- [ ] HowItWorks: horizontal step flow — Discover → Baseline → Enforce → Review → Audit — with connecting lines
- [ ] Capabilities: 6-item grid with icon + title + one-line description each
- [ ] WorkflowExample: code/terminal-style panel showing the drift story narrative
- [ ] BuyerProof: large quote "Know what every agent was allowed to do before it does it." + 3 trust items
- [ ] LandingCTA: full-width CTA section, "Launch Security Console" button → `/dashboard/drift`
- [ ] Footer: logo, tagline, minimal links, © 2026 Interlock
- [ ] Commit: `feat: add landing page components`

---

## Task 14: Landing page assembly + responsive polish

**Files:**
- Modify: `src/pages/Landing.tsx`

- [ ] Assemble all landing components in order: Nav, Hero, Problem, HowItWorks, Capabilities, WorkflowExample, BuyerProof, LandingCTA, Footer
- [ ] Add scroll-based motion (IntersectionObserver or framer-motion whileInView) for below-fold sections
- [ ] Verify mobile layout: nav collapses, hero stacks vertically, grid goes 1-col
- [ ] Commit: `feat: complete landing page`

---

## Task 15: npm install + build + lint + fix

**Files:** `package.json` updates only

- [ ] `cd interlock-web && npm install`
- [ ] `npm run build` — fix all TypeScript and build errors
- [ ] `npm run lint` — fix all ESLint errors
- [ ] Verify: no text overflow in any table, all badges render, dashboard loads in demo mode
- [ ] Final commit: `fix: build and lint clean`

---

## Spec Coverage Check

| Spec requirement | Task |
|---|---|
| `/dashboard` redirects to `/dashboard/drift` | Task 7 |
| Fixed left sidebar with 8 sections | Task 6 |
| DriftReview as visual hero | Task 8 |
| Approve/Keep Quarantined actions + optimistic update | Task 8 |
| Full demo data (3 servers, 6 tools, 3 drifted, 5 audit) | Task 3 |
| Demo fallback with "Demo data" pill | Tasks 4, 6 |
| ActionBadge semantic colors | Task 6 |
| All 8 dashboard sections | Tasks 8–12 |
| Landing page 9 sections | Task 13–14 |
| Landing CTA → `/dashboard/drift` | Task 13 |
| framer-motion: stagger, entrance, badge transition | Tasks 8, 13–14 |
| Build + lint clean | Task 15 |
| No Supabase | Task 1 |
| No lorem ipsum | All tasks |
