import { useCallback, useEffect, useMemo, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { ChevronDown, ChevronRight, RefreshCw, Search, AlertTriangle, CheckCircle2, Lock } from 'lucide-react'
import { TopBar } from '@/components/dashboard/TopBar'
import { SeverityBadge, ToolStatusBadge, ActionBadge } from '@/components/dashboard/StatusBadge'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { LoadingState } from '@/components/ui/LoadingState'
import { listDriftedTools, approveTool, quarantineTool } from '@/lib/interlockApi'
import type { McpTool, ToolMetadata } from '@/lib/types'

const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, moderate: 2, minor: 1, none: 0 }

// Columns: expand | server | tool | severity | status | reason | conf | actions
const COLS = 'grid-cols-[24px_1fr_1fr_130px_120px_1fr_72px_216px]'

function relTime(iso?: string | null) {
  if (!iso) return '—'
  const diff = Date.now() - new Date(iso).getTime()
  if (diff < 60_000) return 'just now'
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`
  return new Date(iso).toLocaleDateString()
}

function MetaRow({ label, value }: { label: string; value?: string | number | string[] | null }) {
  if (!value || (Array.isArray(value) && value.length === 0)) return null
  const display = Array.isArray(value) ? value.join(', ') : String(value)
  return (
    <div className="flex gap-3 py-2 border-b border-[#1c2420]">
      <span className="text-[#6B7670] font-mono text-[13px] w-36 shrink-0">{label}</span>
      <span className="text-[#9CA8A2] font-mono text-[13px] break-all">{display}</span>
    </div>
  )
}

function MetadataPanel({ meta, reasons, warnings }: { meta?: ToolMetadata; reasons: string[]; warnings: string[] }) {
  return (
    <div className="bg-[#0D1210] border-t border-[#27302B] px-6 py-5">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <p className="text-[11px] font-mono font-semibold text-[#6B7670] tracking-widest uppercase mb-3">Drift Reasons</p>
          <ul className="space-y-1.5">
            {reasons.map((r, i) => (
              <li key={i} className="flex gap-2 text-[13px] text-[#D6A23A]">
                <AlertTriangle size={13} className="shrink-0 mt-0.5" />
                <span className="font-mono">{r}</span>
              </li>
            ))}
          </ul>
          {warnings.length > 0 && (
            <div className="mt-4">
              <p className="text-[11px] font-mono font-semibold text-[#6B7670] tracking-widest uppercase mb-3">Warnings</p>
              <ul className="space-y-1.5">
                {warnings.map((w, i) => (
                  <li key={i} className="text-[13px] text-[#D86A4A] font-mono">⚠ {w}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
        {meta && (
          <div>
            <p className="text-[11px] font-mono font-semibold text-[#6B7670] tracking-widest uppercase mb-3">Tool Metadata</p>
            <MetaRow label="effects"            value={meta.effects} />
            <MetaRow label="side_effect"        value={meta.side_effect} />
            <MetaRow label="data_classes"       value={meta.data_classes} />
            <MetaRow label="externality"        value={meta.externality} />
            <MetaRow label="identity_mode"      value={meta.identity_mode} />
            <MetaRow label="verification_level" value={meta.verification_level} />
            <MetaRow label="confidence"         value={meta.confidence != null ? `${Math.round(meta.confidence * 100)}%` : null} />
            <MetaRow label="source"             value={meta.source} />
          </div>
        )}
      </div>
    </div>
  )
}

interface RowAction { key: string; busy: boolean }

export default function DriftReview() {
  const [tools, setTools] = useState<McpTool[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [expandedKey, setExpandedKey] = useState<string | null>(null)
  const [rowAction, setRowAction] = useState<RowAction | null>(null)
  const [search, setSearch] = useState('')
  const [filterSeverity, setFilterSeverity] = useState('all')
  const [filterServer, setFilterServer] = useState('all')

  const load = useCallback(async () => {
    setLoading(true); setError('')
    try { setTools(await listDriftedTools()) }
    catch (e) { setError(e instanceof Error ? e.message : 'Failed to load') }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { void load() }, [load])

  const servers = useMemo(() => Array.from(new Set(tools.map(t => t.server_id))), [tools])

  const filtered = useMemo(() =>
    tools
      .filter(t => filterSeverity === 'all' || t.drift_severity === filterSeverity)
      .filter(t => filterServer === 'all' || t.server_id === filterServer)
      .filter(t => !search || t.tool_name.toLowerCase().includes(search.toLowerCase()) || t.server_id.toLowerCase().includes(search.toLowerCase()))
      .sort((a, b) => (SEVERITY_RANK[b.drift_severity] ?? 0) - (SEVERITY_RANK[a.drift_severity] ?? 0)),
    [tools, filterSeverity, filterServer, search]
  )

  async function handleApprove(tool: McpTool) {
    const key = `${tool.server_id}:${tool.tool_name}`
    setRowAction({ key, busy: true })
    try {
      const updated = await approveTool(tool.server_id, tool.tool_name)
      setTools(prev => prev.map(t => t.server_id === tool.server_id && t.tool_name === tool.tool_name ? updated : t))
    } finally {
      setRowAction(null)
    }
  }

  async function handleQuarantine(tool: McpTool) {
    const key = `${tool.server_id}:${tool.tool_name}`
    setRowAction({ key, busy: true })
    try {
      const updated = await quarantineTool(tool.server_id, tool.tool_name)
      setTools(prev => prev.map(t => t.server_id === tool.server_id && t.tool_name === tool.tool_name ? updated : t))
    } finally {
      setRowAction(null)
    }
  }

  const toggleExpand = (key: string) => setExpandedKey(prev => prev === key ? null : key)

  return (
    <div className="flex flex-col flex-1 min-h-0">
      <TopBar
        title="Drift Review Queue"
        subtitle="Tools that have drifted from their baseline"
        onRefresh={load}
      />

      <div className="flex-1 overflow-auto p-6">
        {/* Filters */}
        <div className="flex flex-wrap gap-3 mb-5">
          <div className="relative">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#6B7670]" />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search tools…"
              className="bg-[#101412] border border-[#27302B] text-[#F4F7F5] text-[14px] pl-9 pr-3 py-2 rounded focus:outline-none focus:border-[#10B981] w-56 placeholder:text-[#6B7670]"
            />
          </div>
          <select
            value={filterSeverity}
            onChange={e => setFilterSeverity(e.target.value)}
            className="bg-[#101412] border border-[#27302B] text-[#9CA8A2] text-[14px] px-3 py-2 rounded focus:outline-none focus:border-[#10B981]"
          >
            <option value="all">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="moderate">Moderate</option>
            <option value="minor">Minor</option>
          </select>
          <select
            value={filterServer}
            onChange={e => setFilterServer(e.target.value)}
            className="bg-[#101412] border border-[#27302B] text-[#9CA8A2] text-[14px] px-3 py-2 rounded focus:outline-none focus:border-[#10B981]"
          >
            <option value="all">All servers</option>
            {servers.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <div className="ml-auto flex items-center gap-2 text-[13px] font-mono text-[#6B7670]">
            <RefreshCw size={13} />
            {filtered.length} item{filtered.length !== 1 ? 's' : ''}
          </div>
        </div>

        {/* Table */}
        {loading ? (
          <LoadingState />
        ) : error ? (
          <div className="text-[#D86A4A] text-[14px] font-mono p-4 bg-[rgba(216,106,74,0.08)] border border-[rgba(216,106,74,0.2)] rounded">{error}</div>
        ) : filtered.length === 0 ? (
          <EmptyState message="No drift detected" sub="All tools match their baselines." />
        ) : (
          <div className="bg-[#101412] border border-[#27302B] rounded-lg overflow-hidden">
            {/* Table header */}
            <div className={`grid ${COLS} gap-x-4 px-4 py-3 border-b border-[#27302B] bg-[#0D1210]`}>
              {['', 'Server', 'Tool', 'Severity', 'Status', 'What Changed', 'Conf.', 'Actions'].map(h => (
                <span key={h} className="text-[11px] font-mono font-semibold text-[#6B7670] tracking-widest uppercase">{h}</span>
              ))}
            </div>

            <AnimatePresence initial={false}>
              {filtered.map((tool, i) => {
                const key = `${tool.server_id}:${tool.tool_name}`
                const isExpanded = expandedKey === key
                const isBusy = rowAction?.key === key && rowAction.busy
                const firstReason = tool.drift_reasons[0] ?? '—'
                const shortReason = firstReason.length > 52 ? firstReason.slice(0, 52) + '…' : firstReason

                return (
                  <motion.div
                    key={key}
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: i * 0.05, duration: 0.25 }}
                  >
                    {/* Row */}
                    <div
                      className={`grid ${COLS} gap-x-4 px-4 py-4 border-b border-[#1c2420] items-center hover:bg-[#111714] transition-colors cursor-pointer ${isExpanded ? 'bg-[#111714]' : ''}`}
                      onClick={() => toggleExpand(key)}
                    >
                      <span className="text-[#6B7670]">
                        {isExpanded ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
                      </span>
                      <span className="text-[#9CA8A2] text-[13px] font-mono truncate">{tool.server_id}</span>
                      <span className="text-[#F4F7F5] text-[14px] font-mono font-medium truncate">{tool.tool_name}</span>
                      <span><SeverityBadge severity={tool.drift_severity} /></span>
                      <span><ToolStatusBadge status={tool.status} /></span>
                      <span className="text-[#9CA8A2] text-[13px] truncate" title={firstReason}>{shortReason}</span>
                      <span className="text-[#9CA8A2] text-[13px] font-mono">
                        {tool.normalized_metadata?.confidence != null
                          ? `${Math.round(tool.normalized_metadata.confidence * 100)}%`
                          : '—'}
                      </span>
                      <div className="flex gap-1.5" onClick={e => e.stopPropagation()}>
                        <Button
                          variant="ghost"
                          size="sm"
                          disabled={isBusy}
                          onClick={() => handleApprove(tool)}
                        >
                          <CheckCircle2 size={13} />
                          Approve
                        </Button>
                        <Button
                          variant="quarantine-ghost"
                          size="sm"
                          disabled={isBusy}
                          onClick={() => handleQuarantine(tool)}
                        >
                          <Lock size={13} />
                          Quarantine
                        </Button>
                      </div>
                    </div>

                    {/* Expanded detail */}
                    <AnimatePresence>
                      {isExpanded && (
                        <motion.div
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: 'auto', opacity: 1 }}
                          exit={{ height: 0, opacity: 0 }}
                          transition={{ duration: 0.2 }}
                          style={{ overflow: 'hidden' }}
                        >
                          <MetadataPanel
                            meta={tool.normalized_metadata}
                            reasons={tool.drift_reasons}
                            warnings={tool.normalized_metadata?.warnings ?? []}
                          />
                          <div className="px-6 py-2.5 bg-[#0D1210] border-t border-[#1c2420] flex items-center gap-3 text-[13px] font-mono text-[#6B7670]">
                            <span>last changed: {relTime(tool.last_changed)}</span>
                            <span>·</span>
                            <ActionBadge action={tool.drift_action} />
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </motion.div>
                )
              })}
            </AnimatePresence>
          </div>
        )}
      </div>
    </div>
  )
}
