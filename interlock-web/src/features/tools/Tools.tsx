import { useCallback, useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { ChevronRight, ChevronDown, Search } from 'lucide-react'
import { TopBar } from '@/components/dashboard/TopBar'
import { SeverityBadge, ToolStatusBadge } from '@/components/dashboard/StatusBadge'
import { EmptyState } from '@/components/ui/EmptyState'
import { LoadingState } from '@/components/ui/LoadingState'
import { listAllTools } from '@/lib/interlockApi'
import type { McpTool } from '@/lib/types'

function MetaVal({ label, value }: { label: string; value?: string | number | string[] | null }) {
  if (!value && value !== 0) return null
  const display = Array.isArray(value) ? value.join(', ') : String(value)
  return (
    <div className="flex gap-3 text-xs py-1.5 border-b border-[#1c2420]">
      <span className="text-[#6B7670] font-mono w-36 shrink-0">{label}</span>
      <span className="text-[#9CA8A2] font-mono">{display}</span>
    </div>
  )
}

export default function Tools() {
  const [tools, setTools] = useState<McpTool[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [expanded, setExpanded] = useState<string | null>(null)
  const [search, setSearch] = useState('')

  const load = useCallback(async () => {
    setLoading(true); setError('')
    try { setTools(await listAllTools()) }
    catch (e) { setError(e instanceof Error ? e.message : 'Failed to load') }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { void load() }, [load])

  const filtered = tools.filter(t =>
    !search || t.tool_name.toLowerCase().includes(search.toLowerCase()) || t.server_id.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className="flex flex-col flex-1 min-h-0">
      <TopBar title="Tools" subtitle="All MCP tools with metadata" onRefresh={load} />
      <div className="flex-1 overflow-auto p-6">
        <div className="relative mb-5 w-64">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#6B7670]" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search tools…"
            className="w-full bg-[#101412] border border-[#27302B] text-[#F4F7F5] text-sm pl-8 pr-3 py-1.5 rounded focus:outline-none focus:border-[#10B981] placeholder:text-[#6B7670]"
          />
        </div>

        {loading ? <LoadingState /> : error ? (
          <div className="text-[#D86A4A] text-sm font-mono p-4 bg-[rgba(216,106,74,0.08)] border border-[rgba(216,106,74,0.2)] rounded">{error}</div>
        ) : filtered.length === 0 ? (
          <EmptyState message="No tools found" />
        ) : (
          <div className="bg-[#101412] border border-[#27302B] rounded-lg overflow-hidden">
            <div className="grid grid-cols-[28px_1fr_1fr_100px_100px_80px] gap-x-4 px-4 py-2.5 border-b border-[#27302B] bg-[#0D1210]">
              {['', 'Server', 'Tool', 'Status', 'Severity', 'Conf.'].map(h => (
                <span key={h} className="text-[10px] font-mono font-semibold text-[#6B7670] tracking-widest uppercase">{h}</span>
              ))}
            </div>
            {filtered.map((tool, i) => {
              const key = `${tool.server_id}:${tool.tool_name}`
              const isOpen = expanded === key
              return (
                <motion.div key={key} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.04 }}>
                  <div
                    className="grid grid-cols-[28px_1fr_1fr_100px_100px_80px] gap-x-4 px-4 py-3 border-b border-[#1c2420] items-center hover:bg-[#111714] transition-colors cursor-pointer"
                    onClick={() => setExpanded(isOpen ? null : key)}
                  >
                    <span className="text-[#6B7670]">{isOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</span>
                    <span className="text-[#9CA8A2] text-xs font-mono truncate">{tool.server_id}</span>
                    <span className="text-[#F4F7F5] text-sm font-mono font-medium truncate">{tool.tool_name}</span>
                    <ToolStatusBadge status={tool.status} />
                    <SeverityBadge severity={tool.drift_severity} />
                    <span className="text-[#9CA8A2] text-xs font-mono">
                      {tool.normalized_metadata?.confidence != null ? `${Math.round(tool.normalized_metadata.confidence * 100)}%` : '—'}
                    </span>
                  </div>
                  <AnimatePresence>
                    {isOpen && (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.18 }}
                        style={{ overflow: 'hidden' }}
                        className="bg-[#0D1210] border-b border-[#27302B] px-6 py-4"
                      >
                        {tool.description && <p className="text-[#9CA8A2] text-xs mb-3">{tool.description}</p>}
                        <MetaVal label="effects"            value={tool.normalized_metadata?.effects} />
                        <MetaVal label="side_effect"        value={tool.normalized_metadata?.side_effect} />
                        <MetaVal label="data_classes"       value={tool.normalized_metadata?.data_classes} />
                        <MetaVal label="externality"        value={tool.normalized_metadata?.externality} />
                        <MetaVal label="identity_mode"      value={tool.normalized_metadata?.identity_mode} />
                        <MetaVal label="verification_level" value={tool.normalized_metadata?.verification_level} />
                        <MetaVal label="source"             value={tool.normalized_metadata?.source} />
                        {(tool.normalized_metadata?.warnings ?? []).length > 0 && (
                          <div className="mt-2 space-y-1">
                            {tool.normalized_metadata!.warnings!.map((w, j) => (
                              <p key={j} className="text-[#D86A4A] text-xs font-mono">⚠ {w}</p>
                            ))}
                          </div>
                        )}
                      </motion.div>
                    )}
                  </AnimatePresence>
                </motion.div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
