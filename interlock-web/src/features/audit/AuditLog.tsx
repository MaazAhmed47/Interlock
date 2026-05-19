import { useCallback, useEffect, useMemo, useState } from 'react'
import { motion } from 'framer-motion'
import { Search } from 'lucide-react'
import { TopBar } from '@/components/dashboard/TopBar'
import { ActionBadge } from '@/components/dashboard/StatusBadge'
import { EmptyState } from '@/components/ui/EmptyState'
import { LoadingState } from '@/components/ui/LoadingState'
import { listAuditEvents } from '@/lib/interlockApi'
import type { AuditEvent } from '@/lib/types'

function relTime(iso: string) {
  const diff = Date.now() - new Date(iso).getTime()
  if (diff < 60_000) return 'just now'
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`
  return new Date(iso).toLocaleString()
}

export default function AuditLog() {
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [filterAction, setFilterAction] = useState('all')

  const load = useCallback(async () => {
    setLoading(true); setError('')
    try { setEvents(await listAuditEvents()) }
    catch (e) { setError(e instanceof Error ? e.message : 'Failed to load') }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { void load() }, [load])

  const filtered = useMemo(() =>
    events
      .filter(e => filterAction === 'all' || e.action === filterAction)
      .filter(e => !search || e.tool_name.toLowerCase().includes(search.toLowerCase()) || e.server_name.toLowerCase().includes(search.toLowerCase()) || e.role.toLowerCase().includes(search.toLowerCase())),
    [events, filterAction, search]
  )

  return (
    <div className="flex flex-col flex-1 min-h-0">
      <TopBar title="Audit Log" subtitle="All policy decisions with reasons and context" onRefresh={load} />

      <div className="flex-1 overflow-auto p-6">
        <div className="flex flex-wrap gap-3 mb-5">
          <div className="relative">
            <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#6B7670]" />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search tool, server, role…"
              className="bg-[#101412] border border-[#27302B] text-[#F4F7F5] text-sm pl-8 pr-3 py-1.5 rounded focus:outline-none focus:border-[#10B981] w-56 placeholder:text-[#6B7670]"
            />
          </div>
          <select
            value={filterAction}
            onChange={e => setFilterAction(e.target.value)}
            className="bg-[#101412] border border-[#27302B] text-[#9CA8A2] text-sm px-3 py-1.5 rounded focus:outline-none focus:border-[#10B981]"
          >
            <option value="all">All actions</option>
            <option value="allow">Allow</option>
            <option value="monitor">Monitor</option>
            <option value="deny">Deny</option>
            <option value="quarantine">Quarantine</option>
          </select>
        </div>

        {loading ? <LoadingState /> : error ? (
          <div className="text-[#D86A4A] text-sm font-mono p-4 bg-[rgba(216,106,74,0.08)] border border-[rgba(216,106,74,0.2)] rounded">{error}</div>
        ) : filtered.length === 0 ? (
          <EmptyState message="No audit events" sub="Events will appear here as policy decisions are made." />
        ) : (
          <div className="bg-[#101412] border border-[#27302B] rounded-lg overflow-hidden">
            <div className="grid grid-cols-[130px_1fr_1fr_100px_120px_140px_1fr] gap-x-4 px-4 py-2.5 border-b border-[#27302B] bg-[#0D1210]">
              {['Timestamp', 'Server', 'Tool', 'Action', 'Role', 'Matched Rule', 'Reason'].map(h => (
                <span key={h} className="text-[10px] font-mono font-semibold text-[#6B7670] tracking-widest uppercase">{h}</span>
              ))}
            </div>

            {filtered.map((evt, i) => (
              <motion.div
                key={evt.id}
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.04, duration: 0.2 }}
                className="grid grid-cols-[130px_1fr_1fr_100px_120px_140px_1fr] gap-x-4 px-4 py-3 border-b border-[#1c2420] items-center hover:bg-[#111714] transition-colors"
              >
                <span className="text-[#6B7670] text-xs font-mono">{relTime(evt.timestamp)}</span>
                <span className="text-[#9CA8A2] text-xs font-mono truncate">{evt.server_name}</span>
                <span className="text-[#F4F7F5] text-sm font-mono font-medium truncate">{evt.tool_name}</span>
                <span><ActionBadge action={evt.action} /></span>
                <span className="text-[#9CA8A2] text-xs font-mono truncate">{evt.role}</span>
                <span className="text-[#9CA8A2] text-xs font-mono truncate">{evt.matched_rule}</span>
                <span className="text-[#6B7670] text-xs truncate" title={evt.reason}>{evt.reason}</span>
              </motion.div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
