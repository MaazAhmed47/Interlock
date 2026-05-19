import { useCallback, useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { CheckCircle2, XCircle } from 'lucide-react'
import { TopBar } from '@/components/dashboard/TopBar'
import { EmptyState } from '@/components/ui/EmptyState'
import { LoadingState } from '@/components/ui/LoadingState'
import { listServers } from '@/lib/interlockApi'
import type { McpServer } from '@/lib/types'

function relTime(iso: string) {
  const diff = Date.now() - new Date(iso).getTime()
  if (diff < 60_000) return 'just now'
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`
  return `${Math.floor(diff / 3_600_000)}h ago`
}

export default function Servers() {
  const [servers, setServers] = useState<McpServer[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    setLoading(true); setError('')
    try { setServers(await listServers()) }
    catch (e) { setError(e instanceof Error ? e.message : 'Failed to load') }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { void load() }, [load])

  return (
    <div className="flex flex-col flex-1 min-h-0">
      <TopBar title="Servers" subtitle="Registered MCP server registry" onRefresh={load} />
      <div className="flex-1 overflow-auto p-6">
        {loading ? <LoadingState /> : error ? (
          <div className="text-[#D86A4A] text-sm font-mono p-4 bg-[rgba(216,106,74,0.08)] border border-[rgba(216,106,74,0.2)] rounded">{error}</div>
        ) : servers.length === 0 ? (
          <EmptyState message="No servers registered" sub="Add MCP servers to begin monitoring." />
        ) : (
          <div className="bg-[#101412] border border-[#27302B] rounded-lg overflow-hidden">
            <div className="grid grid-cols-[1fr_2fr_80px_80px_100px] gap-x-4 px-4 py-2.5 border-b border-[#27302B] bg-[#0D1210]">
              {['Name', 'URL', 'Trust', 'Tools', 'Last Seen'].map(h => (
                <span key={h} className="text-[10px] font-mono font-semibold text-[#6B7670] tracking-widest uppercase">{h}</span>
              ))}
            </div>
            {servers.map((s, i) => (
              <motion.div
                key={s.id}
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.05 }}
                className="grid grid-cols-[1fr_2fr_80px_80px_100px] gap-x-4 px-4 py-3 border-b border-[#1c2420] items-center hover:bg-[#111714] transition-colors"
              >
                <span className="text-[#F4F7F5] text-sm font-medium truncate">{s.name}</span>
                <span className="text-[#6B7670] text-xs font-mono truncate">{s.url}</span>
                <span>
                  {s.trusted
                    ? <span className="flex items-center gap-1 text-xs text-[#10B981]"><CheckCircle2 size={12} /> Trusted</span>
                    : <span className="flex items-center gap-1 text-xs text-[#D86A4A]"><XCircle size={12} /> Untrusted</span>}
                </span>
                <span className="text-[#9CA8A2] text-xs font-mono">{s.tool_count}</span>
                <span className="text-[#6B7670] text-xs font-mono">{relTime(s.last_seen)}</span>
              </motion.div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
