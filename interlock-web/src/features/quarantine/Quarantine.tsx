import { useCallback, useEffect, useMemo, useState } from 'react'
import { motion } from 'framer-motion'
import { CheckCircle2 } from 'lucide-react'
import { TopBar } from '@/components/dashboard/TopBar'
import { SeverityBadge, ActionBadge } from '@/components/dashboard/StatusBadge'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { LoadingState } from '@/components/ui/LoadingState'
import { listDriftedTools, approveTool } from '@/lib/interlockApi'
import type { McpTool } from '@/lib/types'

export default function Quarantine() {
  const [tools, setTools] = useState<McpTool[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [busyKey, setBusyKey] = useState('')

  const load = useCallback(async () => {
    setLoading(true); setError('')
    try { setTools(await listDriftedTools()) }
    catch (e) { setError(e instanceof Error ? e.message : 'Failed to load') }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { void load() }, [load])

  const quarantined = useMemo(() => tools.filter(t => t.status === 'quarantined'), [tools])

  async function handleApprove(tool: McpTool) {
    const key = `${tool.server_id}:${tool.tool_name}`
    setBusyKey(key)
    try {
      const updated = await approveTool(tool.server_id, tool.tool_name)
      setTools(prev => prev.map(t => t.server_id === tool.server_id && t.tool_name === tool.tool_name ? updated : t))
    } finally {
      setBusyKey('')
    }
  }

  return (
    <div className="flex flex-col flex-1 min-h-0">
      <TopBar title="Quarantine" subtitle="Tools quarantined pending operator review" onRefresh={load} />
      <div className="flex-1 overflow-auto p-6">
        {loading ? <LoadingState /> : error ? (
          <div className="text-[#D86A4A] text-sm font-mono p-4 bg-[rgba(216,106,74,0.08)] border border-[rgba(216,106,74,0.2)] rounded">{error}</div>
        ) : quarantined.length === 0 ? (
          <EmptyState message="No quarantined tools" sub="Quarantined tools appear here for operator review." />
        ) : (
          <div className="bg-[#101412] border border-[#27302B] rounded-lg overflow-hidden">
            <div className="grid grid-cols-[1fr_1fr_120px_100px_1fr_160px] gap-x-4 px-4 py-2.5 border-b border-[#27302B] bg-[#0D1210]">
              {['Server', 'Tool', 'Severity', 'Action', 'Reason', 'Release'].map(h => (
                <span key={h} className="text-[10px] font-mono font-semibold text-[#6B7670] tracking-widest uppercase">{h}</span>
              ))}
            </div>
            {quarantined.map((tool, i) => {
              const key = `${tool.server_id}:${tool.tool_name}`
              return (
                <motion.div
                  key={key}
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.05 }}
                  className="grid grid-cols-[1fr_1fr_120px_100px_1fr_160px] gap-x-4 px-4 py-3 border-b border-[#1c2420] items-center hover:bg-[#111714] transition-colors"
                >
                  <span className="text-[#9CA8A2] text-xs font-mono truncate">{tool.server_id}</span>
                  <span className="text-[#F4F7F5] text-sm font-mono font-medium truncate">{tool.tool_name}</span>
                  <SeverityBadge severity={tool.drift_severity} />
                  <ActionBadge action={tool.drift_action} />
                  <span className="text-[#6B7670] text-xs truncate">{tool.drift_reasons[0] ?? '—'}</span>
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={busyKey === key}
                    onClick={() => handleApprove(tool)}
                  >
                    <CheckCircle2 size={12} />
                    Approve Baseline
                  </Button>
                </motion.div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
