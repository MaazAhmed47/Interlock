import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { ArrowRight, AlertTriangle } from 'lucide-react'
import { motion } from 'framer-motion'
import { TopBar } from '@/components/dashboard/TopBar'
import { StatCards } from '@/components/dashboard/StatCards'
import { SeverityBadge } from '@/components/dashboard/StatusBadge'
import { LoadingState } from '@/components/ui/LoadingState'
import { getOverviewStats, listDriftedTools } from '@/lib/interlockApi'
import type { OverviewStats, McpTool } from '@/lib/types'

export default function Overview() {
  const [stats, setStats] = useState<OverviewStats | null>(null)
  const [drifted, setDrifted] = useState<McpTool[]>([])
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    const [s, d] = await Promise.all([getOverviewStats(), listDriftedTools()])
    setStats(s)
    setDrifted(d.slice(0, 3))
    setLoading(false)
  }, [])

  useEffect(() => { void load() }, [load])

  return (
    <div className="flex flex-col flex-1 min-h-0">
      <TopBar title="Overview" subtitle="System health and recent activity" onRefresh={load} />

      <div className="flex-1 overflow-auto p-6 space-y-8">
        {loading ? <LoadingState /> : !stats ? null : (
          <>
            <StatCards stats={stats} />

            {drifted.length > 0 && (
              <motion.div
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.15 }}
                className="bg-[#101412] border border-[#27302B] rounded-lg overflow-hidden"
              >
                <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#27302B]">
                  <div className="flex items-center gap-2">
                    <AlertTriangle size={14} className="text-[#D6A23A]" />
                    <span className="text-[#F4F7F5] text-sm font-semibold">Recent Drift Alerts</span>
                  </div>
                  <Link
                    to="/dashboard/drift"
                    className="flex items-center gap-1 text-xs text-[#10B981] hover:text-[#059669] transition-colors"
                  >
                    View all <ArrowRight size={12} />
                  </Link>
                </div>
                {drifted.map(tool => (
                  <div key={`${tool.server_id}:${tool.tool_name}`} className="flex items-center gap-4 px-5 py-3 border-b border-[#1c2420] last:border-0">
                    <SeverityBadge severity={tool.drift_severity} />
                    <span className="text-[#F4F7F5] text-sm font-mono font-medium">{tool.tool_name}</span>
                    <span className="text-[#6B7670] text-xs font-mono">{tool.server_id}</span>
                    <span className="ml-auto text-[#9CA8A2] text-xs truncate max-w-xs">{tool.drift_reasons[0] ?? ''}</span>
                  </div>
                ))}
              </motion.div>
            )}

            <motion.div
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.25 }}
              className="bg-[#101412] border border-[#27302B] rounded-lg p-5"
            >
              <p className="text-[10px] font-mono font-semibold text-[#6B7670] tracking-widest uppercase mb-3">Pipeline Status</p>
              <div className="flex items-center gap-0 text-xs font-mono">
                {['Agent Request', 'Metadata Normalize', 'Policy Decision', 'Argument Scan', 'MCP Call', 'Response Scan', 'Audit Log'].map((step, i, arr) => (
                  <div key={step} className="flex items-center gap-0">
                    <div className="px-3 py-2 rounded bg-[#161B18] border border-[#27302B] text-[#9CA8A2] whitespace-nowrap">
                      {step}
                    </div>
                    {i < arr.length - 1 && (
                      <div className="w-6 h-px bg-[#10B981] shrink-0 relative">
                        <div className="absolute right-0 top-1/2 -translate-y-1/2 w-1.5 h-1.5 rounded-full bg-[#10B981]" />
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </motion.div>
          </>
        )}
      </div>
    </div>
  )
}
