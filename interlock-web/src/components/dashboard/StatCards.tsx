import { motion } from 'framer-motion'
import type { OverviewStats } from '@/lib/types'

interface StatCardProps { label: string; value: number; color?: string }

function StatCard({ label, value, color = '#10B981' }: StatCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-[#101412] border border-[#27302B] rounded-lg p-5"
    >
      <p className="text-[#6B7670] text-[13px] font-mono uppercase tracking-wider mb-2">{label}</p>
      <p className="font-semibold text-3xl" style={{ color }}>{value}</p>
    </motion.div>
  )
}

interface StatCardsProps { stats: OverviewStats }

export function StatCards({ stats }: StatCardsProps) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
      <StatCard label="MCP Servers"       value={stats.mcp_servers}       />
      <StatCard label="Tools Baselined"   value={stats.tools_baselined}   />
      <StatCard label="Drift Alerts"      value={stats.drift_alerts}      color="#D6A23A" />
      <StatCard label="Blocked Calls"     value={stats.blocked_calls}     color="#D86A4A" />
      <StatCard label="Monitored Calls"   value={stats.monitored_calls}   color="#D6A23A" />
      <StatCard label="Quarantined Tools" value={stats.quarantined_tools} color="#A78BFA" />
    </div>
  )
}
