import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { ShieldCheck, ShieldX, Eye, Lock } from 'lucide-react'
import { TopBar } from '@/components/dashboard/TopBar'
import { demoPolicies } from '@/lib/demoData'
import type { PolicyRule, DriftAction } from '@/lib/types'

const effectIcons: Record<DriftAction, React.ReactNode> = {
  allow:      <ShieldCheck size={14} className="text-[#10B981]" />,
  monitor:    <Eye size={14} className="text-[#D6A23A]" />,
  deny:       <ShieldX size={14} className="text-[#D86A4A]" />,
  quarantine: <Lock size={14} className="text-[#A78BFA]" />,
}

const effectColors: Record<DriftAction, string> = {
  allow:      'border-[rgba(16,185,129,0.2)]  bg-[rgba(16,185,129,0.05)]',
  monitor:    'border-[rgba(214,162,58,0.2)]  bg-[rgba(214,162,58,0.05)]',
  deny:       'border-[rgba(216,106,74,0.2)]  bg-[rgba(216,106,74,0.05)]',
  quarantine: 'border-[rgba(167,139,250,0.2)] bg-[rgba(167,139,250,0.05)]',
}

export default function Policies() {
  const [policies] = useState<PolicyRule[]>(demoPolicies)

  useEffect(() => {}, [])

  return (
    <div className="flex flex-col flex-1 min-h-0">
      <TopBar title="Policies" subtitle="Active security policy rules" />
      <div className="flex-1 overflow-auto p-6">
        <p className="text-[#6B7670] text-xs font-mono mb-6">
          These rules are evaluated on every MCP tool call before execution. Rules are evaluated in order; first match wins.
        </p>
        <div className="space-y-3 max-w-2xl">
          {policies.map((p, i) => (
            <motion.div
              key={p.id}
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.07 }}
              className={`flex items-start gap-4 p-4 rounded-lg border ${effectColors[p.effect]}`}
            >
              <div className="mt-0.5 shrink-0">{effectIcons[p.effect]}</div>
              <div className="flex-1 min-w-0">
                <p className="text-[#F4F7F5] text-sm font-medium font-mono">{p.description}</p>
                <p className="text-[#6B7670] text-xs mt-1">applies to: <span className="text-[#9CA8A2]">{p.applies_to}</span></p>
              </div>
              <span className={`text-xs font-mono px-2 py-0.5 rounded border ${
                p.effect === 'allow' ? 'text-[#10B981] border-[rgba(16,185,129,0.3)]' :
                p.effect === 'monitor' ? 'text-[#D6A23A] border-[rgba(214,162,58,0.3)]' :
                p.effect === 'deny' ? 'text-[#D86A4A] border-[rgba(216,106,74,0.3)]' :
                'text-[#A78BFA] border-[rgba(167,139,250,0.3)]'
              }`}>{p.effect}</span>
            </motion.div>
          ))}
        </div>
      </div>
    </div>
  )
}
