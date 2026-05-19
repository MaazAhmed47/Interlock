import { useRef } from 'react'
import { motion, useInView } from 'framer-motion'
import { Search, Database, ShieldCheck, GitBranch, ScrollText } from 'lucide-react'

const STEPS = [
  { icon: Search,      label: 'Discover',  desc: 'Interlock crawls registered MCP servers and normalizes every tool definition.' },
  { icon: Database,    label: 'Baseline',  desc: 'Each tool\'s metadata, effects, and data classes are recorded as its trusted baseline.' },
  { icon: ShieldCheck, label: 'Enforce',   desc: 'Every tool call is checked against RBAC policy before it reaches the MCP server.' },
  { icon: GitBranch,   label: 'Review',    desc: 'Drift from baseline triggers quarantine. Operators approve or reject each change.' },
  { icon: ScrollText,  label: 'Audit',     desc: 'Every allow, deny, monitor, and quarantine decision is recorded with full context.' },
]

export default function HowItWorks() {
  const ref = useRef<HTMLElement>(null)
  const inView = useInView(ref, { once: true, margin: '-80px' })

  return (
    <section ref={ref} id="how-it-works" className="py-20 px-6 border-t border-[#27302B]">
      <div className="max-w-[1280px] mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          className="text-center mb-14"
        >
          <p className="text-[#10B981] text-[13px] font-mono tracking-widest uppercase mb-3">How It Works</p>
          <h2 className="text-[#F4F7F5] font-bold text-3xl md:text-[2.5rem]">Five-stage security pipeline</h2>
        </motion.div>

        <div className="flex flex-col md:flex-row gap-0">
          {STEPS.map(({ icon: Icon, label, desc }, i) => (
            <motion.div
              key={label}
              initial={{ opacity: 0, y: 16 }}
              animate={inView ? { opacity: 1, y: 0 } : {}}
              transition={{ delay: 0.08 * i, duration: 0.4 }}
              className="flex-1 flex flex-col items-center text-center px-6 py-8 relative"
            >
              {i < STEPS.length - 1 && (
                <div className="hidden md:block absolute right-0 top-10 w-px h-12 bg-gradient-to-b from-[#27302B] to-transparent" />
              )}
              <div className="w-12 h-12 rounded-full border border-[#27302B] bg-[#101412] flex items-center justify-center mb-4">
                <Icon size={20} className="text-[#10B981]" />
              </div>
              <div className="text-[11px] font-mono text-[#10B981] tracking-widest uppercase mb-2">Step {i + 1}</div>
              <p className="text-[#F4F7F5] text-[15px] font-semibold mb-2">{label}</p>
              <p className="text-[#6B7670] text-[14px] leading-relaxed">{desc}</p>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  )
}
