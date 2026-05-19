import { useRef } from 'react'
import { motion, useInView } from 'framer-motion'
import { Database, ShieldCheck, GitBranch, Lock, ScanLine, ScrollText } from 'lucide-react'

const CAPS = [
  { icon: Database,    title: 'Tool Metadata Normalization',     desc: 'Normalize effects, data classes, and side effects across every registered MCP tool.' },
  { icon: ShieldCheck, title: 'Runtime Policy Enforcement',      desc: 'Role-aware RBAC evaluated before every tool call — not after.' },
  { icon: GitBranch,   title: 'Drift Detection',                 desc: 'Detect when a tool\'s schema, effects, or data access expands beyond its baseline.' },
  { icon: Lock,        title: 'Quarantine & Approval Workflow',  desc: 'High-risk drift is auto-quarantined. Operators approve or reject each change with a reason.' },
  { icon: ScanLine,    title: 'Argument & Response Scanning',    desc: 'Scan tool arguments and responses for injection, PII, and sensitive data exfiltration.' },
  { icon: ScrollText,  title: 'Centralized Audit Logs',          desc: 'Every decision — allow, deny, monitor, quarantine — is recorded with role, rule, and reason.' },
]

export default function Features() {
  const ref = useRef<HTMLElement>(null)
  const inView = useInView(ref, { once: true, margin: '-80px' })

  return (
    <section ref={ref} id="capabilities" className="py-20 px-6 border-t border-[#27302B]">
      <div className="max-w-[1280px] mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          className="mb-12"
        >
          <p className="text-[#10B981] text-[13px] font-mono tracking-widest uppercase mb-3">Capabilities</p>
          <h2 className="text-[#F4F7F5] font-bold text-3xl md:text-[2.5rem]">Everything a security team needs</h2>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {CAPS.map(({ icon: Icon, title, desc }, i) => (
            <motion.div
              key={title}
              initial={{ opacity: 0, y: 14 }}
              animate={inView ? { opacity: 1, y: 0 } : {}}
              transition={{ delay: 0.07 * i, duration: 0.4 }}
              className="p-6 bg-[#101412] border border-[#27302B] rounded-lg hover:border-[#3a4a42] transition-colors"
            >
              <Icon size={20} className="text-[#10B981] mb-4" />
              <h3 className="text-[#F4F7F5] text-[15px] font-semibold mb-2">{title}</h3>
              <p className="text-[#6B7670] text-[14px] leading-relaxed">{desc}</p>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  )
}
