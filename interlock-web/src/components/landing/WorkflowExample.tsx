import { useRef } from 'react'
import { motion, useInView } from 'framer-motion'
import { AlertTriangle, Lock, CheckCircle2, ScrollText } from 'lucide-react'

const STEPS = [
  { icon: AlertTriangle, color: '#D6A23A', label: 'Drift Detected',     detail: 'slack-mcp / export_channel gained external_sharing effect and PII data classes not present in baseline.' },
  { icon: Lock,          color: '#A78BFA', label: 'Auto-Quarantined',   detail: 'Tool quarantined immediately. Requests to export_channel return QUARANTINE_POLICY until operator reviews.' },
  { icon: CheckCircle2,  color: '#10B981', label: 'Operator Reviews',   detail: 'Security team sees the drift reason, confidence score, metadata diff, and affected roles in the console.' },
  { icon: ScrollText,    color: '#7AA2F7', label: 'Audit Trail Written', detail: 'Decision recorded: quarantine → operator review → approved or kept quarantined. Full context preserved.' },
]

export default function WorkflowExample() {
  const ref = useRef<HTMLElement>(null)
  const inView = useInView(ref, { once: true, margin: '-80px' })

  return (
    <section ref={ref} id="workflow" className="py-20 px-6 border-t border-[#27302B]">
      <div className="max-w-[1280px] mx-auto grid grid-cols-1 lg:grid-cols-2 gap-14 items-start">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
        >
          <p className="text-[#10B981] text-[13px] font-mono tracking-widest uppercase mb-3">Security Workflow</p>
          <h2 className="text-[#F4F7F5] font-bold text-3xl md:text-[2.5rem] leading-tight mb-4">
            From drift to decision<br />in under a second
          </h2>
          <p className="text-[#9CA8A2] text-[17px] leading-relaxed">
            A tool changes from read-only file access to external sharing. Interlock detects the drift, classifies it as high risk, quarantines the tool automatically, and records the full reason. The operator approves or keeps it quarantined — nothing reaches the MCP server until they decide.
          </p>
        </motion.div>

        <div className="space-y-3">
          {STEPS.map(({ icon: Icon, color, label, detail }, i) => (
            <motion.div
              key={label}
              initial={{ opacity: 0, x: 16 }}
              animate={inView ? { opacity: 1, x: 0 } : {}}
              transition={{ delay: 0.1 + i * 0.1, duration: 0.4 }}
              className="flex gap-4 p-5 bg-[#101412] border border-[#27302B] rounded-lg"
            >
              <div
                className="w-9 h-9 rounded-md flex items-center justify-center shrink-0 mt-0.5"
                style={{ background: `${color}18`, border: `1px solid ${color}30` }}
              >
                <Icon size={16} style={{ color }} />
              </div>
              <div>
                <p className="text-[#F4F7F5] text-[15px] font-semibold mb-1">{label}</p>
                <p className="text-[#6B7670] text-[13px] leading-relaxed font-mono">{detail}</p>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  )
}
