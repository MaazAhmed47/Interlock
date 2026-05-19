import { motion } from 'framer-motion'
import { useInView } from 'framer-motion'
import { useRef } from 'react'
import { AlertTriangle, Layers, Globe, Eye } from 'lucide-react'

const PROBLEMS = [
  { icon: Layers,         text: 'MCP servers expose dozens of tools with no shared baseline or validation.'      },
  { icon: Globe,          text: 'Agents call external services without operator visibility into what changed.'  },
  { icon: AlertTriangle,  text: 'Tool drift goes undetected until a breach, audit, or incident surfaces it.'    },
  { icon: Eye,            text: 'No centralized audit trail means you cannot prove what was allowed and why.'   },
]

export default function Problem() {
  const ref = useRef<HTMLElement>(null)
  const inView = useInView(ref, { once: true, margin: '-80px' })

  return (
    <section ref={ref} id="problem" className="py-24 px-8 border-t border-[#27302B]">
      <div className="max-w-[1100px] mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 24 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.5 }}
          className="max-w-2xl mb-12"
        >
          <p className="text-[#10B981] text-xs font-mono tracking-widest uppercase mb-3">The Problem</p>
          <h2 className="text-[#F4F7F5] font-bold text-3xl md:text-4xl leading-tight mb-4">
            MCP security is fragmented by design
          </h2>
          <p className="text-[#9CA8A2] text-base leading-relaxed">
            AI agents now call many MCP servers, but security policy is fragmented across tools, servers, and teams. There is no system of record for what each tool is allowed to do — or what it was doing last week.
          </p>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {PROBLEMS.map(({ icon: Icon, text }, i) => (
            <motion.div
              key={text}
              initial={{ opacity: 0, y: 16 }}
              animate={inView ? { opacity: 1, y: 0 } : {}}
              transition={{ duration: 0.4, delay: 0.1 + i * 0.08 }}
              className="flex gap-4 p-5 bg-[#101412] border border-[#27302B] rounded-lg"
            >
              <Icon size={18} className="text-[#D86A4A] shrink-0 mt-0.5" />
              <p className="text-[#9CA8A2] text-sm leading-relaxed">{text}</p>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  )
}
