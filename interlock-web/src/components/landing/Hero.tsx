import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { ArrowRight, GitBranch } from 'lucide-react'

const container = { hidden: {}, show: { transition: { staggerChildren: 0.1 } } }
const item = { hidden: { opacity: 0, y: 20 }, show: { opacity: 1, y: 0, transition: { duration: 0.5, ease: 'easeOut' as const } } }

const AGENTS  = ['Research Agent', 'Code Assistant', 'Finance Agent', 'Ops Agent']
const SERVERS = ['Slack MCP',  'Nextcloud', 'Finance DB', 'Shell Tools']

function ArchDiagram() {
  const cardH = 52
  const cardG = 10
  const totalH = AGENTS.length * (cardH + cardG) - cardG
  const centerYs = AGENTS.map((_, i) => i * (cardH + cardG) + cardH / 2)

  return (
    <div className="relative select-none font-mono text-xs" style={{ width: 520 }}>
      {/* Connection lines */}
      <svg className="absolute inset-0 w-full h-full pointer-events-none overflow-visible" style={{ height: totalH + 34 }}>
        {/* Agent → Gateway */}
        {centerYs.map((y, i) => (
          <line key={`ag${i}`} x1={152} y1={y + 34} x2={192} y2={y + 34}
            stroke="#10B981" strokeWidth={1} opacity={0.5} className="flow-line" style={{ animationDelay: `${i * 0.25}s` }} />
        ))}
        {/* Gateway → Servers (allowed: top 3) */}
        {centerYs.slice(0, 3).map((y, i) => (
          <line key={`rs${i}`} x1={360} y1={y + 34} x2={394} y2={y + 34}
            stroke="#10B981" strokeWidth={1} opacity={0.5} className="flow-line" style={{ animationDelay: `${i * 0.25 + 0.1}s` }} />
        ))}
        {/* Blocked (last server) */}
        <line x1={360} y1={centerYs[3] + 34} x2={394} y2={centerYs[3] + 34}
          stroke="#D86A4A" strokeWidth={1} strokeDasharray="4 3" opacity={0.55} />
      </svg>

      <div className="flex gap-0 items-start">
        {/* Agents */}
        <div style={{ width: 152, flexShrink: 0 }}>
          <p className="text-[#6B7670] tracking-widest uppercase text-[10px] mb-2 h-[34px] flex items-end">AI Agents</p>
          <div className="space-y-[10px]">
            {AGENTS.map(a => (
              <div key={a} style={{ height: cardH }} className="bg-[#101412] border border-[#27302B] rounded px-3 flex flex-col justify-center gap-1">
                <span className="text-[#F4F7F5] text-xs font-sans font-medium">{a}</span>
                <span className="flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-[#10B981] pulse" />
                  <span className="text-[#10B981] text-[10px]">Active</span>
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Gap */}
        <div style={{ width: 40, flexShrink: 0 }} />

        {/* Gateway */}
        <div style={{ width: 168, flexShrink: 0 }}>
          <p className="text-[#10B981] tracking-widest uppercase text-[10px] font-bold mb-2 h-[34px] flex items-end">Interlock Gateway</p>
          <div
            style={{ height: totalH }}
            className="border border-[#10B981]/30 rounded-lg bg-[#0D1210] flex flex-col justify-center px-3 py-3 gap-1.5 shadow-[0_0_24px_rgba(16,185,129,0.08)]"
          >
            {['Discover & Baseline', 'Metadata Normalize', 'Policy Enforce', 'Argument Scan', 'Audit Trail'].map(step => (
              <div key={step} className="flex items-center gap-2 text-[10px] text-[#9CA8A2]">
                <span className="w-1 h-1 rounded-full bg-[#10B981]/60 shrink-0" />
                {step}
              </div>
            ))}
          </div>
        </div>

        {/* Gap */}
        <div style={{ width: 34, flexShrink: 0 }} />

        {/* Servers */}
        <div style={{ width: 126, flexShrink: 0 }}>
          <p className="text-[#6B7670] tracking-widest uppercase text-[10px] mb-2 h-[34px] flex items-end">MCP Servers</p>
          <div className="space-y-[10px]">
            {SERVERS.map((s, i) => (
              <div key={s} style={{ height: cardH }} className="bg-[#101412] border border-[#27302B] rounded px-3 flex flex-col justify-center gap-1">
                <span className="text-[#F4F7F5] text-xs font-sans font-medium">{s}</span>
                {i < 3
                  ? <span className="text-[10px] text-[#10B981] font-mono">✓ ALLOWED</span>
                  : <span className="text-[10px] text-[#D86A4A] font-mono">✗ BLOCKED</span>}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

export default function Hero() {
  return (
    <section className="min-h-screen flex items-center pt-16 px-8">
      <div className="max-w-[1200px] mx-auto w-full grid grid-cols-1 lg:grid-cols-[55fr_45fr] gap-14 items-center py-16">
        {/* Left */}
        <motion.div variants={container} initial="hidden" animate="show" className="flex flex-col gap-7">
          <motion.div variants={item}>
            <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-[rgba(16,185,129,0.25)] bg-[rgba(16,185,129,0.08)] text-[#10B981] text-xs font-medium">
              <span className="w-1.5 h-1.5 rounded-full bg-[#10B981] pulse" />
              Runtime security gateway for AI agents
            </div>
          </motion.div>

          <motion.h1
            variants={item}
            className="font-bold leading-[1.05] text-[#F4F7F5]"
            style={{ fontSize: 'clamp(42px, 5.5vw, 72px)' }}
          >
            Control plane for<br />
            <span className="text-[#10B981]">MCP tool security</span>
          </motion.h1>

          <motion.p variants={item} className="text-[#9CA8A2] text-lg leading-relaxed max-w-[480px]">
            Interlock baselines every MCP tool, detects risky drift, enforces role-aware policy before execution, and records an audit trail for every agent decision.
          </motion.p>

          <motion.div variants={item} className="flex flex-wrap gap-3">
            <Link
              to="/dashboard/drift"
              className="inline-flex items-center gap-2 bg-[#10B981] hover:bg-[#059669] text-[#080A09] font-semibold text-sm px-5 py-2.5 rounded transition-colors"
            >
              Launch Security Console <ArrowRight size={15} />
            </Link>
            <Link
              to="/dashboard/drift"
              className="inline-flex items-center gap-2 border border-[#27302B] hover:border-[#10B981] text-[#9CA8A2] hover:text-[#10B981] font-medium text-sm px-5 py-2.5 rounded transition-colors"
            >
              <GitBranch size={15} /> Review Drift
            </Link>
          </motion.div>

          <motion.div variants={item} className="flex flex-wrap gap-x-6 gap-y-2">
            {['Zero-Trust by Default', 'Verify Every Tool Call', 'Full Audit Trail', 'Self-Hosted'].map(t => (
              <span key={t} className="text-[#6B7670] text-xs font-mono">{t}</span>
            ))}
          </motion.div>
        </motion.div>

        {/* Right — Architecture */}
        <motion.div
          initial={{ opacity: 0, x: 32 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.6, delay: 0.3, ease: 'easeOut' }}
          className="flex justify-center overflow-x-auto"
        >
          <ArchDiagram />
        </motion.div>
      </div>
    </section>
  )
}
