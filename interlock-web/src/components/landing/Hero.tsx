import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { ArrowRight, GitBranch } from 'lucide-react'

const container = { hidden: {}, show: { transition: { staggerChildren: 0.1 } } }
const item = { hidden: { opacity: 0, y: 20 }, show: { opacity: 1, y: 0, transition: { duration: 0.5, ease: 'easeOut' as const } } }

const AGENTS  = ['Research Agent', 'Code Assistant', 'Finance Agent', 'Ops Agent']
const SERVERS = ['Slack MCP', 'Nextcloud', 'Finance DB', 'Shell Tools']

// Column widths
const agentW = 176
const gwGap  = 44
const gwW    = 188
const srvGap = 40
const srvW   = 152
const totalW = agentW + gwGap + gwW + srvGap + srvW  // 600

function ArchDiagram() {
  const cardH   = 64
  const cardG   = 12
  const headerH = 40
  const totalH  = AGENTS.length * (cardH + cardG) - cardG

  // vertical center of each card (relative to the cards block start, i.e. below header)
  const centerYs = AGENTS.map((_, i) => i * (cardH + cardG) + cardH / 2)

  // SVG x-coordinates for connector lines
  const agentRight = agentW
  const gwLeft     = agentW + gwGap
  const gwRight    = gwLeft + gwW
  const srvLeft    = gwRight + srvGap

  return (
    <div className="relative select-none" style={{ width: totalW }}>
      {/* Connection lines */}
      <svg
        className="absolute inset-0 pointer-events-none overflow-visible"
        style={{ width: totalW, height: totalH + headerH + 8 }}
      >
        {centerYs.map((y, i) => (
          <line
            key={`ag${i}`}
            x1={agentRight} y1={y + headerH}
            x2={gwLeft}     y2={y + headerH}
            stroke="#10B981" strokeWidth={1} opacity={0.5}
            className="flow-line"
            style={{ animationDelay: `${i * 0.25}s` }}
          />
        ))}
        {centerYs.slice(0, 3).map((y, i) => (
          <line
            key={`rs${i}`}
            x1={gwRight} y1={y + headerH}
            x2={srvLeft} y2={y + headerH}
            stroke="#10B981" strokeWidth={1} opacity={0.5}
            className="flow-line"
            style={{ animationDelay: `${i * 0.25 + 0.1}s` }}
          />
        ))}
        <line
          x1={gwRight} y1={centerYs[3] + headerH}
          x2={srvLeft} y2={centerYs[3] + headerH}
          stroke="#D86A4A" strokeWidth={1} strokeDasharray="4 3" opacity={0.55}
        />
      </svg>

      <div className="flex items-start">
        {/* Agents */}
        <div style={{ width: agentW, flexShrink: 0 }}>
          <p
            className="text-[#6B7670] tracking-widest uppercase font-mono text-[11px] font-semibold mb-3 flex items-end"
            style={{ height: headerH }}
          >
            AI Agents
          </p>
          <div className="space-y-3">
            {AGENTS.map(a => (
              <div
                key={a}
                style={{ height: cardH }}
                className="bg-[#101412] border border-[#27302B] rounded-md px-3.5 flex flex-col justify-center gap-1.5"
              >
                <span className="text-[#F4F7F5] text-[13px] font-sans font-medium leading-tight">{a}</span>
                <span className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-[#10B981] pulse shrink-0" />
                  <span className="text-[#10B981] text-[11px] font-mono">Active</span>
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Gap */}
        <div style={{ width: gwGap, flexShrink: 0 }} />

        {/* Gateway */}
        <div style={{ width: gwW, flexShrink: 0 }}>
          <p
            className="text-[#10B981] tracking-widest uppercase font-mono text-[11px] font-bold mb-3 flex items-end"
            style={{ height: headerH }}
          >
            Interlock Gateway
          </p>
          <div
            style={{ height: totalH }}
            className="border border-[#10B981]/30 rounded-lg bg-[#0D1210] flex flex-col justify-center px-4 py-3 gap-2 shadow-[0_0_28px_rgba(16,185,129,0.07)]"
          >
            {['Discover & Baseline', 'Normalize Metadata', 'Policy Enforce', 'Argument Scan', 'Audit Trail'].map(step => (
              <div key={step} className="flex items-center gap-2 text-[12px] text-[#9CA8A2]">
                <span className="w-1.5 h-1.5 rounded-full bg-[#10B981]/60 shrink-0" />
                {step}
              </div>
            ))}
          </div>
        </div>

        {/* Gap */}
        <div style={{ width: srvGap, flexShrink: 0 }} />

        {/* Servers */}
        <div style={{ width: srvW, flexShrink: 0 }}>
          <p
            className="text-[#6B7670] tracking-widest uppercase font-mono text-[11px] font-semibold mb-3 flex items-end"
            style={{ height: headerH }}
          >
            MCP Servers
          </p>
          <div className="space-y-3">
            {SERVERS.map((s, i) => (
              <div
                key={s}
                style={{ height: cardH }}
                className="bg-[#101412] border border-[#27302B] rounded-md px-3.5 flex flex-col justify-center gap-1.5"
              >
                <span className="text-[#F4F7F5] text-[13px] font-sans font-medium leading-tight">{s}</span>
                {i < 3
                  ? <span className="text-[11px] text-[#10B981] font-mono">✓ ALLOWED</span>
                  : <span className="text-[11px] text-[#D86A4A] font-mono">✗ BLOCKED</span>
                }
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
    <section className="px-6 pb-16 pt-[68px]">
      <div
        className="max-w-[1280px] mx-auto w-full grid grid-cols-1 lg:grid-cols-[52fr_48fr] gap-14 items-center"
        style={{ minHeight: 'calc(100vh - 68px)' }}
      >
        {/* Left */}
        <motion.div variants={container} initial="hidden" animate="show" className="flex flex-col gap-7 py-12 lg:py-0">
          <motion.div variants={item}>
            <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full border border-[rgba(16,185,129,0.25)] bg-[rgba(16,185,129,0.08)] text-[#10B981] text-[13px] font-medium">
              <span className="w-1.5 h-1.5 rounded-full bg-[#10B981] pulse" />
              Runtime security gateway for AI agents
            </div>
          </motion.div>

          <motion.h1
            variants={item}
            className="font-bold leading-[1.05] text-[#F4F7F5]"
            style={{ fontSize: 'clamp(40px, 5vw, 68px)' }}
          >
            Control plane for<br />
            <span className="text-[#10B981]">MCP tool security</span>
          </motion.h1>

          <motion.p variants={item} className="text-[#9CA8A2] text-[17px] leading-relaxed max-w-[500px]">
            Interlock baselines every MCP tool, detects risky drift, enforces role-aware policy before execution, and records an audit trail for every agent decision.
          </motion.p>

          <motion.div variants={item} className="flex flex-wrap gap-3">
            <Link
              to="/dashboard/drift"
              className="inline-flex items-center gap-2 bg-[#10B981] hover:bg-[#059669] text-[#080A09] font-semibold text-[15px] px-6 py-3 rounded transition-colors"
            >
              Launch Security Console <ArrowRight size={16} />
            </Link>
            <Link
              to="/dashboard/drift"
              className="inline-flex items-center gap-2 border border-[#27302B] hover:border-[#10B981] text-[#9CA8A2] hover:text-[#10B981] font-medium text-[15px] px-6 py-3 rounded transition-colors"
            >
              <GitBranch size={16} /> Review Drift
            </Link>
          </motion.div>

          <motion.div variants={item} className="flex flex-wrap gap-x-7 gap-y-2">
            {['Zero-Trust by Default', 'Verify Every Tool Call', 'Full Audit Trail', 'Self-Hosted'].map(t => (
              <span key={t} className="text-[#6B7670] text-[13px] font-mono">{t}</span>
            ))}
          </motion.div>
        </motion.div>

        {/* Right — Architecture Diagram */}
        <motion.div
          initial={{ opacity: 0, x: 32 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.6, delay: 0.3, ease: 'easeOut' }}
          className="flex justify-center lg:justify-end overflow-x-auto py-8 lg:py-0"
        >
          <ArchDiagram />
        </motion.div>
      </div>
    </section>
  )
}
