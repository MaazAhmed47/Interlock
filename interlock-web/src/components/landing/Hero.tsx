import { motion } from 'framer-motion'

const container = {
  hidden: {},
  show: { transition: { staggerChildren: 0.08 } },
}

const item = {
  hidden: { opacity: 0, y: 24 },
  show: { opacity: 1, y: 0, transition: { duration: 0.5, ease: [0.16, 1, 0.3, 1] } },
}

// ─── Architecture Diagram ─────────────────────────────────────────────────

const AGENTS = [
  { name: 'Research Agent', model: 'GPT-4o' },
  { name: 'Code Assistant', model: 'Claude 3.5' },
  { name: 'Data Analyst',   model: 'Gemini 1.5' },
  { name: 'Ops Agent',      model: 'Custom LLM' },
]

const RESOURCES = [
  { name: 'MCP Servers',  allowed: true  },
  { name: 'Databases',    allowed: true  },
  { name: 'Shell / Code', allowed: false },
  { name: 'Unknown Dest', allowed: false },
]

const GATEWAY_ROWS = [
  { icon: '🔍', label: 'Verify Identity' },
  { icon: '🎯', label: 'Check Intent'    },
  { icon: '⚖️', label: 'Enforce Policy'  },
  { icon: '📡', label: 'Monitor Runtime' },
  { icon: '📋', label: 'Log & Audit'     },
]

const COL_W  = { left: 144, center: 160, right: 132 } as const
const GAP    = 32
const HDR_H  = 34
const CARD_H = 60
const CARD_G = 10

const X = {
  agentRight: COL_W.left,
  gwLeft:     COL_W.left + GAP,
  gwRight:    COL_W.left + GAP + COL_W.center,
  resLeft:    COL_W.left + GAP + COL_W.center + GAP,
} as const

function cardCenterY(i: number) {
  return HDR_H + i * (CARD_H + CARD_G) + CARD_H / 2
}

const YS      = [0, 1, 2, 3].map(cardCenterY)
const TOTAL_W = COL_W.left + GAP + COL_W.center + GAP + COL_W.right
const GW_H    = 4 * CARD_H + 3 * CARD_G

function ArchDiagram() {
  return (
    <div style={{ position: 'relative', width: TOTAL_W, userSelect: 'none' }}>

      {/* SVG overlay — connection lines */}
      <svg
        style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', pointerEvents: 'none', overflow: 'visible' }}
        aria-hidden="true"
      >
        {/* Agent → Gateway (green flowing dashes) */}
        {YS.map((y, i) => (
          <line key={`ag-${i}`}
            x1={X.agentRight} y1={y} x2={X.gwLeft} y2={y}
            stroke="#0D8560" strokeWidth={1} opacity={0.65}
            className="flow-line"
            style={{ animationDelay: `${i * 0.3}s` }}
          />
        ))}

        {/* Gateway → Resources: ALLOWED (green flowing dashes) */}
        {[0, 1].map(i => (
          <line key={`res-ok-${i}`}
            x1={X.gwRight} y1={YS[i]} x2={X.resLeft} y2={YS[i]}
            stroke="#0D8560" strokeWidth={1} opacity={0.65}
            className="flow-line"
            style={{ animationDelay: `${i * 0.3 + 0.15}s` }}
          />
        ))}

        {/* Gateway → Resources: BLOCKED (red static dashed) */}
        {[2, 3].map(i => (
          <line key={`res-blk-${i}`}
            x1={X.gwRight} y1={YS[i]} x2={X.resLeft} y2={YS[i]}
            stroke="#EF4444" strokeWidth={1} strokeDasharray="4 3" opacity={0.6}
          />
        ))}
      </svg>

      {/* Three columns */}
      <div style={{ display: 'flex', gap: GAP }}>

        {/* Col 1: AI Agents */}
        <div style={{ width: COL_W.left, flexShrink: 0 }}>
          <ColHeader>AI AGENTS</ColHeader>
          <div style={{ display: 'flex', flexDirection: 'column', gap: CARD_G }}>
            {AGENTS.map(a => <AgentCard key={a.name} name={a.name} model={a.model} />)}
          </div>
        </div>

        {/* Col 2: Gateway */}
        <div style={{ width: COL_W.center, flexShrink: 0 }}>
          <ColHeader accent>INTERLOCK GATEWAY</ColHeader>
          <div style={{
            height: GW_H,
            border: '1.5px solid var(--ac)',
            borderRadius: 10,
            background: 'var(--s2)',
            boxShadow: '0 0 30px rgba(11,110,79,0.18)',
            display: 'flex', flexDirection: 'column',
            justifyContent: 'center', gap: 2,
            padding: '18px 16px',
          }}>
            {GATEWAY_ROWS.map(row => (
              <div key={row.label} style={{
                display: 'flex', alignItems: 'center', gap: 7,
                fontFamily: "'Inter', sans-serif", fontSize: 12, fontWeight: 500,
                color: 'var(--t2)', padding: '5px 0',
              }}>
                <span style={{ fontSize: 12 }}>{row.icon}</span>
                <span>{row.label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Col 3: Resources */}
        <div style={{ width: COL_W.right, flexShrink: 0 }}>
          <ColHeader>RESOURCES</ColHeader>
          <div style={{ display: 'flex', flexDirection: 'column', gap: CARD_G }}>
            {RESOURCES.map(r => <ResourceCard key={r.name} name={r.name} allowed={r.allowed} />)}
          </div>
        </div>
      </div>

      {/* Legend */}
      <div style={{
        marginTop: 10, textAlign: 'right',
        fontFamily: "'JetBrains Mono', monospace", fontSize: 11,
        color: 'var(--t3)',
      }}>
        <span style={{ color: '#0D8560' }}>━━</span> Allowed &nbsp;
        <span style={{ color: '#EF4444' }}>╌╌</span> Blocked
      </div>
    </div>
  )
}

function ColHeader({ children, accent }: { children: string; accent?: boolean }) {
  return (
    <div style={{
      height: HDR_H, display: 'flex', alignItems: 'center',
      fontFamily: "'JetBrains Mono', monospace",
      fontSize: accent ? 12 : 11,
      fontWeight: accent ? 700 : 600,
      letterSpacing: accent ? '0.1em' : '0.15em',
      color: 'var(--t2)',
    }}>
      {children}
    </div>
  )
}

function AgentCard({ name, model }: { name: string; model: string }) {
  return (
    <div style={{
      height: CARD_H,
      background: 'var(--s2)', border: '1px solid var(--bd)',
      borderRadius: 8, padding: '12px 16px',
      display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 4,
    }}>
      <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, fontWeight: 600, color: 'var(--tx)' }}>
        {name}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <PulsingDot />
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: 'var(--t3)' }}>
          {model}
        </span>
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: 'var(--ac)', marginLeft: 'auto' }}>
          Active
        </span>
      </div>
    </div>
  )
}

function ResourceCard({ name, allowed }: { name: string; allowed: boolean }) {
  return (
    <div style={{
      height: CARD_H,
      background: 'var(--s2)', border: `1px solid ${allowed ? 'var(--bd)' : 'rgba(239,68,68,0.2)'}`,
      borderRadius: 8, padding: '8px 10px',
      display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 5,
    }}>
      <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, fontWeight: 600, color: 'var(--tx)' }}>
        {name}
      </div>
      <div style={{
        display: 'inline-flex', alignItems: 'center', gap: 4,
        background: allowed ? 'var(--acs)' : 'var(--rds)',
        borderRadius: 4, padding: '2px 6px',
        fontFamily: "'JetBrains Mono', monospace", fontSize: 11, fontWeight: 700,
        color: allowed ? 'var(--ac)' : 'var(--rd)',
        alignSelf: 'flex-start',
      }}>
        {allowed ? '✓ ALLOWED' : '✗ BLOCKED'}
      </div>
    </div>
  )
}

function PulsingDot() {
  return (
    <span className="pulse" style={{
      display: 'block', width: 6, height: 6,
      borderRadius: '50%', background: 'var(--ac)', flexShrink: 0,
    }} />
  )
}

// ─── Trust badges ─────────────────────────────────────────────────────────

const TRUST_ITEMS = [
  'Zero-Trust by Default',
  'Verify Every Action',
  'Runtime Enforcement',
  'Full Audit Trail',
]

// ─── Hero ─────────────────────────────────────────────────────────────────

export default function Hero() {
  return (
    <section style={{
      minHeight: '100vh',
      display: 'flex', alignItems: 'center',
      padding: '80px 5%',
    }}>
      <div style={{
        display: 'grid',
        gridTemplateColumns: '55fr 45fr',
        gap: 56,
        width: '100%', maxWidth: 1280,
        margin: '0 auto',
        alignItems: 'center',
      }}>

        {/* ── Left column ── */}
        <motion.div
          variants={container}
          initial="hidden"
          animate="show"
          style={{ display: 'flex', flexDirection: 'column', gap: 28 }}
        >

          {/* Badge */}
          <motion.div variants={item}>
            <div style={{
              display: 'inline-flex', alignItems: 'center', gap: 8,
              background: 'var(--acs)', border: '1px solid var(--acb2)',
              color: 'var(--ac)',
              fontFamily: "'Inter', sans-serif", fontWeight: 500, fontSize: 11,
              letterSpacing: '0.12em', textTransform: 'uppercase',
              borderRadius: 20, padding: '5px 14px',
            }}>
              <PulsingDot />
              Zero-Trust Runtime Security for AI Agents
            </div>
          </motion.div>

          {/* Headline */}
          <motion.h1 variants={item} style={{
            fontFamily: "'Bebas Neue', sans-serif",
            fontSize: 'clamp(56px, 7vw, 96px)',
            lineHeight: '1.0', letterSpacing: '0.02em',
            fontWeight: 400, color: 'var(--tx)', textTransform: 'uppercase',
            margin: 0,
          }}>
            <span style={{ display: 'block' }}>Secure AI Agents</span>
            <span style={{ display: 'block', color: 'var(--ac)' }}>Before They Touch</span>
            <span style={{ display: 'block' }}>Your Infrastructure</span>
          </motion.h1>

          {/* Subheading */}
          <motion.p variants={item} style={{
            fontFamily: "'Inter', sans-serif",
            fontSize: '17px', fontWeight: 400,
            color: 'var(--t2)', maxWidth: 480, lineHeight: '1.8',
            margin: 0,
          }}>
            Interlock is the zero-trust runtime security layer for AI agents.
            We enforce least privilege, verify every action, and stop threats
            in real time — before your agents become your attackers.
          </motion.p>

          {/* CTAs */}
          <motion.div variants={item}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                <HeroPilotButton />
                <HeroDemoButton />
              </div>
              <span style={{
                fontFamily: "'JetBrains Mono', monospace", fontSize: 11,
                color: 'var(--t3)',
              }}>
                Free 90-day pilot · No credit card · 2 slots remaining
              </span>
            </div>
          </motion.div>

          {/* Trust badges */}
          <motion.div variants={item}>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px 24px' }}>
              {TRUST_ITEMS.map(label => (
                <span key={label} style={{
                  fontFamily: "'Inter', sans-serif", fontSize: 13, fontWeight: 500,
                  color: 'var(--t2)',
                }}>
                  {label}
                </span>
              ))}
            </div>
          </motion.div>

        </motion.div>

        {/* ── Right column: Architecture Diagram ── */}
        <motion.div
          initial={{ opacity: 0, x: 40 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.6, delay: 0.3, ease: [0.16, 1, 0.3, 1] }}
          style={{ display: 'flex', justifyContent: 'center', overflow: 'auto' }}
        >
          <ArchDiagram />
        </motion.div>

      </div>
    </section>
  )
}

function HeroPilotButton() {
  return (
    <button
      style={{
        background: 'var(--ac)', border: 'none',
        color: 'white',
        fontFamily: "'Inter', sans-serif", fontWeight: 600, fontSize: 14,
        padding: '13px 28px', borderRadius: 8, cursor: 'pointer',
        transition: 'background 150ms ease',
      }}
      onMouseEnter={e => (e.currentTarget.style.background = 'var(--acd)')}
      onMouseLeave={e => (e.currentTarget.style.background = 'var(--ac)')}
    >
      Apply for Pilot →
    </button>
  )
}

function HeroDemoButton() {
  return (
    <button
      style={{
        background: 'transparent',
        border: '1px solid var(--bd2)', color: 'var(--t2)',
        fontFamily: "'Inter', sans-serif", fontWeight: 500, fontSize: 14,
        padding: '12px 24px', borderRadius: 8, cursor: 'pointer',
        transition: 'color 150ms, border-color 150ms',
      }}
      onMouseEnter={e => {
        e.currentTarget.style.color = 'var(--tx)'
        e.currentTarget.style.borderColor = 'var(--bd3)'
      }}
      onMouseLeave={e => {
        e.currentTarget.style.color = 'var(--t2)'
        e.currentTarget.style.borderColor = 'var(--bd2)'
      }}
    >
      Watch Demo ▶
    </button>
  )
}
