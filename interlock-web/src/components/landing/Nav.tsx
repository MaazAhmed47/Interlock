import { useState, useEffect } from 'react'

const LINKS = [
  { label: 'Platform',     href: '#platform' },
  { label: 'How It Works', href: '#how-it-works' },
  { label: 'Pricing',      href: '#pricing' },
  { label: 'GitHub',       href: 'https://github.com/MaazAhmed47/Interlock', external: true },
] as const

export default function Nav() {
  const [scrolled, setScrolled] = useState(false)

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 80)
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  return (
    <nav style={{
      position: 'fixed', top: 0, left: 0, right: 0,
      height: 64,
      background: scrolled ? '#0B0F0E' : 'rgba(11,15,14,0.92)',
      backdropFilter: 'blur(20px)',
      WebkitBackdropFilter: 'blur(20px)',
      borderBottom: '1px solid var(--bd)',
      zIndex: 100,
      transition: 'background 200ms ease',
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      padding: '0 40px',
    }}>

      {/* ── Logo ── */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
        <div style={{
          width: 28, height: 28,
          background: 'var(--ac)', borderRadius: 6,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <svg width="15" height="15" viewBox="0 0 15 15" fill="none">
            {/* shackle */}
            <path d="M4.5 6.5V4a3 3 0 0 1 6 0v2.5" stroke="white" strokeWidth="1.5" strokeLinecap="round" fill="none"/>
            {/* body */}
            <rect x="2.5" y="6.5" width="10" height="7" rx="1.5" fill="white" opacity="0.95"/>
            {/* keyhole */}
            <circle cx="7.5" cy="10" r="1.3" fill="#1D9E75"/>
            <rect x="7" y="11" width="1" height="1.8" rx="0.4" fill="#1D9E75"/>
          </svg>
        </div>
        <span style={{
          fontFamily: "'Bebas Neue', sans-serif", fontWeight: 400,
          fontSize: 16, letterSpacing: '0.12em', color: 'var(--tx)',
        }}>INTERLOCK</span>
      </div>

      {/* ── Center links ── */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 32 }}>
        {LINKS.map(link => (
          <NavLink
            key={link.label}
            href={link.href}
            external={'external' in link ? link.external : false}
          >
            {link.label}
          </NavLink>
        ))}
      </div>

      {/* ── Right buttons ── */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
        <GhostButton>Sign in</GhostButton>
        <PilotButton>Apply for Pilot →</PilotButton>
      </div>
    </nav>
  )
}

function NavLink({ href, external, children }: {
  href: string
  external?: boolean
  children: string
}) {
  return (
    <a
      href={href}
      target={external ? '_blank' : undefined}
      rel={external ? 'noopener noreferrer' : undefined}
      style={{
        fontFamily: "'Inter', sans-serif", fontWeight: 500, fontSize: 14,
        color: 'var(--t2)', textDecoration: 'none',
        transition: 'color 150ms ease',
      }}
      onMouseEnter={e => (e.currentTarget.style.color = 'var(--tx)')}
      onMouseLeave={e => (e.currentTarget.style.color = 'var(--t2)')}
    >
      {children}
    </a>
  )
}

function GhostButton({ children }: { children: string }) {
  return (
    <button
      style={{
        background: 'transparent',
        border: '1px solid var(--bd2)', color: 'var(--t2)',
        fontFamily: "'Inter', sans-serif", fontWeight: 600, fontSize: 13,
        padding: '7px 16px', borderRadius: 6, cursor: 'pointer',
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
    >{children}</button>
  )
}

function PilotButton({ children }: { children: string }) {
  return (
    <button
      style={{
        background: 'var(--ac)', border: 'none',
        color: 'white',
        fontFamily: "'Inter', sans-serif", fontWeight: 600, fontSize: 13,
        padding: '7px 18px', borderRadius: 6, cursor: 'pointer',
        transition: 'background 150ms ease',
      }}
      onMouseEnter={e => (e.currentTarget.style.background = 'var(--acd)')}
      onMouseLeave={e => (e.currentTarget.style.background = 'var(--ac)')}
    >{children}</button>
  )
}
