import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { Shield } from 'lucide-react'

const LINKS = [
  { label: 'How It Works', href: '#how-it-works' },
  { label: 'Capabilities',  href: '#capabilities'  },
  { label: 'Architecture',  href: '#architecture'  },
]

export default function Nav() {
  const [scrolled, setScrolled] = useState(false)

  useEffect(() => {
    const fn = () => setScrolled(window.scrollY > 60)
    window.addEventListener('scroll', fn, { passive: true })
    return () => window.removeEventListener('scroll', fn)
  }, [])

  return (
    <nav className={`fixed top-0 left-0 right-0 z-50 h-16 flex items-center justify-between px-8 transition-all duration-200 border-b ${
      scrolled ? 'bg-[#080A09] border-[#27302B]' : 'bg-[rgba(8,10,9,0.85)] backdrop-blur-xl border-transparent'
    }`}>
      <div className="flex items-center gap-2.5">
        <div className="w-7 h-7 rounded-md bg-[#10B981] flex items-center justify-center">
          <Shield size={14} className="text-[#080A09]" />
        </div>
        <span className="font-semibold text-[#F4F7F5] text-sm tracking-tight">Interlock</span>
      </div>

      <div className="hidden md:flex items-center gap-8">
        {LINKS.map(l => (
          <a
            key={l.label}
            href={l.href}
            className="text-[#9CA8A2] hover:text-[#F4F7F5] transition-colors text-sm font-medium"
          >
            {l.label}
          </a>
        ))}
      </div>

      <Link
        to="/dashboard/drift"
        className="bg-[#10B981] hover:bg-[#059669] text-[#080A09] font-semibold text-sm px-4 py-2 rounded transition-colors"
      >
        Launch Security Console
      </Link>
    </nav>
  )
}
