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
    <nav className={`fixed top-0 left-0 right-0 z-50 h-[68px] flex items-center transition-all duration-200 border-b ${
      scrolled ? 'bg-[#080A09] border-[#27302B]' : 'bg-[rgba(8,10,9,0.88)] backdrop-blur-xl border-transparent'
    }`}>
      <div className="max-w-[1280px] mx-auto w-full flex items-center justify-between px-6">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-md bg-[#10B981] flex items-center justify-center shrink-0">
            <Shield size={16} className="text-[#080A09]" />
          </div>
          <span className="font-semibold text-[#F4F7F5] text-[15px] tracking-tight">Interlock</span>
        </div>

        <div className="hidden md:flex items-center gap-7">
          {LINKS.map(l => (
            <a
              key={l.label}
              href={l.href}
              className="text-[#9CA8A2] hover:text-[#F4F7F5] transition-colors text-[14px] font-medium"
            >
              {l.label}
            </a>
          ))}
        </div>

        <Link
          to="/dashboard/drift"
          className="bg-[#10B981] hover:bg-[#059669] text-[#080A09] font-semibold text-[14px] px-5 py-2.5 rounded transition-colors whitespace-nowrap"
        >
          Launch Security Console
        </Link>
      </div>
    </nav>
  )
}
