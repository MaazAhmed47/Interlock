import { RefreshCw, AlertCircle } from 'lucide-react'
import { isDemoMode } from '@/lib/interlockApi'

interface TopBarProps {
  title: string
  subtitle?: string
  onRefresh?: () => void
}

export function TopBar({ title, subtitle, onRefresh }: TopBarProps) {
  const demo = isDemoMode()
  return (
    <header className="sticky top-0 z-30 bg-[#101412]/95 backdrop-blur-sm border-b border-[#27302B] px-6 h-14 flex items-center justify-between shrink-0">
      <div>
        <h1 className="text-[#F4F7F5] text-sm font-semibold">{title}</h1>
        {subtitle && <p className="text-[#6B7670] text-xs font-mono mt-0.5">{subtitle}</p>}
      </div>
      <div className="flex items-center gap-3">
        {demo && (
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded border border-[rgba(214,162,58,0.3)] bg-[rgba(214,162,58,0.07)]">
            <AlertCircle size={11} className="text-[#D6A23A] shrink-0" />
            <span className="text-[#D6A23A] text-xs font-mono">Demo data</span>
          </div>
        )}
        {onRefresh && (
          <button
            onClick={onRefresh}
            className="w-7 h-7 flex items-center justify-center rounded border border-[#27302B] text-[#6B7670] hover:text-[#9CA8A2] hover:border-[#3a4a42] transition-colors"
            aria-label="Refresh"
          >
            <RefreshCw size={13} />
          </button>
        )}
      </div>
    </header>
  )
}
