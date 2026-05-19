import { Shield } from 'lucide-react'

export default function Footer() {
  return (
    <footer className="border-t border-[#27302B] py-10 px-8">
      <div className="max-w-[1100px] mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-2.5">
          <div className="w-6 h-6 rounded-md bg-[#10B981] flex items-center justify-center">
            <Shield size={12} className="text-[#080A09]" />
          </div>
          <span className="text-[#F4F7F5] text-sm font-semibold">Interlock</span>
          <span className="text-[#6B7670] text-xs font-mono">— Runtime security gateway for AI agents</span>
        </div>
        <p className="text-[#6B7670] text-xs font-mono">© 2026 Interlock. All rights reserved.</p>
      </div>
    </footer>
  )
}
