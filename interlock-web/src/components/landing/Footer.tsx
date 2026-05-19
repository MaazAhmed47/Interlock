import { Shield } from 'lucide-react'

export default function Footer() {
  return (
    <footer className="border-t border-[#27302B] py-10 px-6">
      <div className="max-w-[1280px] mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-7 h-7 rounded-md bg-[#10B981] flex items-center justify-center">
            <Shield size={14} className="text-[#080A09]" />
          </div>
          <span className="text-[#F4F7F5] text-[15px] font-semibold">Interlock</span>
          <span className="text-[#6B7670] text-[13px] font-mono">— Runtime security gateway for AI agents</span>
        </div>
        <p className="text-[#6B7670] text-[13px] font-mono">© 2026 Interlock. All rights reserved.</p>
      </div>
    </footer>
  )
}
