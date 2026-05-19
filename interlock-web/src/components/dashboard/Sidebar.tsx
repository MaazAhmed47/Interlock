import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard, GitBranch, ScrollText, Wrench,
  Server, ShieldCheck, Lock, Settings, Shield,
} from 'lucide-react'

const NAV = [
  { to: '/dashboard/overview',   icon: LayoutDashboard, label: 'Overview'     },
  { to: '/dashboard/drift',      icon: GitBranch,       label: 'Drift Review' },
  { to: '/dashboard/audit',      icon: ScrollText,      label: 'Audit Log'    },
  { to: '/dashboard/tools',      icon: Wrench,          label: 'Tools'        },
  { to: '/dashboard/servers',    icon: Server,          label: 'Servers'      },
  { to: '/dashboard/policies',   icon: ShieldCheck,     label: 'Policies'     },
  { to: '/dashboard/quarantine', icon: Lock,            label: 'Quarantine'   },
  { to: '/dashboard/settings',   icon: Settings,        label: 'Settings'     },
]

export function Sidebar() {
  return (
    <aside className="fixed left-0 top-0 h-screen w-[224px] bg-[#101412] border-r border-[#27302B] flex flex-col z-40">
      {/* Logo */}
      <div className="flex items-center gap-3 px-5 h-[68px] border-b border-[#27302B] shrink-0">
        <div className="w-8 h-8 rounded-md bg-[#10B981] flex items-center justify-center shrink-0">
          <Shield size={16} className="text-[#080A09]" />
        </div>
        <span className="font-semibold text-[#F4F7F5] text-[15px] tracking-tight">Interlock</span>
      </div>

      {/* Nav */}
      <nav className="flex-1 py-4 px-2 overflow-y-auto">
        <p className="text-[11px] font-mono font-semibold text-[#6B7670] tracking-widest px-3 mb-2.5 uppercase select-none">
          Console
        </p>
        {NAV.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              'flex items-center gap-3 px-3 py-2.5 rounded text-[14px] transition-all duration-100 mb-0.5 border-l-2 ' +
              (isActive
                ? 'text-[#10B981] bg-[rgba(16,185,129,0.08)] border-[#10B981]'
                : 'text-[#9CA8A2] hover:text-[#F4F7F5] hover:bg-[#161B18] border-transparent')
            }
          >
            <Icon size={16} className="shrink-0" />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div className="px-5 py-3.5 border-t border-[#27302B] shrink-0">
        <span className="text-[12px] font-mono text-[#6B7670]">v0.1.0 · Interlock</span>
      </div>
    </aside>
  )
}
