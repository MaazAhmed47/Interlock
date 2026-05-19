import { Outlet } from 'react-router-dom'
import { Sidebar } from '@/components/dashboard/Sidebar'

export default function Dashboard() {
  return (
    <div className="flex min-h-screen bg-[#080A09]">
      <Sidebar />
      <div className="flex-1 ml-[220px] flex flex-col min-h-screen min-w-0">
        <Outlet />
      </div>
    </div>
  )
}
