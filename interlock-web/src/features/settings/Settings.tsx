import { useState } from 'react'
import { Save, CheckCircle2 } from 'lucide-react'
import { TopBar } from '@/components/dashboard/TopBar'
import { Button } from '@/components/ui/Button'
import { isDemoMode } from '@/lib/interlockApi'

export default function SettingsPage() {
  const [apiUrl, setApiUrl] = useState(
    () => localStorage.getItem('interlock_api_url') || import.meta.env.VITE_INTERLOCK_API_URL || 'http://localhost:8001'
  )
  const [apiKey, setApiKey] = useState(
    () => localStorage.getItem('interlock_api_key') || ''
  )
  const [saved, setSaved] = useState(false)

  function handleSave() {
    localStorage.setItem('interlock_api_url', apiUrl)
    if (apiKey) localStorage.setItem('interlock_api_key', apiKey)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  return (
    <div className="flex flex-col flex-1 min-h-0">
      <TopBar title="Settings" subtitle="API connection and preferences" />
      <div className="flex-1 overflow-auto p-6">
        <div className="max-w-lg space-y-6">
          {isDemoMode() && (
            <div className="flex items-center gap-2 p-3 rounded border border-[rgba(214,162,58,0.3)] bg-[rgba(214,162,58,0.07)] text-xs text-[#D6A23A] font-mono">
              Demo mode active — configure API URL and key to connect to a live Interlock instance.
            </div>
          )}

          <div>
            <label className="block text-xs font-mono text-[#9CA8A2] mb-1.5">API Base URL</label>
            <input
              value={apiUrl}
              onChange={e => setApiUrl(e.target.value)}
              className="w-full bg-[#101412] border border-[#27302B] text-[#F4F7F5] text-sm px-3 py-2 rounded focus:outline-none focus:border-[#10B981] font-mono placeholder:text-[#6B7670]"
              placeholder="http://localhost:8001"
            />
            <p className="text-[#6B7670] text-xs mt-1">The Interlock gateway base URL. Overrides VITE_INTERLOCK_API_URL.</p>
          </div>

          <div>
            <label className="block text-xs font-mono text-[#9CA8A2] mb-1.5">API Key</label>
            <input
              value={apiKey}
              onChange={e => setApiKey(e.target.value)}
              type="password"
              className="w-full bg-[#101412] border border-[#27302B] text-[#F4F7F5] text-sm px-3 py-2 rounded focus:outline-none focus:border-[#10B981] font-mono placeholder:text-[#6B7670]"
              placeholder="lf-…"
            />
            <p className="text-[#6B7670] text-xs mt-1">Sent as X-API-Key header. Stored in localStorage.</p>
          </div>

          <Button onClick={handleSave} variant="primary">
            {saved ? <><CheckCircle2 size={14} /> Saved</> : <><Save size={14} /> Save Settings</>}
          </Button>
        </div>
      </div>
    </div>
  )
}
