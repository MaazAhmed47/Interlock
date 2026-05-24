import { useState, useEffect } from 'react'
import { Save } from 'lucide-react'
import { API_URL_KEY, API_KEY_KEY, DEFAULT_API_URL, api } from '../api'
import ErrorCard from '../components/ErrorCard'
import { useDashboardData } from '../components/DashLayout'

export default function Settings() {
  const [url, setUrl] = useState(localStorage.getItem(API_URL_KEY) || DEFAULT_API_URL)
  const [key, setKey] = useState(localStorage.getItem(API_KEY_KEY) || '')
  const [saved, setSaved] = useState(false)
  const [siemProviders, setSiemProviders] = useState<string[]>([])
  const [siemError, setSiemError] = useState('')
  const { refreshAll } = useDashboardData()

  function save() {
    localStorage.setItem(API_URL_KEY, url.trim() || DEFAULT_API_URL)
    if (key.trim()) {
      localStorage.setItem(API_KEY_KEY, key.trim())
    } else {
      localStorage.removeItem(API_KEY_KEY)
    }
    setSaved(true)
    void refreshAll()
    setTimeout(() => setSaved(false), 2500)
  }

  function loadSiem() {
    setSiemError('')
    api.siemProviders()
      .then(d => setSiemProviders(d.providers))
      .catch(e => setSiemError((e as Error).message))
  }

  useEffect(() => {
    if (localStorage.getItem(API_KEY_KEY)) loadSiem()
  }, [])

  const storedKey = localStorage.getItem(API_KEY_KEY) || ''
  const fingerprint = storedKey ? `...${storedKey.slice(-6)}` : null

  return (
    <div className="dash-main">
      <div className="dash-page-header">
        <div><h1>Settings</h1><p>API connection and key configuration</p></div>
      </div>

      <div className="settings-section">
        <div className="settings-section-title">Connection</div>
        <div className="form-group">
          <label className="form-label">API Base URL</label>
          <input className="form-input" value={url} onChange={e => setUrl(e.target.value)} placeholder={DEFAULT_API_URL} />
          <div className="form-hint">Default: {DEFAULT_API_URL}</div>
        </div>
        <div className="form-group">
          <label className="form-label">API Key</label>
          <input className="form-input" type="password" value={key} onChange={e => setKey(e.target.value)} placeholder="API key" autoComplete="off" />
          {fingerprint && <div className="key-fingerprint">Active key: {fingerprint}</div>}
          <div className="form-hint">Stored in browser localStorage only. Never sent to any third party.</div>
        </div>
        <button className="btn btn-primary" onClick={save}>
          <Save size={13} />{saved ? 'Saved!' : 'Save Settings'}
        </button>
      </div>

      {storedKey && (
        <div className="settings-section">
          <div className="settings-section-title">SIEM Integrations</div>
          {siemError
            ? <ErrorCard message={siemError} onRetry={loadSiem} />
            : <>
                <p style={{ fontSize: 13, color: 'var(--dim)', marginBottom: 12 }}>
                  Supported export destinations. Configure per-key via the admin API.
                </p>
                <div className="siem-providers-list">
                  {siemProviders.map(p => <span key={p} className="siem-chip">{p}</span>)}
                </div>
              </>
          }
        </div>
      )}
    </div>
  )
}
