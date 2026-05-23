import { useState } from 'react'
import { ScanLine } from 'lucide-react'
import { api, hasApiKey, ScanResult } from '../api'
import StatusBadge from '../components/StatusBadge'
import EmptyState from '../components/EmptyState'
import ErrorCard from '../components/ErrorCard'

function threatClass(level: string) {
  const l = level.toLowerCase()
  if (l === 'safe') return 'threat-safe'
  if (l === 'medium') return 'threat-medium'
  if (l === 'high') return 'threat-high'
  if (l === 'critical') return 'threat-critical'
  return ''
}

type ScanFn = (prompt: string) => Promise<ScanResult>

function ScanForm({ title, action }: { title: string; action: ScanFn }) {
  const [prompt, setPrompt] = useState('')
  const [result, setResult] = useState<ScanResult | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function run() {
    if (!prompt.trim()) return
    setLoading(true); setResult(null); setError('')
    try { setResult(await action(prompt)) }
    catch (e) { setError((e as Error).message) }
    finally { setLoading(false) }
  }

  const rows: [string, string | number | null | undefined][] = [
    ['Reason', result?.reason],
    ['Threat Type', result?.threat_type],
    ['Layer Caught', result?.layer_caught],
    ['Confidence', result?.confidence != null ? `${Math.round(result.confidence * 100)}%` : null],
    ['Risk Score', result?.risk_score != null ? String(result.risk_score) : null],
    ['Scan Time', result?.scan_time_ms != null ? `${result.scan_time_ms}ms` : null],
  ]

  return (
    <div className="card" style={{ flex: 1, minWidth: 280 }}>
      <div className="card-header"><div className="card-title">{title}</div></div>
      <div className="form-group">
        <textarea
          className="form-input"
          style={{ minHeight: 120 }}
          placeholder="Paste text to scan…"
          value={prompt}
          onChange={e => setPrompt(e.target.value)}
        />
      </div>
      <button className="btn btn-primary" onClick={run} disabled={loading || !prompt.trim()}>
        <ScanLine size={13} />{loading ? 'Scanning…' : 'Scan'}
      </button>

      {error && <ErrorCard message={error} />}

      {result && (
        <div className={`scan-result ${threatClass(result.threat_level)}`}>
          <div className="scan-result-header">
            <StatusBadge value={result.threat_level} />
            <span style={{ fontSize: 13, color: result.is_threat ? 'var(--red)' : 'var(--cyan)' }}>
              {result.is_threat ? 'Threat detected' : 'Clean'}
            </span>
          </div>
          {rows.filter(([, v]) => v != null && v !== '').map(([k, v]) => (
            <div key={k} className="scan-result-row">
              <div className="scan-result-key">{k}</div>
              <div className="scan-result-val">{v}</div>
            </div>
          ))}
          {result.sanitized_output && (
            <div className="scan-result-row">
              <div className="scan-result-key">Sanitized</div>
              <div className="scan-result-val" style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                {result.sanitized_output}
              </div>
            </div>
          )}
          {result.redactions && result.redactions.length > 0 && (
            <div className="scan-result-row">
              <div className="scan-result-key">Redactions</div>
              <div className="scan-result-val">{result.redactions.join(', ')}</div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function Scan() {
  if (!hasApiKey()) return (
    <div className="dash-main">
      <div className="dash-page-header"><div><h1>Scan</h1></div></div>
      <EmptyState />
    </div>
  )
  return (
    <div className="dash-main">
      <div className="dash-page-header">
        <div><h1>Scan</h1><p>Run prompt and output scans against the Interlock pipeline</p></div>
      </div>
      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', alignItems: 'flex-start' }}>
        <ScanForm title="Prompt Scan" action={api.scan} />
        <ScanForm title="Output Scan" action={api.scanOutput} />
      </div>
    </div>
  )
}
