import { useEffect, useState } from 'react'
import { useLocation } from 'react-router-dom'
import { ScanLine, Loader2 } from 'lucide-react'
import { api, demoScan, normalizeLayerLabel, ScanMode, ScanResult, DEMO_PROMPTS, DemoPrompt } from '../api'
import StatusBadge from '../components/StatusBadge'
import EmptyState from '../components/EmptyState'
import ErrorCard from '../components/ErrorCard'
import { useDashboardData } from '../components/DashLayout'

function threatClass(level: string) {
  const l = level.toLowerCase()
  if (l === 'safe') return 'threat-safe'
  if (l === 'medium') return 'threat-medium'
  if (l === 'high') return 'threat-high'
  if (l === 'critical') return 'threat-critical'
  return ''
}

function formatElapsed(ms: number) {
  return (ms / 1000).toFixed(1) + 's'
}

function formatMs(ms: number) {
  if (ms > 0 && ms < 1) return '<1ms'
  return String(Math.round(ms * 10) / 10) + 'ms'
}

function progressMessage(ms: number, endpoint: string, mode: ScanMode) {
  if (endpoint === '/scan' && mode === 'fast') return 'Running deterministic runtime checks without waiting on the external judge.'
  if (endpoint === '/scan/output') return 'Output scans should return quickly because they use deterministic response checks.'
  if (ms >= 35000) return 'Still waiting on the backend/provider. This scan will stop at 45s instead of hanging.'
  if (ms >= 15000) return 'Still running. Cold hosted backends and Layer 3 judge calls can be slow.'
  return 'Running policy, pattern, and judge checks...'
}

type ScanFn = (prompt: string) => Promise<ScanResult>

function ScanForm({
  title,
  action,
  examples,
  initialPrompt = '',
  endpoint,
  scanMode = 'fast',
  onComplete,
}: {
  title: string
  action: ScanFn
  examples: DemoPrompt[]
  initialPrompt?: string
  endpoint: string
  scanMode?: ScanMode
  onComplete?: (result: ScanResult, endpoint: string) => void | Promise<void>
}) {
  const [prompt, setPrompt] = useState(initialPrompt)
  const [result, setResult] = useState<ScanResult | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [startedAt, setStartedAt] = useState<number | null>(null)
  const [elapsedMs, setElapsedMs] = useState(0)

  useEffect(() => {
    if (!initialPrompt) return
    setPrompt(initialPrompt)
    setResult(null)
    setError('')
  }, [initialPrompt])

  useEffect(() => {
    if (!loading || !startedAt) return
    const timer = window.setInterval(() => setElapsedMs(Date.now() - startedAt), 150)
    return () => window.clearInterval(timer)
  }, [loading, startedAt])

  async function run() {
    if (loading || !prompt.trim()) return
    const start = Date.now()
    setLoading(true)
    setStartedAt(start)
    setElapsedMs(0)
    setResult(null)
    setError('')
    try {
      const nextResult = await action(prompt)
      setResult(nextResult)
      void onComplete?.(nextResult, endpoint)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setElapsedMs(Date.now() - start)
      setLoading(false)
    }
  }

  const rows: [string, string | number | null | undefined][] = [
    ['Reason', result?.reason],
    ['Threat Type', result?.threat_type],
    ['Layer Caught', normalizeLayerLabel(result?.layer_caught)],
    ['Confidence', result?.confidence != null ? `${Math.round(result.confidence * 100)}%` : null],
    ['Engine Time', result?.scan_time_ms != null ? formatMs(result.scan_time_ms) : null],
    ['Request Time', result ? formatElapsed(elapsedMs) : null],
  ]

  return (
    <div className="card" style={{ flex: 1, minWidth: 280 }}>
      <div className="card-header"><div className="card-title">{title}</div></div>
      <div className="form-group">
        <textarea
          className="form-input"
          style={{ minHeight: 120 }}
          placeholder="Paste text to scan..."
          value={prompt}
          onChange={e => setPrompt(e.target.value)}
        />
        <div className="prompt-chip-row" aria-label={`${title} examples`}>
          {examples.map(example => (
            <button
              key={example.label}
              type="button"
              className={`prompt-chip ${example.tone}`}
              onClick={() => { if (!loading) { setPrompt(example.prompt); setResult(null); setError('') } }}
              title={example.intent}
              disabled={loading}
            >
              {example.label}
            </button>
          ))}
        </div>
      </div>
      <div className="scan-action-row">
        <button className="btn btn-primary" onClick={run} disabled={loading || !prompt.trim()}>
          {loading ? <Loader2 size={13} className="spin" /> : <ScanLine size={13} />}
          {loading ? 'Scanning ' + formatElapsed(elapsedMs) : 'Scan'}
        </button>
        {loading && <span className="scan-progress-note">{progressMessage(elapsedMs, endpoint, scanMode)}</span>}
      </div>

      {error && <ErrorCard message={error} />}

      {result && (
        <div className={`scan-result ${threatClass(result.threat_level)}`}>
          <div className="scan-result-header">
            <StatusBadge value={result.threat_level} />
            <span style={{ fontSize: 13, color: result.is_threat ? 'var(--red)' : 'var(--cyan)' }}>
              {result.is_threat ? 'Threat detected' : 'Clean'}
            </span>
          </div>
          <div className="risk-meter compact">
            <div className="risk-meter-top">
              <span>Risk Score</span>
              <strong>{result.risk_score ?? 0}/100</strong>
            </div>
            <div className="risk-bar"><span style={{ width: `${Math.max(0, Math.min(100, result.risk_score ?? 0))}%` }} /></div>
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
  const { configured, demoMode, refreshScans, recordScanResult } = useDashboardData()
  const location = useLocation()
  const state = location.state as { prompt?: string; target?: 'prompt' | 'output' } | null
  const initialTarget = state?.target === 'output' ? 'output' : 'prompt'
  const initialPrompt = typeof state?.prompt === 'string' ? state.prompt : ''
  const promptExamples = DEMO_PROMPTS.filter(p => p.target === 'prompt')
  const outputExamples = DEMO_PROMPTS.filter(p => p.target === 'output')
  const [scanMode, setScanMode] = useState<ScanMode>('fast')

  function handleComplete(result: ScanResult, endpoint: string) {
    recordScanResult(result, endpoint)
    if (configured) void refreshScans()
  }

  if (!configured && !demoMode) return (
    <div className="dash-main">
      <div className="dash-page-header"><div><h1>Scan</h1></div></div>
      <EmptyState message="Add an API key before running scans. The dashboard includes sample prompts you can test once connected." />
    </div>
  )
  return (
    <div className="dash-main">
      <div className="dash-page-header">
        <div><h1>Scan</h1><p>Run prompt and output scans against the Interlock pipeline</p></div>
        {configured && (
          <div className="segmented-control" aria-label="Prompt scan mode">
            <button className={scanMode === 'fast' ? 'active' : ''} onClick={() => setScanMode('fast')}>Runtime Policy</button>
            <button className={scanMode === 'full' ? 'active' : ''} onClick={() => setScanMode('full')}>Full Judge</button>
          </div>
        )}
      </div>
      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', alignItems: 'flex-start' }}>
        <ScanForm
          title="Prompt Scan"
          action={prompt => configured ? api.scan(prompt, scanMode) : demoScan(prompt, 'prompt')}
          examples={promptExamples}
          initialPrompt={initialTarget === 'prompt' ? initialPrompt : ''}
          endpoint="/scan"
          scanMode={scanMode}
          onComplete={handleComplete}
        />
        <ScanForm
          title="Output Scan"
          action={prompt => configured ? api.scanOutput(prompt) : demoScan(prompt, 'output')}
          examples={outputExamples}
          initialPrompt={initialTarget === 'output' ? initialPrompt : ''}
          endpoint="/scan/output"
          scanMode="fast"
          onComplete={handleComplete}
        />
      </div>
    </div>
  )
}
