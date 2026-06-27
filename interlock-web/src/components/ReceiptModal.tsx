import { createPortal } from 'react-dom'
import { AlertTriangle, FileText, Hash, Link2, Printer, ShieldAlert, ShieldCheck, X } from 'lucide-react'
import { SecurityReceipt } from '../api'

interface Props {
  receipt: SecurityReceipt | null
  loading: boolean
  error: string
  onClose: () => void
}

function riskLabel(score: number): string {
  if (score >= 80) return 'CRITICAL'
  if (score >= 60) return 'HIGH'
  if (score >= 40) return 'MEDIUM'
  if (score >= 20) return 'LOW'
  return 'MINIMAL'
}

function decisionClass(decision: string): string {
  const d = decision.toLowerCase()
  if (d === 'allow') return 'badge-allow'
  if (d === 'monitor') return 'badge-monitor'
  if (d === 'quarantine') return 'badge-quarantine'
  return 'badge-block'
}

// Past tense per decision verb. Naive `${decision}ed` produced "quarantineed"
// and "denyed", so map explicitly.
const DECISION_PAST_TENSE: Record<string, string> = {
  allow: 'allowed',
  deny: 'denied',
  block: 'blocked',
  monitor: 'monitored',
  quarantine: 'quarantined',
}

function decisionPastTense(decision: string): string {
  return DECISION_PAST_TENSE[decision.toLowerCase()] ?? decision
}

type ProbeOutcome = {
  expected: string
  observed: string
}

function formatProbeOutcome(outcome?: unknown, status?: unknown): string {
  const outcomeText = String(outcome ?? '').trim()
  const statusText = String(status ?? '').trim()
  return [outcomeText, statusText].filter(Boolean).join(' / ')
}

function effectivePermissionProbeOutcome(receipt: SecurityReceipt): ProbeOutcome | null {
  const evidence = receipt.drift_evidence
  const record = evidence?.record
  const refType = String(evidence?.evidence_ref?.type ?? '')
  const recordType = String(record?.record_type ?? '')
  const isEffectivePermission =
    refType === 'effective-permission-drift' ||
    recordType === 'interlock.effective-permission-drift'

  if (!record || !isEffectivePermission) return null

  const expected = formatProbeOutcome(record.expected_outcome, record.expected_status_code)
  const observed = formatProbeOutcome(record.observed_outcome, record.observed_status_code)

  if (!expected && !observed) return null
  return { expected: expected || 'unknown', observed: observed || 'unknown' }
}

export default function ReceiptModal({ receipt, loading, error, onClose }: Props) {
  const probeOutcome = receipt ? effectivePermissionProbeOutcome(receipt) : null
  // Portaled to <body> (sibling of #root) so the print block can hide #root and
  // let this overlay flow as the page — same isolation the audit print view uses.
  // Rendered inside #root, it printed blank once the audit print CSS added a
  // global `#root { display:none }`.
  return createPortal(
    <div className="receipt-overlay" onClick={onClose}>
      <div className="receipt-printable" onClick={e => e.stopPropagation()}>
        {loading && (
          <div className="receipt-doc receipt-state">
            <p className="mono dim">Generating receipt…</p>
          </div>
        )}

        {!loading && error && (
          <div className="receipt-doc receipt-state">
            <AlertTriangle size={20} />
            <p>{error}</p>
            <button className="btn btn-ghost btn-sm" onClick={onClose}>Close</button>
          </div>
        )}

        {!loading && !error && receipt && (
          <>
            <div className="receipt-doc">
              <header className="receipt-head">
                <div>
                  <div className="receipt-brand">INTERLOCK</div>
                  <div className="receipt-kicker">Security Receipt</div>
                </div>
                <span className={`badge ${decisionClass(receipt.decision)} receipt-decision`}>
                  {receipt.decision.toUpperCase()}
                </span>
              </header>

              <div className="receipt-meta">
                <span className="mono dim">{receipt.receipt_id}</span>
                <span className="mono dim">{receipt.timestamp}</span>
              </div>

              <div className="receipt-summary">
                <div className="receipt-summary-text">
                  <span className="receipt-label">Decision</span>
                  <strong>
                    {receipt.tool_name} on {receipt.server_id} was{' '}
                    {decisionPastTense(receipt.decision)}
                  </strong>
                </div>
                <div className={`receipt-risk risk-${riskLabel(receipt.risk_score).toLowerCase()}`}>
                  <span className="receipt-risk-num">{receipt.risk_score}</span>
                  <span className="receipt-risk-label">{riskLabel(receipt.risk_score)} RISK</span>
                </div>
              </div>

              <div className="receipt-grid">
                <div><span className="receipt-label">Agent role</span><b className="mono">{receipt.agent_role || '—'}</b></div>
                <div><span className="receipt-label">MCP server</span><b className="mono">{receipt.server_id || '—'}</b></div>
                <div><span className="receipt-label">Tool</span><b className="mono">{receipt.tool_name || '—'}</b></div>
                <div><span className="receipt-label">Rule fired</span><b className="mono">{receipt.rule_fired || 'none'}</b></div>
              </div>

              {probeOutcome && (
                <div className="receipt-probe-outcome">
                  <span className="receipt-label">Probe outcome</span>
                  <div className="receipt-probe-grid">
                    <div className="receipt-probe-box">
                      <span>Expected</span>
                      <strong>{probeOutcome.expected}</strong>
                    </div>
                    <div className="receipt-probe-arrow" aria-hidden="true">→</div>
                    <div className="receipt-probe-box observed">
                      <span>Observed</span>
                      <strong>{probeOutcome.observed}</strong>
                    </div>
                  </div>
                </div>
              )}

              <div className="receipt-section">
                <span className="receipt-label">Why</span>
                <p className="receipt-reason">{receipt.reason || 'No additional detail recorded.'}</p>
              </div>

              <div className="receipt-cols">
                <div className="receipt-section">
                  <span className="receipt-label">Detections</span>
                  {receipt.detections.length === 0
                    ? <p className="dim mono receipt-none">none</p>
                    : <div className="receipt-chips">
                        {receipt.detections.map(d => <span key={d} className="receipt-chip chip-warn">{d}</span>)}
                      </div>}
                </div>
                <div className="receipt-section">
                  <span className="receipt-label">Redactions</span>
                  {receipt.redactions.length === 0
                    ? <p className="dim mono receipt-none">none</p>
                    : <div className="receipt-chips">
                        {receipt.redactions.map(r => <span key={r} className="receipt-chip chip-redact">{r}</span>)}
                      </div>}
                </div>
              </div>

              <div className="receipt-section">
                <span className="receipt-label">Drift evidence</span>
                {receipt.drift.detected
                  ? <div className="receipt-drift">
                      <span className="badge badge-monitor">{(receipt.drift.severity || 'detected').toUpperCase()}</span>
                      <ul>
                        {receipt.drift.changes.length === 0
                          ? <li className="dim">Change detected since approved baseline.</li>
                          : receipt.drift.changes.map((c, i) => <li key={i}>{c}</li>)}
                      </ul>
                    </div>
                  : <p className="dim mono receipt-none">no drift recorded for this event</p>}
              </div>

              <div className={`receipt-integrity ${receipt.chain_verified ? 'is-verified' : 'is-broken'}`}>
                <div className="receipt-integrity-head">
                  {receipt.chain_verified
                    ? <><ShieldCheck size={16} /><span>Hash chain verified ✓</span></>
                    : <><ShieldAlert size={16} /><span>Chain verification failed — possible tampering</span></>}
                </div>
                <div className="receipt-hash"><Hash size={11} /><span className="receipt-label">integrity</span><code>{receipt.integrity_hash || '—'}</code></div>
                <div className="receipt-hash"><Link2 size={11} /><span className="receipt-label">previous</span><code>{receipt.prev_hash || '—'}</code></div>
              </div>

              <footer className="receipt-foot">
                <FileText size={11} />
                <span>Generated by Interlock — runtime security gateway for AI agents. Each receipt is cryptographically linked to the prior event; altering any record breaks the chain.</span>
              </footer>
            </div>

            <div className="receipt-actions receipt-no-print">
              <button className="btn btn-cyan btn-sm" onClick={() => window.print()}><Printer size={13} />Print / Save PDF</button>
              <button className="btn btn-ghost btn-sm" onClick={onClose}><X size={13} />Close</button>
            </div>
          </>
        )}
      </div>
    </div>,
    document.body,
  )
}
