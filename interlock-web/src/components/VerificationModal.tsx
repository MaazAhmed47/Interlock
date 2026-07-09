import { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'
import { AlertTriangle, ShieldAlert, ShieldCheck, X } from 'lucide-react'
import {
  api,
  ReceiptClaims,
  ReceiptVerifyContext,
  ReceiptVerifyResult,
  SecurityReceipt,
} from '../api'

interface Props {
  auditId: number
  onClose: () => void
}

function contextFromBinding(receipt: SecurityReceipt): ReceiptVerifyContext | null {
  const binding = receipt.binding
  if (!binding) return null
  const target = binding.target || '/'
  const slash = target.indexOf('/')
  return {
    server_id: slash >= 0 ? target.slice(0, slash) : target,
    tool_name: slash >= 0 ? target.slice(slash + 1) : '',
    argument_hash: binding.argument_hash || '',
    call_id: binding.call_id || '',
    surface_hash: binding.surface_hash || '',
  }
}

function CheckLine({ label, value }: { label: string; value: boolean | null | undefined }) {
  if (value == null) return (
    <div className="verify-check"><span className="verify-check-skip">–</span><span>{label}</span><span className="dim">not applicable</span></div>
  )
  return (
    <div className="verify-check">
      {value ? <span className="verify-check-ok">✓</span> : <span className="verify-check-bad">✗</span>}
      <span>{label}</span>
      <span className={value ? 'verify-ok-text' : 'verify-bad-text'}>{value ? 'verified' : 'FAILED'}</span>
    </div>
  )
}

function HashRow({ label, hash }: { label: string; hash: string }) {
  return (
    <div className="verify-hash-row">
      <span className="receipt-label">{label}</span>
      <code className="verify-hash">{hash || '—'}</code>
    </div>
  )
}

function SurfaceInspector({ inspectPath, surfaceHash }: { inspectPath?: string | null; surfaceHash: string }) {
  const [open, setOpen] = useState(false)
  const [json, setJson] = useState('')
  const [error, setError] = useState('')

  if (!inspectPath) return null

  async function toggle() {
    if (open) { setOpen(false); return }
    setOpen(true)
    if (json || error) return
    try {
      const snapshot = await api.surfaceSnapshot(surfaceHash)
      try {
        setJson(JSON.stringify(JSON.parse(snapshot.canonical_json), null, 2))
      } catch {
        setJson(snapshot.canonical_json)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load surface snapshot.')
    }
  }

  return (
    <div className="verify-inspect">
      <button className="btn btn-ghost btn-sm" onClick={() => void toggle()}>
        {open ? 'Hide canonical surface' : 'Inspect canonical surface'}
      </button>
      {open && (error
        ? <div className="verify-inspect-error">{error}</div>
        : <pre className="verify-surface-json">{json || 'Loading…'}</pre>)}
    </div>
  )
}

export default function VerificationModal({ auditId, onClose }: Props) {
  const [receipt, setReceipt] = useState<SecurityReceipt | null>(null)
  const [claims, setClaims] = useState<ReceiptClaims | null>(null)
  const [verify, setVerify] = useState<ReceiptVerifyResult | null>(null)
  const [replay, setReplay] = useState<ReceiptVerifyResult | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const [rcpt, clms] = await Promise.all([api.receipt(auditId), api.receiptClaims(auditId)])
        if (cancelled) return
        setReceipt(rcpt)
        setClaims(clms)
        const context = contextFromBinding(rcpt)
        if (context && context.call_id) {
          const good = await api.verifyReceipt(context, rcpt)
          if (cancelled) return
          setVerify(good)
          // Replay probe: present the SAME receipt for a different argument
          // set. This must fail — it proves receipts cannot be forwarded to
          // vouch for a call they were not issued for.
          const bad = await api.verifyReceipt(
            { ...context, argument_hash: 'sha256:' + '0'.repeat(64) },
            rcpt,
          )
          if (cancelled) return
          setReplay(bad)
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Verification failed to load.')
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    void load()
    return () => { cancelled = true }
  }, [auditId])

  const c1 = claims?.claim_1_approved
  const c2 = claims?.claim_2_observed
  const c3 = claims?.claim_3_decision
  const c4 = claims?.claim_4_execution_after_detection
  const bindingUnsupported = !loading && receipt != null && !(receipt.binding && receipt.binding.call_id)

  return createPortal(
    <div className="receipt-overlay" onClick={onClose}>
      <div className="receipt-printable verify-modal" onClick={e => e.stopPropagation()}>
        {loading && (
          <div className="receipt-doc receipt-state"><p className="mono dim">Verifying…</p></div>
        )}

        {!loading && error && (
          <div className="receipt-doc receipt-state">
            <AlertTriangle size={20} />
            <p>{error}</p>
            <button className="btn btn-ghost btn-sm" onClick={onClose}>Close</button>
          </div>
        )}

        {!loading && !error && receipt && claims && (
          <>
            <div className="receipt-doc">
              <header className="receipt-head">
                <div>
                  <div className="receipt-brand">INTERLOCK</div>
                  <div className="receipt-kicker">Receipt Verification — four claims</div>
                </div>
                <span className={`badge ${verify?.verified ? 'badge-allow' : 'badge-block'} receipt-decision`}>
                  {verify == null ? 'UNVERIFIED' : verify.verified ? 'VERIFIED' : 'FAILED'}
                </span>
              </header>

              <div className="receipt-meta">
                <span className="mono dim">{receipt.receipt_id}</span>
                <span className="mono dim">{receipt.timestamp}</span>
              </div>

              {/* Claim 1 */}
              <div className="receipt-section verify-claim">
                <span className="receipt-label">Claim 1 — What was approved</span>
                {c1 && (
                  <>
                    <HashRow label="approved surface" hash={c1.approved_surface_hash} />
                    {c1.expected_outcome && (
                      <p className="verify-line">Approved expectation: <b className="mono">{c1.expected_outcome}{c1.expected_status_code != null ? ` / ${c1.expected_status_code}` : ''}</b></p>
                    )}
                    <SurfaceInspector inspectPath={c1.inspect_path} surfaceHash={c1.approved_surface_hash} />
                  </>
                )}
              </div>

              {/* Claim 2 */}
              <div className="receipt-section verify-claim">
                <span className="receipt-label">Claim 2 — What changed</span>
                {c2 && (
                  <>
                    <HashRow label="observed surface" hash={c2.observed_surface_hash} />
                    {c2.schema_unchanged != null && (
                      <p className="verify-line">
                        Schema surface: <b className="mono">{c2.schema_unchanged ? 'UNCHANGED (hashes identical)' : 'CHANGED (hashes differ)'}</b>
                      </p>
                    )}
                    {c2.observed_outcome && (
                      <p className="verify-line">Observed behavior: <b className="mono">{c2.observed_outcome}{c2.observed_status_code != null ? ` / ${c2.observed_status_code}` : ''}</b></p>
                    )}
                    {c2.changes.length > 0 && (
                      <ul className="verify-changes">{c2.changes.map((c, i) => <li key={i}>{c}</li>)}</ul>
                    )}
                    <SurfaceInspector inspectPath={c2.inspect_path} surfaceHash={c2.observed_surface_hash} />
                  </>
                )}
              </div>

              {/* Claim 3 */}
              <div className="receipt-section verify-claim">
                <span className="receipt-label">Claim 3 — Runtime decision</span>
                {c3 && (
                  <>
                    <p className="verify-line">
                      <span className={`badge badge-${c3.decision === 'allow' ? 'allow' : c3.decision === 'monitor' ? 'monitor' : c3.decision === 'quarantine' ? 'quarantine' : 'block'}`}>{c3.decision.toUpperCase()}</span>
                      {' '}<span className="mono dim">rule: {c3.rule_fired || 'none'} · severity: {c3.drift_severity}</span>
                    </p>
                    <p className="receipt-reason">{c3.reason}</p>
                  </>
                )}
              </div>

              {/* Claim 4 */}
              <div className="receipt-section verify-claim">
                <span className="receipt-label">Claim 4 — Execution after detection</span>
                {c4 && (
                  <>
                    <p className="verify-line">
                      {c4.boundary_crossing_executed
                        ? <b className="verify-bad-text">{c4.executed_count} boundary-crossing call(s) executed after detection.</b>
                        : <b className="verify-ok-text">No boundary-crossing call executed after detection{c4.blocked_attempts > 0 ? ` — ${c4.blocked_attempts} attempt(s) were blocked first` : ''}.</b>}
                    </p>
                    <p className="verify-basis">{c4.basis}</p>
                  </>
                )}
              </div>

              {/* Verification result */}
              <div className={`receipt-integrity ${verify?.verified ? 'is-verified' : 'is-broken'}`}>
                <div className="receipt-integrity-head">
                  {verify?.verified
                    ? <><ShieldCheck size={16} /><span>Receipt verified against its recorded context</span></>
                    : <><ShieldAlert size={16} /><span>{bindingUnsupported ? 'This event predates context binding — verification fails closed' : 'Verification failed'}</span></>}
                </div>
                <CheckLine label="hash chain (content + linkage)" value={verify?.checks.chain} />
                <CheckLine label="receipt matches stored record" value={verify?.checks.receipt_match} />
                <CheckLine label="drift-evidence digest recomputed" value={verify?.checks.evidence_digest} />
                <CheckLine label="context binding (target · args · call id · surface)" value={verify?.checks.binding} />
                {receipt.binding && (
                  <>
                    <HashRow label="call id" hash={receipt.binding.call_id} />
                    <HashRow label="argument hash" hash={receipt.binding.argument_hash} />
                    <HashRow label="integrity hash" hash={receipt.integrity_hash} />
                  </>
                )}
              </div>

              {/* Replay probe result */}
              {replay && (
                <div className={`receipt-integrity ${!replay.verified ? 'is-verified' : 'is-broken'}`}>
                  <div className="receipt-integrity-head">
                    {!replay.verified
                      ? <><ShieldCheck size={16} /><span>Replay check: same receipt presented for a different argument set → correctly REJECTED</span></>
                      : <><ShieldAlert size={16} /><span>Replay check FAILED: a replayed receipt verified — this is a bug</span></>}
                  </div>
                  {!replay.verified && replay.mismatches.length > 0 && (
                    <p className="verify-basis">
                      Rejected on: {replay.mismatches.map(m => m.field).join(', ')}
                    </p>
                  )}
                </div>
              )}

              <footer className="receipt-foot">
                <span>
                  Every value above is read from the hash-chained audit log and recomputed on request.
                  Claim 4 counts gateway-mediated calls only; calls made outside Interlock are not visible.
                </span>
              </footer>
            </div>

            <div className="receipt-actions receipt-no-print">
              <button className="btn btn-ghost btn-sm" onClick={onClose}><X size={13} />Close</button>
            </div>
          </>
        )}
      </div>
    </div>,
    document.body,
  )
}
