import { useEffect, useRef } from 'react'
import {
  ArrowUpRight,
  CheckCircle2,
  GitCompareArrows,
  ShieldAlert,
} from 'lucide-react'

const FIXTURE_LABEL = 'SYNTHETIC DEMO FIXTURE — reproducible offline proof'
const OFFLINE_PROOF_URL =
  'https://github.com/MaazAhmed47/Interlock/blob/main/demo/offline/README.md'

function FixtureLabel() {
  return <div className="proof-fixture-label">{FIXTURE_LABEL}</div>
}

export default function DriftProof() {
  const mainRef = useRef<HTMLElement>(null)

  useEffect(() => {
    mainRef.current?.focus({ preventScroll: true })
  }, [])

  return (
    <main
      ref={mainRef}
      className="dash-main drift-proof-page"
      tabIndex={-1}
      aria-labelledby="drift-proof-title"
    >
      <header className="proof-page-header">
        <div>
          <FixtureLabel />
          <p className="proof-eyebrow">Guided drift proof</p>
          <h1 id="drift-proof-title">One approved boundary. One material change. One runtime decision.</h1>
          <p className="proof-intro">
            Follow the tracked offline fixture from approval through quarantine and hash-chain
            verification. This is reproducible product evidence, not a customer or production incident.
          </p>
        </div>
        <a
          className="proof-run-link"
          href={OFFLINE_PROOF_URL}
          target="_blank"
          rel="noopener noreferrer"
        >
          Run the offline proof
          <ArrowUpRight size={15} aria-hidden="true" />
        </a>
      </header>

      <ol className="proof-flow" aria-label="Guided drift proof sequence">
        <li className="proof-flow-step">
          <div className="proof-step-heading">
            <span className="proof-step-number" aria-hidden="true">1</span>
            <div>
              <p className="proof-step-kicker">Approved boundary → material drift</p>
              <h2>Approved versus Current</h2>
            </div>
          </div>
          <FixtureLabel />

          <div className="proof-comparison-wrap">
            <table className="proof-comparison">
              <caption>Approved and current boundaries for the read_file tool</caption>
              <colgroup>
                <col className="proof-comparison-field" />
                <col />
                <col />
              </colgroup>
              <thead>
                <tr>
                  <th scope="col">Boundary</th>
                  <th scope="col" className="proof-approved-heading">
                    <CheckCircle2 size={14} aria-hidden="true" />
                    Approved
                  </th>
                  <th scope="col" className="proof-current-heading">
                    <GitCompareArrows size={14} aria-hidden="true" />
                    Current
                  </th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <th scope="row">Tool</th>
                  <td><code>read_file</code></td>
                  <td>
                    <code>read_file</code>
                    <span className="proof-unchanged">unchanged identity</span>
                  </td>
                </tr>
                <tr>
                  <th scope="row">Effects</th>
                  <td><span className="proof-value-approved">read</span></td>
                  <td>
                    <span className="proof-value-neutral">read</span>
                    <span className="proof-value-changed">export</span>
                  </td>
                </tr>
                <tr>
                  <th scope="row">Externality</th>
                  <td><span className="proof-value-approved">internal</span></td>
                  <td><span className="proof-value-changed">external</span></td>
                </tr>
              </tbody>
            </table>
          </div>

          <p className="proof-delta-summary">
            <strong>Exact difference:</strong> effects expanded by <code>export</code>;
            externality changed from <code>internal</code> to <code>external</code>.
          </p>
        </li>

        <li className="proof-flow-step">
          <div className="proof-step-heading">
            <span className="proof-step-number" aria-hidden="true">2</span>
            <div>
              <p className="proof-step-kicker">Runtime decision</p>
              <h2>Continuation stopped for <code>read_file</code> at the gateway boundary</h2>
            </div>
          </div>
          <FixtureLabel />

          <div className="proof-decision" role="group" aria-label="Quarantine decision">
            <div className="proof-decision-status">
              <ShieldAlert size={18} aria-hidden="true" />
              Quarantined
            </div>
            {/* Single text node on purpose: .proof-decision p is display:flex,
                which drops whitespace-only nodes between inline children and
                would render "to read_file held" as "toread_fileheld". */}
            <p>subsequent gateway-mediated calls to read_file are held before upstream forwarding</p>
          </div>
          <p className="proof-scope-note">
            Quarantine is scoped to this one tool: unrelated approved tools on the same server —
            the <code>list_documents</code> control — keep working. This is the decision recorded by
            Interlock for calls mediated by its gateway. The offline fixture does not independently
            verify upstream side effects, and traffic that bypasses Interlock is not visible.
          </p>
        </li>

        <li className="proof-flow-step">
          <div className="proof-step-heading">
            <span className="proof-step-number" aria-hidden="true">3</span>
            <div>
              <p className="proof-step-kicker">Evidence</p>
              <h2>Decision evidence remains recomputable</h2>
            </div>
          </div>
          <FixtureLabel />

          <dl className="proof-evidence-list">
            <div>
              <dt>Receipt</dt>
              <dd className="proof-verified">
                <CheckCircle2 size={15} aria-hidden="true" />
                hash-chained
              </dd>
            </div>
            <div>
              <dt>Chain verification</dt>
              <dd className="proof-verified">
                <CheckCircle2 size={15} aria-hidden="true" />
                verified
              </dd>
            </div>
            <div>
              <dt>After detection</dt>
              <dd>
                <span className="proof-offline-result">
                  <CheckCircle2 size={15} aria-hidden="true" />
                  No boundary-crossing call to <code>read_file</code> was forwarded upstream after detection
                </span>
                <span className="proof-result-label">Reproducible offline-proof result</span>
              </dd>
            </div>
          </dl>

          <div
            className="proof-behavior"
            id="behavioral-probe-evidence"
            aria-labelledby="behavior-proof-title"
          >
            <div className="proof-behavior-heading">
              <p>Separate advanced proof — not the journey above</p>
              <h3 id="behavior-proof-title">Controlled effective-permission probe <span>— not schema drift</span></h3>
            </div>
            <p className="proof-scope-note">
              The surface-drift journey above never issues this probe. Here a controlled
              non-production probe is deliberately forwarded upstream, because Interlock needs the
              upstream response to observe a change the manifest does not declare. The probe itself
              is answered; the observed 200 is what quarantines that tool, and only later
              gateway-mediated calls to that same tool are held before forwarding.
            </p>
            <div className="proof-behavior-row">
              <div>
                <span>Manifest / schema</span>
                <strong>same</strong>
              </div>
              <div>
                <span>Expected</span>
                <strong className="proof-value-approved">403 denied</strong>
              </div>
              <div>
                <span>Observed</span>
                <strong className="proof-value-changed">200 allowed</strong>
              </div>
            </div>
          </div>
        </li>
      </ol>
    </main>
  )
}
