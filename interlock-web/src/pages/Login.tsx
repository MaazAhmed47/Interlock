import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { CheckCircle2, KeyRound, LogIn, ShieldCheck, Settings, AlertTriangle, FileClock, ServerCog, Mail } from 'lucide-react'
import {
  authDisplayName,
  beginOidcLogin,
  beginSupabaseOAuth,
  clearAuthSession,
  getOidcConfig,
  getSupabaseAuthConfig,
  oidcConfigStatus,
  requestSupabaseMagicLink,
  supabaseAuthStatus,
  useAuthSession,
} from '../auth'

export default function Login() {
  const [params] = useSearchParams()
  const session = useAuthSession()
  const config = getOidcConfig()
  const status = oidcConfigStatus(config)
  const supabaseConfig = getSupabaseAuthConfig()
  const supabaseStatus = supabaseAuthStatus(supabaseConfig)
  const [email, setEmail] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)
  const returnTo = params.get('returnTo') || '/dashboard/audit?view=admin'

  async function signIn() {
    setError('')
    setNotice('')
    setBusy(true)
    try {
      await beginOidcLogin(returnTo)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not start SSO login.')
      setBusy(false)
    }
  }

  async function signInWithSupabaseProvider() {
    setError('')
    setNotice('')
    setBusy(true)
    try {
      await beginSupabaseOAuth(supabaseConfig.provider, returnTo)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not start Supabase Auth.')
      setBusy(false)
    }
  }

  async function sendMagicLink() {
    setError('')
    setNotice('')
    setBusy(true)
    try {
      await requestSupabaseMagicLink(email)
      setNotice('Magic link sent. Open it from your email on this same browser, then Interlock will complete the admin session.')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not send magic link.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-shell">
      <div className="login-panel glow-card">
        <section className="login-copy">
          <div className="login-kicker"><ShieldCheck size={14} /> Enterprise admin access</div>
          <h1>Sign in to Interlock control plane</h1>
          <p>
            Supabase Auth is wired as the first real provider for this dashboard. Interlock verifies the issued JWT on the backend with issuer, audience, expiry, JWKS, allowed algorithms, and your admin email allowlist.
          </p>
          <div className="login-assurance-grid">
            <div><CheckCircle2 size={15} /><span>Supabase JWT + JWKS</span></div>
            <div><CheckCircle2 size={15} /><span>Email allowlist boundary</span></div>
            <div><CheckCircle2 size={15} /><span>Admin audit identity</span></div>
          </div>
          <div className="login-flow">
            <div><ServerCog size={15} /><span>Project</span><strong>{supabaseConfig.url || 'Supabase project not configured'}</strong></div>
            <div><ShieldCheck size={15} /><span>Backend</span><strong>OIDC issuer and JWKS verify every admin request</strong></div>
            <div><FileClock size={15} /><span>Evidence</span><strong>Token, key, retention, and review actions are audited</strong></div>
          </div>
        </section>

        <section className="login-card">
          {session ? (
            <>
              <div className="auth-state-icon ok"><ShieldCheck size={22} /></div>
              <h2>Signed in</h2>
              <p className="dim">{authDisplayName(session)}</p>
              <div className="auth-session-list">
                <div><span>Role claim</span><strong>{session.profile.role || 'Mapped by backend'}</strong></div>
                <div><span>Issuer</span><strong>{session.profile.issuer || config.issuer || supabaseConfig.url || '-'}</strong></div>
                <div><span>Session</span><strong>{session.expiresAt ? new Date(session.expiresAt).toLocaleString() : 'Token lifetime'}</strong></div>
              </div>
              <div className="login-actions">
                <Link className="btn btn-cyan" to="/dashboard/audit?view=admin">View Admin Audit</Link>
                <button className="btn btn-ghost" onClick={clearAuthSession}>Sign Out</button>
              </div>
            </>
          ) : supabaseStatus.configured ? (
            <>
              <div className="auth-state-icon"><KeyRound size={22} /></div>
              <h2>Continue with Supabase Auth</h2>
              <p className="dim">Use Google/OAuth if enabled in Supabase, or send a passwordless magic link to an allowed admin email.</p>
              <div className="auth-session-list">
                <div><span>Provider</span><strong>{supabaseConfig.provider.toUpperCase()}</strong></div>
                <div><span>Redirect URI</span><strong>{supabaseConfig.redirectUri}</strong></div>
                <div><span>Admin boundary</span><strong>Backend email/domain allowlist</strong></div>
              </div>
              <button className="btn btn-primary auth-wide-action" onClick={signInWithSupabaseProvider} disabled={busy}>
                <LogIn size={14} />{busy ? 'Redirecting' : 'Continue with ' + supabaseConfig.provider.charAt(0).toUpperCase() + supabaseConfig.provider.slice(1)}
              </button>
              <div className="magic-link-box">
                <label className="form-label">Passwordless Admin Email</label>
                <div className="input-action-row">
                  <input className="form-input" value={email} onChange={e => setEmail(e.target.value)} placeholder="you@company.com" autoComplete="email" />
                  <button className="btn btn-cyan" onClick={sendMagicLink} disabled={busy}><Mail size={14} />Send Link</button>
                </div>
              </div>
              <div className="login-mode-note">Enter your email to receive a secure login link. Supabase must allow this redirect URL: {supabaseConfig.redirectUri}</div>
              {notice && <div className="auth-success"><CheckCircle2 size={14} />{notice}</div>}
              {error && <div className="auth-error"><AlertTriangle size={14} />{error}</div>}
              <div className="login-actions">
                <Link className="btn btn-ghost" to="/dashboard/settings"><Settings size={14} />Auth Settings</Link>
                {status.configured && <button className="btn btn-ghost" onClick={signIn} disabled={busy}>Generic OIDC</button>}
              </div>
            </>
          ) : (
            <>
              <div className="auth-state-icon warn"><AlertTriangle size={22} /></div>
              <h2>Supabase Auth not configured</h2>
              <p className="dim">Add your Supabase project URL and publishable key in Settings. Use a public publishable key only; never paste a service role key.</p>
              <div className="missing-list">
                {supabaseStatus.missing.map(item => <span key={item}>{item}</span>)}
              </div>
              {error && <div className="auth-error"><AlertTriangle size={14} />{error}</div>}
              <div className="login-actions">
                <Link className="btn btn-primary" to="/dashboard/settings"><Settings size={14} />Configure Auth</Link>
                <Link className="btn btn-ghost" to="/dashboard">Back to Dashboard</Link>
              </div>
            </>
          )}
        </section>
      </div>
    </div>
  )
}
