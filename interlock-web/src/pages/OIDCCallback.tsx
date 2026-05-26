import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { AlertTriangle, Loader2, ShieldCheck } from 'lucide-react'
import { completeOidcCallback } from '../auth'

export default function OIDCCallback() {
  const navigate = useNavigate()
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    completeOidcCallback()
      .then(({ returnTo }) => {
        if (!cancelled) navigate(returnTo, { replace: true })
      })
      .catch(err => {
        if (!cancelled) setError(err instanceof Error ? err.message : 'SSO callback failed.')
      })
    return () => { cancelled = true }
  }, [navigate])

  return (
    <div className="login-shell">
      <div className="callback-card glow-card">
        {error ? (
          <>
            <div className="auth-state-icon warn"><AlertTriangle size={22} /></div>
            <h1>SSO sign-in failed</h1>
            <p className="dim">{error}</p>
            <div className="login-actions centered">
              <Link className="btn btn-primary" to="/dashboard/login">Try Again</Link>
              <Link className="btn btn-ghost" to="/dashboard/settings">Check Settings</Link>
            </div>
          </>
        ) : (
          <>
            <div className="auth-state-icon ok"><ShieldCheck size={22} /></div>
            <Loader2 className="spin" size={24} />
            <h1>Completing secure sign-in</h1>
            <p className="dim">Exchanging the authorization code with PKCE and opening your dashboard session.</p>
          </>
        )}
      </div>
    </div>
  )
}
