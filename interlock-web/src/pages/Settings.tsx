import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { LogIn, Save, Search, ShieldCheck } from 'lucide-react'
import { API_URL_KEY, API_KEY_KEY, DEFAULT_API_URL, api } from '../api'
import { defaultRedirectUri, discoverOidcFromIssuer, getOidcConfig, getSupabaseAuthConfig, oidcConfigStatus, saveOidcConfig, saveSupabaseAuthConfig, supabaseAuthStatus, useAuthSession } from '../auth'
import ErrorCard from '../components/ErrorCard'
import { useDashboardData } from '../components/DashLayout'

export default function Settings() {
  const [url, setUrl] = useState(sessionStorage.getItem(API_URL_KEY) || DEFAULT_API_URL)
  const [key, setKey] = useState(sessionStorage.getItem(API_KEY_KEY) || '')
  const [urlError, setUrlError] = useState('')
  const [saved, setSaved] = useState(false)
  const [siemProviders, setSiemProviders] = useState<string[]>([])
  const [siemError, setSiemError] = useState('')
  const initialOidc = useMemo(() => getOidcConfig(), [])
  const initialSupabase = useMemo(() => getSupabaseAuthConfig(), [])
  const [oidcIssuer, setOidcIssuer] = useState(initialOidc.issuer)
  const [oidcAuthorizationUrl, setOidcAuthorizationUrl] = useState(initialOidc.authorizationUrl)
  const [oidcTokenUrl, setOidcTokenUrl] = useState(initialOidc.tokenUrl)
  const [oidcClientId, setOidcClientId] = useState(initialOidc.clientId)
  const [oidcRedirectUri, setOidcRedirectUri] = useState(initialOidc.redirectUri || defaultRedirectUri())
  const [oidcScope, setOidcScope] = useState(initialOidc.scope || 'openid email profile')
  const [oidcAudience, setOidcAudience] = useState(initialOidc.audience)
  const [oidcLogoutUrl, setOidcLogoutUrl] = useState(initialOidc.logoutUrl)
  const [oidcSaved, setOidcSaved] = useState(false)
  const [oidcError, setOidcError] = useState('')
  const [discovering, setDiscovering] = useState(false)
  const [supabaseUrl, setSupabaseUrl] = useState(initialSupabase.url)
  const [supabasePublishableKey, setSupabasePublishableKey] = useState(initialSupabase.publishableKey)
  const [supabaseProvider, setSupabaseProvider] = useState(initialSupabase.provider || 'google')
  const [supabaseRedirectUri, setSupabaseRedirectUri] = useState(initialSupabase.redirectUri || defaultRedirectUri())
  const [supabaseCreateUser, setSupabaseCreateUser] = useState(initialSupabase.createUser)
  const [supabaseSaved, setSupabaseSaved] = useState(false)
  const session = useAuthSession()
  const { refreshAll } = useDashboardData()

  const oidcDraft = {
    issuer: oidcIssuer.trim(),
    authorizationUrl: oidcAuthorizationUrl.trim(),
    tokenUrl: oidcTokenUrl.trim(),
    clientId: oidcClientId.trim(),
    redirectUri: oidcRedirectUri.trim(),
    scope: oidcScope.trim() || 'openid email profile',
    audience: oidcAudience.trim(),
    logoutUrl: oidcLogoutUrl.trim(),
  }
  const oidcStatus = oidcConfigStatus(oidcDraft)
  const supabaseDraft = {
    url: supabaseUrl.trim(),
    publishableKey: supabasePublishableKey.trim(),
    provider: supabaseProvider.trim() || 'google',
    redirectUri: supabaseRedirectUri.trim() || defaultRedirectUri(),
    createUser: supabaseCreateUser,
  }
  const supabaseStatus = supabaseAuthStatus(supabaseDraft)

  function validateUrl(raw: string): string {
    const trimmed = raw.trim() || DEFAULT_API_URL
    try {
      const parsed = new URL(trimmed)
      if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
        return 'Invalid URL. Must start with https:// or http://'
      }
    } catch {
      return 'Invalid URL. Must start with https:// or http://'
    }
    return ''
  }

  function save() {
    const err = validateUrl(url)
    if (err) { setUrlError(err); return }
    setUrlError('')
    sessionStorage.setItem(API_URL_KEY, url.trim() || DEFAULT_API_URL)
    if (key.trim()) {
      sessionStorage.setItem(API_KEY_KEY, key.trim())
    } else {
      sessionStorage.removeItem(API_KEY_KEY)
    }
    setSaved(true)
    void refreshAll()
    setTimeout(() => setSaved(false), 2500)
  }

  function saveSso() {
    setOidcError('')
    saveOidcConfig(oidcDraft)
    setOidcSaved(true)
    setTimeout(() => setOidcSaved(false), 2500)
  }

  function saveSupabase() {
    saveSupabaseAuthConfig(supabaseDraft)
    setSupabaseSaved(true)
    setTimeout(() => setSupabaseSaved(false), 2500)
  }

  async function discoverSso() {
    setOidcError('')
    setDiscovering(true)
    try {
      const discovered = await discoverOidcFromIssuer(oidcIssuer)
      if (discovered.issuer) setOidcIssuer(discovered.issuer)
      if (discovered.authorizationUrl) setOidcAuthorizationUrl(discovered.authorizationUrl)
      if (discovered.tokenUrl) setOidcTokenUrl(discovered.tokenUrl)
      if (discovered.logoutUrl) setOidcLogoutUrl(discovered.logoutUrl)
    } catch (err) {
      setOidcError(err instanceof Error ? err.message : 'OIDC discovery failed.')
    } finally {
      setDiscovering(false)
    }
  }

  function loadSiem() {
    setSiemError('')
    api.siemProviders()
      .then(d => setSiemProviders(d.providers))
      .catch(e => setSiemError((e as Error).message))
  }

  useEffect(() => {
    if (sessionStorage.getItem(API_KEY_KEY)) loadSiem()
  }, [])

  const storedKey = sessionStorage.getItem(API_KEY_KEY) || ''
  const fingerprint = storedKey ? `...${storedKey.slice(-6)}` : null

  return (
    <div className="dash-main">
      <div className="dash-page-header">
        <div><h1>Settings</h1><p>API connection, customer key, and browser SSO configuration</p></div>
      </div>

      <div className="settings-grid">
        <div className="settings-section">
          <div className="settings-section-title">Gateway Connection</div>
          <div className="form-group">
            <label className="form-label">API Base URL</label>
            <input className="form-input" value={url} onChange={e => setUrl(e.target.value)} placeholder={DEFAULT_API_URL} />
            <div className="form-hint">Default: {DEFAULT_API_URL}</div>
            {urlError && <div className="form-error" style={{ color: 'var(--red)', fontSize: 12, marginTop: 4 }}>{urlError}</div>}
          </div>
          <div className="form-group">
            <label className="form-label">Customer API Key</label>
            <input className="form-input" type="password" value={key} onChange={e => setKey(e.target.value)} placeholder="API key" autoComplete="off" />
            {fingerprint && <div className="key-fingerprint">Active key: {fingerprint}</div>}
            <div className="form-hint">Stored in browser sessionStorage only. Cleared when the tab is closed. Used for scan, MCP inventory, and runtime audit views.</div>
          </div>
          <button className="btn btn-primary" onClick={save}>
            <Save size={13} />{saved ? 'Saved!' : 'Save Settings'}
          </button>
        </div>

        <div className="settings-section">
          <div className="settings-section-title">Browser SSO</div>
          <div className="sso-status-card">
            <ShieldCheck size={18} />
            <div>
              <strong>{session ? 'Signed in' : supabaseStatus.configured ? 'Supabase Auth ready' : oidcStatus.configured ? 'Generic OIDC ready' : 'Configuration needed'}</strong>
              <span>{session ? (session.profile.email || session.profile.subject || 'Admin session active') : 'Supabase Auth is primary. Generic OIDC remains available for Okta/Auth0/Azure later.'}</span>
            </div>
          </div>
          {!supabaseStatus.configured && <div className="inline-note">Supabase missing: {supabaseStatus.missing.join(', ')}</div>}
          {!oidcStatus.configured && <div className="inline-note">Generic OIDC missing: {oidcStatus.missing.join(', ')}</div>}
          {oidcError && <ErrorCard message={oidcError} />}
          <div className="login-actions">
            <button className="btn btn-primary" onClick={saveSupabase}><Save size={13} />{supabaseSaved ? 'Saved!' : 'Save Supabase'}</button>
            <Link className="btn btn-cyan" to="/dashboard/login"><LogIn size={13} />Test Login</Link>
          </div>
        </div>
      </div>

      <div className="settings-section settings-wide">
        <div className="settings-section-title">Supabase Auth Provider</div>
        <div className="oidc-grid">
          <div className="form-group">
            <label className="form-label">Supabase URL</label>
            <input className="form-input" value={supabaseUrl} onChange={e => setSupabaseUrl(e.target.value)} placeholder="https://project-ref.supabase.co" />
          </div>
          <div className="form-group">
            <label className="form-label">Publishable Key</label>
            <input className="form-input" value={supabasePublishableKey} onChange={e => setSupabasePublishableKey(e.target.value)} placeholder="sb_publishable_... or anon public key" autoComplete="off" />
          </div>
          <div className="form-group">
            <label className="form-label">OAuth Provider</label>
            <input className="form-input" value={supabaseProvider} onChange={e => setSupabaseProvider(e.target.value)} placeholder="google" />
          </div>
          <div className="form-group">
            <label className="form-label">Redirect URI</label>
            <input className="form-input" value={supabaseRedirectUri} onChange={e => setSupabaseRedirectUri(e.target.value)} placeholder={defaultRedirectUri()} />
          </div>
          <label className="checkbox-row oidc-grid-wide">
            <input type="checkbox" checked={supabaseCreateUser} onChange={e => setSupabaseCreateUser(e.target.checked)} />
            <span>Allow Supabase to create the user during first passwordless login. Backend admin access is still limited by `OIDC_ADMIN_EMAIL_ALLOWLIST`.</span>
          </label>
        </div>
        <div className="login-actions">
          <button className="btn btn-primary" onClick={saveSupabase}><Save size={13} />{supabaseSaved ? 'Saved!' : 'Save Supabase Auth'}</button>
          <Link className="btn btn-cyan" to="/dashboard/login"><LogIn size={13} />Open Login</Link>
        </div>
        <div className="form-hint">Supabase Auth tokens are verified by the backend using `{supabaseUrl || 'https://project-ref.supabase.co'}/auth/v1/.well-known/jwks.json`. Use a publishable key only, never a service role key.</div>
      </div>

      <div className="settings-section settings-wide">
        <div className="settings-section-title">OIDC Provider</div>
        <div className="form-group">
          <label className="form-label">Issuer URL</label>
          <div className="input-action-row">
            <input className="form-input" value={oidcIssuer} onChange={e => setOidcIssuer(e.target.value)} placeholder="https://idp.example.com/" />
            <button className="btn btn-ghost" onClick={discoverSso} disabled={discovering || !oidcIssuer.trim()}><Search size={13} />{discovering ? 'Discovering' : 'Discover'}</button>
          </div>
          <div className="form-hint">Discovery reads `/.well-known/openid-configuration` and fills endpoints when your provider supports it.</div>
        </div>
        <div className="oidc-grid">
          <div className="form-group">
            <label className="form-label">Authorization Endpoint</label>
            <input className="form-input" value={oidcAuthorizationUrl} onChange={e => setOidcAuthorizationUrl(e.target.value)} placeholder="https://idp.example.com/oauth2/v1/authorize" />
          </div>
          <div className="form-group">
            <label className="form-label">Token Endpoint</label>
            <input className="form-input" value={oidcTokenUrl} onChange={e => setOidcTokenUrl(e.target.value)} placeholder="https://idp.example.com/oauth2/v1/token" />
          </div>
          <div className="form-group">
            <label className="form-label">Client ID</label>
            <input className="form-input" value={oidcClientId} onChange={e => setOidcClientId(e.target.value)} placeholder="public-spa-client-id" autoComplete="off" />
          </div>
          <div className="form-group">
            <label className="form-label">Redirect URI</label>
            <input className="form-input" value={oidcRedirectUri} onChange={e => setOidcRedirectUri(e.target.value)} placeholder={defaultRedirectUri()} />
          </div>
          <div className="form-group">
            <label className="form-label">Scope</label>
            <input className="form-input" value={oidcScope} onChange={e => setOidcScope(e.target.value)} placeholder="openid email profile" />
          </div>
          <div className="form-group">
            <label className="form-label">Audience</label>
            <input className="form-input" value={oidcAudience} onChange={e => setOidcAudience(e.target.value)} placeholder="interlock-admin" />
          </div>
          <div className="form-group oidc-grid-wide">
            <label className="form-label">Logout Endpoint</label>
            <input className="form-input" value={oidcLogoutUrl} onChange={e => setOidcLogoutUrl(e.target.value)} placeholder="Optional end-session endpoint" />
          </div>
        </div>
        <div className="form-hint">For production, the backend must also have matching `OIDC_ISSUER`, `OIDC_AUDIENCE`, `OIDC_JWKS_URL`, and group-to-role mapping. The browser never needs an OIDC client secret.</div>
        <div className="login-actions">
          <button className="btn btn-ghost" onClick={saveSso}><Save size={13} />{oidcSaved ? 'Saved!' : 'Save Generic OIDC'}</button>
        </div>
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
