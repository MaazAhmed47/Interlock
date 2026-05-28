import { useEffect, useState } from 'react'

export const OIDC_KEYS = {
  issuer: 'interlock_oidc_issuer',
  authorizationUrl: 'interlock_oidc_authorization_url',
  tokenUrl: 'interlock_oidc_token_url',
  clientId: 'interlock_oidc_client_id',
  redirectUri: 'interlock_oidc_redirect_uri',
  scope: 'interlock_oidc_scope',
  audience: 'interlock_oidc_audience',
  logoutUrl: 'interlock_oidc_logout_url',
} as const

export const SUPABASE_AUTH_KEYS = {
  url: 'interlock_supabase_url',
  publishableKey: 'interlock_supabase_publishable_key',
  provider: 'interlock_supabase_provider',
  redirectUri: 'interlock_supabase_redirect_uri',
  createUser: 'interlock_supabase_create_user',
} as const

const AUTH_SESSION_KEY = 'interlock_auth_session'
const OIDC_STATE_KEY = 'interlock_oidc_state'
const OIDC_VERIFIER_KEY = 'interlock_oidc_verifier'
const OIDC_NONCE_KEY = 'interlock_oidc_nonce'
const OIDC_RETURN_TO_KEY = 'interlock_oidc_return_to'
const SUPABASE_RETURN_TO_KEY = 'interlock_supabase_return_to'
const AUTH_CHANGED_EVENT = 'interlock-auth-changed'
const CLOCK_SKEW_MS = 30_000

type EnvMap = Record<string, string | undefined>

export type OidcConfig = {
  issuer: string
  authorizationUrl: string
  tokenUrl: string
  clientId: string
  redirectUri: string
  scope: string
  audience: string
  logoutUrl: string
}

export type SupabaseAuthConfig = {
  url: string
  publishableKey: string
  provider: string
  redirectUri: string
  createUser: boolean
}

export type AuthProfile = {
  subject: string
  email: string
  name: string
  role: string
  groups: string[]
  issuer: string
  audience: string
}

export type AuthSession = {
  accessToken: string
  idToken?: string
  tokenType: string
  expiresAt: number | null
  issuedAt: number
  scope: string
  profile: AuthProfile
}

type TokenResponse = {
  access_token?: string
  id_token?: string
  token_type?: string
  expires_in?: number
  scope?: string
  error?: string
  error_description?: string
}

function envValue(key: string) {
  const env = import.meta.env as unknown as EnvMap
  return (env[key] || '').trim()
}

function storedOrEnv(storageKey: string, envKey: string, fallback = '') {
  return (localStorage.getItem(storageKey) || envValue(envKey) || fallback).trim()
}

export function defaultRedirectUri() {
  return `${window.location.origin}/dashboard/auth/callback`
}

export function getOidcConfig(): OidcConfig {
  return {
    issuer: storedOrEnv(OIDC_KEYS.issuer, 'VITE_INTERLOCK_OIDC_ISSUER'),
    authorizationUrl: storedOrEnv(OIDC_KEYS.authorizationUrl, 'VITE_INTERLOCK_OIDC_AUTHORIZATION_URL'),
    tokenUrl: storedOrEnv(OIDC_KEYS.tokenUrl, 'VITE_INTERLOCK_OIDC_TOKEN_URL'),
    clientId: storedOrEnv(OIDC_KEYS.clientId, 'VITE_INTERLOCK_OIDC_CLIENT_ID'),
    redirectUri: storedOrEnv(OIDC_KEYS.redirectUri, 'VITE_INTERLOCK_OIDC_REDIRECT_URI', defaultRedirectUri()),
    scope: storedOrEnv(OIDC_KEYS.scope, 'VITE_INTERLOCK_OIDC_SCOPE', 'openid email profile'),
    audience: storedOrEnv(OIDC_KEYS.audience, 'VITE_INTERLOCK_OIDC_AUDIENCE'),
    logoutUrl: storedOrEnv(OIDC_KEYS.logoutUrl, 'VITE_INTERLOCK_OIDC_LOGOUT_URL'),
  }
}

export function saveOidcConfig(config: Partial<OidcConfig>) {
  const entries: [keyof OidcConfig, string][] = [
    ['issuer', OIDC_KEYS.issuer],
    ['authorizationUrl', OIDC_KEYS.authorizationUrl],
    ['tokenUrl', OIDC_KEYS.tokenUrl],
    ['clientId', OIDC_KEYS.clientId],
    ['redirectUri', OIDC_KEYS.redirectUri],
    ['scope', OIDC_KEYS.scope],
    ['audience', OIDC_KEYS.audience],
    ['logoutUrl', OIDC_KEYS.logoutUrl],
  ]

  entries.forEach(([field, storageKey]) => {
    const value = (config[field] || '').trim()
    if (value) localStorage.setItem(storageKey, value)
    else localStorage.removeItem(storageKey)
  })
}

export function oidcConfigStatus(config: OidcConfig = getOidcConfig()) {
  const missing: string[] = []
  if (!config.authorizationUrl) missing.push('authorization endpoint')
  if (!config.tokenUrl) missing.push('token endpoint')
  if (!config.clientId) missing.push('client ID')
  if (!config.redirectUri) missing.push('redirect URI')
  return { configured: missing.length === 0, missing }
}

export function getSupabaseAuthConfig(): SupabaseAuthConfig {
  return {
    url: storedOrEnv(SUPABASE_AUTH_KEYS.url, 'VITE_SUPABASE_URL').replace(/\/+$/, ''),
    publishableKey: storedOrEnv(SUPABASE_AUTH_KEYS.publishableKey, 'VITE_SUPABASE_PUBLISHABLE_KEY'),
    provider: storedOrEnv(SUPABASE_AUTH_KEYS.provider, 'VITE_SUPABASE_OAUTH_PROVIDER', 'google'),
    redirectUri: storedOrEnv(SUPABASE_AUTH_KEYS.redirectUri, 'VITE_SUPABASE_REDIRECT_URI', defaultRedirectUri()),
    createUser: (localStorage.getItem(SUPABASE_AUTH_KEYS.createUser) || envValue('VITE_SUPABASE_CREATE_USER') || 'true').toLowerCase() !== 'false',
  }
}

export function saveSupabaseAuthConfig(config: Partial<SupabaseAuthConfig>) {
  const url = (config.url || '').trim().replace(/\/+$/, '')
  const publishableKey = (config.publishableKey || '').trim()
  const provider = (config.provider || '').trim()
  const redirectUri = (config.redirectUri || '').trim()
  if (url) localStorage.setItem(SUPABASE_AUTH_KEYS.url, url)
  else localStorage.removeItem(SUPABASE_AUTH_KEYS.url)
  if (publishableKey) localStorage.setItem(SUPABASE_AUTH_KEYS.publishableKey, publishableKey)
  else localStorage.removeItem(SUPABASE_AUTH_KEYS.publishableKey)
  if (provider) localStorage.setItem(SUPABASE_AUTH_KEYS.provider, provider)
  else localStorage.removeItem(SUPABASE_AUTH_KEYS.provider)
  if (redirectUri) localStorage.setItem(SUPABASE_AUTH_KEYS.redirectUri, redirectUri)
  else localStorage.removeItem(SUPABASE_AUTH_KEYS.redirectUri)
  localStorage.setItem(SUPABASE_AUTH_KEYS.createUser, config.createUser === false ? 'false' : 'true')
}

export function supabaseAuthStatus(config: SupabaseAuthConfig = getSupabaseAuthConfig()) {
  const missing: string[] = []
  if (!config.url) missing.push('Supabase URL')
  if (!config.publishableKey) missing.push('publishable key')
  if (!config.redirectUri) missing.push('redirect URI')
  return { configured: missing.length === 0, missing }
}

export function sanitizeReturnTo(value?: string | null) {
  if (!value || !value.startsWith('/dashboard')) return '/dashboard'
  if (value.includes('/dashboard/auth/callback') || value.includes('/dashboard/login')) return '/dashboard'
  return value
}

function base64Url(bytes: Uint8Array) {
  let binary = ''
  bytes.forEach(byte => { binary += String.fromCharCode(byte) })
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function randomString(size = 32) {
  const bytes = new Uint8Array(size)
  window.crypto.getRandomValues(bytes)
  return base64Url(bytes)
}

async function pkceChallenge(verifier: string) {
  const bytes = new TextEncoder().encode(verifier)
  const digest = await window.crypto.subtle.digest('SHA-256', bytes)
  return base64Url(new Uint8Array(digest))
}

export function parseJwtPayload(token?: string | null): Record<string, unknown> | null {
  if (!token) return null
  const [, payload] = token.split('.')
  if (!payload) return null
  try {
    const padded = payload.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - payload.length % 4) % 4)
    const bytes = Uint8Array.from(atob(padded), char => char.charCodeAt(0))
    return JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>
  } catch {
    return null
  }
}

function claimString(claims: Record<string, unknown>, key: string) {
  const value = claims[key]
  return typeof value === 'string' ? value : ''
}

function claimArray(claims: Record<string, unknown>, key: string) {
  const value = claims[key]
  if (Array.isArray(value)) return value.map(String).filter(Boolean)
  if (typeof value === 'string' && value) return [value]
  return []
}

function audienceString(value: unknown) {
  if (Array.isArray(value)) return value.map(String).join(', ')
  return typeof value === 'string' ? value : ''
}

function profileFromClaims(claims: Record<string, unknown>): AuthProfile {
  return {
    subject: claimString(claims, 'sub'),
    email: claimString(claims, 'email'),
    name: claimString(claims, 'name') || claimString(claims, 'preferred_username'),
    role: claimString(claims, 'interlock_role') || claimString(claims, 'role'),
    groups: claimArray(claims, 'groups'),
    issuer: claimString(claims, 'iss'),
    audience: audienceString(claims.aud),
  }
}

// sessionStorage intentionally: auth tokens are cleared on tab close, limiting exposure window
function saveAuthSession(session: AuthSession) {
  sessionStorage.setItem(AUTH_SESSION_KEY, JSON.stringify(session))
  window.dispatchEvent(new CustomEvent(AUTH_CHANGED_EVENT))
}

export function getAuthSession(): AuthSession | null {
  try {
    const raw = sessionStorage.getItem(AUTH_SESSION_KEY)
    if (!raw) return null
    const session = JSON.parse(raw) as AuthSession
    if (!session.accessToken) return null
    if (session.expiresAt && session.expiresAt <= Date.now() + CLOCK_SKEW_MS) {
      sessionStorage.removeItem(AUTH_SESSION_KEY)
      return null
    }
    return session
  } catch {
    sessionStorage.removeItem(AUTH_SESSION_KEY)
    return null
  }
}

export function clearAuthSession() {
  sessionStorage.removeItem(AUTH_SESSION_KEY)
  sessionStorage.removeItem(OIDC_STATE_KEY)
  sessionStorage.removeItem(OIDC_VERIFIER_KEY)
  sessionStorage.removeItem(OIDC_NONCE_KEY)
  sessionStorage.removeItem(OIDC_RETURN_TO_KEY)
  sessionStorage.removeItem(SUPABASE_RETURN_TO_KEY)
  window.dispatchEvent(new CustomEvent(AUTH_CHANGED_EVENT))
}

export function authDisplayName(session: AuthSession | null) {
  if (!session) return ''
  return session.profile.email || session.profile.name || session.profile.subject || 'Signed in admin'
}

export function useAuthSession() {
  const [session, setSession] = useState<AuthSession | null>(() => getAuthSession())

  useEffect(() => {
    const sync = () => setSession(getAuthSession())
    window.addEventListener(AUTH_CHANGED_EVENT, sync)
    window.addEventListener('storage', sync)
    const timer = window.setInterval(sync, 30_000)
    return () => {
      window.removeEventListener(AUTH_CHANGED_EVENT, sync)
      window.removeEventListener('storage', sync)
      window.clearInterval(timer)
    }
  }, [])

  return session
}

export async function beginSupabaseOAuth(provider?: string, returnTo?: string) {
  const config = getSupabaseAuthConfig()
  const status = supabaseAuthStatus(config)
  if (!status.configured) throw new Error(`Supabase Auth is missing ${status.missing.join(', ')}.`)
  const selectedProvider = (provider || config.provider || 'google').trim()
  sessionStorage.setItem(SUPABASE_RETURN_TO_KEY, sanitizeReturnTo(returnTo || `${window.location.pathname}${window.location.search}`))
  const params = new URLSearchParams({
    provider: selectedProvider,
    redirect_to: config.redirectUri,
  })
  window.location.assign(`${config.url}/auth/v1/authorize?${params.toString()}`)
}

export async function requestSupabaseMagicLink(email: string) {
  const config = getSupabaseAuthConfig()
  const status = supabaseAuthStatus(config)
  if (!status.configured) throw new Error(`Supabase Auth is missing ${status.missing.join(', ')}.`)
  const cleanEmail = email.trim().toLowerCase()
  if (!/^\S+@\S+\.\S+$/.test(cleanEmail)) throw new Error('Enter a valid email address.')
  sessionStorage.setItem(SUPABASE_RETURN_TO_KEY, '/dashboard/audit?view=admin')

  const res = await fetch(`${config.url}/auth/v1/otp`, {
    method: 'POST',
    headers: {
      apikey: config.publishableKey,
      Authorization: `Bearer ${config.publishableKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      email: cleanEmail,
      create_user: config.createUser,
      redirect_to: config.redirectUri,
    }),
  })
  if (!res.ok) {
    const data = await res.json().catch(() => ({})) as { msg?: string; message?: string; error_description?: string; error?: string }
    throw new Error(data.error_description || data.message || data.msg || data.error || `Supabase Auth returned HTTP ${res.status}`)
  }
}

function completeSupabaseCallback(callbackUrl: URL) {
  const hashParams = new URLSearchParams(callbackUrl.hash.replace(/^#/, ''))
  const searchParams = callbackUrl.searchParams
  const error = hashParams.get('error') || searchParams.get('error')
  if (error) {
    throw new Error(hashParams.get('error_description') || searchParams.get('error_description') || error)
  }

  const accessToken = hashParams.get('access_token') || searchParams.get('access_token')
  if (!accessToken) return null
  const idToken = hashParams.get('id_token') || searchParams.get('id_token') || undefined
  const tokenType = hashParams.get('token_type') || searchParams.get('token_type') || 'Bearer'
  const expiresInRaw = hashParams.get('expires_in') || searchParams.get('expires_in')
  const expiresIn = expiresInRaw ? Number(expiresInRaw) : null
  const claims = parseJwtPayload(accessToken) || parseJwtPayload(idToken) || {}
  const expMs = typeof claims.exp === 'number' ? claims.exp * 1000 : null
  const session: AuthSession = {
    accessToken,
    idToken,
    tokenType,
    expiresAt: Number.isFinite(expiresIn) && expiresIn ? Date.now() + Number(expiresIn) * 1000 : expMs,
    issuedAt: Date.now(),
    scope: 'supabase-auth',
    profile: profileFromClaims(claims),
  }
  saveAuthSession(session)
  const returnTo = sanitizeReturnTo(sessionStorage.getItem(SUPABASE_RETURN_TO_KEY) || '/dashboard/audit?view=admin')
  sessionStorage.removeItem(SUPABASE_RETURN_TO_KEY)
  return { session, returnTo }
}

export async function discoverOidcFromIssuer(issuerUrl: string): Promise<Partial<OidcConfig>> {
  const issuer = issuerUrl.trim().replace(/\/+$/, '')
  if (!issuer) throw new Error('Enter an issuer URL first.')

  const res = await fetch(`${issuer}/.well-known/openid-configuration`)
  if (!res.ok) throw new Error(`Discovery failed with HTTP ${res.status}`)
  const data = await res.json() as Record<string, unknown>

  return {
    issuer,
    authorizationUrl: typeof data.authorization_endpoint === 'string' ? data.authorization_endpoint : '',
    tokenUrl: typeof data.token_endpoint === 'string' ? data.token_endpoint : '',
    logoutUrl: typeof data.end_session_endpoint === 'string' ? data.end_session_endpoint : '',
  }
}

export async function beginOidcLogin(returnTo?: string) {
  const config = getOidcConfig()
  const status = oidcConfigStatus(config)
  if (!status.configured) {
    throw new Error(`SSO is missing ${status.missing.join(', ')}.`)
  }

  const state = randomString(24)
  const nonce = randomString(24)
  const verifier = randomString(64)
  const challenge = await pkceChallenge(verifier)
  const target = sanitizeReturnTo(returnTo || `${window.location.pathname}${window.location.search}`)

  sessionStorage.setItem(OIDC_STATE_KEY, state)
  sessionStorage.setItem(OIDC_NONCE_KEY, nonce)
  sessionStorage.setItem(OIDC_VERIFIER_KEY, verifier)
  sessionStorage.setItem(OIDC_RETURN_TO_KEY, target)

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    scope: config.scope,
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  })
  if (config.audience) params.set('audience', config.audience)

  window.location.assign(`${config.authorizationUrl}?${params.toString()}`)
}

export async function completeOidcCallback(callbackHref = window.location.href) {
  const callbackUrl = new URL(callbackHref)
  const supabaseSession = completeSupabaseCallback(callbackUrl)
  if (supabaseSession) return supabaseSession

  const error = callbackUrl.searchParams.get('error')
  if (error) {
    const description = callbackUrl.searchParams.get('error_description') || error
    throw new Error(description)
  }

  const code = callbackUrl.searchParams.get('code')
  const state = callbackUrl.searchParams.get('state')
  const expectedState = sessionStorage.getItem(OIDC_STATE_KEY)
  const verifier = sessionStorage.getItem(OIDC_VERIFIER_KEY)
  if (!code) throw new Error('OIDC callback did not include an authorization code.')
  if (!state || !expectedState || state !== expectedState) throw new Error('OIDC state mismatch. Start login again.')
  if (!verifier) throw new Error('Missing PKCE verifier. Start login again.')

  const config = getOidcConfig()
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: config.clientId,
    code,
    redirect_uri: config.redirectUri,
    code_verifier: verifier,
  })

  const res = await fetch(config.tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  })
  const token = await res.json().catch(() => ({})) as TokenResponse
  if (!res.ok || token.error) {
    throw new Error(token.error_description || token.error || `Token exchange failed with HTTP ${res.status}`)
  }

  const accessToken = token.access_token || token.id_token || ''
  if (!accessToken) throw new Error('OIDC provider did not return an access token.')

  const claims = parseJwtPayload(token.id_token || accessToken) || {}
  const expMs = typeof claims.exp === 'number' ? claims.exp * 1000 : null
  const expiresAt = typeof token.expires_in === 'number' ? Date.now() + token.expires_in * 1000 : expMs
  const session: AuthSession = {
    accessToken,
    idToken: token.id_token,
    tokenType: token.token_type || 'Bearer',
    expiresAt,
    issuedAt: Date.now(),
    scope: token.scope || config.scope,
    profile: profileFromClaims(claims),
  }

  saveAuthSession(session)
  const returnTo = sanitizeReturnTo(sessionStorage.getItem(OIDC_RETURN_TO_KEY))
  sessionStorage.removeItem(OIDC_STATE_KEY)
  sessionStorage.removeItem(OIDC_VERIFIER_KEY)
  sessionStorage.removeItem(OIDC_NONCE_KEY)
  sessionStorage.removeItem(OIDC_RETURN_TO_KEY)
  sessionStorage.removeItem(SUPABASE_RETURN_TO_KEY)
  return { session, returnTo }
}

export function redirectToOidcLogout(fallback = '/dashboard/login') {
  const session = getAuthSession()
  const config = getOidcConfig()
  clearAuthSession()
  if (!config.logoutUrl) return false

  const params = new URLSearchParams({ post_logout_redirect_uri: `${window.location.origin}${fallback}` })
  if (session?.idToken) params.set('id_token_hint', session.idToken)
  window.location.assign(`${config.logoutUrl}?${params.toString()}`)
  return true
}
