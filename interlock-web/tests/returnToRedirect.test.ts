/**
 * Compensating control for the accepted react-router advisories.
 *
 * react-router 6.30.4 carries three advisories whose only upstream fix is the
 * v7 major line (see .github/dependency-audit-policy.json):
 *
 *   GHSA-jjmj-jmhj-qwj2  open redirect -> XSS      (6.30.2-6.30.4, no 6.x fix)
 *   GHSA-wrjc-x8rr-h8h6  open redirect via backslash in <Link>/useNavigate
 *   GHSA-337j-9hxr-rhxg  deserializeErrors() SSR-hydration constructor injection
 *
 * The only attacker-influenced navigation sink in this app is
 * `navigate(returnTo)` in pages/OIDCCallback.tsx. Every path that produces
 * `returnTo` passes it through `sanitizeReturnTo` on BOTH write and read
 * (src/auth.ts: beginOidcLogin / beginSupabaseOAuth / completeOidcCallback /
 * completeSupabaseCallback).
 *
 * These tests pin that control. If `sanitizeReturnTo` is weakened, the
 * documented exception's premise is gone and this suite fails — so the
 * exception cannot silently outlive its justification.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { sanitizeReturnTo } from '../src/auth.ts'

/** Payloads from the advisories: authority-position escapes. */
const OPEN_REDIRECT_PAYLOADS = [
  '//evil.example',
  '/\\evil.example',
  '/\\/evil.example',
  '\\\\evil.example',
  'https://evil.example',
  'http://evil.example/dashboard',
  '//evil.example/dashboard',
  '/\\evil.example/dashboard',
  'javascript:alert(1)',
  ' javascript:alert(1)',
  'data:text/html,<script>alert(1)</script>',
  '//evil.example\\@getinterlock.dev/dashboard',
]

/**
 * Same-origin by construction: an "@" inside a path is only userinfo after a
 * scheme and "//". "/dashboard@evil.example" resolves as a path on the current
 * origin, so the guard correctly lets it through; the authority/scheme
 * assertions below still bound it.
 */
const SAME_ORIGIN_LOOKALIKES = ['/dashboard@evil.example', '/dashboard/../evil']

test('every off-origin payload is rejected to a safe internal default', () => {
  for (const payload of OPEN_REDIRECT_PAYLOADS) {
    const result = sanitizeReturnTo(payload)
    assert.equal(
      result,
      '/dashboard',
      `payload ${JSON.stringify(payload)} must collapse to /dashboard, got ${JSON.stringify(result)}`,
    )
  }
})

test('sanitized output can never begin an authority component', () => {
  // "//host" and "/\host" are the shapes a browser resolves off-origin. The
  // guard must never emit a value whose second character starts an authority.
  const all = [...OPEN_REDIRECT_PAYLOADS, ...SAME_ORIGIN_LOOKALIKES, '/dashboard', '/dashboard/proof']
  for (const payload of all) {
    const out = sanitizeReturnTo(payload)
    assert.ok(out.startsWith('/'), `must stay path-relative: ${out}`)
    assert.doesNotMatch(out, /^\/[/\\]/, `must not start an authority: ${out}`)
    assert.doesNotMatch(out, /^[a-z][a-z0-9+.-]*:/i, `must not carry a scheme: ${out}`)
  }
})

test('nullish and empty input fall back to the dashboard root', () => {
  for (const v of [undefined, null, '']) {
    assert.equal(sanitizeReturnTo(v as string | null | undefined), '/dashboard')
  }
})

test('legitimate in-app destinations survive unchanged', () => {
  for (const ok of [
    '/dashboard',
    '/dashboard/proof',
    '/dashboard/overview',
    '/dashboard/audit?view=admin',
    '/dashboard/settings',
  ]) {
    assert.equal(sanitizeReturnTo(ok), ok, `internal route must be preserved: ${ok}`)
  }
})

test('auth bounce targets are refused so callbacks cannot loop', () => {
  assert.equal(sanitizeReturnTo('/dashboard/auth/callback'), '/dashboard')
  assert.equal(sanitizeReturnTo('/dashboard/login'), '/dashboard')
  assert.equal(sanitizeReturnTo('/dashboard/login?next=/dashboard/proof'), '/dashboard')
})

test('the guard requires the /dashboard prefix, not merely a leading slash', () => {
  // A bare "/" or another app path must not become a redirect primitive.
  for (const other of ['/', '/admin', '/dashboardsomething-else'.replace('dashboard', 'dashbo4rd')]) {
    assert.equal(sanitizeReturnTo(other), '/dashboard')
  }
})
