/**
 * Permanent authentication-return and internal-navigation security contracts.
 *
 * Every attacker-influenced post-authentication destination passes through
 * `sanitizeReturnTo` when it is stored and again before React Router navigates
 * to it. These tests therefore exercise the canonical route a browser will
 * interpret, including percent decoding, separator handling, case-insensitive
 * route matching, and URL dot-segment normalization.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { sanitizeReturnTo } from '../src/auth.ts'

const FALLBACK = '/dashboard'
const INTERLOCK_ORIGIN = 'https://getinterlock.dev'

const OFF_ORIGIN_AND_AUTHORITY_PAYLOADS = [
  '//evil.example',
  '/\\evil.example',
  '/\\/evil.example',
  '\\\\evil.example',
  'https://evil.example',
  'http://evil.example/dashboard',
  'javascript:alert(1)',
  'data:text/html,<script>alert(1)</script>',
  '//evil.example\\@getinterlock.dev/dashboard',
  '//user:getinterlock.dev@evil.example/dashboard',
  'https://user:getinterlock.dev@evil.example/dashboard',
  '%2F%2Fevil.example/dashboard',
  '%252F%252Fevil.example/dashboard',
  '/%2F%2Fevil.example/dashboard',
  '/%252F%252Fevil.example/dashboard',
  '/dashboard/%2F%2Fevil.example',
  '/dashboard/%252F%252Fevil.example',
]

const AUTH_BOUNCE_PAYLOADS = [
  '/dashboard/login',
  '/dashboard/login/',
  '/dashboard/login/child',
  '/dashboard/LOGIN',
  '/DASHBOARD/Login/child',
  '/dashboard/auth/callback',
  '/dashboard/auth/callback/',
  '/dashboard/auth/callback/child',
  '/DASHBOARD/AUTH/CALLBACK',
  '/dashboard/%6cogin',
  '/dashboard/%4Cogin',
  '/dashboard/%256cogin',
  '/dashboard/%254Cogin',
  '/dashboard/%61uth/callback',
  '/dashboard/%2561uth/callback',
  '/dashboard%2Flogin',
  '/dashboard%252Flogin',
  '/dashboard/%2Flogin',
  '/dashboard/auth%2Fcallback',
  '/dashboard%2Fauth%2Fcallback',
  '/dashboard/%61uth%2Fcallback/child',
]

const MALFORMED_PATHS = [
  '/dashboard/%',
  '/dashboard/%2',
  '/dashboard/%GG',
  '/dashboard/%E0%A4%A',
  '/dashboard/%GG/login',
  '/dashboard/%E0%A4%A/login',
  '/dashboard/proof?value=%GG',
  '/dashboard/proof#value=%2',
]

const BOUNDARY_AND_DOT_SEGMENT_PAYLOADS = [
  '/dashboardish',
  '/dashboard-evil',
  '/dashboard@evil.example',
  '/dashboards',
  '/dashboard/../outside',
  '/dashboard/%2e%2e/outside',
  '/dashboard/%252e%252e/outside',
  '/dashboard/proof/../../outside',
  '/dashboard%69sh',
  '/dashboard%40evil.example',
]

const SLASH_AND_CONTROL_PAYLOADS = [
  '/dashboard/path\\with-mixed/slashes',
  '/dashboard\\login',
  '/dashboard/%5clogin',
  '/dashboard/%255clogin',
  '/dashboard/%5Cauth%2Fcallback',
  '/dashboard//proof',
  '\u0000/dashboard/proof',
  '/dashboard/\u0000proof',
  '/dashboard/%00proof',
  '\r\n/dashboard/proof',
  '/dashboard/proof\u007f',
]

const REJECTED_VALUES = [
  ...OFF_ORIGIN_AND_AUTHORITY_PAYLOADS,
  ...AUTH_BOUNCE_PAYLOADS,
  ...MALFORMED_PATHS,
  ...BOUNDARY_AND_DOT_SEGMENT_PAYLOADS,
  ...SLASH_AND_CONTROL_PAYLOADS,
]

const SAFE_CASES = [
  ['/dashboard', '/dashboard'],
  ['/dashboard/', '/dashboard/'],
  ['/dashboard/proof', '/dashboard/proof'],
  ['/dashboard/overview', '/dashboard/overview'],
  ['/dashboard/settings?tab=security#details', '/dashboard/settings?tab=security#details'],
  ['/dashboard/audit?view=admin#receipt-42', '/dashboard/audit?view=admin#receipt-42'],
  ['/dashboard/settings?returnTo=%252F%252Fevil.example', '/dashboard/settings?returnTo=%252F%252Fevil.example'],
  ['/dashboard/proof#encoded=%2Fdashboard%2Flogin', '/dashboard/proof#encoded=%2Fdashboard%2Flogin'],
  ['/dashboard/%70roof', '/dashboard/proof'],
  ['/%64ashboard/overview', '/dashboard/overview'],
  ['/DASHBOARD/Proof', '/dashboard/Proof'],
  ['/dashboard/%E2%9C%93', '/dashboard/%E2%9C%93'],
] as const

function fullyDecodePathname(pathname: string) {
  let decoded = pathname
  for (let pass = 0; pass < 8; pass += 1) {
    const next = decodeURIComponent(decoded)
    if (next === decoded) return decoded
    decoded = next
  }
  throw new Error(`pathname did not stabilize: ${pathname}`)
}

function assertRejected(values: readonly string[]) {
  const unexpected = values
    .map(value => ({ value, result: sanitizeReturnTo(value) }))
    .filter(({ result }) => result !== FALLBACK)
  assert.deepEqual(unexpected, [], 'every listed return target must collapse to /dashboard')
}

test('off-origin and authority-shaped return targets fail closed', () => {
  assertRejected(OFF_ORIGIN_AND_AUTHORITY_PAYLOADS)
})

test('canonical and encoded authentication bounce routes fail closed', () => {
  assertRejected(AUTH_BOUNCE_PAYLOADS)
})

test('malformed percent encoding fails closed', () => {
  assertRejected(MALFORMED_PATHS)
})

test('dashboard boundary confusion and escaping dot segments fail closed', () => {
  assertRejected(BOUNDARY_AND_DOT_SEGMENT_PAYLOADS)
})

test('slash confusion and control characters fail closed', () => {
  assertRejected(SLASH_AND_CONTROL_PAYLOADS)
})

test('nullish and empty return targets fail closed', () => {
  for (const value of [undefined, null, '']) {
    assert.equal(sanitizeReturnTo(value), FALLBACK)
  }
})

test('safe dashboard routes become canonical loadable navigation targets', () => {
  for (const [value, expected] of SAFE_CASES) {
    assert.equal(sanitizeReturnTo(value), expected, `unexpected canonical output for ${value}`)
  }
})

test('accepted outputs retain the exact dashboard boundary and Interlock origin', () => {
  const candidates = [...REJECTED_VALUES, ...SAFE_CASES.map(([value]) => value)]
  for (const value of candidates) {
    const target = sanitizeReturnTo(value)
    const parsed = new URL(target, INTERLOCK_ORIGIN)
    const decodedPathname = fullyDecodePathname(parsed.pathname)
    const route = decodedPathname.toLowerCase()

    assert.equal(parsed.origin, INTERLOCK_ORIGIN)
    assert.ok(route === '/dashboard' || route.startsWith('/dashboard/'), `invalid boundary: ${target}`)
    assert.doesNotMatch(target, /\\/, `raw backslash survived: ${target}`)
    assert.doesNotMatch(decodedPathname, /\\/, `decoded backslash survived: ${target}`)
    assert.doesNotMatch(route, /^\/dashboard\/login(?:\/|$)/, `login bounce survived: ${target}`)
    assert.doesNotMatch(route, /^\/dashboard\/auth\/callback(?:\/|$)/, `callback bounce survived: ${target}`)
    assert.equal(new URL(parsed.href).href, parsed.href, `browser URL is not stable: ${target}`)
  }
})

test('query strings and fragments are preserved without path interpretation', () => {
  const target = '/dashboard/settings?next=%2Fdashboard%2Flogin&raw=%252F%252Fevil.example#%2Fdashboard%2Fauth%2Fcallback'
  assert.equal(sanitizeReturnTo(target), target)
})

test('excessive repeated encoding fails closed within a fixed work bound', () => {
  let target = '/dashboard/login'
  for (let pass = 0; pass < 12; pass += 1) target = encodeURIComponent(target).replace(/^%2F/i, '/')
  assert.equal(sanitizeReturnTo(target), FALLBACK)
})
