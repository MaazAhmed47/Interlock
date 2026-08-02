/**
 * Compensating control for GHSA-337j-9hxr-rhxg (react-router
 * deserializeErrors() constructor injection during SSR hydration).
 *
 * That advisory is accepted in .github/dependency-audit-policy.json purely
 * because this app is a client-only SPA: deserializeErrors() is reached only on
 * SSR hydration, and interlock-web has no server renderer.
 *
 * If SSR is ever introduced, the exception's premise disappears and the
 * advisory becomes reachable. These tests fail at that moment, forcing the
 * react-router 7.18+ upgrade instead of letting a stale exception stand.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'

const here = fileURLToPath(new URL('.', import.meta.url))
const srcRoot = join(here, '..', 'src')

function sourceFiles(dir: string): string[] {
  const out: string[] = []
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry)
    if (statSync(p).isDirectory()) out.push(...sourceFiles(p))
    else if (/\.(ts|tsx)$/.test(entry)) out.push(p)
  }
  return out
}

/** APIs that would put react-router into an SSR/hydration code path. */
const SSR_MARKERS = [
  'hydrateRoot',
  'StaticRouter',
  'StaticRouterProvider',
  'createStaticHandler',
  'createStaticRouter',
  'renderToString',
  'renderToPipeableStream',
  'renderToReadableStream',
  'deserializeErrors',
]

test('no SSR or hydration entry point exists in the dashboard source', () => {
  const offenders: string[] = []
  for (const file of sourceFiles(srcRoot)) {
    const text = readFileSync(file, 'utf8')
    for (const marker of SSR_MARKERS) {
      if (text.includes(marker)) offenders.push(`${file.replace(srcRoot, 'src')}: ${marker}`)
    }
  }
  assert.deepEqual(
    offenders,
    [],
    'SSR detected — GHSA-337j-9hxr-rhxg becomes reachable and the accepted ' +
      'exception in .github/dependency-audit-policy.json is no longer valid. ' +
      `Upgrade react-router to >=7.18.0 instead.\n${offenders.join('\n')}`,
  )
})

test('the app mounts with client-side createRoot only', () => {
  const main = readFileSync(join(srcRoot, 'main.tsx'), 'utf8')
  assert.match(main, /createRoot\(/, 'expected a client-side createRoot mount')
  assert.doesNotMatch(main, /hydrateRoot/, 'hydrateRoot indicates SSR hydration')
})

test('no server-render dependency is declared', () => {
  const pkg = JSON.parse(readFileSync(join(here, '..', 'package.json'), 'utf8'))
  const all = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) }
  for (const banned of ['react-dom/server', '@remix-run/node', '@remix-run/server-runtime']) {
    assert.ok(!(banned in all), `${banned} would introduce a server renderer`)
  }
})
