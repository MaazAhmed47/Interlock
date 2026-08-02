import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'
import {
  DASHBOARD_OVERVIEW_PATH,
  PUBLIC_DASHBOARD_LANDING,
  isProofRoutePath,
} from '../src/routePaths.ts'

const here = fileURLToPath(new URL('.', import.meta.url))
const webRoot = join(here, '..')
const source = (path: string) => readFileSync(join(webRoot, path), 'utf8')

const app = source('src/App.tsx')
const main = source('src/main.tsx')
const layout = source('src/components/DashLayout.tsx')

test('the dashboard remains a client-only declarative BrowserRouter application', () => {
  assert.match(main, /<BrowserRouter>/)
  assert.match(app, /<Routes>/)
  assert.doesNotMatch(main + app, /createBrowserRouter|RouterProvider|HydratedRouter/)
  assert.doesNotMatch(source('vite.config.ts'), /@react-router\/dev/)
})

test('the complete dashboard route table remains wired to its intended pages', () => {
  const routes = [
    ['overview', 'Dashboard'],
    ['proof', 'DriftProof'],
    ['scan', 'Scan'],
    ['mcp', 'MCPGateway'],
    ['audit', 'Audit'],
    ['settings', 'Settings'],
    ['login', 'Login'],
    ['auth/callback', 'OIDCCallback'],
  ] as const

  assert.match(app, /<Route path="\/dashboard" element=\{<DashLayout \/>\}>/)
  for (const [path, element] of routes) {
    const pathPattern = path === 'overview'
      ? 'path=\\{DASHBOARD_OVERVIEW_PATH\\.replace\\(\'\\/dashboard\\/\', \'\'\\)\\}'
      : `path="${path.replace('/', '\\/')}"`
    assert.match(
      app,
      new RegExp(`<Route ${pathPattern} element=\\{<${element} \\/>\\} \\/>`),
      `${path} must render ${element}`,
    )
  }
})

test('entry and unknown dashboard routes replace history with the proof route', () => {
  assert.equal(PUBLIC_DASHBOARD_LANDING, '/dashboard/proof')
  assert.equal(new URL(PUBLIC_DASHBOARD_LANDING, 'https://getinterlock.dev/unknown?keep=1#frag').search, '')
  assert.equal(new URL(PUBLIC_DASHBOARD_LANDING, 'https://getinterlock.dev/unknown?keep=1#frag').hash, '')
  assert.match(app, /<Route index element=\{<Navigate to=\{PUBLIC_DASHBOARD_LANDING\} replace \/>\} \/>/)
  assert.match(app, /<Route path="\*" element=\{<Navigate to=\{PUBLIC_DASHBOARD_LANDING\} replace \/>\} \/>/)
})

test('proof routes alone suppress the dashboard topbar', () => {
  assert.equal(isProofRoutePath('/dashboard/proof'), true)
  assert.equal(isProofRoutePath('/dashboard/proof/'), true)
  for (const path of ['/dashboard/overview', '/dashboard/mcp', '/dashboard/scan', '/dashboard/settings']) {
    assert.equal(isProofRoutePath(path), false)
  }
  assert.match(layout, /const isProofRoute = isProofRoutePath\(location\.pathname\)/)
  assert.match(layout, /\{!isProofRoute && \([\s\S]*?className="dash-topbar"/)
})

test('logo and dashboard navigation targets remain explicit internal destinations', () => {
  assert.ok((layout.match(/href="\/"/g) ?? []).length >= 2, 'desktop and mobile logos must return to the landing page')
  for (const path of [
    '/dashboard/proof',
    '/dashboard/scan',
    '/dashboard/mcp',
    '/dashboard/audit',
    '/dashboard/login',
    '/dashboard/settings',
  ]) {
    assert.match(layout, new RegExp(`to: '${path}'`), `navigation must retain ${path}`)
  }
  assert.equal(DASHBOARD_OVERVIEW_PATH, '/dashboard/overview')
})

test('development, container, and Vercel hosting retain nested dashboard fallbacks', () => {
  assert.match(source('vite.config.ts'), /path\.startsWith\('\/dashboard\/'\)/)
  assert.match(source('nginx.conf'), /try_files \$uri \$uri\/ \/dashboard\/index\.html/)
  const vercel = JSON.parse(source('vercel.json'))
  assert.deepEqual(vercel.rewrites, [
    { source: '/dashboard', destination: '/dashboard/index.html' },
    { source: '/dashboard/(.*)', destination: '/dashboard/index.html' },
  ])
})
