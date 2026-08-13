/**
 * Public-truth contracts for the landing page and the guided drift proof.
 *
 * Interlock makes two different proof claims and they must never read as one
 * call:
 *
 *   Default evaluator  — approved surface -> material capability/surface change
 *                        found at re-discovery -> quarantine -> the NEXT
 *                        gateway-mediated call is held before upstream
 *                        forwarding -> receipt verified.
 *   Advanced probe     — a controlled non-production probe IS forwarded, the
 *                        upstream answers 200 where 403 was expected, and that
 *                        observation is what triggers quarantine. Only LATER
 *                        calls are held.
 *
 * A request cannot return an observed upstream 200 unless it was forwarded, so
 * these tests assert the two stories stay separable rather than banning a
 * phrase. They parse narrowly-scoped regions keyed off stable ids.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { DASHBOARD_OVERVIEW_PATH, PUBLIC_DASHBOARD_LANDING } from '../src/routePaths.ts'

const here = fileURLToPath(new URL('.', import.meta.url))
const landing = readFileSync(`${here}../index.html`, 'utf8')
const driftProof = readFileSync(`${here}../src/pages/DriftProof.tsx`, 'utf8')
const readme = readFileSync(`${here}../../README.md`, 'utf8')
const evaluatorSource = readFileSync(
  `${here}../../demo/offline/evaluator_journey.py`,
  'utf8',
)

const EVALUATOR_WALKTHROUGH =
  'https://github.com/MaazAhmed47/Interlock/blob/main/docs/evaluator-quickstart.md'

/**
 * Read the evaluator's identity from the EXECUTABLE runner, never from a
 * constant pinned in this file. If demo/offline/evaluator_journey.py switches
 * tools, these tests start demanding the new name on the public pages, so a
 * stale website fails instead of silently disagreeing with the proof it claims
 * to depict.
 */
function evaluatorConstant(name: string): string {
  const found = evaluatorSource.match(new RegExp(`^${name}\\s*=\\s*"([^"]+)"`, 'm'))
  assert.ok(found, `could not read ${name} from demo/offline/evaluator_journey.py`)
  const value = found[1].trim()
  // Guard against a vacuous pass if the parse ever degrades to an empty match.
  assert.ok(value.length > 2, `${name} parsed as implausible value ${JSON.stringify(value)}`)
  return value
}

const EVALUATOR_TOOL = evaluatorConstant('TOOL_NAME')
const EVALUATOR_CONTROL_TOOL = evaluatorConstant('CONTROL_TOOL')

test('public project surfaces identify the maintainer and route readers by role', () => {
  assert.match(readme, /### Start here by role/)
  assert.match(readme, /docs\/mcp-runtime-security-threat-model\.md/)
  assert.match(readme, /Maintainer: \[Maaz Ahmed\]/)
  assert.doesNotMatch(readme, /img\.shields\.io\/badge\/quality-/)

  const founder = regionById(landing, 'founder')
  assert.match(founder, /Built and maintained by Maaz Ahmed/)
  assert.match(founder, /Founder &amp; Engineer, Interlock/)
  assert.match(founder, /linkedin\.com\/in\/maaz-ahmed-abb422295/)
  assert.match(founder, /mailto:maaz@getinterlock\.dev/)
  assert.match(landing, /property="og:image" content="https:\/\/getinterlock\.dev\/interlock-social-preview\.png"/)
  assert.match(landing, /name="twitter:image" content="https:\/\/getinterlock\.dev\/interlock-social-preview\.png"/)
  assert.match(landing, /property="og:image:alt"/)
  assert.match(landing, /name="twitter:image:alt"/)
})

test('landing page CSS uses only declared custom properties', () => {
  const declared = new Set(Array.from(landing.matchAll(/(--[\w-]+)\s*:/g), (match) => match[1]))
  const used = new Set(Array.from(landing.matchAll(/var\((--[\w-]+)/g), (match) => match[1]))
  assert.deepEqual([...used].filter((token) => !declared.has(token)), [])
})

test('closing call to action closes its wrapper before the section', () => {
  assert.match(landing, /<div class="founder-block[\s\S]*?<\/div>\s*<\/div>\s*<\/section>\s*<footer>/)
  assert.doesNotMatch(landing, /<\/section>\s*<\/div>\s*<footer>/)
})

test('README labels the local behavioral proof without implying an external live system', () => {
  assert.match(readme, /^## Local behavioral drift proof$/m)
  assert.doesNotMatch(readme, /^## Live-proven behavioral drift$/m)
  assert.match(readme, /\(#local-behavioral-drift-proof\)/)
})

/** Slice an element's markup by id, balancing the given tag. */
function regionById(source: string, id: string, tag = 'div'): string {
  const start = source.indexOf(`id="${id}"`)
  assert.notEqual(start, -1, `expected a stable region with id="${id}"`)
  const openTag = source.lastIndexOf(`<${tag}`, start)
  assert.notEqual(openTag, -1, `id="${id}" is not on a <${tag}> element`)

  const open = new RegExp(`<${tag}[\\s>]`, 'g')
  const close = new RegExp(`</${tag}>`, 'g')
  open.lastIndex = openTag + 1
  close.lastIndex = openTag + 1

  let depth = 1
  let cursor = openTag + 1
  while (depth > 0) {
    open.lastIndex = cursor
    close.lastIndex = cursor
    const nextOpen = open.exec(source)
    const nextClose = close.exec(source)
    assert.ok(nextClose, `unbalanced <${tag}> for id="${id}"`)
    if (nextOpen && nextOpen.index < nextClose.index) {
      depth += 1
      cursor = nextOpen.index + 1
    } else {
      depth -= 1
      cursor = nextClose.index + 1
      if (depth === 0) return source.slice(openTag, nextClose.index + `</${tag}>`.length)
    }
  }
  throw new Error(`unreachable region scan for id="${id}"`)
}

/**
 * Visible prose only. <style>/<script> bodies survive naive tag-stripping and
 * would otherwise feed CSS token comments (e.g. "red = held/quarantined") into
 * the copy scanners as if they were public claims.
 */
const text = (html: string) =>
  html
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()

const defaultFlow = text(regionById(landing, 'default-proof-flow'))
const defaultEvidence = text(regionById(landing, 'default-evidence-diff'))
const advancedSection = text(regionById(landing, 'behavioral-probe', 'section'))
const offlineClaims = text(regionById(landing, 'offline-proof-claims'))
const landingText = text(landing)
const driftProofText = driftProof.replace(/\s+/g, ' ')

/**
 * Quarantine in Interlock is a per-(server_id, tool_name) row: core/db.py
 * updates `mcp_tool_metadata ... WHERE server_id = ? AND tool_name = ?`, and
 * core/mcp_gateway.py only returns `tool_quarantined` for that stored tool.
 * The evaluator asserts `blocked_tools == 1` while its control tool stays
 * usable. So every holding claim must name WHICH tool is held — an unscoped
 * claim reads as "Interlock pauses all gateway traffic", which is false.
 *
 * This scans for holding claims and requires a tool qualifier near each one,
 * rather than banning any single phrase.
 */
const HOLD_CLAIM = /\b(?:held|hold|holding|holds)\b/gi
const TOOL_QUALIFIER =
  /\bto (?:that|the|this|its|it|such) (?:same )?(?:tool|quarantined tool)\b|\bto (?:that same )?[a-z_]*read_file\b|\bcalls? to [a-z_]+\b|\bto it\b|\bthat tool\b|\bquarantined tool\b/i
/** Negated or meta uses ("is not held", "the held call") make no scope claim. */
const NOT_A_SCOPE_CLAIM = /\bnot held\b|\bnot be held\b/i

function unscopedHoldingClaims(source: string): string[] {
  const offenders: string[] = []
  for (const match of source.matchAll(HOLD_CLAIM)) {
    const start = Math.max(0, match.index - 170)
    const window = source.slice(start, match.index + 170)
    if (NOT_A_SCOPE_CLAIM.test(window)) continue
    // Only claims about forwarding/quarantine need tool scope.
    if (!/forward|quarantin|gateway|call/i.test(window)) continue
    if (TOOL_QUALIFIER.test(window)) continue
    offenders.push(window.trim())
  }
  return offenders
}

/* ---------- the default flow is surface / capability drift ---------- */

test('default landing flow presents surface/capability drift evidence', () => {
  assert.match(defaultFlow, /capability drift detected at re-discovery/i)
  // The declared boundary widened while the tool identity stayed the same.
  assert.match(defaultFlow, /tool identity: unchanged/i)
  assert.match(defaultFlow, /externality: internal → external/i)
  assert.match(defaultFlow, /export/i)

  assert.match(defaultEvidence, /capability \/ surface drift/i)
  assert.match(defaultEvidence, /same identity/i)
})

test('default landing flow holds the SUBSEQUENT call before upstream forwarding', () => {
  assert.match(defaultFlow, /next gateway-mediated call to \S+: held before upstream forwarding/i)
  assert.match(defaultEvidence, /subsequent calls to \S+: held before forwarding/i)
})

test('default landing flow records and verifies a receipt', () => {
  assert.match(defaultFlow, /hash-chained receipt/i)
  assert.match(defaultFlow, /chain: verified/i)
})

test('the default evaluator does not claim it runs the 403 -> 200 probe', () => {
  for (const [name, region] of [
    ['hero proof flow', defaultFlow],
    ['evidence diff', defaultEvidence],
    ['offline proof claims', offlineClaims],
  ] as const) {
    assert.doesNotMatch(region, /403/, `${name} must not claim the default evaluator runs a 403 probe`)
    assert.doesNotMatch(region, /observed\s*200/i, `${name} must not claim a default observed 200`)
  }
})

/* ---------- the advanced probe is separate, controlled and forwarded ---------- */

test('advanced behavioral section identifies the probe as controlled and forwarded', () => {
  assert.match(advancedSection, /controlled/i)
  assert.match(advancedSection, /non-production/i)
  assert.match(advancedSection, /forwarded upstream/i)
  // Interlock must say WHY it forwards: it needs the response to observe.
  assert.match(advancedSection, /needs the upstream response to observe/i)
  assert.match(advancedSection, /expected 403 → observed .*200/i)
  // The observation is the cause, and it quarantines a specific tool.
  assert.match(advancedSection, /observed 200 quarantines that tool/i)
})

test('advanced section distinguishes the forwarded probe from later held calls', () => {
  assert.match(
    advancedSection,
    /later gateway-mediated calls to that (?:same )?tool are held before forwarding/i,
  )
  assert.match(
    advancedSection,
    /the calls that are held are the later ones to that same tool/i,
    'the probe and the held calls must be stated as different calls, tool-scoped',
  )
  assert.match(advancedSection, /is not held/i)
})

test('advanced section disclaims the default journey and over-broad claims', () => {
  assert.match(advancedSection, /not the default evaluator journey/i)
  assert.match(advancedSection, /does not prevent the first observable behavioral change/i)
  assert.match(advancedSection, /not generic OAuth introspection/i)
})

/* ---------- no public flow pairs an observed 200 with "not forwarded" ---------- */

test('no landing region combines an observed 200 with a not-forwarded claim', () => {
  const regions = [defaultFlow, defaultEvidence, advancedSection, offlineClaims]
  for (const region of regions) {
    const observes200 = /observed\s*(<[^>]*>\s*)?200|→ *(<[^>]*>)? *200|allowed \/ 200/i.test(region)
    if (!observes200) continue
    assert.doesNotMatch(
      region,
      /call not forwarded|not forwarded|forwarding: not forwarded/i,
      'a region that observes an upstream 200 cannot claim that call was not forwarded',
    )
  }
})

test('landing page never states forwarding status as plainly "not forwarded"', () => {
  // The old console fixture printed `forwarding: not forwarded` next to a 200.
  assert.doesNotMatch(landing, /forwarding: *not forwarded/i)
})

/* ---------- walkthrough link ---------- */

test('"Read the walkthrough" targets the evaluator quickstart', () => {
  const anchor = landing.match(/<a[^>]*>\s*Read the walkthrough\s*<\/a>/i)
  assert.ok(anchor, 'expected a "Read the walkthrough" link on the landing page')
  assert.match(anchor[0], new RegExp(`href="${EVALUATOR_WALKTHROUGH}"`))
  assert.match(anchor[0], /docs\/evaluator-quickstart\.md/)
})

/* ---------- the guided drift proof page keeps both stories distinct ---------- */

test('drift proof page leads with surface drift, not a 403 probe', () => {
  const primary = driftProof.slice(0, driftProof.indexOf('behavioral-probe-evidence'))
  assert.match(primary, /effects expanded by/i)
  assert.match(primary, /externality/i)
  assert.doesNotMatch(primary, /403/, 'the primary drift-proof flow must not run a 403 probe')
})

test('drift proof behavioral block is marked separate, controlled and forwarded', () => {
  const secondary = driftProof.slice(driftProof.indexOf('behavioral-probe-evidence'))
  assert.match(secondary, /Separate advanced proof/i)
  assert.match(secondary, /not the journey above/i)
  assert.match(secondary, /deliberately forwarded upstream/i)
  assert.match(secondary, /needs the\s+upstream response to observe/i)
  assert.match(
    secondary,
    /only later\s+gateway-mediated calls to that same tool are held before forwarding/i,
  )
  assert.match(secondary, /403 denied/)
  assert.match(secondary, /200 allowed/)
})

test('drift proof quarantine step scopes holding to subsequent calls', () => {
  assert.match(
    driftProofText,
    new RegExp(
      `subsequent gateway-mediated calls to ${EVALUATOR_TOOL} are held before upstream forwarding`,
      'i',
    ),
  )
  assert.doesNotMatch(driftProof, /call not forwarded/i)
})

test('flex decision banner keeps its wording in one text node', () => {
  // .proof-decision p is display:flex; whitespace-only nodes between inline
  // children are dropped there, so an inline <code> would render as
  // "toread_fileheld". Guard the regression, not just the wording.
  const banner = driftProofText.match(/<p>subsequent gateway-mediated calls[^<]*<\/p>/i)
  assert.ok(banner, 'quarantine banner must be a single <p> text node')
  assert.doesNotMatch(banner[0], /<code>/, 'no inline element inside the flex banner')
})

/* ---------- every holding claim names the tool it applies to ---------- */

test('no landing holding claim is left unscoped to a tool', () => {
  const offenders = unscopedHoldingClaims(landingText)
  assert.deepEqual(
    offenders,
    [],
    `holding claims must say WHICH tool is held; quarantine is per (server_id, tool_name):\n${offenders.join('\n---\n')}`,
  )
})

test('no drift-proof holding claim is left unscoped to a tool', () => {
  const offenders = unscopedHoldingClaims(text(driftProof))
  assert.deepEqual(offenders, [], `unscoped holding claims:\n${offenders.join('\n---\n')}`)
})

test('landing never claims all gateway traffic is paused', () => {
  for (const overbroad of [
    /hold the next gateway-mediated call before/i,
    /subsequent gateway-mediated calls (?:are )?held before forwarding(?! to)/i,
    /later gateway-mediated calls are held before forwarding(?! to)/i,
    /subsequent gateway-mediated calls: held before/i,
    /all (?:gateway|traffic|calls) (?:are )?(?:held|paused)/i,
  ]) {
    assert.doesNotMatch(landingText, overbroad, `overbroad holding claim: ${overbroad}`)
  }
})

test('the default proof states quarantine does not stop unrelated tools', () => {
  assert.match(landingText, /other approved tools keep working|not to the whole server/i)
  assert.match(driftProofText, /unrelated approved tools on the same server/i)
})

/* ---------- the public fixture matches the EXECUTABLE evaluator ---------- */

test('landing default proof depicts the tool the evaluator actually runs', () => {
  for (const [name, region] of [
    ['hero proof flow', defaultFlow],
    ['evidence diff', defaultEvidence],
    ['offline proof claims', offlineClaims],
  ] as const) {
    assert.ok(
      region.includes(EVALUATOR_TOOL),
      `${name} must depict "${EVALUATOR_TOOL}" (from evaluator_journey.py), got: ${region.slice(0, 200)}`,
    )
  }
  // The console fixture row is the same proof and must agree.
  assert.match(landingText, new RegExp(`${EVALUATOR_TOOL} \\(fixture\\)`))
})

test('drift proof depicts the tool the evaluator actually runs', () => {
  assert.ok(
    driftProofText.includes(EVALUATOR_TOOL),
    `DriftProof must depict "${EVALUATOR_TOOL}"`,
  )
  assert.match(
    driftProofText,
    new RegExp(`Approved and current boundaries for the ${EVALUATOR_TOOL} tool`),
    'the accessible table caption must name the evaluator tool',
  )
  assert.ok(
    driftProofText.includes(EVALUATOR_CONTROL_TOOL),
    `DriftProof should cite the control tool "${EVALUATOR_CONTROL_TOOL}" as proof quarantine is tool-scoped`,
  )
})

test('no stale fixture tool identity survives on public proof surfaces', () => {
  assert.doesNotMatch(landing, /read_document/)
  assert.doesNotMatch(driftProof, /read_document/)
})

test('public effects diff does not overclaim beyond the fixture', () => {
  // The mock server widens read_file to effects ["read", "export"] only.
  // "share" appears in the evaluator's allowed-vocabulary enum, not the drift.
  assert.doesNotMatch(landing, /export, share|export<\/span>, share/i)
  assert.doesNotMatch(driftProof, />share</)
})

/* ---------- console copy matches the real dashboard entry route ---------- */

test('landing does not claim the review queue is the first dashboard screen', () => {
  assert.doesNotMatch(landingText, /first thing you see/i)
  assert.doesNotMatch(landingText, /first screen|opens on the drift review queue/i)
  // It should still describe what the console actually provides.
  assert.match(landingText, /operational console keeps the drift review queue available/i)
})

test('the public dashboard entry is the guided proof, which is why the queue is not first', () => {
  // Copy above is only true because /dashboard redirects to the proof page.
  // If routing ever changes back, this pins the reason the copy was reworded.
  assert.equal(PUBLIC_DASHBOARD_LANDING, '/dashboard/proof')
  assert.equal(DASHBOARD_OVERVIEW_PATH, '/dashboard/overview')
  assert.match(
    readFileSync(`${here}../src/App.tsx`, 'utf8'),
    /<Route index element=\{<Navigate to=\{PUBLIC_DASHBOARD_LANDING\}/,
    '/dashboard must still redirect to the public landing route',
  )
})
