/**
 * Risk-meter banding and availability tests. Run with `npm test` from
 * interlock-web/ — Node strips the types, so this needs no test runner or extra
 * dependency.
 *
 * Lives outside src/ on purpose: tsconfig has "include": ["src"], and importing
 * node:test from there would fail `tsc --noEmit` without @types/node.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  riskMeter,
  riskBand,
  normalizeRiskScore,
  RISK_BANDS,
  RISK_SCORE_LABEL,
  THREAT_SEVERITY_LABEL,
  RISK_UNAVAILABLE_LABEL,
  RISK_UNAVAILABLE_CLASS,
  type RiskMeterState,
} from '../src/riskSeverity.ts'

/** Narrowing helper so the assertions below read as the render path does. */
function available(state: RiskMeterState) {
  assert.ok(state.available, `expected an available reading, got ${state.label}`)
  return state
}

test('threshold boundaries land in the documented band', () => {
  const cases: Array<[number, string]> = [
    [24, 'low'],
    [25, 'moderate'],
    [49, 'moderate'],
    [50, 'high'],
    [74, 'high'],
    [75, 'critical'],
  ]
  for (const [score, severity] of cases) {
    assert.equal(riskBand(score).severity, severity, `score ${score} should be ${severity}`)
  }
})

test('band edges are exactly 0/24, 25/49, 50/74, 75/100', () => {
  assert.deepEqual(
    RISK_BANDS.map(b => [b.severity, b.min, b.max]),
    [['low', 0, 24], ['moderate', 25, 49], ['high', 50, 74], ['critical', 75, 100]],
  )
})

test('bands are contiguous and cover 0-100 with no gap or overlap', () => {
  for (let i = 1; i < RISK_BANDS.length; i++) {
    assert.equal(RISK_BANDS[i].min, RISK_BANDS[i - 1].max + 1)
  }
  assert.equal(RISK_BANDS[0].min, 0)
  assert.equal(RISK_BANDS[RISK_BANDS.length - 1].max, 100)
  for (let n = 0; n <= 100; n++) {
    const matches = RISK_BANDS.filter(b => n >= b.min && n <= b.max)
    assert.equal(matches.length, 1, `score ${n} matched ${matches.length} bands`)
  }
})

test('every band has a distinct label and class', () => {
  assert.equal(new Set(RISK_BANDS.map(b => b.label)).size, RISK_BANDS.length)
  assert.equal(new Set(RISK_BANDS.map(b => b.className)).size, RISK_BANDS.length)
  for (const b of RISK_BANDS) assert.equal(b.className, `risk-${b.severity}`)
})

test('score, label and fill class always describe the same value', () => {
  for (let n = 0; n <= 100; n++) {
    const m = available(riskMeter(n))
    assert.equal(m.score, n)
    assert.equal(m.percent, n)
    assert.equal(m.className, riskBand(m.score).className)
    assert.equal(m.label, riskBand(m.score).label)
    assert.ok(m.score >= m.min && m.score <= m.max, `score ${m.score} outside its own band`)
  }
})

test('boundary scores report matching label and fill class', () => {
  const expected: Array<[number, string, string]> = [
    [24, 'Low', 'risk-low'],
    [25, 'Moderate', 'risk-moderate'],
    [49, 'Moderate', 'risk-moderate'],
    [50, 'High', 'risk-high'],
    [74, 'High', 'risk-high'],
    [75, 'Critical', 'risk-critical'],
  ]
  for (const [score, label, className] of expected) {
    const m = available(riskMeter(score))
    assert.equal(m.score, score)
    assert.equal(m.label, label)
    assert.equal(m.className, className)
  }
})

test('fractional scores band by their displayed rounded value', () => {
  assert.equal(available(riskMeter(24.4)).score, 24)
  assert.equal(available(riskMeter(24.4)).severity, 'low')
  assert.equal(available(riskMeter(24.5)).score, 25)
  assert.equal(available(riskMeter(24.5)).severity, 'moderate')
  assert.equal(available(riskMeter(74.6)).score, 75)
  assert.equal(available(riskMeter(74.6)).severity, 'critical')
})

test('-Infinity clamps to 0 Low', () => {
  assert.equal(normalizeRiskScore(-Infinity), 0)
  const m = available(riskMeter(-Infinity))
  assert.equal(m.score, 0)
  assert.equal(m.percent, 0)
  assert.equal(m.severity, 'low')
  assert.equal(m.label, 'Low')
  assert.equal(m.className, 'risk-low')
})

test('+Infinity clamps to 100 Critical', () => {
  assert.equal(normalizeRiskScore(Infinity), 100)
  const m = available(riskMeter(Infinity))
  assert.equal(m.score, 100)
  assert.equal(m.percent, 100)
  assert.equal(m.severity, 'critical')
  assert.equal(m.label, 'Critical')
  assert.equal(m.className, 'risk-critical')
})

test('finite out-of-range numbers clamp rather than going unavailable', () => {
  assert.equal(normalizeRiskScore(-40), 0)
  assert.equal(normalizeRiskScore(1000), 100)
  assert.equal(available(riskMeter(-40)).severity, 'low')
  assert.equal(available(riskMeter(1000)).severity, 'critical')
})

test('null, undefined, NaN and non-numbers render "Risk unavailable"', () => {
  const unusable: unknown[] = [
    null, undefined, NaN,
    '83', '', 'high', {}, [], true, false,
    Symbol('x'), 83n, () => 83, new Date(),
  ]
  for (const raw of unusable) {
    const label = typeof raw === 'symbol' ? 'Symbol' : String(raw)
    assert.equal(normalizeRiskScore(raw), null, `${label} should have no reading`)
    const m = riskMeter(raw)
    assert.equal(m.available, false, `${label} should be unavailable`)
    assert.equal(m.label, RISK_UNAVAILABLE_LABEL, `${label} should read "Risk unavailable"`)
    assert.equal(m.label, 'Risk unavailable')
    assert.equal(m.className, RISK_UNAVAILABLE_CLASS)
    assert.equal(m.severity, null)
    // The whole point: nothing reassuring leaks through.
    assert.ok(!('score' in m), `${label} must not carry a score`)
    assert.ok(!('percent' in m), `${label} must not carry a fill width`)
    assert.notEqual(m.className, 'risk-low')
    assert.notEqual(m.label, 'Low')
  }
})

test('the unavailable state shares no class or label with a scored band', () => {
  assert.ok(!RISK_BANDS.some(b => b.className === RISK_UNAVAILABLE_CLASS))
  assert.ok(!RISK_BANDS.some(b => b.label === RISK_UNAVAILABLE_LABEL))
})

test('threat severity and risk score are labelled as separate measurements', () => {
  assert.equal(THREAT_SEVERITY_LABEL, 'Threat severity')
  assert.equal(RISK_SCORE_LABEL, 'Risk score')
  assert.notEqual(THREAT_SEVERITY_LABEL, RISK_SCORE_LABEL)
  // Neither label is a substring of the other, so the two fields can't be read
  // as one qualifying the other.
  assert.ok(!THREAT_SEVERITY_LABEL.toLowerCase().includes(RISK_SCORE_LABEL.toLowerCase()))
  assert.ok(!RISK_SCORE_LABEL.toLowerCase().includes(THREAT_SEVERITY_LABEL.toLowerCase()))
})

test('a HIGH threat severity with an 83/100 CRITICAL risk score keeps both readings distinct', () => {
  // Backend fields are independent: threat_level is categorical, risk_score is
  // 0-100. This pairing is valid data, not a defect, and each side must present
  // under its own label with its own value.
  const threatLevel = 'HIGH'
  const risk = available(riskMeter(83))

  assert.equal(risk.score, 83)
  assert.equal(risk.label, 'Critical')
  assert.equal(risk.className, 'risk-critical')

  const fields = [
    { label: THREAT_SEVERITY_LABEL, value: threatLevel },
    { label: RISK_SCORE_LABEL, value: `${risk.score}/100 ${risk.label}` },
  ]
  assert.equal(new Set(fields.map(f => f.label)).size, 2, 'both fields must be labelled')
  for (const f of fields) assert.ok(f.value.length > 0, `${f.label} must render a value`)
  assert.equal(fields[0].value, 'HIGH')
  assert.equal(fields[1].value, '83/100 Critical')
  // The severity word and the threat level are allowed to differ — nothing in
  // the display derives one from the other.
  assert.notEqual(risk.label.toUpperCase(), threatLevel)
})
