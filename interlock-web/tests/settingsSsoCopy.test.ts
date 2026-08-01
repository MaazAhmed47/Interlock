import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const settings = readFileSync(new URL('../src/pages/Settings.tsx', import.meta.url), 'utf8')

// The status an evaluator sees before configuring anything. docs/evaluator-quickstart.md
// quotes this verbatim, and tests/test_evaluator_journey.py holds both sides together.
const OPTIONAL_STATUS = 'Optional — not configured'

test('labels Browser SSO as optional rather than unconfigured', () => {
  assert.ok(settings.includes('Browser SSO (optional)'))
  assert.ok(settings.includes(OPTIONAL_STATUS))
  // "Configuration needed" read as a required setup step during the cold run.
  assert.ok(!settings.includes('Configuration needed'))
})

test('scopes Supabase and OIDC to Browser SSO only', () => {
  assert.ok(settings.includes('Supabase or generic OIDC is needed only for Browser SSO'))
  assert.ok(settings.includes('Supabase is needed only for Browser SSO.'))
  assert.ok(settings.includes('Supabase Auth Provider (optional)'))
  assert.ok(settings.includes('OIDC Provider (optional)'))
})

test('tells evaluators the offline flow uses API-key access', () => {
  assert.ok(settings.includes('do not require Browser SSO'))
  assert.ok(settings.includes('local and offline evaluator'))
  assert.ok(settings.includes('optional browser SSO configuration'))
})
