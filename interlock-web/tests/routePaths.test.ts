import { test } from 'node:test'
import assert from 'node:assert/strict'
import { isProofRoutePath, normalizeRoutePath } from '../src/routePaths.ts'

test('normalizes trailing slashes without changing other path segments', () => {
  assert.equal(normalizeRoutePath('/dashboard/proof'), '/dashboard/proof')
  assert.equal(normalizeRoutePath('/dashboard/proof/'), '/dashboard/proof')
  assert.equal(normalizeRoutePath('/dashboard/proof///'), '/dashboard/proof')
  assert.equal(normalizeRoutePath('/'), '/')
  assert.equal(normalizeRoutePath('///'), '/')
  assert.equal(normalizeRoutePath('/dashboard/audit/'), '/dashboard/audit')
})

test('identifies only canonical and trailing-slash proof routes', () => {
  assert.equal(isProofRoutePath('/dashboard/proof'), true)
  assert.equal(isProofRoutePath('/dashboard/proof/'), true)
  assert.equal(isProofRoutePath('/dashboard/proof///'), true)
  assert.equal(isProofRoutePath('/dashboard'), false)
  assert.equal(isProofRoutePath('/dashboard/audit/'), false)
  assert.equal(isProofRoutePath('/dashboard/proof/receipt'), false)
})
