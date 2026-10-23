'use strict'

// This repository's engine, through conformance/adapters/engine.js, against
// every scenario. One subtest per scenario, so a failure names the
// scenario and the section it breaks.
//
// The same run from the command line:
//
//   node conformance/src/cli.js -- node conformance/adapters/engine.js

const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('node:path')

const { runScenarios } = require('../src/harness')
const { scenarios } = require('../src/scenarios')

const slow = process.env.ADHAL_FAST === '1'
  ? { skip: 'slow tier: spawns adapter processes (unset ADHAL_FAST to run it)' }
  : {}

const ADAPTER = [process.execPath, path.join(__dirname, '..', 'adapters', 'engine.js')]

test('scenario IDs are unique', () => {
  const ids = scenarios.map((s) => s.id)
  assert.equal(new Set(ids).size, ids.length)
})

for (const s of scenarios) {
  test(`${s.id}: ${s.title} [${s.refs}]`, { ...slow, timeout: 120000 }, async () => {
    const [result] = await runScenarios(ADAPTER, [s])
    assert.ok(result.ok, result.error)
  })
}
