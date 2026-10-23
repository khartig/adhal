#!/usr/bin/env node
'use strict'

// Runs the conformance scenarios against an adapter.
//
//   ad-hal-conformance [--only <regex>] [--list] [--json] -- <adapter command...>
//
// From the repository root, against this repository's engine:
//
//   node conformance/src/cli.js -- node conformance/adapters/engine.js
//
// Exits 0 when every selected scenario passes, 1 otherwise. --json prints
// one JSON object per scenario instead of the table, for a CI log to keep.

const { runScenarios } = require('./harness')
const { scenarios } = require('./scenarios')

function usage () {
  return 'usage: ad-hal-conformance [--only <regex>] [--list] [--json] -- <adapter command...>'
}

async function main () {
  const argv = process.argv.slice(2)
  const split = argv.indexOf('--')
  const own = split === -1 ? argv : argv.slice(0, split)
  const adapter = split === -1 ? [] : argv.slice(split + 1)
  const only = own.includes('--only') ? new RegExp(own[own.indexOf('--only') + 1]) : null
  const selected = only ? scenarios.filter((s) => only.test(s.id)) : scenarios

  if (own.includes('--list')) {
    for (const s of selected) console.log(`${s.id.padEnd(30)} ${s.title}  [${s.refs}]`)
    return
  }
  if (adapter.length === 0) {
    console.error(usage())
    process.exitCode = 2
    return
  }
  const asJson = own.includes('--json')

  const results = await runScenarios(adapter, selected, {
    onResult (r) {
      if (asJson) console.log(JSON.stringify(r))
      else console.log(`${r.ok ? 'pass' : 'FAIL'}  ${r.id.padEnd(30)} ${r.title}${r.ok ? '' : `\n      ${r.error}`}`)
    }
  })
  const failed = results.filter((r) => !r.ok)
  if (!asJson) console.log(`\n${results.length - failed.length} of ${results.length} scenarios pass`)
  process.exitCode = failed.length ? 1 : 0
}

main().catch((err) => {
  console.error(err && err.stack ? err.stack : err)
  process.exitCode = 2
})
