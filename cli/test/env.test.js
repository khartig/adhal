'use strict'

// Environment overrides and what the swarm CLIs print by default (Q-17).

const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('node:path')
const os = require('node:os')
const fs = require('node:fs')
const { spawn } = require('node:child_process')

const { parseBootstrap, MAX_BOOTSTRAP_NODES } = require('../src/env')
const { slow } = require('../test-helpers/tiers')

const SWARM_RECEIVE = path.join(__dirname, '..', 'src', 'swarm-receive.js')
const SWARM_SEND = path.join(__dirname, '..', 'src', 'swarm-send.js')

test('ADHAL_BOOTSTRAP accepts a list of host/port nodes and nothing else', () => {
  assert.equal(parseBootstrap(undefined), undefined, 'unset: the public DHT')
  assert.equal(parseBootstrap(''), undefined)
  assert.deepEqual(
    parseBootstrap('[{"host":"127.0.0.1","port":49737},{"host":"node.example","port":1,"extra":true}]'),
    [{ host: '127.0.0.1', port: 49737 }, { host: 'node.example', port: 1 }],
    'extra fields are dropped, not passed on to the DHT'
  )

  for (const [raw, pattern] of [
    ['not json', /not valid JSON \(8 characters\)/],
    ['{"host":"a","port":1}', /must be a JSON array/],
    ['[]', /1 to \d+ entries/],
    [JSON.stringify(Array.from({ length: MAX_BOOTSTRAP_NODES + 1 }, () => ({ host: 'a', port: 1 }))), /1 to \d+ entries/],
    ['[{"host":"a","port":0}]', /entry 1 is not/],
    ['[{"host":"a","port":65536}]', /entry 1 is not/],
    ['[{"host":"a","port":"80"}]', /entry 1 is not/],
    ['[{"host":"","port":80}]', /entry 1 is not/],
    ['[{"host":"a b","port":80}]', /entry 1 is not/],
    ['[{"host":"ok","port":80},null]', /entry 2 is not/]
  ]) {
    assert.throws(() => parseBootstrap(/** @type {string} */ (raw)), /** @type {RegExp} */ (pattern), /** @type {string} */ (raw))
  }

  // A malformed value is described, not echoed: the message must not
  // carry the raw text back to the terminal.
  assert.throws(() => parseBootstrap('\u001b[2J oops'), (err) => !/\u001b/.test(/** @type {Error} */ (err).message))
})

/**
 * Runs a CLI to completion and returns its exit code and output.
 * @param {string} script
 * @param {string[]} args
 * @param {Record<string, string>} env
 */
function run (script, args, env) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [script, ...args], { env: { ...process.env, NO_COLOR: '1', ADHAL_NO_PROGRESS: '1', ...env } })
    let out = ''
    child.stdout.on('data', (c) => { out += c })
    child.stderr.on('data', (c) => { out += c })
    child.on('close', (code) => resolve({ code, out }))
  })
}

test('the CLIs refuse a bad ADHAL_BOOTSTRAP cleanly, and print the topic only with --verbose', slow, async (t) => {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'adhal-env-'))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const file = path.join(dir, 'f.bin')
  await fs.promises.writeFile(file, 'x')

  // A bad value exits with the reason and no stack trace.
  const bad = /** @type {any} */ (await run(SWARM_SEND, ['acid-acorn-acre-acts-afar', file], { ADHAL_BOOTSTRAP: '[{host:1}]' }))
  assert.equal(bad.code, 1)
  assert.match(bad.out, /ADHAL_BOOTSTRAP is not valid JSON/)
  assert.doesNotMatch(bad.out, /^\s+at /m, 'no stack trace')

  // A bootstrap node nobody is listening on, and a short join, so the
  // receiver prints its "joining topic" line and then gives up.
  const env = { ADHAL_BOOTSTRAP: '[{"host":"127.0.0.1","port":9}]', ADHAL_JOIN_TIMEOUT: '1500' }
  const quiet = /** @type {any} */ (await run(SWARM_RECEIVE, ['--new', dir], env))
  assert.match(quiet.out, /joining topic \(refresh=/)
  assert.doesNotMatch(quiet.out, /[0-9a-f]{64}/, 'no topic hex by default')

  const verbose = /** @type {any} */ (await run(SWARM_RECEIVE, ['--new', dir, '--verbose'], env))
  assert.match(verbose.out, /joining topic [0-9a-f]{64} \(refresh=/, 'shown when asked for')
})
