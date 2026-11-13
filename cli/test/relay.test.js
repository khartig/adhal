'use strict'

// --relay=<key>: a drop whose hole punch fails connects through the relay,
// and a drop that can connect directly never touches it (THREAT-MODEL.md
// section 8, gate 6). relayOnlyAfterFailedPunch and watchRelayDials in
// engine/src/swarm.js; ../src/relay-flag.js.
//
// The end-to-end cases spawn the real CLIs on a testnet. There, every peer
// connects directly, so the relayed cases load ../test-helpers/fail-punch-preload.js
// into both CLIs, and a control shows that without a relay the same setup
// does not connect at all. Without that control, "it was relayed" could
// pass on a setup that would have connected anyway.

const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const crypto = require('node:crypto')
const { spawn } = require('node:child_process')
const createTestnet = require('hyperdht/testnet')
const HyperDHT = require('hyperdht')

const { parseRelayKey, createSwarm, generateCode } = require('@ad-hal/engine')
const { relayFlag } = require('../src/relay-flag')
const { slow } = require('../test-helpers/tiers')
const { startRelay } = require('../test-helpers/relay')

// The z32 hyperdht itself depends on, to check the engine's own decoder against.
const z32 = require(require.resolve('z32', { paths: [path.dirname(require.resolve('hyperdht'))] }))

const SEND = path.join(__dirname, '..', 'src', 'swarm-send.js')
const RECEIVE = path.join(__dirname, '..', 'src', 'swarm-receive.js')
const FAIL_PUNCH = path.join(__dirname, '..', 'test-helpers', 'fail-punch-preload.js')

// --- the key ---------------------------------------------------------------

test('a relay key is accepted as hex or as z-base-32, and both give the same 32 bytes', () => {
  for (let i = 0; i < 64; i++) {
    const key = crypto.randomBytes(32)
    assert.ok(parseRelayKey(key.toString('hex')).equals(key), 'hex')
    assert.ok(parseRelayKey(key.toString('hex').toUpperCase()).equals(key), 'uppercase hex')
    const encoded = z32.encode(key)
    assert.equal(encoded.length, 52)
    assert.ok(parseRelayKey(encoded).equals(key), `z32 ${encoded}`)
    assert.ok(parseRelayKey(` ${encoded}\n`).equals(key), 'surrounding whitespace, as a paste brings')
  }
})

test('anything else is refused, without echoing it back', () => {
  const key = crypto.randomBytes(32)
  const encoded = z32.encode(key)
  const last = encoded.at(-1)
  // The last digit carries 1 bit of key and 4 of padding. Any other digit
  // with the same top bit is the same key with nonzero padding.
  const sameTopBit = 'ybndrfg8ejkmcpqxot1uwisza345h769'.split('').find((d) => d !== last &&
    ('ybndrfg8ejkmcpqxot1uwisza345h769'.indexOf(d) >> 4) === ('ybndrfg8ejkmcpqxot1uwisza345h769'.indexOf(/** @type {string} */ (last)) >> 4))
  for (const bad of [
    '',
    key.toString('hex').slice(2), // 31 bytes
    key.toString('hex') + '00', // 33 bytes
    encoded.slice(1), // 51 digits
    encoded.slice(0, -1) + 'l', // not a z32 digit
    encoded.slice(0, -1) + sameTopBit, // nonzero padding
    key.toString('base64')
  ]) {
    assert.throws(() => parseRelayKey(bad), (err) => {
      assert.ok(err instanceof TypeError)
      if (bad.length > 8) assert.ok(!/** @type {Error} */ (err).message.includes(bad), 'the input is not repeated back')
      return true
    }, JSON.stringify(bad))
  }
  assert.throws(() => parseRelayKey(/** @type {any} */ (key)), TypeError, 'a Buffer is not a typed key')
})

test('--relay= is the only spelling, given once', () => {
  const key = crypto.randomBytes(32)
  assert.equal(relayFlag(['-', 'file']), null)
  assert.ok(/** @type {Buffer} */ (relayFlag(['-', 'file', `--relay=${key.toString('hex')}`])).equals(key))
  assert.throws(() => relayFlag(['-', 'file', '--relay', key.toString('hex')]), /--relay=<key>/, 'a space would make the key a positional')
  assert.throws(() => relayFlag([`--relay=${key.toString('hex')}`, `--relay=${key.toString('hex')}`]), /more than once/)
  assert.throws(() => relayFlag(['--relay=']), /--relay: /)
  assert.throws(() => relayFlag(['--relay=abc']), /--relay: /)
})

// --- when the relay is offered ------------------------------------------------

test('the swarm offers its relay only on a retry after a failed punch, even when its own NAT is randomized', async (t) => {
  const key = crypto.randomBytes(32)
  const swarm = createSwarm({ relayThrough: key, bootstrap: [{ host: '127.0.0.1', port: 9 }] })
  t.after(() => swarm.destroy())
  assert.equal(swarm.relayThrough(false, swarm), null, 'a first dial is never relayed')
  assert.ok(swarm.relayThrough(true, swarm).equals(key), 'a retry after a punch-class failure is')
  // Hyperswarm's default for a bare key relays here, before any punch is
  // tried (toRelayFunction, hyperswarm 4.17.1). Ours does not.
  Object.defineProperty(swarm.dht, 'randomized', { value: true, configurable: true })
  assert.equal(swarm.relayThrough(false, swarm), null, 'a randomized NAT on this side alone still tries the punch first')
})

test('createSwarm refuses a relay that is not a 32-byte key, and offers none without one', async (t) => {
  for (const bad of [crypto.randomBytes(31), crypto.randomBytes(33), 'a'.repeat(64), {}]) {
    assert.throws(() => createSwarm({ relayThrough: /** @type {any} */ (bad) }), TypeError)
  }
  const swarm = createSwarm({ bootstrap: [{ host: '127.0.0.1', port: 9 }] })
  t.after(() => swarm.destroy())
  assert.equal(swarm.relayThrough, null)
})

// --- end to end, through the CLIs ------------------------------------------

/**
 * @param {string} script
 * @param {string[]} args
 * @param {NodeJS.ProcessEnv} env
 * @param {string} stdin
 * @param {{ failPunch: boolean }} options
 */
function run (script, args, env, stdin, { failPunch }) {
  const child = spawn(process.execPath, [...(failPunch ? ['--require', FAIL_PUNCH] : []), script, ...args], { env })
  let stdout = ''
  let stderr = ''
  child.stdout.on('data', (c) => { stdout += c.toString('utf8') })
  child.stderr.on('data', (c) => { stderr += c.toString('utf8') })
  child.stdin.end(stdin)
  /** @type {Promise<number | null>} */
  const exited = new Promise((resolve) => child.on('exit', (code) => resolve(code)))
  const events = () => stdout.split('\n').filter((l) => l.startsWith('{')).map((l) => JSON.parse(l))
  return { child, exited, events, output: () => `${stdout}\n${stderr}` }
}

/**
 * One drop between the two CLIs on a fresh testnet, with a relay running.
 * @param {any} t
 * @param {{ failPunch: boolean, senderRelay: boolean, receiverRelay: boolean, joinTimeout?: number, relayDown?: boolean }} options
 */
async function drop (t, { failPunch, senderRelay, receiverRelay, joinTimeout = 30000, relayDown = false }) {
  const net = await createTestnet(5)
  t.after(() => net.destroy())
  const relay = await startRelay(net.bootstrap)
  // Down: its key is still the one passed, and nothing answers to it.
  if (relayDown) await relay.destroy()
  else t.after(() => relay.destroy())
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'adhal-relay-'))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const bytes = crypto.randomBytes(1024 * 1024)
  const source = path.join(dir, 'payload.bin')
  await fs.promises.writeFile(source, bytes)
  const out = path.join(dir, 'out')

  const env = { ...process.env, ADHAL_BOOTSTRAP: JSON.stringify(net.bootstrap), ADHAL_JOIN_TIMEOUT: String(joinTimeout) }
  const relayArg = `--relay=${relay.publicKey.toString('hex')}`
  const code = generateCode()
  const rx = run(RECEIVE, ['-', out, '--json', '--yes', ...(receiverRelay ? [relayArg] : [])], env, `${code}\n`, { failPunch })
  t.after(() => rx.child.kill())
  const started = Date.now()
  while (!rx.events().some((e) => e.event === 'announced')) {
    if (Date.now() - started > 20000 || rx.child.exitCode !== null) throw new Error(`the receiver never announced:\n${rx.output()}`)
    await new Promise((resolve) => setTimeout(resolve, 20))
  }
  const tx = run(SEND, ['-', source, '--json', ...(senderRelay ? [relayArg] : [])], env, `${code}\n`, { failPunch })
  t.after(() => tx.child.kill())
  const [rxCode, txCode] = await Promise.all([rx.exited, tx.exited])
  return {
    rxCode,
    txCode,
    rx: rx.events(),
    tx: tx.events(),
    output: () => `--- receiver\n${rx.output()}\n--- sender\n${tx.output()}`,
    sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
    relay
  }
}

/** @param {any[]} events @param {string} name */
const one = (events, name) => events.find((e) => e.event === name)

test('the punch failures watched for are hyperdht\'s own error codes', () => {
  // A rename in hyperdht would otherwise turn the hint off without a sound.
  const errors = require('hyperdht/lib/errors')
  for (const code of ['HOLEPUNCH_ABORTED', 'CANNOT_HOLEPUNCH', 'REMOTE_NOT_HOLEPUNCHABLE']) {
    assert.equal(typeof errors[code], 'function', code)
    assert.equal(errors[code]().code, code)
  }
})

test('control: with the punch made to fail and no relay, the drop does not connect, and both sides say a relay would', slow, async (t) => {
  const r = await drop(t, { failPunch: true, senderRelay: false, receiverRelay: false, joinTimeout: 15000 })
  assert.notEqual(r.txCode, 0, r.output())
  assert.equal(one(r.tx, 'paired'), undefined, 'never paired')
  for (const [events, side] of /** @type {Array<[any[], string]>} */ ([[r.tx, 'sender'], [r.rx, 'receiver']])) {
    const failed = one(events, 'failed')
    assert.equal(failed.code, 'ERR_NO_PEER', r.output())
    assert.ok(failed.holepunchFailed > 0, `${side} counted the failed punches\n${r.output()}`)
    assert.equal(failed.relayAttempts, undefined)
    assert.match(failed.message, /--relay=<key> at either end/)
    const hints = events.filter((e) => e.event === 'warning' && e.kind === 'holepunch-failed')
    assert.equal(hints.length, 1, `${side} gave the hint once`)
    assert.match(hints[0].message, /--relay=<key>/)
  }
})

test('with the punch made to fail and a relay that is down, the drop says the relay was tried', slow, async (t) => {
  const r = await drop(t, { failPunch: true, senderRelay: true, receiverRelay: false, joinTimeout: 15000, relayDown: true })
  assert.notEqual(r.txCode, 0, r.output())
  const failed = one(r.tx, 'failed')
  assert.equal(failed.code, 'ERR_NO_PEER', r.output())
  assert.ok(failed.relayAttempts > 0, r.output())
  assert.match(failed.message, /relay given with --relay was tried/)
  assert.doesNotMatch(failed.message, /--relay=<key>/, 'not told to pass what it passed')
  const hint = r.tx.find((e) => e.event === 'warning' && e.kind === 'holepunch-failed')
  assert.match(hint.message, /Trying the relay/)
})

for (const [who, senderRelay, receiverRelay] of /** @type {Array<[string, boolean, boolean]>} */ ([['the sender', true, false], ['the receiver', false, true]])) {
  test(`with the punch made to fail and --relay at ${who} only, the drop completes through the relay, and both sides say so`, slow, async (t) => {
    const r = await drop(t, { failPunch: true, senderRelay, receiverRelay })
    assert.equal(r.txCode, 0, r.output())
    assert.equal(r.rxCode, 0, r.output())
    assert.equal(one(r.rx, 'done').sha256, r.sha256)
    assert.equal(one(r.tx, 'start').relay, senderRelay)
    assert.equal(one(r.rx, 'start').relay, receiverRelay)
    for (const [events, side] of /** @type {Array<[any[], string]>} */ ([[r.tx, 'sender'], [r.rx, 'receiver']])) {
      // Both, including the side that did not pass --relay: the peer chose it.
      assert.equal(one(events, 'paired').relayed, true, `${side} paired through the relay\n${r.output()}`)
      assert.equal(one(events, 'done').connection.relayed, true, `${side} ended through the relay`)
    }
    assert.ok(r.relay.stats.pairings.matched >= 1, 'the relay matched a pair')
    // The side with the relay is told it is being tried, not told to give one.
    const withRelay = senderRelay ? r.tx : r.rx
    for (const hint of withRelay.filter((e) => e.event === 'warning' && e.kind === 'holepunch-failed')) {
      assert.match(hint.message, /Trying the relay/)
    }
  })
}

test('gate 6: with --relay at both ends and a punch that works, the relay is never contacted', slow, async (t) => {
  const r = await drop(t, { failPunch: false, senderRelay: true, receiverRelay: true })
  assert.equal(r.txCode, 0, r.output())
  assert.equal(r.rxCode, 0, r.output())
  assert.equal(one(r.rx, 'done').sha256, r.sha256)
  for (const events of [r.tx, r.rx]) {
    assert.equal(one(events, 'paired').relayed, false)
    assert.equal(one(events, 'done').connection.relayed, false)
  }
  assert.equal(r.relay.sessionPeers.size, 0, 'no one opened a session with the relay')
  assert.equal(r.relay.stats.pairings.requested, 0)
})

test('a bare --relay is refused before any network work', slow, async (t) => {
  const key = HyperDHT.keyPair().publicKey.toString('hex')
  const env = { ...process.env, ADHAL_BOOTSTRAP: '[{"host":"127.0.0.1","port":9}]', ADHAL_JOIN_TIMEOUT: '1500' }
  for (const [script, args] of /** @type {Array<[string, string[]]>} */ ([[SEND, ['-', __filename, '--json', '--relay', key]], [RECEIVE, ['-', '--json', '--relay', key]]])) {
    const p = run(script, args, env, `${generateCode()}\n`, { failPunch: false })
    t.after(() => p.child.kill())
    assert.equal(await p.exited, 1, p.output())
    const failed = one(p.events(), 'failed')
    assert.equal(failed.code, 'ERR_USAGE', p.output())
    assert.match(failed.message, /--relay=<key>/)
  }
})
