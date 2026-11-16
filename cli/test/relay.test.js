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

const { parseRelayKey, createSwarm, generateCode, splitCode, acceptStream, connectStream, sendFile, receiveFile, topicFromNameplate, Responder, MessageReader, ERR_CONFIRMATION } = require('@ad-hal/engine')
const { relayFlag } = require('../src/relay-flag')
const { slow } = require('../test-helpers/tiers')
const { startRelay, pairThroughRelay, makePunchFailing, BlindRelay } = require('../test-helpers/relay')
const { within } = require('../test-helpers/test-peer')
const { assertSameBytes } = require('../test-helpers/bytes')

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

// --- gate 1: the relay in the middle, with no Noise under the drop ---------
//
// THREAT-MODEL.md section 8, gate 1: a drop carried through the relay, with
// no Noise session underneath, completes, and a byte the relay alters fails
// authentication at that frame. hyperdht always starts a Noise secret
// stream on a relayed connection, and an altered byte would fail there,
// before Adhal's channel saw it. That shows the relay cannot tamper, but
// not that the channel alone stops it, which is what a relayed connection
// "exactly as safe as a direct one" needs, whatever the transport. So
// these pair two raw streams through blind-relay's own server, as hyperdht
// does, and run the handshake and the transfer on them directly: the
// plain-TCP case in sealed-transfer.test.js, with the relay in the middle.

/**
 * What a relay that reads the sender's direction as it forwards it sees,
 * and, if told to, the one byte it alters: payload byte `at` of frame
 * `target`, counting frames from when `armed` is set. It needs no key to
 * find the frames, because their 4-byte length prefixes (PROTOCOL.md
 * section 5) are not encrypted by anything underneath.
 * @param {{ target?: number, at?: number }} [options]
 */
function relayEye ({ target = 0, at = 0 } = {}) {
  const seen = { armed: false, frames: 0, altered: false, bytes: /** @type {Buffer[]} */ ([]) }
  let header = Buffer.alloc(0)
  let left = 0
  let pos = 0
  /** @param {Buffer} chunk @param {{ fromInitiator: boolean }} from */
  const tamper = (chunk, { fromInitiator }) => {
    // The sender pairs as the initiator, below.
    if (!fromInitiator) return chunk
    seen.bytes.push(Buffer.from(chunk))
    if (!seen.armed) return chunk
    const out = Buffer.from(chunk)
    for (let i = 0; i < out.length; i++) {
      if (left === 0) {
        header = Buffer.concat([header, out.subarray(i, i + 1)])
        if (header.length === 4) {
          left = header.readUInt32BE(0)
          header = Buffer.alloc(0)
          pos = 0
          seen.frames++
        }
        continue
      }
      if (seen.frames === target && pos === at && !seen.altered) {
        out[i] ^= 0x01
        seen.altered = true
      }
      pos++
      left--
    }
    return out
  }
  return { seen, tamper }
}

/**
 * A sender and a receiver whose only path is a raw stream through a
 * blind-relay on a fresh testnet, with no Noise session on it.
 * @param {any} t
 * @param {Parameters<typeof startRelay>[1]} relayOptions
 */
async function rawRelayedPair (t, relayOptions) {
  const net = await createTestnet(5)
  t.after(() => net.destroy())
  const relay = await startRelay(net.bootstrap, relayOptions)
  t.after(() => relay.destroy())
  const nodes = [new HyperDHT({ bootstrap: net.bootstrap, ephemeral: true }), new HyperDHT({ bootstrap: net.bootstrap, ephemeral: true })]
  t.after(() => Promise.all(nodes.map((n) => n.destroy())))
  // Fresh and random, as hyperdht makes it (gate 3).
  const token = BlindRelay.token()
  const [tx, rx] = await Promise.all([
    pairThroughRelay(nodes[0], relay.publicKey, { isInitiator: true, token }),
    pairThroughRelay(nodes[1], relay.publicKey, { isInitiator: false, token })
  ])
  t.after(() => { tx.close(); rx.close() })
  assert.equal(relay.stats.pairings.matched, 1, 'blind-relay paired the two')
  for (const end of [tx, rx]) assert.equal(end.stream.handshakeHash, undefined, 'a raw stream, not a Noise secret stream')
  return { tx: tx.stream, rx: rx.stream }
}

/** @param {any} t @param {Buffer} body */
async function dropFixture (t, body) {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'adhal-relay-raw-'))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const source = path.join(dir, 'payload.bin')
  await fs.promises.writeFile(source, body)
  const out = path.join(dir, 'out')
  await fs.promises.mkdir(out)
  return { source, out, sha256: crypto.createHash('sha256').update(body).digest('hex') }
}

/**
 * The PAKE, and then the relay armed: everything the sender writes from
 * here on is a sealed channel frame, starting with the MANIFEST.
 * @param {any} tx @param {any} rx @param {{ armed: boolean }} seen
 */
async function handshakeThenArm (tx, rx, seen) {
  const { nameplate, secret } = splitCode(generateCode())
  const [rxKeys, txKeys] = await Promise.all([
    acceptStream(rx, { nameplate, secret }),
    connectStream(tx, { nameplate, secret })
  ])
  // REPLY, the sender's only handshake message, has reached the receiver,
  // or acceptStream would not have resolved.
  seen.armed = true
  return { rxKeys, txKeys }
}

/** @param {any} promise */
const settle = (promise) => promise.then((value) => ({ ok: true, value }), (error) => ({ ok: false, error }))

test('gate 1: a drop through the relay with no Noise underneath completes, and the relay sees only sealed frames', slow, async (t) => {
  // Easy to spot, as in sealed-transfer.test.js's wire test.
  const marker = Buffer.from('ADHAL-PLAINTEXT-MARKER-', 'utf8')
  const body = Buffer.concat(Array.from({ length: 40000 }, () => marker))
  const { source, out, sha256 } = await dropFixture(t, body)
  const eye = relayEye()
  const { tx, rx } = await rawRelayedPair(t, { tamper: eye.tamper })
  const { rxKeys, txKeys } = await handshakeThenArm(tx, rx, eye.seen)

  const [received, sent] = await Promise.all([
    receiveFile(rx, out, { sendKey: rxKeys.sendKey, receiveKey: rxKeys.receiveKey, pending: rxKeys.pending }),
    sendFile(tx, source, { sendKey: txKeys.sendKey, receiveKey: txKeys.receiveKey, pending: txKeys.pending, resultTimeout: 10000 })
  ])
  assert.equal(sent.sha256, sha256)
  assert.equal(received.sha256, sha256)
  assertSameBytes(await fs.promises.readFile(received.path), body)

  // The relay could read the framing, which only an unencrypted transport
  // allows: nothing but Adhal's own channel stood between it and the drop.
  assert.ok(eye.seen.frames >= 2, `the relay found the MANIFEST and the CHUNKs (${eye.seen.frames} frames)`)
  const relayed = Buffer.concat(eye.seen.bytes)
  assert.ok(relayed.length > body.length, 'the whole transfer went through the relay')
  for (const [what, needle] of /** @type {Array<[string, Buffer]>} */ ([
    ['the file content', marker],
    ['the file name', Buffer.from('payload.bin', 'utf8')],
    ['the digest', Buffer.from(sha256, 'utf8')]
  ])) {
    assert.equal(relayed.includes(needle), false, `${what} must not be legible to the relay`)
  }
})

test('gate 1: a byte the relay alters fails authentication at that frame, and nothing is written', slow, async (t) => {
  const { source, out } = await dropFixture(t, crypto.randomBytes(512 * 1024))
  // Frame 2 is the first CHUNK, after the MANIFEST: one byte into its
  // ciphertext, past the 12 bytes the relay could not use anyway.
  const eye = relayEye({ target: 2, at: 16 })
  const { tx, rx } = await rawRelayedPair(t, { tamper: eye.tamper })
  const { rxKeys, txKeys } = await handshakeThenArm(tx, rx, eye.seen)

  let manifests = 0
  const receiving = settle(receiveFile(rx, out, {
    sendKey: rxKeys.sendKey,
    receiveKey: rxKeys.receiveKey,
    pending: rxKeys.pending,
    onManifest: () => { manifests++ }
  }).catch((/** @type {any} */ err) => {
    // What both CLIs do on a failed receive, and how the sender learns:
    // an unauthenticated peer is owed no RESULT.
    rx.destroy()
    throw err
  }))
  const [received, sent] = await Promise.all([
    receiving,
    settle(sendFile(tx, source, { sendKey: txKeys.sendKey, receiveKey: txKeys.receiveKey, pending: txKeys.pending, resultTimeout: 10000 }))
  ])

  assert.equal(eye.seen.altered, true, 'the relay altered a byte')
  assert.equal(received.ok, false)
  assert.equal(received.error.code, 'ERR_PROTOCOL', received.error.stack)
  assert.match(received.error.message, /failed to authenticate/)
  assert.equal(received.error.framesReceived, 2n, 'it failed at the frame the relay altered, the first CHUNK')
  assert.equal(manifests, 1, 'the MANIFEST before it, untouched, was accepted')
  assert.equal(sent.ok, false, 'the sender does not call it a success')
  assert.equal(sent.error.code, 'ERR_CONNECTION', 'it heard the receiver hang up through the relay')
  assert.deepEqual(await fs.promises.readdir(out), [], 'nothing published, no partial left')
})

// --- gate 2: a relay that holds the nameplate and a token, not the secret ---
//
// THREAT-MODEL.md section 8, gate 2: a relay holding the nameplate and a
// valid token, but not the secret, cannot complete a handshake, and its
// attempt counts toward the cap like any other failed confirmation. The
// token is the relay's by construction: it is what the relay pairs on. The
// nameplate is assumed: it is the public half of the code, read aloud.

test('gate 2: a relay in the middle with the nameplate and the token, but not the secret, completes a handshake with neither side', slow, async (t) => {
  // No Noise underneath, as for gate 1, so the relay is free to speak the
  // handshake itself on both legs: to the receiver as a sender, and to the
  // sender as a receiver, with one guessed secret.
  const { nameplate, secret } = splitCode(generateCode())
  const guess = splitCode(generateCode()).secret
  /** @type {(r: any) => void} */
  let relayFinished = () => {}
  const relayRuns = new Promise((resolve) => { relayFinished = resolve })
  /** @type {Buffer | null} */
  let relayToken = null
  const takeOver = async (/** @type {{ initiator: any, responder: any, token: Buffer }} */ { initiator, responder, token }) => {
    relayToken = token
    // The sender pairs as the initiator, below. Each failed leg is hung up,
    // as the CLIs hang up on a failed handshake.
    const hangUpOnFailure = (/** @type {any} */ leg) => (/** @type {any} */ r) => { if (!r.ok) leg.destroy(); return r }
    const [asReceiver, asSender] = await Promise.all([
      settle(acceptStream(initiator, { nameplate, secret: guess, timeout: 10000 })).then(hangUpOnFailure(initiator)),
      settle(connectStream(responder, { nameplate, secret: guess, timeout: 10000 })).then(hangUpOnFailure(responder))
    ])
    relayFinished({ asReceiver, asSender })
  }
  const { tx, rx } = await rawRelayedPair(t, { takeOver })

  const hangUpOnError = (/** @type {any} */ leg) => (/** @type {any} */ err) => { leg.destroy(); throw err }
  const [received, sent] = await Promise.all([
    settle(acceptStream(rx, { nameplate, secret, timeout: 10000 }).catch(hangUpOnError(rx))),
    settle(connectStream(tx, { nameplate, secret, timeout: 10000 }).catch(hangUpOnError(tx)))
  ])
  const relay = await within(relayRuns, 15000, 'the relay\'s two handshakes ending')

  assert.ok(relayToken, 'the relay held the token it paired the two on')
  // The receiver: the relay's REPLY did not confirm. A guess, refused at
  // the confirmation, which is what the swarm counts toward the cap.
  assert.equal(received.ok, false, 'the receiver derived no keys with the relay')
  assert.equal(received.error.code, ERR_CONFIRMATION)
  assert.equal(relay.asSender.ok, false, 'nor did the relay, playing the sender')
  // The sender: its REPLY lets whoever reads it test one guess, and the
  // relay's failed. With no valid CONFIRM to send, the relay hangs up,
  // which the swarm counts on the sender as ERR_REPLY_UNANSWERED.
  assert.equal(relay.asReceiver.ok, false, 'the relay, playing the receiver, could not confirm')
  assert.equal(relay.asReceiver.error.code, ERR_CONFIRMATION, 'its guess failed against the sender\'s REPLY')
  assert.equal(sent.ok, false, 'the sender derived no keys with the relay')
  // The hang-up, however the transport reports it: a close on TCP, a reset
  // here.
  assert.ok(['ERR_CONNECTION', 'ECONNRESET'].includes(sent.error.code), sent.error.stack)
})

/**
 * Polls until `predicate` holds, and gives up by itself at `ms`. A loop
 * raced against a timeout would go on polling after the race was lost and
 * keep the test process alive: a failing test that hangs instead.
 * @param {() => boolean} predicate @param {number} ms @param {string} what
 */
async function waitFor (predicate, ms, what) {
  const deadline = Date.now() + ms
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error(`${what}: not within ${ms}ms`)
    await new Promise((resolve) => setTimeout(resolve, 20))
  }
}

test('gate 2: a guess made through the relay counts toward the receiver\'s cap, and the real sender still gets through', slow, async (t) => {
  // Under hyperdht, every relayed connection is a Noise session between its
  // two peers, so a relay operator who wants to try the handshake has to
  // be one of those peers: a guesser that pairs through its own relay.
  // This is that guesser, against the real receiver CLI, whose punch fails
  // so that every connection it accepts comes through the relay.
  const net = await createTestnet(5)
  t.after(() => net.destroy())
  const relay = await startRelay(net.bootstrap)
  t.after(() => relay.destroy())
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'adhal-relay-guess-'))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const bytes = crypto.randomBytes(256 * 1024)
  const source = path.join(dir, 'payload.bin')
  await fs.promises.writeFile(source, bytes)
  const out = path.join(dir, 'out')

  const env = { ...process.env, ADHAL_BOOTSTRAP: JSON.stringify(net.bootstrap), ADHAL_JOIN_TIMEOUT: '60000' }
  const code = generateCode()
  const { nameplate } = splitCode(code)
  const rx = run(RECEIVE, ['-', out, '--json', '--yes'], env, `${code}\n`, { failPunch: true })
  t.after(() => rx.child.kill())
  await waitFor(() => {
    if (rx.child.exitCode !== null) throw new Error(`the receiver exited:\n${rx.output()}`)
    return rx.events().some((e) => e.event === 'announced')
  }, 20000, 'the receiver announcing')

  // ONE guess, whatever the guesser's swarm does next: it redials after the
  // receiver drops it, and a second REPLY would be a second counted failure.
  let guessed = false
  /** @type {boolean | null} */
  let guessRelayed = null
  /** @type {(v?: any) => void} */
  let replied = () => {}
  const answered = new Promise((resolve) => { replied = resolve })
  const guesser = makePunchFailing(net.bootstrap, { relay: relay.publicKey })
  t.after(() => guesser.destroy())
  guesser.on('connection', (/** @type {any} */ socket) => {
    if (guessed) { socket.destroy(); return }
    const reader = new MessageReader()
    const wrong = new Responder({ nameplate, secret: splitCode(generateCode()).secret })
    socket.on('data', (/** @type {Buffer} */ chunk) => {
      if (guessed) return
      reader.push(chunk)
      const answer = wrong.readHello(reader)
      if (!answer) return
      guessed = true
      // isRelayed knows only createSwarm's swarms. On a testnet every node
      // is on 127.0.0.1, so the port says where the stream really goes.
      guessRelayed = socket.rawStream.remotePort === relay.port
      socket.write(answer.reply)
      replied()
    })
  })
  guesser.join(topicFromNameplate(nameplate), { server: false, client: true })
  await within(answered, 45000, 'the guesser\'s REPLY')
  const counted = () => rx.events().filter((e) => e.event === 'candidate-dropped' && e.counted)
  await waitFor(() => counted().length > 0, 15000, `the receiver counting the guess\n${rx.output()}`)
  await guesser.destroy()
  const matchedByGuess = relay.stats.pairings.matched

  const tx = run(SEND, ['-', source, '--json', `--relay=${relay.publicKey.toString('hex')}`], env, `${code}\n`, { failPunch: true })
  t.after(() => tx.child.kill())
  const [rxCode, txCode] = await Promise.all([rx.exited, tx.exited])
  const output = () => `--- receiver\n${rx.output()}\n--- sender\n${tx.output()}`

  assert.equal(guessRelayed, true, 'the guess came through the relay')
  assert.ok(matchedByGuess >= 1, 'the relay paired the guesser with the receiver')
  assert.deepEqual(counted().map((e) => e.code), [ERR_CONFIRMATION], `one counted failure, the guess's confirmation\n${output()}`)
  assert.equal(rxCode, 0, output())
  assert.equal(txCode, 0, output())
  assert.equal(one(rx.events(), 'paired').relayed, true)
  assert.equal(one(rx.events(), 'done').sha256, crypto.createHash('sha256').update(bytes).digest('hex'))
})
