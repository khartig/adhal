'use strict'

// ERR_DROP_TAKEN over a real DHT (PROTOCOL.md section 4, DECLINE).
//
// The code is a bearer capability: anyone holding it can complete the
// handshake. So a second person with the code -- forwarded, read off a
// shared screen, or racing the intended peer -- is a case the protocol has
// to have an answer for. Before W15a the answer was silence: whoever
// confirmed second waited out its own timeout with no reason given, and
// the winner's human never learned there had been a race.
//
// Now the side that paired keeps answering, runs the same handshake with
// any late candidate, and tells one that proves the code
// DECLINE{ERR_DROP_TAKEN}. These tests put that on a real transport, in
// both directions, and check the two properties that matter as much as
// the message: the transfer already paired is not disturbed, and a late
// candidate that FAILS is still counted against the attempt cap.
//
// Frame-level cases (which role may send it, and when) are in
// accept-gate.test.js.

const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('node:path')
const os = require('node:os')
const fs = require('node:fs')
const crypto = require('node:crypto')
const createTestnet = require('hyperdht/testnet')

const {
  createSwarm,
  acceptOnce,
  connectOnce,
  sendFile,
  receiveFile,
  topicFromNameplate,
  generateCode,
  splitCode,
  AttemptCap,
  ERR_CONFIRMATION
} = require('@ad-hal/engine')
const { slow } = require('../test-helpers/tiers')

async function fixture (t, label) {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), `adhal-${label}-`))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const sourcePath = path.join(dir, 'source.bin')
  const body = crypto.randomBytes(128 * 1024)
  await fs.promises.writeFile(sourcePath, body)
  const out = async (name) => {
    const p = path.join(dir, name)
    await fs.promises.mkdir(p)
    return p
  }
  return { sourcePath, out, sha256: crypto.createHash('sha256').update(body).digest('hex') }
}

/** @param {any} promise */
const settle = (promise) => promise.then((value) => ({ ok: true, value }), (error) => ({ ok: false, error }))

const delay = (/** @type {number} */ ms) => new Promise((resolve) => setTimeout(resolve, ms))

// Waits for an event the test is about, with a bound, instead of letting a
// peer's own timeout decide. Discovery on the testnet takes anywhere from
// ~4s to ~15s (see engine/src/swarm.js on duplicate connections), so a
// short join timeout would fail the peer before it ever reached anyone --
// and a test asserting on that failure would pass or fail for the wrong
// reason.
/**
 * @param {Promise<any>} promise
 * @param {string} what
 */
function within (promise, what, ms = 60000) {
  /** @type {NodeJS.Timeout | undefined} */
  let timer
  const bound = new Promise((resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`timed out after ${ms}ms waiting for ${what}`)), ms)
  })
  return Promise.race([promise, bound]).finally(() => clearTimeout(timer))
}

// A swarm on the testnet, destroyed with the test.
function swarmFor (t, testnet) {
  const swarm = createSwarm({ bootstrap: testnet.bootstrap })
  t.after(() => swarm.destroy())
  return swarm
}

/** @param {any} joined */
function quiet (joined) {
  joined.socket.on('error', () => {})
  return joined
}

// The pair the drop was meant for: a receiver announced on the topic, and
// the first sender to reach it. Resolves once both sides have paired, with
// the sockets still paused and nothing transferred yet.
async function pairOf (t, testnet, drop, receiverOptions = {}, senderOptions = {}) {
  const rxSwarm = swarmFor(t, testnet)
  const txSwarm = swarmFor(t, testnet)
  /** @type {(value?: any) => void} */
  let announced = () => {}
  const ready = new Promise((resolve) => { announced = resolve })
  const accepted = acceptOnce(rxSwarm, drop.topic, {
    ...drop.halves,
    timeout: 60000,
    onAnnounced: () => announced(),
    ...receiverOptions
  })
  await ready
  const [rx, tx] = await Promise.all([
    accepted,
    connectOnce(txSwarm, drop.topic, { ...drop.halves, timeout: 60000, ...senderOptions })
  ])
  return { rx: quiet(rx), tx: quiet(tx), rxSwarm, txSwarm }
}

function newDrop () {
  const halves = splitCode(generateCode())
  return { halves, topic: topicFromNameplate(halves.nameplate) }
}

// The drop the pair was paired for still completes, byte for byte.
async function transfer (pair, sourcePath, outputDir) {
  const [received, sent] = await Promise.all([
    receiveFile(pair.rx.socket, outputDir, { sendKey: pair.rx.sendKey, receiveKey: pair.rx.receiveKey, caps: pair.rx.caps, pending: pair.rx.pending }),
    sendFile(pair.tx.socket, sourcePath, { sendKey: pair.tx.sendKey, receiveKey: pair.tx.receiveKey, caps: pair.tx.caps, pending: pair.tx.pending })
  ])
  return { received, sent }
}

test('a second sender with the code is told the drop is taken, and the first transfer still completes', slow, async (t) => {
  const testnet = await createTestnet(3)
  t.after(() => testnet.destroy())
  const { sourcePath, out, sha256 } = await fixture(t, 'taken-sender')
  const drop = newDrop()

  /** @type {any[]} */
  const told = []
  const pair = await pairOf(t, testnet, drop, { onDropTaken: (info) => told.push(info) })

  // The second sender holds the same code and completes the handshake --
  // with the receiver's late listener, not the transfer.
  const late = quiet(await connectOnce(swarmFor(t, testnet), drop.topic, { ...drop.halves, timeout: 60000 }))
  const outcome = await settle(sendFile(late.socket, sourcePath, { sendKey: late.sendKey, receiveKey: late.receiveKey, pending: late.pending }))

  assert.equal(outcome.ok, false)
  assert.equal(outcome.error.code, 'ERR_DROP_TAKEN')
  assert.equal(told.length, 1, 'the receiver\'s side hears about the race too')
  assert.equal(told[0].publicKey.equals(pair.rx.peerInfo.publicKey), false, 'the peer told is the late one, never the paired sender')

  const { received, sent } = await transfer(pair, sourcePath, await out('rx'))
  assert.equal(sent.sha256, sha256)
  assert.equal(received.sha256, sha256, 'the paired transfer is untouched by the late candidate')
})

test('a second receiver with the code is told by the paired sender', slow, async (t) => {
  const testnet = await createTestnet(3)
  t.after(() => testnet.destroy())
  const { sourcePath, out, sha256 } = await fixture(t, 'taken-receiver')
  const drop = newDrop()

  /** @type {any[]} */
  const told = []
  const pair = await pairOf(t, testnet, drop, {}, { onDropTaken: (info) => told.push(info) })

  const late = quiet(await acceptOnce(swarmFor(t, testnet), drop.topic, { ...drop.halves, timeout: 60000 }))
  const outcome = await settle(receiveFile(late.socket, await out('late'), { sendKey: late.sendKey, receiveKey: late.receiveKey, pending: late.pending }))

  assert.equal(outcome.ok, false)
  assert.equal(outcome.error.code, 'ERR_DROP_TAKEN')
  assert.equal(told.length, 1, 'the sender\'s side hears about the race too')
  assert.deepEqual(await fs.promises.readdir(path.join(path.dirname(sourcePath), 'late')), [], 'the late receiver wrote nothing')

  const { received } = await transfer(pair, sourcePath, await out('rx'))
  assert.equal(received.sha256, sha256)
})

test('a late candidate with the wrong secret is counted and reported, and changes nothing else', slow, async (t) => {
  const testnet = await createTestnet(3)
  t.after(() => testnet.destroy())
  const { sourcePath, out, sha256 } = await fixture(t, 'taken-guess')
  const drop = newDrop()

  const cap = new AttemptCap()
  /** @type {Array<string | undefined>} */
  const dropped = []
  /** @type {any[]} */
  const told = []
  /** @type {(value?: any) => void} */
  let sawGuess = () => {}
  const guessed = new Promise((resolve) => { sawGuess = resolve })
  const pair = await pairOf(t, testnet, drop, {
    attemptCap: cap,
    onCandidateDropped: (_info, _reason, code) => {
      dropped.push(code)
      if (code === ERR_CONFIRMATION) sawGuess()
    },
    onDropTaken: (info) => told.push(info)
  })
  assert.equal(cap.attempts, 0)

  // The nameplate is public; the secret is guessed. Guessing does not
  // become free because a transfer is running. The guesser never pairs, so
  // it is stopped once the receiver has seen it fail rather than left to
  // time out.
  const wrong = { nameplate: drop.halves.nameplate, secret: splitCode(generateCode()).secret }
  const stop = new AbortController()
  const guess = settle(connectOnce(swarmFor(t, testnet), drop.topic, { ...wrong, timeout: 90000, signal: stop.signal }))
  await within(guessed, 'the receiver to count the late guess')
  stop.abort()
  assert.equal((await guess).ok, false, 'a wrong secret never pairs')

  assert.equal(cap.attempts, 1, 'the late failure is counted, once')
  assert.ok(dropped.includes(ERR_CONFIRMATION), `and reported with its code, got ${JSON.stringify(dropped)}`)
  assert.equal(told.length, 0, 'a guesser is never told the drop is taken: it did not prove the code')

  const { received } = await transfer(pair, sourcePath, await out('rx'))
  assert.equal(received.sha256, sha256)
})

test('stopAnswering stops telling late candidates, and they then find no one', slow, async (t) => {
  const testnet = await createTestnet(3)
  t.after(() => testnet.destroy())
  const drop = newDrop()

  /** @type {any[]} */
  const told = []
  const pair = await pairOf(t, testnet, drop, { onDropTaken: (info) => told.push(info) })
  pair.rx.stopAnswering()

  // The late sender must actually REACH the receiver for this to prove
  // anything: a sender that timed out before connecting would fail the
  // same way whether or not the receiver had stopped. So wait for a
  // connection to the receiver's key, then give it the time a listening
  // receiver needs to send HELLO and finish -- well under a second on the
  // testnet -- and check that nothing did.
  const receiverKey = pair.tx.peerInfo.publicKey
  /** @type {(value?: any) => void} */
  let reached = () => {}
  const reachedReceiver = new Promise((resolve) => { reached = resolve })
  const stop = new AbortController()
  const late = settle(connectOnce(swarmFor(t, testnet), drop.topic, {
    ...drop.halves,
    timeout: 90000,
    signal: stop.signal,
    onCandidate: (info) => { if (info.publicKey.equals(receiverKey)) reached() }
  }))
  await within(reachedReceiver, 'the late sender to connect to the receiver')
  await delay(3000)
  stop.abort()

  const outcome = await late
  assert.equal(outcome.ok, false, 'nothing answered once the receiver had stopped')
  assert.equal(outcome.error.code, 'ABORT_ERR', 'still waiting when stopped, not refused')
  assert.equal(told.length, 0)
  pair.rx.socket.destroy()
  pair.tx.socket.destroy()
})
