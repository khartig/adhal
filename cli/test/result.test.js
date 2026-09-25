'use strict'

// RESULT (PROTOCOL.md section 4.2): the receiver's verdict, sent back to
// the sender once the file is verified and published.
//
// WHY THIS FILE EXISTS. Before RESULT, sendFile resolved once its last
// chunk was handed to the transport, and both CLIs then ended the socket,
// waited up to 5s for a close, and destroyed the swarm. On a 100-trial run
// between a Starlink receiver and a firewalled Comcast sender, the sender
// scored 100/100 and the receiver 94: all six failures were trials whose
// 5s wait ran out with 0.3 to 4.2 MB still undelivered, and the receiver
// saw "connection reset by peer". The first test below is that trial,
// reduced to a stream.
//
// The hand-rolled receiver here plays the peer, so each test can hold
// RESULT back, garble it, or never send it. It speaks the sealed v2
// channel (../test-helpers/sealed.js), because that is all sendFile will
// open.

const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('node:path')
const os = require('node:os')
const fs = require('node:fs')
const crypto = require('node:crypto')

const {
  sendFile,
  receiveFile,
  resultBody,
  TYPE_MANIFEST,
  TYPE_CHUNK,
  TYPE_RESULT
} = require('@quay/engine')
const { duplexPair } = require('../test-helpers/duplex-pair')
const { channelKeys, sealedPeer } = require('../test-helpers/sealed')

async function fixture (t, label, size = 256 * 1024) {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), `quay-${label}-`))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const sourcePath = path.join(dir, 'source.bin')
  const outputDir = path.join(dir, 'out')
  await fs.promises.mkdir(outputDir)
  const body = crypto.randomBytes(size)
  await fs.promises.writeFile(sourcePath, body)
  const sha256 = crypto.createHash('sha256').update(body).digest('hex')
  return { sourcePath, outputDir, body, sha256 }
}

/** @param {any} promise */
async function settle (promise) {
  return promise.then((value) => ({ ok: true, value }), (error) => ({ ok: false, error }))
}

// Plays the receiver against a real sendFile: returns the socket and keys
// to hand sendFile, a `reply` that seals a message back, and `allIn`, which
// resolves once every byte the manifest declared has arrived -- the moment
// the sender starts waiting for RESULT.
function receiverPeer () {
  const [txSocket, peer] = duplexPair()
  const keys = channelKeys()
  let manifest = null
  let received = 0
  /** @type {(m: any) => void} */
  let done
  const allIn = new Promise((resolve) => { done = resolve })
  const rx = sealedPeer(peer, keys.receiver, {
    onMessage: (type, body) => {
      if (type === TYPE_MANIFEST) manifest = JSON.parse(body.toString('utf8'))
      if (type === TYPE_CHUNK) received += body.length
      if (manifest && received === manifest.size) done(manifest)
    }
  })
  return {
    txSocket,
    peer,
    keys: keys.sender,
    allIn,
    /** @param {Buffer} body */
    reply: (body) => rx.send(TYPE_RESULT, body)
  }
}

// Plays the sender against a real receiveFile: `send` seals a message at
// it, and `frames` collects what it writes back, JSON-decoded.
function senderPeer () {
  const [peer, rxSocket] = duplexPair()
  const keys = channelKeys()
  /** @type {{ type: number, body: any }[]} */
  const frames = []
  const tx = sealedPeer(peer, keys.sender, {
    onMessage: (type, body) => frames.push({ type, body: JSON.parse(body.toString('utf8')) })
  })
  return { rxSocket, keys: keys.receiver, frames, send: tx.send }
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 20))

test('a receiver that closes after every byte but before RESULT fails the send, not passes it', async (t) => {
  const { sourcePath } = await fixture(t, 'result-close')
  const { txSocket, peer, keys, allIn } = receiverPeer()

  const sent = settle(sendFile(txSocket, sourcePath, { ...keys }))
  await allIn
  // The proofv2-3 trials, reduced: every byte handed off, then the
  // connection goes away. This used to resolve as a success.
  peer.end()

  const outcome = await sent
  assert.equal(outcome.ok, false)
  assert.equal(outcome.error.code, 'ERR_CONNECTION')
  assert.equal(outcome.error.phase, 'result')
})

test('the sender does not resolve on hand-off, only on RESULT', async (t) => {
  const { sourcePath, sha256 } = await fixture(t, 'result-wait')
  const { txSocket, keys, allIn, reply } = receiverPeer()

  let resolved = false
  const sent = sendFile(txSocket, sourcePath, { ...keys }).then((r) => { resolved = true; return r })
  await allIn
  await tick()
  assert.equal(resolved, false, 'every byte was handed off, but nothing has confirmed them')

  reply(resultBody({ ok: true, sha256 }))
  const result = await sent
  assert.equal(result.sha256, sha256)
})

test('RESULT{error} fails the send with the receiver\'s own reason', async (t) => {
  const { sourcePath } = await fixture(t, 'result-error')
  const { txSocket, keys, allIn, reply } = receiverPeer()

  const sent = settle(sendFile(txSocket, sourcePath, { ...keys }))
  await allIn
  reply(resultBody({ error: 'disk full\u001b[2J' }))

  const outcome = await sent
  assert.equal(outcome.ok, false)
  assert.equal(outcome.error.code, 'ERR_RECEIVER_FAILED')
  // Printed into the sender's terminal, so it is sanitised like a CANCEL
  // reason.
  assert.equal(outcome.error.peerReason, 'disk full [2J')
})

test('an {ok} RESULT carrying a different digest is not a success', async (t) => {
  const { sourcePath, sha256 } = await fixture(t, 'result-wrong-digest')
  const { txSocket, keys, allIn, reply } = receiverPeer()

  const sent = settle(sendFile(txSocket, sourcePath, { ...keys }))
  await allIn
  reply(resultBody({ ok: true, sha256: '0'.repeat(64) }))

  const outcome = await sent
  assert.equal(outcome.ok, false)
  assert.equal(outcome.error.code, 'ERR_HASH_MISMATCH')
  assert.equal(outcome.error.reportedBy, 'receiver')
  assert.equal(outcome.error.expected, sha256)
})

test('a RESULT the sender cannot parse is a protocol error, never a success', async (t) => {
  const { sourcePath } = await fixture(t, 'result-garbled')
  const { txSocket, keys, allIn, reply } = receiverPeer()

  const sent = settle(sendFile(txSocket, sourcePath, { ...keys }))
  await allIn
  // Sealed properly, so this reaches decodeResult: it is the verdict that
  // is unreadable, not the frame.
  reply(Buffer.from('{"ok":true}', 'utf8'))

  const outcome = await sent
  assert.equal(outcome.ok, false)
  assert.equal(outcome.error.code, 'ERR_PROTOCOL')
})

test('a RESULT before the last byte is refused', async (t) => {
  // Large enough that the sender cannot finish in the tick it takes the
  // manifest to arrive.
  const { sourcePath, sha256 } = await fixture(t, 'result-early', 4 * 1024 * 1024)
  const { txSocket, peer, keys, reply } = receiverPeer()

  const sent = settle(sendFile(txSocket, sourcePath, { ...keys }))
  peer.once('data', () => reply(resultBody({ ok: true, sha256 })))

  const outcome = await sent
  assert.equal(outcome.ok, false)
  assert.equal(outcome.error.code, 'ERR_PROTOCOL')
})

test('a receiver that never answers times out as unconfirmed rather than hanging the sender', async (t) => {
  const { sourcePath } = await fixture(t, 'result-timeout')
  const { txSocket, keys, allIn } = receiverPeer()

  const sent = settle(sendFile(txSocket, sourcePath, { ...keys, resultTimeout: 100 }))
  await allIn

  const outcome = await sent
  assert.equal(outcome.ok, false)
  assert.equal(outcome.error.code, 'ERR_STALLED')
  assert.equal(outcome.error.phase, 'result')
})

test('a receiver that vanishes mid-send is reported as the send phase', async (t) => {
  const { sourcePath } = await fixture(t, 'result-midsend', 4 * 1024 * 1024)
  const { txSocket, peer, keys } = receiverPeer()

  const sent = settle(sendFile(txSocket, sourcePath, { ...keys }))
  peer.once('data', () => peer.end())

  const outcome = await sent
  assert.equal(outcome.ok, false)
  assert.equal(outcome.error.code, 'ERR_CONNECTION')
  assert.equal(outcome.error.phase, 'send')
})

test('the receiver sends {ok, sha256} only once the file is under its real name', async (t) => {
  const { body, sha256, outputDir } = await fixture(t, 'result-rx-ok', 1024)
  const { rxSocket, keys, frames, send } = senderPeer()

  const received = receiveFile(rxSocket, outputDir, { ...keys })
  send(TYPE_MANIFEST, Buffer.from(JSON.stringify({
    v: 1, type: 'manifest', name: 'payload.bin', size: body.length, chunkSize: 64 * 1024, sha256
  }), 'utf8'))
  send(TYPE_CHUNK, body)

  const result = await received
  assert.deepEqual(frames, [{ type: TYPE_RESULT, body: { ok: true, sha256 } }])
  // Already published by the time RESULT is out, which is what {ok}
  // promises the sender.
  assert.deepEqual(await fs.promises.readdir(outputDir), ['payload.bin'])
  assert.equal(result.sha256, sha256)
})

test('a receiver that refuses the file on its digest tells the sender why', async (t) => {
  const { body, outputDir } = await fixture(t, 'result-rx-mismatch', 1024)
  const { rxSocket, keys, frames, send } = senderPeer()

  const received = settle(receiveFile(rxSocket, outputDir, { ...keys }))
  send(TYPE_MANIFEST, Buffer.from(JSON.stringify({
    v: 1, type: 'manifest', name: 'payload.bin', size: body.length, chunkSize: 64 * 1024, sha256: 'f'.repeat(64)
  }), 'utf8'))
  send(TYPE_CHUNK, body)

  const outcome = await received
  assert.equal(outcome.ok, false)
  assert.equal(outcome.error.code, 'ERR_HASH_MISMATCH')
  assert.equal(frames.length, 1)
  assert.equal(frames[0].type, TYPE_RESULT)
  assert.match(frames[0].body.error, /does not match the manifest's digest/)
  assert.equal('ok' in frames[0].body, false)
})

// There used to be an end-to-end test here that flipped a CHUNK byte in
// transit to produce a digest mismatch on the receiver. Under v2 that is
// no longer reachable: the altered frame fails to authenticate and the
// receive stops at that frame, before the digest is ever compared. The
// test moved to sealed-transfer.test.js and now asserts that instead. The
// sender's half of a digest refusal is still covered above, by
// "RESULT{error} fails the send", and the receiver's half by the test
// before this note.
