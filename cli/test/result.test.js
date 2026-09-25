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
// RESULT back, garble it, or never send it.

const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('node:path')
const os = require('node:os')
const fs = require('node:fs')
const crypto = require('node:crypto')

const {
  sendFile,
  receiveFile,
  encodeMessage,
  encodeResult,
  decodeMessage,
  FrameDecoder,
  TYPE_MANIFEST,
  TYPE_CHUNK,
  TYPE_RESULT
} = require('@quay/engine')
const { duplexPair } = require('../test-helpers/duplex-pair')

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

// Reads the sender's frames off `peer` and resolves once every byte the
// manifest declared has arrived -- the moment the sender starts waiting
// for RESULT.
function readAll (peer) {
  return new Promise((resolve, reject) => {
    let manifest = null
    let received = 0
    const decoder = new FrameDecoder((payload) => {
      const { type, body } = decodeMessage(payload)
      if (type === TYPE_MANIFEST) manifest = JSON.parse(body.toString('utf8'))
      if (type === TYPE_CHUNK) received += body.length
      if (manifest && received === manifest.size) resolve(manifest)
    })
    peer.on('data', (chunk) => {
      try { decoder.push(chunk) } catch (err) { reject(err) }
    })
  })
}

// Collects the frames receiveFile writes back, for the receiver-side tests.
function framesFrom (peer) {
  /** @type {{ type: number, body: any }[]} */
  const frames = []
  const decoder = new FrameDecoder((payload) => {
    const { type, body } = decodeMessage(payload)
    frames.push({ type, body: JSON.parse(body.toString('utf8')) })
  })
  peer.on('data', (chunk) => decoder.push(chunk))
  return frames
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 20))

test('a receiver that closes after every byte but before RESULT fails the send, not passes it', async (t) => {
  const { sourcePath } = await fixture(t, 'result-close')
  const [txSocket, peer] = duplexPair()

  const sent = settle(sendFile(txSocket, sourcePath))
  await readAll(peer)
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
  const [txSocket, peer] = duplexPair()

  let resolved = false
  const sent = sendFile(txSocket, sourcePath).then((r) => { resolved = true; return r })
  await readAll(peer)
  await tick()
  assert.equal(resolved, false, 'every byte was handed off, but nothing has confirmed them')

  peer.write(encodeResult({ ok: true, sha256 }))
  const result = await sent
  assert.equal(result.sha256, sha256)
})

test('RESULT{error} fails the send with the receiver\'s own reason', async (t) => {
  const { sourcePath } = await fixture(t, 'result-error')
  const [txSocket, peer] = duplexPair()

  const sent = settle(sendFile(txSocket, sourcePath))
  await readAll(peer)
  peer.write(encodeResult({ error: 'disk full\u001b[2J' }))

  const outcome = await sent
  assert.equal(outcome.ok, false)
  assert.equal(outcome.error.code, 'ERR_RECEIVER_FAILED')
  // Printed into the sender's terminal, so it is sanitised like a CANCEL
  // reason.
  assert.equal(outcome.error.peerReason, 'disk full [2J')
})

test('an {ok} RESULT carrying a different digest is not a success', async (t) => {
  const { sourcePath, sha256 } = await fixture(t, 'result-wrong-digest')
  const [txSocket, peer] = duplexPair()

  const sent = settle(sendFile(txSocket, sourcePath))
  await readAll(peer)
  peer.write(encodeResult({ ok: true, sha256: '0'.repeat(64) }))

  const outcome = await sent
  assert.equal(outcome.ok, false)
  assert.equal(outcome.error.code, 'ERR_HASH_MISMATCH')
  assert.equal(outcome.error.reportedBy, 'receiver')
  assert.equal(outcome.error.expected, sha256)
})

test('a RESULT the sender cannot parse is a protocol error, never a success', async (t) => {
  const { sourcePath } = await fixture(t, 'result-garbled')
  const [txSocket, peer] = duplexPair()

  const sent = settle(sendFile(txSocket, sourcePath))
  await readAll(peer)
  peer.write(encodeMessage(TYPE_RESULT, Buffer.from('{"ok":true}', 'utf8')))

  const outcome = await sent
  assert.equal(outcome.ok, false)
  assert.equal(outcome.error.code, 'ERR_PROTOCOL')
})

test('a RESULT before the last byte is refused', async (t) => {
  // Large enough that the sender cannot finish in the tick it takes the
  // manifest to arrive.
  const { sourcePath, sha256 } = await fixture(t, 'result-early', 4 * 1024 * 1024)
  const [txSocket, peer] = duplexPair()

  const sent = settle(sendFile(txSocket, sourcePath))
  peer.once('data', () => peer.write(encodeResult({ ok: true, sha256 })))

  const outcome = await sent
  assert.equal(outcome.ok, false)
  assert.equal(outcome.error.code, 'ERR_PROTOCOL')
})

test('a receiver that never answers times out as unconfirmed rather than hanging the sender', async (t) => {
  const { sourcePath } = await fixture(t, 'result-timeout')
  const [txSocket, peer] = duplexPair()

  const sent = settle(sendFile(txSocket, sourcePath, { resultTimeout: 100 }))
  await readAll(peer)

  const outcome = await sent
  assert.equal(outcome.ok, false)
  assert.equal(outcome.error.code, 'ERR_STALLED')
  assert.equal(outcome.error.phase, 'result')
})

test('a receiver that vanishes mid-send is reported as the send phase', async (t) => {
  const { sourcePath } = await fixture(t, 'result-midsend', 4 * 1024 * 1024)
  const [txSocket, peer] = duplexPair()

  const sent = settle(sendFile(txSocket, sourcePath))
  peer.once('data', () => peer.end())

  const outcome = await sent
  assert.equal(outcome.ok, false)
  assert.equal(outcome.error.code, 'ERR_CONNECTION')
  assert.equal(outcome.error.phase, 'send')
})

test('the receiver sends {ok, sha256} only once the file is under its real name', async (t) => {
  const { body, sha256, outputDir } = await fixture(t, 'result-rx-ok', 1024)
  const [peer, rxSocket] = duplexPair()
  const frames = framesFrom(peer)

  const received = receiveFile(rxSocket, outputDir)
  peer.write(encodeMessage(TYPE_MANIFEST, Buffer.from(JSON.stringify({
    v: 1, type: 'manifest', name: 'payload.bin', size: body.length, chunkSize: 64 * 1024, sha256
  }), 'utf8')))
  peer.write(encodeMessage(TYPE_CHUNK, body))

  const result = await received
  assert.deepEqual(frames, [{ type: TYPE_RESULT, body: { ok: true, sha256 } }])
  // Already published by the time RESULT is out, which is what {ok}
  // promises the sender.
  assert.deepEqual(await fs.promises.readdir(outputDir), ['payload.bin'])
  assert.equal(result.sha256, sha256)
})

test('a receiver that refuses the file on its digest tells the sender why', async (t) => {
  const { body, outputDir } = await fixture(t, 'result-rx-mismatch', 1024)
  const [peer, rxSocket] = duplexPair()
  const frames = framesFrom(peer)

  const received = settle(receiveFile(rxSocket, outputDir))
  peer.write(encodeMessage(TYPE_MANIFEST, Buffer.from(JSON.stringify({
    v: 1, type: 'manifest', name: 'payload.bin', size: body.length, chunkSize: 64 * 1024, sha256: 'f'.repeat(64)
  }), 'utf8')))
  peer.write(encodeMessage(TYPE_CHUNK, body))

  const outcome = await received
  assert.equal(outcome.ok, false)
  assert.equal(outcome.error.code, 'ERR_HASH_MISMATCH')
  assert.equal(frames.length, 1)
  assert.equal(frames[0].type, TYPE_RESULT)
  assert.match(frames[0].body.error, /does not match the manifest's digest/)
  assert.equal('ok' in frames[0].body, false)
})

test('end to end, a mismatch on the receiver surfaces on the sender as ERR_RECEIVER_FAILED', async (t) => {
  // The honest-receiver path through both halves of the engine: the
  // sender's file changes between hashing and the receiver's check is not
  // reproducible here, so tamper with the bytes in transit instead.
  const { sourcePath, outputDir } = await fixture(t, 'result-e2e-mismatch', 64 * 1024)
  const [txSocket, rxSocket] = duplexPair()
  const write = rxSocket.push.bind(rxSocket)
  let flipped = false
  rxSocket.push = (chunk) => {
    // Flip one byte of the first CHUNK body, past its 5-byte header.
    if (chunk && !flipped && chunk.length > 5 && chunk[4] === TYPE_CHUNK) {
      chunk = Buffer.from(chunk)
      chunk[5] ^= 0xff
      flipped = true
    }
    return write(chunk)
  }

  const [sent, received] = await Promise.all([
    settle(sendFile(txSocket, sourcePath)),
    settle(receiveFile(rxSocket, outputDir))
  ])
  assert.equal(flipped, true)
  assert.equal(received.error.code, 'ERR_HASH_MISMATCH')
  assert.equal(sent.error.code, 'ERR_RECEIVER_FAILED')
  assert.match(sent.error.peerReason, /does not match/)
})
