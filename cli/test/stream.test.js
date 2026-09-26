'use strict'

// Streaming (PROTOCOL.md section 4.3): `tar c dir | quay send -`. A
// manifest with size: null and sha256: null, the chunks, and END{sha256}
// carrying the digest the sender computed as it read.
//
// WHY THIS IS A WIRE FEATURE AND NOT A CLI ONE. A manifest that requires a
// length cannot describe a pipe, and v1's did. Section 1 names this as one
// of the reasons v2 breaks the wire at all: leaving it out would have cost
// a third break. These tests pin the two things the section says a
// receiver must not get wrong -- a null sha256 means "the digest arrives
// at the end", never "no verification", and the stream capability comes
// from the handshake, not from the manifest.

const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('node:path')
const os = require('node:os')
const fs = require('node:fs')
const crypto = require('node:crypto')
const { Readable, PassThrough } = require('node:stream')

const {
  sendStream,
  receiveFile,
  acceptBody,
  endBody,
  resultBody,
  TYPE_MANIFEST,
  TYPE_CHUNK,
  TYPE_ACCEPT,
  TYPE_DECLINE,
  TYPE_END,
  TYPE_RESULT
} = require('@quay/engine')
const { duplexPair } = require('../test-helpers/duplex-pair')
const { channelKeys, sealedPeer, sealedSender } = require('../test-helpers/sealed')

const STREAM = ['stream']

async function tmpDir (t, label) {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), `quay-${label}-`))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  return dir
}

/** @param {any} promise */
async function settle (promise) {
  return promise.then((value) => ({ ok: true, value }), (error) => ({ ok: false, error }))
}

const sha = (/** @type {Buffer} */ b) => crypto.createHash('sha256').update(b).digest('hex')
const tick = (ms = 20) => new Promise((resolve) => setTimeout(resolve, ms))

// A producer that writes `parts` as-is, so a test controls chunk sizes the
// way a pipe does -- including chunks far larger than the blockSize.
function producer (/** @type {Buffer[]} */ parts) {
  let reads = 0
  let i = 0
  const readable = new Readable({
    read () {
      reads++
      this.push(i < parts.length ? parts[i++] : null)
    }
  })
  return { readable, reads: () => reads }
}

const streamManifest = (overrides = {}) => ({ v: 2, name: 'backup.tar', size: null, sha256: null, blockSize: 64 * 1024, ...overrides })

// --- end to end -----------------------------------------------------------

test('a stream of unknown length arrives whole, verified against END\'s digest', async (t) => {
  const outputDir = await tmpDir(t, 'stream-e2e')
  // Uneven parts, one of them 1 MiB: far past the 16 KiB blockSize below,
  // which is the case a file read stream never produces and a pipe does.
  const parts = [crypto.randomBytes(10), crypto.randomBytes(1024 * 1024), crypto.randomBytes(7), crypto.randomBytes(300 * 1024)]
  const whole = Buffer.concat(parts)
  const [txSocket, rxSocket] = duplexPair()
  const keys = channelKeys()
  /** @type {any[]} */
  const progress = []

  const [sent, received] = await Promise.all([
    sendStream(txSocket, producer(parts).readable, {
      ...keys.sender, name: 'backup.tar', caps: STREAM, chunkSize: 16 * 1024, onProgress: (p) => progress.push(p)
    }),
    receiveFile(rxSocket, outputDir, { ...keys.receiver, caps: STREAM })
  ])

  assert.equal(sent.sha256, sha(whole))
  assert.equal(sent.size, whole.length)
  assert.equal(received.sha256, sha(whole))
  assert.equal(received.size, whole.length)
  assert.equal(received.name, 'backup.tar')
  assert.deepEqual(await fs.promises.readFile(received.path), whole)

  // No total until the end, and bytes still never go backwards.
  assert.ok(progress.every((p) => p.total === null))
  assert.deepEqual(progress.map((p) => p.bytes), [...progress.map((p) => p.bytes)].sort((a, b) => a - b))
  assert.equal(progress.at(-1).bytes, whole.length)
})

test('an empty stream is still a verified, published file', async (t) => {
  const outputDir = await tmpDir(t, 'stream-empty')
  const [txSocket, rxSocket] = duplexPair()
  const keys = channelKeys()

  const [sent, received] = await Promise.all([
    sendStream(txSocket, producer([]).readable, { ...keys.sender, name: 'nothing', caps: STREAM }),
    receiveFile(rxSocket, outputDir, { ...keys.receiver, caps: STREAM })
  ])
  assert.equal(sent.sha256, sha(Buffer.alloc(0)))
  assert.equal(received.size, 0)
  assert.deepEqual(await fs.promises.readdir(outputDir), ['nothing'])
})

// --- the sender's half ----------------------------------------------------

test('the sender offers size and sha256 as null, reads nothing before ACCEPT, and ends with END', async (t) => {
  const parts = [crypto.randomBytes(100 * 1024)]
  const { readable, reads } = producer(parts)
  const [txSocket, peer] = duplexPair()
  const keys = channelKeys()
  const rx = sealedPeer(peer, keys.receiver)

  const sent = sendStream(txSocket, readable, { ...keys.sender, name: 'pipe', caps: STREAM, chunkSize: 32 * 1024 })
  await tick(50)
  assert.deepEqual(rx.received.map((f) => f.type), [TYPE_MANIFEST])
  assert.deepEqual(JSON.parse(rx.received[0].body.toString('utf8')), { v: 2, name: 'pipe', size: null, sha256: null, blockSize: 32 * 1024 })
  // A declined stream must leave its producer where it was.
  assert.equal(reads(), 0, 'nothing may be read from the producer before the receiver accepts')

  rx.send(TYPE_ACCEPT, acceptBody({ resumeFrom: 0 }))
  await tick(50)
  const types = rx.received.map((f) => f.type)
  assert.equal(types.at(-1), TYPE_END, 'the stream closes with END')
  const chunks = rx.received.filter((f) => f.type === TYPE_CHUNK)
  assert.ok(chunks.every((f) => f.body.length <= 32 * 1024), 'every chunk respects the declared blockSize')
  const end = JSON.parse(rx.received.at(-1).body.toString('utf8'))
  assert.deepEqual(end, { sha256: sha(parts[0]) })

  rx.send(TYPE_RESULT, resultBody({ ok: true, sha256: end.sha256 }))
  assert.equal((await sent).sha256, sha(parts[0]))
})

test('a sender refuses to offer a stream the handshake did not negotiate', async () => {
  const [txSocket] = duplexPair()
  const keys = channelKeys()
  let written = 0
  const realWrite = txSocket.write.bind(txSocket)
  txSocket.write = (/** @type {any[]} */ ...args) => { written++; return realWrite(...args) }
  const { readable, reads } = producer([Buffer.from('data')])

  for (const caps of [[], ['resume'], undefined]) {
    const outcome = await settle(sendStream(txSocket, readable, { ...keys.sender, name: 'pipe', caps: /** @type {any} */ (caps) }))
    assert.equal(outcome.ok, false)
    assert.equal(outcome.error.code, 'ERR_PROTOCOL')
    assert.equal(outcome.error.capability, 'stream')
  }
  assert.equal(written, 0, 'nothing may reach the wire')
  assert.equal(reads(), 0)
})

test('a receiver that confirms a different digest than END carried fails the stream', async () => {
  const [txSocket, peer] = duplexPair()
  const keys = channelKeys()
  const rx = sealedPeer(peer, keys.receiver, {
    onMessage: (type) => {
      if (type === TYPE_MANIFEST) rx.send(TYPE_ACCEPT, acceptBody({ resumeFrom: 0 }))
      if (type === TYPE_END) rx.send(TYPE_RESULT, resultBody({ ok: true, sha256: '0'.repeat(64) }))
    }
  })
  const outcome = await settle(sendStream(txSocket, producer([Buffer.from('abc')]).readable, { ...keys.sender, name: 'pipe', caps: STREAM }))
  assert.equal(outcome.error.code, 'ERR_HASH_MISMATCH')
  assert.equal(outcome.error.expected, sha(Buffer.from('abc')))
})

// --- the receiver's half --------------------------------------------------

test('a stream offered without the capability negotiated is declined, by name', async (t) => {
  const outputDir = await tmpDir(t, 'stream-no-cap')
  // Default caps: nothing negotiated. A caller that did not pass the
  // handshake's list gets the safe answer.
  for (const caps of [undefined, [], ['resume']]) {
    const { socket, keys, offer } = sealedSender()
    const received = settle(receiveFile(socket, outputDir, { ...keys, ...(caps ? { caps } : {}) }))
    const reply = await offer(streamManifest())
    assert.equal(reply.type, TYPE_DECLINE)
    assert.match(reply.body.reason, /"stream" capability/)
    const outcome = await received
    assert.equal(outcome.error.code, 'ERR_MANIFEST_INVALID')
    assert.equal(outcome.error.field, 'size')
  }
  assert.deepEqual(await fs.promises.readdir(outputDir), [])
})

test('a null sha256 means the digest arrives at the end, never that nothing is checked', async (t) => {
  const outputDir = await tmpDir(t, 'stream-end-mismatch')
  const { socket, keys, offer, send, received: frames } = sealedSender()
  const body = crypto.randomBytes(4096)

  const received = settle(receiveFile(socket, outputDir, { ...keys, caps: STREAM }))
  await offer(streamManifest(), body)
  send(TYPE_END, endBody({ sha256: 'c'.repeat(64) }))

  const outcome = await received
  assert.equal(outcome.error.code, 'ERR_HASH_MISMATCH')
  assert.equal(outcome.error.expected, 'c'.repeat(64))
  assert.match(outcome.error.message, /digest the stream ended with/)
  assert.deepEqual(await fs.promises.readdir(outputDir), [], 'a stream that fails its digest is left nowhere')
  const result = frames.find((f) => f.type === TYPE_RESULT)
  assert.ok(result, 'the sender is told')
  assert.ok('error' in JSON.parse(result.body.toString('utf8')))
})

test('END is refused on a transfer that declared its size, and garbled END on a stream', async (t) => {
  const outputDir = await tmpDir(t, 'stream-end-misuse')
  const body = crypto.randomBytes(1024)

  {
    const { socket, keys, offer, send } = sealedSender()
    const received = settle(receiveFile(socket, outputDir, { ...keys, caps: STREAM }))
    await offer({ v: 2, name: 'x.bin', size: 4096, sha256: sha(body), blockSize: 64 * 1024 }, body)
    send(TYPE_END, endBody({ sha256: sha(body) }))
    const outcome = await received
    assert.equal(outcome.error.code, 'ERR_PROTOCOL')
    assert.match(outcome.error.message, /END for a transfer whose size it had declared/)
  }
  {
    const { socket, keys, offer, send } = sealedSender()
    const received = settle(receiveFile(socket, outputDir, { ...keys, caps: STREAM }))
    await offer(streamManifest(), body)
    send(TYPE_END, Buffer.from('{"sha256":"ABC"}'))
    const outcome = await received
    assert.equal(outcome.error.code, 'ERR_PROTOCOL')
    assert.match(outcome.error.message, /END does not carry a lowercase hex sha256/)
  }
  assert.deepEqual(await fs.promises.readdir(outputDir), [])
})

test('a stream that runs past maxSize is stopped, and the sender is told why', async (t) => {
  const outputDir = await tmpDir(t, 'stream-cap')
  const [txSocket, rxSocket] = duplexPair()
  const keys = channelKeys()
  const parts = Array.from({ length: 8 }, () => crypto.randomBytes(64 * 1024))

  const [sent, received] = await Promise.all([
    settle(sendStream(txSocket, producer(parts).readable, { ...keys.sender, name: 'endless', caps: STREAM })),
    settle(receiveFile(rxSocket, outputDir, { ...keys.receiver, caps: STREAM, maxSize: 200 * 1024 }))
  ])

  assert.equal(received.error.code, 'ERR_SIZE_MISMATCH')
  assert.equal(received.error.limit, 200 * 1024)
  // Not a mystery disconnect: the sender promised no length, so it is not
  // at fault, and it hears the receiver's reason.
  assert.equal(sent.error.code, 'ERR_CANCELLED_PEER')
  assert.match(sent.error.peerReason, /passed the 204800 byte limit/)
  assert.deepEqual(await fs.promises.readdir(outputDir), [])
})

test('a sender that vanishes mid-stream is reported as cut off before its END', async (t) => {
  const outputDir = await tmpDir(t, 'stream-vanish')
  const { peer, socket, keys, offer } = sealedSender()

  const received = settle(receiveFile(socket, outputDir, { ...keys, caps: STREAM }))
  await offer(streamManifest(), crypto.randomBytes(1000))
  await tick()
  peer.destroy()

  const outcome = await received
  assert.equal(outcome.error.code, 'ERR_CONNECTION')
  assert.match(outcome.error.message, /1000 bytes of a stream, before its END/)
  assert.deepEqual(await fs.promises.readdir(outputDir), [])
})

test('a stream from a live pipe survives the producer pausing between writes', async (t) => {
  const outputDir = await tmpDir(t, 'stream-pipe')
  const [txSocket, rxSocket] = duplexPair()
  const keys = channelKeys()
  const pipe = new PassThrough()
  const parts = [crypto.randomBytes(5000), crypto.randomBytes(70000), crypto.randomBytes(1)]

  const done = Promise.all([
    sendStream(txSocket, pipe, { ...keys.sender, name: 'live', caps: STREAM }),
    receiveFile(rxSocket, outputDir, { ...keys.receiver, caps: STREAM })
  ])
  // tar does not write in one burst; a stream is a sequence over time.
  for (const part of parts) {
    await tick(30)
    pipe.write(part)
  }
  pipe.end()

  const [, received] = await done
  assert.deepEqual(await fs.promises.readFile(received.path), Buffer.concat(parts))
})
