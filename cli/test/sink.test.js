'use strict'

// A receive into a sink rather than a directory: `ad-hal-receive --stdout
// | tar x` (W13, docs/CLI-CONTRACT.md section 2).
//
// WHAT A SINK GIVES UP, AND WHAT IT MUST NOT. The bytes reach the sink as
// they arrive, so the guarantee a `.part` gives -- nothing is published
// until the digest matches -- is gone, and the contract says so: exit 0 is
// the only success. What must survive is everything else: the digest is
// still checked and still reported to the sender, an unsafe name is still
// refused, the size limit still applies, and backpressure still reaches
// the network. And the sink's reader going away has to reach the sender
// as a reason, not a hang-up.

const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('node:path')
const os = require('node:os')
const fs = require('node:fs')
const crypto = require('node:crypto')
const { Writable, Readable } = require('node:stream')

const {
  sendFile,
  sendStream,
  receiveFile,
  acceptOnce,
  connectOnce,
  generateCode,
  splitCode,
  KNOWN_CAPS,
  TYPE_RESULT
} = require('@ad-hal/engine')
const { duplexPair } = require('../test-helpers/duplex-pair')
const { channelKeys, sealedSender } = require('../test-helpers/sealed')
const { assertSameBytes } = require('../test-helpers/bytes')
const { FakeSwarm } = require('../test-helpers/fake-swarm')

const sha = (/** @type {Buffer} */ b) => crypto.createHash('sha256').update(b).digest('hex')

/** @param {any} promise */
async function settle (promise) {
  return promise.then((value) => ({ ok: true, value }), (error) => ({ ok: false, error }))
}

async function tmpFile (t, bytes) {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'adhal-sink-'))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const file = path.join(dir, 'source.bin')
  await fs.promises.writeFile(file, bytes)
  return { dir, file }
}

/**
 * A sink that keeps what it is given. `delay` makes each write take that
 * long, with a small highWaterMark, so write() returns false and the
 * receiver has to wait for 'drain'.
 * @param {{ delay?: number }} [options]
 */
function collector ({ delay = 0 } = {}) {
  /** @type {Buffer[]} */
  const parts = []
  const sink = new Writable({
    highWaterMark: delay ? 1024 : 16 * 1024,
    write (chunk, _enc, done) {
      parts.push(Buffer.from(chunk))
      if (delay) setTimeout(done, delay)
      else done()
    }
  })
  return { sink, bytes: () => Buffer.concat(parts) }
}

test('a declared file reaches the sink whole, and nothing is published', async (t) => {
  const whole = crypto.randomBytes(300 * 1024)
  const { dir, file } = await tmpFile(t, whole)
  const [txSocket, rxSocket] = duplexPair()
  const keys = channelKeys()
  const { sink, bytes } = collector()
  /** @type {any[]} */
  const offers = []

  const [sent, received] = await Promise.all([
    sendFile(txSocket, file, { ...keys.sender, caps: ['resume', 'stream'], chunkSize: 16 * 1024 }),
    receiveFile(rxSocket, null, {
      ...keys.receiver,
      // Resume negotiated, as from a sender that offers it: a sink still
      // offers no partial, and the onOffer hint says so.
      caps: ['resume', 'stream'],
      sink,
      onOffer: (offer) => { offers.push(offer); return true }
    })
  ])

  assert.equal(sent.sha256, sha(whole))
  assert.equal(received.sha256, sha(whole))
  assert.equal(received.path, null)
  assert.equal(received.published, null)
  assert.equal(received.resumedFrom, 0)
  assertSameBytes(bytes(), whole)
  assert.equal(offers[0].partial, 0)
  // The source's directory holds the source and nothing the receiver made.
  assert.deepEqual(await fs.promises.readdir(dir), ['source.bin'])
  assert.equal(sink.writableEnded, false, 'the sink is flushed, never ended: process.stdout cannot be')
})

test('a stream reaches the sink whole, against a slow reader', async () => {
  const parts = [crypto.randomBytes(10), crypto.randomBytes(200 * 1024), crypto.randomBytes(7)]
  const whole = Buffer.concat(parts)
  const [txSocket, rxSocket] = duplexPair()
  const keys = channelKeys()
  const { sink, bytes } = collector({ delay: 1 })

  const [sent, received] = await Promise.all([
    sendStream(txSocket, Readable.from(parts), { ...keys.sender, name: 'backup.tar', caps: ['stream'], chunkSize: 16 * 1024 }),
    receiveFile(rxSocket, null, { ...keys.receiver, caps: ['stream'], sink })
  ])
  assert.equal(sent.sha256, sha(whole))
  assert.equal(received.sha256, sha(whole))
  assert.equal(received.name, 'backup.tar')
  assertSameBytes(bytes(), whole)
})

test('a digest that does not match fails the receive, and the sender is told, after the sink has the bytes', async () => {
  const body = crypto.randomBytes(4096)
  const sender = sealedSender()
  const { sink, bytes } = collector()
  const result = settle(receiveFile(sender.socket, null, { ...sender.keys, sink }))

  const reply = await sender.offer({ v: 2, name: 'x.bin', size: body.length, sha256: sha(Buffer.from('not this')), blockSize: 64 * 1024 }, body)
  assert.equal(reply.body.resumeFrom, 0)
  const outcome = await result
  assert.equal(outcome.ok, false)
  assert.equal(outcome.error.code, 'ERR_HASH_MISMATCH')
  // What the contract warns about: the reader already has them.
  assertSameBytes(bytes(), body)
  const told = sender.received.find((f) => f.type === TYPE_RESULT)
  assert.ok(told, 'the sender gets RESULT')
  assert.ok(JSON.parse(told.body.toString('utf8')).error, 'and it carries an error, not ok')
})

test('an unsafe name is still refused with a sink, before a byte is written', async () => {
  const sender = sealedSender()
  const { sink, bytes } = collector()
  const result = settle(receiveFile(sender.socket, null, { ...sender.keys, sink }))
  const reply = await sender.offer({ v: 2, name: '../evil', size: 1, sha256: sha(Buffer.from('x')), blockSize: 64 * 1024 }, Buffer.from('x'))
  assert.equal(reply.body.code, 'ERR_UNSAFE_NAME')
  assert.equal((await result).error.code, 'ERR_UNSAFE_NAME')
  assert.equal(bytes().length, 0)
})

test('a reader that goes away stops the transfer, and the sender hears why', async (t) => {
  const whole = crypto.randomBytes(256 * 1024)
  const { file } = await tmpFile(t, whole)
  const [txSocket, rxSocket] = duplexPair()
  const keys = channelKeys()
  let written = 0
  // `| head -c 100`: takes a little, then its end of the pipe is gone.
  const sink = new Writable({
    write (chunk, _enc, done) {
      if (written > 0) {
        const err = /** @type {any} */ (new Error('write EPIPE'))
        err.code = 'EPIPE'
        done(err)
        return
      }
      written += chunk.length
      done()
    }
  })

  const [sent, received] = await Promise.all([
    settle(sendFile(txSocket, file, { ...keys.sender, chunkSize: 16 * 1024 })),
    settle(receiveFile(rxSocket, null, { ...keys.receiver, sink }))
  ])
  assert.equal(received.ok, false)
  assert.equal(received.error.code, 'EPIPE')
  assert.equal(typeof received.error.bytes, 'number')
  assert.equal(sent.ok, false)
  assert.equal(sent.error.code, 'ERR_CANCELLED_PEER')
  assert.equal(sent.error.peerReason, "the receiver's output was closed")
})

test('the sender hears ACCEPT once, before the first byte, with where it sends from', async (t) => {
  const whole = crypto.randomBytes(64 * 1024)
  const { file } = await tmpFile(t, whole)
  const [txSocket, rxSocket] = duplexPair()
  const keys = channelKeys()
  const { sink } = collector()
  /** @type {string[]} */
  const order = []

  await Promise.all([
    sendFile(txSocket, file, {
      ...keys.sender,
      chunkSize: 16 * 1024,
      onAccepted: (a) => order.push(`accepted:${a.resumeFrom}`),
      onProgress: (p) => { if (p.bytes > 0) order.push('progress') }
    }),
    receiveFile(rxSocket, null, { ...keys.receiver, sink })
  ])
  assert.equal(order.filter((e) => e.startsWith('accepted')).length, 1)
  assert.equal(order[0], 'accepted:0', 'ACCEPT is reported before any byte is')
})

test('a receiver that leaves resume out of its caps is paired without it', async () => {
  // Two fake swarms joined by one duplex pair: the receiver's candidate is
  // the sender's connection.
  const code = generateCode()
  const rxSwarm = new FakeSwarm()
  const txSwarm = new FakeSwarm()
  const topic = Buffer.alloc(32)
  const rx = acceptOnce(/** @type {any} */ (rxSwarm), topic, {
    ...splitCode(code), refreshInterval: 0, timeout: 5000,
    caps: KNOWN_CAPS.filter((/** @type {string} */ c) => c !== 'resume')
  })
  const tx = connectOnce(/** @type {any} */ (txSwarm), topic, { ...splitCode(code), refreshInterval: 0, timeout: 5000 })
  rxSwarm.candidate((far) => {
    far.rawStream = { packetsReceived: 1 }
    txSwarm.emit('connection', far, { publicKey: crypto.randomBytes(32) })
  })
  const [r, s] = await Promise.all([rx, tx])
  r.stopAnswering()
  s.stopAnswering()
  assert.deepEqual(r.caps, ['stream'])
  assert.deepEqual(s.caps, ['stream'], 'the sender acts on the intersection, so it will not try to resume')
  r.socket.destroy()
  s.socket.destroy()
})
