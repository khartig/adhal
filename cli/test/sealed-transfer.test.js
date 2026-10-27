'use strict'

// The v2 AEAD channel on the shipping path (PROTOCOL.md sections 3.3-3.4).
//
// channel.test.js proves the Channel class; this file proves sendFile and
// receiveFile actually put every frame through it. The difference matters:
// a channel that is correct and unused -- which is what the tree held for
// a commit -- passes every test in channel.test.js.
//
// Several of these are only meaningful because they would have passed
// the other way before the channel was wired in: tampering in transit
// surfaced as a hash mismatch at the END of the file, and the wire carried
// the file name and digest in the clear. Each assertion below states the
// v2 behavior and names the v1 behavior it replaces.

const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('node:path')
const os = require('node:os')
const fs = require('node:fs')
const net = require('node:net')
const crypto = require('node:crypto')

const {
  sendFile,
  receiveFile,
  acceptStream,
  connectStream,
  generateCode,
  splitCode,
  MAX_CHUNK_SIZE,
  ERR_CONFIRMATION
} = require('@ad-hal/engine')
const { duplexPair } = require('../test-helpers/duplex-pair')
const { channelKeys } = require('../test-helpers/sealed')
const { assertSameBytes } = require('../test-helpers/bytes')

async function fixture (t, label, body = crypto.randomBytes(256 * 1024), name = 'source.bin') {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), `adhal-${label}-`))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const sourcePath = path.join(dir, name)
  const outputDir = path.join(dir, 'out')
  await fs.promises.mkdir(outputDir)
  await fs.promises.writeFile(sourcePath, body)
  const sha256 = crypto.createHash('sha256').update(body).digest('hex')
  return { sourcePath, outputDir, body, sha256 }
}

/** @param {any} promise */
async function settle (promise) {
  return promise.then((value) => ({ ok: true, value }), (error) => ({ ok: false, error }))
}

// --- the keys are not optional -------------------------------------------

test('sendFile refuses to start without channel keys, before touching the file', async () => {
  const [txSocket] = duplexPair()
  let written = 0
  const realWrite = txSocket.write.bind(txSocket)
  txSocket.write = (/** @type {any[]} */ ...args) => { written++; return realWrite(...args) }

  // A path that does not exist: if the keys were checked after the stat,
  // this would reject with ENOENT and say nothing about the real mistake.
  const outcome = await settle(sendFile(txSocket, '/nonexistent/adhal-no-such-file', /** @type {any} */ ({})))
  assert.equal(outcome.ok, false)
  assert.ok(outcome.error instanceof TypeError, `expected a TypeError, got ${outcome.error}`)
  assert.match(outcome.error.message, /sendKey and receiveKey are required/)
  assert.equal(written, 0, 'nothing may reach the wire unsealed')
})

test('receiveFile refuses to start without channel keys, and attaches nothing', async (t) => {
  const { outputDir } = await fixture(t, 'sealed-nokeys-rx')
  const [, rxSocket] = duplexPair()

  const outcome = await settle(receiveFile(rxSocket, outputDir, /** @type {any} */ ({})))
  assert.equal(outcome.ok, false)
  assert.ok(outcome.error instanceof TypeError)
  assert.equal(rxSocket.listenerCount('data'), 0, 'a receiver without keys must not read a byte')
})

test('one key for both directions is refused rather than trusted', async (t) => {
  // The mistake the Channel constructor exists to catch, reached through
  // the public API: two counters from zero under one key is nonce reuse on
  // the very first frame each way.
  const { sourcePath } = await fixture(t, 'sealed-samekey', crypto.randomBytes(16))
  const [txSocket] = duplexPair()
  const k = crypto.randomBytes(32)
  const outcome = await settle(sendFile(txSocket, sourcePath, { sendKey: k, receiveKey: k }))
  assert.equal(outcome.ok, false)
  assert.match(outcome.error.message, /must differ/)
})

// --- what crosses the wire ------------------------------------------------

test('nothing about the file is legible on the wire, in either direction', async (t) => {
  // A body that is easy to spot, and a name that is too. v1 wrote the
  // manifest as JSON in the clear -- name, size, digest -- and every chunk
  // verbatim; Noise hid that from the network, but not from anything that
  // sat between Noise and this code, which a relay would.
  const marker = Buffer.from('ADHAL-PLAINTEXT-MARKER-', 'utf8')
  const body = Buffer.concat(Array.from({ length: 2000 }, () => marker))
  const name = 'distinctive-secret-report-name.pdf'
  const { sourcePath, outputDir, sha256 } = await fixture(t, 'sealed-wire', body, name)

  const [txSocket, rxSocket] = duplexPair()
  const keys = channelKeys()
  /** @type {Buffer[]} */
  const wire = []
  txSocket.on('data', (/** @type {Buffer} */ c) => wire.push(Buffer.from(c))) // receiver -> sender
  rxSocket.on('data', (/** @type {Buffer} */ c) => wire.push(Buffer.from(c))) // sender -> receiver

  const [sent, received] = await Promise.all([
    sendFile(txSocket, sourcePath, { ...keys.sender }),
    receiveFile(rxSocket, outputDir, { ...keys.receiver })
  ])
  assert.equal(sent.sha256, sha256)
  assert.equal(received.sha256, sha256)

  const all = Buffer.concat(wire)
  assert.ok(all.length > body.length, 'the capture must actually contain the transfer')
  for (const [what, needle] of /** @type {Array<[string, Buffer]>} */ ([
    ['the file content', marker],
    ['the file name', Buffer.from(name, 'utf8')],
    ['the manifest', Buffer.from('"manifest"', 'utf8')],
    ['the digest, in the manifest or RESULT', Buffer.from(sha256, 'utf8')],
    ['the RESULT verdict', Buffer.from('"ok"', 'utf8')]
  ])) {
    assert.equal(all.includes(needle), false, `${what} must not appear on the wire`)
  }
})

// --- tampering -------------------------------------------------------------

test('a byte altered in transit fails the receive at that frame, not as a hash mismatch at the end', async (t) => {
  // THIS WAS A HASH MISMATCH IN v1, and a test in result.test.js asserted
  // exactly that: flip one byte of a CHUNK and the receiver wrote the whole
  // file, hashed it, and refused it at the end. The file was still
  // protected -- by accident, by the digest -- and the report blamed the
  // content rather than the path it crossed. Under v2 the altered frame
  // does not open, the receive stops there, and the digest is never
  // reached.
  const { sourcePath, outputDir } = await fixture(t, 'sealed-tamper', crypto.randomBytes(512 * 1024))
  const [txSocket, rxSocket] = duplexPair()
  const keys = channelKeys()

  // duplexPair pushes one chunk per write, so the second push is the
  // first CHUNK frame (the first is the MANIFEST). Past the 4-byte length
  // prefix, into the ciphertext.
  const push = rxSocket.push.bind(rxSocket)
  let pushes = 0
  rxSocket.push = (/** @type {any} */ chunk) => {
    if (chunk && ++pushes === 2) {
      chunk = Buffer.from(chunk)
      chunk[20] ^= 0x01
    }
    return push(chunk)
  }

  let manifests = 0
  const receiving = settle(receiveFile(rxSocket, outputDir, {
    ...keys.receiver,
    onManifest: () => { manifests++ }
  }).catch((err) => {
    // What both CLIs do on a failed receive: tear the socket down. That
    // is how the sender learns, since an unauthenticated peer is owed no
    // RESULT.
    rxSocket.destroy()
    throw err
  }))
  const [sent, received] = await Promise.all([
    settle(sendFile(txSocket, sourcePath, { ...keys.sender })),
    receiving
  ])

  assert.equal(pushes >= 2, true)
  assert.equal(received.ok, false)
  assert.equal(received.error.code, 'ERR_PROTOCOL')
  assert.match(received.error.message, /failed to authenticate/)
  assert.equal(received.error.framesReceived, 2n, 'it failed at the second frame -- the first CHUNK')
  assert.equal(manifests, 1, 'the untampered manifest before it was accepted')

  // The sender does not get to call this a success.
  assert.equal(sent.ok, false)
  assert.equal(sent.error.code, 'ERR_CONNECTION')

  assert.deepEqual(await fs.promises.readdir(outputDir), [], 'nothing published, no partial left')
})

test('keys from a different handshake cannot deliver even the manifest', async (t) => {
  // Standing in for any peer that did not complete THIS handshake: a
  // stranger, a replay from another drop, a relay that tries to be a
  // party. Its frames are well formed and sealed -- just not under keys
  // this receiver derived.
  const { sourcePath, outputDir } = await fixture(t, 'sealed-wrongkeys', crypto.randomBytes(4096))
  const [txSocket, rxSocket] = duplexPair()
  const ours = channelKeys()
  const theirs = channelKeys()

  let manifests = 0
  const received = await Promise.race([
    settle(receiveFile(rxSocket, outputDir, { ...ours.receiver, onManifest: () => { manifests++ } })),
    // The sender is left waiting for a RESULT it will not get; only the
    // receiver's verdict is under test.
    sendFile(txSocket, sourcePath, { ...theirs.sender, resultTimeout: 0 }).then(() => ({ ok: true, value: 'sender resolved' }))
  ])

  assert.equal(received.ok, false)
  assert.equal(received.error.code, 'ERR_PROTOCOL')
  assert.match(received.error.message, /failed to authenticate/)
  assert.equal(received.error.framesReceived, 1n, 'refused at the very first frame')
  assert.equal(manifests, 0, 'a manifest nobody authenticated must not be acted on')
  assert.deepEqual(await fs.promises.readdir(outputDir), [])
  txSocket.destroy()
})

// --- the frame budget, on the real path ----------------------------------

test('the largest chunk the budget allows goes through end to end, and one byte more is refused up front', async (t) => {
  // v1's off-by-one was a chunk size the manifest validated and the frame
  // cap refused. v2 adds the 16-byte authenticator to the same budget, so
  // the boundary moved, and this pins it on the shipping path rather than
  // on the Channel alone.
  assert.equal(MAX_CHUNK_SIZE, 1048559, 'PROTOCOL.md section 5 states this number')

  const { sourcePath, outputDir, sha256 } = await fixture(t, 'sealed-maxchunk', crypto.randomBytes(MAX_CHUNK_SIZE * 2 + 7))
  const [txSocket, rxSocket] = duplexPair()
  const keys = channelKeys()
  const [sent, received] = await Promise.all([
    sendFile(txSocket, sourcePath, { ...keys.sender, chunkSize: MAX_CHUNK_SIZE }),
    receiveFile(rxSocket, outputDir, { ...keys.receiver })
  ])
  assert.equal(sent.sha256, sha256)
  assert.equal(received.sha256, sha256)

  // Before this check, an oversize chunkSize threw from inside the read
  // stream's 'data' handler -- an uncaught exception, not a rejection.
  const [tx2] = duplexPair()
  const outcome = await settle(sendFile(tx2, sourcePath, { ...channelKeys().sender, chunkSize: MAX_CHUNK_SIZE + 1 }))
  assert.equal(outcome.ok, false)
  assert.ok(outcome.error instanceof RangeError)
})

// --- the handshake over a stream with no Noise under it -------------------

/**
 * A real TCP connection on 127.0.0.1: the transport the loopback CLI uses,
 * with nothing underneath to authenticate anything.
 * @returns {Promise<{ client: net.Socket, server: net.Socket, close: () => void }>}
 */
async function tcpPair () {
  const listener = net.createServer()
  await new Promise((resolve) => listener.listen(0, '127.0.0.1', () => resolve(undefined)))
  const { port } = /** @type {net.AddressInfo} */ (listener.address())
  const accepted = new Promise((resolve) => listener.once('connection', resolve))
  const client = net.connect(port, '127.0.0.1')
  await new Promise((resolve) => client.once('connect', () => resolve(undefined)))
  const server = /** @type {net.Socket} */ (await accepted)
  listener.close()
  client.on('error', () => {})
  server.on('error', () => {})
  return { client, server, close: () => { client.destroy(); server.destroy() } }
}

test('the PAKE over plain TCP keys a channel that carries a whole drop', async (t) => {
  // Section 3.3's claim, end to end: nothing here came from the transport.
  //
  // Also the regression for a real bug found wiring this in. connectStream
  // pauses the socket to hold the gap before sendFile attaches its reader,
  // and attaching a 'data' listener does not resume an explicitly paused
  // stream -- so the sender never read RESULT and waited out the full
  // RESULT_TIMEOUT_MS on a transfer that had succeeded. duplexPair never
  // pauses, which is why only a real socket shows it; the resultTimeout
  // below turns that hang into a failure with a name.
  const { sourcePath, outputDir, sha256 } = await fixture(t, 'sealed-tcp', crypto.randomBytes(1024 * 1024))
  const { client, server, close } = await tcpPair()
  t.after(close)
  const { nameplate, secret } = splitCode(generateCode())

  const [rx, tx] = await Promise.all([
    acceptStream(server, { nameplate, secret }),
    connectStream(client, { nameplate, secret })
  ])
  assert.deepEqual(rx.sendKey, tx.receiveKey)
  assert.deepEqual(rx.receiveKey, tx.sendKey)

  const [received, sent] = await Promise.all([
    receiveFile(server, outputDir, { sendKey: rx.sendKey, receiveKey: rx.receiveKey, pending: rx.pending }),
    sendFile(client, sourcePath, { sendKey: tx.sendKey, receiveKey: tx.receiveKey, pending: tx.pending, resultTimeout: 5000 })
  ])
  assert.equal(sent.sha256, sha256)
  assert.equal(received.sha256, sha256)
  assertSameBytes(await fs.promises.readFile(received.path), await fs.promises.readFile(sourcePath))
})

test('a wrong code over a stream fails the confirmation, and the sender hears a handshake-phase hang-up', async () => {
  const [rxSocket, txSocket] = duplexPair()
  const right = splitCode(generateCode())
  // Same nameplate, different secret: the case the PAKE exists for.
  const wrong = { nameplate: right.nameplate, secret: splitCode(generateCode()).secret }

  const [received, sent] = await Promise.all([
    settle(acceptStream(rxSocket, right).catch((err) => {
      // The loopback receiver's response to a failed handshake.
      rxSocket.destroy()
      throw err
    })),
    settle(connectStream(txSocket, wrong))
  ])

  assert.equal(received.ok, false)
  assert.equal(received.error.code, ERR_CONFIRMATION)
  assert.equal(sent.ok, false)
  assert.equal(sent.error.code, 'ERR_CONNECTION')
  assert.equal(sent.error.phase, 'handshake')
  assert.equal(sent.error.role, 'sender')
})

test('a stream handshake with a silent peer times out rather than hanging', async () => {
  const [, txSocket] = duplexPair()
  const { nameplate, secret } = splitCode(generateCode())
  const outcome = await settle(connectStream(txSocket, { nameplate, secret, timeout: 100 }))
  assert.equal(outcome.ok, false)
  assert.equal(outcome.error.code, 'ERR_STALLED')
  assert.equal(outcome.error.phase, 'handshake')
  assert.equal(txSocket.listenerCount('data'), 0, 'its listeners come back off')
})

test('both sides wipe their channel keys when the transfer ends, however it ends (Q-18)', async (t) => {
  const zero = (/** @type {Buffer} */ b) => b.every((byte) => byte === 0)

  // Completed. Each side gets its own copies, as a real handshake gives
  // them, so each side's wipe is observed separately.
  {
    const { sourcePath, outputDir } = await fixture(t, 'wipe-done', crypto.randomBytes(8 * 1024))
    const [txSocket, rxSocket] = duplexPair()
    const keys = channelKeys()
    const tx = { sendKey: Buffer.from(keys.sender.sendKey), receiveKey: Buffer.from(keys.sender.receiveKey) }
    const rx = { sendKey: Buffer.from(keys.receiver.sendKey), receiveKey: Buffer.from(keys.receiver.receiveKey) }
    await Promise.all([sendFile(txSocket, sourcePath, tx), receiveFile(rxSocket, outputDir, rx)])
    for (const [side, view] of [['sender', tx], ['receiver', rx]]) {
      assert.ok(zero(/** @type {any} */ (view).sendKey) && zero(/** @type {any} */ (view).receiveKey), `${side} keys wiped after success`)
    }
  }

  // Refused before anything was sealed: still wiped.
  {
    const [txSocket] = duplexPair()
    const keys = channelKeys()
    const tx = { sendKey: Buffer.from(keys.sender.sendKey), receiveKey: Buffer.from(keys.sender.receiveKey) }
    await assert.rejects(sendFile(txSocket, '/nonexistent/adhal-wipe', tx))
    assert.ok(zero(tx.sendKey) && zero(tx.receiveKey), 'sender keys wiped after a refusal')
  }
})
