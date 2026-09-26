'use strict'

// The accept gate (PROTOCOL.md section 4): a MANIFEST is an offer, the
// receiver answers ACCEPT{resumeFrom} or DECLINE{reason}, and no file byte
// moves before the answer.
//
// WHAT IT REPLACES. The sender used to write the manifest and the chunks
// back to back, and the receiver's only way to refuse -- a name it will
// not write, a size over its cap, a disk without room -- was to hang up.
// The sender had by then started uploading, and reported "the receiver
// disconnected", which is byte for byte what a dead hole punch looks like.
// Each test below states which half of that it pins.
//
// Both halves are played by hand here, one at a time, so each test can
// withhold the answer, garble it, or break the order on purpose; the last
// tests run the real pair end to end.

const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('node:path')
const os = require('node:os')
const fs = require('node:fs')
const crypto = require('node:crypto')

const {
  sendFile,
  receiveFile,
  acceptBody,
  declineBody,
  resultBody,
  cancelBody,
  TYPE_MANIFEST,
  TYPE_CHUNK,
  TYPE_CANCEL,
  TYPE_ACCEPT,
  TYPE_DECLINE,
  TYPE_CHECKPOINT,
  TYPE_RESULT
} = require('@quay/engine')
const { duplexPair } = require('../test-helpers/duplex-pair')
const { channelKeys, sealedPeer, sealedSender } = require('../test-helpers/sealed')
const { describeError } = require('../src/report')

async function fixture (t, label, size = 256 * 1024) {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), `quay-${label}-`))
  t.after(async () => {
    await fs.promises.chmod(dir, 0o755).catch(() => {})
    fs.rmSync(dir, { recursive: true, force: true })
  })
  const sourcePath = path.join(dir, 'source.bin')
  const outputDir = path.join(dir, 'out')
  await fs.promises.mkdir(outputDir)
  const body = crypto.randomBytes(size)
  await fs.promises.writeFile(sourcePath, body)
  const sha256 = crypto.createHash('sha256').update(body).digest('hex')
  return { dir, sourcePath, outputDir, body, sha256 }
}

function manifestFor (body, overrides = {}) {
  return {
    v: 2,
    name: 'payload.bin',
    size: body.length,
    sha256: crypto.createHash('sha256').update(body).digest('hex'),
    blockSize: 64 * 1024,
    ...overrides
  }
}

/** @param {any} promise */
async function settle (promise) {
  return promise.then((value) => ({ ok: true, value }), (error) => ({ ok: false, error }))
}

const tick = (ms = 20) => new Promise((resolve) => setTimeout(resolve, ms))

// Plays the receiver against a real sendFile, and answers nothing on its
// own: `answer` seals a reply, and `frames` is everything the sender wrote.
function receiverPeer () {
  const [txSocket, peer] = duplexPair()
  const keys = channelKeys()
  /** @type {(m: any) => void} */
  let offered = () => {}
  const manifest = new Promise((resolve) => { offered = resolve })
  const rx = sealedPeer(peer, keys.receiver, {
    onMessage: (type, body) => {
      if (type === TYPE_MANIFEST) offered(JSON.parse(body.toString('utf8')))
    }
  })
  return {
    txSocket,
    peer,
    keys: keys.sender,
    manifest,
    frames: rx.received,
    /** @param {number} type @param {Buffer} body */
    answer: (type, body) => rx.send(type, body)
  }
}

// --- the sender's half ----------------------------------------------------

test('the sender offers manifest v2 and sends no file byte until it is accepted', async (t) => {
  const { sourcePath, body, sha256 } = await fixture(t, 'gate-wait')
  const { txSocket, keys, manifest, frames, answer } = receiverPeer()

  const sent = sendFile(txSocket, sourcePath, { ...keys })
  const offer = await manifest
  // Exactly the v2 field set, and nothing of v1's.
  assert.deepEqual(offer, { v: 2, name: 'source.bin', size: body.length, sha256, blockSize: 64 * 1024 })

  // THE ASSERTION. Before the gate the chunks followed the manifest in the
  // same tick; now they wait for an answer that has not come.
  await tick(50)
  assert.deepEqual(frames.map((f) => f.type), [TYPE_MANIFEST], 'nothing may follow the offer before ACCEPT')

  answer(TYPE_ACCEPT, acceptBody({ resumeFrom: 0 }))
  await tick(50)
  const chunks = frames.filter((f) => f.type === TYPE_CHUNK)
  assert.deepEqual(Buffer.concat(chunks.map((f) => f.body)), body, 'after ACCEPT the whole file follows')

  answer(TYPE_RESULT, resultBody({ ok: true, sha256 }))
  assert.equal((await sent).sha256, sha256)
})

test('a DECLINE fails the send with the receiver\'s reason, before any file byte', async (t) => {
  const { sourcePath } = await fixture(t, 'gate-decline')
  const { txSocket, keys, manifest, frames, answer } = receiverPeer()

  const sent = settle(sendFile(txSocket, sourcePath, { ...keys }))
  await manifest
  // Printed into the sender's terminal, so sanitised like a CANCEL reason.
  answer(TYPE_DECLINE, declineBody('too big for this disk\u001b[2J'))

  const outcome = await sent
  assert.equal(outcome.ok, false)
  assert.equal(outcome.error.code, 'ERR_DECLINED')
  assert.equal(outcome.error.peerReason, 'too big for this disk [2J')
  assert.equal(outcome.error.bytes, 0)
  assert.deepEqual(frames.map((f) => f.type), [TYPE_MANIFEST], 'a declined file is never sent')
})

test('an answer that is neither ACCEPT nor DECLINE is a protocol error, named', async (t) => {
  const { sourcePath, sha256 } = await fixture(t, 'gate-wrong-answer')

  for (const [type, body, named] of [
    [TYPE_RESULT, resultBody({ ok: true, sha256 }), /RESULT before answering the offer/],
    [TYPE_CHECKPOINT, Buffer.from('{"offset":0}'), /CHECKPOINT before answering the offer/]
  ]) {
    const { txSocket, keys, manifest, answer } = receiverPeer()
    const sent = settle(sendFile(txSocket, sourcePath, { ...keys }))
    await manifest
    answer(/** @type {number} */ (type), /** @type {Buffer} */ (body))
    const outcome = await sent
    assert.equal(outcome.ok, false)
    assert.equal(outcome.error.code, 'ERR_PROTOCOL')
    assert.match(outcome.error.message, /** @type {RegExp} */ (named))
  }
})

test('an ACCEPT the sender cannot act on is refused, not guessed at', async (t) => {
  const { sourcePath } = await fixture(t, 'gate-bad-accept')

  for (const [body, why] of [
    // Resume is not implemented: starting at 0 against a receiver that
    // kept a prefix would append the whole file to it.
    [acceptBody({ resumeFrom: 4096 }), /resume from byte 4096/],
    [Buffer.from('{"resumeFrom":-1}'), /non-negative integer resumeFrom/],
    [Buffer.from('{"resumeFrom":"0"}'), /non-negative integer resumeFrom/],
    [Buffer.from('not json'), /ACCEPT is not valid JSON/]
  ]) {
    const { txSocket, keys, manifest, frames, answer } = receiverPeer()
    const sent = settle(sendFile(txSocket, sourcePath, { ...keys }))
    await manifest
    answer(TYPE_ACCEPT, /** @type {Buffer} */ (body))
    const outcome = await sent
    assert.equal(outcome.ok, false)
    assert.equal(outcome.error.code, 'ERR_PROTOCOL')
    assert.match(outcome.error.message, /** @type {RegExp} */ (why))
    assert.equal(frames.filter((f) => f.type === TYPE_CHUNK).length, 0)
  }
})

test('a receiver that never answers times out as the offer phase, with nothing sent', async (t) => {
  const { sourcePath } = await fixture(t, 'gate-timeout')
  const { txSocket, keys, manifest } = receiverPeer()

  const sent = settle(sendFile(txSocket, sourcePath, { ...keys, acceptTimeout: 100 }))
  await manifest
  const outcome = await sent
  assert.equal(outcome.ok, false)
  assert.equal(outcome.error.code, 'ERR_STALLED')
  assert.equal(outcome.error.phase, 'offer')
  assert.equal(outcome.error.bytes, 0)
})

test('a receiver that hangs up on the offer is reported as the offer phase', async (t) => {
  const { sourcePath } = await fixture(t, 'gate-hangup')
  const { txSocket, peer, keys, manifest } = receiverPeer()

  const sent = settle(sendFile(txSocket, sourcePath, { ...keys }))
  await manifest
  peer.end()
  const outcome = await sent
  assert.equal(outcome.error.code, 'ERR_CONNECTION')
  assert.equal(outcome.error.phase, 'offer')
})

// --- the receiver's half --------------------------------------------------

test('a chunk sent before ACCEPT is a protocol error and writes nothing', async (t) => {
  const { outputDir, body } = await fixture(t, 'gate-early-chunk', 1024)
  const { socket, keys, send } = sealedSender()

  const received = settle(receiveFile(socket, outputDir, { ...keys }))
  // v1's shape of sender: manifest and bytes back to back, no answer
  // awaited.
  send(TYPE_MANIFEST, Buffer.from(JSON.stringify(manifestFor(body)), 'utf8'))
  send(TYPE_CHUNK, body)

  const outcome = await received
  assert.equal(outcome.ok, false)
  assert.equal(outcome.error.code, 'ERR_PROTOCOL')
  assert.match(outcome.error.message, /CHUNK before its offer was answered/)
  assert.deepEqual(await fs.promises.readdir(outputDir), [])
})

test('a second MANIFEST while the first is being considered is a protocol error', async (t) => {
  const { outputDir, body } = await fixture(t, 'gate-two-offers', 1024)
  const { socket, keys, send } = sealedSender()

  const received = settle(receiveFile(socket, outputDir, { ...keys }))
  const manifest = Buffer.from(JSON.stringify(manifestFor(body)), 'utf8')
  send(TYPE_MANIFEST, manifest)
  send(TYPE_MANIFEST, manifest)

  const outcome = await received
  assert.equal(outcome.error.code, 'ERR_PROTOCOL')
  assert.match(outcome.error.message, /MANIFEST before its offer was answered/)
})

test('onOffer sees the name that will be written and the one that was asked for', async (t) => {
  const { outputDir, body, sha256 } = await fixture(t, 'gate-onoffer-args', 1024)
  const { socket, keys, offer } = sealedSender()

  /** @type {any[]} */
  const offers = []
  const received = receiveFile(socket, outputDir, {
    ...keys,
    platform: 'win32',
    onOffer: (o) => { offers.push(o); return true }
  })
  await offer(manifestFor(body, { name: 'aux.txt' }), body)
  await received

  // The safe name, not the peer's: an accept screen has to show what will
  // actually land on disk, and the peer's original beside it.
  assert.deepEqual(offers, [{ name: '_aux.txt', declaredName: 'aux.txt', size: 1024, sha256, blockSize: 64 * 1024 }])
})

test('onOffer can decline, with or without a reason, and nothing is created', async (t) => {
  const { outputDir, body } = await fixture(t, 'gate-onoffer-decline', 1024)

  for (const [verdict, reason] of [
    [false, 'the receiver declined the file'],
    ['not expecting a file\u0007 today', 'not expecting a file  today'],
    // A hook that forgot to return must not have said yes.
    [undefined, 'the receiver declined the file'],
    [1, 'the receiver declined the file']
  ]) {
    const { socket, keys, offer } = sealedSender()
    const received = settle(receiveFile(socket, outputDir, { ...keys, onOffer: async () => /** @type {any} */ (verdict) }))
    const reply = await offer(manifestFor(body), body)
    assert.equal(reply.type, TYPE_DECLINE, `${JSON.stringify(verdict)} must decline`)
    assert.equal(reply.body.reason, reason)

    const outcome = await received
    assert.equal(outcome.error.code, 'ERR_DECLINED')
    assert.equal(outcome.error.local, true)
  }
  assert.deepEqual(await fs.promises.readdir(outputDir), [], 'a declined offer opens nothing')
})

test('onOffer is only asked about an offer the engine would take', async (t) => {
  const { outputDir, body } = await fixture(t, 'gate-onoffer-unsafe', 1024)
  const { socket, keys, offer } = sealedSender()

  let asked = 0
  const received = settle(receiveFile(socket, outputDir, { ...keys, onOffer: () => { asked++; return true } }))
  const reply = await offer(manifestFor(body, { name: '../escape.bin' }), body)

  assert.equal(reply.type, TYPE_DECLINE)
  assert.match(reply.body.reason, /resolves outside|separator|refusing the peer's filename/)
  assert.equal((await received).error.code, 'ERR_UNSAFE_NAME')
  assert.equal(asked, 0, 'a person must never be asked to approve a name the engine refuses anyway')
})

test('a slow decision is not mistaken for a stalled sender', async (t) => {
  const { outputDir, body } = await fixture(t, 'gate-slow-decision', 1024)
  const { socket, keys, offer } = sealedSender()

  // A person at an accept screen, taking three stall budgets to decide.
  const received = receiveFile(socket, outputDir, {
    ...keys,
    manifestTimeout: 50,
    progressTimeout: 50,
    onOffer: () => new Promise((resolve) => setTimeout(() => resolve(true), 150))
  })
  await offer(manifestFor(body), body)
  const result = await received
  assert.deepEqual(await fs.promises.readFile(result.path), body)
})

test('a sender that cancels while its offer is considered is heard, and not accepted after', async (t) => {
  const { outputDir, body } = await fixture(t, 'gate-cancel-offer', 1024)
  const { socket, keys, send, received: frames } = sealedSender()

  /** @type {(v: boolean) => void} */
  let decide = () => {}
  const received = settle(receiveFile(socket, outputDir, {
    ...keys,
    onOffer: () => new Promise((resolve) => { decide = resolve })
  }))
  send(TYPE_MANIFEST, Buffer.from(JSON.stringify(manifestFor(body)), 'utf8'))
  await tick()
  send(TYPE_CANCEL, cancelBody('changed my mind'))

  const outcome = await received
  assert.equal(outcome.error.code, 'ERR_CANCELLED_PEER')
  assert.equal(outcome.error.peerReason, 'changed my mind')

  // The person answers after the sender has gone. Nothing may follow.
  decide(true)
  await tick()
  assert.deepEqual(frames.map((f) => f.type), [], 'no ACCEPT for an offer that was withdrawn')
  assert.deepEqual(await fs.promises.readdir(outputDir), [])
})

test('a chunk larger than the declared blockSize is refused', async (t) => {
  const { outputDir, body } = await fixture(t, 'gate-blocksize', 4096)
  const { socket, keys, offer } = sealedSender()

  const received = settle(receiveFile(socket, outputDir, { ...keys }))
  await offer(manifestFor(body, { blockSize: 1024 }), body)

  const outcome = await received
  assert.equal(outcome.error.code, 'ERR_PROTOCOL')
  assert.match(outcome.error.message, /4096-byte chunk, over the 1024-byte blockSize/)
  assert.deepEqual(await fs.promises.readdir(outputDir), [])
})

// --- what the sender is told ---------------------------------------------

test('a decline for a local fault tells the peer its code, not the receiver\'s paths', { skip: process.platform === 'win32' || process.getuid?.() === 0 ? 'needs POSIX permissions and a non-root user' : false }, async (t) => {
  const { outputDir, body } = await fixture(t, 'gate-leak', 1024)
  // The .part cannot be created, so the open fails with EACCES -- whose
  // message is "EACCES: permission denied, open '<outputDir>/payload.bin.part'".
  await fs.promises.chmod(outputDir, 0o555)
  const { socket, keys, offer } = sealedSender()

  const received = settle(receiveFile(socket, outputDir, { ...keys }))
  const reply = await offer(manifestFor(body), body)

  assert.equal(reply.type, TYPE_DECLINE)
  assert.match(reply.body.reason, /EACCES/)
  assert.equal(reply.body.reason.includes(outputDir), false, `the reason leaked a local path: ${reply.body.reason}`)
  assert.equal(reply.body.reason.includes(os.userInfo().username), false)
  // The receiver's own report keeps the full detail; only the peer's copy
  // is trimmed.
  assert.match((await received).error.message, /permission denied/)
})

test('a size the disk cannot hold is declined without saying how full the disk is', async (t) => {
  const { outputDir } = await fixture(t, 'gate-nospace', 0)
  const { socket, keys, offer } = sealedSender()

  // 4 PiB: past any real disk while still a safe integer, and past the
  // default cap too, which is opted out of so that the free-space check is
  // what refuses it.
  const size = 2 ** 52
  const received = settle(receiveFile(socket, outputDir, { ...keys, maxSize: null }))
  const reply = await offer({ v: 2, name: 'huge.bin', size, sha256: 'a'.repeat(64), blockSize: 64 * 1024 })

  const outcome = await received
  assert.equal(outcome.error.code, 'ERR_NO_SPACE')
  assert.equal(reply.type, TYPE_DECLINE)
  assert.equal(reply.body.reason, `the receiver does not have ${size} bytes free`)
})

// --- end to end -----------------------------------------------------------

test('end to end: a receiver that declines is reported by the sender with its reason', async (t) => {
  const { sourcePath, outputDir } = await fixture(t, 'gate-e2e-decline')
  const [txSocket, rxSocket] = duplexPair()
  const keys = channelKeys()
  let progressed = 0

  const [sent, received] = await Promise.all([
    settle(sendFile(txSocket, sourcePath, { ...keys.sender, onProgress: ({ bytes }) => { progressed = bytes } })),
    settle(receiveFile(rxSocket, outputDir, { ...keys.receiver, onOffer: () => 'only photos, please' }))
  ])

  assert.equal(sent.error.code, 'ERR_DECLINED')
  assert.equal(sent.error.peerReason, 'only photos, please')
  assert.equal(received.error.code, 'ERR_DECLINED')
  assert.equal(progressed, 0, 'no byte of a declined file was handed off')
  assert.deepEqual(await fs.promises.readdir(outputDir), [])

  // And both CLIs say so in words, rather than falling through to the
  // generic "error:" line an unknown code gets.
  assert.equal(describeError(sent.error), 'the receiver declined the file: only photos, please. Nothing was sent.')
  assert.equal(describeError(received.error), 'declined the offer: only photos, please. The sender was told, and nothing was written.')
})

test('end to end: an empty file is offered, accepted and confirmed', async (t) => {
  const { sourcePath, outputDir, sha256 } = await fixture(t, 'gate-e2e-empty', 0)
  const [txSocket, rxSocket] = duplexPair()
  const keys = channelKeys()

  const [sent, received] = await Promise.all([
    sendFile(txSocket, sourcePath, { ...keys.sender }),
    receiveFile(rxSocket, outputDir, { ...keys.receiver })
  ])
  assert.equal(sent.sha256, sha256)
  assert.equal(received.size, 0)
  assert.deepEqual(await fs.promises.readdir(outputDir), ['source.bin'])
})
