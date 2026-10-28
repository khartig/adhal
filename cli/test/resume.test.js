'use strict'

// Resume (PROTOCOL.md sections 7 and 8.3): ACCEPT{resumeFrom}, CHECKPOINT
// every few seconds after an fsync, a re-hashed .part prefix, and a failed
// receive that keeps its partial when -- and only when -- it was
// interrupted.
//
// Re-pairing, not a persisted secret (section 7.1): every resumed transfer
// below runs under FRESH channel keys, as a second drop with a new code
// would. The receiver finds the partial by name; nothing about the first
// session survives except the bytes on disk.
//
// The partial is not trusted (section 7.2), and the security tests here
// are the ones that matter most: a .part is a predictable name in a
// directory other things can write to, so each way of planting one --
// symlink, hard link, foreign bytes -- is tried against a real receiver.
//
// And a prefix is checked before it is resumed (section 7.5): ACCEPT
// proposes a PREFIX_BOUNDARY-aligned offset, the sender answers with
// PREFIX{sha256} of its own first bytes, and the receiver's second ACCEPT
// is that offset on a match or 0 after discarding its partial.

const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('node:path')
const os = require('node:os')
const fs = require('node:fs')
const crypto = require('node:crypto')
const { Readable } = require('node:stream')

const {
  sendFile,
  sendStream,
  receiveFile,
  acceptBody,
  resultBody,
  checkpointBody,
  prefixBody,
  declineBody,
  cancelBody,
  PREFIX_BOUNDARY,
  TYPE_MANIFEST,
  TYPE_CHUNK,
  TYPE_ACCEPT,
  TYPE_DECLINE,
  TYPE_CHECKPOINT,
  TYPE_RESULT,
  TYPE_PREFIX,
  TYPE_CANCEL
} = require('@ad-hal/engine')
const { duplexPair } = require('../test-helpers/duplex-pair')
const { channelKeys, sealedPeer, sealedSender } = require('../test-helpers/sealed')
const { assertSameBytes } = require('../test-helpers/bytes')

const RESUME = ['resume']
const MiB = 1024 * 1024

async function fixture (t, label, size = 4 * MiB) {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), `adhal-${label}-`))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const sourcePath = path.join(dir, 'payload.bin')
  const outputDir = path.join(dir, 'out')
  await fs.promises.mkdir(outputDir)
  const body = crypto.randomBytes(size)
  await fs.promises.writeFile(sourcePath, body)
  const sha256 = crypto.createHash('sha256').update(body).digest('hex')
  return { dir, sourcePath, outputDir, body, sha256, partPath: path.join(outputDir, 'payload.bin.part') }
}

/** @param {any} promise */
async function settle (promise) {
  return promise.then((value) => ({ ok: true, value }), (error) => ({ ok: false, error }))
}

const tick = (ms = 20) => new Promise((resolve) => setTimeout(resolve, ms))

const sha = (/** @type {Buffer} */ bytes) => crypto.createHash('sha256').update(bytes).digest('hex')
const accepts = (/** @type {Array<{ type: number, body: Buffer }>} */ frames) =>
  frames.filter((f) => f.type === TYPE_ACCEPT).map((f) => JSON.parse(f.body.toString('utf8')).resumeFrom)

/**
 * @param {() => boolean} ready
 * @param {string} what
 */
async function until (ready, what) {
  for (let i = 0; i < 250; i++) {
    if (ready()) return
    await tick(10)
  }
  throw new Error(`timed out waiting for ${what}`)
}

// A real receiveFile against a hand-rolled sender, for the tests that must
// send what an honest sendFile never would.
function receiverUnderTest (outputDir, options = {}) {
  const [peer, socket] = duplexPair()
  const keys = channelKeys()
  const tx = sealedPeer(peer, keys.sender)
  const received = settle(receiveFile(socket, outputDir, { ...keys.receiver, caps: RESUME, ...options }))
  return { peer, tx, received }
}

// A hand-rolled receiver that proposes `from` and then answers the sender's
// PREFIX through `answer`, so a test can see exactly what the sender sends.
function senderUnderTest (sourcePath, from, answer, options = {}) {
  const [txSocket, peer] = duplexPair()
  const keys = channelKeys()
  const rx = sealedPeer(peer, keys.receiver, {
    onMessage: (type, body) => {
      if (type === TYPE_MANIFEST) rx.send(TYPE_ACCEPT, acceptBody({ resumeFrom: from }))
      if (type === TYPE_PREFIX) answer(rx, JSON.parse(body.toString('utf8')).sha256)
    }
  })
  const sent = settle(sendFile(txSocket, sourcePath, { ...keys.sender, caps: RESUME, ...options }))
  return { rx, sent }
}

// One complete sendFile/receiveFile pair under fresh keys: a drop.
function drop (sourcePath, outputDir, { sender = {}, receiver = {} } = {}) {
  const [txSocket, rxSocket] = duplexPair()
  const keys = channelKeys()
  return {
    txSocket,
    rxSocket,
    sent: settle(sendFile(txSocket, sourcePath, { ...keys.sender, caps: RESUME, ...sender })),
    received: settle(receiveFile(rxSocket, outputDir, { ...keys.receiver, caps: RESUME, ...receiver }))
  }
}

// A drop whose connection is cut once the receiver has `after` bytes: the
// dead hole punch, the laptop lid, the process that was killed.
async function interruptedDrop (sourcePath, outputDir, after) {
  /** @type {any} */
  let cut = null
  const d = drop(sourcePath, outputDir, {
    receiver: { onProgress: ({ bytes }) => { if (bytes >= after && cut) { cut.destroy(); cut = null } } }
  })
  cut = d.txSocket
  return { sent: await d.sent, received: await d.received }
}

// --- the round trip -------------------------------------------------------

test('an interrupted transfer keeps its partial, and a re-paired one resumes from it', async (t) => {
  const { sourcePath, outputDir, body, sha256, partPath } = await fixture(t, 'resume-e2e')

  const first = await interruptedDrop(sourcePath, outputDir, MiB)
  assert.equal(first.received.error.code, 'ERR_CONNECTION')
  // THE CHANGE. A failed receive used to delete its partial on every path.
  const kept = first.received.error.partial
  assert.ok(kept, 'an interrupted, resumable transfer must report the partial it kept')
  assert.equal(kept.path, partPath)
  assert.ok(kept.bytes >= MiB && kept.bytes < body.length, `kept ${kept.bytes} bytes`)
  const onDisk = await fs.promises.readFile(partPath)
  assertSameBytes(onDisk, body.subarray(0, onDisk.length), 'what was kept is exactly a prefix of the file')

  // A second drop: new keys, as a new code would give. Found by name.
  // Resumed from the last whole boundary it held (section 7.5): the bytes
  // past it are cut off and sent again.
  const boundary = onDisk.length - (onDisk.length % PREFIX_BOUNDARY)
  const second = drop(sourcePath, outputDir)
  const [sent, received] = [await second.sent, await second.received]
  assert.equal(received.ok, true, received.error && received.error.message)
  assert.equal(sent.value.resumedFrom, boundary)
  assert.equal(received.value.resumedFrom, boundary)
  assert.equal(received.value.sha256, sha256)
  assert.equal(received.value.size, body.length)
  assertSameBytes(await fs.promises.readFile(received.value.path), body)
  assert.deepEqual(await fs.promises.readdir(outputDir), ['payload.bin'], 'the partial became the file')
})

test('a resumed sender proves its prefix, then reads the file from resumeFrom and nothing before it', async (t) => {
  const { sourcePath, body, sha256 } = await fixture(t, 'resume-sender', 2 * MiB + 12345)
  const from = 2 * MiB
  /** @type {number[]} */
  const progress = []
  /** @type {string[]} */
  const digests = []
  const { rx, sent } = senderUnderTest(sourcePath, from, (peer, digest) => {
    digests.push(digest)
    peer.send(TYPE_ACCEPT, acceptBody({ resumeFrom: from }))
  }, { onProgress: ({ bytes }) => progress.push(bytes) })

  await until(() => rx.received.filter((f) => f.type === TYPE_CHUNK).length > 0, 'the first chunk')
  await tick(50)
  // The digest of the sender's OWN first `from` bytes, recorded while it
  // hashed the file for the manifest.
  assert.deepEqual(digests, [sha(body.subarray(0, from))])
  const types = rx.received.map((f) => f.type)
  assert.equal(types.indexOf(TYPE_PREFIX), 1, 'PREFIX follows the MANIFEST and precedes every chunk')
  const chunks = rx.received.filter((f) => f.type === TYPE_CHUNK).map((f) => f.body)
  assertSameBytes(Buffer.concat(chunks), body.subarray(from))
  rx.send(TYPE_RESULT, resultBody({ ok: true, sha256 }))

  const outcome = await sent
  assert.equal(outcome.ok, true, outcome.error && outcome.error.message)
  const result = outcome.value
  assert.equal(result.resumedFrom, from)
  assert.equal(result.size, body.length)
  // Starts at 0 as the contract promises, jumps to where it resumed, and
  // never goes backwards.
  assert.equal(progress[0], 0)
  assert.equal(progress[1], from)
  assert.deepEqual(progress, [...progress].sort((a, b) => a - b))
})

test('an ACCEPT that asks to resume where it cannot is refused', async (t) => {
  const { sourcePath, body } = await fixture(t, 'resume-bad-accept', 1024)

  for (const [caps, resumeFrom, stream, why] of [
    [[], 10, false, /did not negotiate resume/],
    [RESUME, body.length + 1, false, /past the 1024 bytes offered/],
    // Section 7.5: only a boundary multiple or the whole file.
    [RESUME, 1000, false, /neither a multiple of 1048576 nor the whole file/],
    [['resume', 'stream'], 10, true, /a stream cannot be resumed/]
  ]) {
    const [txSocket, peer] = duplexPair()
    const keys = channelKeys()
    const rx = sealedPeer(peer, keys.receiver, {
      onMessage: (type) => { if (type === TYPE_MANIFEST) rx.send(TYPE_ACCEPT, acceptBody({ resumeFrom: /** @type {number} */ (resumeFrom) })) }
    })
    const options = { ...keys.sender, caps: /** @type {string[]} */ (caps) }
    const outcome = await settle(stream
      ? sendStream(txSocket, Readable.from([body]), { ...options, name: 'pipe' })
      : sendFile(txSocket, sourcePath, options))
    assert.equal(outcome.error.code, 'ERR_PROTOCOL')
    assert.match(outcome.error.message, /** @type {RegExp} */ (why))
    assert.equal(rx.received.filter((f) => f.type === TYPE_CHUNK).length, 0)
  }
})

test('a partial that already holds every byte is verified and published with nothing sent', async (t) => {
  const { sourcePath, outputDir, body, partPath } = await fixture(t, 'resume-complete', 64 * 1024)
  await fs.promises.writeFile(partPath, body)

  const d = drop(sourcePath, outputDir)
  const [sent, received] = [await d.sent, await d.received]
  assert.equal(received.value.resumedFrom, body.length)
  assert.equal(sent.value.resumedFrom, body.length)
  assert.deepEqual(await fs.promises.readdir(outputDir), ['payload.bin'])
})

// --- the partial is not trusted -------------------------------------------

test('a foreign partial is caught by the prefix check and the same transfer starts over, with no failure', async (t) => {
  const { sourcePath, outputDir, body, partPath } = await fixture(t, 'resume-foreign', 3 * MiB)
  // Bytes that are not a prefix of this file, under the name it will look
  // for: a planted partial, long enough to be proposed.
  await fs.promises.writeFile(partPath, crypto.randomBytes(2 * MiB + 500))

  const d = drop(sourcePath, outputDir)
  const [sent, received] = [await d.sent, await d.received]
  // THE CHANGE (section 7.5). This used to fail ERR_HASH_MISMATCH after the
  // whole remainder had been sent, and the person saw it. Now the mismatch
  // costs one round trip and is not an error at all.
  assert.equal(received.ok, true, received.error && received.error.message)
  assert.equal(sent.ok, true, sent.error && sent.error.message)
  assert.equal(received.value.resumedFrom, 0)
  assert.equal(sent.value.resumedFrom, 0)
  assertSameBytes(await fs.promises.readFile(received.value.path), body)
  assert.deepEqual(await fs.promises.readdir(outputDir), ['payload.bin'], 'the foreign partial became this file, from zero')
})

test('a stale partial of an older version of the file is discarded by the prefix check, not resumed', async (t) => {
  // The everyday case: an interrupted send of an older report.pdf, now
  // offered again as a newer file under the same name. Same length, same
  // tail; only its first bytes differ.
  const { sourcePath, outputDir, body, partPath } = await fixture(t, 'resume-stale', 3 * MiB)
  const older = Buffer.from(body.subarray(0, 2 * MiB))
  older[0] ^= 0xff
  await fs.promises.writeFile(partPath, older)

  const d = drop(sourcePath, outputDir)
  const [sent, received] = [await d.sent, await d.received]
  assert.equal(received.ok, true, received.error && received.error.message)
  assert.equal(sent.value.resumedFrom, 0)
  assertSameBytes(await fs.promises.readFile(received.value.path), body)
})

test('a matching prefix with a foreign tail resumes at the boundary, and the tail is cut off', async (t) => {
  const { sourcePath, outputDir, body, partPath } = await fixture(t, 'resume-tail', 3 * MiB)
  await fs.promises.writeFile(partPath, Buffer.concat([body.subarray(0, MiB), crypto.randomBytes(300000)]))

  const d = drop(sourcePath, outputDir)
  const [sent, received] = [await d.sent, await d.received]
  assert.equal(received.ok, true, received.error && received.error.message)
  assert.equal(received.value.resumedFrom, MiB)
  assert.equal(sent.value.resumedFrom, MiB)
  assertSameBytes(await fs.promises.readFile(received.value.path), body)
})

test('a partial under one boundary is reused from zero, not left beside a fresh .part.1', async (t) => {
  const { sourcePath, outputDir, body, partPath } = await fixture(t, 'resume-small', 3 * MiB)
  await fs.promises.writeFile(partPath, body.subarray(0, 1000))

  const d = drop(sourcePath, outputDir)
  const [sent, received] = [await d.sent, await d.received]
  assert.equal(received.value.resumedFrom, 0)
  assert.equal(sent.value.resumedFrom, 0)
  assertSameBytes(await fs.promises.readFile(received.value.path), body)
  assert.deepEqual(await fs.promises.readdir(outputDir), ['payload.bin'], 'one partial, the primary one, and it became the file')
})

// --- the prefix check, frame by frame (section 7.5) -----------------------

test('the receiver proposes a boundary, and answers a wrong PREFIX with ACCEPT{0} after truncating its partial', async (t) => {
  const { outputDir, body, sha256, partPath } = await fixture(t, 'prefix-wrong', 3 * MiB)
  const prefix = body.subarray(0, 2 * MiB + 777)
  await fs.promises.writeFile(partPath, prefix)
  const { tx, received } = receiverUnderTest(outputDir)

  tx.send(TYPE_MANIFEST, Buffer.from(JSON.stringify({ v: 2, name: 'payload.bin', size: body.length, sha256, blockSize: 65536 })))
  await until(() => accepts(tx.received).length === 1, 'the proposal')
  assert.deepEqual(accepts(tx.received), [2 * MiB], 'rounded down to the boundary')
  // Nothing is cut off or adopted while the proposal is outstanding.
  assertSameBytes(await fs.promises.readFile(partPath), prefix)

  tx.send(TYPE_PREFIX, prefixBody({ sha256: sha(crypto.randomBytes(16)) }))
  await until(() => accepts(tx.received).length === 2, 'the final answer')
  assert.deepEqual(accepts(tx.received), [2 * MiB, 0])
  assert.equal((await fs.promises.stat(partPath)).size, 0, 'the prefix that did not match is gone before the answer')

  for (let offset = 0; offset < body.length; offset += 65536) tx.send(TYPE_CHUNK, body.subarray(offset, offset + 65536))
  const outcome = await received
  assert.equal(outcome.ok, true, outcome.error && outcome.error.message)
  assert.equal(outcome.value.resumedFrom, 0)
  assertSameBytes(await fs.promises.readFile(outcome.value.path), body)
})

test('the receiver answers a right PREFIX with the offset it proposed, and cuts the tail past it', async (t) => {
  const { outputDir, body, sha256, partPath } = await fixture(t, 'prefix-right', 3 * MiB)
  await fs.promises.writeFile(partPath, body.subarray(0, 2 * MiB + 777))
  const { tx, received } = receiverUnderTest(outputDir)

  tx.send(TYPE_MANIFEST, Buffer.from(JSON.stringify({ v: 2, name: 'payload.bin', size: body.length, sha256, blockSize: 65536 })))
  await until(() => accepts(tx.received).length === 1, 'the proposal')
  tx.send(TYPE_PREFIX, prefixBody({ sha256: sha(body.subarray(0, 2 * MiB)) }))
  await until(() => accepts(tx.received).length === 2, 'the final answer')
  assert.deepEqual(accepts(tx.received), [2 * MiB, 2 * MiB])
  assert.equal((await fs.promises.stat(partPath)).size, 2 * MiB)

  for (let offset = 2 * MiB; offset < body.length; offset += 65536) tx.send(TYPE_CHUNK, body.subarray(offset, offset + 65536))
  const outcome = await received
  assert.equal(outcome.value.resumedFrom, 2 * MiB)
  assertSameBytes(await fs.promises.readFile(outcome.value.path), body)
})

test('nothing the receiver sends carries a digest of its own partial', async (t) => {
  // Section 7.5's reason for the direction. A digest of the receiver's
  // partial would give a peer whose only credential is the code something
  // to test guesses of it against, offline -- and an HMAC keyed from the
  // session would not help, because the peer holds the session key too.
  const { outputDir, body, sha256, partPath } = await fixture(t, 'prefix-no-leak', 3 * MiB)
  const partial = crypto.randomBytes(2 * MiB)
  await fs.promises.writeFile(partPath, partial)
  const { tx, received } = receiverUnderTest(outputDir)

  tx.send(TYPE_MANIFEST, Buffer.from(JSON.stringify({ v: 2, name: 'payload.bin', size: body.length, sha256, blockSize: 65536 })))
  await until(() => accepts(tx.received).length === 1, 'the proposal')
  tx.send(TYPE_PREFIX, prefixBody({ sha256: sha(body.subarray(0, 2 * MiB)) }))
  await until(() => accepts(tx.received).length === 2, 'the final answer')
  for (let offset = 0; offset < body.length; offset += 65536) tx.send(TYPE_CHUNK, body.subarray(offset, offset + 65536))
  await received

  const raw = crypto.createHash('sha256').update(partial).digest()
  for (const frame of tx.received) {
    assert.equal(frame.body.includes(raw), false, `${frame.type} carries the raw digest`)
    assert.equal(frame.body.includes(raw.toString('hex')), false, `${frame.type} carries the hex digest`)
    assert.equal(frame.body.includes(raw.toString('base64')), false, `${frame.type} carries the base64 digest`)
  }
})

test('a sender that does not answer the proposal with PREFIX is refused, and the earlier partial is left intact', async (t) => {
  const { outputDir, body, sha256, partPath } = await fixture(t, 'prefix-refused', 3 * MiB)
  const prefix = body.subarray(0, 2 * MiB)
  const manifest = Buffer.from(JSON.stringify({ v: 2, name: 'payload.bin', size: body.length, sha256, blockSize: 65536 }))

  for (const [what, act, code, why] of [
    ['a CHUNK', (/** @type {any} */ tx) => tx.send(TYPE_CHUNK, body.subarray(2 * MiB, 2 * MiB + 100)), 'ERR_PROTOCOL', /while a resume was being checked; only PREFIX or CANCEL/],
    ['a malformed PREFIX', (/** @type {any} */ tx) => tx.send(TYPE_PREFIX, Buffer.from('{"sha256":"ABC"}')), 'ERR_PROTOCOL', /PREFIX does not carry a lowercase hex sha256/],
    ['silence', () => {}, 'ERR_STALLED', /never sent the PREFIX its resume needs/]
  ]) {
    await fs.promises.writeFile(partPath, prefix)
    const { tx, received } = receiverUnderTest(outputDir, { progressTimeout: 100 })
    tx.send(TYPE_MANIFEST, manifest)
    await until(() => accepts(tx.received).length === 1, 'the proposal')
    const misbehave = /** @type {(tx: any) => void} */ (act)
    misbehave(tx)
    const outcome = await received
    assert.equal(outcome.ok, false, /** @type {string} */ (what))
    assert.equal(outcome.error.code, code, /** @type {string} */ (what))
    assert.match(outcome.error.message, /** @type {RegExp} */ (why))
    assertSameBytes(await fs.promises.readFile(partPath), prefix, `${what} before the final ACCEPT must leave the earlier partial intact`)
  }
})

test('a PREFIX nobody asked for is refused', async (t) => {
  const { outputDir, body, sha256 } = await fixture(t, 'prefix-unsolicited', 64 * 1024)
  const manifest = Buffer.from(JSON.stringify({ v: 2, name: 'payload.bin', size: body.length, sha256, blockSize: 65536 }))

  // Before any offer, and after an ACCEPT{0} that proposed nothing.
  for (const afterOffer of [false, true]) {
    const { tx, received } = receiverUnderTest(outputDir)
    if (afterOffer) {
      tx.send(TYPE_MANIFEST, manifest)
      await until(() => accepts(tx.received).length === 1, 'the answer')
      assert.deepEqual(accepts(tx.received), [0])
    }
    tx.send(TYPE_PREFIX, prefixBody({ sha256 }))
    const outcome = await received
    assert.equal(outcome.error.code, 'ERR_PROTOCOL')
  }
})

test('the sender starts over from zero when the receiver answers its PREFIX with ACCEPT{0}', async (t) => {
  const { sourcePath, body, sha256 } = await fixture(t, 'prefix-restart', 2 * MiB + 99)
  const { rx, sent } = senderUnderTest(sourcePath, MiB, (peer) => peer.send(TYPE_ACCEPT, acceptBody({ resumeFrom: 0 })))

  await until(() => rx.received.filter((f) => f.type === TYPE_CHUNK).reduce((n, f) => n + f.body.length, 0) === body.length, 'every byte')
  const chunks = rx.received.filter((f) => f.type === TYPE_CHUNK).map((f) => f.body)
  assertSameBytes(Buffer.concat(chunks), body, 'the whole file, from byte 0')
  rx.send(TYPE_RESULT, resultBody({ ok: true, sha256 }))
  const outcome = await sent
  assert.equal(outcome.value.resumedFrom, 0)
})

test('a whole-file proposal is proven with the manifest\'s own digest', async (t) => {
  const { sourcePath, body, sha256 } = await fixture(t, 'prefix-whole', 2 * MiB)
  /** @type {string[]} */
  const digests = []
  const { rx, sent } = senderUnderTest(sourcePath, body.length, (peer, digest) => {
    digests.push(digest)
    peer.send(TYPE_ACCEPT, acceptBody({ resumeFrom: body.length }))
    peer.send(TYPE_RESULT, resultBody({ ok: true, sha256 }))
  })
  const outcome = await sent
  assert.equal(outcome.ok, true, outcome.error && outcome.error.message)
  assert.deepEqual(digests, [sha256])
  assert.equal(rx.received.filter((f) => f.type === TYPE_CHUNK).length, 0)
})

test('the sender refuses any answer to its PREFIX but the proposed offset, 0, DECLINE, or CANCEL', async (t) => {
  const { sourcePath } = await fixture(t, 'prefix-sender-refuses', 3 * MiB)

  for (const [what, answer, code, why] of [
    ['a different offset', (/** @type {any} */ peer) => peer.send(TYPE_ACCEPT, acceptBody({ resumeFrom: MiB })), 'ERR_PROTOCOL', /only 2097152 \(a match\) or 0 \(start over\)/],
    ['a CHECKPOINT', (/** @type {any} */ peer) => peer.send(TYPE_CHECKPOINT, checkpointBody({ offset: 0 })), 'ERR_PROTOCOL', /before answering its prefix check/],
    ['a DECLINE', (/** @type {any} */ peer) => peer.send(TYPE_DECLINE, declineBody('changed my mind', 'ERR_DECLINED')), 'ERR_DECLINED', /changed my mind/],
    ['silence', () => {}, 'ERR_STALLED', /has not answered its prefix check/]
  ]) {
    const { rx, sent } = senderUnderTest(sourcePath, 2 * MiB, /** @type {any} */ (answer), { acceptTimeout: 100 })
    const outcome = await sent
    assert.equal(outcome.ok, false, /** @type {string} */ (what))
    assert.equal(outcome.error.code, code, /** @type {string} */ (what))
    assert.match(outcome.error.message, /** @type {RegExp} */ (why))
    assert.equal(rx.received.filter((f) => f.type === TYPE_CHUNK).length, 0, `no file byte moves after ${what}`)
  }
})

test('a receiver that goes quiet after proposing a resume is reported as stalled in the prefix phase, with nothing sent', async (t) => {
  // The log has to say where the transfer stopped and how much moved: a
  // proposal nobody followed up is the prefix phase, and no file byte has
  // been sent in it.
  const { sourcePath } = await fixture(t, 'prefix-sender-silence', 3 * MiB)
  const { sent } = senderUnderTest(sourcePath, 2 * MiB, () => {}, { acceptTimeout: 100 })
  const outcome = await sent
  assert.equal(outcome.ok, false)
  assert.equal(outcome.error.code, 'ERR_STALLED')
  assert.equal(outcome.error.phase, 'prefix')
  assert.equal(outcome.error.bytes, 0)
})

test('the prefix digests are right even when the file is read in chunks that straddle a boundary', async (t) => {
  // The hash splits every read at each PREFIX_BOUNDARY, so PREFIX can be
  // answered from digests recorded on the one read. A local disk read in
  // 64 KiB pieces never straddles a 1 MiB boundary, so the split never
  // happens there -- the W12 mutation run showed nothing exercised it --
  // but a network filesystem's short reads can misalign every read after
  // them. An odd read size, forced on the hashing read only, plays that.
  const { sourcePath, body } = await fixture(t, 'prefix-unaligned', 3 * MiB)
  const realOpen = fs.promises.open
  t.mock.method(fs.promises, 'open', async (/** @type {any[]} */ ...args) => {
    const handle = await realOpen.apply(fs.promises, /** @type {any} */ (args))
    if (args[0] === sourcePath) {
      const realCreate = handle.createReadStream.bind(handle)
      let first = true
      handle.createReadStream = (/** @type {any} */ options) => {
        if (!first) return realCreate(options)
        first = false
        return realCreate({ ...options, highWaterMark: 100000 })
      }
    }
    return handle
  })

  /** @type {string | null} */
  let digest = null
  const { sent } = senderUnderTest(sourcePath, 2 * MiB, (/** @type {any} */ peer, /** @type {string} */ sha256) => {
    digest = sha256
    peer.send(TYPE_DECLINE, declineBody('only checking', 'ERR_DECLINED'))
  })
  const outcome = await sent
  assert.equal(outcome.ok, false)
  assert.equal(outcome.error.code, 'ERR_DECLINED', outcome.error.message)
  assert.equal(digest, sha(body.subarray(0, 2 * MiB)))
})

test('a CHECKPOINT that arrives with the RESULT is not reported after the transfer is over', async (t) => {
  // Once RESULT{ok} has settled the send, nothing the receiver sends can
  // change it, or be reported as if it could. Frames packed into the same
  // write are still opened one by one after RESULT, so the settle has to
  // stop them, not just the next 'data' event.
  const { sourcePath, body, sha256 } = await fixture(t, 'checkpoint-after-result', 256 * 1024)
  const [txSocket, peer] = duplexPair()
  const keys = channelKeys()
  let got = 0
  const rx = sealedPeer(peer, keys.receiver, {
    onMessage: (type, frame) => {
      if (type === TYPE_MANIFEST) rx.send(TYPE_ACCEPT, acceptBody({ resumeFrom: 0 }))
      if (type !== TYPE_CHUNK) return
      got += frame.length
      if (got < body.length) return
      peer.write(Buffer.concat([
        rx.channel.seal(TYPE_RESULT, resultBody({ ok: true, sha256 })),
        rx.channel.seal(TYPE_CHECKPOINT, checkpointBody({ offset: body.length }))
      ]))
    }
  })
  /** @type {number[]} */
  const checkpoints = []
  const sent = await sendFile(txSocket, sourcePath, { ...keys.sender, caps: RESUME, onCheckpoint: ({ offset }) => checkpoints.push(offset) })
  await tick()
  assert.equal(sent.sha256, sha256)
  assert.deepEqual(checkpoints, [])
})

test('a planted .part symlink is never followed on resume', { skip: process.platform === 'win32' ? 'symlinks need privileges on Windows' : false }, async (t) => {
  const { dir, sourcePath, outputDir, body, partPath } = await fixture(t, 'resume-symlink', 64 * 1024)
  const target = path.join(dir, 'authorized_keys')
  await fs.promises.writeFile(target, 'ssh-ed25519 AAAA the real key\n')
  await fs.promises.symlink(target, partPath)

  const d = drop(sourcePath, outputDir)
  const received = await d.received
  assert.equal(received.value.resumedFrom, 0, 'a symlink is not a partial to resume')
  assertSameBytes(await fs.promises.readFile(received.value.path), body)
  assert.equal(await fs.promises.readFile(target, 'utf8'), 'ssh-ed25519 AAAA the real key\n', 'the link target is untouched')
  assert.equal((await fs.promises.lstat(partPath)).isSymbolicLink(), true, 'and the link is not ours to remove')
})

test('a planted .part hard link is never appended to on resume', { skip: process.platform === 'win32' ? 'hard-link semantics differ on Windows' : false }, async (t) => {
  // The case O_NOFOLLOW cannot see: a hard link is a regular file. Only
  // its link count gives it away, and appending to it would write into
  // the file it shares an inode with.
  const { dir, sourcePath, outputDir, body, partPath } = await fixture(t, 'resume-hardlink', 64 * 1024)
  const target = path.join(dir, 'bashrc')
  await fs.promises.writeFile(target, 'alias ls=ls\n')
  await fs.promises.link(target, partPath)

  const d = drop(sourcePath, outputDir)
  const received = await d.received
  assert.equal(received.value.resumedFrom, 0)
  assertSameBytes(await fs.promises.readFile(received.value.path), body)
  assert.equal(await fs.promises.readFile(target, 'utf8'), 'alias ls=ls\n', 'the linked file is untouched')
})

test('a partial longer than the offer is not a prefix of it, and is left alone', async (t) => {
  const { sourcePath, outputDir, body, partPath } = await fixture(t, 'resume-longer', 1024)
  const other = crypto.randomBytes(4096)
  await fs.promises.writeFile(partPath, other)

  const d = drop(sourcePath, outputDir)
  const received = await d.received
  assert.equal(received.value.resumedFrom, 0)
  assertSameBytes(await fs.promises.readFile(received.value.path), body)
  assertSameBytes(await fs.promises.readFile(partPath), other, 'not ours, so not deleted either')
})

// --- which failures keep a partial ----------------------------------------

test('a cancel discards the partial, and so does an interruption where resume was not negotiated', async (t) => {
  const { sourcePath, outputDir } = await fixture(t, 'resume-keep-rules')

  // A deliberate cancel by the receiver means "I do not want this".
  {
    const controller = new AbortController()
    const d = drop(sourcePath, outputDir, {
      receiver: { signal: controller.signal, onProgress: ({ bytes }) => { if (bytes > MiB) controller.abort('no thanks') } }
    })
    const received = await d.received
    assert.equal(received.error.name, 'AbortError')
    assert.equal(received.error.partial, undefined)
    await d.sent
    assert.deepEqual(await fs.promises.readdir(outputDir), [], 'a canceled receive keeps nothing')
  }

  // Without resume negotiated there is nobody to resume it, so an
  // interruption discards exactly as it always did.
  {
    /** @type {any} */
    let cut = null
    const d = drop(sourcePath, outputDir, {
      sender: { caps: [] },
      receiver: { caps: [], onProgress: ({ bytes }) => { if (bytes >= MiB && cut) { cut.destroy(); cut = null } } }
    })
    cut = d.txSocket
    const received = await d.received
    assert.equal(received.error.code, 'ERR_CONNECTION')
    assert.deepEqual(await fs.promises.readdir(outputDir), [])
  }
})

test('a sender that goes silent mid-file leaves a resumable partial', async (t) => {
  const { outputDir, body } = await fixture(t, 'resume-stall', 8192)
  const { socket, keys, offer } = sealedSender()

  const received = settle(receiveFile(socket, outputDir, { ...keys, caps: RESUME, progressTimeout: 100 }))
  await offer({ v: 2, name: 'payload.bin', size: body.length, sha256: crypto.createHash('sha256').update(body).digest('hex'), blockSize: 65536 }, body.subarray(0, 3000))

  const outcome = await received
  assert.equal(outcome.error.code, 'ERR_STALLED')
  assert.equal(outcome.error.partial.bytes, 3000)
  assertSameBytes(await fs.promises.readFile(path.join(outputDir, 'payload.bin.part')), body.subarray(0, 3000))
})

// --- CHECKPOINT -----------------------------------------------------------

test('the receiver reports fsynced offsets periodically, and not while nothing is written', async (t) => {
  const { outputDir, body, sha256 } = await fixture(t, 'resume-checkpoint', 64 * 1024)
  const { socket, keys, offer, send, received: frames } = sealedSender()

  const received = receiveFile(socket, outputDir, { ...keys, caps: RESUME, checkpointInterval: 20 })
  await offer({ v: 2, name: 'payload.bin', size: body.length, sha256, blockSize: 8192 })

  const checkpoints = () => frames.filter((f) => f.type === TYPE_CHECKPOINT).map((f) => JSON.parse(f.body.toString('utf8')).offset)
  for (let offset = 0; offset < body.length / 2; offset += 8192) {
    send(TYPE_CHUNK, body.subarray(offset, offset + 8192))
    await tick(30)
  }
  // A CHECKPOINT is sent when its fsync returns, and on Windows that can
  // outlast the loop above: one still in flight here would land during the
  // idle wait below and look like a timer fsync. Wait until everything
  // written is reported, so the idle check sees only what the timer does.
  await until(() => checkpoints().at(-1) === body.length / 2, 'the checkpoint covering every byte sent')
  const seen = checkpoints()
  assert.ok(seen.length >= 2, `expected periodic checkpoints, got ${JSON.stringify(seen)}`)
  assert.deepEqual(seen, [...seen].sort((a, b) => a - b), 'offsets only move forward')
  assert.ok(seen.at(-1) <= body.length / 2)
  // What a checkpoint promises is on disk: the file really is that long.
  assert.ok((await fs.promises.stat(path.join(outputDir, 'payload.bin.part'))).size >= seen.at(-1))

  // Section 8.3's guard: an idle transfer does not fsync on a timer.
  await tick(120)
  assert.equal(checkpoints().length, seen.length, 'no checkpoint without new bytes')

  for (let offset = body.length / 2; offset < body.length; offset += 8192) send(TYPE_CHUNK, body.subarray(offset, offset + 8192))
  await received
})

test('no CHECKPOINT is sent where resume was not negotiated', async (t) => {
  const { outputDir, body, sha256 } = await fixture(t, 'resume-no-checkpoint', 64 * 1024)
  const { socket, keys, offer, send, received: frames } = sealedSender()

  const received = receiveFile(socket, outputDir, { ...keys, checkpointInterval: 10 })
  await offer({ v: 2, name: 'payload.bin', size: body.length, sha256, blockSize: 8192 })
  for (let offset = 0; offset < body.length; offset += 8192) {
    send(TYPE_CHUNK, body.subarray(offset, offset + 8192))
    await tick(15)
  }
  await received
  assert.equal(frames.filter((f) => f.type === TYPE_CHECKPOINT).length, 0)
})

test('the sender hears checkpoints, and refuses ones that are impossible', async (t) => {
  const { sourcePath, sha256 } = await fixture(t, 'resume-sender-checkpoint', 256 * 1024)

  // Honest: monotonic, within what was sent.
  {
    const [txSocket, peer] = duplexPair()
    const keys = channelKeys()
    let got = 0
    const rx = sealedPeer(peer, keys.receiver, {
      onMessage: (type, body) => {
        if (type === TYPE_MANIFEST) rx.send(TYPE_ACCEPT, acceptBody({ resumeFrom: 0 }))
        if (type === TYPE_CHUNK) {
          got += body.length
          if (got === 128 * 1024) rx.send(TYPE_CHECKPOINT, checkpointBody({ offset: 64 * 1024 }))
          if (got === 256 * 1024) {
            rx.send(TYPE_CHECKPOINT, checkpointBody({ offset: 256 * 1024 }))
            rx.send(0x07, resultBody({ ok: true, sha256 }))
          }
        }
      }
    })
    /** @type {number[]} */
    const heard = []
    await sendFile(txSocket, sourcePath, { ...keys.sender, caps: RESUME, onCheckpoint: ({ offset }) => heard.push(offset) })
    assert.deepEqual(heard, [64 * 1024, 256 * 1024])
  }

  for (const [caps, offsets, why] of [
    [[], [1024], /only a resumable transfer carries/],
    [RESUME, [8192, 4096], /outside 8192\.\./],
    [RESUME, [10 * 1024 * 1024], /outside 0\.\./]
  ]) {
    const [txSocket, peer] = duplexPair()
    const keys = channelKeys()
    let got = 0
    const rx = sealedPeer(peer, keys.receiver, {
      onMessage: (type, body) => {
        if (type === TYPE_MANIFEST) rx.send(TYPE_ACCEPT, acceptBody({ resumeFrom: 0 }))
        if (type === TYPE_CHUNK) {
          got += body.length
          if (got === 64 * 1024) for (const offset of /** @type {number[]} */ (offsets)) rx.send(TYPE_CHECKPOINT, checkpointBody({ offset }))
        }
      }
    })
    const outcome = await settle(sendFile(txSocket, sourcePath, { ...keys.sender, caps: /** @type {string[]} */ (caps) }))
    assert.equal(outcome.error.code, 'ERR_PROTOCOL')
    assert.match(outcome.error.message, /** @type {RegExp} */ (why))
  }
})

test('the receiver CLI says a partial was kept, and how to resume it, instead of that it was discarded', async (t) => {
  const { describeError } = require('../src/report')
  const { sourcePath, outputDir, partPath } = await fixture(t, 'resume-report')

  const first = await interruptedDrop(sourcePath, outputDir, MiB)
  const line = describeError(first.received.error)
  assert.match(line, new RegExp(`Kept \\d+ bytes in ${partPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`))
  assert.match(line, /resumes from there/)
  assert.equal(/discarded/.test(line), false, 'a kept partial must not be reported as discarded')

  // And the old sentence still stands where it is true.
  assert.match(describeError({ code: 'ERR_CONNECTION', bytes: 10 }), /The partial file was discarded/)
})

test('an offer that fails before ACCEPT never deletes a partial it reopened from an earlier attempt', async (t) => {
  // The partial belongs to the interrupted drop before this one. This
  // offer had only reopened it to re-hash, so a cancel or a dropped
  // connection before ACCEPT must leave it exactly as it was -- otherwise
  // a flaky re-pairing destroys the bytes resume exists to save.
  const { outputDir, body, sha256, partPath } = await fixture(t, 'resume-early-fail', 256 * 1024)
  const prefix = body.subarray(0, 100000)
  const manifest = Buffer.from(JSON.stringify({ v: 2, name: 'payload.bin', size: body.length, sha256, blockSize: 65536 }))

  for (const how of ['cancel', 'close']) {
    await fs.promises.writeFile(partPath, prefix)
    const [peer, socket] = duplexPair()
    const keys = channelKeys()
    const tx = sealedPeer(peer, keys.sender)
    const received = settle(receiveFile(socket, outputDir, { ...keys.receiver, caps: RESUME }))
    // In one tick: the receiver has started reopening the partial when
    // the second event lands.
    tx.send(TYPE_MANIFEST, manifest)
    if (how === 'cancel') tx.send(0x03, Buffer.from('{"reason":"wrong file"}'))
    else peer.destroy()

    const outcome = await received
    assert.equal(outcome.ok, false, how)
    assertSameBytes(await fs.promises.readFile(partPath), prefix, `${how} before ACCEPT must leave the earlier partial intact`)
  }
})

// --- the partial's edges, pinned --------------------------------------------

// Open descriptors in this process, where the platform exposes them; as in
// verify.test.js.
function openFds () {
  for (const dir of ['/proc/self/fd', '/dev/fd']) {
    try { return fs.readdirSync(dir).length } catch {}
  }
  return null
}

// The prototype every fs.promises FileHandle shares, for the tests that
// slow or fail one of its methods.
async function fileHandlePrototype () {
  const handle = await fs.promises.open(__filename, 'r')
  const proto = Object.getPrototypeOf(handle)
  await handle.close()
  return proto
}

test('a .part that becomes a symlink after it was checked is still never followed', { skip: process.platform === 'win32' ? 'symlinks need privileges on Windows' : false }, async (t) => {
  // The lstat in reopenPartial is the Windows fallback, and it is racy: a
  // link swapped in between the lstat and the open is followed. On every
  // platform with O_NOFOLLOW the open itself refuses the link, which is
  // what this pins -- by letting the lstat lose that race on purpose, so
  // the open is the only check left.
  const { dir, sourcePath, outputDir, body, partPath } = await fixture(t, 'resume-symlink-race', 64 * 1024)
  const target = path.join(dir, 'authorized_keys')
  await fs.promises.writeFile(target, 'ssh-ed25519 AAAA the real key\n')
  await fs.promises.symlink(target, partPath)
  const realLstat = fs.promises.lstat
  t.mock.method(fs.promises, 'lstat', (/** @type {any} */ p, /** @type {any[]} */ ...rest) => realLstat(p === partPath ? target : p, ...rest))

  const received = await drop(sourcePath, outputDir).received
  assert.equal(received.ok, true, received.error && received.error.message)
  assert.equal(received.value.resumedFrom, 0)
  assertSameBytes(await fs.promises.readFile(received.value.path), body)
  assert.equal(await fs.promises.readFile(target, 'utf8'), 'ssh-ed25519 AAAA the real key\n', 'the link target is untouched')
})

test('a partial that holds every byte is published with nothing sent, whatever its length', async (t) => {
  // The re-hash reads the partial a boundary at a time, so its last read
  // is as short as the file's length past the last boundary -- one byte,
  // for these two. A short read is not the end of the file.
  for (const size of [1, PREFIX_BOUNDARY + 1]) {
    const { sourcePath, outputDir, body, partPath } = await fixture(t, 'resume-complete-odd', size)
    await fs.promises.writeFile(partPath, body)
    const d = drop(sourcePath, outputDir)
    const [sent, received] = [await d.sent, await d.received]
    assert.equal(received.ok, true, received.error && received.error.message)
    assert.equal(received.value.resumedFrom, size, `${size} bytes`)
    assert.equal(sent.value.resumedFrom, size, `${size} bytes`)
    assert.deepEqual(await fs.promises.readdir(outputDir), ['payload.bin'], `${size} bytes: the partial became the file`)
  }
})

test('an interruption before the first byte keeps nothing, and a reset partway keeps what arrived', async (t) => {
  // A resumable partial is worth keeping only if it holds something, and
  // a reset is an interruption exactly as a clean close is: the peer's
  // RST is the routine end of a dead connection, not a reason to throw
  // the bytes away.
  const { outputDir, body, sha256, partPath } = await fixture(t, 'resume-keep-edges', 64 * 1024)
  const manifest = Buffer.from(JSON.stringify({ v: 2, name: 'payload.bin', size: body.length, sha256, blockSize: 65536 }))

  {
    const { peer, tx, received } = receiverUnderTest(outputDir)
    tx.send(TYPE_MANIFEST, manifest)
    await until(() => accepts(tx.received).length === 1, 'the answer')
    peer.destroy()
    const outcome = await received
    assert.equal(outcome.error.code, 'ERR_CONNECTION')
    assert.equal(outcome.error.partial, undefined, 'nothing arrived, so there is nothing to resume')
    assert.deepEqual(await fs.promises.readdir(outputDir), [])
  }
  {
    const [peer, socket] = duplexPair()
    const keys = channelKeys()
    const tx = sealedPeer(peer, keys.sender)
    const received = settle(receiveFile(socket, outputDir, { ...keys.receiver, caps: RESUME }))
    tx.send(TYPE_MANIFEST, manifest)
    await until(() => accepts(tx.received).length === 1, 'the answer')
    tx.send(TYPE_CHUNK, body.subarray(0, 1000))
    await tick()
    socket.destroy(Object.assign(new Error('connection reset'), { code: 'ECONNRESET' }))
    const outcome = await received
    assert.equal(outcome.error.code, 'ERR_CONNECTION')
    assert.equal(outcome.error.cause.code, 'ECONNRESET')
    assert.equal(outcome.error.partial && outcome.error.partial.bytes, 1000, 'a reset keeps the partial')
    assertSameBytes(await fs.promises.readFile(partPath), body.subarray(0, 1000))
  }
})

test('a resumed file needs free space only for the bytes it has yet to receive', async (t) => {
  // 1 MiB held, 2 MiB offered, 1.5 MiB free: the remaining MiB fits, so
  // the receiver proposes the resume rather than refusing a file it could
  // finish.
  const { outputDir, body, sha256, partPath } = await fixture(t, 'resume-free-space', 2 * MiB)
  await fs.promises.writeFile(partPath, body.subarray(0, MiB))
  t.mock.method(fs.promises, 'statfs', async () => ({ bavail: 1.5 * MiB, bsize: 1 }))

  const { peer, tx, received } = receiverUnderTest(outputDir)
  tx.send(TYPE_MANIFEST, Buffer.from(JSON.stringify({ v: 2, name: 'payload.bin', size: body.length, sha256, blockSize: 65536 })))
  await until(() => tx.received.length > 0, 'the answer')
  assert.deepEqual(tx.received.map((f) => f.type), [TYPE_ACCEPT], 'not a DECLINE')
  assert.deepEqual(accepts(tx.received), [MiB])
  peer.destroy()
  await received
})

test('a second PREFIX is a protocol error, not a second answer', async (t) => {
  // PREFIX answers one proposal, once. A sender that sends it again while
  // the first is being acted on is out of turn, and acting on it twice
  // would adopt the partial twice and send the sender two final answers.
  const { outputDir, body, sha256, partPath } = await fixture(t, 'prefix-twice', 2 * MiB)
  await fs.promises.writeFile(partPath, body.subarray(0, MiB))
  const { tx, received } = receiverUnderTest(outputDir, { progressTimeout: 300 })

  tx.send(TYPE_MANIFEST, Buffer.from(JSON.stringify({ v: 2, name: 'payload.bin', size: body.length, sha256, blockSize: 65536 })))
  await until(() => accepts(tx.received).length === 1, 'the proposal')
  const prefix = prefixBody({ sha256: sha(body.subarray(0, MiB)) })
  tx.send(TYPE_PREFIX, prefix)
  tx.send(TYPE_PREFIX, prefix)
  const outcome = await received
  assert.equal(outcome.ok, false)
  assert.equal(outcome.error.code, 'ERR_PROTOCOL')
  assert.deepEqual(accepts(tx.received), [MiB], 'the proposal, and no answer after it')
})

test('a slow disk while a resumed partial is adopted is not mistaken for a stalled sender', async (t) => {
  // Between the sender's PREFIX and the final ACCEPT, the receiver is the
  // one working -- truncating the partial to the confirmed prefix -- and
  // no stall timer may run against the sender for that.
  const { sourcePath, outputDir, body, partPath } = await fixture(t, 'resume-slow-adopt', 2 * MiB)
  await fs.promises.writeFile(partPath, body.subarray(0, MiB))
  const proto = await fileHandlePrototype()
  const realTruncate = proto.truncate
  t.mock.method(proto, 'truncate', async function (/** @type {any[]} */ ...args) {
    await tick(30)
    return realTruncate.apply(this, args)
  })

  const received = await drop(sourcePath, outputDir).received
  assert.equal(received.ok, true, received.error && received.error.message)
  assert.equal(received.value.resumedFrom, MiB)
  assertSameBytes(await fs.promises.readFile(received.value.path), body)
})

test('checkpoints never overlap, so their offsets only move forward even when an fsync is slow', async (t) => {
  // An fsync that outlasts the checkpoint interval must not start a second
  // one beside it: two in flight can finish out of order, and a CHECKPOINT
  // that goes backwards is one the sender refuses as impossible.
  const { outputDir, body, sha256 } = await fixture(t, 'checkpoint-slow-fsync', 64 * 1024)
  const proto = await fileHandlePrototype()
  const realDatasync = proto.datasync
  const delays = [60, 5]
  let calls = 0
  let live = 0
  let most = 0
  t.mock.method(proto, 'datasync', async function () {
    const delay = delays[calls++ % delays.length]
    most = Math.max(most, ++live)
    try {
      await tick(delay)
      return await realDatasync.call(this)
    } finally {
      live--
    }
  })

  const { socket, keys, offer, send, received: frames } = sealedSender()
  const received = receiveFile(socket, outputDir, { ...keys, caps: RESUME, checkpointInterval: 10 })
  await offer({ v: 2, name: 'payload.bin', size: body.length, sha256, blockSize: 4096 })
  for (let offset = 0; offset < body.length; offset += 4096) {
    send(TYPE_CHUNK, body.subarray(offset, offset + 4096))
    await tick(12)
  }
  await received
  const offsets = frames.filter((f) => f.type === TYPE_CHECKPOINT).map((f) => JSON.parse(f.body.toString('utf8')).offset)
  assert.ok(offsets.length > 0, 'checkpoints were sent')
  assert.equal(most, 1, 'one fsync at a time')
  assert.ok(offsets.every((offset, i) => i === 0 || offset > offsets[i - 1]), `offsets move forward: ${JSON.stringify(offsets)}`)
})

test('an fsync that fails once does not end checkpointing for the rest of the transfer', async (t) => {
  // A failed fsync reports nothing, which is right, and the next interval
  // tries again: one bad moment on the disk must not leave a long
  // transfer with no durable offset to resume from.
  const { outputDir, body, sha256 } = await fixture(t, 'checkpoint-fsync-fails', 64 * 1024)
  const proto = await fileHandlePrototype()
  const realDatasync = proto.datasync
  let calls = 0
  t.mock.method(proto, 'datasync', async function () {
    if (calls++ === 0) throw Object.assign(new Error('i/o error'), { code: 'EIO' })
    return realDatasync.call(this)
  })

  const { socket, keys, offer, send, received: frames } = sealedSender()
  const received = receiveFile(socket, outputDir, { ...keys, caps: RESUME, checkpointInterval: 10 })
  await offer({ v: 2, name: 'payload.bin', size: body.length, sha256, blockSize: 4096 })
  for (let offset = 0; offset < body.length; offset += 4096) {
    send(TYPE_CHUNK, body.subarray(offset, offset + 4096))
    await tick(12)
  }
  await received
  assert.ok(calls > 1, 'fsync was tried again after it failed')
  assert.ok(frames.some((f) => f.type === TYPE_CHECKPOINT), 'and a checkpoint was reported after the failure')
})

test('an offer that ends while its partial is reopened or kept closes every descriptor it opened', { skip: openFds() === null ? 'no way to count open descriptors here' : false }, async (t) => {
  // A receiver can outlive many offers -- a long-running process, or one
  // embedding the engine -- so a descriptor leaked per failed resume is a
  // limit a peer can run it into. Each way an offer can end with the
  // reopened partial still unadopted, or with an interrupted transfer's
  // partial kept, must close what it opened.
  const { outputDir, body, sha256, partPath } = await fixture(t, 'resume-descriptors', 2 * MiB)
  const manifest = Buffer.from(JSON.stringify({ v: 2, name: 'payload.bin', size: body.length, sha256, blockSize: 65536 }))
  const prefix = prefixBody({ sha256: sha(body.subarray(0, MiB)) })

  for (const [what, act] of /** @type {Array<[string, (tx: any, peer: any) => void]>} */ ([
    ['a CANCEL while the prefix is checked', (tx) => tx.send(TYPE_CANCEL, cancelBody('wrong file'))],
    ['a hang-up while the prefix is checked', (tx, peer) => peer.destroy()],
    ['a CANCEL right behind the PREFIX', (tx) => { tx.send(TYPE_PREFIX, prefix); tx.send(TYPE_CANCEL, cancelBody('wrong file')) }]
  ])) {
    await fs.promises.writeFile(partPath, body.subarray(0, MiB))
    const before = openFds()
    const { peer, tx, received } = receiverUnderTest(outputDir)
    tx.send(TYPE_MANIFEST, manifest)
    await until(() => accepts(tx.received).length === 1, 'the proposal')
    act(tx, peer)
    assert.equal((await received).ok, false, what)
    await tick(50)
    assert.equal(openFds(), before, `${what}: every descriptor is closed`)
  }

  // And the partial an interrupted transfer keeps.
  await fs.promises.rm(partPath)
  const before = openFds()
  const { peer, tx, received } = receiverUnderTest(outputDir)
  tx.send(TYPE_MANIFEST, manifest)
  await until(() => accepts(tx.received).length === 1, 'the answer')
  for (let offset = 0; offset < 4 * 65536; offset += 65536) tx.send(TYPE_CHUNK, body.subarray(offset, offset + 65536))
  peer.destroy()
  const outcome = await received
  assert.equal(outcome.error.partial && outcome.error.partial.bytes, 4 * 65536)
  await tick(50)
  assert.equal(openFds(), before, 'a kept partial is closed, not left open')
  assertSameBytes(await fs.promises.readFile(partPath), body.subarray(0, 4 * 65536))
})
