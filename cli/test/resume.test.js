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
  TYPE_MANIFEST,
  TYPE_CHUNK,
  TYPE_ACCEPT,
  TYPE_CHECKPOINT
} = require('@quay/engine')
const { duplexPair } = require('../test-helpers/duplex-pair')
const { channelKeys, sealedPeer, sealedSender } = require('../test-helpers/sealed')

const RESUME = ['resume']
const MiB = 1024 * 1024

async function fixture (t, label, size = 4 * MiB) {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), `quay-${label}-`))
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
  assert.deepEqual(onDisk, body.subarray(0, onDisk.length), 'what was kept is exactly a prefix of the file')

  // A second drop: new keys, as a new code would give. Found by name.
  const second = drop(sourcePath, outputDir)
  const [sent, received] = [await second.sent, await second.received]
  assert.equal(received.ok, true, received.error && received.error.message)
  assert.equal(sent.value.resumedFrom, onDisk.length)
  assert.equal(received.value.resumedFrom, onDisk.length)
  assert.equal(received.value.sha256, sha256)
  assert.equal(received.value.size, body.length)
  assert.deepEqual(await fs.promises.readFile(received.value.path), body)
  assert.deepEqual(await fs.promises.readdir(outputDir), ['payload.bin'], 'the partial became the file')
})

test('a resumed sender reads the file from resumeFrom and nothing before it', async (t) => {
  const { sourcePath, body, sha256 } = await fixture(t, 'resume-sender', 256 * 1024)
  const [txSocket, peer] = duplexPair()
  const keys = channelKeys()
  const from = 100000
  const rx = sealedPeer(peer, keys.receiver, {
    onMessage: (type) => { if (type === TYPE_MANIFEST) rx.send(TYPE_ACCEPT, acceptBody({ resumeFrom: from })) }
  })
  /** @type {number[]} */
  const progress = []

  const sent = sendFile(txSocket, sourcePath, { ...keys.sender, caps: RESUME, onProgress: ({ bytes }) => progress.push(bytes) })
  await tick(50)
  const chunks = rx.received.filter((f) => f.type === TYPE_CHUNK).map((f) => f.body)
  assert.deepEqual(Buffer.concat(chunks), body.subarray(from))
  rx.send(0x07, resultBody({ ok: true, sha256 }))

  const result = await sent
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

test('a foreign partial is caught by the final digest, discarded, and the retry starts clean', async (t) => {
  const { sourcePath, outputDir, body, partPath } = await fixture(t, 'resume-foreign', 256 * 1024)
  // Bytes that are not a prefix of this file, under the name it will look
  // for: a stale partial of a different file, or a planted one.
  await fs.promises.writeFile(partPath, crypto.randomBytes(1000))

  const first = drop(sourcePath, outputDir)
  const [sent, received] = [await first.sent, await first.received]
  // Never published wrong. A whole-file digest cannot vouch for a prefix,
  // so this is where a foreign one is caught -- after the transfer, which
  // is the cost section 7.2 now states.
  assert.equal(received.error.code, 'ERR_HASH_MISMATCH')
  assert.equal(received.error.resumedFrom, 1000)
  assert.match(received.error.message, /resumed from byte 1000.*discarded/)
  assert.equal(sent.error.code, 'ERR_RECEIVER_FAILED')
  assert.deepEqual(await fs.promises.readdir(outputDir), [], 'the foreign partial is gone')

  const retry = drop(sourcePath, outputDir)
  const again = await retry.received
  assert.equal(again.value.resumedFrom, 0)
  assert.deepEqual(await fs.promises.readFile(again.value.path), body)
})

test('a planted .part symlink is never followed on resume', { skip: process.platform === 'win32' ? 'symlinks need privileges on Windows' : false }, async (t) => {
  const { dir, sourcePath, outputDir, body, partPath } = await fixture(t, 'resume-symlink', 64 * 1024)
  const target = path.join(dir, 'authorized_keys')
  await fs.promises.writeFile(target, 'ssh-ed25519 AAAA the real key\n')
  await fs.promises.symlink(target, partPath)

  const d = drop(sourcePath, outputDir)
  const received = await d.received
  assert.equal(received.value.resumedFrom, 0, 'a symlink is not a partial to resume')
  assert.deepEqual(await fs.promises.readFile(received.value.path), body)
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
  assert.deepEqual(await fs.promises.readFile(received.value.path), body)
  assert.equal(await fs.promises.readFile(target, 'utf8'), 'alias ls=ls\n', 'the linked file is untouched')
})

test('a partial longer than the offer is not a prefix of it, and is left alone', async (t) => {
  const { sourcePath, outputDir, body, partPath } = await fixture(t, 'resume-longer', 1024)
  const other = crypto.randomBytes(4096)
  await fs.promises.writeFile(partPath, other)

  const d = drop(sourcePath, outputDir)
  const received = await d.received
  assert.equal(received.value.resumedFrom, 0)
  assert.deepEqual(await fs.promises.readFile(received.value.path), body)
  assert.deepEqual(await fs.promises.readFile(partPath), other, 'not ours, so not deleted either')
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
    assert.deepEqual(await fs.promises.readdir(outputDir), [], 'a cancelled receive keeps nothing')
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
  assert.deepEqual(await fs.promises.readFile(path.join(outputDir, 'payload.bin.part')), body.subarray(0, 3000))
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
    assert.deepEqual(await fs.promises.readFile(partPath), prefix, `${how} before ACCEPT must leave the earlier partial intact`)
  }
})
