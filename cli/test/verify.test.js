'use strict'

// Step 6 of the v1 data path -- "receiver verifies the full-file hash;
// atomic rename into Downloads" -- was written down in docs/ARCHITECTURE.md
// during the loopback milestone and, until the failure-reporting work, was not implemented anywhere that
// shipped.
//
// receiveFile computed a SHA-256 and returned it. Nothing compared it to
// the manifest's. The only comparison in the repo lived in
// engine/scratch-trials.js, so the measurement harness verified integrity
// and neither CLI did: a corrupted file was written into the output
// directory, under its final name, and reported as a success with a
// hash line that looked authoritative.
//
// The other half of this file is the receiver's liveness. Before that work the
// only socket listeners were 'data' and 'error', so a sender that vanished
// mid-transfer -- the routine outcome of a half-failed punch, which the Hyperswarm work
// spent a week learning to recognize -- left the receive promise pending
// forever. No error, no timeout, no exit.

const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('node:path')
const os = require('node:os')
const fs = require('node:fs')
const crypto = require('node:crypto')

const { sendFile, receiveFile, TYPE_CHUNK } = require('@ad-hal/engine')
const { duplexPair } = require('../test-helpers/duplex-pair')
const { channelKeys, sealedSender } = require('../test-helpers/sealed')

async function tmpDir (t, label) {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), `adhal-${label}-`))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  return dir
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
async function rejectsWith (promise, code, extra = null) {
  const err = await promise.then(
    (value) => { throw new Error(`expected a rejection, resolved with ${JSON.stringify(value)}`) },
    (e) => e
  )
  assert.equal(err.code, code, `expected ${code}, got ${err.code}: ${err.message}`)
  if (extra) extra(err)
  return err
}

function waitFor (predicate, what, timeoutMs = 2000) {
  return new Promise((resolve, reject) => {
    const start = Date.now()
    const timer = setInterval(() => {
      if (predicate()) { clearInterval(timer); resolve(undefined) } else if (Date.now() - start > timeoutMs) {
        clearInterval(timer)
        reject(new Error(`timed out waiting for ${what}`))
      }
    }, 5)
  })
}

test('a file whose bytes do not match the manifest is refused and left nowhere', async (t) => {
  const outputDir = await tmpDir(t, 'verify-mismatch')
  const body = crypto.randomBytes(2048)

  // A manifest that declares a digest the bytes do not have: corruption in
  // flight, a lying peer, and a framing bug all present exactly like this.
  const lying = manifestFor(body, { sha256: 'b'.repeat(64) })

  const { socket, keys, offer } = sealedSender()
  const received = receiveFile(socket, outputDir, { ...keys })
  offer(lying, body)

  await rejectsWith(received, 'ERR_HASH_MISMATCH', (err) => {
    assert.equal(err.expected, 'b'.repeat(64))
    assert.equal(err.actual, crypto.createHash('sha256').update(body).digest('hex'))
  })

  // Both halves matter. The final name must never have existed -- that is
  // what the atomic rename buys -- and the partial must be gone, because
  // bytes known to be wrong must never be left looking resumable -- and
  // resume does keep the partial of an interrupted transfer.
  assert.deepEqual(await fs.promises.readdir(outputDir), [])
})

test('a partial is visible only under .part, never under the final name, until it verifies', async (t) => {
  const outputDir = await tmpDir(t, 'verify-partial')
  const body = crypto.randomBytes(4096)
  const manifest = manifestFor(body)
  const finalPath = path.join(outputDir, 'payload.bin')
  const partPath = `${finalPath}.part`

  const { socket, keys, send, offer } = sealedSender()
  const received = receiveFile(socket, outputDir, { ...keys })

  await offer(manifest, body.subarray(0, 1024))

  // Mid-stream: the transfer is under way and incomplete.
  await waitFor(() => fs.existsSync(partPath), 'the .part file to appear')
  assert.equal(fs.existsSync(finalPath), false, 'an unverified file must not be visible under its real name')

  // `.part` is predictable rather than randomized on purpose: resume (W11) has
  // to find this exact file again to resume it.
  assert.equal(path.basename(partPath), 'payload.bin.part')

  send(TYPE_CHUNK, body.subarray(1024))
  const result = await received

  assert.equal(result.path, finalPath)
  assert.equal(fs.existsSync(partPath), false, 'the .part must be renamed away, not left beside the file')
  assert.deepEqual(await fs.promises.readFile(finalPath), body)
  assert.equal(result.sha256, manifest.sha256)
})

test('an empty file still verifies and lands under its real name', async (t) => {
  const outputDir = await tmpDir(t, 'verify-empty')
  const body = Buffer.alloc(0)

  const { socket, keys, offer } = sealedSender()
  const received = receiveFile(socket, outputDir, { ...keys })
  offer(manifestFor(body, { name: 'empty.bin' }))

  const result = await received
  assert.equal(result.size, 0)
  assert.deepEqual(await fs.promises.readdir(outputDir), ['empty.bin'])
})

test('a sender that sends more than it declared is refused, not silently truncated', async (t) => {
  const outputDir = await tmpDir(t, 'verify-overread')
  const body = crypto.randomBytes(1024)

  // Truncate-and-accept would be the tempting fix and the wrong one: a
  // correct sender cannot over-read its own manifest, so trimming hides a
  // real bug -- and means accepting an unbounded number of bytes from a
  // peer that proved it knows the code but is not thereby well-behaved.
  const { socket, keys, offer } = sealedSender()
  const received = receiveFile(socket, outputDir, { ...keys })
  offer(manifestFor(body), Buffer.concat([body, crypto.randomBytes(1)]))

  await rejectsWith(received, 'ERR_SIZE_MISMATCH', (err) => {
    assert.equal(err.size, 1024)
    assert.equal(err.bytes, 1025)
  })
  assert.deepEqual(await fs.promises.readdir(outputDir), [])
})

test('a sender that vanishes mid-transfer fails the receive instead of hanging it forever', async (t) => {
  const outputDir = await tmpDir(t, 'verify-earlyclose')
  const body = crypto.randomBytes(8192)

  const { peer, socket, keys, offer } = sealedSender()
  const received = receiveFile(socket, outputDir, { ...keys })
  offer(manifestFor(body), body.subarray(0, 100))

  // The vanish. No FIN negotiation, no error -- the far side simply stops
  // existing, which is what a dead hole punch looks like.
  await waitFor(() => fs.existsSync(path.join(outputDir, 'payload.bin.part')), 'the transfer to be under way')
  peer.destroy()

  // The regression this pins: before that work, this promise never settled at
  // all. A race against a timer is the only way to assert "it settles",
  // and it is not flaky in the direction that matters -- a correct
  // implementation settles in microseconds, and only the old hanging one
  // needs the full budget.
  const outcome = await Promise.race([
    received.then(() => 'resolved', (err) => err),
    new Promise((resolve) => setTimeout(() => resolve('hung'), 3000))
  ])
  assert.notEqual(outcome, 'hung', 'the receive must settle when the sender disappears')
  assert.notEqual(outcome, 'resolved', 'and it must not report success for a truncated file')
  assert.equal(outcome.code, 'ERR_CONNECTION')
  assert.equal(outcome.bytes, 100, 'the error should say how far it got')

  assert.deepEqual(await fs.promises.readdir(outputDir), [], 'the partial is discarded')
})

test('the sender leaves no listeners behind on the socket it was lent', async (t) => {
  const dir = await tmpDir(t, 'verify-listeners')
  const sourcePath = path.join(dir, 'source.bin')
  const outputDir = path.join(dir, 'out')
  await fs.promises.mkdir(outputDir)
  await fs.promises.writeFile(sourcePath, crypto.randomBytes(256 * 1024))

  const [txSocket, rxSocket] = duplexPair()
  const keys = channelKeys()
  const before = {
    error: txSocket.listenerCount('error'),
    drain: txSocket.listenerCount('drain'),
    data: txSocket.listenerCount('data')
  }

  const [sent] = await Promise.all([
    sendFile(txSocket, sourcePath, { ...keys.sender }),
    receiveFile(rxSocket, outputDir, { ...keys.receiver })
  ])
  assert.equal(sent.size, 256 * 1024)

  // sendFile does not own this socket -- the caller does, and goes on to
  // end it and wait for 'close' (see cli/src/swarm-send.js). Every
  // listener it added during the transfer, including the 'drain' handler
  // installed per backpressure pause and the inbound-CANCEL reader, has
  // to come back off. These leaked per call before the failure-reporting work.
  assert.equal(txSocket.listenerCount('error'), before.error)
  assert.equal(txSocket.listenerCount('drain'), before.drain)
  assert.equal(txSocket.listenerCount('data'), before.data)
})

test('a sender that disconnects before sending anything says so plainly', async (t) => {
  const outputDir = await tmpDir(t, 'verify-nomanifest')
  const { peer, socket, keys, send } = sealedSender()
  const received = receiveFile(socket, outputDir, { ...keys })
  peer.end()

  await rejectsWith(received, 'ERR_CONNECTION', (err) => {
    assert.match(err.message, /before sending a manifest/)
  })
})

// --- one descriptor for the hash and the send (Q-16) ----------------------

// Open descriptors in this process, where the platform exposes them.
function openFds () {
  for (const dir of ['/proc/self/fd', '/dev/fd']) {
    try { return fs.readdirSync(dir).length } catch {}
  }
  return null
}

test('a file swapped at its path after hashing is not what gets sent', async (t) => {
  // The sender hashes, offers, and waits for ACCEPT; the receiver's policy
  // runs in between. That is the window in which a local attacker (or a
  // build tool) can rename a different file over the path. The sender used
  // to reopen the path to send, so it hashed one file and sent another.
  // It now sends through the descriptor it hashed, so the swap is invisible
  // to the transfer: the receiver gets exactly the bytes the manifest
  // described.
  const dir = await tmpDir(t, 'q16-swap')
  const sourcePath = path.join(dir, 'report.bin')
  const original = crypto.randomBytes(200 * 1024)
  await fs.promises.writeFile(sourcePath, original)
  const decoy = path.join(dir, 'decoy.bin')
  await fs.promises.writeFile(decoy, crypto.randomBytes(original.length))
  const outputDir = path.join(dir, 'out')
  await fs.promises.mkdir(outputDir)

  const [txSocket, rxSocket] = duplexPair()
  const keys = channelKeys()
  let swapped = false
  const [sent, received] = await Promise.all([
    sendFile(txSocket, sourcePath, { ...keys.sender }),
    receiveFile(rxSocket, outputDir, {
      ...keys.receiver,
      onOffer: async () => {
        try {
          await fs.promises.rename(decoy, sourcePath)
          swapped = true
        } catch (err) {
          // Windows refuses to rename over a file the sender holds open,
          // so the swap cannot happen there. The bytes are still checked.
          if (process.platform !== 'win32' || /** @type {any} */ (err).code !== 'EPERM') throw err
        }
        return true
      }
    })
  ])
  assert.equal(swapped, process.platform !== 'win32', 'the swap happens where the OS allows it')

  const expected = crypto.createHash('sha256').update(original).digest('hex')
  assert.equal(sent.sha256, expected)
  assert.equal(received.sha256, expected)
  assert.deepEqual(await fs.promises.readFile(path.join(outputDir, 'report.bin')), original, 'the bytes that were hashed, not the decoy')
})

test('the sender releases its descriptor however the transfer ends', { skip: openFds() === null && 'no fd listing on this platform' }, async (t) => {
  const dir = await tmpDir(t, 'q16-fd')
  const sourcePath = path.join(dir, 'a.bin')
  await fs.promises.writeFile(sourcePath, crypto.randomBytes(64 * 1024))
  const outputDir = path.join(dir, 'out')
  await fs.promises.mkdir(outputDir)
  const before = openFds()

  // Completed.
  {
    const [txSocket, rxSocket] = duplexPair()
    const keys = channelKeys()
    await Promise.all([sendFile(txSocket, sourcePath, { ...keys.sender }), receiveFile(rxSocket, outputDir, { ...keys.receiver, replace: true })])
  }
  // Declined, so the send fails after the file was opened and hashed.
  {
    const [txSocket, rxSocket] = duplexPair()
    const keys = channelKeys()
    const [sent] = await Promise.allSettled([
      sendFile(txSocket, sourcePath, { ...keys.sender }),
      receiveFile(rxSocket, outputDir, { ...keys.receiver, onOffer: () => false })
    ])
    assert.equal(sent.status, 'rejected')
  }
  // The duplex pair's own handles are not file descriptors, so any growth
  // here is the source file left open.
  assert.equal(openFds(), before, 'no descriptor was left open')
})

test('a path that is not a regular file is refused before anything is offered', async (t) => {
  const dir = await tmpDir(t, 'q16-dir')
  const [txSocket] = duplexPair()
  const keys = channelKeys()
  await assert.rejects(sendFile(txSocket, dir, { ...keys.sender }), /not a regular file/)
})
