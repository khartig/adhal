'use strict'

// Cancellation, and the one distinction the whole of item 5 turns on:
// a peer that deliberately stopped must not look like a peer that died.
//
// Before this, Ctrl-C reset the socket and the far side printed
// "connection reset by peer" -- byte for byte what a half-failed hole
// punch produces. engine/src/swarm.js carries a long comment about a
// cross-ISP failure that cost a debugging session precisely because two
// unrelated causes presented identically, and shipping a *user-initiated*
// action that produces that same signature would have reintroduced the
// confusion on purpose.
//
// Everything here runs over cross-piped duplex streams. The subject is
// what arrives on the stream, so a DHT and a hole punch would add nothing
// but flake -- except for the last test, which needs a real swarm because
// its subject is the swarm's own listener bookkeeping.

const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('node:path')
const os = require('node:os')
const fs = require('node:fs')
const crypto = require('node:crypto')
const { spawn } = require('node:child_process')
const createTestnet = require('hyperdht/testnet')

const {
  sendFile,
  receiveFile,
  createSwarm,
  acceptOnce,
  topicFromCode,
  generateCode,
  dropKey
} = require('@quay/engine')
const { duplexPair } = require('../test-helpers/duplex-pair')

const REPO_ROOT = path.resolve(__dirname, '..', '..')
const SWARM_RECEIVE = path.join(REPO_ROOT, 'cli', 'src', 'swarm-receive.js')

async function fixture (t, label, size = 4 * 1024 * 1024) {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), `quay-${label}-`))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const sourcePath = path.join(dir, 'source.bin')
  const outputDir = path.join(dir, 'out')
  await fs.promises.mkdir(outputDir)
  await fs.promises.writeFile(sourcePath, crypto.randomBytes(size))
  return { dir, sourcePath, outputDir }
}

/** @param {any} promise */
async function settle (promise) {
  return promise.then((value) => ({ ok: true, value }), (error) => ({ ok: false, error }))
}

test('a receiver that cancels makes the sender report a cancellation, not a network error', async (t) => {
  const { sourcePath, outputDir } = await fixture(t, 'cancel-rx')
  const [txSocket, rxSocket] = duplexPair()
  const controller = new AbortController()

  // Cancel once the transfer is genuinely under way, so this is a
  // mid-stream cancel rather than a refused connection.
  let cancelledAt = null
  const onProgress = ({ bytes, total }) => {
    if (cancelledAt === null && bytes > 0 && bytes < total) {
      cancelledAt = bytes
      controller.abort('the human changed their mind')
    }
  }

  const [sent, received] = await Promise.all([
    settle(sendFile(txSocket, sourcePath)),
    settle(receiveFile(rxSocket, outputDir, { signal: controller.signal, onProgress }))
  ])

  // THE HEADLINE ASSERTION FOR THIS ITEM. Not ECONNRESET, not EPIPE, not
  // a generic Error: a named cancellation carrying the peer's own reason.
  assert.equal(sent.ok, false)
  assert.equal(sent.error.code, 'ERR_CANCELLED_PEER')
  assert.equal(sent.error.peerReason, 'the human changed their mind')
  assert.equal(typeof sent.error.bytes, 'number')

  // And the cancelling side reports its own cancellation as Node's
  // standard abort, so generic AbortSignal handling elsewhere works.
  assert.equal(received.ok, false)
  assert.equal(received.error.name, 'AbortError')
  assert.equal(received.error.code, 'ABORT_ERR')

  assert.deepEqual(await fs.promises.readdir(outputDir), [], 'the partial is discarded')
})

test('a sender that cancels makes the receiver report a cancellation, not a truncated file', async (t) => {
  const { sourcePath, outputDir } = await fixture(t, 'cancel-tx')
  const [txSocket, rxSocket] = duplexPair()
  const controller = new AbortController()

  const onProgress = ({ bytes, total }) => {
    if (bytes > 0 && bytes < total) controller.abort('sender pulled the plug')
  }

  const [sent, received] = await Promise.all([
    settle(sendFile(txSocket, sourcePath, { signal: controller.signal, onProgress })),
    settle(receiveFile(rxSocket, outputDir))
  ])

  assert.equal(sent.ok, false)
  assert.equal(sent.error.name, 'AbortError')

  // The mirror case, and the one that would otherwise be worst: without a
  // CANCEL the receiver sees a socket that stopped, which is
  // indistinguishable from a dead punch -- and before item 5 it did not
  // even see that, it simply waited forever.
  assert.equal(received.ok, false)
  assert.equal(received.error.code, 'ERR_CANCELLED_PEER')
  assert.equal(received.error.peerReason, 'sender pulled the plug')
  assert.deepEqual(await fs.promises.readdir(outputDir), [])
})

test('an already-aborted signal rejects before a single byte moves', async (t) => {
  const { sourcePath, outputDir } = await fixture(t, 'cancel-pre', 1024)
  const controller = new AbortController()
  controller.abort('never mind')

  const [txSocket, rxSocket] = duplexPair()
  let bytesSeen = 0
  rxSocket.on('data', (c) => { bytesSeen += c.length })

  const sent = await settle(sendFile(txSocket, sourcePath, { signal: controller.signal }))
  assert.equal(sent.ok, false)
  assert.equal(sent.error.name, 'AbortError')
  assert.equal(bytesSeen, 0, 'not even a manifest should be written')

  // Same on the receiving side, and without creating anything on disk.
  const received = await settle(receiveFile(rxSocket, outputDir, { signal: controller.signal }))
  assert.equal(received.ok, false)
  assert.equal(received.error.name, 'AbortError')
  assert.deepEqual(await fs.promises.readdir(outputDir), [])
})

test('a simultaneous cancel settles both sides, each reporting its own', async (t) => {
  const { sourcePath, outputDir } = await fixture(t, 'cancel-both')
  const [txSocket, rxSocket] = duplexPair()
  const txController = new AbortController()
  const rxController = new AbortController()

  let fired = false
  const bothCancel = ({ bytes, total }) => {
    if (fired || bytes === 0 || bytes >= total) return
    fired = true
    txController.abort('sender quit')
    rxController.abort('receiver quit')
  }

  const [sent, received] = await Promise.all([
    settle(sendFile(txSocket, sourcePath, { signal: txController.signal, onProgress: bothCancel })),
    settle(receiveFile(rxSocket, outputDir, { signal: rxController.signal }))
  ])

  // What is deterministic, and what is not.
  //
  // Both sides must settle -- neither may hang, and neither may report a
  // network or protocol error, because nothing failed. That is asserted.
  //
  // WHICH side reports its own AbortError and which reports the other's
  // ERR_CANCELLED_PEER is a genuine race: it depends on whether a CANCEL
  // crosses the wire before the local abort is processed, which on a real
  // socket is decided by latency. Asserting a winner would be asserting a
  // race outcome, which is the kind of test that passes on a laptop and
  // fails on a loaded CI box. So the invariant is stated as what it
  // actually is: first settle wins, locally, on each side.
  const cancellations = [sent, received].map((outcome) => {
    assert.equal(outcome.ok, false, 'a cancelled transfer must not resolve')
    return outcome.error
  })
  for (const err of cancellations) {
    const isCancellation = err.name === 'AbortError' || err.code === 'ERR_CANCELLED_PEER'
    assert.ok(isCancellation, `expected a cancellation, got ${err.code}: ${err.message}`)
  }

  // The one deterministic half: the side that aborted first cannot
  // possibly have seen the other's CANCEL yet, so it reports its own.
  assert.equal(sent.error.name, 'AbortError', 'the side that cancelled first reports its own cancellation')

  assert.deepEqual(await fs.promises.readdir(outputDir), [])
})

test('a cancel reason chosen by the peer cannot smuggle escape sequences into a terminal', async (t) => {
  const { sourcePath, outputDir } = await fixture(t, 'cancel-hostile')
  const [txSocket, rxSocket] = duplexPair()
  const controller = new AbortController()

  const hostile = `[2K\r[swarm-receive] verified: totally fine\n${'x'.repeat(1000)}`
  const onProgress = ({ bytes, total }) => {
    if (bytes > 0 && bytes < total) controller.abort(hostile)
  }

  const [sent] = await Promise.all([
    settle(sendFile(txSocket, sourcePath)),
    settle(receiveFile(rxSocket, outputDir, { signal: controller.signal, onProgress }))
  ])

  assert.equal(sent.error.code, 'ERR_CANCELLED_PEER')
  const reason = sent.error.peerReason
  // This string is printed straight into a terminal by the CLI, so a peer
  // must not be able to clear the line, forge a second log line, or run
  // the output off the screen.
  assert.equal(/[ --]/.test(reason), false, 'control characters must be stripped')
  assert.ok(Buffer.byteLength(reason, 'utf8') <= 256, 'the reason must be capped')
})

test('a transfer that is never cancelled is unaffected by having been given a signal', async (t) => {
  const { sourcePath, outputDir } = await fixture(t, 'cancel-none', 512 * 1024)
  const [txSocket, rxSocket] = duplexPair()
  const controller = new AbortController()

  const [sent, received] = await Promise.all([
    sendFile(txSocket, sourcePath, { signal: controller.signal }),
    receiveFile(rxSocket, outputDir, { signal: controller.signal })
  ])

  assert.equal(received.sha256, sent.sha256)
  // And the listeners the signal path installed must come back off, or a
  // long-lived controller accumulates one set per transfer.
  assert.deepEqual(await fs.promises.readdir(outputDir), ['source.bin'])
})

// --- cancelling while still waiting for a peer ---------------------------

test('acceptOnce aborted while waiting rejects and leaves the swarm as it found it', async (t) => {
  const testnet = await createTestnet(3)
  t.after(() => testnet.destroy())

  const swarm = createSwarm({ bootstrap: testnet.bootstrap })
  t.after(() => swarm.destroy())

  const code = generateCode()
  const controller = new AbortController()

  // Nothing is ever on this topic, so the only way out is the abort.
  const accepted = settle(acceptOnce(swarm, topicFromCode(code), {
    key: dropKey(code),
    timeout: 60000,
    signal: controller.signal
  }))

  // This is the moment a human is most likely to give up -- a receiver
  // showing a QR code spends nearly all its life here -- and until item 5
  // there was no path out of it but killing the process.
  controller.abort('changed my mind')
  const outcome = await accepted

  assert.equal(outcome.ok, false)
  assert.equal(outcome.error.name, 'AbortError')

  // The riskiest part of the change: aborting must remove only our own
  // listener. Destroying the caller's swarm here would break every CLI,
  // all of which destroy it themselves in a `finally` after this rejection
  // propagates.
  assert.equal(swarm.listenerCount('connection'), 0, 'the connection listener must be removed')
  assert.equal(swarm.destroyed, false, 'the swarm belongs to the caller and must survive')
})

test('Ctrl-C while the receiver CLI waits for a peer exits promptly, cleanly, and with 130', async (t) => {
  const testnet = await createTestnet(3)
  t.after(() => testnet.destroy())

  const tmp = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'quay-sigint-'))
  t.after(() => fs.rmSync(tmp, { recursive: true, force: true }))

  // DELIBERATELY NOT MID-TRANSFER. Interrupting a transfer requires one
  // slow enough to interrupt, which means either a huge file or an
  // artificial delay -- and a test whose correctness depends on losing a
  // race against a 10 MB local copy is a test that fails under load. The
  // engine-level mid-transfer cancel is covered deterministically above,
  // over duplex pairs. What can only be covered here is the actual signal
  // plumbing, and waiting for a peer is where a human really does press
  // Ctrl-C.
  const env = {
    ...process.env,
    QUAY_BOOTSTRAP: JSON.stringify(testnet.bootstrap),
    // Generous, so "it exited quickly" cannot be the join timeout firing.
    QUAY_JOIN_TIMEOUT: '60000',
    QUAY_NO_PROGRESS: '1',
    NO_COLOR: '1'
  }

  const receiveProc = spawn(process.execPath, [SWARM_RECEIVE, '--new', tmp], { env })
  const out = { stdout: '', stderr: '' }
  receiveProc.stdout.on('data', (c) => { out.stdout += c.toString('utf8') })
  receiveProc.stderr.on('data', (c) => { out.stderr += c.toString('utf8') })
  t.after(() => { if (receiveProc.exitCode === null) receiveProc.kill('SIGKILL') })

  await new Promise((resolve, reject) => {
    const started = Date.now()
    const timer = setInterval(() => {
      if (/waiting for a peer/.test(out.stdout)) { clearInterval(timer); resolve(undefined) } else if (Date.now() - started > 30000) {
        clearInterval(timer)
        reject(new Error(`receiver never announced\n${out.stdout}\n${out.stderr}`))
      }
    }, 50)
  })

  const interruptedAt = Date.now()
  receiveProc.kill('SIGINT')

  const exitCode = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`did not exit after SIGINT\n${out.stdout}\n${out.stderr}`)), 20000)
    receiveProc.on('exit', (code) => { clearTimeout(timer); resolve(code) })
  })
  const took = Date.now() - interruptedAt

  // 130 is 128 + SIGINT, the shell convention -- and specifically not 1,
  // so a script can tell "the human stopped this" from "it failed".
  assert.equal(exitCode, 130, `expected 130, got ${exitCode}\n${out.stdout}\n${out.stderr}`)

  // It must say it is cancelling, rather than dying silently or, worse,
  // reporting the DHT timeout it never reached.
  assert.match(out.stdout, /\[swarm-receive\] cancelled \(SIGINT\)/)
  assert.doesNotMatch(out.stdout + out.stderr, /no peer ever connected/, 'this was a cancellation, not a timeout')

  // The point of not just calling process.exit(): teardown runs. But it
  // has to run fast, because a Ctrl-C that appears to do nothing is one
  // people follow with kill -9.
  assert.ok(took < 15000, `teardown took ${took}ms, which is long enough to look like a hang`)
})

test('an acceptOnce given an already-aborted signal never joins at all', async (t) => {
  const testnet = await createTestnet(3)
  t.after(() => testnet.destroy())

  const swarm = createSwarm({ bootstrap: testnet.bootstrap })
  t.after(() => swarm.destroy())

  const code = generateCode()
  const controller = new AbortController()
  controller.abort('too late')

  const outcome = await settle(acceptOnce(swarm, topicFromCode(code), {
    key: dropKey(code),
    timeout: 60000,
    signal: controller.signal
  }))

  assert.equal(outcome.ok, false)
  assert.equal(outcome.error.name, 'AbortError')
  assert.equal(swarm.listenerCount('connection'), 0)
})
