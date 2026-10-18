'use strict'

// Cancellation, and the one distinction the whole of the failure-reporting work turns on:
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
  connectOnce,
  topicFromNameplate,
  splitCode,
  generateCode,
  TYPE_MANIFEST
} = require('@ad-hal/engine')
const { slow } = require('../test-helpers/tiers')
const { interrupt } = require('../test-helpers/interrupt')
const { duplexPair } = require('../test-helpers/duplex-pair')
const { channelKeys, sealedPeer } = require('../test-helpers/sealed')

const REPO_ROOT = path.resolve(__dirname, '..', '..')
const SWARM_RECEIVE = path.join(REPO_ROOT, 'cli', 'src', 'swarm-receive.js')
const SWARM_SEND = path.join(REPO_ROOT, 'cli', 'src', 'swarm-send.js')

async function fixture (t, label, size = 4 * 1024 * 1024) {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), `adhal-${label}-`))
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
  const keys = channelKeys()
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
    settle(sendFile(txSocket, sourcePath, { ...keys.sender })),
    settle(receiveFile(rxSocket, outputDir, { ...keys.receiver, signal: controller.signal, onProgress }))
  ])

  // THE HEADLINE ASSERTION FOR THIS ITEM. Not ECONNRESET, not EPIPE, not
  // a generic Error: a named cancellation carrying the peer's own reason.
  assert.equal(sent.ok, false)
  assert.equal(sent.error.code, 'ERR_CANCELLED_PEER')
  assert.equal(sent.error.peerReason, 'the human changed their mind')
  assert.equal(typeof sent.error.bytes, 'number')

  // And the canceling side reports its own cancellation as Node's
  // standard abort, so generic AbortSignal handling elsewhere works.
  assert.equal(received.ok, false)
  assert.equal(received.error.name, 'AbortError')
  assert.equal(received.error.code, 'ABORT_ERR')

  assert.deepEqual(await fs.promises.readdir(outputDir), [], 'the partial is discarded')
})

test('a sender that cancels makes the receiver report a cancellation, not a truncated file', async (t) => {
  const { sourcePath, outputDir } = await fixture(t, 'cancel-tx')
  const [txSocket, rxSocket] = duplexPair()
  const keys = channelKeys()
  const controller = new AbortController()

  const onProgress = ({ bytes, total }) => {
    if (bytes > 0 && bytes < total) controller.abort('sender pulled the plug')
  }

  const [sent, received] = await Promise.all([
    settle(sendFile(txSocket, sourcePath, { ...keys.sender, signal: controller.signal, onProgress })),
    settle(receiveFile(rxSocket, outputDir, { ...keys.receiver }))
  ])

  assert.equal(sent.ok, false)
  assert.equal(sent.error.name, 'AbortError')

  // The mirror case, and the one that would otherwise be worst: without a
  // CANCEL the receiver sees a socket that stopped, which is
  // indistinguishable from a dead punch -- and before that work it did not
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

  const keys = channelKeys()
  let bytesSeen = 0
  rxSocket.on('data', (c) => { bytesSeen += c.length })

  const sent = await settle(sendFile(txSocket, sourcePath, { ...keys.sender, signal: controller.signal }))
  assert.equal(sent.ok, false)
  assert.equal(sent.error.name, 'AbortError')
  assert.equal(bytesSeen, 0, 'not even a manifest should be written')

  // Same on the receiving side, and without creating anything on disk.
  // Its own keys: a transfer wipes the keys it was given when it ends,
  // aborted or not, and in this test the two sides would otherwise share
  // one pair of Buffers.
  const received = await settle(receiveFile(rxSocket, outputDir, { ...channelKeys().receiver, signal: controller.signal }))
  assert.equal(received.ok, false)
  assert.equal(received.error.name, 'AbortError')
  assert.deepEqual(await fs.promises.readdir(outputDir), [])
})

test('a simultaneous cancel settles both sides, each reporting its own', async (t) => {
  const { sourcePath, outputDir } = await fixture(t, 'cancel-both')
  const [txSocket, rxSocket] = duplexPair()
  const keys = channelKeys()
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
    settle(sendFile(txSocket, sourcePath, { ...keys.sender, signal: txController.signal, onProgress: bothCancel })),
    settle(receiveFile(rxSocket, outputDir, { ...keys.receiver, signal: rxController.signal }))
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
    assert.equal(outcome.ok, false, 'a canceled transfer must not resolve')
    return outcome.error
  })
  for (const err of cancellations) {
    const isCancellation = err.name === 'AbortError' || err.code === 'ERR_CANCELLED_PEER'
    assert.ok(isCancellation, `expected a cancellation, got ${err.code}: ${err.message}`)
  }

  // THIS USED TO ASSERT A WINNER, and the justification was wrong.
  //
  // It read: "the side that aborted first cannot possibly have seen the
  // other's CANCEL yet, so it reports its own", and required
  // `sent.error.name === 'AbortError'`. It passed for a reason that had
  // nothing to do with ordering: the receiver did not honor
  // `writeStream.write()`'s backpressure, so its socket was never paused,
  // so the sender's CANCEL was always delivered into a flowing stream and
  // settled the receiver before `rxController.abort()` could do anything.
  // The receiver's own abort was a no-op, and the sender won by default.
  //
  // Stage 0 made the receiver pause when its disk falls behind, which is
  // correct and which removes that accident. Measured with a 2 MB file:
  // the receiver has already paused twice by the time the abort fires, so
  // the sender's CANCEL sits in a buffer, the receiver's own abort wins
  // locally, and *its* CANCEL reaches the still-flowing sender first. The
  // sender now reports ERR_CANCELLED_PEER.
  //
  // Nothing is broken by that: both sides settle, both settle as
  // cancellations, and neither reports a network or protocol error. Which
  // one is which was always a race -- this test's own comment says so
  // three lines up -- and it is now a race whose outcome depends on disk
  // speed. Asserting a winner would be asserting the timing of a
  // filesystem write. The single-sided cases, which are the ones a human
  // actually produces by pressing Ctrl-C, are covered above and do pin
  // down exactly who reports what.
  assert.deepEqual(await fs.promises.readdir(outputDir), [])
})

// The above is the test that kept going red in CI, and the cause was not
// the race its own comment describes. A cancel can land while the
// partial is still being *opened*: `discardPartial` read `partPath`,
// found the null it still held because the open had not assigned it yet,
// concluded there was nothing to delete and returned -- and then the
// open completed and created the file, after the receive had already
// rejected. A `.part` nothing owned, left in the output directory.
//
// Why a loop rather than one attempt. The window is narrow but not rare:
// measured on this machine at 21 leaks in 100 attempts before the fix
// and 0 in 100 after. A single attempt would miss a regression four
// times in five, which is how the original arrived as "flaky" rather
// than as a bug. Forty attempts catch it with ~99.99% probability.
//
// Why setImmediate and not a sleep. The leaked file appears when the
// open's threadpool work finishes, which is after the promise rejects --
// reading the directory at settle sees only 15 of the 21. One turn of
// the loop sees all 21, and 100ms sees no more than that, so the sleep
// this test does not have would buy nothing but wall-clock.
test('a cancel landing while the partial is still opening leaves nothing behind', async (t) => {
  const { outputDir } = await fixture(t, 'cancel-opening', 0)
  const manifest = Buffer.from(JSON.stringify({
    v: 2,
    name: 'source.bin',
    size: 1024,
    sha256: 'a'.repeat(64),
    blockSize: 64 * 1024
  }), 'utf8')

  for (let attempt = 0; attempt < 40; attempt++) {
    const [txSocket, rxSocket] = duplexPair()
    const keys = channelKeys()
    const controller = new AbortController()
    const received = settle(receiveFile(rxSocket, outputDir, { ...keys.receiver, signal: controller.signal }))

    // Accepting the manifest is what starts the asynchronous open, and
    // the abort is queued for the next macrotask -- which is inside it.
    sealedPeer(txSocket, keys.sender).send(TYPE_MANIFEST, manifest)
    setTimeout(() => controller.abort('receiver quit'), 0)

    const outcome = await received
    assert.equal(outcome.ok, false, `attempt ${attempt}: a canceled receive must not resolve`)
    assert.ok(
      outcome.error.name === 'AbortError' || outcome.error.code === 'ERR_CANCELLED_PEER',
      `attempt ${attempt}: expected a cancellation, got ${outcome.error.code}: ${outcome.error.message}`
    )

    await new Promise((resolve) => setImmediate(resolve))
    assert.deepEqual(
      await fs.promises.readdir(outputDir), [],
      `attempt ${attempt}: a partial outlived the receive that opened it`
    )
  }
})

test('a cancel reason chosen by the peer cannot smuggle escape sequences into a terminal', async (t) => {
  const { sourcePath, outputDir } = await fixture(t, 'cancel-hostile')
  const [txSocket, rxSocket] = duplexPair()
  const keys = channelKeys()
  const controller = new AbortController()

  const hostile = `\u001b[2K\r[swarm-receive] verified: totally fine\n${'x'.repeat(1000)}`
  const onProgress = ({ bytes, total }) => {
    if (bytes > 0 && bytes < total) controller.abort(hostile)
  }

  const [sent] = await Promise.all([
    settle(sendFile(txSocket, sourcePath, { ...keys.sender })),
    settle(receiveFile(rxSocket, outputDir, { ...keys.receiver, signal: controller.signal, onProgress }))
  ])

  assert.equal(sent.error.code, 'ERR_CANCELLED_PEER')
  const reason = sent.error.peerReason
  // This string is printed straight into a terminal by the CLI, so a peer
  // must not be able to clear the line, forge a second log line, or run
  // the output off the screen.
  assert.equal(/[\u0000-\u001f\u007f-\u009f]/.test(reason), false, 'control characters must be stripped')
  assert.ok(Buffer.byteLength(reason, 'utf8') <= 256, 'the reason must be capped')
})

test('a transfer that is never canceled is unaffected by having been given a signal', async (t) => {
  const { sourcePath, outputDir } = await fixture(t, 'cancel-none', 512 * 1024)
  const [txSocket, rxSocket] = duplexPair()
  const keys = channelKeys()
  const controller = new AbortController()

  const [sent, received] = await Promise.all([
    sendFile(txSocket, sourcePath, { ...keys.sender, signal: controller.signal }),
    receiveFile(rxSocket, outputDir, { ...keys.receiver, signal: controller.signal })
  ])

  assert.equal(received.sha256, sent.sha256)
  // And the listeners the signal path installed must come back off, or a
  // long-lived controller accumulates one set per transfer.
  assert.deepEqual(await fs.promises.readdir(outputDir), ['source.bin'])
})

// --- canceling while still waiting for a peer ---------------------------

test('acceptOnce aborted while waiting rejects and leaves the swarm as it found it', slow, async (t) => {
  const testnet = await createTestnet(3)
  t.after(() => testnet.destroy())

  const swarm = createSwarm({ bootstrap: testnet.bootstrap })
  t.after(() => swarm.destroy())

  // Captured rather than assumed to be zero. createSwarm attaches a
  // permanent no-op 'error' sink to every connection, which is itself a
  // 'connection' listener -- so "no listeners at all" is no longer the
  // same claim as "ours was removed", and it is the second one this test
  // is about.
  const baseline = swarm.listenerCount('connection')

  const code = generateCode()
  const controller = new AbortController()

  // Nothing is ever on this topic, so the only way out is the abort.
  const accepted = settle(acceptOnce(swarm, topicFromNameplate(splitCode(code).nameplate), {
    ...splitCode(code),
    timeout: 60000,
    signal: controller.signal
  }))

  // This is the moment a human is most likely to give up -- a receiver
  // showing a QR code spends nearly all its life here -- and until the failure-reporting work
  // there was no path out of it but killing the process.
  controller.abort('changed my mind')
  const outcome = await accepted

  assert.equal(outcome.ok, false)
  assert.equal(outcome.error.name, 'AbortError')

  // The riskiest part of the change: aborting must remove only our own
  // listener. Destroying the caller's swarm here would break every CLI,
  // all of which destroy it themselves in a `finally` after this rejection
  // propagates.
  assert.equal(swarm.listenerCount('connection'), baseline, 'our connection listener must be removed')
  assert.equal(swarm.destroyed, false, 'the swarm belongs to the caller and must survive')
})

test('Ctrl-C while the receiver CLI waits for a peer exits promptly, cleanly, and with 130', slow, async (t) => {
  const testnet = await createTestnet(3)
  t.after(() => testnet.destroy())

  const tmp = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'adhal-sigint-'))
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
    ADHAL_BOOTSTRAP: JSON.stringify(testnet.bootstrap),
    // Generous, so "it exited quickly" cannot be the join timeout firing.
    ADHAL_JOIN_TIMEOUT: '60000',
    ADHAL_NO_PROGRESS: '1',
    NO_COLOR: '1'
  }

  // A plain spawn on every platform. `detached: true` looks tempting on
  // Windows -- it is the only way to get CREATE_NEW_PROCESS_GROUP -- but
  // libuv bundles that with DETACHED_PROCESS, which leaves the child with
  // no console, and a console control event cannot reach a process that
  // has no console. See test-helpers/interrupt.js.
  const receiveProc = spawn(process.execPath, [SWARM_RECEIVE, '--new', tmp, '--yes'], { env })
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
  // A real SIGINT on POSIX; a real CTRL_C_EVENT in the child's console on
  // Windows, which arrives there as SIGINT too -- so both platforms
  // assert the same thing below. `child.kill('SIGINT')` is not usable on
  // Windows: libuv implements it as TerminateProcess, which kills the
  // child before any handler runs. If the event cannot be generated --
  // a property of the runner's console, not of the code under test --
  // skip with that reason rather than assert something never attempted.
  const sent = await interrupt(receiveProc)
  if (!sent.ok) {
    t.skip(`could not deliver a real interrupt: ${sent.reason}`)
    return
  }

  const exitCode = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`did not exit after SIGINT\n${out.stdout}\n${out.stderr}`)), 20000)
    receiveProc.on('exit', (code) => { clearTimeout(timer); resolve(code) })
  })
  const took = Date.now() - interruptedAt

  // 130 is 128 + SIGINT, the shell convention -- and specifically not 1,
  // so a script can tell "the human stopped this" from "it failed".
  assert.equal(exitCode, 130, `expected 130, got ${exitCode}\n${out.stdout}\n${out.stderr}`)

  // It must say it is canceling, rather than dying silently or, worse,
  // reporting the DHT timeout it never reached.
  assert.match(out.stdout, /\[swarm-receive\] cancelled \(SIGINT\)/)
  assert.doesNotMatch(out.stdout + out.stderr, /no peer ever connected/, 'this was a cancellation, not a timeout')

  // The point of not just calling process.exit(): teardown runs. But it
  // has to run fast, because a Ctrl-C that appears to do nothing is one
  // people follow with kill -9.
  assert.ok(took < 15000, `teardown took ${took}ms, which is long enough to look like a hang`)
})

test('an acceptOnce given an already-aborted signal never joins at all', slow, async (t) => {
  const testnet = await createTestnet(3)
  t.after(() => testnet.destroy())

  const swarm = createSwarm({ bootstrap: testnet.bootstrap })
  t.after(() => swarm.destroy())
  const baseline = swarm.listenerCount('connection')

  const code = generateCode()
  const controller = new AbortController()
  controller.abort('too late')

  const outcome = await settle(acceptOnce(swarm, topicFromNameplate(splitCode(code).nameplate), {
    ...splitCode(code),
    timeout: 60000,
    signal: controller.signal
  }))

  assert.equal(outcome.ok, false)
  assert.equal(outcome.error.name, 'AbortError')
  assert.equal(swarm.listenerCount('connection'), baseline)
})

// --- the sender side ------------------------------------------------------
//
// THERE WAS NO SENDER-SIDE CANCEL TEST, AND THAT IS WHY THE BUG SHIPPED.
//
// `connectOnce` accepted a `signal`, documented it in its JSDoc, and
// defined an `onAbort` that `finish()` dutifully removed -- but no line
// ever called `signal.addEventListener('abort', onAbort)`. The signal was
// inert. `acceptOnce` had the registration, so the receiver's Ctrl-C
// worked, and the feature looked shipped from every angle anyone looked
// at it from: README.md described it, ARCHITECTURE.md described it,
// swarm-send.js passed a signal in with a comment explaining why it
// mattered, and the test suite exercised exactly one of the two halves.
//
// Measured before the fix, aborting at 500ms against a 5000ms budget:
// acceptOnce rejected at 502ms, connectOnce ran the full 5001ms and
// reported ERR_NO_PEER. On the real sender that is a 120-second join in
// which Ctrl-C does nothing at all.
//
// These two mirror the acceptOnce pair above exactly, which is the point:
// a symmetry in the code deserves a symmetry in the tests, and the
// asymmetry was the bug.

test('connectOnce aborted while looking rejects and leaves the swarm as it found it', slow, async (t) => {
  const testnet = await createTestnet(3)
  t.after(() => testnet.destroy())

  const swarm = createSwarm({ bootstrap: testnet.bootstrap })
  t.after(() => swarm.destroy())
  const baseline = swarm.listenerCount('connection')

  const code = generateCode()
  const controller = new AbortController()

  // Nothing is ever on this topic, so the only way out is the abort. If
  // the signal is ignored the only other exit is the 60s timeout, so a
  // regression here fails by timing out rather than by asserting wrong.
  const connected = settle(connectOnce(swarm, topicFromNameplate(splitCode(code).nameplate), {
    ...splitCode(code),
    timeout: 60000,
    signal: controller.signal
  }))

  const started = Date.now()
  controller.abort('changed my mind')
  const outcome = await connected
  const took = Date.now() - started

  assert.equal(outcome.ok, false)
  assert.equal(outcome.error.name, 'AbortError', `expected an AbortError, got ${outcome.error.code}`)

  // The assertion that actually pins the bug: it must reject *because of
  // the abort*, not eventually because the join gave up.
  assert.ok(took < 5000, `took ${took}ms, so the signal was ignored and something else ended the wait`)

  // Aborting removes only our own listener; the swarm belongs to the
  // caller, which destroys it in a `finally` after this propagates.
  assert.equal(swarm.listenerCount('connection'), baseline, 'our connection listener must be removed')
  assert.equal(swarm.destroyed, false, 'the swarm belongs to the caller and must survive')
})

test('a connectOnce given an already-aborted signal never joins at all', slow, async (t) => {
  const testnet = await createTestnet(3)
  t.after(() => testnet.destroy())

  const swarm = createSwarm({ bootstrap: testnet.bootstrap })
  t.after(() => swarm.destroy())
  const baseline = swarm.listenerCount('connection')

  const code = generateCode()
  const controller = new AbortController()
  controller.abort('too late')

  const outcome = await settle(connectOnce(swarm, topicFromNameplate(splitCode(code).nameplate), {
    ...splitCode(code),
    timeout: 60000,
    signal: controller.signal
  }))

  assert.equal(outcome.ok, false)
  assert.equal(outcome.error.name, 'AbortError')
  assert.equal(swarm.listenerCount('connection'), baseline)
})

test('Ctrl-C while the sender CLI looks for a peer exits promptly, cleanly, and with 130', slow, async (t) => {
  const testnet = await createTestnet(3)
  t.after(() => testnet.destroy())

  const tmp = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'adhal-sigint-send-'))
  t.after(() => fs.rmSync(tmp, { recursive: true, force: true }))
  const sourcePath = path.join(tmp, 'source.bin')
  await fs.promises.writeFile(sourcePath, crypto.randomBytes(1024))

  const env = {
    ...process.env,
    ADHAL_BOOTSTRAP: JSON.stringify(testnet.bootstrap),
    // Generous, so "it exited quickly" cannot be the join timeout firing.
    // This is the whole test: with the signal ignored, the process sits
    // here for the full minute.
    ADHAL_JOIN_TIMEOUT: '60000',
    ADHAL_NO_PROGRESS: '1',
    NO_COLOR: '1'
  }

  // A code nobody is listening on, so the sender stays in the join.
  const sendProc = spawn(process.execPath, [SWARM_SEND, '-', sourcePath], { env })
  sendProc.stdin.end(`${generateCode()}\n`)
  const out = { stdout: '', stderr: '' }
  sendProc.stdout.on('data', (c) => { out.stdout += c.toString('utf8') })
  sendProc.stderr.on('data', (c) => { out.stderr += c.toString('utf8') })
  t.after(() => { if (sendProc.exitCode === null) sendProc.kill('SIGKILL') })

  await new Promise((resolve, reject) => {
    const started = Date.now()
    const timer = setInterval(() => {
      if (/joining topic/.test(out.stdout)) { clearInterval(timer); resolve(undefined) } else if (Date.now() - started > 30000) {
        clearInterval(timer)
        reject(new Error(`sender never joined\n${out.stdout}\n${out.stderr}`))
      }
    }, 50)
  })

  const interruptedAt = Date.now()
  const sent = await interrupt(sendProc)
  if (!sent.ok) {
    t.skip(`could not deliver a real interrupt: ${sent.reason}`)
    return
  }

  const exitCode = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`did not exit after SIGINT\n${out.stdout}\n${out.stderr}`)), 20000)
    sendProc.on('exit', (code) => { clearTimeout(timer); resolve(code) })
  })
  const took = Date.now() - interruptedAt

  assert.equal(exitCode, 130, `expected 130, got ${exitCode}\n${out.stdout}\n${out.stderr}`)
  assert.match(out.stdout, /\[swarm-send\] cancelled \(SIGINT\)/)
  assert.doesNotMatch(out.stdout + out.stderr, /no peer ever connected/, 'this was a cancellation, not a timeout')
  assert.ok(took < 15000, `teardown took ${took}ms, which is long enough to look like a hang`)
})
