'use strict'

// Regression test for the failure that broke the first cross-ISP drop
// attempt (Starlink sender -> Comcast receiver): hyperdht discovery and a
// raw dial both succeeded, but no bytes ever moved and the sender reported
// "timed out looking for a peer" having in fact found one.
//
// Cause: acceptOnce resolved on its first 'connection' event, clearing its
// timeout and removing its listener before the peer had proven itself. A
// punch that half-failed -- routine on a firewalled CGNAT path, and the
// exact case connectOnce was already hardened against -- therefore
// consumed the receiver permanently. The sender correctly discarded the
// dead candidate and kept dialing; the receiver could no longer answer any
// of it.
//
// The peer these tests use to reproduce that is a real Hyperswarm node
// that joins the topic and then declines to finish the handshake: it takes
// the receiver's HELLO and drops the connection. That is what a
// half-failed punch, and equally a scratch-lookup.js --connect probe,
// looks like from the receiver's side.
//
// Peers that answer *wrongly* -- the PAKE threat model -- are covered in
// pake-handshake.test.js. This file stays about candidates that die rather
// than candidates that lie.

const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('node:path')
const os = require('node:os')
const fs = require('node:fs')
const crypto = require('node:crypto')
const { spawn } = require('node:child_process')
const createTestnet = require('hyperdht/testnet')

const {
  createSwarm,
  acceptOnce,
  connectOnce,
  timeoutMessage,
  topicFromNameplate,
  splitCode,
  generateCode,
  sendFile,
  receiveFile,
} = require('@ad-hal/engine')
const { slow } = require('../test-helpers/tiers')

const REPO_ROOT = path.resolve(__dirname, '..', '..')
const SWARM_RECEIVE = path.join(REPO_ROOT, 'cli', 'src', 'swarm-receive.js')

// Joins `topic`, waits for the receiver's HELLO, then drops the connection
// without answering -- a peer that punches through and then vanishes
// mid-handshake.
//
// Waiting for HELLO before destroying is what makes this deterministic:
// the receiver is guaranteed to have reached the candidate stage, so the
// test exercises "candidate discarded" rather than racing the connection
// against the receiver's own bookkeeping.
async function joinAsBadPeer (bootstrap, topic) {
  const swarm = createSwarm({ bootstrap })
  /** @type {(value?: any) => void} */
  let sawHello = () => {}
  const helloSeen = new Promise((resolve) => { sawHello = resolve })

  swarm.on('connection', (socket) => {
    socket.on('error', () => {})
    socket.once('data', () => {
      sawHello()
      socket.destroy()
    })
  })

  const discovery = swarm.join(topic)
  await discovery.flushed()
  return { swarm, helloSeen }
}

function captureOutput (child) {
  const state = { stdout: '', stderr: '' }
  child.stdout.on('data', (c) => { state.stdout += c.toString('utf8') })
  child.stderr.on('data', (c) => { state.stderr += c.toString('utf8') })
  return state
}

function waitForPattern (state, pattern, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const start = Date.now()
    const timer = setInterval(() => {
      const match = state.stdout.match(pattern)
      if (match) { clearInterval(timer); resolve(match) } else if (Date.now() - start > timeoutMs) {
        clearInterval(timer)
        reject(new Error(`timed out waiting for ${pattern}\nstdout:\n${state.stdout}\nstderr:\n${state.stderr}`))
      }
    }, 20)
  })
}

test('a peer that connects and vanishes without proving itself does not consume the receiver', slow, async (t) => {
  const testnet = await createTestnet(3)
  t.after(() => testnet.destroy())

  const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'adhal-handshake-'))
  t.after(() => fs.rmSync(tmpDir, { recursive: true, force: true }))

  const sourcePath = path.join(tmpDir, 'source.bin')
  const outputDir = path.join(tmpDir, 'received')
  await fs.promises.mkdir(outputDir, { recursive: true })
  const payload = crypto.randomBytes(512 * 1024)
  await fs.promises.writeFile(sourcePath, payload)
  const expected = crypto.createHash('sha256').update(payload).digest('hex')

  const code = generateCode()
  const topic = topicFromNameplate(splitCode(code).nameplate)
  const receiveSwarm = createSwarm({ bootstrap: testnet.bootstrap })
  t.after(() => receiveSwarm.destroy())

  const dropped = []
  let announce
  const announced = new Promise((resolve) => { announce = resolve })

  const accepted = acceptOnce(receiveSwarm, topic, {
    ...splitCode(code),
    timeout: 60000,
    onAnnounced: () => announce(),
    onCandidateDropped: (info, reason) => dropped.push(reason)
  })
  await announced

  // Burn a candidate: connect, take the HELLO, then disappear.
  const bad = await joinAsBadPeer(testnet.bootstrap, topic)
  await bad.helloSeen
  await bad.swarm.destroy()

  // The bug was that the receiver was now permanently committed to that
  // dead socket -- listener removed, timeout cleared. It must still be
  // waiting, and a genuine sender must still be able to complete a drop.
  const sendSwarm = createSwarm({ bootstrap: testnet.bootstrap })
  t.after(() => sendSwarm.destroy())

  const [rx, tx] = await Promise.all([
    accepted,
    connectOnce(sendSwarm, topic, { ...splitCode(code), timeout: 60000 })
  ])

  rx.socket.on('error', () => {})
  tx.socket.on('error', () => {})

  const [received, sent] = await Promise.all([
    receiveFile(rx.socket, outputDir, { sendKey: rx.sendKey, receiveKey: rx.receiveKey, pending: rx.pending }),
    sendFile(tx.socket, sourcePath, { sendKey: tx.sendKey, receiveKey: tx.receiveKey })
  ])

  assert.equal(sent.sha256, expected)
  assert.equal(received.sha256, expected, 'the drop completed despite the earlier dead candidate')
  assert.ok(dropped.length >= 1, `the dead candidate should have been reported, got ${JSON.stringify(dropped)}`)

  const onDisk = crypto.createHash('sha256').update(await fs.promises.readFile(received.path)).digest('hex')
  assert.equal(onDisk, expected)
})

test('a timeout reports whether it found nobody or found peers that never confirmed', () => {
  // Asserted directly rather than end to end. Driving the candidate branch
  // through a real swarm means racing a real peer's connection against a
  // real timeout: the peer has to arrive first for `candidates` to be
  // non-zero, and when the test files run in parallel it sometimes did not,
  // turning a correct implementation into a red build. The two branches are
  // pure string logic, so they are tested as such, and the CLI test below
  // covers candidates being observed and logged against a live peer.
  const none = timeoutMessage('looking for a peer', 1000, 0)
  assert.match(none, /no peer ever connected/)
  assert.doesNotMatch(none, /handshake/, 'must not blame the handshake when nothing connected')

  const some = timeoutMessage('looking for a peer', 1000, 3)
  assert.match(some, /3 peer\(s\) connected/)
  assert.match(some, /none completed the readiness handshake/)
  assert.match(some, /not a DHT one/, 'must point above the DHT, not at it')
})

test('a join that finds nobody says so', slow, async (t) => {
  const testnet = await createTestnet(3)
  t.after(() => testnet.destroy())

  // Deterministic: nothing is ever on this topic, so the zero-candidate
  // branch is the only one reachable regardless of timing.
  const lonely = createSwarm({ bootstrap: testnet.bootstrap })
  t.after(() => lonely.destroy())

  await assert.rejects(
    () => connectOnce(lonely, topicFromNameplate(splitCode(generateCode()).nameplate), { ...splitCode(generateCode()), timeout: 1500 }),
    /no peer ever connected/
  )
})

test('the receiver CLI reports a dropped candidate and keeps waiting', slow, async (t) => {
  const testnet = await createTestnet(3)
  t.after(() => testnet.destroy())

  const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'adhal-handshake-cli-'))
  t.after(() => fs.rmSync(tmpDir, { recursive: true, force: true }))

  const env = {
    ...process.env,
    ADHAL_BOOTSTRAP: JSON.stringify(testnet.bootstrap),
    ADHAL_JOIN_TIMEOUT: '60000',
    NO_COLOR: '1'
  }

  const receiveProc = spawn(process.execPath, [SWARM_RECEIVE, '--new', tmpDir], { env })
  const output = captureOutput(receiveProc)
  t.after(() => { if (receiveProc.exitCode === null) receiveProc.kill() })

  const codeMatch = await waitForPattern(output, /scan the code above, or type: {2}(\S+)/)
  const topic = topicFromNameplate(splitCode(codeMatch[1]).nameplate)

  const bad = await joinAsBadPeer(testnet.bootstrap, topic)
  t.after(() => bad.swarm.destroy())
  await bad.helloSeen

  // The two lines that turn this failure from invisible into obvious.
  await waitForPattern(output, /candidate \w+\.\.\., sent HELLO, awaiting REPLY/)
  await waitForPattern(output, /dropped before proving \(.*\); still waiting/)
  assert.equal(receiveProc.exitCode, null, 'the receiver must still be running')
})
