'use strict'

// Automated version of the Hyperswarm milestone:
// "Same CLI over Hyperswarm on one LAN (two laptops) -- Proves topic join
// + Noise without your protocol bugs." Two real CLI processes join the
// same Hyperswarm topic and exchange a file over an encrypted DHT
// connection. Runs against an isolated local hyperdht testnet (not the
// public DHT), so it's fast, offline-safe, and doesn't require two
// physical machines to prove the topic-join + Noise-encrypted transport.

const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('node:path')
const os = require('node:os')
const fs = require('node:fs')
const crypto = require('node:crypto')
const { spawn } = require('node:child_process')
const createTestnet = require('hyperdht/testnet')
const { generateCode } = require('@ad-hal/engine')
const { slow } = require('../test-helpers/tiers')

const REPO_ROOT = path.resolve(__dirname, '..', '..')
const SWARM_RECEIVE_SCRIPT = path.join(REPO_ROOT, 'cli', 'src', 'swarm-receive.js')
const SWARM_SEND_SCRIPT = path.join(REPO_ROOT, 'cli', 'src', 'swarm-send.js')

function sha256File (filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256')
    const stream = fs.createReadStream(filePath)
    stream.on('data', (chunk) => hash.update(chunk))
    stream.on('end', () => resolve(hash.digest('hex')))
    stream.on('error', reject)
  })
}

// Accumulates stdout/stderr for the lifetime of the child so pattern
// waiting never races with later readers of the same stream.
function captureOutput (child) {
  const state = { stdout: '', stderr: '' }
  child.stdout.on('data', (chunk) => { state.stdout += chunk.toString('utf8') })
  child.stderr.on('data', (chunk) => { state.stderr += chunk.toString('utf8') })
  return state
}

function waitForPattern (state, pattern, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    const start = Date.now()
    const timer = setInterval(() => {
      const match = state.stdout.match(pattern)
      if (match) {
        clearInterval(timer)
        resolve(match)
      } else if (Date.now() - start > timeoutMs) {
        clearInterval(timer)
        reject(new Error(`timed out waiting for ${pattern}\nstdout:\n${state.stdout}\nstderr:\n${state.stderr}`))
      }
    }, 20)
  })
}

/** @returns {Promise<void>} */
function waitForExit (child, output) {
  return new Promise((resolve, reject) => {
    child.on('exit', (code) => {
      if (code === 0) resolve()
      else reject(new Error(`process exited with code ${code}\nstdout:\n${output.stdout}\nstderr:\n${output.stderr}`))
    })
    child.on('error', reject)
  })
}

// One end-to-end attempt: fresh isolated testnet, fresh temp files, spawn
// both CLI processes, and assert matching hashes. Broken out from the
// test body so it can be retried (see below).
async function attemptTransfer (t) {
  // A single-node testnet is too small for DHT peer lookup (find_peer) to
  // reliably converge -- verified empirically; 5 nodes gives comfortable
  // margin over hyperdht's own isolated-network guidance of at least one
  // persistent routing node plus enough peers for lookups to succeed.
  const testnet = await createTestnet(5)

  try {
    const bootstrapEnv = JSON.stringify(testnet.bootstrap)
    // A real generated code rather than the `test-<hex>` opaque string
    // this used to use. Opaque codes are now opt-in (see resolveCode), so
    // the old form would need `--insecure-opaque-code` on both spawns -- and a
    // test that has to disable a safety check to pass is testing the
    // wrong path. generateCode() is equally unique per run and exercises
    // what a user actually gets.
    const code = generateCode()
    const env = { ...process.env, ADHAL_BOOTSTRAP: bootstrapEnv }

    const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'adhal-swarm-'))
    const sourcePath = path.join(tmpDir, 'source.bin')
    const outputDir = path.join(tmpDir, 'received')

    try {
      const size = 10 * 1024 * 1024 // 10 MB, matching the doc's loopback/Hyperswarm spec
      await fs.promises.writeFile(sourcePath, crypto.randomBytes(size))
      const expectedHash = await sha256File(sourcePath)

      const receiveProc = spawn(process.execPath, [SWARM_RECEIVE_SCRIPT, code, outputDir], { env })
      const receiveOutput = captureOutput(receiveProc)

      try {
        await waitForPattern(receiveOutput, /waiting for a peer/)

        const sendProc = spawn(process.execPath, [SWARM_SEND_SCRIPT, code, sourcePath], { env })
        const sendOutput = captureOutput(sendProc)

        try {
          await Promise.all([waitForExit(sendProc, sendOutput), waitForExit(receiveProc, receiveOutput)])
        } finally {
          if (sendProc.exitCode === null) sendProc.kill()
        }

        const sendMatch = sendOutput.stdout.match(/\[swarm-send\] sha256: ([0-9a-f]{64})/)
        const receiveMatch = receiveOutput.stdout.match(/\[swarm-receive\] sha256: ([0-9a-f]{64})/)

        assert.ok(sendMatch, `swarm-send.js should print a sha256 line, got:\n${sendOutput.stdout}\n${sendOutput.stderr}`)
        assert.ok(receiveMatch, `swarm-receive.js should print a sha256 line, got:\n${receiveOutput.stdout}\n${receiveOutput.stderr}`)
        assert.equal(sendMatch[1], expectedHash)
        assert.equal(receiveMatch[1], expectedHash)

        const receivedFilePath = path.join(outputDir, 'source.bin')
        const receivedHash = await sha256File(receivedFilePath)
        assert.equal(receivedHash, expectedHash)
      } finally {
        if (receiveProc.exitCode === null) receiveProc.kill()
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true })
    }
  } finally {
    await testnet.destroy()
  }
}

test('two local processes transfer a 10 MB file over a Hyperswarm topic on an isolated DHT testnet', slow, async (t) => {
  // NAT-traversal/hole-punch protocols are inherently probabilistic --
  // the doc's own premise is that punch success isn't 100% (hence a relay
  // fallback in a later phase). A handful of retries here absorbs that
  // expected transient flakiness without masking a real regression: a
  // genuine protocol bug fails every attempt, not just an occasional one.
  const attempts = 3
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      await attemptTransfer(t)
      return
    } catch (err) {
      if (attempt === attempts) throw err
      console.log(`[swarm-lan.test] attempt ${attempt} failed, retrying: ${err.message.split('\n')[0]}`)
    }
  }
})
