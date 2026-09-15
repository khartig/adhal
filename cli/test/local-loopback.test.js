'use strict'

// Automated version of docs/Refined-Implementation-Plan.md section 4, item 1:
// "Node CLI: two processes on one machine, localhost pipe, send 10 MB,
// print SHA-256 both sides." Zero NAT, zero Hyperswarm -- just proves the
// chunking/hashing pipeline works before item 2 adds the DHT.

const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('node:path')
const os = require('node:os')
const fs = require('node:fs')
const crypto = require('node:crypto')
const { spawn } = require('node:child_process')

const REPO_ROOT = path.resolve(__dirname, '..', '..')
const RECEIVE_SCRIPT = path.join(REPO_ROOT, 'cli', 'src', 'receive.js')
const SEND_SCRIPT = path.join(REPO_ROOT, 'cli', 'src', 'send.js')

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

function waitForPattern (state, pattern, timeoutMs = 5000) {
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
function waitForExit (child) {
  return new Promise((resolve, reject) => {
    child.on('exit', (code) => {
      if (code === 0) resolve()
      else reject(new Error(`process exited with code ${code}`))
    })
    child.on('error', reject)
  })
}

test('two local processes transfer a 10 MB file over a loopback TCP pipe and agree on the SHA-256', async (t) => {
  const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'quay-loopback-'))
  const sourcePath = path.join(tmpDir, 'source.bin')
  const outputDir = path.join(tmpDir, 'received')

  t.after(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true })
  })

  const size = 10 * 1024 * 1024 // 10 MB, matching the doc's item 1 spec
  await fs.promises.writeFile(sourcePath, crypto.randomBytes(size))
  const expectedHash = await sha256File(sourcePath)

  const receiveProc = spawn(process.execPath, [RECEIVE_SCRIPT, '0', outputDir])
  const receiveOutput = captureOutput(receiveProc)
  t.after(() => { if (receiveProc.exitCode === null) receiveProc.kill() })

  const listeningMatch = await waitForPattern(receiveOutput, /listening on 127\.0\.0\.1:(\d+)/)
  const boundPort = listeningMatch[1]

  const sendProc = spawn(process.execPath, [SEND_SCRIPT, boundPort, sourcePath])
  const sendOutput = captureOutput(sendProc)

  await Promise.all([waitForExit(sendProc), waitForExit(receiveProc)])

  const sendMatch = sendOutput.stdout.match(/\[send\] sha256: ([0-9a-f]{64})/)
  const receiveMatch = receiveOutput.stdout.match(/\[receive\] sha256: ([0-9a-f]{64})/)

  assert.ok(sendMatch, `send.js should print a sha256 line, got:\n${sendOutput.stdout}\n${sendOutput.stderr}`)
  assert.ok(receiveMatch, `receive.js should print a sha256 line, got:\n${receiveOutput.stdout}\n${receiveOutput.stderr}`)
  assert.equal(sendMatch[1], expectedHash)
  assert.equal(receiveMatch[1], expectedHash)

  const receivedFilePath = path.join(outputDir, 'source.bin')
  const receivedHash = await sha256File(receivedFilePath)
  assert.equal(receivedHash, expectedHash)
})
