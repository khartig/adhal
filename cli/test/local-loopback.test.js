'use strict'
const { slow } = require('../test-helpers/tiers')

// Automated version of the loopback milestone:
// "Node CLI: two processes on one machine, localhost pipe, send 10 MB,
// print SHA-256 both sides." Zero NAT, zero Hyperswarm -- just proves the
// chunking/hashing pipeline works before the DHT transport adds.
//
// Since v2 it also proves PROTOCOL.md section 3.3's claim end to end: the
// two processes run the CPace handshake over plain TCP, with no Noise
// underneath, and the transfer is sealed under the keys it derives.

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

test('two local processes transfer a 10 MB file over a loopback TCP pipe and agree on the SHA-256', slow, async (t) => {
  const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'adhal-loopback-'))
  const sourcePath = path.join(tmpDir, 'source.bin')
  const outputDir = path.join(tmpDir, 'received')

  t.after(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true })
  })

  const size = 10 * 1024 * 1024 // 10 MB, matching the doc's loopback spec
  await fs.promises.writeFile(sourcePath, crypto.randomBytes(size))
  const expectedHash = await sha256File(sourcePath)

  const receiveProc = spawn(process.execPath, [RECEIVE_SCRIPT, '0', outputDir])
  const receiveOutput = captureOutput(receiveProc)
  t.after(() => { if (receiveProc.exitCode === null) receiveProc.kill() })

  const listeningMatch = await waitForPattern(receiveOutput, /listening on 127\.0\.0\.1:(\d+)/)
  const boundPort = listeningMatch[1]
  const code = (await waitForPattern(receiveOutput, /\[receive\] code: (\S+)/))[1]

  // On stdin, the way ./read-code.js recommends, rather than in argv.
  const sendProc = spawn(process.execPath, [SEND_SCRIPT, boundPort, '-', sourcePath])
  const sendOutput = captureOutput(sendProc)
  sendProc.stdin.end(`${code}\n`)

  await Promise.all([waitForExit(sendProc), waitForExit(receiveProc)])

  const sendMatch = sendOutput.stdout.match(/\[send\] sha256: ([0-9a-f]{64})/)
  const receiveMatch = receiveOutput.stdout.match(/\[receive\] sha256: ([0-9a-f]{64})/)

  assert.ok(sendMatch, `send.js should print a sha256 line, got:\n${sendOutput.stdout}\n${sendOutput.stderr}`)
  assert.ok(receiveMatch, `receive.js should print a sha256 line, got:\n${receiveOutput.stdout}\n${receiveOutput.stderr}`)
  assert.equal(sendMatch[1], expectedHash)
  assert.equal(receiveMatch[1], expectedHash)
  // Both sides say the handshake completed before any file byte moved.
  assert.match(sendOutput.stdout, /\[send\] handshake confirmed/)
  assert.match(receiveOutput.stdout, /\[receive\] handshake confirmed/)

  const receivedFilePath = path.join(outputDir, 'source.bin')
  const receivedHash = await sha256File(receivedFilePath)
  assert.equal(receivedHash, expectedHash)
})

test('a pipe streams through the CLI: send.js <port> <code> - offers it with no size and it arrives verified', slow, async (t) => {
  // PROTOCOL.md section 4.3 end to end, and the one test that shows the
  // handshake's negotiated caps reaching both transfer halves: the unit
  // tests hand `caps` in themselves, so only a real handshake proves the
  // CLIs pass along what it actually agreed.
  const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'adhal-loopback-stream-'))
  const outputDir = path.join(tmpDir, 'received')
  t.after(() => { fs.rmSync(tmpDir, { recursive: true, force: true }) })

  const payload = crypto.randomBytes(3 * 1024 * 1024 + 17)
  const expectedHash = crypto.createHash('sha256').update(payload).digest('hex')

  const receiveProc = spawn(process.execPath, [RECEIVE_SCRIPT, '0', outputDir])
  const receiveOutput = captureOutput(receiveProc)
  t.after(() => { if (receiveProc.exitCode === null) receiveProc.kill() })

  const boundPort = (await waitForPattern(receiveOutput, /listening on 127\.0\.0\.1:(\d+)/))[1]
  const code = (await waitForPattern(receiveOutput, /\[receive\] code: (\S+)/))[1]

  // The code on argv, because stdin is the data.
  const sendProc = spawn(process.execPath, [SEND_SCRIPT, boundPort, code, '-'])
  const sendOutput = captureOutput(sendProc)
  sendProc.stdin.end(payload)

  await Promise.all([waitForExit(sendProc), waitForExit(receiveProc)])

  assert.match(receiveOutput.stdout, /\[receive\] manifest: stdin \(streamed, size unknown until it ends\)/)
  assert.equal(sendOutput.stdout.match(/\[send\] sha256: ([0-9a-f]{64})/)?.[1], expectedHash, sendOutput.stdout + sendOutput.stderr)
  assert.equal(receiveOutput.stdout.match(/\[receive\] sha256: ([0-9a-f]{64})/)?.[1], expectedHash, receiveOutput.stdout + receiveOutput.stderr)
  assert.deepEqual(await fs.promises.readFile(path.join(outputDir, 'stdin')), payload)
})

test('a transfer killed partway resumes under a new code: the receiver keeps its partial and the next drop continues it', slow, async (t) => {
  // PROTOCOL.md section 7 through the real CLIs: the handshake has to
  // negotiate "resume", and both scripts have to hand that to the engine,
  // or the partial is discarded and the second drop starts from zero.
  // SIGKILL rather than SIGINT, because a crash sends no CANCEL -- and a
  // cancel, by design, would discard the partial.
  const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'adhal-loopback-resume-'))
  const sourcePath = path.join(tmpDir, 'source.bin')
  const outputDir = path.join(tmpDir, 'received')
  t.after(() => { fs.rmSync(tmpDir, { recursive: true, force: true }) })

  await fs.promises.writeFile(sourcePath, crypto.randomBytes(64 * 1024 * 1024))
  const expectedHash = await sha256File(sourcePath)

  async function startReceiver () {
    const proc = spawn(process.execPath, [RECEIVE_SCRIPT, '0', outputDir])
    const output = captureOutput(proc)
    t.after(() => { if (proc.exitCode === null) proc.kill() })
    const port = (await waitForPattern(output, /listening on 127\.0\.0\.1:(\d+)/))[1]
    const code = (await waitForPattern(output, /\[receive\] code: (\S+)/))[1]
    return { proc, output, port, code }
  }

  const first = await startReceiver()
  const firstSender = spawn(process.execPath, [SEND_SCRIPT, first.port, first.code, sourcePath])
  const firstSenderOutput = captureOutput(firstSender)
  await waitForPattern(first.output, /\[receive\] progress: 25%/, 20000)
  firstSender.kill('SIGKILL')
  await new Promise((resolve) => first.proc.on('exit', resolve))

  assert.match(first.output.stderr, /Kept \d+ bytes in .*source\.bin\.part/, first.output.stderr + firstSenderOutput.stderr)
  const kept = (await fs.promises.stat(path.join(outputDir, 'source.bin.part'))).size
  assert.ok(kept > 0)

  const second = await startReceiver()
  const secondSender = spawn(process.execPath, [SEND_SCRIPT, second.port, second.code, sourcePath])
  const secondSenderOutput = captureOutput(secondSender)
  await Promise.all([waitForExit(secondSender), waitForExit(second.proc)])

  const resumedAt = Number((second.output.stdout.match(/\[receive\] resuming from byte (\d+)/) || [])[1])
  assert.ok(resumedAt > 0, `the second receiver must resume, got:\n${second.output.stdout}`)
  assert.equal(second.output.stdout.match(/\[receive\] sha256: ([0-9a-f]{64})/)?.[1], expectedHash)
  assert.equal(secondSenderOutput.stdout.match(/\[send\] sha256: ([0-9a-f]{64})/)?.[1], expectedHash, secondSenderOutput.stdout + secondSenderOutput.stderr)
  assert.equal(await sha256File(path.join(outputDir, 'source.bin')), expectedHash)
  assert.deepEqual(await fs.promises.readdir(outputDir), ['source.bin'])
})
