'use strict'

// Progress has two halves with two different failure modes, so it is
// tested as two things.
//
// The engine half is a contract: `{ bytes, total }` per chunk, never
// going backwards, guaranteed to start at 0 and to end at total. Anything
// built on it -- a bar, a test, Phase B's UI -- depends on those four
// promises and on nothing else, which is why the engine computes no
// percentage, rate or ETA.
//
// The CLI half is about not corrupting the output it shares. This suite
// already matches on exact line shapes (`/\[receive\] sha256: ([0-9a-f]{64})/`
// and friends), and a progress line that emitted '\r' into a pipe, or
// landed on the same line as `sha256:`, would break those tests in a way
// that looks like a transfer bug. So that is asserted directly rather
// than left as a convention.

const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('node:path')
const os = require('node:os')
const fs = require('node:fs')
const crypto = require('node:crypto')
const { spawn } = require('node:child_process')

const { sendFile, receiveFile } = require('@quay/engine')
const { slow } = require('../test-helpers/tiers')
const { duplexPair } = require('../test-helpers/duplex-pair')
const { channelKeys } = require('../test-helpers/sealed')
const { createProgressReporter } = require('../src/progress')

const REPO_ROOT = path.resolve(__dirname, '..', '..')
const RECEIVE_SCRIPT = path.join(REPO_ROOT, 'cli', 'src', 'receive.js')
const SEND_SCRIPT = path.join(REPO_ROOT, 'cli', 'src', 'send.js')

async function tmpDir (t, label) {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), `quay-${label}-`))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  return dir
}

// A stream that records instead of printing, with isTTY under the test's
// control -- the one thing that decides which of the two output modes
// runs, and the one thing a test process cannot otherwise choose.
function fakeStream (isTTY) {
  const chunks = []
  return {
    isTTY,
    write: (s) => { chunks.push(s); return true },
    get text () { return chunks.join('') },
    get writes () { return chunks.slice() }
  }
}

// --- the engine's contract -----------------------------------------------

test('both directions report progress that starts at 0, never goes backwards, and ends at the total', async (t) => {
  const dir = await tmpDir(t, 'progress-contract')
  const sourcePath = path.join(dir, 'source.bin')
  const outputDir = path.join(dir, 'out')
  await fs.promises.mkdir(outputDir)

  // Several chunks' worth, so "one event per chunk" is actually exercised
  // rather than collapsing into a single call.
  const size = 5 * 64 * 1024 + 11
  await fs.promises.writeFile(sourcePath, crypto.randomBytes(size))

  const sendEvents = []
  const receiveEvents = []
  const [txSocket, rxSocket] = duplexPair()
  const keys = channelKeys()

  await Promise.all([
    sendFile(txSocket, sourcePath, { ...keys.sender, onProgress: (p) => sendEvents.push(p) }),
    receiveFile(rxSocket, outputDir, { ...keys.receiver, onProgress: (p) => receiveEvents.push(p) })
  ])

  for (const { side, events } of [{ side: 'send', events: sendEvents }, { side: 'receive', events: receiveEvents }]) {
    assert.ok(events.length > 2, `${side} should emit one event per chunk, got ${events.length}`)
    assert.equal(events[0].bytes, 0, `${side} must start at 0`)
    assert.equal(events[events.length - 1].bytes, size, `${side} must finish at the total`)
    for (const event of events) assert.equal(event.total, size, `${side} total must not change`)
    for (let i = 1; i < events.length; i++) {
      assert.ok(events[i].bytes >= events[i - 1].bytes, `${side} progress must not go backwards`)
    }
  }
})

test('a zero-byte file still reports a complete transfer exactly once', async (t) => {
  const dir = await tmpDir(t, 'progress-empty')
  const sourcePath = path.join(dir, 'empty.bin')
  const outputDir = path.join(dir, 'out')
  await fs.promises.mkdir(outputDir)
  await fs.promises.writeFile(sourcePath, Buffer.alloc(0))

  const events = []
  const [txSocket, rxSocket] = duplexPair()
  const keys = channelKeys()
  await Promise.all([
    sendFile(txSocket, sourcePath, { ...keys.sender, onProgress: (p) => events.push(p) }),
    receiveFile(rxSocket, outputDir, { ...keys.receiver })
  ])

  // "First call at 0" and "final call at total" are the same call here,
  // and it must not be emitted twice.
  assert.deepEqual(events, [{ bytes: 0, total: 0 }])
})

// --- the CLI's rendering -------------------------------------------------

test('a non-TTY stream gets whole lines at fixed milestones and never a carriage return', () => {
  const stream = fakeStream(false)
  const reporter = createProgressReporter({ label: 'receive', stream, env: {} })

  const total = 1000
  reporter.onProgress({ bytes: 0, total })
  for (let bytes = 1; bytes <= total; bytes++) reporter.onProgress({ bytes, total })
  reporter.close()

  assert.equal(stream.text.includes('\r'), false, 'a carriage return in piped output corrupts whatever reads it next')

  // Milestones, not a timer: a timer makes the line count depend on how
  // fast the machine ran, and any test asserting on it becomes flaky
  // under load. 1001 events must always produce these five lines.
  const lines = stream.text.trim().split('\n')
  assert.deepEqual(lines.map((l) => l.match(/(\d+)%/)[1]), ['0', '25', '50', '75', '100'])
  for (const line of lines) assert.match(line, /^\[receive\] progress: \d+% \(\d+\/1000 bytes\)$/)
})

test('a TTY stream gets one line redrawn in place, throttled, but always rendered at the end', () => {
  const stream = fakeStream(true)
  let clock = 0
  const reporter = createProgressReporter({ label: 'send', stream, env: {}, now: () => clock })

  const total = 100
  reporter.onProgress({ bytes: 0, total })
  // Inside the throttle window: these must be collapsed away.
  for (let bytes = 1; bytes < 99; bytes++) reporter.onProgress({ bytes, total })
  clock += 1000
  reporter.onProgress({ bytes: 99, total })
  // The completing event must never be throttled away -- a bar frozen at
  // 99% because the last event landed inside the window reads as a hang.
  reporter.onProgress({ bytes: 100, total })
  reporter.close()

  const redraws = stream.writes.filter((w) => w.startsWith('\r'))
  assert.equal(redraws.length, 3, 'expected the first, one post-throttle and the final render')
  assert.match(redraws[redraws.length - 1], /100%/)
  assert.equal(stream.writes[stream.writes.length - 1], '\n', 'close() must end the line so the next log starts clean')
})

test('a stream of unknown length gets a running count on a TTY and nothing off one', () => {
  // total: null is a stream (PROTOCOL.md section 4.3). There is no
  // percentage to draw a bar or a milestone from, and a line per chunk off
  // a TTY would make the output depend on chunking -- the flakiness
  // milestones exist to prevent.
  const piped = fakeStream(false)
  const quiet = createProgressReporter({ label: 'send', stream: piped, env: {} })
  for (const bytes of [0, 10, 5000, 70000]) quiet.onProgress({ bytes, total: null })
  quiet.close()
  assert.equal(piped.text, '')

  const tty = fakeStream(true)
  let clock = 0
  const live = createProgressReporter({ label: 'send', stream: tty, env: {}, now: () => clock })
  live.onProgress({ bytes: 0, total: null })
  clock += 1000
  live.onProgress({ bytes: 2048, total: null })
  live.close()
  const redraws = tty.writes.filter((w) => w.startsWith('\r'))
  // Throttled like the bar: with no total there is no "complete" event to
  // exempt, so both of these are 1000ms apart on purpose.
  assert.equal(redraws.length, 2)
  assert.match(redraws[1], /\[send\] 2\.0 KB \(streaming, size unknown\)$/)
  assert.equal(/NaN|null/.test(tty.text), false, 'no total must never render as NaN or null')
})

test('QUAY_NO_PROGRESS=1 silences it completely', () => {
  const stream = fakeStream(true)
  const reporter = createProgressReporter({ label: 'send', stream, env: { QUAY_NO_PROGRESS: '1' } })
  reporter.onProgress({ bytes: 0, total: 10 })
  reporter.onProgress({ bytes: 10, total: 10 })
  reporter.close()
  assert.equal(stream.text, '')
})

test('close() is safe to call twice and on a reporter that never drew', () => {
  // Both happen on real paths: a transfer cancelled before its first
  // event, and a catch block that closes after the success path already
  // did.
  const stream = fakeStream(true)
  const reporter = createProgressReporter({ label: 'send', stream, env: {} })
  reporter.close()
  reporter.close()
  assert.equal(stream.text, '')
})

// --- the two halves together, through the real CLI -----------------------

test('the CLI prints progress and still prints the exact lines the rest of the suite matches on', slow, async (t) => {
  const dir = await tmpDir(t, 'progress-cli')
  const sourcePath = path.join(dir, 'source.bin')
  const outputDir = path.join(dir, 'received')
  const payload = crypto.randomBytes(2 * 1024 * 1024)
  await fs.promises.writeFile(sourcePath, payload)
  const expected = crypto.createHash('sha256').update(payload).digest('hex')

  const capture = (child) => {
    const state = { stdout: '', stderr: '' }
    child.stdout.on('data', (c) => { state.stdout += c.toString('utf8') })
    child.stderr.on('data', (c) => { state.stderr += c.toString('utf8') })
    return state
  }
  const waitForExit = (child) => new Promise((resolve, reject) => {
    child.on('exit', (code) => code === 0 ? resolve(undefined) : reject(new Error(`exited ${code}`)))
    child.on('error', reject)
  })

  const receiveProc = spawn(process.execPath, [RECEIVE_SCRIPT, '0', outputDir])
  const receiveOut = capture(receiveProc)
  t.after(() => { if (receiveProc.exitCode === null) receiveProc.kill() })

  await new Promise((resolve, reject) => {
    const started = Date.now()
    const timer = setInterval(() => {
      if (/listening on 127\.0\.0\.1:(\d+)/.test(receiveOut.stdout)) { clearInterval(timer); resolve(undefined) } else if (Date.now() - started > 5000) { clearInterval(timer); reject(new Error('receiver never listened')) }
    }, 20)
  })
  const port = receiveOut.stdout.match(/listening on 127\.0\.0\.1:(\d+)/)[1]
  // Printed on the line after the port, in the same write or the next.
  const code = receiveOut.stdout.match(/\[receive\] code: (\S+)/)?.[1] ??
    await new Promise((resolve) => receiveProc.stdout.on('data', () => {
      const m = receiveOut.stdout.match(/\[receive\] code: (\S+)/)
      if (m) resolve(m[1])
    }))

  // The loopback CLI runs the v2 handshake, so it needs the code; stdin
  // keeps it out of argv, as ./read-code.js recommends.
  const sendProc = spawn(process.execPath, [SEND_SCRIPT, port, '-', sourcePath])
  const sendOut = capture(sendProc)
  sendProc.stdin.end(`${code}\n`)
  await Promise.all([waitForExit(sendProc), waitForExit(receiveProc)])

  // Spawned with pipes, so both children see a non-TTY stdout.
  for (const { who, out } of [{ who: 'send', out: sendOut }, { who: 'receive', out: receiveOut }]) {
    assert.equal(out.stdout.includes('\r'), false, `${who} must not write a carriage return to a pipe`)
    assert.match(out.stdout, /progress: 100%/, `${who} should have reported progress`)
  }

  // The anchored forms. `^...$` with /m is what proves progress did not
  // smear onto the line, which an unanchored match would not catch.
  assert.match(receiveOut.stdout, new RegExp(`^\\[receive\\] sha256: ${expected}$`, 'm'))
  assert.match(sendOut.stdout, new RegExp(`^\\[send\\] sha256: ${expected}$`, 'm'))
  assert.match(receiveOut.stdout, /^\[receive\] verified: /m)
  assert.match(receiveOut.stdout, /^\[receive\] saved to: .+source\.bin$/m)
})
