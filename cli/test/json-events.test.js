'use strict'

// The --json event stream and --stdout (W13, docs/CLI-CONTRACT.md).
//
// THE CONTRACT IS CHECKED, NOT TRANSCRIBED. `checkEvent` below is the
// table in CLI-CONTRACT.md section 3.2 as code, and every line every test
// here reads goes through it: a field that drifts from the table fails a
// test before it fails a script. The end-to-end tests then check the
// things only a real drop shows -- the order, the one final event, the
// exit status that goes with it, and that stdout under --stdout is the
// file and nothing else.

const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('node:path')
const os = require('node:os')
const fs = require('node:fs')
const crypto = require('node:crypto')
const { spawn } = require('node:child_process')
const { Writable } = require('node:stream')

const { createEventStream, failureCode, PROGRESS_MS, SCHEMA_VERSION } = require('../src/events')
const { createConsent } = require('../src/consent')
const { slow } = require('../test-helpers/tiers')

const REPO_ROOT = path.resolve(__dirname, '..', '..')
const RECEIVE = path.join(REPO_ROOT, 'cli', 'src', 'swarm-receive.js')
const SEND = path.join(REPO_ROOT, 'cli', 'src', 'swarm-send.js')

// --- the schema, from CLI-CONTRACT.md section 3.2 ----------------------------

const nullable = (/** @type {string} */ type) => (/** @type {any} */ v) => v === null || typeof v === type
const is = (/** @type {string} */ type) => (/** @type {any} */ v) => typeof v === type

/** @type {Record<string, Record<string, (v: any) => boolean>>} */
const REQUIRED = {
  start: { version: is('string'), time: is('string'), joinTimeout: is('number'), refreshInterval: is('number') },
  code: { code: is('string'), payload: is('string') },
  announced: {},
  candidate: { peer: is('string') },
  'candidate-dropped': { peer: is('string'), code: nullable('string'), counted: is('boolean'), paired: is('boolean') },
  'drop-taken': { peer: is('string') },
  warning: { kind: is('string'), message: is('string') },
  paired: { peer: is('string') },
  offer: { name: is('string'), declaredName: is('string'), size: nullable('number'), sha256: nullable('string'), partial: is('number'), risk: nullable('string') },
  accepted: { resumeFrom: is('number') },
  progress: { bytes: is('number'), total: nullable('number') },
  done: { name: is('string'), declaredName: is('string'), size: is('number'), sha256: is('string'), resumedFrom: is('number') },
  failed: { code: nullable('string'), message: is('string'), bytes: nullable('number') }
}

/**
 * Parses one line and checks it against the table. Returns the event.
 * @param {string} line
 */
function checkEvent (line) {
  const event = JSON.parse(line)
  assert.equal(typeof event, 'object')
  assert.equal(event.v, SCHEMA_VERSION, line)
  assert.ok(Object.hasOwn(REQUIRED, event.event), `unknown event: ${line}`)
  assert.equal(typeof event.ms, 'number', line)
  assert.ok(event.role === 'send' || event.role === 'receive', line)
  for (const [field, ok] of Object.entries(REQUIRED[event.event])) {
    assert.ok(ok(event[field]), `${event.event}.${field} is ${JSON.stringify(event[field])}: ${line}`)
  }
  return event
}

/** @param {string} text */
const eventsIn = (text) => text.split('\n').filter((l) => l.length > 0).map(checkEvent)

// --- the stream itself ---------------------------------------------------

/** A stream that keeps what is written, and a clock the test moves. */
function harness () {
  let out = ''
  let clock = 0
  const events = createEventStream({ role: 'receive', stream: { write: (s) => { out += s } }, now: () => clock })
  return { events, lines: () => eventsIn(out), advance: (/** @type {number} */ ms) => { clock += ms } }
}

test('every event is one line of JSON carrying v, event, ms, and role', () => {
  const h = harness()
  h.events.emit('start', { version: '0.0.0', time: new Date(0).toISOString(), joinTimeout: 30000, refreshInterval: 4000 })
  h.advance(12.6)
  h.events.emit('paired', { peer: 'abcdef012345' })
  const [start, paired] = h.lines()
  assert.equal(start.event, 'start')
  assert.equal(paired.ms, 13, 'ms is rounded')
})

test('a peer-chosen string with controls and a bidi override still makes one valid line', () => {
  const h = harness()
  const hostile = 'a\nb\r\x1b[2J‮exe.fdp\u0085\ud800'
  h.events.emit('offer', { name: 'x', declaredName: hostile, size: 1, sha256: null, partial: 0, risk: null })
  const lines = h.lines()
  assert.equal(lines.length, 1)
  assert.equal(lines[0].declaredName.slice(0, 4), 'a\nb\r', 'passed through as the engine had it, for the consumer to escape')
})

test('progress is throttled, never drops the completing event, and flushes what it held back', () => {
  const h = harness()
  h.events.emit('accepted', { resumeFrom: 0 })
  h.events.onProgress({ bytes: 0, total: 100 })
  h.advance(10)
  h.events.onProgress({ bytes: 10, total: 100 })
  h.advance(10)
  h.events.onProgress({ bytes: 20, total: 100 })
  h.advance(PROGRESS_MS)
  h.events.onProgress({ bytes: 30, total: 100 })
  h.advance(1)
  h.events.onProgress({ bytes: 100, total: 100 })
  assert.deepEqual(h.lines().filter((e) => e.event === 'progress').map((e) => e.bytes), [0, 30, 100])

  // A stream has no total to complete at: its last count waits for the flush.
  const s = harness()
  s.events.emit('accepted', { resumeFrom: 0 })
  s.events.onProgress({ bytes: 0, total: null })
  s.advance(1)
  s.events.onProgress({ bytes: 5, total: null })
  const bytes = () => s.lines().filter((e) => e.event === 'progress').map((e) => e.bytes)
  assert.deepEqual(bytes(), [0])
  s.events.flushProgress()
  assert.deepEqual(bytes(), [0, 5])
})

test('no progress before accepted: the engine reports 0 bytes while the offer is still unanswered', () => {
  // Found on the first real two-machine run (2026-10-29): both sides sent
  // progress{bytes: 0} ahead of accepted.
  const h = harness()
  h.events.onProgress({ bytes: 0, total: 100 })
  h.events.flushProgress()
  assert.deepEqual(h.lines(), [])
  h.events.emit('accepted', { resumeFrom: 0 })
  h.events.onProgress({ bytes: 0, total: 100 })
  assert.deepEqual(h.lines().map((e) => e.event), ['accepted', 'progress'])
})

test('failed takes its code from err.code, maps EPIPE, and copies the fields a script needs', () => {
  assert.equal(failureCode({ code: 'EPIPE' }), 'ERR_OUTPUT_CLOSED')
  assert.equal(failureCode({ code: 'ERR_ATTEMPT_CAP' }), 'ERR_ATTEMPT_CAP')
  assert.equal(failureCode(new Error('ERR_HASH_MISMATCH in the message is not a code')), null)

  const h = harness()
  h.events.failed({ code: 'ERR_DECLINED', peerReason: 'no', declineCode: 'ERR_DECLINED', bytes: 0, stack: 'x' }, 'the receiver declined')
  const [failed] = h.lines()
  assert.equal(failed.code, 'ERR_DECLINED')
  assert.equal(failed.peerReason, 'no')
  assert.equal(failed.bytes, 0)
  assert.equal(failed.stack, undefined, 'only the listed fields')
})

test('consent with ask: false declines without asking, even at a terminal', async () => {
  /** @type {string[]} */
  const lines = []
  const consent = createConsent({
    yes: false,
    ask: false,
    label: 'rx',
    log: (l) => lines.push(l),
    input: /** @type {any} */ ({ isTTY: true }),
    output: new Writable({ write (_c, _e, done) { assert.fail('nothing may be written to the terminal'); done() } })
  })
  const verdict = await consent.onOffer({ name: 'a.txt', declaredName: 'a.txt', size: 1, sha256: null })
  assert.equal(typeof verdict, 'string', 'a decline, with its reason')
})

// --- end to end, on a testnet --------------------------------------------

/**
 * @param {string} script
 * @param {string[]} args
 * @param {Record<string, string | undefined>} env
 * @param {string | null} stdin
 */
function run (script, args, env, stdin) {
  const child = spawn(process.execPath, [script, ...args], { env })
  /** @type {Buffer[]} */
  const stdout = []
  let stderr = ''
  child.stdout.on('data', (c) => stdout.push(c))
  child.stderr.on('data', (c) => { stderr += c.toString('utf8') })
  if (stdin !== null) child.stdin.end(stdin)
  /** @type {Promise<number | null>} */
  const exited = new Promise((resolve) => child.on('exit', (code) => resolve(code)))
  return { child, exited, stdout: () => Buffer.concat(stdout), stderr: () => stderr }
}

/** @param {() => string} read @param {string} name */
async function waitForEvent (read, name, ms = 20000) {
  const start = Date.now()
  while (Date.now() - start < ms) {
    if (eventsIn(read()).some((e) => e.event === name)) return
    await new Promise((resolve) => setTimeout(resolve, 20))
  }
  throw new Error(`no ${name} event within ${ms}ms:\n${read()}`)
}

/** @param {any} t */
async function testnet (t) {
  const createTestnet = require('hyperdht/testnet')
  const net = await createTestnet(5)
  t.after(() => net.destroy())
  return { ...process.env, ADHAL_BOOTSTRAP: JSON.stringify(net.bootstrap), ADHAL_JOIN_TIMEOUT: '30000' }
}

/** Pairing on a testnet can lose a race (docs/history/WORK-RECORD.md, W17): a few tries. */
async function attempts (/** @type {() => Promise<void>} */ fn, n = 3) {
  for (let i = 1; ; i++) {
    try {
      return await fn()
    } catch (err) {
      if (i === n) throw err
    }
  }
}

test('--stdout --json: stdout is exactly the file, stderr is exactly the events, and both sides end in done', slow, async (t) => {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'adhal-json-'))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const whole = crypto.randomBytes(2 * 1024 * 1024)
  const source = path.join(dir, 'archive.tar')
  await fs.promises.writeFile(source, whole)
  const sha = crypto.createHash('sha256').update(whole).digest('hex')

  await attempts(async () => {
    const env = await testnet(t)
    const code = require('@ad-hal/engine').generateCode()
    const rx = run(RECEIVE, ['-', '--stdout', '--json', '--yes'], env, `${code}\n`)
    try {
      await waitForEvent(rx.stderr, 'announced')
      const tx = run(SEND, ['-', source, '--json'], env, `${code}\n`)
      const [rxCode, txCode] = await Promise.all([rx.exited, tx.exited])

      const rxEvents = eventsIn(rx.stderr())
      const txEvents = eventsIn(tx.stdout().toString('utf8'))
      assert.equal(rxCode, 0, rx.stderr())
      assert.equal(txCode, 0, tx.stdout().toString('utf8'))
      assert.equal(tx.stderr(), '', 'the sender writes nothing outside the event stream')

      // The file, byte for byte, and nothing else on stdout.
      assert.ok(rx.stdout().equals(whole), 'stdout is the file')

      for (const [events, role] of /** @type {Array<[any[], string]>} */ ([[rxEvents, 'receive'], [txEvents, 'send']])) {
        assert.ok(events.every((e) => e.role === role))
        assert.equal(events[0].event, 'start')
        assert.equal(events.filter((e) => e.event === 'done' || e.event === 'failed').length, 1, 'exactly one final event')
        assert.equal(events.at(-1).event, 'done', 'and it is last')
        assert.equal(events.at(-1).sha256, sha)
        assert.ok(events.some((e) => e.event === 'warning' && e.kind === 'not-anonymous'))
        assert.ok(events.findIndex((e) => e.event === 'paired') < events.findIndex((e) => e.event === 'accepted'))
        const firstProgress = events.findIndex((e) => e.event === 'progress')
        assert.ok(firstProgress === -1 || firstProgress > events.findIndex((e) => e.event === 'accepted'), 'no progress before accepted')
        const ms = events.map((e) => e.ms)
        assert.deepEqual(ms, [...ms].sort((a, b) => a - b), 'ms never goes backwards')
      }
      const done = rxEvents.at(-1)
      assert.equal(done.path, null)
      assert.equal(done.acknowledged, true)
      assert.equal(rxEvents.find((e) => e.event === 'start').stdout, true)
      assert.equal(rxEvents.find((e) => e.event === 'offer').name, 'archive.tar')
      // An explicit code, so no code event: the secret is not repeated.
      assert.equal(rxEvents.some((e) => e.event === 'code'), false)
    } finally {
      if (rx.child.exitCode === null) rx.child.kill()
    }
  })
})

test('--json without --yes declines the offer, and both sides fail with ERR_DECLINED', slow, async (t) => {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'adhal-json-'))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const source = path.join(dir, 'a.txt')
  await fs.promises.writeFile(source, 'hello')

  await attempts(async () => {
    const env = await testnet(t)
    const code = require('@ad-hal/engine').generateCode()
    const rx = run(RECEIVE, ['-', path.join(dir, 'out'), '--json'], env, `${code}\n`)
    try {
      await waitForEvent(() => rx.stdout().toString('utf8'), 'announced')
      const tx = run(SEND, ['-', source, '--json'], env, `${code}\n`)
      const [rxCode, txCode] = await Promise.all([rx.exited, tx.exited])
      const rxEvents = eventsIn(rx.stdout().toString('utf8'))
      const txEvents = eventsIn(tx.stdout().toString('utf8'))
      assert.equal(rxCode, 1)
      assert.equal(txCode, 1)
      assert.equal(rxEvents.at(-1).event, 'failed')
      assert.equal(rxEvents.at(-1).code, 'ERR_DECLINED')
      assert.ok(rxEvents.some((e) => e.event === 'offer'), 'what was declined is reported')
      assert.equal(txEvents.at(-1).code, 'ERR_DECLINED')
      assert.equal(txEvents.at(-1).declineCode, 'ERR_DECLINED')
      assert.equal(fs.existsSync(path.join(dir, 'out', 'a.txt')), false)
    } finally {
      if (rx.child.exitCode === null) rx.child.kill()
    }
  })
})

test('a generated code is reported in a code event after announced', slow, async (t) => {
  const env = await testnet(t)
  const rx = run(RECEIVE, ['--json', '--stdout'], env, null)
  try {
    await waitForEvent(rx.stderr, 'code')
    const events = eventsIn(rx.stderr())
    const at = (/** @type {string} */ name) => events.findIndex((e) => e.event === name)
    assert.ok(at('announced') < at('code'))
    assert.match(events[at('code')].payload, /^ADHAL2:/)
  } finally {
    rx.child.kill('SIGINT')
    await rx.exited
  }
  const events = eventsIn(rx.stderr())
  assert.equal(events.at(-1).event, 'failed')
  assert.equal(events.at(-1).code, 'ABORT_ERR')
})

test('usage errors under --json are a failed event with a CLI-level code', slow, async () => {
  const bad = run(RECEIVE, ['--json', '--no-such-flag'], process.env, null)
  assert.equal(await bad.exited, 1)
  const [failed] = eventsIn(bad.stdout().toString('utf8'))
  assert.equal(failed.code, 'ERR_USAGE')

  // One positional is the code; the second is the directory --stdout replaces.
  const both = run(RECEIVE, ['-', 'somewhere', '--json', '--stdout'], process.env, null)
  assert.equal(await both.exited, 1)
  assert.equal(eventsIn(both.stderr())[0].code, 'ERR_USAGE', '--stdout puts the events on stderr, even for this')

  const word = run(SEND, ['-', __filename, '--json'], process.env, 'not-a-real-code-at-all\n')
  assert.equal(await word.exited, 1)
  assert.equal(eventsIn(word.stdout().toString('utf8'))[0].code, 'ERR_CODE_INVALID')
})

test('--stdout whose reader goes away: ERR_OUTPUT_CLOSED, exit 1, and the sender hears why', slow, async (t) => {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'adhal-json-'))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const source = path.join(dir, 'big.bin')
  await fs.promises.writeFile(source, crypto.randomBytes(32 * 1024 * 1024))

  await attempts(async () => {
    const env = await testnet(t)
    const code = require('@ad-hal/engine').generateCode()
    const rx = run(RECEIVE, ['-', '--stdout', '--json', '--yes'], env, `${code}\n`)
    // `| head -c 1`: the first bytes, then the read end is closed.
    rx.child.stdout.once('data', () => rx.child.stdout.destroy())
    try {
      await waitForEvent(rx.stderr, 'announced')
      const tx = run(SEND, ['-', source, '--json'], env, `${code}\n`)
      const [rxCode, txCode] = await Promise.all([rx.exited, tx.exited])
      const rxLast = eventsIn(rx.stderr()).at(-1)
      const txLast = eventsIn(tx.stdout().toString('utf8')).at(-1)
      assert.equal(rxCode, 1, rx.stderr())
      assert.equal(rxLast.code, 'ERR_OUTPUT_CLOSED')
      assert.equal(typeof rxLast.bytes, 'number')
      assert.equal(txCode, 1)
      assert.equal(txLast.code, 'ERR_CANCELLED_PEER')
      assert.equal(txLast.peerReason, "the receiver's output was closed")
    } finally {
      if (rx.child.exitCode === null) rx.child.kill()
    }
  })
})

test('--stdout without --json: the human lines move to stderr, and stdout is the file', slow, async (t) => {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'adhal-json-'))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const whole = crypto.randomBytes(512 * 1024)
  const source = path.join(dir, 'a.bin')
  await fs.promises.writeFile(source, whole)

  await attempts(async () => {
    const env = await testnet(t)
    const code = require('@ad-hal/engine').generateCode()
    const rx = run(RECEIVE, ['-', '--stdout', '--yes'], env, `${code}\n`)
    try {
      const start = Date.now()
      while (!/waiting for a peer/.test(rx.stderr())) {
        if (Date.now() - start > 20000) throw new Error(`never announced:\n${rx.stderr()}`)
        await new Promise((resolve) => setTimeout(resolve, 20))
      }
      const tx = run(SEND, ['-', source], env, `${code}\n`)
      const [rxCode, txCode] = await Promise.all([rx.exited, tx.exited])
      assert.equal(rxCode, 0, rx.stderr())
      assert.equal(txCode, 0)
      assert.ok(rx.stdout().equals(whole), 'stdout is the file and nothing else')
      assert.match(rx.stderr(), /^\[swarm-receive\] written to stdout$/m)
      assert.match(rx.stderr(), /^\[swarm-receive\] verified: /m)
    } finally {
      if (rx.child.exitCode === null) rx.child.kill()
    }
  })
})

test('a warning raised while the code is read comes after start, not before it', slow, async () => {
  // Found on the first real two-machine run (2026-10-29): with
  // --code-on-argv, the code-on-argv warning was the first line. Nothing
  // answers at this bootstrap, so the drop ends in ERR_NO_PEER quickly.
  const env = { ...process.env, ADHAL_BOOTSTRAP: '[{"host":"127.0.0.1","port":9}]', ADHAL_JOIN_TIMEOUT: '1500' }
  const code = require('@ad-hal/engine').generateCode()
  const tx = run(SEND, [code, __filename, '--code-on-argv', '--json'], env, null)
  assert.equal(await tx.exited, 1)
  const events = eventsIn(tx.stdout().toString('utf8'))
  assert.equal(events[0].event, 'start')
  const argvWarning = events.findIndex((e) => e.event === 'warning' && e.kind === 'code-on-argv')
  assert.ok(argvWarning > 0, 'the warning is still reported')
  assert.equal(events.at(-1).event, 'failed')
})
