'use strict'

// tools/cli-trials.js, the CLI trials driver, and the code it shares with
// engine/scratch-trials.js.
//
// THE THING TO PROTECT IS THE READING. A harness that miscounts makes a
// broken path look fine or a fine one look broken, and a rate is all
// anyone reads of it. So the fast tests pin how a run's events and exit
// status become an outcome, including the cases that should be loud: a
// done whose bytes this harness hashed differently, and a run that broke
// the event contract. The slow test runs both roles against a local
// testnet, in both receive modes.

const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('node:path')
const os = require('node:os')
const fs = require('node:fs')
const crypto = require('node:crypto')
const { spawn } = require('node:child_process')

const { trialCode, wilson, startMsFor, OUTCOME_BY_CODE } = require('../../engine/scratch-trials-shared')
const { parseArgs, eventReader, readRun, trialRecord, summarise, pathInfo } = require('../../tools/cli-trials')
const { resolveCode } = require('@ad-hal/engine')
const { slow } = require('../test-helpers/tiers')

const DRIVER = path.resolve(__dirname, '..', '..', 'tools', 'cli-trials.js')

// --- the shared code -----------------------------------------------------

test('trial codes are the ones scratch-trials.js has always derived, and real five-word codes', () => {
  // Pinned from scratch-trials.js before the derivation moved into
  // scratch-trials-shared.js (2026-10-31): a change here would make new
  // runs incomparable with every run already recorded under a seed.
  assert.equal(trialCode('run1', 0), 'genre-deletion-paradox-olive-sister')
  assert.equal(trialCode('run1', 1), 'guise-security-tricycle-sponsor-cake')
  assert.notEqual(trialCode('run1', 0), trialCode('run2', 0))
  for (let i = 0; i < 20; i++) {
    const resolved = resolveCode(trialCode('w14', i))
    assert.equal(resolved.kind, 'words', 'not an opaque code: that would measure a path no user takes')
  }
})

test('the Wilson interval matches known values, and never leaves 0..1', () => {
  // 3 of 3 and 0 of 1 are what the dry runs printed; 8 of 10 is a
  // textbook case (0.490..0.943).
  const close = (/** @type {number} */ a, /** @type {number} */ b) => assert.ok(Math.abs(a - b) < 0.001, `${a} vs ${b}`)
  const three = /** @type {any} */ (wilson(3, 3))
  close(three.low, 0.4385)
  close(three.high, 1)
  const eight = /** @type {any} */ (wilson(8, 10))
  close(eight.low, 0.4902)
  close(eight.high, 0.9433)
  const none = /** @type {any} */ (wilson(0, 1))
  close(none.low, 0)
  close(none.high, 0.7935)
  assert.equal(wilson(0, 0), null)
})

test('the default first slot is a 5-minute boundary at least a minute out', () => {
  const now = Date.UTC(2026, 9, 31, 12, 3, 30)
  assert.equal(startMsFor(undefined, now), Date.UTC(2026, 9, 31, 12, 5, 0))
  assert.equal(startMsFor(undefined, Date.UTC(2026, 9, 31, 12, 4, 30)), Date.UTC(2026, 9, 31, 12, 10, 0))
  assert.equal(startMsFor('1793493687', now), 1793493687000)
})

// --- arguments -------------------------------------------------------------

test('arguments: the sender needs a file, and a slot must leave the sender time', () => {
  assert.throws(() => parseArgs(['--role', 'sender', '--seed', 's']), /--file/)
  assert.throws(() => parseArgs(['--role', 'nobody', '--seed', 's']), /--role/)
  assert.throws(() => parseArgs(['--role', 'receiver']), /--seed/)
  assert.throws(() => parseArgs(['--role', 'receiver', '--seed', 's', '--mode', 'pipe']), /--mode/)
  assert.throws(() => parseArgs(['--role', 'receiver', '--seed', 's', '--slot', '15']), /under 5 s/)
  const opts = parseArgs(['--role', 'receiver', '--seed', 's', '--note', 'eero, IPv6 off', '--note', 'second'])
  assert.equal(opts.slotSeconds, 135)
  assert.equal(opts.leadMs, 10000)
  assert.equal(opts.mode, 'dir')
  assert.deepEqual(opts.notes, ['eero, IPv6 off', 'second'])
})

// --- reading a stream ------------------------------------------------------

test('events are split from other lines, across chunk boundaries', () => {
  const r = eventReader()
  const a = JSON.stringify({ v: 1, event: 'start', ms: 1, role: 'send' })
  const b = JSON.stringify({ v: 1, event: 'done', ms: 2, role: 'send' })
  r.push(Buffer.from(`${a.slice(0, 10)}`))
  r.push(Buffer.from(`${a.slice(10)}\n(node:123) Warning: something\n{"not":"an event"}\n${b}`))
  r.end()
  assert.deepEqual(r.events.map((e) => e.event), ['start', 'done'])
  assert.deepEqual(r.other, ['(node:123) Warning: something', '{"not":"an event"}'])
})

// --- reading a run -----------------------------------------------------------

const ev = (/** @type {string} */ event, /** @type {Record<string, any>} */ fields = {}, ms = 0) => ({ v: 1, event, ms, role: 'receive', ...fields })
const goodRun = (/** @type {Record<string, any>} */ done = {}) => [
  ev('start'), ev('announced', {}, 5), ev('candidate', { peer: 'a' }, 100), ev('paired', { peer: 'a' }, 200),
  ev('accepted', { resumeFrom: 0 }, 300), ev('done', { sha256: 'aa', size: 10, acknowledged: true, ...done }, 900)
]

test('a done with exit 0 is ok, and its timings are read from the events', () => {
  const read = readRun({ events: goodRun(), status: 0, killed: false }, { independentSha256: 'aa' })
  assert.equal(read.outcome, 'ok')
  assert.deepEqual(read.contract, [])
  assert.equal(read.pairedMs, 200)
  assert.equal(read.acceptedMs, 300)
  assert.equal(read.finalMs, 900)
})

test('a done whose bytes this harness hashed differently is the loudest outcome there is', () => {
  const read = readRun({ events: goodRun(), status: 0, killed: false }, { independentSha256: 'bb' })
  assert.equal(read.outcome, 'hash-crosscheck-disagreed')
  const { lines, summary } = summarise([{ trial: 0, outcome: read.outcome, contract: [] }], { role: 'receiver', seed: 's' })
  assert.deepEqual(summary.crossCheckDisagreed, [0])
  assert.ok(lines.some((l) => /THIS HARNESS HASHED SOMETHING ELSE/.test(l)))
})

test('failures are bucketed by code, never by message, with the CLI-level codes beside the engine\'s', () => {
  const failed = (/** @type {string} */ code) => readRun({
    events: [ev('start'), ev('failed', { code, message: 'ERR_HASH_MISMATCH would be a lie here', bytes: 0 })],
    status: 1,
    killed: false
  }).outcome
  assert.equal(failed('ERR_NO_PEER'), 'no-peer')
  assert.equal(failed('ERR_CANCELLED_PEER'), 'cancelled-by-peer')
  assert.equal(failed('ERR_OUTPUT_CLOSED'), 'output-closed')
  assert.equal(failed('ENOSPC'), 'transfer-error')
  // Every engine code has a bucket of its own.
  for (const code of Object.keys(OUTCOME_BY_CODE)) assert.equal(failed(code), OUTCOME_BY_CODE[code])
})

test('a run the harness had to stop is killed-at-slot-end, not a cancel by a person', () => {
  const stopped = readRun({ events: [ev('start'), ev('failed', { code: 'ABORT_ERR', bytes: 0 })], status: 130, killed: true })
  assert.equal(stopped.outcome, 'killed-at-slot-end')
  assert.equal(readRun({ events: [ev('start')], status: null, killed: true }).outcome, 'killed-at-slot-end')
  assert.equal(readRun({ events: [ev('start')], status: 1, killed: false }).outcome, 'no-final-event')
})

test('a run that breaks the event contract is flagged, whatever its outcome', () => {
  const withStatus = (/** @type {any[]} */ events, /** @type {number} */ status) => readRun({ events, status, killed: false }).contract
  assert.match(withStatus(goodRun(), 1).join(), /done, but the exit status is 1/)
  assert.match(withStatus([ev('start'), ev('failed', { code: 'ERR_NO_PEER' })], 0).join(), /failed, but the exit status is 0/)
  assert.match(withStatus([ev('warning', { kind: 'code-on-argv' }), ...goodRun()], 0).join(), /first event is warning/)
  assert.match(withStatus([...goodRun(), ev('progress', { bytes: 1 })], 0).join(), /not the last line/)
  assert.match(withStatus([...goodRun(), ev('failed', { code: 'ERR_PROTOCOL' })], 1).join(), /2 final events/)
  // A usage error is the only event, and that is allowed.
  assert.deepEqual(withStatus([ev('failed', { code: 'ERR_USAGE' })], 1), [])
})

test('a final event\'s connection counters become the trial\'s path, in its log line and its summary', () => {
  const connection = { remoteKind: 'public', rttMs: 48, mtu: 1200, retransmits: 3, rtoCount: 1, fastRecoveries: 0, inflight: 0, packetsSent: 9, packetsReceived: 8, bytesSent: 10, bytesReceived: 7 }
  const run = { status: 0, signal: null, killed: false, spawnedAtEpochMs: 1000, endedAtEpochMs: 2000, otherLines: [] }
  const withPath = trialRecord(0, { ...run, events: goodRun({ connection }) }, readRun({ events: goodRun({ connection }), status: 0, killed: false }), 1000, {})
  assert.deepEqual(withPath.path, connection)
  assert.equal(pathInfo(withPath.path), ' path=public rtt=48ms retx=3 rto=1')
  assert.equal(pathInfo({ ...connection, inflight: 262144 }), ' path=public rtt=48ms retx=3 rto=1 inflight=262144', 'data never acked is called out')

  // A CLI from before the counters, and a failure before pairing: no path.
  const without = trialRecord(1, { ...run, events: goodRun() }, readRun({ events: goodRun(), status: 0, killed: false }), 1000, {})
  assert.equal(without.path, null)
  assert.equal(pathInfo(without.path), '')

  const { lines } = summarise([
    { trial: 0, outcome: 'ok', contract: [], path: connection },
    { trial: 1, outcome: 'ok', contract: [], path: { ...connection, remoteKind: 'private' } },
    { trial: 2, outcome: 'no-peer', contract: [], path: null }
  ], { role: 'receiver', seed: 's' })
  assert.ok(lines.some((l) => /^peer address: public 1, private 1 +\(private = same LAN/.test(l)), lines.join('\n'))
})

test('a no-peer whose hole punches hyperdht refused is said to need a relay', () => {
  const events = [ev('start'), ev('failed', { code: 'ERR_NO_PEER', message: 'x', bytes: null, holepunchRefused: 4 })]
  const read = readRun({ events, status: 1, killed: false })
  assert.equal(read.outcome, 'no-peer', 'still a no-peer: the bucket is the code')
  const run = { status: 1, signal: null, killed: false, spawnedAtEpochMs: 1000, endedAtEpochMs: 2000, otherLines: [], events }
  const record = trialRecord(0, run, read, 1000, {})
  assert.equal(record.holepunchRefused, 4)
  const { lines, summary } = summarise([{ ...record, contract: [] }], { role: 'sender', seed: 's' })
  assert.deepEqual(summary.holepunchRefused, [0])
  assert.ok(lines.some((l) => /both NATs randomized; only a relay connects/.test(l)), lines.join('\n'))
})

test('the summary counts skipped slots apart, and says when a rate cannot be called', () => {
  const results = [
    { trial: 0, outcome: 'ok', connectedMs: 1000, completedMs: 3000, transferMs: 2000, contract: [] },
    { trial: 1, outcome: 'no-peer', contract: [] },
    { trial: 2, outcome: 'skipped' }
  ]
  const { lines, summary } = summarise(results, { role: 'sender', seed: 's' })
  assert.equal(summary.trials, 2)
  assert.equal(summary.skipped, 1)
  assert.equal(summary.succeeded, 1)
  assert.deepEqual(summary.failures, { 'no-peer': 1 })
  assert.ok(lines.some((l) => /Too few trials/.test(l)))
})

// --- end to end ------------------------------------------------------------

/**
 * @param {string[]} args
 * @param {Record<string, string | undefined>} env
 */
function driver (args, env) {
  const child = spawn(process.execPath, [DRIVER, ...args], { env })
  let out = ''
  child.stdout.on('data', (c) => { out += c })
  child.stderr.on('data', (c) => { out += c })
  return new Promise((resolve) => child.on('exit', (code) => resolve({ code, out })))
}

test('two drivers against a testnet agree on every trial, in both receive modes', { ...slow, timeout: 240000 }, async (t) => {
  const createTestnet = require('hyperdht/testnet')
  const net = await createTestnet(5)
  t.after(() => net.destroy())
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'adhal-cli-trials-'))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const file = path.join(dir, 'src.bin')
  const bytes = crypto.randomBytes(512 * 1024)
  await fs.promises.writeFile(file, bytes)
  const sha = crypto.createHash('sha256').update(bytes).digest('hex')
  const env = { ...process.env, ADHAL_BOOTSTRAP: JSON.stringify(net.bootstrap) }

  for (const mode of ['dir', 'stdout']) {
    const start = Math.floor(Date.now() / 1000) + 4
    const common = ['--seed', `test-${mode}-${start}`, '--trials', '2', '--slot', '20', '--lead', '3', '--start-epoch', String(start), '--no-environment']
    const rxOut = path.join(dir, `rx-${mode}.json`)
    const txOut = path.join(dir, `tx-${mode}.json`)
    const [rx, tx] = await Promise.all([
      driver(['--role', 'receiver', ...common, '--mode', mode, '--out', rxOut], env),
      driver(['--role', 'sender', ...common, '--file', file, '--out', txOut], env)
    ])
    assert.equal(/** @type {any} */ (rx).code, 0, /** @type {any} */ (rx).out)
    assert.equal(/** @type {any} */ (tx).code, 0, /** @type {any} */ (tx).out)
    const rxJson = JSON.parse(fs.readFileSync(rxOut, 'utf8'))
    const txJson = JSON.parse(fs.readFileSync(txOut, 'utf8'))
    assert.equal(rxJson.tool, 'cli-trials')
    assert.equal(rxJson.mode, mode)
    assert.equal(rxJson.environment, null, 'skipped, so null: what the environment generator reads as not recorded')
    for (const r of [...rxJson.results, ...txJson.results]) {
      assert.equal(r.outcome, 'ok', JSON.stringify(r))
      assert.equal(r.exit, 0)
      assert.equal(r.sha256, sha)
      assert.deepEqual(r.contract, [])
      assert.ok(r.connectedMs >= 0 && r.completedMs >= r.connectedMs)
      assert.ok(r.path && r.path.packetsReceived > 0, `the transport counters are recorded: ${JSON.stringify(r.path)}`)
    }
    for (const r of rxJson.results) {
      assert.equal(r.independentSha256, sha, 'this harness hashed the bytes itself')
      assert.equal(r.acknowledged, true)
      if (mode === 'stdout') assert.equal(r.stdoutBytes, bytes.length)
    }
    assert.equal(txJson.file.sha256, sha)
    assert.equal(rxJson.summary.succeeded, 2)
    assert.equal(txJson.summary.succeeded, 2)
  }
})

test('a sender that finds nobody ends in its own ERR_NO_PEER, not stopped by the harness', { ...slow, timeout: 120000 }, async (t) => {
  // The first dry run (2026-10-31): the harness stopped the CLI at the very
  // moment its join timeout was due, and recorded the trial as stopped.
  const createTestnet = require('hyperdht/testnet')
  const net = await createTestnet(3)
  t.after(() => net.destroy())
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'adhal-cli-trials-'))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const file = path.join(dir, 'src.bin')
  await fs.promises.writeFile(file, crypto.randomBytes(1024))
  const start = Math.floor(Date.now() / 1000) + 3
  const out = path.join(dir, 'tx.json')
  const run = /** @type {any} */ (await driver(['--role', 'sender', '--seed', `alone-${start}`, '--trials', '1', '--slot', '20', '--lead', '3',
    '--start-epoch', String(start), '--no-environment', '--file', file, '--out', out], { ...process.env, ADHAL_BOOTSTRAP: JSON.stringify(net.bootstrap) }))
  assert.equal(run.code, 0, run.out)
  const [r] = JSON.parse(fs.readFileSync(out, 'utf8')).results
  assert.equal(r.outcome, 'no-peer', JSON.stringify(r))
  assert.equal(r.killed, false)
  assert.equal(r.exit, 1)
  assert.equal(r.path, null, 'nobody paired, so no connection to report')
})
