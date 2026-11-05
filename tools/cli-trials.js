#!/usr/bin/env node
'use strict'

// Repeated real drops through the CLIs, not the engine: the measured
// version of the W13 smoke tests, and the Adhal half of W14.
//
// WHY A SECOND HARNESS. engine/scratch-trials.js calls acceptOnce and
// sendFile directly, so it measures the engine and never runs what a user
// runs. W14 compares Adhal with other tools, and every other tool can only
// be driven through its CLI. Driving Adhal the same way -- spawn the
// command, give it the code, read what it reports, take its exit status --
// is what makes the comparison like for like. W13's --json is what lets it
// read the outcome without matching prose (docs/CLI-CONTRACT.md).
//
// Usage, on the two real machines, with the same --seed and --trials:
//
//   # receiver
//   node tools/cli-trials.js --role receiver --seed w14-a --trials 20 --out ~/rx.json
//
//   # sender, started within a few minutes of the receiver
//   head -c 10485760 /dev/urandom > /tmp/test.bin
//   node tools/cli-trials.js --role sender --seed w14-a --trials 20 --file /tmp/test.bin --out ~/tx.json
//
// It keeps the two constraints scratch-trials.js documents, through the
// code they share (engine/scratch-trials-shared.js): each trial's code is a
// real five-word code derived from (seed, trial), so the two machines agree
// without talking, and trials are pinned to wall-clock slots, so a fast
// failure on one side cannot put the two on different trials.
//
// Options:
//   --mode dir|stdout      receiver only: land the file in a temporary
//                          directory (default), or take it on stdout with
//                          --stdout. Either way this harness hashes what it
//                          got, independently of the CLI's own check.
//   --slot <s>             seconds per trial (default 135; see below)
//   --start-epoch <s>      pin the first slot; default the next 5-minute
//                          boundary at least a minute out
//   --receiver-timeout <ms>  the receiver's ADHAL_JOIN_TIMEOUT. Default: the
//                          rest of its slot, as scratch-trials.js gives its
//                          receiver. 30000 measures the CLI's own default.
//   --refresh <ms>         ADHAL_REFRESH_INTERVAL for both CLIs
//   --out <path>           per-trial JSON, rewritten after every trial
//   --note <text>          repeatable; what the machine cannot detect
//   --lookup-isp, --record-addresses   passed to the environment probe
//   --no-environment       skip the probe (tests; it uses the public DHT)
//   --lead <s>             the sender's start within its slot (default 10).
//                          For tests only: changing it changes what is measured.
//
// The default 135 s slot gives the sender 135 - 10 - 5 = 120 s, the CLI's own
// join timeout, which is what scratch-trials.js chose for the same reason.
//
// ADHAL_BOOTSTRAP is passed through to the CLIs, which is how the tests run
// this on a local testnet. A real run leaves it unset.

const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const crypto = require('node:crypto')
const { spawn, execFileSync } = require('node:child_process')
const {
  trialCode,
  SENDER_LEAD_MS,
  TEARDOWN_MS,
  startMsFor,
  OUTCOME_BY_CODE,
  percentile,
  wilson
} = require('../engine/scratch-trials-shared')

const REPO_ROOT = path.resolve(__dirname, '..')
const RECEIVE = path.join(REPO_ROOT, 'cli', 'src', 'swarm-receive.js')
const SEND = path.join(REPO_ROOT, 'cli', 'src', 'swarm-send.js')
const PROBE = path.join(REPO_ROOT, 'engine', 'scratch-trials.js')

// A CLI still running at the end of its budget is asked to stop the way a
// person would, so it sends CANCEL and the peer reports a cancel rather
// than a dead connection. This long later it is killed.
const KILL_GRACE_MS = 3000

// THE CLI'S OWN TIMEOUT MUST FIRE FIRST. Each CLI is given its budget as
// ADHAL_JOIN_TIMEOUT, but its timer starts only once Node has loaded it,
// so a stop at the budget's end beat it, and a trial that found nobody
// was recorded as stopped instead of ERR_NO_PEER (found in the first dry
// run). The stop comes this long after the budget, inside the teardown,
// and still KILL_GRACE_MS before the next slot.
const STOP_AFTER_BUDGET_MS = TEARDOWN_MS - KILL_GRACE_MS - 500

// The CLI-level codes (CLI-CONTRACT.md section 4), in the same lowercase
// shape as the engine's buckets in OUTCOME_BY_CODE.
const CLI_OUTCOMES = {
  ERR_OUTPUT_CLOSED: 'output-closed',
  ERR_USAGE: 'usage-error',
  ERR_CODE_INVALID: 'code-invalid'
}

// Lines that are not events are kept for the record, but only this many:
// a CLI that prints a warning per chunk must not grow the JSON unbounded.
const MAX_OTHER_LINES = 20

// --- arguments ---------------------------------------------------------------

/**
 * @param {string[]} argv
 */
function parseArgs (argv) {
  /** @param {string} name */
  const value = (name) => {
    const i = argv.indexOf(`--${name}`)
    return i === -1 ? undefined : argv[i + 1]
  }
  const num = (/** @type {string} */ name, /** @type {number | undefined} */ fallback) => {
    const raw = value(name)
    if (raw === undefined) return fallback
    const n = Number(raw)
    if (!Number.isFinite(n) || n < 0) throw new Error(`--${name} must be a non-negative number, got ${raw}`)
    return n
  }
  const opts = {
    role: value('role'),
    seed: value('seed'),
    trials: num('trials', 10),
    file: value('file'),
    mode: value('mode') ?? 'dir',
    slotSeconds: num('slot', 135),
    startEpoch: value('start-epoch'),
    receiverTimeoutMs: num('receiver-timeout', undefined),
    refreshMs: num('refresh', undefined),
    out: value('out'),
    notes: argv.flatMap((a, i) => a === '--note' && argv[i + 1] !== undefined ? [argv[i + 1]] : []),
    lookupIsp: argv.includes('--lookup-isp'),
    recordAddresses: argv.includes('--record-addresses'),
    environment: !argv.includes('--no-environment'),
    leadMs: num('lead', SENDER_LEAD_MS / 1000) * 1000
  }
  if (opts.role !== 'receiver' && opts.role !== 'sender') throw new Error('--role must be receiver or sender')
  if (!opts.seed) throw new Error('--seed is required, and must match on both machines')
  if (!Number.isInteger(opts.trials) || opts.trials < 1) throw new Error('--trials must be a whole number, at least 1')
  if (opts.role === 'sender' && !opts.file) throw new Error('the sender needs --file')
  if (opts.mode !== 'dir' && opts.mode !== 'stdout') throw new Error('--mode must be dir or stdout')
  if (opts.slotSeconds * 1000 <= opts.leadMs + TEARDOWN_MS + 5000) {
    throw new Error(`--slot ${opts.slotSeconds} leaves the sender under 5 s after its ${opts.leadMs / 1000} s lead and the ${TEARDOWN_MS / 1000} s teardown`)
  }
  return opts
}

// --- one CLI run ---------------------------------------------------------------

/**
 * Splits a stream into lines, and each line into an event or not. An event
 * is a JSON object with `v` and `event`; anything else -- a Node warning, a
 * prompt -- is kept separately, as CLI-CONTRACT.md section 3 says a
 * consumer must expect.
 */
function eventReader () {
  let partial = ''
  /** @type {any[]} */
  const events = []
  /** @type {string[]} */
  const other = []
  /** @param {string} line */
  const take = (line) => {
    if (line.length === 0) return
    try {
      const parsed = JSON.parse(line)
      if (parsed && typeof parsed === 'object' && parsed.v !== undefined && typeof parsed.event === 'string') {
        events.push(parsed)
        return
      }
    } catch {}
    if (other.length < MAX_OTHER_LINES) other.push(line)
  }
  return {
    events,
    other,
    /** @param {Buffer} chunk */
    push (chunk) {
      partial += chunk.toString('utf8')
      const lines = partial.split('\n')
      partial = /** @type {string} */ (lines.pop())
      for (const line of lines) take(line)
    },
    end () {
      take(partial)
      partial = ''
    }
  }
}

/**
 * Runs one CLI to its end or its deadline.
 *
 * @param {{
 *   script: string,
 *   args: string[],
 *   code: string,
 *   env: Record<string, string | undefined>,
 *   deadlineMs: number,
 *   eventsOn: 'stdout' | 'stderr',
 *   hashStdout?: boolean
 * }} options
 *   `deadlineMs` is a wall-clock time. `hashStdout` hashes stdout as the
 *   file's bytes, for a receiver run with --stdout.
 */
function runCli ({ script, args, code, env, deadlineMs, eventsOn, hashStdout = false }) {
  return new Promise((resolve) => {
    const spawnedAtEpochMs = Date.now()
    const child = spawn(process.execPath, [script, ...args], { env, stdio: ['pipe', 'pipe', 'pipe'] })
    const reader = eventReader()
    const hash = hashStdout ? crypto.createHash('sha256') : null
    let stdoutBytes = 0
    let killed = false

    const eventStream = eventsOn === 'stdout' ? child.stdout : child.stderr
    eventStream.on('data', (chunk) => reader.push(chunk))
    if (hash) {
      child.stdout.on('data', (chunk) => {
        hash.update(chunk)
        stdoutBytes += chunk.length
      })
    } else if (eventsOn === 'stderr') {
      child.stdout.resume()
    }
    if (eventsOn === 'stdout') child.stderr.on('data', (chunk) => reader.push(chunk))

    // The code on stdin, the way the smoke tests gave it, so it never
    // reaches argv.
    child.stdin.on('error', () => {})
    child.stdin.end(`${code}\n`)

    /** @type {NodeJS.Timeout | null} */
    let killTimer = null
    const stopTimer = setTimeout(() => {
      killed = true
      child.kill('SIGINT')
      killTimer = setTimeout(() => child.kill('SIGKILL'), KILL_GRACE_MS)
    }, Math.max(0, deadlineMs - Date.now()))

    child.on('close', (status, signal) => {
      clearTimeout(stopTimer)
      if (killTimer) clearTimeout(killTimer)
      reader.end()
      resolve({
        spawnedAtEpochMs,
        endedAtEpochMs: Date.now(),
        status,
        signal,
        killed,
        events: reader.events,
        otherLines: reader.other,
        stdoutSha256: hash ? hash.digest('hex') : null,
        stdoutBytes: hash ? stdoutBytes : null
      })
    })
  })
}

/** @param {string} file */
function sha256File (file) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256')
    fs.createReadStream(file)
      .on('data', (chunk) => hash.update(chunk))
      .on('end', () => resolve(hash.digest('hex')))
      .on('error', reject)
  })
}

// --- reading a run -------------------------------------------------------------

/**
 * What a run's events and exit status say happened. Pure, so the tests can
 * hand it events without running anything.
 *
 * @param {{ events: any[], status: number | null, killed: boolean }} run
 * @param {{ independentSha256?: string | null }} [check]
 *   `independentSha256` is what this harness hashed itself: the landed
 *   file, stdout, or the sender's source. Compared with the final event's.
 */
function readRun ({ events, status, killed }, { independentSha256 = null } = {}) {
  const finals = events.filter((e) => e.event === 'done' || e.event === 'failed')
  const final = finals.length ? finals[finals.length - 1] : null
  /** @type {string[]} */
  const contract = []
  if (finals.length > 1) contract.push(`${finals.length} final events, where the contract allows one`)
  if (final && events[events.length - 1] !== final) contract.push('the final event is not the last line')
  if (events.length && events[0].event !== 'start' && !(events.length === 1 && final)) contract.push(`the first event is ${events[0].event}, not start`)
  if (final && final.event === 'done' && status !== 0 && !killed) contract.push(`done, but the exit status is ${status}`)
  if (final && final.event === 'failed' && status === 0) contract.push('failed, but the exit status is 0')

  /** @type {string} */
  let outcome
  if (!final) {
    outcome = killed ? 'killed-at-slot-end' : 'no-final-event'
  } else if (killed && final.event === 'failed' && final.code === 'ABORT_ERR') {
    // The cancel this harness asked for, not one a person made.
    outcome = 'killed-at-slot-end'
  } else if (final.event === 'done') {
    outcome = independentSha256 && independentSha256 !== final.sha256 ? 'hash-crosscheck-disagreed' : 'ok'
  } else {
    outcome = OUTCOME_BY_CODE[final.code] ?? CLI_OUTCOMES[final.code] ?? 'transfer-error'
  }

  const at = (/** @type {string} */ name) => {
    const e = events.find((x) => x.event === name)
    return e ? e.ms : null
  }
  const dropped = events.filter((e) => e.event === 'candidate-dropped')
  return {
    outcome,
    code: final && final.event === 'failed' ? final.code : null,
    contract,
    pairedMs: at('paired'),
    acceptedMs: at('accepted'),
    finalMs: final ? final.ms : null,
    final,
    candidates: events.filter((e) => e.event === 'candidate').length,
    dropped: dropped.map((e) => ({ code: e.code, counted: e.counted, paired: e.paired })),
    badConfirmations: dropped.filter((e) => e.code === 'ERR_PAKE_CONFIRMATION').length,
    warnings: events.filter((e) => e.event === 'warning').map((e) => e.kind),
    progressEvents: events.filter((e) => e.event === 'progress').length
  }
}

/**
 * The short form of a trial's transport counters for its log line, in
 * scratch-trials.js's words, plus what was still unacknowledged at the
 * end. Retransmits, RTOs, and inflight are the ones to read beside a slow
 * or failed trial.
 * @param {any} p
 */
function pathInfo (p) {
  if (!p) return ''
  return ` path=${p.remoteKind ?? '?'} rtt=${p.rttMs}ms retx=${p.retransmits} rto=${p.rtoCount}` +
    (p.inflight ? ` inflight=${p.inflight}` : '')
}

/**
 * One trial's record. Times are measured from `dialBaselineMs`, the moment
 * the sender is scheduled to start, on both sides, so the two roles report
 * comparable numbers -- the rule scratch-trials.js keeps, and for the same
 * reason. An event's `ms` is from its own process start, which is taken as
 * the spawn time: off by Node's startup, tens of milliseconds.
 *
 * @param {number} trial
 * @param {any} run what runCli resolved
 * @param {ReturnType<typeof readRun>} read
 * @param {number} dialBaselineMs
 * @param {Record<string, any>} extra
 */
function trialRecord (trial, run, read, dialBaselineMs, extra) {
  const fromBaseline = (/** @type {number | null} */ ms) => ms === null ? null : run.spawnedAtEpochMs + ms - dialBaselineMs
  const final = read.final
  return {
    trial,
    outcome: read.outcome,
    code: read.code,
    exit: run.status,
    signal: run.signal,
    killed: run.killed,
    connectedMs: fromBaseline(read.pairedMs),
    completedMs: read.outcome === 'ok' ? fromBaseline(read.finalMs) : null,
    transferMs: read.outcome === 'ok' && read.acceptedMs !== null ? read.finalMs - read.acceptedMs : null,
    bytes: final ? (final.event === 'done' ? final.size : final.bytes) : null,
    sha256: final && final.event === 'done' ? final.sha256 : null,
    acknowledged: final && final.event === 'done' && 'acknowledged' in final ? final.acknowledged : undefined,
    peerReason: final && final.peerReason !== undefined ? final.peerReason : undefined,
    phase: final && final.phase !== undefined ? final.phase : undefined,
    // Hole punches hyperdht refused because both NATs were randomized: a
    // no-peer that no amount of retrying would have fixed.
    holepunchRefused: final && final.holepunchRefused !== undefined ? final.holepunchRefused : undefined,
    // The paired connection's transport counters, from the final event's
    // `connection`, under the name scratch-trials.js records them as, so
    // scratch-trials-environment.js reads both harnesses the same way.
    // null before a peer paired, and from a CLI too old to report them.
    path: final && final.connection ? final.connection : null,
    contract: read.contract,
    candidates: read.candidates,
    dropped: read.dropped,
    badConfirmations: read.badConfirmations,
    warnings: read.warnings,
    progressEvents: read.progressEvents,
    // Every event but progress, so a surprising trial can be read later.
    events: run.events.filter((/** @type {any} */ e) => e.event !== 'progress'),
    otherLines: run.otherLines,
    startedAtEpochMs: run.spawnedAtEpochMs,
    endedAtEpochMs: run.endedAtEpochMs,
    ...extra
  }
}

// --- the summary -------------------------------------------------------------

/**
 * @param {any[]} results
 * @param {{ role: string, seed: string }} run
 * @returns {{ lines: string[], summary: Record<string, any> }}
 */
function summarise (results, { role, seed }) {
  const ok = results.filter((r) => r.outcome === 'ok')
  const counted = results.filter((r) => r.outcome !== 'skipped')
  const interval = wilson(ok.length, counted.length)
  const sorted = (/** @type {string} */ key) => ok.map((r) => r[key]).filter((v) => typeof v === 'number').sort((a, b) => a - b)
  const stat = (/** @type {number[]} */ values) => values.length
    ? { median: percentile(values, 50), p90: percentile(values, 90), min: values[0], max: values[values.length - 1] }
    : null
  /** @type {Record<string, number>} */
  const failures = {}
  for (const r of counted) if (r.outcome !== 'ok') failures[r.outcome] = (failures[r.outcome] || 0) + 1
  const summary = {
    succeeded: ok.length,
    trials: counted.length,
    skipped: results.length - counted.length,
    rate: counted.length ? ok.length / counted.length : null,
    wilson95: interval,
    connectedMs: stat(sorted('connectedMs')),
    completedMs: stat(sorted('completedMs')),
    transferMs: stat(sorted('transferMs')),
    failures,
    contractViolations: results.filter((r) => r.contract && r.contract.length).map((r) => ({ trial: r.trial, contract: r.contract })),
    crossCheckDisagreed: results.filter((r) => r.outcome === 'hash-crosscheck-disagreed').map((r) => r.trial),
    badConfirmations: results.reduce((n, r) => n + (r.badConfirmations || 0), 0),
    unacknowledged: results.filter((r) => r.acknowledged === false).map((r) => r.trial),
    holepunchRefused: results.filter((r) => r.holepunchRefused).map((r) => r.trial)
  }
  /** @type {Map<string, number>} */
  const kinds = new Map()
  for (const r of counted) if (r.path) kinds.set(r.path.remoteKind ?? '?', (kinds.get(r.path.remoteKind ?? '?') || 0) + 1)

  const s = (/** @type {number} */ ms) => `${(ms / 1000).toFixed(1)}s`
  const pct = (/** @type {number} */ f) => `${(f * 100).toFixed(0)}%`
  const lines = ['', '=== SUMMARY ===', `role: ${role}   seed: ${seed}   trials: ${counted.length}${summary.skipped ? ` (+${summary.skipped} skipped)` : ''}`]
  lines.push(`succeeded: ${ok.length}/${counted.length}` +
    (interval ? `  (${pct(/** @type {number} */ (summary.rate))}, 95% Wilson interval ${pct(interval.low)}-${pct(interval.high)})` : ''))
  for (const [label, key] of [['connect', 'connectedMs'], ['complete', 'completedMs'], ['transfer', 'transferMs']]) {
    const v = /** @type {any} */ (summary)[key]
    if (v) lines.push(`${label.padEnd(9)} median ${s(v.median)}  p90 ${s(v.p90)}  min ${s(v.min)}  max ${s(v.max)}`)
  }
  if (kinds.size) {
    lines.push(`peer address: ${[...kinds].map(([k, n]) => `${k} ${n}`).join(', ')}` +
      (kinds.has('private') ? '  (private = same LAN, not a punch across the internet)' : ''))
  }
  if (Object.keys(failures).length) {
    lines.push('failures:')
    for (const [reason, n] of Object.entries(failures).sort((a, b) => b[1] - a[1])) lines.push(`  ${reason.padEnd(26)} ${n}`)
  }
  if (summary.holepunchRefused.length) {
    lines.push(`trial(s) ${summary.holepunchRefused.map((t) => t + 1).join(', ')}: hyperdht refused to hole-punch, both NATs randomized; only a relay connects such a pair`)
  }
  if (summary.unacknowledged.length) {
    lines.push(`trial(s) ${summary.unacknowledged.map((t) => t + 1).join(', ')}: saved and verified here, but the sender never acknowledged RESULT`)
  }
  // The loud ones, in order of how bad they are.
  if (summary.crossCheckDisagreed.length) {
    lines.push('', `>> ${summary.crossCheckDisagreed.length} TRIAL(S) WHERE THE CLI REPORTED done BUT THIS HARNESS HASHED SOMETHING ELSE.`,
      '   The verification itself is broken. Stop and investigate before reading anything else here.')
  }
  if (summary.contractViolations.length) {
    lines.push('', `>> ${summary.contractViolations.length} TRIAL(S) BROKE THE EVENT CONTRACT (docs/CLI-CONTRACT.md):`)
    for (const v of summary.contractViolations) lines.push(`   trial ${v.trial + 1}: ${v.contract.join('; ')}`)
  }
  if (summary.badConfirmations) {
    lines.push('', `>> ${summary.badConfirmations} PEER(S) FAILED THE PAKE CONFIRMATION. Nobody should reach this topic`,
      '   without the secret: check both machines run the same build and nobody else uses this --seed.')
  }
  if (counted.length < 5) {
    lines.push('', '>> Too few trials to call a rate. Use --trials 10 or more, and read the interval, not the rate.')
  }
  return { lines, summary }
}

// --- the run -----------------------------------------------------------------

/**
 * @param {ReturnType<typeof parseArgs>} opts
 */
async function main (opts) {
  const t0 = Date.now()
  const log = (/** @type {string} */ line) => console.log(`+${((Date.now() - t0) / 1000).toFixed(1)}s ${line}`)
  const slotMs = opts.slotSeconds * 1000
  const startMs = startMsFor(opts.startEpoch)
  const baseEnv = { ...process.env }
  if (opts.refreshMs !== undefined) baseEnv.ADHAL_REFRESH_INTERVAL = String(opts.refreshMs)

  log(`host: ${os.hostname()} (${os.platform()}/${os.arch()}) node ${process.version}`)
  log(`role=${opts.role} seed=${opts.seed} trials=${opts.trials} slot=${opts.slotSeconds}s` +
    `${opts.role === 'receiver' ? ` mode=${opts.mode}` : ''} refresh=${opts.refreshMs ?? 'default(4000)'}`)
  if (process.env.ADHAL_BOOTSTRAP) log('ADHAL_BOOTSTRAP is set: the CLIs will use it, not the public DHT')

  // Null when skipped or when the probe failed, never a partial block:
  // engine/scratch-trials-environment.js reads a missing block as "not
  // recorded", which is true, and a partial one as a machine it cannot
  // describe.
  let environment = null
  /** @type {string | null} */
  let environmentError = null
  if (opts.environment) {
    const envPath = path.join(os.tmpdir(), `adhal-cli-trials-env-${process.pid}.json`)
    const probeArgs = ['--environment-only', '--out', envPath,
      ...(opts.lookupIsp ? ['--lookup-isp'] : []),
      ...(opts.recordAddresses ? ['--record-addresses'] : []),
      ...opts.notes.flatMap((n) => ['--note', n])]
    try {
      const printed = execFileSync(process.execPath, [PROBE, ...probeArgs], { encoding: 'utf8', timeout: 60000 })
      for (const line of printed.split('\n').filter(Boolean)) log(`env ${line.replace(/^\+[\d.]+s /, '')}`)
      environment = JSON.parse(fs.readFileSync(envPath, 'utf8'))
    } catch (err) {
      environmentError = err.message.split('\n')[0]
      log(`environment probe failed: ${environmentError}`)
    } finally {
      fs.rmSync(envPath, { force: true })
    }
  }

  /** @type {{ path: string, size: number, sha256: string } | null} */
  let file = null
  if (opts.role === 'sender') {
    const stat = await fs.promises.stat(/** @type {string} */ (opts.file))
    file = { path: /** @type {string} */ (opts.file), size: stat.size, sha256: await sha256File(/** @type {string} */ (opts.file)) }
    log(`file: ${file.path} (${file.size} bytes, sha256 ${file.sha256.slice(0, 16)}…)`)
    if (file.size === 0) log('WARNING: the file is empty, so every trial measures an empty drop')
  }

  log(`slot start: ${Math.floor(startMs / 1000)} (${new Date(startMs).toLocaleTimeString()}) <-- MUST MATCH ON BOTH MACHINES`)
  log(`waiting ${((startMs - Date.now()) / 1000).toFixed(0)}s for the first slot...`)

  /** @type {any[]} */
  const results = []
  const write = () => {
    if (!opts.out) return
    const { summary } = summarise(results, opts)
    fs.writeFileSync(opts.out, JSON.stringify({
      tool: 'cli-trials',
      role: opts.role,
      seed: opts.seed,
      trials: opts.trials,
      slotSeconds: opts.slotSeconds,
      refreshMs: opts.refreshMs ?? 4000,
      mode: opts.role === 'receiver' ? opts.mode : undefined,
      receiverTimeoutMs: opts.role === 'receiver' ? opts.receiverTimeoutMs ?? null : undefined,
      leadMs: opts.leadMs,
      startEpoch: Math.floor(startMs / 1000),
      startedAtEpochMs: t0,
      endedAtEpochMs: Date.now(),
      file,
      environment,
      // Recorded here as well, so a run without the probe still says what
      // it ran and what the operator noted.
      environmentSkipped: !opts.environment,
      environmentError,
      build: buildCommit(),
      notes: opts.notes,
      results,
      summary
    }, null, 2))
  }

  for (let i = 0; i < opts.trials; i++) {
    const slotStart = startMs + i * slotMs
    const dialBaseline = slotStart + opts.leadMs
    const myStart = opts.role === 'sender' ? dialBaseline : slotStart
    await sleep(myStart - Date.now())
    const deadline = slotStart + slotMs - TEARDOWN_MS
    const budget = deadline - Date.now()
    if (budget < 5000) {
      log(`trial ${i + 1}/${opts.trials}: SKIPPED (slot already over -- clock skew, or a slot too short)`)
      results.push({ trial: i, outcome: 'skipped' })
      write()
      continue
    }

    const code = trialCode(opts.seed, i)
    let record
    if (opts.role === 'receiver') {
      const outDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'adhal-cli-trial-'))
      try {
        const toStdout = opts.mode === 'stdout'
        const run = await runCli({
          script: RECEIVE,
          args: toStdout ? ['-', '--stdout', '--json', '--yes'] : ['-', outDir, '--json', '--yes'],
          code,
          env: { ...baseEnv, ADHAL_JOIN_TIMEOUT: String(Math.round(opts.receiverTimeoutMs ?? budget)) },
          deadlineMs: deadline + STOP_AFTER_BUDGET_MS,
          eventsOn: toStdout ? 'stderr' : 'stdout',
          hashStdout: toStdout
        })
        const done = run.events.find((/** @type {any} */ e) => e.event === 'done')
        let independent = null
        if (toStdout) independent = run.stdoutSha256
        else if (done && done.path) independent = await sha256File(done.path).catch(() => 'unreadable')
        const read = readRun(run, { independentSha256: done ? independent : null })
        record = trialRecord(i, run, read, dialBaseline, {
          independentSha256: independent,
          stdoutBytes: run.stdoutBytes
        })
      } finally {
        fs.rmSync(outDir, { recursive: true, force: true })
      }
    } else {
      const run = await runCli({
        script: SEND,
        args: ['-', /** @type {string} */ (opts.file), '--json'],
        code,
        env: { ...baseEnv, ADHAL_JOIN_TIMEOUT: String(Math.round(budget)) },
        deadlineMs: deadline + STOP_AFTER_BUDGET_MS,
        eventsOn: 'stdout'
      })
      // The sender's own check: the digest the receiver confirmed is the
      // one this harness computed from the source before the run.
      const read = readRun(run, { independentSha256: /** @type {any} */ (file).sha256 })
      record = trialRecord(i, run, read, dialBaseline, {})
    }
    results.push(record)
    write()

    const t = (/** @type {number | null} */ ms) => ms === null ? '?' : `${(ms / 1000).toFixed(1)}s`
    const timing = record.outcome === 'ok' ? ` connect=${t(record.connectedMs)} total=${t(record.completedMs)} transfer=${t(record.transferMs)}` : ''
    const detail = record.outcome === 'ok'
      ? ''
      : ` [code=${record.code ?? 'none'} exit=${record.exit ?? record.signal}${record.killed ? ' killed' : ''} bytes=${record.bytes ?? '?'}` +
        `${record.peerReason ? ` peerReason="${record.peerReason}"` : ''}` +
        `${record.holepunchRefused ? ` holepunchRefused=${record.holepunchRefused}` : ''}]`
    const flags = (record.contract.length ? ' CONTRACT' : '') + (record.badConfirmations ? ` badConfirmations=${record.badConfirmations}` : '')
    log(`trial ${i + 1}/${opts.trials}: ${record.outcome}${timing}${pathInfo(record.path)}${detail}${flags}`)
  }

  const { lines } = summarise(results, opts)
  for (const line of lines) log(line)
  write()
  if (opts.out) log(`per-trial JSON written to ${opts.out}`)
}

function buildCommit () {
  try {
    const git = (/** @type {string[]} */ args) => execFileSync('git', args, { cwd: REPO_ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim()
    return { commit: git(['rev-parse', '--short=12', 'HEAD']), dirty: git(['status', '--porcelain', '--untracked-files=no']) !== '' }
  } catch {
    return { commit: null, dirty: null }
  }
}

const sleep = (/** @type {number} */ ms) => new Promise((resolve) => setTimeout(resolve, Math.max(0, ms)))

if (require.main === module) {
  let opts
  try {
    opts = parseArgs(process.argv.slice(2))
  } catch (err) {
    console.error(`cli-trials: ${err.message}`)
    console.error('Usage: cli-trials.js --role <receiver|sender> --seed <s> --trials <n> [--file <path>] [--mode dir|stdout]')
    console.error('                     [--slot 135] [--start-epoch <s>] [--receiver-timeout <ms>] [--refresh <ms>] [--out <path>]')
    console.error('                     [--note <text>]... [--lookup-isp] [--record-addresses] [--no-environment]')
    process.exit(1)
  }
  main(opts).catch((err) => {
    console.error('cli-trials failed:', err.stack || err.message)
    process.exit(1)
  })
}

module.exports = { parseArgs, eventReader, readRun, trialRecord, summarise, pathInfo }
