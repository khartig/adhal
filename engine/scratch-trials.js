'use strict'
// Repeated-trial measurement harness: runs N real drops back to back and
// reports a success RATE, not an anecdote.
//
// This exists because every wrong conclusion in this project's cross-ISP
// debugging came from reasoning about single runs. One failure looks like a
// bug; one success looks like a fix. On a path that is intermittently
// unable to hole punch, neither is true, and there was no instrument that
// could tell the difference. This is that instrument. It is also the direct
// input to plan section 8 ("Transfer success (direct or relay) >= 75%") and
// to section 9 spike 1 (our punch rate on a genuinely hostile path).
//
// Usage, on the two real machines:
//
//   # Comcast (or wherever the receiver lives)
//   node engine/scratch-trials.js --role receiver --seed run7 --trials 10
//
//   # Starlink
//   node engine/scratch-trials.js --role sender --seed run7 --trials 10 \
//     --file /tmp/test.bin
//
// Both sides must be given the SAME --seed and --trials. Start them within
// a minute of each other, then leave them alone.
//
// Options: --slot <s> per-trial budget (default 90), --start-epoch <s> to
// pin the schedule explicitly, --out <path> to write per-trial JSON.
//
// TWO DESIGN CONSTRAINTS, because the two ends cannot talk to each other:
//
// 1. Codes are derived from (seed, trial index), so both sides agree on
//    every topic without exchanging anything. They are deliberately opaque
//    secrets rather than six-word codes: a topic is a 32-byte hash either
//    way, resolveCode handles both, and word parsing is already covered by
//    cli/test/code.test.js. Nothing about the measurement changes.
//
// 2. Trials are pinned to absolute wall-clock slots, NOT to each other's
//    progress. If each side simply advanced when its own trial ended, a
//    fast failure on one side and a slow timeout on the other would
//    desynchronise them, and every subsequent trial would fail because the
//    two were on different topics -- turning a working path into a 0%
//    result. Slot alignment makes drift impossible on NTP-synced hosts.

const os = require('node:os')
const fs = require('node:fs')
const path = require('node:path')
const crypto = require('node:crypto')
const {
  createSwarm,
  acceptOnce,
  connectOnce,
  resolveCode,
  sendFile,
  receiveFile
} = require('./src')

function flag (name, fallback = undefined) {
  const i = process.argv.indexOf(`--${name}`)
  return i === -1 ? fallback : process.argv[i + 1]
}

const role = flag('role')
const seed = flag('seed')
const trials = Number(flag('trials', 10))
const slotSeconds = Number(flag('slot', 135))
const filePath = flag('file')
const outPath = flag('out')
// Optional A/B for engine/src/swarm.js REFRESH_INTERVAL. Single runs
// succeeded at both 4000 and 30000, which proves neither is fatal and
// settles nothing about the rate -- exactly the question this harness is
// for. Omitted, the engine default applies.
const refreshMs = flag('refresh') === undefined ? undefined : Number(flag('refresh'))

if (!['receiver', 'sender'].includes(role) || !seed || !Number.isInteger(trials) || trials < 1) {
  console.error('Usage: scratch-trials.js --role <receiver|sender> --seed <string> --trials <n>')
  console.error('                         [--file <path>] [--slot 135] [--refresh <ms>] [--start-epoch <s>] [--out <path>]')
  console.error('The sender requires --file. Both sides need the same --seed and --trials.')
  process.exit(1)
}
if (role === 'sender' && !filePath) {
  console.error('scratch-trials: --role sender requires --file <path>')
  process.exit(1)
}

// The sender waits this long into each slot before dialing, so the
// receiver has announced first -- the lookup-before-announce race in
// engine/src/swarm.js is a real effect, and measuring it here would just be
// measuring our own starting order.
const SENDER_LEAD_MS = 10000
// Leave the tail of each slot free so a trial that runs long still tears
// down before the next slot opens.
const TEARDOWN_MS = 5000

// The default --slot of 135 is not arbitrary: the sender's per-trial budget
// works out to SLOT - SENDER_LEAD - TEARDOWN = 120s, which is exactly
// swarm-send.js's default join timeout. The harness therefore measures what
// a real drop would experience. A shorter slot would cut trials off early
// and under-report the success rate relative to the actual CLI.

const SLOT_MS = slotSeconds * 1000
// Align to a 5-minute boundary at least a minute out. Wide enough that two
// hosts started within the same few minutes pick the same schedule; the
// chosen value is printed so a mismatch is obvious rather than silent.
const ALIGN_MS = 300000
const startEpoch = flag('start-epoch')
const startMs = startEpoch
  ? Number(startEpoch) * 1000
  : Math.ceil((Date.now() + 60000) / ALIGN_MS) * ALIGN_MS

const t0 = Date.now()
const log = (...a) => console.log(`+${((Date.now() - t0) / 1000).toFixed(1)}s`, ...a)

// Deterministic per-trial secret. Both roles compute the same string, so
// neither has to be told the codes.
function codeForTrial (i) {
  const digest = crypto.createHash('sha256').update(`quay-trial:${seed}:${i}`).digest('hex')
  return `trial-${digest.slice(0, 16)}`
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, Math.max(0, ms)))

// Classifies a failure into something countable. The swarm layer's own
// timeout message already distinguishes "found nobody" from "found peers
// that never completed the handshake" (engine/src/swarm.js timeoutMessage);
// this preserves that distinction in the tally instead of flattening every
// failure into "it didn't work".
function classify (err) {
  const message = err.message || String(err)
  if (/no peer ever connected/.test(message)) return 'no-peer'
  if (/none completed the readiness handshake/.test(message)) return 'no-handshake'
  if (/timed out/.test(message)) return 'timeout-other'
  return 'transfer-error'
}

// `dialBaselineMs` is the wall-clock moment the sender is scheduled to
// start dialing. Connect and completion times are measured from there, not
// from when this side started waiting, so the two roles report comparable
// numbers. Measuring from the receiver's own start would silently add
// SENDER_LEAD_MS to every figure -- an instrument that inflates the
// connect time by ten seconds would corrupt any read against plan section
// 8's "10 MB median < 30-45s" target.
async function runReceiverTrial (i, budgetMs, dialBaselineMs) {
  const { topic } = resolveCode(codeForTrial(i))
  const swarm = createSwarm()
  const outDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'quay-trial-'))
  const started = Date.now()
  const sinceDial = () => Math.max(0, Date.now() - dialBaselineMs)
  /** @type {any} */
  let manifest = null
  let announcedAt = null
  let candidateAt = null

  try {
    const { socket, pending } = await acceptOnce(swarm, topic, {
      timeout: budgetMs,
      refreshInterval: refreshMs,
      onAnnounced: () => { announcedAt = Date.now() - started },
      onCandidate: () => { if (candidateAt === null) candidateAt = sinceDial() }
    })
    socket.on('error', () => {})
    const connectedAt = sinceDial()

    const result = await receiveFile(socket, outDir, {
      pending,
      onManifest: (m) => { manifest = m }
    })
    await new Promise((resolve) => socket.end(resolve))

    // The real integrity check, and it is decidable locally: compare what
    // we hashed off the wire against the hash the sender put in its
    // manifest. A mismatch is a corruption bug, not a network failure, and
    // must never be counted as merely "failed".
    const hashOk = !!manifest && manifest.sha256 === result.sha256
    return {
      trial: i,
      outcome: hashOk ? 'ok' : 'hash-mismatch',
      announcedMs: announcedAt,
      candidateMs: candidateAt,
      connectedMs: connectedAt,
      completedMs: sinceDial(),
      bytes: result.size,
      sha256: result.sha256
    }
  } catch (err) {
    return {
      trial: i,
      outcome: classify(err),
      announcedMs: announcedAt,
      candidateMs: candidateAt,
      error: err.message
    }
  } finally {
    await swarm.destroy().catch(() => {})
    await fs.promises.rm(outDir, { recursive: true, force: true }).catch(() => {})
  }
}

async function runSenderTrial (i, budgetMs) {
  const { topic } = resolveCode(codeForTrial(i))
  const swarm = createSwarm()
  const started = Date.now()
  let candidateAt = null
  let dropped = 0

  try {
    const { socket } = await connectOnce(swarm, topic, {
      timeout: budgetMs,
      refreshInterval: refreshMs,
      onCandidate: () => { if (candidateAt === null) candidateAt = Date.now() - started },
      onCandidateDropped: () => { dropped++ }
    })
    socket.on('error', () => {})
    const connectedAt = Date.now() - started

    const result = await sendFile(socket, filePath)
    socket.end()
    await Promise.race([
      new Promise((resolve) => socket.once('close', resolve)),
      sleep(5000)
    ])

    return {
      trial: i,
      outcome: 'ok',
      candidateMs: candidateAt,
      connectedMs: connectedAt,
      completedMs: Date.now() - started,
      droppedCandidates: dropped,
      bytes: result.size,
      sha256: result.sha256
    }
  } catch (err) {
    return {
      trial: i,
      outcome: classify(err),
      candidateMs: candidateAt,
      droppedCandidates: dropped,
      error: err.message
    }
  } finally {
    await swarm.destroy().catch(() => {})
  }
}

function percentile (sorted, p) {
  if (sorted.length === 0) return null
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))
  return sorted[idx]
}

function summarise (results) {
  const ok = results.filter((r) => r.outcome === 'ok')
  const rate = results.length ? (ok.length / results.length) * 100 : 0
  const connects = ok.map((r) => r.connectedMs).filter((v) => typeof v === 'number').sort((a, b) => a - b)

  const counts = new Map()
  for (const r of results) {
    if (r.outcome === 'ok') continue
    counts.set(r.outcome, (counts.get(r.outcome) || 0) + 1)
  }

  log('')
  log('=== SUMMARY ===')
  log(`role: ${role}   seed: ${seed}   trials: ${results.length}   refresh: ${refreshMs ?? 4000}ms`)
  log(`succeeded: ${ok.length}/${results.length}  (${rate.toFixed(0)}%)`)
  if (connects.length) {
    const median = percentile(connects, 50)
    const p90 = percentile(connects, 90)
    log(`connect time: median ${(median / 1000).toFixed(1)}s  p90 ${(p90 / 1000).toFixed(1)}s  ` +
      `min ${(connects[0] / 1000).toFixed(1)}s  max ${(connects[connects.length - 1] / 1000).toFixed(1)}s`)
  }
  if (counts.size) {
    log('failures:')
    for (const [reason, n] of [...counts].sort((a, b) => b[1] - a[1])) {
      log(`  ${reason.padEnd(22)} ${n}`)
    }
  }

  // Interpretation, so the number is actionable rather than decorative.
  const mismatches = results.filter((r) => r.outcome === 'hash-mismatch').length
  log('')
  if (mismatches > 0) {
    log(`>> ${mismatches} HASH MISMATCH(ES). This is a correctness bug, not a network`)
    log('   failure. Stop feature work and investigate framing/chunking.')
  } else if (results.length < 5) {
    log('>> Too few trials to call a rate. Use --trials 10 or more.')
  } else if (rate >= 75) {
    log(`>> ${rate.toFixed(0)}% meets plan section 8's >=75% bar for this path.`)
    if (counts.get('no-peer')) {
      log(`   ${counts.get('no-peer')} trial(s) never saw a peer -- intermittent discovery or punch`)
      log('   failure, which is what makes a single failing run look like a bug.')
    }
  } else if (rate >= 50) {
    log(`>> ${rate.toFixed(0)}% is below the section 8 bar of 75% but above the`)
    log('   kill threshold of 50%. This path is flaky, not broken -- expect')
    log('   single runs to fail and do not read a code bug into them.')
  } else {
    log(`>> ${rate.toFixed(0)}% is below section 8's 50% kill threshold. Per the plan,`)
    log('   relay quality (section 4 item 9) is the product, not an optional extra.')
  }
}

async function main () {
  log(`host machine: ${os.hostname()} (${os.platform()}/${os.arch()}) node ${process.version}`)
  log(`role=${role} seed=${seed} trials=${trials} slot=${slotSeconds}s refresh=${refreshMs ?? 'default(4000)'}`)
  if (role === 'sender') {
    const stat = await fs.promises.stat(filePath)
    log(`file: ${filePath} (${stat.size} bytes)`)
  }
  // Printed so that two hosts which picked different schedules are caught
  // immediately, rather than producing a confusing 0% result.
  log(`slot start: ${Math.floor(startMs / 1000)} (${new Date(startMs).toLocaleTimeString()}) ` +
    '<-- MUST MATCH ON BOTH MACHINES')
  log(`waiting ${((startMs - Date.now()) / 1000).toFixed(0)}s for the first slot...`)

  const results = []
  for (let i = 0; i < trials; i++) {
    const slotStart = startMs + i * SLOT_MS
    const myStart = slotStart + (role === 'sender' ? SENDER_LEAD_MS : 0)
    await sleep(myStart - Date.now())

    // Budget ends before the slot does, so a hung trial cannot bleed into
    // the next one and corrupt its result.
    const budget = (slotStart + SLOT_MS - TEARDOWN_MS) - Date.now()
    if (budget < 5000) {
      log(`trial ${i + 1}/${trials}: SKIPPED (slot already over -- clock skew or a slot too short)`)
      results.push({ trial: i, outcome: 'skipped' })
      continue
    }

    const result = role === 'receiver'
      ? await runReceiverTrial(i, budget, slotStart + SENDER_LEAD_MS)
      : await runSenderTrial(i, budget)
    results.push(result)

    const timing = result.connectedMs !== undefined && result.connectedMs !== null
      ? ` connect=${(result.connectedMs / 1000).toFixed(1)}s total=${(result.completedMs / 1000).toFixed(1)}s`
      : ''
    log(`trial ${i + 1}/${trials}: ${result.outcome}${timing}${result.error ? ` -- ${result.error}` : ''}`)
  }

  summarise(results)

  if (outPath) {
    await fs.promises.writeFile(outPath, JSON.stringify({ role, seed, trials, slotSeconds, refreshMs: refreshMs ?? 4000, results }, null, 2))
    log(`per-trial JSON written to ${outPath}`)
  }
}

main().catch((err) => {
  console.error('scratch-trials failed:', err.message)
  process.exit(1)
})
