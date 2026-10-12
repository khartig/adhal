'use strict'
// Repeated-trial measurement harness: runs N real drops back to back and
// reports a success RATE, not an anecdote.
//
// This exists because every wrong conclusion in this project's cross-ISP
// debugging came from reasoning about single runs. One failure looks like a
// bug; one success looks like a fix. On a path that is intermittently
// unable to hole punch, neither is true, and there was no instrument that
// could tell the difference. This is that instrument. Its results are read
// against the reliability bar docs/MEASURING-TRANSFER-RELIABILITY.md states
// (>= 75% success on a path, and 50% as the line below which relay quality
// is the product), and it is what W14's head-to-head runs reuse.
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
// Options: --slot <s> per-trial budget (default 135), --start-epoch <s> to
// pin the schedule explicitly, --out <path> to write per-trial JSON.
//
// TWO DESIGN CONSTRAINTS, because the two ends cannot talk to each other:
//
// 1. Codes are derived from (seed, trial index), so both sides agree on
//    every topic without exchanging anything.
//
//    UNDER v2 THEY ARE REAL FIVE-WORD CODES, and that is a correctness fix
//    rather than tidying. They used to be opaque `trial-<hex>` secrets, on
//    the reasoning that "a topic is a 32-byte hash either way". That
//    stopped being true: an opaque code is its own nameplate AND its own
//    secret (see engine/src/resolve-code.js), so every trial would have
//    run down the --insecure-opaque-code path -- publishing its secret in the
//    announced topic and measuring a configuration no user can reach. The
//    instrument would have been measuring something other than the
//    product. Deriving a word code from the same seed keeps the "neither
//    side has to be told the codes" property and measures the real path.
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
  receiveFile,
  WORD_COUNT,
  ERR_CONFIRMATION
} = require('./src')
const { WORDS } = require('./src/wordlist')

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

// Deterministic per-trial code: a real five-word drop code, derived from
// (seed, trial index) so that both roles compute the same one without
// exchanging anything.
//
// Rejection sampled rather than plain modulo, for the same reason
// generateCode uses crypto.randomInt: 7772 is not a power of two, so
// reducing a 16-bit window modulo 7772 would favour the front of the list.
// It does not matter much for a rendezvous label on a private topic, but a
// harness that quietly draws from a skewed distribution is not the thing to
// leave lying around in a repo whose codes are its security argument.
const SAMPLE_LIMIT = 65536 - (65536 % WORDS.length)

function codeForTrial (i) {
  const words = []
  for (let counter = 0; words.length < WORD_COUNT; counter++) {
    const digest = crypto.createHash('sha256').update(`adhal-trial:${seed}:${i}:${counter}`).digest()
    for (let off = 0; off + 2 <= digest.length && words.length < WORD_COUNT; off += 2) {
      const n = digest.readUInt16BE(off)
      if (n >= SAMPLE_LIMIT) continue
      words.push(WORDS[n % WORDS.length])
    }
  }
  return words.join('-')
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, Math.max(0, ms)))

// Classifies a failure into something countable.
//
// KEYED ON err.code SINCE ITEM 5, and that is not a cleanup. This harness
// used to classify by regex-matching error *messages*, which coupled the
// project's only measurement instrument to prose: rewording a sentence in
// engine/src/swarm.js silently re-bucketed results, and nothing would have
// said so. engine/src/errors.js exists largely for this.
//
// The failure-reporting work also changed what this function has to catch. The engine now
// verifies the received file against the manifest itself, so a corrupted
// transfer arrives here as a REJECTION rather than as a successful receive
// with a mismatching digest. Without the ERR_HASH_MISMATCH entry below it
// would land in the generic 'transfer-error' bucket, and the loudest
// output this tool has -- ">> N HASH MISMATCH(ES) ... stop feature work"
// -- would never fire again.
const OUTCOME_BY_CODE = {
  ERR_NO_PEER: 'no-peer',
  ERR_NO_HANDSHAKE: 'no-handshake',
  // Should never appear in an unattended run on a private topic. If it
  // does, the run is not measuring the network at all -- somebody reached
  // the nameplate and spent the drop's hundred guesses (section 6).
  ERR_ATTEMPT_CAP: 'attempt-cap',
  ERR_HASH_MISMATCH: 'hash-mismatch',
  ERR_SIZE_MISMATCH: 'size-mismatch',
  ERR_CONNECTION: 'connection-lost',
  ERR_STALLED: 'stalled',
  // Sender only: the receiver had every byte and said, in RESULT, that it
  // could not keep the file. Its own record for the trial says why.
  ERR_RECEIVER_FAILED: 'receiver-failed',
  // The accept gate. This harness's receiver asks no person, so a decline
  // here is the engine's own: a name, a size, the disk. ERR_DECLINED is
  // what the sender sees of any of them, with the receiver's reason.
  ERR_DECLINED: 'declined',
  ERR_NO_SPACE: 'no-space',
  ERR_EXISTS: 'exists',
  // Someone else holding this trial's code paired first. On a derived,
  // private code that should not happen; if it does, a second machine is
  // running the same --seed.
  ERR_DROP_TAKEN: 'drop-taken',
  ERR_UNSAFE_NAME: 'unsafe-name',
  ERR_MANIFEST_INVALID: 'manifest-invalid',
  ERR_PROTOCOL: 'protocol-error',
  ERR_CANCELLED_PEER: 'cancelled-by-peer',
  ABORT_ERR: 'cancelled-locally'
}

function classify (err) {
  if (err && OUTCOME_BY_CODE[err.code]) return OUTCOME_BY_CODE[err.code]

  // FALLBACK ONLY, and documented as such. Anything reaching these
  // patterns is an error that predates the code vocabulary -- a raw
  // socket error, or something thrown by a dependency. If a *ad-hal* error
  // starts landing here, the fix is to give it a code, not to add a
  // pattern.
  //
  // ONE PATTERN WAS REMOVED IN W11, and it is worth saying why rather than
  // just deleting it. It matched /failed the code proof/ to produce a
  // 'bad-proof' bucket -- which is exactly the prose coupling the rest of
  // this comment warns against, and it was already dead: a drop that ends
  // with peers having failed their handshake reports ERR_NO_HANDSHAKE,
  // which the table above catches first. Failed confirmations are
  // per-candidate events, not drop outcomes, so they are now counted
  // where they happen, off the code ERR_PAKE_CONFIRMATION -- see
  // `badConfirmations` below.
  const message = (err && err.message) || String(err)
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
  const { topic, nameplate, secret } = resolveCode(codeForTrial(i))
  const swarm = createSwarm()
  const outDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'adhal-trial-'))
  const started = Date.now()
  const sinceDial = () => Math.max(0, Date.now() - dialBaselineMs)
  /** @type {any} */
  let manifest = null
  let announcedAt = null
  let candidateAt = null
  let badConfirmations = 0
  // WHERE a failure happened, and how far the bytes got. Added after a run
  // whose trial 4 the sender scored 'ok' and the receiver scored "connection
  // reset by peer": the suspect is the sender's 5s close-wait fallback
  // destroying a socket the receiver was still draining. `failedAtEpochMs`
  // is wall-clock so it can be lined up against the sender's
  // `destroyAtEpochMs` for the same trial -- valid to NTP accuracy, which
  // slot alignment already assumes.
  /** @type {'accept' | 'receive' | 'end'} */
  let phase = 'accept'
  let connectedAt = null
  let bytesReceived = 0

  try {
    const { socket, pending, sendKey, receiveKey } = await acceptOnce(swarm, topic, {
      nameplate,
      secret,
      timeout: budgetMs,
      refreshInterval: refreshMs,
      onAnnounced: () => { announcedAt = Date.now() - started },
      onCandidate: () => { if (candidateAt === null) candidateAt = sinceDial() },
      // Counted off the CODE, never off the message. On a private topic
      // this should be zero, so a non-zero count means either a
      // build-version skew between the two hosts or someone else on the
      // topic -- both of which would otherwise hide inside the
      // handshake-failure bucket and be read as a NAT problem.
      onCandidateDropped: (info, reason, code) => {
        if (code === ERR_CONFIRMATION) badConfirmations++
      }
    })
    socket.on('error', () => {})
    connectedAt = sinceDial()

    phase = 'receive'
    const result = await receiveFile(socket, outDir, {
      sendKey,
      receiveKey,
      pending,
      onManifest: (m) => { manifest = m },
      onProgress: (p) => { bytesReceived = p.bytes }
    })
    // RESULT is written but only locally flushed, and the finally below
    // destroys the swarm. So wait for the sender's end in reply, as
    // cli/src/swarm-receive.js does; the file is already verified, so the
    // timer can cost the sender its confirmation but never this trial.
    phase = 'end'
    socket.end()
    await Promise.race([
      new Promise((resolve) => socket.once('close', resolve)),
      sleep(5000)
    ])

    // A CROSS-CHECK, no longer the integrity check itself.
    //
    // This comparison used to be the only place in the repo that verified
    // a received file against its manifest -- the measurement harness did
    // it and neither CLI did. The failure-reporting work moved it into receiveFile, where it
    // is unconditional, so reaching this line at all means the engine
    // already compared these two digests and was satisfied.
    //
    // It is kept anyway, and labelled differently, because it now tests
    // something else: that the engine's verification agrees with an
    // independent comparison. A disagreement cannot be a corrupt transfer
    // (the engine would have rejected it); it can only be a bug in the
    // verification itself, which is worth hearing about loudly and
    // separately.
    const crossCheckOk = !!manifest && manifest.sha256 === result.sha256
    return {
      trial: i,
      outcome: crossCheckOk ? 'ok' : 'hash-crosscheck-disagreed',
      announcedMs: announcedAt,
      candidateMs: candidateAt,
      connectedMs: connectedAt,
      completedMs: sinceDial(),
      badConfirmations,
      bytes: result.size,
      sha256: result.sha256
    }
  } catch (err) {
    return {
      trial: i,
      outcome: classify(err),
      announcedMs: announcedAt,
      candidateMs: candidateAt,
      connectedMs: connectedAt,
      badConfirmations,
      error: err.message,
      phase,
      bytesReceived,
      manifestSize: manifest ? manifest.size : null,
      failedAtEpochMs: Date.now()
    }
  } finally {
    await swarm.destroy().catch(() => {})
    await fs.promises.rm(outDir, { recursive: true, force: true }).catch(() => {})
  }
}

async function runSenderTrial (i, budgetMs) {
  const { topic, nameplate, secret } = resolveCode(codeForTrial(i))
  const swarm = createSwarm()
  const started = Date.now()
  let candidateAt = null
  let dropped = 0
  let badConfirmations = 0
  // How the post-send wait ended. This used to be the only evidence
  // against a false 'ok': sendFile resolved on hand-off, and all six of the
  // proofv2-3 run's receiver-side resets were among its nine 'timer'
  // trials, none among the 91 that closed. sendFile now resolves only
  // on the receiver's RESULT, so 'ok' here means delivered and verified,
  // and a 'timer' now only means the receiver was slow to close after
  // confirming. Kept because a rise in timers would still be worth seeing.
  /** @type {'closed' | 'timer' | null} */
  let closeWait = null
  let closeWaitMs = null
  let sentAtEpochMs = null
  /** @type {string | null} */
  let socketErrorAfterSend = null
  /** @type {any} */
  let out

  try {
    const { socket, pending, sendKey, receiveKey } = await connectOnce(swarm, topic, {
      nameplate,
      secret,
      timeout: budgetMs,
      refreshInterval: refreshMs,
      onCandidate: () => { if (candidateAt === null) candidateAt = Date.now() - started },
      onCandidateDropped: (info, reason, code) => {
        dropped++
        if (code === ERR_CONFIRMATION) badConfirmations++
      }
    })
    socket.on('error', () => {})
    const connectedAt = Date.now() - started

    // `pending` is anything the receiver coalesced after its proof.
    // Ordinarily empty, but sendFile reads now (for CANCEL), so dropping
    // it would lose a message rather than merely skipping a no-op.
    const result = await sendFile(socket, filePath, { sendKey, receiveKey, pending })
    sentAtEpochMs = Date.now()
    socket.on('error', (err) => { if (!socketErrorAfterSend) socketErrorAfterSend = err.message })
    socket.end()
    // A socket already gone before the wait starts would never emit
    // 'close' to this listener, and would be misreported as 'timer'.
    closeWait = socket.destroyed
      ? 'closed'
      : await Promise.race([
        new Promise((resolve) => socket.once('close', () => resolve('closed'))),
        sleep(5000).then(() => 'timer')
      ])
    closeWaitMs = Date.now() - sentAtEpochMs

    out = {
      trial: i,
      outcome: 'ok',
      candidateMs: candidateAt,
      connectedMs: connectedAt,
      completedMs: Date.now() - started,
      droppedCandidates: dropped,
      badConfirmations,
      bytes: result.size,
      sha256: result.sha256,
      closeWait,
      closeWaitMs,
      sentAtEpochMs,
      socketErrorAfterSend
    }
  } catch (err) {
    out = {
      trial: i,
      outcome: classify(err),
      candidateMs: candidateAt,
      droppedCandidates: dropped,
      badConfirmations,
      error: err.message,
      // 'send' or 'result': whether the receiver was lost while bytes were
      // still going out, or after they all had and before it confirmed.
      // The second is the case the receiver's own record has to settle.
      phase: (err && err.phase) || null,
      failedAtEpochMs: Date.now()
    }
  } finally {
    // Stamped immediately before the destroy, so it can be lined up with
    // the receiver's `failedAtEpochMs`. This destroy was what reset
    // receivers still draining, before sendFile waited for RESULT.
    if (out) out.destroyAtEpochMs = Date.now()
    await swarm.destroy().catch(() => {})
  }
  return out
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

  // Reported separately from the failure buckets, because a failed
  // confirmation is not a trial outcome: a trial can succeed having
  // rejected several peers first, which is the behaviour section 6 relies
  // on. On a private topic this should be zero, and a non-zero total is
  // worth a line of its own -- it means peers reached the nameplate
  // without the secret, i.e. a version skew between the two hosts or
  // somebody else on the topic.
  // A sender-side 'ok' now means the receiver's RESULT confirmed the same
  // digest, so the two roles' rates should agree. A 'timer' is a receiver
  // that confirmed and was then slow to close: harmless to the file.
  const timerWaits = ok.filter((r) => r.closeWait === 'timer').length
  if (role === 'sender' && ok.length) {
    log(`close wait: ${ok.length - timerWaits} closed by receiver, ${timerWaits} ended by the 5s timer (after RESULT)`)
  }
  const unconfirmed = results.filter((r) => r.phase === 'result').length
  if (role === 'sender' && unconfirmed) {
    log(`   ${unconfirmed} trial(s) sent every byte and never got RESULT; the receiver's`)
    log('   record for those trials is the only one that knows whether the file landed.')
  }

  const badConfirmations = results.reduce((n, r) => n + (r.badConfirmations || 0), 0)
  if (badConfirmations > 0) {
    log('')
    log(`>> ${badConfirmations} PEER(S) FAILED THE PAKE CONFIRMATION across these trials.`)
    log('   Nobody should be able to reach this topic without the secret. Check')
    log('   both hosts are on the same build before reading anything else here.')
  }

  // Interpretation, so the number is actionable rather than decorative.
  //
  // Both buckets count, and they mean different things. 'hash-mismatch'
  // is the engine having rejected a file whose bytes did not match the
  // manifest. 'hash-crosscheck-disagreed' is worse: the engine accepted a
  // file that an independent comparison says is wrong, i.e. the
  // verification itself is broken.
  const mismatches = results.filter((r) => r.outcome === 'hash-mismatch').length
  const crossCheckFailures = results.filter((r) => r.outcome === 'hash-crosscheck-disagreed').length
  log('')
  if (crossCheckFailures > 0) {
    log(`>> ${crossCheckFailures} TRIAL(S) WHERE THE ENGINE ACCEPTED A FILE THIS HARNESS SAYS IS WRONG.`)
    log('   That is a bug in hash verification itself, not in the transfer.')
    log('   Stop everything and investigate engine/src/transfer.js finalize().')
  } else if (mismatches > 0) {
    log(`>> ${mismatches} HASH MISMATCH(ES). This is a correctness bug, not a network`)
    log('   failure. Stop feature work and investigate framing/chunking.')
  } else if (results.length < 5) {
    log('>> Too few trials to call a rate. Use --trials 10 or more.')
  } else if (rate >= 75) {
    log(`>> ${rate.toFixed(0)}% meets the >=75% reliability bar for this path.`)
    if (counts.get('no-peer')) {
      log(`   ${counts.get('no-peer')} trial(s) never saw a peer -- intermittent discovery or punch`)
      log('   failure, which is what makes a single failing run look like a bug.')
    }
  } else if (rate >= 50) {
    log(`>> ${rate.toFixed(0)}% is below the 75% reliability bar but above the`)
    log('   kill threshold of 50%. This path is flaky, not broken -- expect')
    log('   single runs to fail and do not read a code bug into them.')
  } else {
    log(`>> ${rate.toFixed(0)}% is below the 50% kill threshold. On this path,`)
    log('   relay quality is the product, not an optional extra.')
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

    const timing = typeof result.completedMs === 'number'
      ? ` connect=${(result.connectedMs / 1000).toFixed(1)}s total=${(result.completedMs / 1000).toFixed(1)}s`
      : ''
    // The two lines that line a sender 'ok' up against a receiver failure:
    // how the sender's close wait ended, and where the receiver stopped.
    const closeInfo = result.closeWait
      ? ` close=${result.closeWait}(${(result.closeWaitMs / 1000).toFixed(1)}s) destroyAt=${result.destroyAtEpochMs}`
      : ''
    const failInfo = result.phase
      ? ` [phase=${result.phase} bytes=${result.bytesReceived}/${result.manifestSize ?? '?'} failedAt=${result.failedAtEpochMs}]`
      : ''
    log(`trial ${i + 1}/${trials}: ${result.outcome}${timing}${closeInfo}${result.error ? ` -- ${result.error}` : ''}${failInfo}`)
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
