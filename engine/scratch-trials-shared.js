'use strict'

// What engine/scratch-trials.js and tools/cli-trials.js must agree on, in
// one place. Two copies of any of this drift, and here a drift is not a
// style problem: two harnesses that derive codes differently, or bucket a
// failure differently, produce numbers that cannot be read side by side,
// and W14 is a side-by-side reading. Not part of the published engine:
// engine/package.json publishes `src` only.

const crypto = require('node:crypto')
const { WORD_COUNT } = require('./src')
const { WORDS } = require('./src/wordlist')

// Deterministic per-trial code: a real five-word drop code, derived from
// (seed, trial index) so that both roles compute the same one without
// exchanging anything.
//
// Rejection sampled rather than plain modulo, for the same reason
// generateCode uses crypto.randomInt: 7772 is not a power of two, so
// reducing a 16-bit window modulo 7772 would favor the front of the list.
// It does not matter much for a rendezvous label on a private topic, but a
// harness that quietly draws from a skewed distribution is not the thing to
// leave lying around in a repo whose codes are its security argument.
const SAMPLE_LIMIT = 65536 - (65536 % WORDS.length)

/**
 * @param {string} seed
 * @param {number} i the trial's index, from 0
 * @returns {string}
 */
function trialCode (seed, i) {
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

// The sender waits this long into each slot before dialing, so the
// receiver has announced first -- the lookup-before-announce race in
// engine/src/swarm.js is a real effect, and measuring it here would just be
// measuring our own starting order.
const SENDER_LEAD_MS = 10000
// Leave the tail of each slot free so a trial that runs long still tears
// down before the next slot opens.
const TEARDOWN_MS = 5000

// Align to a 5-minute boundary at least a minute out. Wide enough that two
// hosts started within the same few minutes pick the same schedule; the
// chosen value is printed so a mismatch is obvious rather than silent.
const ALIGN_MS = 300000

/**
 * The run's first slot: `--start-epoch` in seconds if given, otherwise the
 * next ALIGN_MS boundary at least a minute from `now`.
 * @param {string | number | undefined} startEpoch
 * @param {number} [now]
 */
function startMsFor (startEpoch, now = Date.now()) {
  return startEpoch !== undefined ? Number(startEpoch) * 1000 : Math.ceil((now + 60000) / ALIGN_MS) * ALIGN_MS
}

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

function percentile (sorted, p) {
  if (sorted.length === 0) return null
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))
  return sorted[idx]
}

/**
 * The Wilson score interval for `ok` successes in `n` trials, at 95%, as
 * fractions. A rate is published with it, never bare: at ten trials the
 * interval is too wide to tell two good tools apart (POSITIONING.md
 * section 4).
 * @param {number} ok
 * @param {number} n
 * @returns {{ low: number, high: number } | null}
 */
function wilson (ok, n) {
  if (n === 0) return null
  const z = 1.959963984540054
  const p = ok / n
  const denom = 1 + (z * z) / n
  const centre = p + (z * z) / (2 * n)
  const margin = z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n))
  return { low: Math.max(0, (centre - margin) / denom), high: Math.min(1, (centre + margin) / denom) }
}

module.exports = { trialCode, SENDER_LEAD_MS, TEARDOWN_MS, ALIGN_MS, startMsFor, OUTCOME_BY_CODE, percentile, wilson }
