'use strict'

const { TransferError } = require('./errors')

// The attempt cap (PROTOCOL.md section 6).
//
// WHAT v2 NEEDS THIS FOR. v1's secret had to defend a public hash: the
// topic was hash(code || salt), so an attacker who scraped a topic could
// grind candidates offline at whatever rate its hardware allowed, and no
// amount of counting by a peer would have slowed it down. Under v2 the
// topic commits only to the nameplate and the secret is a PAKE password,
// so a guess costs a live protocol run against a peer -- which means
// counting those runs is, for the first time, the thing that bounds an
// attacker. ~38.8 bits of secret is ample against 100 guesses and nothing at
// all against unlimited ones.
//
// THIS DELIBERATELY REVERSES A v1 RULE, and it is worth being explicit
// because the old rule is still written down elsewhere. v1 held that an
// attacker must not be able to end a drop by connecting and failing, and
// engine/src/swarm.js therefore discards a failed candidate and keeps
// waiting. Under v2 a nameplate-holder CAN end a drop, after 100 failed
// guesses. Accepted deliberately per section 6 and THREAT-MODEL.md section
// 5.3: the alternative is unlimited guessing against ~38.8 bits, and a
// denial of service is a better failure than a silent compromise. The
// human is told what happened, which is what makes it a report rather
// than a mystery.
//
// WHAT IS COUNTED, AND -- MORE IMPORTANTLY -- WHAT IS NOT.
//
// Counted: a PAKE confirmation failure; a repeated `sid` from a peer for
// the same nameplate (section 3.2's mitigation for a receiver-chosen sid,
// which is why that choice is acceptable at all); and, on the sender, any
// run that was sent REPLY and did not answer it with a valid CONFIRM.
//
// THE THIRD ONE IS NOT NETWORK NOISE, although it can look like it. REPLY
// carries confirmS, which lets whoever reads it test one candidate secret
// offline. A run that read REPLY and then hung up, went quiet or was reset
// has been handed that test whatever happened next, and before this was
// counted a guesser could repeat it with no limit and no backoff
// (PROTOCOL.md section 12.5, step 4). The receiver has no equivalent: it
// sends nothing derived from K until confirmS has verified.
//
// NOT counted: anything else, and in particular never a dropped
// candidate. Stale DHT announces routinely produce dead candidates -- a
// DHT announce outlives the process that made it, and measured in this
// repo, three of them were once enough to starve every connection slot --
// so counting them would let the DHT's own garbage burn a legitimate drop.
// That is not a hypothetical: it is the failure mode engine/src/swarm.js's
// MAX_PARALLEL exists to survive. A cap that fires on network noise is
// worse than no cap, because it converts an intermittent transport problem
// into a permanent one and blames the wrong thing. A dead candidate never
// sends a well-formed HELLO, so it never receives REPLY, and the third
// counted case does not reach it.

// Section 6's number.
const MAX_ATTEMPTS = 100

// Exponential backoff, applied as a DELAY BEFORE ANSWERING rather than as
// a refusal to talk.
//
// That distinction is the whole design of this part. Refusing new
// candidates during a backoff window would discard the legitimate peer
// along with the attacker -- and the legitimate peer is the one that
// cannot simply retry a thousand times. Delaying our own next message
// slows a guesser (each guess needs our HELLO, or our REPLY) while a real
// peer merely waits a moment longer.
//
// The cap on the delay is chosen against two budgets, not picked for
// roundness: it must stay below HANDSHAKE_TIMEOUT_MS (15 s, so a delayed
// candidate still has time to finish) and comfortably below the receiver's
// 30 s join budget (so a legitimate sender arriving mid-attack is not
// timed out by our own defence). 5 s satisfies both.
//
// Reaching the cap takes about seven failures; 100 attempts then cost an
// attacker on the order of eight minutes of wall clock, on top of a hole
// punch and a CPace run each. The point is not to make guessing impossible
// -- the count does that -- but to stop 100 guesses being free.
const BASE_DELAY_MS = 50
const MAX_DELAY_MS = 5000

// The seen-sid set is BOUNDED, or this module is itself a memory DoS --
// which would be a particular embarrassment in the one file whose job is
// resisting abuse. A peer can open connections cheaply and each one
// carries a fresh sid, so an unbounded set grows with attacker effort
// rather than with anything legitimate.
//
// The honest cost of bounding it: once the set is full, the oldest sid is
// evicted, and a repeat of an evicted value goes undetected. That is
// acceptable because the set only has to outlive a plausible attack
// window, and 1024 entries is an order of magnitude more than the 100
// attempts the cap permits before burning the drop anyway. An attacker who
// cycles more than 1024 distinct sids to evade this has spent more than
// the cap allows in the process.
const MAX_REMEMBERED_SIDS = 1024

// A reused sid, as a per-candidate discard reason. Like
// ERR_PAKE_CONFIRMATION (./handshake.js) this is NOT in section 10's
// table, and for the same reason: it says why one candidate was dropped,
// not how the drop ended. What the drop reports is ERR_NO_HANDSHAKE, or
// ERR_ATTEMPT_CAP once enough of these have accumulated.
const ERR_SID_REUSED = 'ERR_SID_REUSED'

/**
 * @param {Buffer} sid
 * @returns {Error & { code: string }}
 */
function sidReusedError (sid) {
  const err = /** @type {Error & { code: string }} */ (new Error(
    `reused the session id ${sid.toString('hex').slice(0, 8)}... on this nameplate, ` +
    'which a correct peer never does: a sid is sampled fresh per connection. ' +
    'Either a peer is replaying a session, or its build has a scalar-reuse bug ' +
    '(draft section 9.9 makes that a MUST NOT). Counted as a failed attempt'
  ))
  err.code = ERR_SID_REUSED
  return err
}

// A run that was sent REPLY and ended without a valid CONFIRM, as a
// per-candidate discard reason. Not in section 10's table, for the reason
// ERR_SID_REUSED is not.
const ERR_REPLY_UNANSWERED = 'ERR_REPLY_UNANSWERED'

/**
 * @param {any} [cause] how the run actually ended: a reset, a close, the
 *   per-candidate deadline
 * @returns {Error & { code: string }}
 */
function replyUnansweredError (cause) {
  const how = cause && cause.message ? cause.message : 'closed'
  const err = /** @type {Error & { code: string }} */ (new Error(
    `read our REPLY and did not confirm (${how}). REPLY lets a peer test one ` +
    'guess at the secret, so this counts as a failed attempt. A real receiver ' +
    'whose connection was replaced by a duplicate can cost one too'
  ))
  err.code = ERR_REPLY_UNANSWERED
  if (cause !== undefined) err.cause = cause
  return err
}

/**
 * @param {number} attempts
 * @returns {InstanceType<typeof TransferError>}
 */
function attemptCapError (attempts) {
  return new TransferError(
    'ERR_ATTEMPT_CAP',
    `the drop was burned after ${attempts} failed attempts to confirm the secret. ` +
    'Somebody was guessing: this code is spent and must not be reused. Generate a ' +
    'new one and hand it over by a route the guesser does not have',
    { attempts, max: MAX_ATTEMPTS }
  )
}

// One drop's worth of counting. Constructed per join, so "burn the drop"
// means "this instance is exhausted" and nothing outlives the drop it
// belongs to.
class AttemptCap {
  /**
   * @param {{ max?: number, baseDelayMs?: number, maxDelayMs?: number, maxSids?: number }} [options]
   *   Overridable for tests only. The defaults are section 6's, and a
   *   caller that lowers `max` in production has removed the defence.
   */
  constructor ({
    max = MAX_ATTEMPTS,
    baseDelayMs = BASE_DELAY_MS,
    maxDelayMs = MAX_DELAY_MS,
    maxSids = MAX_REMEMBERED_SIDS
  } = {}) {
    this._max = max
    this._baseDelayMs = baseDelayMs
    this._maxDelayMs = maxDelayMs
    this._maxSids = maxSids
    this._attempts = 0
    this._pending = 0
    // Insertion-ordered, so eviction is FIFO for free: a JavaScript Set
    // iterates in insertion order, and the oldest entry is the first one
    // its iterator yields.
    /** @type {Set<string>} */
    this._sids = new Set()
  }

  /** @returns {number} how many countable failures have happened */
  get attempts () {
    return this._attempts
  }

  /** @returns {boolean} true once the drop is burned */
  get exhausted () {
    return this._attempts >= this._max
  }

  /**
   * How long to wait before answering the next peer, in milliseconds.
   *
   * @returns {number} 0 while nothing has failed
   */
  delayMs () {
    if (this._attempts === 0) return 0
    return Math.min(this._maxDelayMs, this._baseDelayMs * 2 ** (this._attempts - 1))
  }

  /**
   * Records one countable failure.
   *
   * @returns {boolean} true if this was the one that burned the drop
   */
  fail () {
    this._attempts++
    return this.exhausted
  }

  /** @returns {number} runs charged by `charge()` and not yet settled */
  get pending () {
    return this._pending
  }

  /**
   * Reserves an attempt before revealing a confirmation, which on the
   * sender means before writing REPLY. Settle it with `settle()`.
   *
   * WHY RESERVE RATHER THAN COUNT AFTERWARDS. Counting when a run ends lets
   * every run still in flight read its REPLY first: measured over
   * FakeSwarm, 301 guessers connecting at once all read REPLY before the
   * first hang-up was counted, against a cap of 100. Reserving first means
   * no more than `max` confirmations ever reach peers that do not confirm
   * back. A reservation is refused, not counted, when there is no room:
   * that peer is sent nothing and has tested nothing.
   *
   * Reservations do not feed `delayMs()`. Only settled failures do, so a
   * real receiver's duplicate connection, which is in flight alongside the
   * one that will confirm, is not slowed down by it.
   *
   * @returns {boolean} false if failures and reservations already fill the cap
   */
  charge () {
    if (this._attempts + this._pending >= this._max) return false
    this._pending++
    return true
  }

  /**
   * Settles a reservation from `charge()`. Call exactly once per charge.
   *
   * @param {boolean} confirmed true if the peer answered with a valid
   *   confirmation, which releases the reservation uncounted
   * @returns {boolean} true if this settlement burned the drop
   */
  settle (confirmed) {
    this._pending--
    return confirmed ? false : this.fail()
  }

  /**
   * Has this `sid` been seen before on this drop?
   *
   * Section 3.2's second mitigation for a receiver-chosen sid, and the
   * reason that choice is acceptable: a jointly contributed sid would cost
   * an extra round trip, which section 3.1 shows is load-bearing for
   * Hyperswarm's duplicate tie-break. So the sender remembers instead, and
   * a repeat becomes expensive rather than invisible.
   *
   * Note what a repeat does and does not mean. It is not proof of an
   * attack -- a 16-byte CSPRNG value repeating by chance is not going to
   * happen, but a buggy peer reusing one would land here too. Either way
   * it is a peer doing something a correct one never does, so counting it
   * is right and the reported reason says "reused", not "attacked".
   *
   * @param {Buffer} sid
   * @returns {boolean} true if it is a repeat
   */
  seenSid (sid) {
    const key = sid.toString('hex')
    if (this._sids.has(key)) return true

    if (this._sids.size >= this._maxSids) {
      // Evict the oldest. See MAX_REMEMBERED_SIDS for why this is bounded
      // at all and what the eviction costs.
      const oldest = this._sids.values().next().value
      if (oldest !== undefined) this._sids.delete(oldest)
    }
    this._sids.add(key)
    return false
  }

  /**
   * The error to fail the drop with. Separate from `fail()` so the caller
   * decides when to reject -- swarm.js has listeners and timers to unwind
   * first, and throwing from inside a counter would skip that.
   *
   * @returns {InstanceType<typeof TransferError>}
   */
  error () {
    return attemptCapError(this._attempts)
  }
}

module.exports = {
  AttemptCap,
  attemptCapError,
  sidReusedError,
  replyUnansweredError,
  ERR_SID_REUSED,
  ERR_REPLY_UNANSWERED,
  MAX_ATTEMPTS,
  BASE_DELAY_MS,
  MAX_DELAY_MS,
  MAX_REMEMBERED_SIDS
}
