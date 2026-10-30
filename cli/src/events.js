'use strict'

// The --json event stream: one JSON object per line, the contract in
// docs/CLI-CONTRACT.md section 3. One file for both swarm CLIs, for the
// reason report.js is one file: two copies of a schema drift, and the
// copy that drifts is the one a script was reading.
//
// WHAT THIS FILE GUARANTEES, and the tests in cli/test/json-events.test.js
// check: every line is a JSON object that parses, every object carries
// `v`, `event`, `ms`, and `role`, and a failure's `code` comes from
// `err.code`, never from its message (PROTOCOL.md section 10).
//
// Peer-chosen strings are passed through as the engine has them. JSON
// escapes the C0 controls; a consumer that displays a declared name or a
// peer's reason must escape the rest itself (CLI-CONTRACT.md section 3.4).

const { performance } = require('node:perf_hooks')
const { version } = require('../package.json')

// Bumped only by a breaking change: CLI-CONTRACT.md section 5.
const SCHEMA_VERSION = 1

// A progress event at most this often, plus one at the end. Fast enough
// for a wrapper's bar, slow enough that a local transfer at hundreds of
// chunks a second does not turn the stream into progress and nothing else.
const PROGRESS_MS = 250

// The error fields worth a script's attention, copied onto `failed` when
// the error has them. A list, not the whole error: `expected` and
// `actual` are useful, a stack is not, and an error the engine never
// built could carry anything.
const ERROR_FIELDS = ['phase', 'reportedBy', 'peerReason', 'declineCode', 'detail', 'field', 'attempts', 'max', 'limit', 'size', 'expected', 'actual', 'partial']

/**
 * The 12 hex characters the human lines show, from the candidate's
 * ephemeral public key.
 * @param {any} peerInfo
 * @returns {string | null}
 */
function peerId (peerInfo) {
  return peerInfo && peerInfo.publicKey ? peerInfo.publicKey.toString('hex').slice(0, 12) : null
}

/**
 * The `code` a failure is reported under: the error's own, except for a
 * consumer that closed its end of stdout, which has a CLI-level code of
 * its own (CLI-CONTRACT.md section 4).
 * @param {any} err
 * @returns {string | null}
 */
function failureCode (err) {
  if (!err) return null
  if (err.code === 'EPIPE') return 'ERR_OUTPUT_CLOSED'
  return typeof err.code === 'string' ? err.code : null
}

/**
 * @param {{
 *   role: 'send' | 'receive',
 *   stream?: { write: (chunk: string) => any },
 *   now?: () => number
 * }} options
 *   `now` is milliseconds since the process started, from a monotonic
 *   clock: performance.now() is exactly that.
 */
function createEventStream ({ role, stream = process.stdout, now = () => performance.now() }) {
  // Nothing moves before the offer is answered, but the engine reports 0
  // bytes as soon as it sets a transfer up, which on both sides is before
  // ACCEPT. Reported then, it would put `progress` ahead of `accepted`,
  // against the order CLI-CONTRACT.md section 3.2 gives.
  let accepted = false

  /**
   * @param {string} event
   * @param {Record<string, any>} [fields]
   */
  function emit (event, fields = {}) {
    if (event === 'accepted') accepted = true
    stream.write(`${JSON.stringify({ v: SCHEMA_VERSION, event, ms: Math.round(now()), role, ...fields })}\n`)
  }

  /** @type {number | null} */
  let lastAt = null
  /** @type {{ bytes: number, total: number | null } | null} */
  let unsent = null

  /** @param {{ bytes: number, total: number | null }} p */
  function onProgress ({ bytes, total }) {
    if (!accepted) return
    const at = now()
    const complete = total !== null && bytes >= total
    if (lastAt !== null && !complete && at - lastAt < PROGRESS_MS) {
      unsent = { bytes, total }
      return
    }
    lastAt = at
    unsent = null
    emit('progress', { bytes, total })
  }

  // The last count, if throttling held it back: a stream has no total to
  // be complete at, so its final count would otherwise never be sent.
  function flushProgress () {
    if (!unsent) return
    const last = unsent
    unsent = null
    emit('progress', last)
  }

  /**
   * The one `failed` event. `message` is the CLI's own sentence, already
   * escaped for a terminal.
   * @param {any} err
   * @param {string} message
   * @param {Record<string, any>} [extra]
   */
  function failed (err, message, extra = {}) {
    flushProgress()
    /** @type {Record<string, any>} */
    const fields = { code: failureCode(err), message }
    fields.bytes = err && typeof err.bytes === 'number' ? err.bytes : null
    for (const key of ERROR_FIELDS) {
      if (err && err[key] !== undefined) fields[key] = err[key]
    }
    emit('failed', { ...fields, ...extra })
  }

  return { emit, onProgress, flushProgress, failed }
}

module.exports = { createEventStream, peerId, failureCode, SCHEMA_VERSION, PROGRESS_MS, version }
