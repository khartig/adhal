'use strict'

// Turns whatever a human typed into a topic, and is the one place any
// entry point should call to do that. Nothing outside this module should
// reach for topicFromCode directly.
//
// The reason this exists rather than each script calling parseCode itself:
// two kinds of string legitimately reach those scripts. Generated six-word
// codes are one. The other is the opaque throwaway secret -- the
// `crypto.randomBytes(8).toString('hex')` in demo-swarm.js, or a
// hand-typed 'quay-test-3' while reproducing a network measurement -- and
// those have to keep working, because the engine/scratch-*.js diagnostics
// and the swarm tests are built on them.
//
// Choosing between them by *shape* rather than by "try the strict parse and
// fall back" is the point. A silent fallback would take a code with one
// mistyped word, treat it as an opaque secret, hash it to a perfectly
// valid but entirely wrong topic, and produce a peer-discovery timeout --
// indistinguishable from the announce-propagation races documented in
// engine/src/swarm.js, and the single most expensive class of bug to
// misattribute in this codebase.

const { parseCode, WORD_COUNT, QR_SCHEME } = require('./code')
const { topicFromCode } = require('./topic')

// Does this look like an *attempt* at a six-word code? If so we hold it to
// the strict parse and report which word is wrong, instead of quietly
// accepting it as an opaque secret.
function looksLikeWordCode (input) {
  if (new RegExp(`^${QR_SCHEME}:`, 'i').test(input.trim())) return true
  const tokens = input.trim().toLowerCase().split(/[\s\-_.]+/).filter(Boolean)
  return tokens.length === WORD_COUNT && tokens.every((t) => /^[a-z]+$/.test(t))
}

// OPAQUE CODES ARE NOW OPT-IN, and the reason is that they are the only
// way this engine can be handed a weak secret.
//
// A generated word code carries ~62 bits (five or six words from a 1295-
// word list). An opaque code carries whatever the caller typed, and the
// real ones in this repo's history include `quay-test-3`. Both are hashed
// into a topic the receiver must announce publicly, and both derive the
// drop key -- so an opaque code is dictionary-attackable in exactly the
// way a word code is not, and nothing downstream can tell the difference.
//
// They stay, because the diagnostics in engine/scratch-*.js and several
// tests are built on being able to name a topic by hand, and removing
// that would cost more than it buys. What changes is that a caller has to
// ASK for one. No product surface can reach this path by accident, which
// is the actual failure mode: `swarm-send.js <whatever you typed>` used
// to accept any string at all as a drop code, silently.
function allowOpaqueByDefault () {
  return process.env.QUAY_UNSAFE_OPAQUE === '1'
}

/**
 * @param {string} input
 * @param {{ allowOpaque?: boolean }} [options]
 *   `allowOpaque` defaults to the QUAY_UNSAFE_OPAQUE=1 environment
 *   variable, so a diagnostic session can be opted in once rather than
 *   per call. The CLIs expose it as `--unsafe-opaque`.
 * @returns {{ code: string, topic: Buffer, kind: 'words' | 'opaque' }}
 *   `code` is the canonical form for a word code, or the input verbatim for
 *   an opaque one. Both peers must pass the *same* thing here, which for
 *   word codes is what parseCode guarantees across case and separators.
 */
function resolveCode (input, { allowOpaque = allowOpaqueByDefault() } = {}) {
  if (looksLikeWordCode(input)) {
    const code = parseCode(input) // throws, naming the offending word
    return { code, topic: topicFromCode(code), kind: 'words' }
  }

  const code = input.trim()
  if (code.length === 0) throw new Error('code is empty')
  if (!allowOpaque) {
    throw new Error(
      `${JSON.stringify(code)} is not a ${WORD_COUNT}-word drop code. Codes are generated, not ` +
      'chosen: run the receiver with no argument and it will print one. ' +
      'If you meant to use an arbitrary string as a topic -- which is ' +
      'dictionary-attackable and only appropriate for diagnostics -- pass ' +
      '--unsafe-opaque or set QUAY_UNSAFE_OPAQUE=1.'
    )
  }
  return { code, topic: topicFromCode(code), kind: 'opaque' }
}

module.exports = { resolveCode, looksLikeWordCode }
