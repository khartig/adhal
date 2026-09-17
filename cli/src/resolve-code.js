'use strict'

// Turns whatever a human put on the command line into a topic, and is the
// single place in the CLI that is allowed to call topicFromCode.
//
// The reason this exists rather than each script calling parseCode itself:
// two kinds of string legitimately reach these scripts. Item 3's six-word
// codes are one. The other is the opaque throwaway secret -- the
// `crypto.randomBytes(8).toString('hex')` in demo-swarm.js, or a
// hand-typed 'quay-test-3' while reproducing a network measurement -- and
// those have to keep working, because the engine/scratch-*.js diagnostics
// and the item-2 tests are built on them.
//
// Choosing between them by *shape* rather than by "try the strict parse and
// fall back" is the point. A silent fallback would take a code with one
// mistyped word, treat it as an opaque secret, hash it to a perfectly
// valid but entirely wrong topic, and produce a peer-discovery timeout --
// indistinguishable from the announce-propagation races documented in
// engine/src/swarm.js, and the single most expensive class of bug to
// misattribute in this codebase.

const { parseCode, topicFromCode, WORD_COUNT, QR_SCHEME } = require('@quay/engine')

// Does this look like an *attempt* at a six-word code? If so we hold it to
// the strict parse and report which word is wrong, instead of quietly
// accepting it as an opaque secret.
function looksLikeWordCode (input) {
  if (new RegExp(`^${QR_SCHEME}:`, 'i').test(input.trim())) return true
  const tokens = input.trim().toLowerCase().split(/[\s\-_.]+/).filter(Boolean)
  return tokens.length === WORD_COUNT && tokens.every((t) => /^[a-z]+$/.test(t))
}

/**
 * @param {string} input
 * @returns {{ code: string, topic: Buffer, kind: 'words' | 'opaque' }}
 *   `code` is the canonical form for a word code, or the input verbatim for
 *   an opaque one. Both peers must pass the *same* thing here, which for
 *   word codes is what parseCode guarantees across case and separators.
 */
function resolveCode (input) {
  if (looksLikeWordCode(input)) {
    const code = parseCode(input) // throws, naming the offending word
    return { code, topic: topicFromCode(code), kind: 'words' }
  }

  const code = input.trim()
  if (code.length === 0) throw new Error('code is empty')
  return { code, topic: topicFromCode(code), kind: 'opaque' }
}

module.exports = { resolveCode, looksLikeWordCode }
