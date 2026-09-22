'use strict'

// Turns whatever a human typed into the three values a drop needs -- a
// topic to join, a nameplate to bind, and a secret to authenticate with --
// and is the one place any entry point should call to do that. Nothing
// outside this module should reach for topicFromNameplate directly.
//
// The reason this exists rather than each script calling parseCode itself:
// two kinds of string legitimately reach those scripts. Generated five-word
// codes are one. The other is the opaque throwaway secret -- the
// `crypto.randomBytes(8).toString('hex')` a diagnostic might use, or a
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

const { parseCode, splitCode, WORD_COUNT, SCHEMES_BY_AGE } = require('./code')
const { topicFromNameplate } = require('./topic')

// Does this look like an *attempt* at a five-word code? If so we hold it to
// the strict parse and report which word is wrong, instead of quietly
// accepting it as an opaque secret.
//
// Every scheme prefix we recognise counts, not just the current one: a
// QUAY1: payload is unmistakably an attempt at a word code, and routing it
// here is what lets parseCode report the version skew by name instead of
// letting it fall through and be hashed as an opaque topic.
function looksLikeWordCode (input) {
  const trimmed = input.trim()
  for (const scheme of SCHEMES_BY_AGE) {
    if (new RegExp(`^${scheme}:`, 'i').test(trimmed)) return true
  }
  const tokens = trimmed.toLowerCase().split(/[\s\-_.]+/).filter(Boolean)
  return tokens.length === WORD_COUNT && tokens.every((t) => /^[a-z]+$/.test(t))
}

// OPAQUE CODES ARE OPT-IN, and the reason is that they are the only way
// this engine can be handed a weak secret.
//
// A generated word code carries ~20.7 bits in its public nameplate and
// ~31.0 in its secret. An opaque code carries whatever the caller typed,
// and the real ones in this repo's history include `quay-test-3`.
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
 * @returns {{ code: string, nameplate: string, secret: string, topic: Buffer, kind: 'words' | 'opaque' }}
 *   `code` is the canonical form for a word code, or the input verbatim for
 *   an opaque one. Both peers must pass the *same* thing here, which for
 *   word codes is what parseCode guarantees across case and separators.
 *   `nameplate` is what the topic commits to; `secret` is what the PAKE
 *   authenticates with and must reach nothing else.
 */
function resolveCode (input, { allowOpaque = allowOpaqueByDefault() } = {}) {
  if (looksLikeWordCode(input)) {
    const code = parseCode(input) // throws, naming the offending word
    const { nameplate, secret } = splitCode(code)
    return { code, nameplate, secret, topic: topicFromNameplate(nameplate), kind: 'words' }
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

  // AN OPAQUE CODE IS ITS OWN NAMEPLATE *AND* ITS OWN SECRET, WHICH PUTS
  // THE SECRET INTO THE PUBLIC TOPIC AND SO REINTRODUCES EXACTLY THE
  // OFFLINE GRINDING TARGET v2 EXISTS TO REMOVE.
  //
  // Stated in those words because this is the one path where v2's central
  // property is deliberately voided, and it would otherwise be invisible:
  // the call looks identical to the word-code call above, and every
  // downstream module behaves the same way. An observer who scrapes this
  // topic off the DHT holds hash("quay-v2:topic" || secret) and can grind
  // candidates offline at full speed, which for 'quay-test-3' is instant.
  // The PAKE still runs and still works; it simply has nothing left to
  // protect, because the password is committed to in public.
  //
  // Acceptable only because this path is gated behind --unsafe-opaque and
  // documented as diagnostics-only. It must never acquire a product
  // surface. If one is ever wanted, the fix is a separate topic secret,
  // not a relaxation of the gate.
  return { code, nameplate: code, secret: code, topic: topicFromNameplate(code), kind: 'opaque' }
}

module.exports = { resolveCode, looksLikeWordCode }
