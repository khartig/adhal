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
// hand-typed 'adhal-test-3' while reproducing a network measurement -- and
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

const { parseCode, splitCode, WORD_COUNT, SCHEME_FAMILY } = require('./code')
const { INDEX } = require('./wordlist')
const { topicFromNameplate } = require('./topic')

// v1's code length. Recognised for exactly one purpose: reporting the
// version skew by name. See looksLikeV1Code.
const V1_WORD_COUNT = 6

// Does this look like an *attempt* at a five-word code? If so we hold it to
// the strict parse and report which word is wrong, instead of quietly
// accepting it as an opaque secret.
//
// Any payload in this protocol's scheme family counts, not just the
// current version: an ADHAL3: payload is unmistakably an attempt at a word
// code, and routing it here is what lets parseCode report the version skew
// by name instead of letting it fall through and be hashed as an opaque
// topic.
function looksLikeWordCode (input) {
  const trimmed = input.trim()
  if (SCHEME_FAMILY.test(trimmed)) return true
  const tokens = trimmed.toLowerCase().split(/[\s\-_.]+/).filter(Boolean)
  return tokens.length === WORD_COUNT && tokens.every((t) => /^[a-z]+$/.test(t))
}

// Is this a v1 six-word code?
//
// NARROW ON PURPOSE. It is not enough for the token count to be wrong:
// a hand-typed diagnostic secret can be any shape, and several in this
// repo's history are two or three words ('adhal-test-3', 'acid-acorn').
// So this asks for exactly SIX tokens that are ALL in the word list --
// which a hand-typed string is not going to be by accident, and which a
// v1 generated code always is.
//
// WHY THIS EXISTS AT ALL, because it looks like a nicety and is not. A v1
// code otherwise falls through to the opaque branch, and the refusal
// there ends by suggesting --unsafe-opaque. Following that suggestion
// makes the whole six-word code both nameplate and secret, which
// publishes the secret inside the announced topic -- so the error message
// would be recommending the one action that voids v2's central property,
// to the one person most likely to take it: someone mid-upgrade with an
// old code still in their shell history.
function looksLikeV1Code (tokens) {
  return tokens.length === V1_WORD_COUNT && tokens.every((t) => INDEX.has(t))
}

// OPAQUE CODES ARE OPT-IN, and the reason is that they are the only way
// this engine can be handed a weak secret.
//
// A generated word code carries ~20.7 bits in its public nameplate and
// ~31.0 in its secret. An opaque code carries whatever the caller typed,
// and the real ones in this repo's history include `adhal-test-3`.
//
// They stay, because the diagnostics in engine/scratch-*.js and several
// tests are built on being able to name a topic by hand, and removing
// that would cost more than it buys. What changes is that a caller has to
// ASK for one. No product surface can reach this path by accident, which
// is the actual failure mode: `swarm-send.js <whatever you typed>` used
// to accept any string at all as a drop code, silently.
function allowOpaqueByDefault () {
  return process.env.ADHAL_UNSAFE_OPAQUE === '1'
}

/**
 * @param {string} input
 * @param {{ allowOpaque?: boolean }} [options]
 *   `allowOpaque` defaults to the ADHAL_UNSAFE_OPAQUE=1 environment
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

  // Lowercased, not merely trimmed, and this was a real bug rather than
  // tidying. The opaque code becomes the PAKE password, and
  // ./handshake.js requires a canonical secret -- so 'Adhal-Test-3'
  // resolved fine here and then threw a bare TypeError out of the join
  // advising the caller about "canonical form, as splitCode produces it",
  // naming a function that never runs on this path. A documented,
  // deliberately-supported diagnostic input was unusable, in a confusing
  // way.
  //
  // Lowercasing also removes the footgun v1 had here: v1's topicFromCode
  // hashed exactly what it was given, so 'Adhal-Test-3' on one machine and
  // 'adhal-test-3' on the other produced unrelated topics and a discovery
  // timeout -- which resolve-code.js's own header calls the most
  // expensive class of bug to misattribute in this codebase. Nothing
  // regresses: every opaque code that worked before was already
  // lowercase, and the ones that change were the ones that failed.
  //
  // Whitespace is NOT collapsed, deliberately: an opaque code is an
  // arbitrary string and collapsing separators is what would make two
  // distinct diagnostic topics silently the same. It is refused below
  // instead, where the message can say so.
  const code = input.trim().toLowerCase()
  if (code.length === 0) throw new Error('code is empty')

  // Reported before the opaque gate, and refused even when opaque codes
  // are allowed. A v1 code is not a topic someone chose; it is a code from
  // a build that no longer interoperates, and hashing it as an opaque
  // secret would put its secret half in the public topic while appearing
  // to work.
  const tokens = code.toLowerCase().split(/[\s\-_.]+/).filter(Boolean)
  if (looksLikeV1Code(tokens)) {
    throw new Error(
      `that is a ${V1_WORD_COUNT}-word code from before the v2 wire ` +
      `change; this build uses ${WORD_COUNT} words. It cannot be converted, because v2 ` +
      'derives its topic from only the first two words and feeds the rest to a PAKE. ' +
      'Redeploy both sides and generate a new code. Do NOT pass --unsafe-opaque to ' +
      'force this one through: that would make the whole code its own topic secret, ' +
      'which is exactly the offline-guessing exposure v2 removes.'
    )
  }

  if (!allowOpaque) {
    // THE INPUT IS NOT ECHOED, and it used to be. A stray separator turns
    // a valid code into a 6-token string that lands here, so this message
    // put all five words -- secret included -- on stderr, undoing
    // cli/src/read-code.js's whole reason for existing. The token count
    // is the diagnostic; the words are not.
    throw new Error(
      `that is not a ${WORD_COUNT}-word drop code (it has ${tokens.length} ` +
      'words or word-like parts). Codes are generated, not ' +
      'chosen: run the receiver with no argument and it will print one. ' +
      'If you meant to use an arbitrary string as a topic -- which is ' +
      'dictionary-attackable and only appropriate for diagnostics -- pass ' +
      '--unsafe-opaque or set ADHAL_UNSAFE_OPAQUE=1.'
    )
  }

  // Refused rather than silently mangled, for the reason the lowercasing
  // above does not extend to whitespace: an opaque code is an arbitrary
  // string, and collapsing its separators would make two distinct
  // diagnostic topics the same without saying so. The PAKE needs a
  // canonical secret, so this is the one shape that cannot be accepted.
  if (/\s/.test(code)) {
    throw new Error(
      'an opaque code may not contain whitespace: it is used directly as the ' +
      'PAKE secret, which must be canonical. Use hyphens instead ' +
      '(e.g. adhal-test-3).'
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
  // topic off the DHT holds hash("adhal-v2:topic" || secret) and can grind
  // candidates offline at full speed, which for 'adhal-test-3' is instant.
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
