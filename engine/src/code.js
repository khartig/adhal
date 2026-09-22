'use strict'

const crypto = require('crypto')
const { WORDS, INDEX } = require('./wordlist')

// The drop code: five words, and a QR encoding of the same payload.
//
// This module owns the drop code as a *value*: how one is generated, how a
// human-typed or QR-scanned string is turned back into one, how it splits
// into its two halves, and how it is rendered for a QR symbol. It
// deliberately knows nothing about topics, swarms, or terminals -- deriving
// a topic is topic.js's job (always from the nameplate; see below) and
// drawing the symbol is the CLI's.
//
// THE CODE HAS TWO HALVES UNDER v2, AND THAT IS THE WHOLE POINT OF THE
// FORMAT (PROTOCOL.md section 2):
//
//   acid-acorn-acre-acts-afar
//   ^^^^^^^^^^ nameplate      public; hashed into the DHT topic
//              ^^^^^^^^^^^^^^ secret; goes into the PAKE, hashed nowhere
//
// v1's topic was hash(code || salt), so announcing a topic published a
// commitment to the entire code and an attacker could grind candidates
// offline, without ever touching a peer. Under v2 the announced topic
// commits only to the nameplate, which is not a secret; the secret is the
// PAKE password and appears in no value an observer can obtain. Guessing it
// costs a live protocol run against a peer that is counting.
//
// So the code is SHORTER than v1's six words and STRONGER, because its
// entropy no longer has to defend a public hash. Note what that means for
// the two halves: a nameplate collision is a rendezvous accident (two drops
// on one topic, which the PAKE then separates), while the secret is the
// only thing whose entropy is load-bearing.

const WORD_COUNT = 5

// Nameplate first, secret second -- the order is fixed by the canonical
// form, not by a delimiter, so both sides slice at the same index without
// negotiating anything.
const NAMEPLATE_WORDS = 2
const SECRET_WORDS = 3

// Words are joined with '-' rather than spaces so the code survives being
// pasted into a chat message, a URL, or a shell argument without quoting.
// This is also why wordlist.js drops the one hyphenated EFF word.
const SEPARATOR = '-'

// The QR scheme carries a format version, so a payload that changes shape
// cannot be silently misread by a build that predates the change. v2 is
// exactly such a change -- five words where v1 had six, and a topic derived
// from two of them -- so the scheme moves with it. A QUAY1: payload can
// still be *recognised*, which is what lets parseCode say "older build"
// instead of "newer version"; see SCHEMES_BY_AGE.
const QR_SCHEME = 'QUAY2'

// Every scheme this build knows about, oldest first. The list exists so
// that an unknown scheme can be reported with a DIRECTION rather than a
// shrug: a version we know to be older means the *peer* needs updating
// ("redeploy both sides"), while anything unrecognised means *this* build
// is the old one. v1 conflated them and told a QUAY1: holder their code
// came from a newer version, which sends someone looking for an upgrade
// that does not exist.
const SCHEMES_BY_AGE = ['QUAY1', 'QUAY2']

// log2(1295) per word, split the way the format splits.
//
// ONE NUMBER CANNOT EXPRESS v2. v1 had a single CODE_ENTROPY_BITS of ~62,
// and it was meaningful because all 62 bits defended one thing: a public
// hash of the whole code. Under v2 the two halves defend different things
// against different attacks, so a combined figure would be actively
// misleading -- it would let ~51 bits look like the strength of a secret
// that carries ~31.
const NAMEPLATE_ENTROPY_BITS = NAMEPLATE_WORDS * Math.log2(WORDS.length)
const SECRET_ENTROPY_BITS = SECRET_WORDS * Math.log2(WORDS.length)

/**
 * A fresh drop code, e.g. 'acid-acorn-acre-acts-afar'.
 *
 * `crypto.randomInt` is used rather than `randomBytes` and a modulo,
 * because 1295 is not a power of two: reducing a random byte range modulo
 * 1295 would make the first words of the list measurably likelier than the
 * last. `randomInt` does the rejection sampling that avoids that bias.
 *
 * Repeated words are not filtered out. 'acid-acid-...' is a legitimate
 * draw, and excluding it would both shrink the keyspace and make the
 * generator's output distribution harder to reason about than the bias it
 * was meant to avoid.
 *
 * @returns {string}
 */
function generateCode () {
  const words = []
  for (let i = 0; i < WORD_COUNT; i++) {
    words.push(WORDS[crypto.randomInt(WORDS.length)])
  }
  return words.join(SEPARATOR)
}

/**
 * Normalizes anything a human or a camera might hand us into the one
 * canonical form -- lowercase, hyphen-separated, no scheme prefix. That
 * canonical string is the only thing that should ever reach `splitCode`:
 * the nameplate is hashed and the secret is a PAKE password, so
 * 'ACID-ACORN' and 'acid acorn' would otherwise land on two different
 * topics and the two peers would never find each other.
 *
 * Accepted, because all of these turn up in practice when a code is read
 * off another screen:
 *
 *   QUAY2:ACID-ACORN-ACRE-ACTS-AFAR   (as encoded in the QR)
 *   quay2:acid-acorn-acre-acts-afar
 *   acid-acorn-acre-acts-afar
 *   Acid Acorn Acre Acts Afar          (pasted from a chat client)
 *   acid_acorn.acre acts--afar         (mangled separators)
 *
 * @param {string} input
 * @returns {string} canonical code
 */
function parseCode (input) {
  if (typeof input !== 'string') {
    throw new TypeError('code must be a string')
  }

  let rest = input.trim()
  if (rest.length === 0) {
    throw new Error('code is empty')
  }

  // Strip an optional scheme prefix, and refuse a version we don't know
  // rather than trying to read it as words.
  const scheme = rest.match(/^([a-z][a-z0-9]*):/i)
  if (scheme) {
    const found = scheme[1].toUpperCase()
    if (found !== QR_SCHEME) {
      throw new Error(schemeSkewMessage(found))
    }
    rest = rest.slice(scheme[0].length)
  }

  // Any run of separator-ish characters splits words, so a code that lost
  // its hyphens to a line wrap or gained an underscore still parses.
  const words = rest.toLowerCase().split(/[\s\-_.]+/).filter((w) => w.length > 0)

  if (words.length !== WORD_COUNT) {
    // The count is the diagnostic. The words are NOT echoed: three of
    // them are the drop secret, this message reaches stderr, and
    // cli/src/read-code.js goes to real lengths to keep the code off the
    // screen and out of shell history. Echoing it on a typo would undo
    // that for the one input shape most likely to contain a typo.
    //
    // The sibling message below names the one word that is not in the
    // list, which is different: that word is by definition wrong, and
    // naming it is the difference between a one-character fix and
    // retyping the whole code off another device's screen.
    throw new Error(`expected ${WORD_COUNT} words, got ${words.length}`)
  }

  // Name the offending word and its position. This code was typed by hand
  // off another device's screen, so "word 3 is not in the list" is the
  // difference between a one-character fix and retyping the whole thing.
  words.forEach((word, i) => {
    if (!INDEX.has(word)) {
      throw new Error(`word ${i + 1} of ${WORD_COUNT}, "${word}", is not in the word list`)
    }
  })

  return words.join(SEPARATOR)
}

// Which way the version skew points, and it is the one thing this message
// has to get right. Telling the holder of an older payload that their code
// is from "a newer version" is worse than saying nothing: it sends them
// looking for an upgrade when the fix is to update the *other* machine.
/**
 * @param {string} found the scheme found, uppercased
 * @returns {string}
 */
function schemeSkewMessage (found) {
  const known = SCHEMES_BY_AGE.indexOf(found)
  const mine = SCHEMES_BY_AGE.indexOf(QR_SCHEME)
  if (known !== -1 && known < mine) {
    return `code format "${found}:" is older than this build reads (${QR_SCHEME}:) -- ` +
      'it was created by a build from before the v2 wire change. Redeploy both ' +
      'sides to the same version; the code itself cannot be converted, because ' +
      'v2 derives its topic from only part of it'
  }
  return `unrecognized code format "${found}:" -- this code may have been ` +
    `created by a newer version of Quay (this build reads ${QR_SCHEME}:)`
}

/**
 * Splits a code into its public half and its secret half.
 *
 * Runs `parseCode` first rather than trusting the caller to have done it.
 * That is not defensive tidying: the nameplate becomes a hash input and the
 * secret becomes a PAKE password, and a caller who passes 'ACID-ACORN...'
 * here gets a different topic *and* a different password, so the two peers
 * would find each other only if both made the same mistake. parseCode is
 * idempotent on canonical input, so this costs nothing where it is already
 * right.
 *
 * @param {string} code canonical or human-entered code
 * @returns {{ nameplate: string, secret: string }} both in canonical form
 */
function splitCode (code) {
  const words = parseCode(code).split(SEPARATOR)
  return {
    nameplate: words.slice(0, NAMEPLATE_WORDS).join(SEPARATOR),
    secret: words.slice(NAMEPLATE_WORDS).join(SEPARATOR)
  }
}

/**
 * True if `input` parses as a drop code. For callers that want to branch
 * rather than catch -- e.g. a UI that enables its "Receive" button only
 * once five valid words have been typed.
 *
 * @param {string} input
 * @returns {boolean}
 */
function isValidCode (input) {
  try {
    parseCode(input)
    return true
  } catch {
    return false
  }
}

/**
 * The string to encode into a QR symbol. This is exactly the typed code and
 * nothing else -- no public key, no manifest preview -- so that scanning
 * and typing are provably the same path instead of two paths to test.
 * `QR_SCHEME`'s version is what buys the room to change that decision
 * later.
 *
 * Uppercase is not cosmetic. QR's "alphanumeric" encoding mode covers only
 * 0-9, A-Z, space and $%*+-./: -- both ':' and '-' qualify, but lowercase
 * letters do not, and falling back to byte mode costs about 40% more
 * capacity for the same text. Uppercased, a five-word code is at most 35
 * characters, which fits a version-3 symbol (29x29 modules) while leaving
 * room for ECC level H -- byte mode would need version 5 for the same
 * error correction. See cli/src/qr.js for the measured table, and for why
 * v2's shorter code was spent on error correction rather than on a smaller
 * symbol. `parseCode` is case-insensitive, so the scanned result still
 * round-trips, and humans are shown lowercase.
 *
 * @param {string} code canonical or human-entered code
 * @returns {string}
 */
function encodeQrPayload (code) {
  return `${QR_SCHEME}:${parseCode(code).toUpperCase()}`
}

module.exports = {
  generateCode,
  parseCode,
  splitCode,
  isValidCode,
  encodeQrPayload,
  WORD_COUNT,
  NAMEPLATE_WORDS,
  SECRET_WORDS,
  SEPARATOR,
  QR_SCHEME,
  SCHEMES_BY_AGE,
  NAMEPLATE_ENTROPY_BITS,
  SECRET_ENTROPY_BITS
}
