'use strict'

const crypto = require('crypto')
const { WORDS, INDEX } = require('./wordlist')

// Section 4, The drop code: six words plus a QR encoding of the same payload.
//
// This module owns the drop code as a *value*: how one is generated, how a
// human-typed or QR-scanned string is turned back into one, and how it is
// rendered for a QR symbol. It deliberately knows nothing about topics,
// swarms, or terminals -- deriving a topic is topic.js's job (always from
// the canonical form; see below) and drawing the symbol is the CLI's.

const WORD_COUNT = 6

// Words are joined with '-' rather than spaces so the code survives being
// pasted into a chat message, a URL, or a shell argument without quoting.
// This is also why wordlist.js drops the one hyphenated EFF word.
const SEPARATOR = '-'

// The QR scheme carries a format version, so a future payload that adds
// fields (a peer public key for direct dial, say -- plan section 9 spike 5)
// can be introduced without old clients silently misreading it. An old
// client seeing QUAY2: says "newer version" instead of guessing.
const QR_SCHEME = 'QUAY1'

// log2(1295) * 6. Recorded because it is the number that justifies not
// bothering with a longer code: a drop topic is short-lived and, from item
// 4 onward, guarded by challenge-response, so 62 bits is far past the
// point where guessing is the weak link.
const CODE_ENTROPY_BITS = WORD_COUNT * Math.log2(WORDS.length)

/**
 * A fresh drop code, e.g. 'acid-acorn-acre-acts-afar-agent'.
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
 * canonical string is the only thing that should ever reach
 * `topicFromCode`: the topic is a hash, so 'ACID-ACORN' and 'acid acorn'
 * would otherwise land on two different topics and the two peers would
 * never find each other.
 *
 * Accepted, because all of these turn up in practice when a code is read
 * off another screen:
 *
 *   QUAY1:ACID-ACORN-ACRE-ACTS-AFAR-AGENT   (as encoded in the QR)
 *   quay1:acid-acorn-acre-acts-afar-agent
 *   acid-acorn-acre-acts-afar-agent
 *   Acid Acorn Acre Acts Afar Agent          (pasted from a chat client)
 *   acid_acorn.acre acts--afar-agent         (mangled separators)
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
    if (scheme[1].toUpperCase() !== QR_SCHEME) {
      throw new Error(
        `unrecognized code format "${scheme[1]}:" -- this code may have been ` +
        `created by a newer version of Quay (this build reads ${QR_SCHEME}:)`
      )
    }
    rest = rest.slice(scheme[0].length)
  }

  // Any run of separator-ish characters splits words, so a code that lost
  // its hyphens to a line wrap or gained an underscore still parses.
  const words = rest.toLowerCase().split(/[\s\-_.]+/).filter((w) => w.length > 0)

  if (words.length !== WORD_COUNT) {
    throw new Error(
      `expected ${WORD_COUNT} words, got ${words.length}` +
      (words.length > 0 ? ` (${words.join(SEPARATOR)})` : '')
    )
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

/**
 * True if `input` parses as a drop code. For callers that want to branch
 * rather than catch -- e.g. a UI that enables its "Receive" button only
 * once six valid words have been typed.
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
 * The string to encode into a QR symbol. Per plan section 9 spike 5, this
 * is exactly the typed code and nothing else -- no public key, no manifest
 * preview -- so that scanning and typing are provably the same path
 * instead of two paths to test. `QR_SCHEME`'s version digit is what buys
 * the room to change that decision later.
 *
 * Uppercase is not cosmetic. QR's "alphanumeric" encoding mode covers only
 * 0-9, A-Z, space and $%*+-./: -- both ':' and '-' qualify, but lowercase
 * letters do not, and falling back to byte mode costs about 40% more
 * capacity for the same text. Uppercased, a six-word code is at most 41
 * characters, which fits a version-3 symbol (29x29 modules) while leaving
 * room for ECC level Q -- byte mode would need version 4 for the same
 * error correction. See cli/src/qr.js for the measured table and why that
 * headroom is spent on error correction rather than on a smaller symbol.
 * `parseCode` is case-insensitive, so the scanned result still
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
  isValidCode,
  encodeQrPayload,
  WORD_COUNT,
  SEPARATOR,
  QR_SCHEME,
  CODE_ENTROPY_BITS
}
