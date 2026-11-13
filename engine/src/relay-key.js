'use strict'

// A relay is named by its hyperdht public key: 32 bytes, the key the relay's
// DHT server listens under. hyperdht reaches the relay with that key alone
// (`dht.connect(publicKey)`, lib/connect.js and lib/server.js, 6.36.0), so
// the key is the whole of what a user configures. It is not a secret: a
// relay announces it to be reachable, and anyone holding it can use the relay.
//
// Two spellings are accepted, because relays print one or the other:
// 64 hex characters, and 52 characters of z-base-32, which is what
// hypercore-id-encoding (and so most Holepunch tooling) prints. z-base-32
// is decoded here rather than by adding a dependency for 20 lines
// (DEPENDENCY-POLICY.md); cli/test/relay.test.js checks it against the
// z32 package hyperdht depends on.

const Z32_ALPHABET = 'ybndrfg8ejkmcpqxot1uwisza345h769'

/**
 * @param {string} text
 * @returns {Buffer | null} null when `text` is not 52 characters of z-base-32
 *   that encode exactly 32 bytes
 */
function decodeZ32Key (text) {
  if (text.length !== 52) return null
  const out = Buffer.alloc(32)
  let bits = 0
  let value = 0
  let index = 0
  for (const ch of text) {
    const digit = Z32_ALPHABET.indexOf(ch)
    if (digit === -1) return null
    value = (value << 5) | digit
    bits += 5
    if (bits >= 8) {
      bits -= 8
      out[index++] = (value >>> bits) & 0xff
    }
    value &= (1 << bits) - 1
  }
  // 52 digits are 260 bits: 256 of key and 4 of padding, which an encoder
  // writes as zero. Nonzero padding is a different string for the same key,
  // or a typo, and is refused rather than guessed at.
  if (index !== 32 || value !== 0) return null
  return out
}

/**
 * The relay key a user typed, as the 32 bytes hyperdht wants.
 * @param {string} text 64 hex characters, or 52 of z-base-32
 * @returns {Buffer}
 */
function parseRelayKey (text) {
  if (typeof text !== 'string') throw new TypeError('a relay key must be a string')
  const trimmed = text.trim()
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) return Buffer.from(trimmed, 'hex')
  const z32 = decodeZ32Key(trimmed.toLowerCase())
  if (z32) return z32
  throw new TypeError(
    `a relay key is the relay's 32-byte public key, as 64 hex characters or 52 of z-base-32; got ${trimmed.length} characters that are neither`
  )
}

module.exports = { parseRelayKey }
