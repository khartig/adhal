'use strict'

// The v2 wire format, written a second time, for the harness to speak.
//
// WHY NOT REQUIRE @ad-hal/engine. The harness judges an implementation by
// what it puts on the wire. If its own side of the conversation came from
// engine/src, then running it against the engine would be the engine
// agreeing with itself, which is self-consistency and not conformance --
// the distinction cli/test/cpace-vectors.test.js opens with. So nothing
// here imports the engine. Everything is built from PROTOCOL.md and from
// node:crypto: X25519, SHA-512, HKDF-SHA256, HMAC-SHA256, and
// ChaCha20-Poly1305 are all Node's, not @noble's, which makes them a
// different implementation of each primitive from the one the engine uses.
//
// THE ONE THING BORROWED is the Elligator2 map, from @noble/curves at the
// version the engine pins. Writing it again would be hand-rolling the one
// piece of curve arithmetic the project decided not to (PROTOCOL.md section
// 8.1), and the map is checked here the same way it is checked there:
// conformance/test/wire.test.js runs this file against every published
// vector, the CFRG ones included. A wrong map fails the generator vector.
//
// THE ONE THING WRITTEN FROM SCRATCH is BLAKE2b, for section 2's topic.
// Node ships blake2b512 and blake2s256, and BLAKE2b-256 is neither: the
// output length is in BLAKE2b's parameter block, so a truncated
// blake2b512 is a different hash. It is here, from RFC 7693, so that
// code.json's topics are reproduced by a second implementation too. At a
// 64-byte output it must agree with Node's blake2b512 on any input, which
// is how conformance/test/wire.test.js checks the compression function.
//
// Otherwise only what the harness needs is here. There is no code parsing:
// the harness is handed a nameplate and a secret, and discovery is outside
// what a byte stream can test.

const crypto = require('node:crypto')
const { _map_to_curve_elligator2_curve25519: mapToCurveElligator2 } = require('@noble/curves/ed25519.js')

// --- section 2: the topic, over BLAKE2b (RFC 7693) -------------------------

const MASK64 = (1n << 64n) - 1n
const BLAKE2B_IV = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n
]
// Rounds 10 and 11 reuse the first two rows (RFC 7693 section 2.7).
const SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]
]
const BLOCK = 128

const rotr64 = (/** @type {bigint} */ x, /** @type {bigint} */ n) => ((x >> n) | (x << (64n - n))) & MASK64

/**
 * F, the compression function (RFC 7693 section 3.2).
 * @param {bigint[]} h @param {Buffer} block @param {bigint} t bytes so far @param {boolean} last
 */
function compress (h, block, t, last) {
  const m = Array.from({ length: 16 }, (_, i) => block.readBigUInt64LE(i * 8))
  const v = [...h, ...BLAKE2B_IV]
  v[12] ^= t & MASK64
  v[13] ^= t >> 64n
  if (last) v[14] ^= MASK64
  /** @param {number} a @param {number} b @param {number} c @param {number} d @param {bigint} x @param {bigint} y */
  const G = (a, b, c, d, x, y) => {
    v[a] = (v[a] + v[b] + x) & MASK64
    v[d] = rotr64(v[d] ^ v[a], 32n)
    v[c] = (v[c] + v[d]) & MASK64
    v[b] = rotr64(v[b] ^ v[c], 24n)
    v[a] = (v[a] + v[b] + y) & MASK64
    v[d] = rotr64(v[d] ^ v[a], 16n)
    v[c] = (v[c] + v[d]) & MASK64
    v[b] = rotr64(v[b] ^ v[c], 63n)
  }
  for (let r = 0; r < 12; r++) {
    const s = SIGMA[r % 10]
    G(0, 4, 8, 12, m[s[0]], m[s[1]])
    G(1, 5, 9, 13, m[s[2]], m[s[3]])
    G(2, 6, 10, 14, m[s[4]], m[s[5]])
    G(3, 7, 11, 15, m[s[6]], m[s[7]])
    G(0, 5, 10, 15, m[s[8]], m[s[9]])
    G(1, 6, 11, 12, m[s[10]], m[s[11]])
    G(2, 7, 8, 13, m[s[12]], m[s[13]])
    G(3, 4, 9, 14, m[s[14]], m[s[15]])
  }
  for (let i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8]
}

/**
 * Unkeyed BLAKE2b with an output of `outlen` bytes (RFC 7693 section 3.3).
 * @param {Buffer} data @param {number} outlen 1 to 64
 */
function blake2b (data, outlen) {
  if (!Number.isInteger(outlen) || outlen < 1 || outlen > 64) throw new RangeError('outlen must be 1 to 64')
  const h = [...BLAKE2B_IV]
  h[0] ^= 0x01010000n ^ BigInt(outlen)
  // The last block is compressed with the final flag set, even when the
  // input fills it exactly, and an empty input is one block of zeros.
  const blocks = Math.max(1, Math.ceil(data.length / BLOCK))
  for (let i = 0; i < blocks - 1; i++) {
    compress(h, data.subarray(i * BLOCK, (i + 1) * BLOCK), BigInt((i + 1) * BLOCK), false)
  }
  const tail = Buffer.alloc(BLOCK)
  data.copy(tail, 0, (blocks - 1) * BLOCK)
  compress(h, tail, BigInt(data.length), true)
  const out = Buffer.alloc(64)
  h.forEach((word, i) => out.writeBigUInt64LE(word, i * 8))
  return out.subarray(0, outlen)
}

const TOPIC_LABEL = 'adhal-v2:topic'

/** topic = BLAKE2b-256(lv_cat("adhal-v2:topic", nameplate)). @param {string} nameplate */
const topic = (nameplate) => blake2b(lvCat(utf8(TOPIC_LABEL), utf8(nameplate)), 32)

// --- section 3.2: CPace255 and the parameter mapping ----------------------

const DSI = 'CPace255'
const DSI_ISK = 'CPace255_ISK'
const S_IN_BYTES = 128
const P = 2n ** 255n - 19n

const VERSION = 0x02
const SID_SIZE = 16
const ELEMENT_SIZE = 32
const CONFIRM_SIZE = 32
const MAX_CAPS_BYTES = 128
const KNOWN_CAPS = ['resume', 'stream']
const CAPS_TOKEN = /^[a-z0-9]([a-z0-9-]{0,14}[a-z0-9])?$/

// HELLO = [len][version 1][sid 16][Ya 32][caps_r], REPLY = [len][Yb 32]
// [confirmS 32][caps_s]: the body bounds section 3.1 states.
const HELLO_FIXED = 1 + SID_SIZE + ELEMENT_SIZE
const REPLY_FIXED = ELEMENT_SIZE + CONFIRM_SIZE
const HELLO_BODY = { min: HELLO_FIXED, max: HELLO_FIXED + MAX_CAPS_BYTES }
const REPLY_BODY = { min: REPLY_FIXED, max: REPLY_FIXED + MAX_CAPS_BYTES }

const LABELS = {
  CI: 'adhal-v2',
  mac: 'adhal-v2:mac',
  r2s: 'adhal-v2:r2s',
  s2r: 'adhal-v2:s2r',
  confirmS: 'adhal-v2:confirm-s',
  confirmR: 'adhal-v2:confirm-r'
}

const utf8 = (/** @type {string} */ s) => Buffer.from(s, 'utf8')

/**
 * prepend_len: the length as unsigned LEB128, then the bytes.
 * @param {Buffer} data
 */
function prependLen (data) {
  const prefix = []
  let n = data.length
  do {
    let byte = n & 0x7f
    n = Math.floor(n / 128)
    if (n > 0) byte |= 0x80
    prefix.push(byte)
  } while (n > 0)
  return Buffer.concat([Buffer.from(prefix), data])
}

/** @param {...Buffer} parts */
const lvCat = (...parts) => Buffer.concat(parts.map(prependLen))

/**
 * @param {Buffer} PRS
 * @param {Buffer} CI
 * @param {Buffer} sid
 */
function generatorString (PRS, CI, sid) {
  const dsi = utf8(DSI)
  const zpad = Math.max(0, S_IN_BYTES - 1 - prependLen(PRS).length - prependLen(dsi).length)
  return lvCat(dsi, PRS, Buffer.alloc(zpad), CI, sid)
}

/** @param {Buffer} bytes */
function fromLittleEndian (bytes) {
  let n = 0n
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i])
  return n
}

/** @param {bigint} n */
function toLittleEndian (n) {
  const out = Buffer.alloc(ELEMENT_SIZE)
  for (let i = 0; i < ELEMENT_SIZE; i++) {
    out[i] = Number(n & 0xffn)
    n >>= 8n
  }
  return out
}

/** @param {bigint} base @param {bigint} exponent */
function modPow (base, exponent) {
  let result = 1n
  let b = ((base % P) + P) % P
  for (let e = exponent; e > 0n; e >>= 1n) {
    if (e & 1n) result = (result * b) % P
    b = (b * b) % P
  }
  return result
}

/**
 * calculate_generator for X25519: the first 32 bytes of SHA-512 over the
 * generator string, bit #255 masked, through Elligator2, as a
 * u-coordinate.
 * @param {Buffer} PRS
 * @param {Buffer} CI
 * @param {Buffer} sid
 */
function calculateGenerator (PRS, CI, sid) {
  const u = crypto.createHash('sha512').update(generatorString(PRS, CI, sid)).digest().subarray(0, ELEMENT_SIZE)
  u[ELEMENT_SIZE - 1] &= 0x7f
  const { xMn, xMd } = mapToCurveElligator2(fromLittleEndian(u))
  // x = xMn / xMd in GF(p), by Fermat: xMd^(p-2) is its inverse.
  return toLittleEndian((xMn * modPow(xMd, P - 2n)) % P)
}

const b64url = (/** @type {Buffer} */ b) => Buffer.from(b).toString('base64url')

// PKCS#8 PrivateKeyInfo for X25519 (RFC 8410), up to the 32-byte scalar.
// A JWK private key would need x, the public key, and some builds (Windows)
// reject one that does not match d.
const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex')

/**
 * X25519 with the draft's mandatory abort on the neutral element
 * (scalar_mult_vfy). Node clamps the scalar, as RFC 7748 does, and refuses
 * a shared secret of all zeros; both are what the draft requires.
 * @param {Buffer} scalar
 * @param {Buffer} u
 */
function scalarMultVfy (scalar, u) {
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([X25519_PKCS8_PREFIX, scalar]),
    format: 'der',
    type: 'pkcs8'
  })
  let out
  try {
    const publicKey = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: b64url(u) }, format: 'jwk' })
    out = crypto.diffieHellman({ privateKey, publicKey })
  } catch (cause) {
    throw Object.assign(new Error('CPace: the point yields the neutral element'), { code: 'ERR_CPACE_NEUTRAL', cause })
  }
  if (out.every((b) => b === 0)) {
    throw Object.assign(new Error('CPace: the point yields the neutral element'), { code: 'ERR_CPACE_NEUTRAL' })
  }
  return out
}

/** @param {Buffer} Ya @param {Buffer} ADa @param {Buffer} Yb @param {Buffer} ADb */
const transcriptIR = (Ya, ADa, Yb, ADb) => Buffer.concat([lvCat(Ya, ADa), lvCat(Yb, ADb)])

/** @param {Buffer} sid @param {Buffer} K @param {Buffer} transcript */
const isk = (sid, K, transcript) =>
  crypto.createHash('sha512').update(Buffer.concat([lvCat(utf8(DSI_ISK), sid, K), transcript])).digest()

/** @param {string} nameplate */
const channelIdentifier = (nameplate) => lvCat(utf8(LABELS.CI), utf8(nameplate))

/** @param {Buffer} caps */
const associatedData = (caps) => lvCat(Buffer.from([VERSION]), caps)

/**
 * Everything the ISK keys (section 3.2).
 * @param {Buffer} sid
 * @param {Buffer} K
 * @param {Buffer} transcript
 */
function deriveKeys (sid, K, transcript) {
  const key = isk(sid, K, transcript)
  const hkdf = (/** @type {string} */ info) => Buffer.from(crypto.hkdfSync('sha256', key, sid, info, 32))
  const macKey = hkdf(LABELS.mac)
  const mac = (/** @type {string} */ label) =>
    crypto.createHmac('sha256', macKey).update(Buffer.concat([utf8(label), transcript])).digest()
  return {
    isk: key,
    macKey,
    confirmS: mac(LABELS.confirmS),
    confirmR: mac(LABELS.confirmR),
    kR2S: hkdf(LABELS.r2s),
    kS2R: hkdf(LABELS.s2r)
  }
}

/**
 * The canonical capability encoding: valid tokens, deduplicated, sorted
 * bytewise ascending, comma-joined, at most 128 bytes.
 * @param {string[]} tokens
 */
function encodeCaps (tokens) {
  for (const t of tokens) if (!CAPS_TOKEN.test(t)) throw new TypeError(`not a capability token: ${JSON.stringify(t)}`)
  const sorted = [...new Set(tokens)].map(utf8).sort(Buffer.compare)
  const out = Buffer.from(sorted.map((b) => b.toString('utf8')).join(','), 'utf8')
  if (out.length > MAX_CAPS_BYTES) throw new TypeError('capabilities over 128 bytes')
  return out
}

/**
 * The tokens of a peer's caps field, or null when it is not canonical.
 * @param {Buffer} bytes
 * @returns {string[] | null}
 */
function parseCanonicalCaps (bytes) {
  if (bytes.length === 0) return []
  if (bytes.length > MAX_CAPS_BYTES) return null
  const tokens = bytes.toString('utf8').split(',')
  if (!tokens.every((t) => CAPS_TOKEN.test(t))) return null
  return encodeCaps(tokens).equals(bytes) ? tokens : null
}

/**
 * What both sides act on: the known tokens in both sets (trap #3).
 * @param {string[]} ours @param {string[]} theirs
 */
const effectiveCaps = (ours, theirs) => KNOWN_CAPS.filter((t) => ours.includes(t) && theirs.includes(t))

/** A 2-byte big-endian length, then the body: HELLO and REPLY. @param {Buffer} body */
function withLength16 (body) {
  const out = Buffer.alloc(2 + body.length)
  out.writeUInt16BE(body.length, 0)
  body.copy(out, 2)
  return out
}

// --- sections 3.4 and 5: the sealed channel ------------------------------

const MAX_FRAME = 1024 * 1024
const TYPE_TAG_SIZE = 1
const AEAD_TAG_SIZE = 16
const MIN_SEALED = TYPE_TAG_SIZE + AEAD_TAG_SIZE
const MAX_CHUNK = MAX_FRAME - TYPE_TAG_SIZE - AEAD_TAG_SIZE

/** Four zero bytes, then the counter as 8 bytes big-endian. @param {bigint} counter */
function nonce (counter) {
  const n = Buffer.alloc(12)
  n.writeBigUInt64BE(counter, 4)
  return n
}

/**
 * One direction's sealing half: frame = [len][AEAD(type || body, aad = len)].
 */
class Sealer {
  /** @param {Buffer} key */
  constructor (key) {
    this.key = key
    this.counter = 0n
  }

  /** @param {number} type @param {Buffer} body */
  seal (type, body) {
    const plaintext = Buffer.concat([Buffer.from([type]), body])
    const header = Buffer.alloc(4)
    header.writeUInt32BE(plaintext.length + AEAD_TAG_SIZE, 0)
    const cipher = crypto.createCipheriv('chacha20-poly1305', this.key, nonce(this.counter++), { authTagLength: AEAD_TAG_SIZE })
    cipher.setAAD(header, { plaintextLength: plaintext.length })
    return Buffer.concat([header, cipher.update(plaintext), cipher.final(), cipher.getAuthTag()])
  }
}

/**
 * The other direction's opening half. `open` takes one whole frame's header
 * and sealed bytes and returns its plaintext, or null if it does not
 * authenticate under the next counter.
 */
class Opener {
  /** @param {Buffer} key */
  constructor (key) {
    this.key = key
    this.counter = 0n
  }

  /** @param {Buffer} header @param {Buffer} sealed */
  open (header, sealed) {
    const decipher = crypto.createDecipheriv('chacha20-poly1305', this.key, nonce(this.counter), { authTagLength: AEAD_TAG_SIZE })
    const ciphertext = sealed.subarray(0, sealed.length - AEAD_TAG_SIZE)
    decipher.setAAD(header, { plaintextLength: ciphertext.length })
    decipher.setAuthTag(sealed.subarray(sealed.length - AEAD_TAG_SIZE))
    try {
      const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()])
      this.counter++
      return plaintext
    } catch {
      return null
    }
  }
}

// --- section 4: the message set ------------------------------------------

const TYPE = {
  RESERVED: 0x00,
  MANIFEST: 0x01,
  CHUNK: 0x02,
  CANCEL: 0x03,
  ACCEPT: 0x04,
  DECLINE: 0x05,
  CHECKPOINT: 0x06,
  RESULT: 0x07,
  END: 0x08,
  PREFIX: 0x09
}
const TYPE_NAME = Object.fromEntries(Object.entries(TYPE).map(([k, v]) => [v, k]))

const PREFIX_BOUNDARY = 1024 * 1024
const MANIFEST_FIELDS = ['blockSize', 'name', 'sha256', 'size', 'v']
const SHA256_HEX = /^[0-9a-f]{64}$/
const DECLINE_CODE_SHAPE = /^ERR_[A-Z0-9_]{1,48}$/

/** @param {Buffer} data */
const sha256 = (data) => crypto.createHash('sha256').update(data).digest('hex')

module.exports = {
  DSI,
  DSI_ISK,
  S_IN_BYTES,
  VERSION,
  SID_SIZE,
  ELEMENT_SIZE,
  CONFIRM_SIZE,
  MAX_CAPS_BYTES,
  KNOWN_CAPS,
  HELLO_FIXED,
  REPLY_FIXED,
  HELLO_BODY,
  REPLY_BODY,
  LABELS,
  blake2b,
  TOPIC_LABEL,
  topic,
  prependLen,
  lvCat,
  generatorString,
  calculateGenerator,
  scalarMultVfy,
  transcriptIR,
  isk,
  channelIdentifier,
  associatedData,
  deriveKeys,
  encodeCaps,
  parseCanonicalCaps,
  effectiveCaps,
  withLength16,
  MAX_FRAME,
  MIN_SEALED,
  MAX_CHUNK,
  Sealer,
  Opener,
  TYPE,
  TYPE_NAME,
  PREFIX_BOUNDARY,
  MANIFEST_FIELDS,
  SHA256_HEX,
  DECLINE_CODE_SHAPE,
  sha256
}
