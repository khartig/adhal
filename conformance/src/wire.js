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
// Only what the harness needs is here. There is no code parsing and no
// topic: the harness is handed a nameplate and a secret, and discovery is
// outside what a byte stream can test.

const crypto = require('node:crypto')
const { _map_to_curve_elligator2_curve25519: mapToCurveElligator2 } = require('@noble/curves/ed25519.js')

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

/**
 * X25519 with the draft's mandatory abort on the neutral element
 * (scalar_mult_vfy). Node clamps the scalar, as RFC 7748 does, and refuses
 * a shared secret of all zeros; both are what the draft requires.
 * @param {Buffer} scalar
 * @param {Buffer} u
 */
function scalarMultVfy (scalar, u) {
  let out
  try {
    const privateKey = crypto.createPrivateKey({
      key: { kty: 'OKP', crv: 'X25519', d: b64url(scalar), x: b64url(Buffer.alloc(32)) },
      format: 'jwk'
    })
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
