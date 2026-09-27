'use strict'

const crypto = require('node:crypto')
const { sha512 } = require('@noble/hashes/sha2.js')
const {
  x25519,
  _map_to_curve_elligator2_curve25519: mapToCurveElligator2
} = require('@noble/curves/ed25519.js')
const { Field } = require('@noble/curves/abstract/modular.js')

// CPACE-X25519-SHA512, the balanced PAKE v2's handshake is built on.
// Composition only: every field and group operation below comes out of
// @noble/curves, which is audited. Nothing here reimplements arithmetic.
//
// WHY A PAKE AT ALL. v1 proved knowledge of the code with an HMAC over
// nonces (../src/proof.js). That is sound as a proof, and useless as a
// defence, because v1's topic is hash(code || salt): the topic is public
// the moment a receiver announces, so an attacker holding it can grind
// candidate codes offline and never touch a peer. A PAKE removes the
// offline target entirely -- the secret is never hashed into anything an
// observer can obtain, so a guess costs a live protocol run against a
// peer that is counting (PROTOCOL.md section 6).
//
// WHY THIS SUITE, AND WHY NOBLE. The premise this work started from was
// that libsodium's ristretto255 primitives were already in the tree via
// sodium-native. They are not: sodium-native@5.1.0 exports 313 symbols
// and zero ristretto255 ones, and it is a transitive dependency that no
// package.json here declares. What settled the choice instead was
// running the CFRG vectors: @noble/curves@2.4.0 reproduces all 9
// CPACE-X25519-SHA512 vectors and all 12 low-order/twist vectors exactly,
// at 2.1 ms per side (p50, measured on this machine). Those vectors are
// cli/test/cpace-vectors.test.js, and they -- not this comment -- are the
// evidence. A PAKE validated only against itself is worse than the HMAC
// proof it replaces, because it looks stronger.
//
// THE ABORT IN scalarMultVfy IS NORMATIVE, NOT DEFENSIVE. X25519 accepts
// low-order and twist points, and for a dozen specific u-coordinates it
// returns the all-zero neutral element for *every* scalar. A peer that
// sends one of those learns nothing but forces both sides to agree on a
// key it also knows. The draft requires the abort; the twelve inputs that
// must trigger it are in the vector test, including ua and ub, which have
// bit #255 set and are the pair that silently breaks any implementation
// skipping RFC 7748's decodeUCoordinate.
//
// ON THE WIRE AS OF W11. ./handshake.js owns the ad-hal-specific parameter
// mapping -- what goes in PRS, CI, sid, ADa and ADb -- and ./swarm.js
// runs the exchange. That mapping is the part this file deliberately does
// not decide: everything here is the suite as the draft defines it, which
// is what makes cli/test/cpace-vectors.test.js able to check it against
// values computed by someone else. See PROTOCOL.md section 3.2.

// The suite's domain-separation identifiers. G.DSI seeds the generator,
// G.DSI_ISK the key derivation, and they differ so that no hash input can
// be replayed from one context into the other.
const DSI = 'CPace255'
const DSI_ISK = 'CPace255_ISK'

// SHA-512's *input block* size, not its output size. It is a parameter of
// generatorString because the zero padding exists to push everything
// after the password out of the first compression-function block -- a
// side-channel mitigation, so it is measured in blocks.
const S_IN_BYTES = 128

const ELEMENT_SIZE = 32
const SCALAR_SIZE = 32
const ISK_SIZE = 64

// Curve25519's prime. Used for exactly one thing: taking the Elligator2
// map's projective output to affine. noble's inversion is the audited
// one; a hand-written modular inverse here would be the one piece of
// field arithmetic this module wrote itself, which is the thing it is
// structured to avoid.
const Fp = Field(2n ** 255n - 19n)

/**
 * LEB128 length prefix, per the draft's prepend_len.
 *
 * Unambiguous concatenation is load-bearing, not tidiness: without it a
 * peer could shift bytes between two adjacent fields and produce the same
 * hash input from different parameters.
 *
 * @param {Buffer|Uint8Array} data
 * @returns {Buffer}
 */
function prependLen (data) {
  const prefix = []
  let length = data.length
  for (;;) {
    prefix.push(length < 128 ? length : (length & 0x7f) + 0x80)
    length >>= 7
    if (length === 0) break
  }
  return Buffer.concat([Buffer.from(prefix), Buffer.from(data)])
}

/**
 * Length-prefixed concatenation, per the draft's lv_cat.
 *
 * @param {...(Buffer|Uint8Array)} parts
 * @returns {Buffer}
 */
function lvCat (...parts) {
  return Buffer.concat(parts.map(prependLen))
}

/**
 * The hash input the generator is derived from, per the draft's
 * generator_string.
 *
 * Exported rather than inlined into calculateGenerator because it is one
 * of the published test vectors, and because W12's conformance harness
 * has to be able to check it against another implementation without
 * trusting that implementation's curve arithmetic.
 *
 * @param {Buffer|Uint8Array} PRS the low-entropy shared secret
 * @param {Buffer|Uint8Array} CI channel identifier; public
 * @param {Buffer|Uint8Array} sid session identifier; public
 * @returns {Buffer}
 */
function generatorString (PRS, CI, sid) {
  const dsi = Buffer.from(DSI, 'utf8')
  // Everything before CI has to fill one whole hash block, so that the
  // first compression call covers the secret and nothing that follows it.
  // The -1 is the single length byte prepended to the padding itself.
  const zpadLength = Math.max(
    0,
    S_IN_BYTES - 1 - prependLen(PRS).length - prependLen(dsi).length
  )
  return lvCat(dsi, PRS, Buffer.alloc(zpadLength), CI, sid)
}

/**
 * The secret generator g, as a 32-byte little-endian u-coordinate.
 *
 * Both sides derive the same g if and only if they hold the same PRS, CI
 * and sid. That is the whole trick: an attacker with the wrong password
 * is working in a group it cannot relate to this one.
 *
 * @param {Buffer|Uint8Array} PRS
 * @param {Buffer|Uint8Array} CI
 * @param {Buffer|Uint8Array} sid
 * @returns {Buffer} 32 bytes
 */
function calculateGenerator (PRS, CI, sid) {
  const digest = Buffer.from(sha512(generatorString(PRS, CI, sid)))
  // The draft takes the field's worth of bytes off the front of the
  // digest, then applies RFC 7748's decodeUCoordinate -- which for a
  // 255-bit field means clearing bit #255. Skipping the clear is the
  // documented way to get an implementation that passes every ordinary
  // vector and fails on two specific inputs.
  const u = digest.subarray(0, ELEMENT_SIZE)
  u[ELEMENT_SIZE - 1] &= 0x7f

  const { xMn, xMd } = mapToCurveElligator2(decodeLittleEndian(u))
  return encodeLittleEndian(Fp.mul(xMn, Fp.inv(xMd)))
}

/**
 * A fresh secret scalar.
 *
 * Unclamped 32 random bytes, deliberately: X25519 clamps internally, and
 * the CFRG vectors' own ya has both its low bits and its high bit set,
 * so pre-clamping here would fail them.
 *
 * MUST NOT be reused across sessions (draft section 9.9). In this engine
 * that is not a theoretical caution -- Hyperswarm hands a receiver
 * several candidate peers per drop and two connections per peer, and
 * caching one Ya across them to save 2 ms would be exactly the reuse the
 * draft forbids.
 *
 * @returns {Buffer} 32 bytes
 */
function sampleScalar () {
  return crypto.randomBytes(SCALAR_SIZE)
}

/**
 * X25519 with the draft's mandatory abort, per G.scalar_mult_vfy.
 *
 * @param {Buffer|Uint8Array} y a scalar from sampleScalar
 * @param {Buffer|Uint8Array} u a 32-byte u-coordinate
 * @returns {Buffer} 32 bytes, never the neutral element
 * @throws {Error} with `code: 'ERR_CPACE_NEUTRAL'` when the result is the
 *   neutral element -- the draft's abort case
 */
function scalarMultVfy (y, u) {
  let result
  try {
    result = Buffer.from(x25519.scalarMult(y, u))
  } catch (err) {
    // noble raises on a zero output rather than returning it. Translate,
    // so callers switch on one code instead of on a library's wording.
    throw neutralElementError(err)
  }
  // Belt and braces: the throw above is noble's behaviour, not its
  // documented contract, and this module pins an exact version precisely
  // because such behaviour can change. A version that returned the zero
  // instead of throwing would otherwise hand a shared key to an attacker.
  if (isAllZero(result)) throw neutralElementError()
  return result
}

/**
 * @param {any} [cause]
 * @returns {Error & { code: string }}
 */
function neutralElementError (cause) {
  const err = /** @type {Error & { code: string }} */ (
    new Error('CPace: peer point yields the neutral element')
  )
  err.code = 'ERR_CPACE_NEUTRAL'
  if (cause !== undefined) err.cause = cause
  return err
}

/**
 * @param {Buffer} buf
 * @returns {boolean}
 */
function isAllZero (buf) {
  let acc = 0
  for (const b of buf) acc |= b
  return acc === 0
}

/**
 * The initiator/responder transcript, per the draft's transcript_ir.
 *
 * `_ir` and not `_oc` because this protocol enforces message order: the
 * receiver always writes first, and PROTOCOL.md section 3.1 explains why
 * that cannot change. The draft permits `_ir` exactly under that
 * condition. Using it when order is *not* enforced is a real bug, so the
 * condition is worth restating wherever this is called.
 *
 * @param {Buffer|Uint8Array} Ya initiator's public point
 * @param {Buffer|Uint8Array} ADa initiator's associated data
 * @param {Buffer|Uint8Array} Yb responder's public point
 * @param {Buffer|Uint8Array} ADb responder's associated data
 * @returns {Buffer}
 */
function transcriptIR (Ya, ADa, Yb, ADb) {
  return Buffer.concat([lvCat(Ya, ADa), lvCat(Yb, ADb)])
}

/**
 * The intermediate shared key.
 *
 * "Intermediate" is the draft's word and it is a warning: ISK is not a
 * key to encrypt with. Run it through a KDF first -- PROTOCOL.md section
 * 3.2 specifies which, and with what info strings.
 *
 * @param {Buffer|Uint8Array} sid
 * @param {Buffer|Uint8Array} K the output of scalarMultVfy
 * @param {Buffer|Uint8Array} transcript from transcriptIR
 * @returns {Buffer} 64 bytes
 */
function isk (sid, K, transcript) {
  const input = Buffer.concat([
    lvCat(Buffer.from(DSI_ISK, 'utf8'), sid, K),
    Buffer.from(transcript)
  ])
  return Buffer.from(sha512(input))
}

/**
 * @param {Buffer|Uint8Array} bytes little-endian
 * @returns {bigint}
 */
function decodeLittleEndian (bytes) {
  let n = 0n
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i])
  return n
}

/**
 * @param {bigint} n
 * @returns {Buffer} 32 bytes, little-endian
 */
function encodeLittleEndian (n) {
  const out = Buffer.alloc(ELEMENT_SIZE)
  let rest = n
  for (let i = 0; i < ELEMENT_SIZE; i++) {
    out[i] = Number(rest & 0xffn)
    rest >>= 8n
  }
  return out
}

module.exports = {
  prependLen,
  lvCat,
  generatorString,
  calculateGenerator,
  sampleScalar,
  scalarMultVfy,
  transcriptIR,
  isk,
  DSI,
  DSI_ISK,
  S_IN_BYTES,
  ELEMENT_SIZE,
  SCALAR_SIZE,
  ISK_SIZE
}
