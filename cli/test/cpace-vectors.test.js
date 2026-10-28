'use strict'

// CPACE-X25519-SHA512 against the CFRG draft's published test vectors.
//
// WHY THIS FILE IS DIFFERENT FROM EVERY OTHER TEST HERE. Until now, every
// expected value in cli/test/ was recomputed at runtime by the same
// primitive under test: the proof tests build an HMAC and compare it to
// an HMAC, the code tests re-derive a code and compare it to a code. That
// proves self-consistency, which is worth having and is not conformance.
// A module that is wrong in the same way twice passes all of it.
//
// The values below are not computed here. They are transcribed from
// draft-irtf-cfrg-cpace-14 (testvectors.md, "Test vector for CPace using
// group X25519 and hash SHA-512") and are fixed input/output pairs an
// independent implementation must also reproduce. They are the acceptance
// criterion for engine/src/cpace.js: if they do not match byte for byte,
// the module is wrong, and no amount of internal agreement rescues it.
// PROTOCOL.md section 11 makes this the seed of the conformance suite.
//
// TWO GROUPS, AND THE SECOND MATTERS MORE. The nine positive vectors
// check that a correct run produces the right key. The twelve low-order
// vectors check the abort -- the case where a peer sends a point chosen
// so that scalar multiplication yields the neutral element for *any*
// scalar, handing the attacker a key both sides agree on. Seven must
// abort and five must return specific non-zero values, and getting that
// split wrong in either direction is a real vulnerability: aborting on
// u6 is a peer you can never talk to, not aborting on u3 is a peer who
// owns your session.
//
// ua and ub earn their own mention. Both have bit #255 set, which
// RFC 7748's decodeUCoordinate mandates clearing. An implementation that
// skips the clear passes every other vector in this file and fails these
// two, which is precisely why the draft ships them.
//
// Imported by path rather than from '@ad-hal/engine': cpace.js is not part
// of the engine's public surface yet. W11 is what puts it on the wire
// (PROTOCOL.md section 3); W10 only had to prove it reproduces.

const test = require('node:test')
const assert = require('node:assert/strict')

const {
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
  SCALAR_SIZE,
  ISK_SIZE
} = require('../../engine/src/cpace')

const hex = (/** @type {Buffer|Uint8Array} */ b) => Buffer.from(b).toString('hex')
const h = (/** @type {string} */ s) => Buffer.from(s, 'hex')
const utf8 = (/** @type {string} */ s) => Buffer.from(s, 'utf8')

// --- the shared inputs of the draft's X25519/SHA-512 test case ----------
//
// Transcribed into conformance/vectors/cpace.json, which is what a second
// implementation is checked against; this file reads them from there so
// the two cannot drift apart.

const CPACE = require('../../conformance/vectors/cpace.json')
const CASE = CPACE.case

const PRS = utf8(CASE.PRSUtf8)
const CI = h(CASE.CI)
const SID = h(CASE.sid)
const ADa = utf8(CASE.ADaUtf8)
const ADb = utf8(CASE.ADbUtf8)

const YA_SCALAR = h(CASE.ya)
const YB_SCALAR = h(CASE.yb)

const EXPECTED = {
  generatorString: CASE.generatorString,
  generator: CASE.generator,
  Ya: CASE.Ya,
  Yb: CASE.Yb,
  K: CASE.K,
  transcriptIR: CASE.transcriptIR,
  ISK_IR: CASE.ISK_IR
}

// --- string utilities, which the rest of the vectors sit on -------------
//
// These have their own published vectors, and they are worth running:
// every hash input in CPace is an lv_cat, so an off-by-one in the length
// encoding produces a module that is internally consistent and
// interoperates with nothing.

/**
 * A prependLen vector's input: hex, UTF-8, or the bytes 00 01 02 ... counted
 * up to a length, which is how the draft states its 127- and 128-byte cases.
 * @param {any} v
 */
function prependInput (v) {
  if ('inputHex' in v) return h(v.inputHex)
  if ('inputUtf8' in v) return utf8(v.inputUtf8)
  return Buffer.from(Array.from({ length: v.inputCountingFrom0 }, (_, i) => i))
}

test('prepend_len emits the draft LEB128 encoding, including the two-byte case', () => {
  for (const v of CPACE.prependLen) {
    const out = hex(prependLen(prependInput(v)))
    if ('outputHex' in v) {
      assert.equal(out, v.outputHex, v.what)
    } else {
      assert.equal(out.slice(0, v.outputPrefixHex.length), v.outputPrefixHex, v.what)
    }
  }
  // An empty field still carries a length, or concatenation is ambiguous;
  // and 127 and 128 are the two sides of the one-byte boundary, where a
  // fixed one-byte prefix breaks and nowhere earlier. Asserted, so that a
  // vector file that lost one of them fails here rather than passing.
  const lengths = CPACE.prependLen.map((/** @type {any} */ v) => prependInput(v).length)
  for (const n of [0, 127, 128]) assert.ok(lengths.includes(n), `a ${n}-byte prepend_len vector`)
})

test('lv_cat concatenates length-prefixed fields, empty ones included', () => {
  assert.equal(
    hex(lvCat(...CPACE.lvCat.inputsUtf8.map(utf8))),
    CPACE.lvCat.outputHex,
    'the empty third field must still contribute its 00, or two different ' +
    'parameter sets hash to the same input'
  )
  assert.ok(CPACE.lvCat.inputsUtf8.includes(''), 'the vector has an empty field')
})

test('transcript_ir is the two length-prefixed message pairs in order', () => {
  const { Ya, ADa, Yb, ADb } = CPACE.transcriptIR.inputsUtf8
  assert.equal(
    hex(transcriptIR(utf8(Ya), utf8(ADa), utf8(Yb), utf8(ADb))),
    CPACE.transcriptIR.outputHex
  )
})

// --- the nine positive vectors -----------------------------------------

test('generator_string matches the draft, zero padding and all', () => {
  const gs = generatorString(PRS, CI, SID)
  assert.equal(gs.length, CASE.generatorStringLength, 'the draft states 172 bytes for this input')
  assert.equal(hex(gs), EXPECTED.generatorString)
})

test('the zero padding fills the first hash block after DSI and PRS', () => {
  // Not a draft vector but the invariant the padding exists for: the
  // secret and nothing after it occupies SHA-512's first compression
  // block. Stated here because the length is computed, not constant, and
  // a wrong formula still produces a plausible-looking generator string.
  const prefixLength = prependLen(utf8(DSI)).length + prependLen(PRS).length
  const zpad = 172 - prefixLength - prependLen(CI).length - prependLen(SID).length
  assert.equal(zpad, 110, 'one length byte plus 109 zero bytes')
  assert.equal(prefixLength + zpad, S_IN_BYTES,
    'DSI, PRS, and the padding together are exactly one SHA-512 input block')
})

test('a password too long to leave room for padding gets none, as the second implementation computes', () => {
  // The draft's vector has room to spare, so the max(0, ...) floor is never
  // reached by it. A PRS of 117 bytes or more fills the first block on its
  // own and takes no padding at all; a floor of one byte instead would
  // still pair two copies of this engine, and break against everyone else.
  // conformance/src/wire.js is that everyone else, written separately.
  const wire = require('../../conformance/src/wire')
  for (const length of [100, 116, 117, 118, 200, 300]) {
    const prs = Buffer.alloc(length, 0x61)
    assert.equal(hex(generatorString(prs, CI, SID)), hex(wire.generatorString(prs, CI, SID)), `a ${length}-byte PRS`)
  }
})

test('the generator g reproduces the draft, which exercises Elligator2', () => {
  assert.equal(hex(calculateGenerator(PRS, CI, SID)), EXPECTED.generator,
    'g is where the password enters the group; a wrong map is a wrong ' +
    'group and every later value follows it')
})

test('Ya and Yb reproduce the draft from its own secret scalars', () => {
  const g = calculateGenerator(PRS, CI, SID)
  assert.equal(hex(scalarMultVfy(YA_SCALAR, g)), EXPECTED.Ya)
  assert.equal(hex(scalarMultVfy(YB_SCALAR, g)), EXPECTED.Yb)
})

test('both sides compute the same secret point K, and it is the draft value', () => {
  const g = calculateGenerator(PRS, CI, SID)
  const Ya = scalarMultVfy(YA_SCALAR, g)
  const Yb = scalarMultVfy(YB_SCALAR, g)

  assert.equal(hex(scalarMultVfy(YA_SCALAR, Yb)), EXPECTED.K, 'A side')
  assert.equal(hex(scalarMultVfy(YB_SCALAR, Ya)), EXPECTED.K, 'B side')
})

test('transcript_ir and ISK reproduce the draft for the initiator/responder case', () => {
  const g = calculateGenerator(PRS, CI, SID)
  const Ya = scalarMultVfy(YA_SCALAR, g)
  const Yb = scalarMultVfy(YB_SCALAR, g)
  const K = scalarMultVfy(YA_SCALAR, Yb)

  const transcript = transcriptIR(Ya, ADa, Yb, ADb)
  assert.equal(hex(transcript), EXPECTED.transcriptIR)

  const key = isk(SID, K, transcript)
  assert.equal(key.length, ISK_SIZE)
  assert.equal(hex(key), EXPECTED.ISK_IR,
    'this is the value the whole suite exists to produce; everything ' +
    'above it is only interesting because it feeds this')
})

// --- the twelve low-order vectors ---------------------------------------

// Draft section "Test vectors for G_X25519.scalar_mult_vfy: low order
// points". The scalar is the draft's, and it is fixed: the point of these
// is that the *u-coordinate* decides the outcome, whatever the scalar.
const LOW_ORDER_SCALAR = h(CPACE.lowOrder.scalar)

/** @type {Record<string, string>} */
const MUST_ABORT = CPACE.lowOrder.mustAbort

/** @type {Record<string, { u: string, q: string }>} */
const MUST_SUCCEED = CPACE.lowOrder.mustSucceed

test('the low-order set is the draft\'s twelve, split seven to five', () => {
  // A meta-assertion, because a vector file that lost an entry would
  // otherwise run one test fewer and still pass.
  assert.deepEqual(Object.keys(MUST_ABORT), ['u0', 'u1', 'u2', 'u3', 'u4', 'u5', 'u7'])
  assert.deepEqual(Object.keys(MUST_SUCCEED), ['u6', 'u8', 'u9', 'ua', 'ub'])
})

for (const [name, u] of Object.entries(MUST_ABORT)) {
  test(`scalar_mult_vfy aborts on the low-order point ${name}`, () => {
    assert.throws(
      () => scalarMultVfy(LOW_ORDER_SCALAR, h(u)),
      // With the library's own error kept as the cause, so a log shows
      // what the curve code said and not only our translation of it.
      (/** @type {any} */ err) => err.code === 'ERR_CPACE_NEUTRAL' && err.cause instanceof Error,
      `${name} drives the result to the neutral element for every scalar, so ` +
      'continuing would agree a key the peer who sent it already knows'
    )
  })
}

for (const [name, { u, q }] of Object.entries(MUST_SUCCEED)) {
  test(`scalar_mult_vfy returns the draft value for ${name}, and does not abort`, () => {
    assert.equal(hex(scalarMultVfy(LOW_ORDER_SCALAR, h(u))), q,
      `${name} looks like the abort cases and is not one; rejecting it ` +
      'would refuse honest peers'
    )
  })
}

test('bit #255 is cleared without reducing mod p, which is what splits ua from u3', () => {
  // The sharpest pair in the draft, and not for the reason it first looks.
  // ua and u3 are the SAME field element: 2**255 is congruent to 19 mod
  // p, so setting bit #255 and subtracting 19 lands on the same point.
  // Yet u3 must abort and ua must not. That is only consistent if
  // decodeUCoordinate does exactly what RFC 7748 says -- mask bit #255,
  // and do not reduce.
  //
  // So both of the natural mistakes fail here and nowhere else: reducing
  // mod p folds ua onto u3 and aborts on an honest peer, and skipping the
  // mask leaves a 256-bit value that any internal reduction folds the
  // same way.
  const p = 2n ** 255n - 19n
  const le = (/** @type {string} */ s) => {
    let n = 0n
    const b = h(s)
    for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i])
    return n
  }
  const masked = (/** @type {bigint} */ n) => n & ((1n << 255n) - 1n)

  for (const [abortName, aborting, okName, ok] of [
    ['u3', MUST_ABORT.u3, 'ua', MUST_SUCCEED.ua.u],
    ['u4', MUST_ABORT.u4, 'ub', MUST_SUCCEED.ub.u]
  ]) {
    assert.equal(le(ok) >> 255n, 1n, `${okName} has bit #255 set`)
    assert.equal(le(ok) % p, le(aborting) % p,
      `${okName} and ${abortName} are the same field element mod p`)
    assert.equal(masked(le(ok)), le(aborting) - 19n,
      `masking ${okName} gives ${abortName} minus 19, not ${abortName}: ` +
      'that 19 is the whole difference between accepting an honest peer ' +
      'and refusing one')
  }
})

// --- properties the vectors cannot state -------------------------------

test('a different password derives a different generator', () => {
  const other = calculateGenerator(utf8('Passw0rd'), CI, SID)
  assert.notEqual(hex(other), EXPECTED.generator,
    'the generator is the only place the secret enters; if it did not ' +
    'move with the password there would be no PAKE here at all')
})

test('sid and CI are bound into the generator, not merely carried alongside', () => {
  const otherSid = calculateGenerator(PRS, CI, h('00'.repeat(16)))
  const otherCI = calculateGenerator(PRS, utf8('adhal-v2'), SID)
  assert.notEqual(hex(otherSid), EXPECTED.generator,
    'a replayed sid must not reproduce a previous session generator')
  assert.notEqual(hex(otherCI), EXPECTED.generator,
    'CI carries the nameplate in PROTOCOL.md section 3.2; a generator ' +
    'that ignored it would let one drop be answered on another')
})

test('sample_scalar returns unclamped random scalars', () => {
  const a = sampleScalar()
  const b = sampleScalar()
  assert.equal(a.length, SCALAR_SIZE)
  assert.notEqual(hex(a), hex(b), 'two samples must not collide')

  // Not clamped on purpose: X25519 clamps internally, and the draft's own
  // ya has low bits set and bit #255 set. Pre-clamping here would fail
  // the vectors above -- assert the draft scalar's shape so that a future
  // "hardening" change to sampleScalar has to confront this.
  assert.notEqual(YA_SCALAR[0] & 0x07, 0, 'the draft scalar has low bits set')
  assert.notEqual(YA_SCALAR[31] & 0x80, 0, 'and bit #255 set')
})

test('the suite constants are the ones the draft names', () => {
  assert.equal(DSI, 'CPace255')
  assert.equal(DSI_ISK, 'CPace255_ISK')
  assert.equal(S_IN_BYTES, 128, "SHA-512's input block size, not its digest size")
  assert.deepEqual(CPACE.constants, { DSI, DSI_ISK, s_in_bytes: S_IN_BYTES },
    'cpace.json states the constants it was transcribed under')
})
