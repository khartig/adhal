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

const PRS = utf8('Password')
const CI = h('6f630b425f726573706f6e6465720b415f696e69746961746f72')
const SID = h('7e4b4791d6a8ef019b936c79fb7f2c57')
const ADa = utf8('ADa')
const ADb = utf8('ADb')

const YA_SCALAR = h('21b4f4bd9e64ed355c3eb676a28ebedaf6d8f17bdc365995b319097153044080')
const YB_SCALAR = h('848b0779ff415f0af4ea14df9dd1d3c29ac41d836c7808896c4eba19c51ac40a')

const EXPECTED = {
  generatorString:
    '0843506163653235350850617373776f72646d' + '00'.repeat(109) +
    '1a6f630b425f726573706f6e6465720b415f696e69746961746f72' +
    '107e4b4791d6a8ef019b936c79fb7f2c57',
  generator: '64e8099e3ea682cfdc5cb665c057ebb514d06bf23ebc9f743b51b82242327074',
  Ya: '1b02dad6dbd29a07b6d28c9e04cb2f184f0734350e32bb7e62ff9dbcfdb63d15',
  Yb: '20cda5955f82c4931545bcbf40758ce1010d7db4db2a907013d79c7a8fcf957f',
  K: 'f97fdfcfff1c983ed6283856a401de3191ca919902b323c5f950c9703df7297a',
  transcriptIR:
    '201b02dad6dbd29a07b6d28c9e04cb2f184f0734350e32bb7e62ff9dbcfdb63d15' +
    '034144612020cda5955f82c4931545bcbf40758ce1010d7db4db2a907013d79c7a' +
    '8fcf957f03414462',
  ISK_IR:
    'a051ee5ee2499d16da3f69f430218b8ea94a18a45b67f9e86495b382c33d14a5' +
    'c38cecc0cc834f960e39e0d1bf7d76b9ef5d54eecc5e0f386c97ad12da8c3d5f'
}

// --- string utilities, which the rest of the vectors sit on -------------
//
// These have their own published vectors, and they are worth running:
// every hash input in CPace is an lv_cat, so an off-by-one in the length
// encoding produces a module that is internally consistent and
// interoperates with nothing.

test('prepend_len emits the draft LEB128 encoding, including the two-byte case', () => {
  assert.equal(hex(prependLen(Buffer.alloc(0))), '00',
    'an empty field still carries a length, or concatenation is ambiguous')
  assert.equal(hex(prependLen(utf8('1234'))), '0431323334')

  const r127 = Buffer.from(Array.from({ length: 127 }, (_, i) => i))
  const r128 = Buffer.from(Array.from({ length: 128 }, (_, i) => i))
  assert.equal(hex(prependLen(r127).subarray(0, 1)), '7f',
    '127 is the largest length that fits in one LEB128 byte')
  assert.equal(hex(prependLen(r128).subarray(0, 2)), '8001',
    '128 rolls over to two bytes; a fixed one-byte prefix breaks here and nowhere earlier')
})

test('lv_cat concatenates length-prefixed fields, empty ones included', () => {
  assert.equal(
    hex(lvCat(utf8('1234'), utf8('5'), Buffer.alloc(0), utf8('678'))),
    '043132333401350003363738',
    'the empty third field must still contribute its 00, or two different ' +
    'parameter sets hash to the same input'
  )
})

test('transcript_ir is the two length-prefixed message pairs in order', () => {
  assert.equal(
    hex(transcriptIR(utf8('123'), utf8('PartyA'), utf8('234'), utf8('PartyB'))),
    '03313233065061727479410332333406506172747942'
  )
})

// --- the nine positive vectors -----------------------------------------

test('generator_string matches the draft, zero padding and all', () => {
  const gs = generatorString(PRS, CI, SID)
  assert.equal(gs.length, 172, 'the draft states 172 bytes for this input')
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
const LOW_ORDER_SCALAR = h('af46e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449aff')

const MUST_ABORT = {
  u0: '0000000000000000000000000000000000000000000000000000000000000000',
  u1: '0100000000000000000000000000000000000000000000000000000000000000',
  u2: 'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  u3: 'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
  u4: '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
  u5: 'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  u7: 'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'
}

const MUST_SUCCEED = {
  u6: {
    u: 'daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    q: 'd8e2c776bbacd510d09fd9278b7edcd25fc5ae9adfba3b6e040e8d3b71b21806'
  },
  u8: {
    u: 'dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    q: 'c85c655ebe8be44ba9c0ffde69f2fe10194458d137f09bbff725ce58803cdb38'
  },
  u9: {
    u: 'd9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    q: 'db64dafa9b8fdd136914e61461935fe92aa372cb056314e1231bc4ec12417456'
  },
  ua: {
    u: 'cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880',
    q: 'e062dcd5376d58297be2618c7498f55baa07d7e03184e8aada20bca28888bf7a'
  },
  ub: {
    u: '4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7',
    q: '993c6ad11c4c29da9a56f7691fd0ff8d732e49de6250b6c2e80003ff4629a175'
  }
}

for (const [name, u] of Object.entries(MUST_ABORT)) {
  test(`scalar_mult_vfy aborts on the low-order point ${name}`, () => {
    assert.throws(
      () => scalarMultVfy(LOW_ORDER_SCALAR, h(u)),
      (/** @type {any} */ err) => err.code === 'ERR_CPACE_NEUTRAL',
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
})
