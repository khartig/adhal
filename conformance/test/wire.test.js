'use strict'

// The harness's own wire layer (conformance/src/wire.js) against every
// published vector.
//
// This is what lets the harness be trusted to judge anything. wire.js shares
// no code with engine/src, so when it reproduces these values the vectors
// have been met by two implementations, not one. For cpace.json that is a
// second implementation meeting an external acceptance criterion; for
// handshake.json and frames-negative.json, which this repository generated,
// it is the first evidence that someone other than their author can
// reproduce them from PROTOCOL.md. code.json's topics are reproduced
// through wire.js's own BLAKE2b, written from RFC 7693.

const test = require('node:test')
const assert = require('node:assert/strict')
const crypto = require('node:crypto')

const wire = require('../src/wire')
const CODE = require('../vectors/code.json')
const CPACE = require('../vectors/cpace.json')
const HANDSHAKE = require('../vectors/handshake.json')
const FRAMES = require('../vectors/frames-negative.json')
const HANDSHAKE_NEGATIVE = require('../vectors/handshake-negative.json')

const h = (/** @type {string} */ s) => Buffer.from(s, 'hex')
const hex = (/** @type {Buffer} */ b) => b.toString('hex')
const utf8 = (/** @type {string} */ s) => Buffer.from(s, 'utf8')

// Node's blake2b512 is an independent implementation of the same
// compression function, so at a 64-byte output the two must agree. The
// lengths cover the empty input, which is one block of zeros, and both
// sides of each block boundary, where the final flag and the counter go
// wrong.
test('BLAKE2b at a 64-byte output agrees with node:crypto, around every block boundary', () => {
  for (let n = 0; n <= 3 * 128 + 1; n++) {
    const data = Buffer.from(Array.from({ length: n }, (_, i) => (i * 7 + n) & 0xff))
    assert.equal(hex(wire.blake2b(data, 64)), crypto.createHash('blake2b512').update(data).digest('hex'), `${n} bytes`)
  }
})

test('code.json: BLAKE2b-256 of "abc", and every topic', () => {
  assert.equal(hex(wire.blake2b(utf8('abc'), 32)), CODE.blake2b256Abc, 'the published digest')
  assert.notEqual(hex(wire.blake2b(utf8('abc'), 64)).slice(0, 64), CODE.blake2b256Abc, 'BLAKE2b-256 is not a truncated BLAKE2b-512')
  assert.equal(wire.TOPIC_LABEL, CODE.topicLabel)
  for (const v of CODE.vectors) assert.equal(hex(wire.topic(v.nameplate)), v.topic, v.what)
})

test('cpace.json: the string utilities', () => {
  for (const v of CPACE.prependLen) {
    const input = 'inputHex' in v
      ? h(v.inputHex)
      : 'inputUtf8' in v ? utf8(v.inputUtf8) : Buffer.from(Array.from({ length: v.inputCountingFrom0 }, (_, i) => i))
    const out = hex(wire.prependLen(input))
    if ('outputHex' in v) assert.equal(out, v.outputHex)
    else assert.equal(out.slice(0, v.outputPrefixHex.length), v.outputPrefixHex)
  }
  assert.equal(hex(wire.lvCat(...CPACE.lvCat.inputsUtf8.map(utf8))), CPACE.lvCat.outputHex)
  const t = CPACE.transcriptIR.inputsUtf8
  assert.equal(hex(wire.transcriptIR(utf8(t.Ya), utf8(t.ADa), utf8(t.Yb), utf8(t.ADb))), CPACE.transcriptIR.outputHex)
  assert.deepEqual(CPACE.constants, { DSI: wire.DSI, DSI_ISK: wire.DSI_ISK, s_in_bytes: wire.S_IN_BYTES })
})

test('cpace.json: the initiator/responder case, end to end', () => {
  const c = CPACE.case
  const PRS = utf8(c.PRSUtf8)
  const gs = wire.generatorString(PRS, h(c.CI), h(c.sid))
  assert.equal(gs.length, c.generatorStringLength)
  assert.equal(hex(gs), c.generatorString)

  const g = wire.calculateGenerator(PRS, h(c.CI), h(c.sid))
  assert.equal(hex(g), c.generator, 'the generator, through the Elligator2 map')
  const Ya = wire.scalarMultVfy(h(c.ya), g)
  const Yb = wire.scalarMultVfy(h(c.yb), g)
  assert.equal(hex(Ya), c.Ya)
  assert.equal(hex(Yb), c.Yb)
  assert.equal(hex(wire.scalarMultVfy(h(c.ya), Yb)), c.K)
  assert.equal(hex(wire.scalarMultVfy(h(c.yb), Ya)), c.K)

  const transcript = wire.transcriptIR(Ya, utf8(c.ADaUtf8), Yb, utf8(c.ADbUtf8))
  assert.equal(hex(transcript), c.transcriptIR)
  assert.equal(hex(wire.isk(h(c.sid), h(c.K), transcript)), c.ISK_IR)
})

test('cpace.json: the low-order points abort or return the draft value', () => {
  const scalar = h(CPACE.lowOrder.scalar)
  for (const [name, u] of Object.entries(CPACE.lowOrder.mustAbort)) {
    assert.throws(() => wire.scalarMultVfy(scalar, h(/** @type {string} */ (u))), { code: 'ERR_CPACE_NEUTRAL' }, `${name} must abort`)
  }
  for (const [name, { u, q }] of Object.entries(CPACE.lowOrder.mustSucceed)) {
    assert.equal(hex(wire.scalarMultVfy(scalar, h(u))), q, `${name} must not abort`)
  }
  assert.equal(Object.keys(CPACE.lowOrder.mustAbort).length + Object.keys(CPACE.lowOrder.mustSucceed).length, 12)
})

test('handshake.json: the whole parameter mapping', () => {
  const V = HANDSHAKE.vector
  assert.deepEqual(HANDSHAKE.labels, { ...wire.LABELS, version: wire.VERSION })

  const capsR = wire.encodeCaps(V.capsR)
  const capsS = wire.encodeCaps(V.capsS)
  assert.equal(hex(wire.channelIdentifier(V.nameplate)), V.CI)
  assert.equal(hex(wire.associatedData(capsR)), V.ADa)
  assert.equal(hex(wire.associatedData(capsS)), V.ADb)

  const g = wire.calculateGenerator(utf8(V.secret), h(V.CI), h(V.sid))
  assert.equal(hex(g), V.generator)
  const Ya = wire.scalarMultVfy(h(V.ya), g)
  const Yb = wire.scalarMultVfy(h(V.yb), g)
  assert.equal(hex(Ya), V.Ya)
  assert.equal(hex(Yb), V.Yb)
  const K = wire.scalarMultVfy(h(V.yb), Ya)
  assert.equal(hex(K), V.K)
  assert.equal(hex(wire.scalarMultVfy(h(V.ya), Yb)), V.K)

  const transcript = wire.transcriptIR(Ya, h(V.ADa), Yb, h(V.ADb))
  assert.equal(hex(transcript), V.transcript)
  const d = wire.deriveKeys(h(V.sid), K, transcript)
  assert.equal(hex(d.isk), V.isk)
  assert.equal(hex(d.macKey), V.macKey)
  assert.equal(hex(d.confirmS), V.confirmS)
  assert.equal(hex(d.confirmR), V.confirmR)
  assert.equal(hex(d.kR2S), V.kR2S)
  assert.equal(hex(d.kS2R), V.kS2R)
})

test('handshake-negative.json: every non-canonical encoding is refused, and the canonical ones are not', () => {
  for (const caps of HANDSHAKE_NEGATIVE.nonCanonicalCaps) {
    assert.equal(wire.parseCanonicalCaps(utf8(caps)), null, JSON.stringify(caps))
  }
  assert.deepEqual(wire.parseCanonicalCaps(utf8('resume,stream')), ['resume', 'stream'])
  assert.deepEqual(wire.parseCanonicalCaps(Buffer.alloc(0)), [])
  assert.equal(hex(wire.encodeCaps(['stream', 'resume', 'stream'])), hex(utf8('resume,stream')))
})

test('frames-negative.json: the sealed frames are reproduced from the fixed keys', () => {
  const S = FRAMES.sealed
  const json = (/** @type {any} */ v) => utf8(JSON.stringify(v))
  const s2r = new wire.Sealer(h(FRAMES.kS2R))
  assert.equal(hex(s2r.seal(wire.TYPE.MANIFEST, json(FRAMES.manifest))), S.manifest.hex)
  assert.equal(hex(s2r.seal(wire.TYPE.PREFIX, json({ sha256: FRAMES.manifest.sha256 }))), S.prefixAfterManifest.hex)
  assert.equal(hex(new wire.Sealer(h(FRAMES.kS2R)).seal(wire.TYPE.CHUNK, utf8('abc'))), S.chunk.hex)
  assert.equal(hex(new wire.Sealer(h(FRAMES.kS2R)).seal(0x00, json({}))), S.reserved.hex)
  assert.equal(hex(new wire.Sealer(h(FRAMES.kS2R)).seal(0x0a, json({}))), S.unassigned.hex)
  assert.equal(hex(new wire.Sealer(h(FRAMES.kR2S)).seal(wire.TYPE.ACCEPT, json({ resumeFrom: 0 }))), S.acceptR2S.hex)
})

test('frames-negative.json: what the opener refuses, it refuses on authentication', () => {
  const S = FRAMES.sealed
  /** @param {string} frame @returns {[Buffer, Buffer]} */
  const split = (frame) => { const b = h(frame); return [b.subarray(0, 4), b.subarray(4)] }
  const opener = () => new wire.Opener(h(FRAMES.kS2R))

  const [mh, ms] = split(S.manifest.hex)
  const good = opener()
  assert.equal(good.open(mh, ms).toString('utf8').slice(1), JSON.stringify(FRAMES.manifest), 'the positive control opens')
  assert.equal(good.open(mh, ms), null, 'the same frame again is a replay, under the next counter')

  assert.equal(opener().open(...split(S.manifestNoAad.hex)), null, 'no associated data')
  assert.equal(opener().open(...split(S.acceptR2S.hex)), null, 'the other direction')
  for (const v of FRAMES.vectors.filter((/** @type {any} */ v) => v.name.startsWith('a rewritten length'))) {
    const frame = h(v.frames[0])
    assert.equal(opener().open(frame.subarray(0, 4), frame.subarray(4)), null, v.name)
  }
})
