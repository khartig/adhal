'use strict'

// Negative vectors (PROTOCOL.md section 11): inputs a correct
// implementation must refuse, and the refusal it must give.
//
// A specification that only says what valid looks like has not said much,
// and neither has a vector set that only pins the happy path. These are
// published beside the positive ones (code-vectors, handshake-vectors) for
// a second implementation to replay.
//
// TWO KINDS, and the difference is stated rather than blurred:
//
//   FRAME vectors are exact bytes. The channel keys are fixed, so every
//   sealed frame below is reproducible byte for byte, and the first test
//   checks that this implementation still produces them. Feed them to a
//   receiver keyed the same way and it must refuse each one as shown.
//
//   HANDSHAKE vectors are transformations of a live handshake: take an
//   honest HELLO or REPLY, alter it as described, and the named side must
//   refuse. They cannot be fixed bytes, because nothing in this engine
//   accepts an injected scalar or sid (section 3.2, trap #1) -- a fixed
//   HELLO would need exactly that. The one exception is the reflection
//   vector, which is stated over handshake-vectors.test.js's fixed
//   transcript.

const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('node:path')
const os = require('node:os')
const fs = require('node:fs')
const crypto = require('node:crypto')

const {
  Channel,
  receiveFile,
  connectOnce,
  AttemptCap,
  Initiator,
  Responder,
  MessageReader,
  deriveAll,
  confirmationMatches,
  HELLO_FIXED,
  REPLY_FIXED,
  LENGTH_PREFIX_SIZE,
  ERR_CONFIRMATION,
  ERR_SID_REUSED,
  TYPE_ACCEPT,
  generateCode,
  splitCode
} = require('@ad-hal/engine')
const { duplexPair } = require('../test-helpers/duplex-pair')
const { FakeSwarm } = require('../test-helpers/fake-swarm')

const hex = (/** @type {Buffer} */ b) => b.toString('hex')
const bytes = (/** @type {string} */ h) => Buffer.from(h, 'hex')

// --- frame vectors --------------------------------------------------------

// The vectors are in conformance/vectors/frames-negative.json, which is
// what a second implementation replays; this file reads them from there so
// the two cannot drift apart.
//
// k_s2r = 00 01 02 ... 1f and k_r2s = 20 21 22 ... 3f. The receiver opens
// under k_s2r and seals under k_r2s; every frame is the first its direction
// has sealed (nonce counter 0) unless the vector says otherwise.
const FRAMES = require('../../conformance/vectors/frames-negative.json')
const K_S2R = bytes(FRAMES.kS2R)
const K_R2S = bytes(FRAMES.kR2S)

// The MANIFEST these vectors use, offering the three bytes "abc".
const MANIFEST = FRAMES.manifest

// The sealed frames, as this implementation produces them from the keys
// above. Pinned, and checked in the first test. Each one's `what` in the
// JSON says what it is.
/** @type {Record<string, string>} */
const SEALED = Object.fromEntries(Object.entries(FRAMES.sealed).map(([k, v]) => [k, /** @type {any} */ (v).hex]))

// Each vector: the byte strings written to the receiver, in order ("await
// ACCEPT" between two of them means "after the receiver's ACCEPT"), whether
// the stream then ends, and the code the receive must fail with. Three are
// worth knowing about without opening the JSON:
//
//   - A truncated length prefix is three header bytes and then the end of
//     the stream. Indistinguishable from a close mid-frame, and reported
//     as the close it is -- never as a frame.
//   - A rewritten length re-delimits the frame, so the tag is read from
//     the wrong place and the frame fails to authenticate. That held
//     before W15a too; it is the attack a reader of the layout thinks of
//     first.
//   - What only the associated data catches (W15a): the pre-W15a seal,
//     byte-identical ciphertext under the right key and nonce, with no AAD.
/** @type {Array<{ name: string, frames: string[], end?: boolean, code: string }>} */
const FRAME_VECTORS = FRAMES.vectors

test('the frame vectors are the frames this implementation seals from the fixed keys', () => {
  const tx = () => new Channel({ sendKey: Buffer.from(K_S2R), receiveKey: Buffer.from(K_R2S), onMessage () {} })
  const json = (/** @type {any} */ v) => Buffer.from(JSON.stringify(v), 'utf8')
  const both = tx()
  assert.equal(hex(both.seal(0x01, json(MANIFEST))), SEALED.manifest)
  assert.equal(hex(both.seal(0x09, json({ sha256: MANIFEST.sha256 }))), SEALED.prefixAfterManifest)
  assert.equal(hex(tx().seal(0x02, Buffer.from('abc'))), SEALED.chunk)
  assert.equal(hex(tx().seal(0x00, json({}))), SEALED.reserved)
  assert.equal(hex(tx().seal(0x0a, json({}))), SEALED.unassigned)
  const rx = new Channel({ sendKey: Buffer.from(K_R2S), receiveKey: Buffer.from(K_S2R), onMessage () {} })
  assert.equal(hex(rx.seal(0x04, json({ resumeFrom: 0 }))), SEALED.acceptR2S)

  // The no-AAD vector, rebuilt with node:crypto rather than trusted: it
  // differs from the real MANIFEST frame in its tag and nowhere else.
  const plaintext = Buffer.concat([Buffer.from([0x01]), json(MANIFEST)])
  const cipher = crypto.createCipheriv('chacha20-poly1305', K_S2R, Buffer.alloc(12), { authTagLength: 16 })
  const noAad = Buffer.concat([bytes(SEALED.manifest).subarray(0, 4), cipher.update(plaintext), cipher.final(), cipher.getAuthTag()])
  assert.equal(hex(noAad), SEALED.manifestNoAad)
  assert.equal(SEALED.manifestNoAad.slice(0, -32), SEALED.manifest.slice(0, -32), 'only the tag differs')
  assert.notEqual(SEALED.manifestNoAad.slice(-32), SEALED.manifest.slice(-32))

  // And the positive control: the manifest and a chunk, in order, deliver.
  const opened = []
  const reader = new Channel({ sendKey: Buffer.from(K_R2S), receiveKey: Buffer.from(K_S2R), onMessage: (type, body) => opened.push([type, body.toString('utf8')]) })
  reader.push(bytes(SEALED.manifest))
  assert.deepEqual(opened, [[0x01, JSON.stringify(MANIFEST)]])
})

for (const vector of FRAME_VECTORS) {
  test(`frame vector: ${vector.name} -> ${vector.code}`, async (t) => {
    const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'adhal-negvec-'))
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
    const [far, near] = duplexPair()
    let accepted = false
    // The far end reads the receiver's frames only to know when it has
    // answered; it holds k_r2s to open them.
    const listener = new Channel({ sendKey: Buffer.from(K_S2R), receiveKey: Buffer.from(K_R2S), onMessage: (type) => { if (type === TYPE_ACCEPT) accepted = true } })
    far.on('data', (/** @type {Buffer} */ chunk) => { try { listener.push(chunk) } catch {} })

    const received = receiveFile(near, dir, { sendKey: Buffer.from(K_R2S), receiveKey: Buffer.from(K_S2R) })
      .then(() => null, (err) => err)
    for (const frame of vector.frames) {
      if (frame === 'await ACCEPT') {
        for (let i = 0; i < 200 && !accepted; i++) await new Promise((resolve) => setTimeout(resolve, 5))
        assert.ok(accepted, 'the receiver answered the manifest before the next frame')
        continue
      }
      far.write(bytes(frame))
    }
    if (vector.end) far.end()
    // A vector that is wrongly accepted leaves the receiver waiting for
    // the rest of a transfer; that must fail here, not hang the suite.
    t.after(() => { near.destroy(); far.destroy() })
    const err = await Promise.race([received, new Promise((resolve) => setTimeout(() => resolve('accepted'), 2000).unref())])
    assert.notEqual(err, 'accepted', `${vector.name} was accepted: the receiver is still waiting for more`)
    assert.ok(err, `${vector.name} was accepted`)
    assert.equal(err.code, vector.code, err.message)
    assert.deepEqual(await fs.promises.readdir(dir), [], 'nothing was written')
  })
}

test('frame vector, at the channel: an oversize header throws on its four bytes; a truncated one yields nothing', () => {
  const opened = []
  const channel = () => new Channel({ sendKey: Buffer.from(K_R2S), receiveKey: Buffer.from(K_S2R), onMessage: (type) => opened.push(type) })
  assert.throws(() => channel().push(bytes('00100001')), { code: 'ERR_PROTOCOL' })
  channel().push(bytes('000000'))
  assert.deepEqual(opened, [], 'three bytes of header are neither a frame nor an error: the close decides')
})

// --- handshake vectors ----------------------------------------------------

/** @param {Buffer} message @param {number} fixed @param {string} caps */
function withCaps (message, fixed, caps) {
  const body = Buffer.concat([message.subarray(LENGTH_PREFIX_SIZE, LENGTH_PREFIX_SIZE + fixed), Buffer.from(caps, 'utf8')])
  const out = Buffer.alloc(LENGTH_PREFIX_SIZE + body.length)
  out.writeUInt16BE(body.length)
  body.copy(out, LENGTH_PREFIX_SIZE)
  return out
}

/** @param {Buffer} message */
const reading = (message) => { const r = new MessageReader(); r.push(message); return r }

/** @param {() => any} fn @param {string} code */
function refuses (fn, code) {
  assert.throws(fn, (/** @type {any} */ err) => {
    assert.equal(err.code, code, err.message)
    return true
  })
}

function pair () {
  const code = splitCode(generateCode())
  return { ...code, initiator: new Initiator(code), responder: new Responder(code) }
}

test('handshake vector: a reflected confirmation -- the sender\'s own confirmS returned as CONFIRM -- fails', () => {
  const { initiator, responder } = pair()
  const { reply } = /** @type {any} */ (responder.readHello(reading(initiator.hello())))
  const confirmS = reply.subarray(LENGTH_PREFIX_SIZE + 32, LENGTH_PREFIX_SIZE + REPLY_FIXED)
  refuses(() => responder.readConfirm(reading(confirmS)), ERR_CONFIRMATION)
})

test('handshake vector: over the fixed transcript, neither confirmation verifies as the other', () => {
  // handshake.json's transcript, sid, and K, the vector
  // handshake-vectors.test.js checks. The confirmations share a key and a
  // transcript and differ only by role label, which is what makes
  // reflection fail rather than succeed.
  const { vector: V } = require('../../conformance/vectors/handshake.json')
  const { reflection } = require('../../conformance/vectors/handshake-negative.json')
  const d = deriveAll(bytes(V.sid), bytes(V.K), bytes(V.transcript))
  assert.equal(hex(d.confirmS), reflection.confirmS)
  assert.equal(hex(d.confirmR), reflection.confirmR)
  assert.equal(confirmationMatches(d.confirmS, d.confirmR), false, 'confirmR must not pass where confirmS is checked')
  assert.equal(confirmationMatches(d.confirmR, d.confirmS), false, 'confirmS must not pass where confirmR is checked')
})

test('handshake vector: capabilities stripped from HELLO in transit fail the receiver\'s confirmation', () => {
  const { initiator, responder } = pair()
  const downgraded = withCaps(initiator.hello(), HELLO_FIXED, 'stream')
  const { reply } = /** @type {any} */ (responder.readHello(reading(downgraded)))
  refuses(() => initiator.readReply(reading(reply)), ERR_CONFIRMATION)
})

test('handshake vector: capabilities stripped from REPLY in transit fail the receiver\'s confirmation', () => {
  const { initiator, responder } = pair()
  const { reply } = /** @type {any} */ (responder.readHello(reading(initiator.hello())))
  refuses(() => initiator.readReply(reading(withCaps(reply, REPLY_FIXED, 'stream'))), ERR_CONFIRMATION)
})

// Every one is a set some serializer could produce, and the canonical form
// (section 3.2, trap #2) forbids. Refused, never normalized.
/** @type {string[]} */
const NON_CANONICAL = require('../../conformance/vectors/handshake-negative.json').nonCanonicalCaps

for (const caps of NON_CANONICAL) {
  test(`handshake vector: non-canonical caps ${JSON.stringify(caps)} in HELLO are refused by the sender`, () => {
    const { initiator, responder } = pair()
    refuses(() => responder.readHello(reading(withCaps(initiator.hello(), HELLO_FIXED, caps))), 'ERR_PROTOCOL')
  })
  test(`handshake vector: non-canonical caps ${JSON.stringify(caps)} in REPLY are refused by the receiver`, () => {
    const { initiator, responder } = pair()
    const { reply } = /** @type {any} */ (responder.readHello(reading(initiator.hello())))
    refuses(() => initiator.readReply(reading(withCaps(reply, REPLY_FIXED, caps))), 'ERR_PROTOCOL')
  })
}

test('handshake vector: a v1 peer\'s opening (version 0x01) is named as a version skew', () => {
  const { initiator, responder } = pair()
  const hello = Buffer.from(initiator.hello())
  hello[LENGTH_PREFIX_SIZE] = 0x01
  assert.throws(() => responder.readHello(reading(hello)), (/** @type {any} */ err) => err.code === 'ERR_PROTOCOL' && /version skew/.test(err.message))
})

test('handshake vector: a sealed frame where HELLO belongs is refused on its declared length', () => {
  // A sender that skipped the handshake: its first bytes are a frame
  // header, read here as a HELLO length prefix of 0.
  const { responder } = pair()
  refuses(() => responder.readHello(reading(bytes(SEALED.manifest))), 'ERR_PROTOCOL')
})

// The sid vectors run through connectOnce, because remembering sids is the
// sender's join, not its Responder: one Responder serves one connection.
/** @param {(swarm: InstanceType<typeof FakeSwarm>, code: { secret: string, nameplate: string }) => Promise<void>} play */
async function senderDrops (play) {
  const code = splitCode(generateCode())
  const swarm = new FakeSwarm()
  /** @type {Array<string | undefined>} */
  const codes = []
  /** @type {Array<() => void>} */
  const waiters = []
  const joined = connectOnce(/** @type {any} */ (swarm), Buffer.alloc(32), {
    ...code,
    attemptCap: new AttemptCap({ baseDelayMs: 1 }),
    handshakeTimeout: 500,
    refreshInterval: 0,
    timeout: 10000,
    onCandidateDropped: (_info, _reason, why) => { codes.push(why); const w = waiters.shift(); if (w) w() }
  })
  joined.catch(() => {})
  const next = () => new Promise((resolve) => { waiters.push(() => resolve(undefined)) })
  await play(swarm, code)
  return { codes, next }
}

test('handshake vector: a HELLO replayed on a second connection is a reused sid, and counted', async () => {
  const { codes } = await senderDrops(async (swarm, code) => {
    const hello = new Initiator(code).hello()
    await new Promise((resolve) => swarm.candidate((far, near) => { far.write(hello); far.once('data', () => { near.destroy(); resolve(undefined) }) }))
    await new Promise((resolve) => { swarm.candidate((far) => far.write(hello)); setTimeout(resolve, 50) })
  })
  assert.equal(codes.at(-1), ERR_SID_REUSED)
})

test('handshake vector: a fresh Ya under a sid already seen is a reused sid, and counted', async () => {
  const { codes } = await senderDrops(async (swarm, code) => {
    const first = new Initiator(code).hello()
    await new Promise((resolve) => swarm.candidate((far, near) => { far.write(first); far.once('data', () => { near.destroy(); resolve(undefined) }) }))
    const second = Buffer.from(new Initiator(code).hello())
    first.copy(second, LENGTH_PREFIX_SIZE + 1, LENGTH_PREFIX_SIZE + 1, LENGTH_PREFIX_SIZE + 17)
    await new Promise((resolve) => { swarm.candidate((far) => far.write(second)); setTimeout(resolve, 50) })
  })
  assert.equal(codes.at(-1), ERR_SID_REUSED)
})
