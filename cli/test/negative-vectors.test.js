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

// k_s2r = 00 01 02 ... 1f and k_r2s = 20 21 22 ... 3f. The receiver opens
// under k_s2r and seals under k_r2s; every frame is the first its direction
// has sealed (nonce counter 0) unless the vector says otherwise.
const K_S2R = Buffer.from(Array.from({ length: 32 }, (_, i) => i))
const K_R2S = Buffer.from(Array.from({ length: 32 }, (_, i) => 0x20 + i))

// The MANIFEST these vectors use, offering the three bytes "abc".
const MANIFEST = { v: 2, name: 'vector.bin', size: 3, sha256: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', blockSize: 65536 }

// The sealed frames, as this implementation produces them from the keys
// above. Pinned, and checked in the first test.
const SEALED = {
  // MANIFEST, S->R, counter 0.
  manifest: '0000009319c360478fdc94fd310f3d0cca6174058ed490818edf753e8596de3e08461c26172a325efdcc4f35fcb36d124634225efa97ce6fe83f3ff66b1a7b1c57f03bf973c61ce8972ef7e008c6efdd1bbc415950134c00768b8d8ec5d1ab07afb98080b099327dec6a3a42a6fd0cbc6e72345cebc5c2142297c8b183fb07f05bf3a816d49d6cc5a4f274d8b6c3beffae794ca2c8f8db',
  // PREFIX{sha256 of "abc"}, S->R, counter 1: the frame after the manifest.
  prefixAfterManifest: '0000005e60275eaa596b8a4f1b53440dd175202a21c75d26f6d7cc44265cd0491ddfab3be71d886f869fcfe6137ad917c4d39afdf3cf2440b05d6502535a292d0d231e4979b4568ba408b91d4c4544a993fa6423be4cfe3df32ba03e16401bf52e0e',
  // CHUNK "abc", S->R, counter 0.
  chunk: '000000141ad920524042a43231abdec67aefea679cad2bf2',
  // Type 0x00 with body "{}", S->R, counter 0.
  reserved: '0000001318c33f2b2db4201ed4dd28b4ef841f0c40206b',
  // Type 0x0a with body "{}", S->R, counter 0.
  unassigned: '0000001312c33f929fb1da176f958af841cb4db9e91b69',
  // ACCEPT{resumeFrom: 0}, R->S, counter 0: a frame for the other direction.
  acceptR2S: '0000002184187dae76fba270ff6e8b8e88ab742dbbf3e2edfed47563ebf52fa1a5cc008e81',
  // The MANIFEST above sealed WITHOUT associated data -- the pre-W15a
  // construction. Same ciphertext, different tag (the last 16 bytes).
  manifestNoAad: '0000009319c360478fdc94fd310f3d0cca6174058ed490818edf753e8596de3e08461c26172a325efdcc4f35fcb36d124634225efa97ce6fe83f3ff66b1a7b1c57f03bf973c61ce8972ef7e008c6efdd1bbc415950134c00768b8d8ec5d1ab07afb98080b099327dec6a3a42a6fd0cbc6e72345cebc5c2142297c8b183fb07f05bf3a816d49d6cc55941a5330436e5363bfff0a92b6c9b'
}

/** The manifest frame with its length rewritten by `delta`, body adjusted to match. */
function rewrittenLength (/** @type {number} */ delta) {
  const frame = bytes(SEALED.manifest)
  const sealed = frame.subarray(4)
  const body = delta > 0 ? Buffer.concat([sealed, Buffer.alloc(delta)]) : sealed.subarray(0, sealed.length + delta)
  const header = Buffer.alloc(4)
  header.writeUInt32BE(body.length)
  return hex(Buffer.concat([header, body]))
}

// Each vector: the byte strings written to the receiver, in order (`wait`
// between two of them means "after the receiver's ACCEPT"), whether the
// stream then ends, and the code the receive must fail with.
const FRAME_VECTORS = [
  { name: 'CHUNK before MANIFEST', frames: [SEALED.chunk], code: 'ERR_PROTOCOL' },
  { name: 'a 0x00 tag, sealed correctly', frames: [SEALED.reserved], code: 'ERR_PROTOCOL' },
  { name: 'an unassigned tag (0x0a), sealed correctly', frames: [SEALED.unassigned], code: 'ERR_PROTOCOL' },
  // The header alone is enough to refuse it: nothing is buffered toward it.
  { name: 'an oversize frame: a header declaring 1 MiB + 1', frames: ['00100001'], code: 'ERR_PROTOCOL' },
  { name: 'a declared length too short to be sealed (16 bytes)', frames: ['00000010' + '00'.repeat(16)], code: 'ERR_PROTOCOL' },
  // Three bytes of a header, then the stream ends. Indistinguishable from
  // a close mid-frame, and reported as the close it is -- never as a frame.
  { name: 'a truncated length prefix', frames: ['000000'], end: true, code: 'ERR_CONNECTION' },
  // A rewritten length re-delimits the frame, so the tag is read from the
  // wrong place and the frame fails to authenticate. That held before W15a
  // too; it is the attack a reader of the layout thinks of first.
  { name: 'a rewritten length (+1, one byte appended)', frames: [rewrittenLength(1)], code: 'ERR_PROTOCOL' },
  { name: 'a rewritten length (-1, last byte dropped)', frames: [rewrittenLength(-1)], code: 'ERR_PROTOCOL' },
  // What only the associated data catches (W15a): the pre-W15a seal,
  // byte-identical ciphertext under the right key and nonce, with no AAD.
  { name: 'a frame sealed without the length as associated data', frames: [SEALED.manifestNoAad], code: 'ERR_PROTOCOL' },
  { name: 'a frame sealed for the other direction (reflected)', frames: [SEALED.acceptR2S], code: 'ERR_PROTOCOL' },
  { name: 'a replayed frame: the MANIFEST twice', frames: [SEALED.manifest, SEALED.manifest], code: 'ERR_PROTOCOL' },
  { name: 'PREFIX when no resume was proposed', frames: [SEALED.manifest, 'wait', SEALED.prefixAfterManifest], code: 'ERR_PROTOCOL' }
]

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
      if (frame === 'wait') {
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
  // handshake-vectors.test.js's transcript, sid, and K. The confirmations
  // share a key and a transcript and differ only by role label, which is
  // what makes reflection fail rather than succeed.
  const sid = bytes('0123456789abcdef0123456789abcdef')
  const K = bytes('9f28ae742f859cc3f0a5b7be169c8fda37b95b710ae297618a444c1e5b5da260')
  const transcript = bytes(
    '20ccb6464cffda7c8bf5b93d45a427e1cdb2f2ff24d79d3519c3927e4b1dad3278' +
    '1001020d726573756d652c73747265616d' +
    '20f049a9334faad701af51e7c623949022b283ed9ad2cff47bf7d88d091badd74d' +
    '09010206726573756d65'
  )
  const d = deriveAll(sid, K, transcript)
  assert.equal(hex(d.confirmS), '22cb2fc85b8b54f002b21074511bcc3145b626a0fd95239e0987cc90d7d798ca')
  assert.equal(hex(d.confirmR), '8fab90ca833c0b7a1ce505de7cc606d6b372184880cc001c4c65a0d8db56b1a1')
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
const NON_CANONICAL = ['stream,resume', 'resume,resume', 'resume,', ',resume', 'resume,,stream', 'Resume', 'resume stream']

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
