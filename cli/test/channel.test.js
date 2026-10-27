'use strict'

// The v2 AEAD channel (PROTOCOL.md sections 3.4 and 5).
//
// Five of these are the negative vectors section 11 asks for -- tampered
// tag, tampered length, replay, reorder, wrong direction -- and they are
// the reason this file exists rather than a round-trip test. A channel that
// only round-trips is indistinguishable from one that ignores its
// authenticator, and "a specification that only says what valid looks like
// has not said much".
//
// Every failure mode below is asserted to arrive as ONE event: the
// authenticator did not verify. That is deliberate rather than lazy
// reporting -- a peer that can choose between these outcomes must not learn
// which one it achieved, so the channel does not distinguish them and
// neither do these tests.

const test = require('node:test')
const assert = require('node:assert/strict')
const crypto = require('node:crypto')

const {
  Channel,
  maxChunkSize,
  AEAD_TAG_SIZE,
  MIN_SEALED_SIZE,
  TAG_SIZE,
  TYPE_MANIFEST,
  TYPE_CHUNK,
  TYPE_CANCEL,
  TYPE_RESERVED,
  TYPE_ACCEPT,
  TYPE_END,
  TYPE_NAMES,
  encodeMessage,
  DEFAULT_MAX_FRAME_SIZE,
  HEADER_SIZE
} = require('@ad-hal/engine')
const { assertSameBytes } = require('../test-helpers/bytes')

// Stand-ins for the two directional keys the handshake derives (k_r2s and
// k_s2r). Fixed rather than random so a failure is reproducible.
const K_R2S = Buffer.alloc(32, 0x11)
const K_S2R = Buffer.alloc(32, 0x22)

// One connection's worth of channel: the receiver's view and the sender's,
// wired so that what one seals the other opens. `collect` returns the
// messages a side has been handed.
function pair (options = {}) {
  /** @type {Array<{ type: number, body: Buffer }>} */
  const atSender = []
  /** @type {Array<{ type: number, body: Buffer }>} */
  const atReceiver = []

  const receiver = new Channel({
    sendKey: K_R2S,
    receiveKey: K_S2R,
    onMessage: (type, body) => atReceiver.push({ type, body }),
    ...options
  })
  const sender = new Channel({
    sendKey: K_S2R,
    receiveKey: K_R2S,
    onMessage: (type, body) => atSender.push({ type, body }),
    ...options
  })

  return { receiver, sender, atSender, atReceiver }
}

test('a message round trips through the channel in both directions', () => {
  const { receiver, sender, atSender, atReceiver } = pair()

  const manifest = Buffer.from(JSON.stringify({ v: 2, name: 'report.pdf' }), 'utf8')
  sender.push(receiver.seal(TYPE_ACCEPT, Buffer.from('{"resumeFrom":0}', 'utf8')))
  receiver.push(sender.seal(TYPE_MANIFEST, manifest))

  assert.equal(atSender.length, 1)
  assert.equal(atSender[0].type, TYPE_ACCEPT)
  assert.equal(atReceiver.length, 1)
  assert.equal(atReceiver[0].type, TYPE_MANIFEST)
  assert.deepEqual(atReceiver[0].body, manifest)

  // An empty body is a real case -- END{} and a zero-length chunk both
  // produce one -- and it is the shortest frame the cipher will be asked
  // to open.
  receiver.push(sender.seal(TYPE_END, Buffer.alloc(0)))
  assert.equal(atReceiver[1].type, TYPE_END)
  assert.equal(atReceiver[1].body.length, 0)
})

test('a sealed frame reveals neither its type nor its body, and each one differs', () => {
  const { receiver, sender } = pair()
  const body = Buffer.from('the quick brown fox', 'utf8')

  const first = sender.seal(TYPE_CHUNK, body)
  const second = sender.seal(TYPE_CHUNK, body)

  // The type tag is inside the seal (section 5), so it must not be legible
  // on the wire. v1 put it in the clear, and encodeMessage still produces
  // that shape -- comparing against it is what makes this deterministic
  // rather than a 1-in-256 guess about the first ciphertext byte.
  assert.equal(first.includes(body), false, 'the body must not appear in the clear')
  assert.notDeepEqual(
    first,
    encodeMessage(TYPE_CHUNK, body),
    'a sealed frame must not be v1\'s cleartext [length][type][body]'
  )

  // The counter advances, so identical plaintexts produce different
  // ciphertexts. If these matched, the nonce would be static and the
  // construction would be broken in the one way it cannot survive.
  assert.notDeepEqual(first, second, 'two identical messages must not seal identically')
  assert.deepEqual(sender.frames, { sent: 2n, received: 0n })

  // Both still open, in order.
  receiver.push(Buffer.concat([first, second]))
  assert.deepEqual(receiver.frames, { sent: 0n, received: 2n })
})

test('the frame length prefix stays outside the ciphertext so a frame can be bounded first', () => {
  const { sender } = pair()
  const body = Buffer.from('x'.repeat(100), 'utf8')
  const frame = sender.seal(TYPE_CHUNK, body)

  // Section 5's reason for keeping it outside: the decoder must reject an
  // absurd declared length before buffering toward it.
  assert.equal(frame.readUInt32BE(0), TAG_SIZE + body.length + AEAD_TAG_SIZE)
  assert.equal(frame.length, HEADER_SIZE + TAG_SIZE + body.length + AEAD_TAG_SIZE)
})

test('the length prefix is bound into the tag as associated data, and nothing else is', () => {
  // THE CONSTRUCTION, rebuilt with node:crypto instead of trusted. Every
  // other test here would pass whether or not the header is associated
  // data: a rewritten length re-delimits the stream, so the frame fails to
  // open either way. What only this test can tell apart is the exact
  // construction section 5 specifies --
  //
  //   AEAD(k_s2r, nonce 0, [type][body], aad = [4-byte BE length])
  //
  // -- from its two nearest wrong versions: no associated data (the pre-W15a
  // wire) and associated data that is something other than the header.
  const { receiver, sender } = pair()
  const body = Buffer.from('bound', 'utf8')
  const plaintext = Buffer.concat([Buffer.from([TYPE_CHUNK]), body])
  const header = Buffer.alloc(HEADER_SIZE)
  header.writeUInt32BE(plaintext.length + AEAD_TAG_SIZE, 0)
  const nonce0 = Buffer.alloc(12)

  /** @param {Buffer | null} aad */
  const sealBy = (aad) => {
    const cipher = crypto.createCipheriv('chacha20-poly1305', K_S2R, nonce0, { authTagLength: AEAD_TAG_SIZE })
    if (aad) cipher.setAAD(aad)
    return Buffer.concat([header, cipher.update(plaintext), cipher.final(), cipher.getAuthTag()])
  }

  // Byte-identical to what the channel produces for its first frame.
  assert.deepEqual(sender.seal(TYPE_CHUNK, body), sealBy(header))

  // And the receiver holds the peer to it. Each attempt gets a fresh
  // channel, because the first failed open is terminal.
  const fresh = () => pair().receiver
  assert.throws(() => fresh().push(sealBy(null)), /failed to authenticate/, 'no associated data: the pre-W15a wire')
  assert.throws(() => fresh().push(sealBy(Buffer.alloc(HEADER_SIZE))), /failed to authenticate/, 'associated data that is not the header')
  assert.doesNotThrow(() => receiver.push(sealBy(header)))
  assert.deepEqual(receiver.frames, { sent: 0n, received: 1n })
})

test('a tampered authenticator is refused', () => {
  const { receiver, sender, atReceiver } = pair()
  const frame = sender.seal(TYPE_CHUNK, Buffer.from('payload', 'utf8'))

  // Flip the last bit of the Poly1305 tag.
  frame[frame.length - 1] ^= 0x01

  assert.throws(() => receiver.push(frame), /** @param {any} err */ (err) => {
    assert.equal(err.code, 'ERR_PROTOCOL')
    assert.match(err.message, /failed to authenticate/)
    return true
  })
  assert.equal(atReceiver.length, 0, 'nothing may be delivered from a frame that did not open')
})

test('a tampered ciphertext is refused', () => {
  const { receiver, sender } = pair()
  const frame = sender.seal(TYPE_CHUNK, Buffer.from('payload', 'utf8'))

  // A byte of the ciphertext rather than of the tag. ChaCha20 is a stream
  // cipher, so this flips exactly the corresponding plaintext bit -- which
  // is precisely why the authenticator is not optional.
  frame[HEADER_SIZE + 2] ^= 0xff

  assert.throws(() => receiver.push(frame), /failed to authenticate/)
})

test('a tampered length prefix is refused', () => {
  // The length is authenticated as associated data (see the test above),
  // and a rewritten one also re-delimits the stream, so the frame it points
  // at fails to open on both counts. Kept as a negative vector because it is
  // the attack a reader of the frame layout thinks of first.
  const { receiver, sender } = pair()
  const frame = sender.seal(TYPE_CHUNK, Buffer.from('payload-of-known-length', 'utf8'))

  const shortened = Buffer.from(frame)
  shortened.writeUInt32BE(frame.readUInt32BE(0) - 1, 0)
  assert.throws(() => receiver.push(shortened), /failed to authenticate/)

  // Declaring more than arrived is not an error at all -- it is an
  // incomplete frame, and the decoder must wait rather than guess. Worth
  // pinning: treating it as a failure would break every split chunk.
  const { receiver: fresh } = pair()
  const lengthened = Buffer.from(frame)
  lengthened.writeUInt32BE(frame.readUInt32BE(0) + 1, 0)
  assert.doesNotThrow(() => fresh.push(lengthened))
  assert.deepEqual(fresh.frames, { sent: 0n, received: 0n }, 'an incomplete frame delivers nothing')
})

test('an absurd declared length is refused before anything is buffered toward it', () => {
  const { receiver } = pair()
  const header = Buffer.alloc(HEADER_SIZE)
  header.writeUInt32BE(0xffffffff, 0)

  // The bound that stops a peer making the decoder accumulate toward 4 GB.
  // Enforced by ./frame.js, which the channel reuses unchanged.
  assert.throws(() => receiver.push(header), /** @param {any} err */ (err) => {
    assert.equal(err.code, 'ERR_PROTOCOL')
    assert.match(err.message, /exceeds the \d+ byte maximum/)
    return true
  })
})

test('a frame too short to be sealed is refused without reaching the cipher', () => {
  const { receiver } = pair()
  // A valid length prefix over a payload that cannot possibly be a seal:
  // one byte short of a type tag plus an authenticator.
  const runt = Buffer.alloc(HEADER_SIZE + MIN_SEALED_SIZE - 1)
  runt.writeUInt32BE(MIN_SEALED_SIZE - 1, 0)

  assert.throws(() => receiver.push(runt), /** @param {any} err */ (err) => {
    assert.equal(err.code, 'ERR_PROTOCOL')
    assert.match(err.message, /too short to be sealed/)
    return true
  })
})

test('a replayed frame is refused, because the counter has already moved', () => {
  const { receiver, sender, atReceiver } = pair()
  const frame = sender.seal(TYPE_CHUNK, Buffer.from('once', 'utf8'))

  receiver.push(Buffer.from(frame))
  assert.equal(atReceiver.length, 1)

  // The same bytes again. Nothing about the frame changed; what changed is
  // that the receiver's counter is now 1, so the nonce it will try does not
  // match the one the frame was sealed under. This is the defense v1 got
  // from per-attempt nonces, made structural.
  assert.throws(() => receiver.push(Buffer.from(frame)), /failed to authenticate/)
  assert.equal(atReceiver.length, 1, 'a replay must not be delivered')
})

test('a reordered frame is refused, and so is a skipped one', () => {
  const { receiver, sender } = pair()
  const first = sender.seal(TYPE_CHUNK, Buffer.from('one', 'utf8'))
  const second = sender.seal(TYPE_CHUNK, Buffer.from('two', 'utf8'))

  // Frame 1 presented where frame 0 is expected. Under UDX/Noise this
  // cannot happen by accident -- the transport is reliable and ordered --
  // so it is an attacker or a bug either way, and it must not open.
  assert.throws(() => receiver.push(second), /failed to authenticate/)

  // And once a counter has moved past a frame, that frame is gone: the
  // channel offers no reordering window at all, because a window is state
  // an attacker can aim at.
  const { receiver: fresh } = pair()
  fresh.push(first)
  assert.throws(() => fresh.push(first), /failed to authenticate/)
})

test('a channel that failed to open a frame refuses everything after it', () => {
  // THE TEST THAT SHOULD HAVE EXISTED WITH THE CLAIM. This module's
  // comment asserted that a failed open is terminal, and it was not: the
  // receive counter and the decoder's buffer are both left correctly
  // positioned for the peer's NEXT frame, so a caller that caught the
  // error and carried on would silently skip the frame that failed.
  //
  // Against a forged or corrupted CHUNK that is a hole in the output file,
  // caught later by the SHA-256 -- integrity by accident, reported as a
  // hash mismatch rather than as tampering. Against a forged CANCEL it is
  // a no-op. Both current callers do treat a throw as fatal, so this was
  // latent; it is a caller convention guarding a security boundary, and
  // v2 has just added five message types whose handling is the natural
  // place for someone to add a per-frame try/catch.
  const { receiver, sender, atReceiver } = pair()
  const first = sender.seal(TYPE_CHUNK, Buffer.from('one', 'utf8'))
  const tampered = sender.seal(TYPE_CHUNK, Buffer.from('two', 'utf8'))
  const third = sender.seal(TYPE_CHUNK, Buffer.from('three', 'utf8'))

  receiver.push(first)
  assert.equal(atReceiver.length, 1)

  tampered[HEADER_SIZE + 2] ^= 0xff
  assert.throws(() => receiver.push(tampered), /failed to authenticate/)

  // The frame after the failure must NOT be delivered. Without the latch
  // this push succeeds and atReceiver grows to 2 -- the whole defect.
  assert.throws(() => receiver.push(third), /** @param {any} err */ (err) => {
    assert.equal(err.code, 'ERR_PROTOCOL')
    assert.match(err.message, /already failed to open a frame/)
    return true
  })
  assert.equal(atReceiver.length, 1, 'no frame after a failed open may be delivered')

  // And it stays refused, rather than the latch being a one-shot.
  assert.throws(() => receiver.push(Buffer.alloc(0)), /already failed/)
})

test('the short-frame rejection is terminal too, not just the tag failure', () => {
  // The two failure paths used to leave the counter in DIFFERENT states --
  // the short-frame check throws before the counter advances, the tag
  // failure after. That asymmetry meant "is the counter where it should
  // be?" was not a usable proxy for "did this channel fail?", so the latch
  // has to be set on both paths rather than inferred from the counter.
  const { receiver, sender, atReceiver } = pair()
  const runt = Buffer.alloc(HEADER_SIZE + MIN_SEALED_SIZE - 1)
  runt.writeUInt32BE(MIN_SEALED_SIZE - 1, 0)

  assert.throws(() => receiver.push(runt), /too short to be sealed/)
  assert.throws(() => receiver.push(sender.seal(TYPE_CHUNK, Buffer.from('after', 'utf8'))), /already failed/)
  assert.equal(atReceiver.length, 0)
})

test('a frame sealed under k_r2s does not open under k_s2r', () => {
  // Separate keys per direction, so a frame cannot be reflected back at
  // the peer that sent it. With one shared key this would open cleanly,
  // AND the two directions' counters would collide on frame 0 -- reusing a
  // nonce immediately.
  const receiver = new Channel({ sendKey: K_R2S, receiveKey: K_S2R, onMessage: () => {} })
  const reflector = new Channel({ sendKey: K_S2R, receiveKey: K_R2S, onMessage: () => {} })

  const fromReceiver = receiver.seal(TYPE_CANCEL, Buffer.from('{"reason":"stop"}', 'utf8'))

  // The sender opens it correctly, since it receives under k_r2s.
  assert.doesNotThrow(() => reflector.push(Buffer.from(fromReceiver)))

  // But the receiver itself cannot: it only ever opens under k_s2r.
  const echo = new Channel({ sendKey: K_R2S, receiveKey: K_S2R, onMessage: () => {} })
  assert.throws(() => echo.push(Buffer.from(fromReceiver)), /sealed for the other direction|failed to authenticate/)
})

test('one key for both directions is refused outright', () => {
  // A plausible mistake, because both keys come out of one HKDF call site,
  // and a silent one: two counters starting at zero under one key reuse a
  // nonce on the very first frame in each direction.
  assert.throws(
    () => new Channel({ sendKey: K_R2S, receiveKey: Buffer.from(K_R2S), onMessage: () => {} }),
    (err) => {
      assert.ok(err instanceof TypeError)
      assert.match(err.message, /must differ/)
      return true
    }
  )

  for (const bad of [Buffer.alloc(31, 1), Buffer.alloc(33, 1), 'not a buffer', undefined]) {
    assert.throws(
      () => new Channel({ sendKey: /** @type {any} */ (bad), receiveKey: K_S2R, onMessage: () => {} }),
      TypeError
    )
  }
})

test('maxChunk is an equation, and the boundary is exact', () => {
  // v1's off-by-one, pinned. MAX_CHUNK_SIZE and the frame cap were both
  // written as 1024 * 1024, but a one-byte type tag made a maximum-sized
  // chunk one byte over the cap: the manifest validated and the first chunk
  // was refused. v2 has two terms to account for rather than one.
  assert.equal(maxChunkSize(), DEFAULT_MAX_FRAME_SIZE - TAG_SIZE - AEAD_TAG_SIZE)
  assert.equal(maxChunkSize(), 1048559, 'section 5 states this number; it must be derived, not restated')
  assert.equal(maxChunkSize(1024), 1024 - 17)

  const { receiver, sender, atReceiver } = pair()
  assert.equal(sender.maxChunk, 1048559)

  // Exactly the maximum must be accepted, and the frame it produces must
  // be exactly the cap -- not one byte over it, which is the bug.
  const biggest = crypto.randomBytes(sender.maxChunk)
  const frame = sender.seal(TYPE_CHUNK, biggest)
  assert.equal(frame.length - HEADER_SIZE, DEFAULT_MAX_FRAME_SIZE)
  assert.doesNotThrow(() => receiver.push(frame))
  assertSameBytes(atReceiver[0].body, biggest)

  // And one byte more must be refused by the sender, where the caller can
  // see which of its own frames was too big, rather than arriving as an
  // ERR_PROTOCOL from the far end after the bytes are on the wire.
  assert.throws(() => sender.seal(TYPE_CHUNK, Buffer.alloc(sender.maxChunk + 1)), /** @param {any} err */ (err) => {
    assert.equal(err.code, 'ERR_PROTOCOL')
    assert.equal(err.max, 1048559)
    assert.equal(err.bytes, 1048560)
    return true
  })
})

test('a non-default frame cap moves the chunk bound with it', () => {
  // The equation has to hold at any cap, or the two numbers drift apart
  // again the next time one of them is tuned.
  const { receiver, sender, atReceiver } = pair({ maxFrameSize: 4096 })
  assert.equal(sender.maxChunk, 4096 - 17)

  const body = crypto.randomBytes(sender.maxChunk)
  assert.doesNotThrow(() => receiver.push(sender.seal(TYPE_CHUNK, body)))
  assertSameBytes(atReceiver[0].body, body)
  assert.throws(() => sender.seal(TYPE_CHUNK, Buffer.alloc(sender.maxChunk + 1)), /exceeds the 4079-byte maximum/)
})

test('the reserved type 0x00 is still refused after a frame opens', () => {
  // 0x00 stays reserved under v2, but its job has changed. It was v1's
  // desync sentinel, catchable because the tag was in the clear; now the
  // tag is inside the seal, so desync fails at the authenticator first.
  // This is the remaining case: a frame that DID open and still carries it,
  // which can only be a peer sending something it must not.
  const { receiver, sender } = pair()
  assert.throws(() => receiver.push(sender.seal(TYPE_RESERVED, Buffer.alloc(4))), /** @param {any} err */ (err) => {
    assert.equal(err.code, 'ERR_PROTOCOL')
    assert.match(err.message, /reserved type 0x00/)
    return true
  })
})

test('the v2 message types are named rather than reported as unknown', () => {
  // A type missing from TYPE_NAMES arrives as "unknown message type 0x04",
  // which reads like a corrupt stream. Named, the v1 transfer path refuses
  // the same frame as "receiver sent ACCEPT during a transfer" -- accurate
  // about a version skew instead of blaming the framing.
  assert.deepEqual(
    [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09].map((t) => TYPE_NAMES.get(t)),
    ['MANIFEST', 'CHUNK', 'CANCEL', 'ACCEPT', 'DECLINE', 'CHECKPOINT', 'RESULT', 'END', 'PREFIX']
  )
  assert.equal(TYPE_NAMES.has(TYPE_RESERVED), false, '0x00 must stay nameless and invalid')
  assert.equal(TYPE_NAMES.has(0x0a), false, 'the space above PREFIX is still unassigned')
})

test('frames arriving split or coalesced are reassembled by byte count', () => {
  // The discipline ./frame.js already applies, asserted through the
  // channel because the seal makes the consequence worse: a frame handed
  // to the cipher one byte short fails to authenticate, which would
  // present as an attack rather than as a partial read.
  const { receiver, sender, atReceiver } = pair()
  const frames = Buffer.concat([
    sender.seal(TYPE_MANIFEST, Buffer.from('{"v":2}', 'utf8')),
    sender.seal(TYPE_CHUNK, crypto.randomBytes(300)),
    sender.seal(TYPE_END, Buffer.from('{"sha256":"ab"}', 'utf8'))
  ])

  // One byte at a time: the worst case the transport can produce.
  for (const byte of frames) receiver.push(Buffer.from([byte]))
  assert.deepEqual(atReceiver.map((m) => m.type), [TYPE_MANIFEST, TYPE_CHUNK, TYPE_END])

  // And all three coalesced into one push.
  const { receiver: bulk, sender: bulkSender, atReceiver: got } = pair()
  bulk.push(Buffer.concat([
    bulkSender.seal(TYPE_MANIFEST, Buffer.from('{"v":2}', 'utf8')),
    bulkSender.seal(TYPE_CHUNK, Buffer.alloc(10)),
    bulkSender.seal(TYPE_END, Buffer.alloc(0))
  ]))
  assert.deepEqual(got.map((m) => m.type), [TYPE_MANIFEST, TYPE_CHUNK, TYPE_END])
})

// --- wipe (Q-18) -----------------------------------------------------------

test('a wiped channel has zero keys and refuses to seal or open anything', () => {
  const sendKey = Buffer.from(K_R2S)
  const receiveKey = Buffer.from(K_S2R)
  const channel = new Channel({ sendKey, receiveKey, onMessage: () => {} })
  channel.wipe()
  assert.ok(sendKey.every((b) => b === 0) && receiveKey.every((b) => b === 0), 'the caller\'s own Buffers are cleared')
  assert.throws(() => channel.seal(TYPE_CHUNK, Buffer.alloc(1)), /keys wiped/)
  assert.throws(() => channel.push(Buffer.alloc(8)), /keys wiped/)

  // And keys that were wiped are named as such if anyone tries again,
  // rather than failing as "must differ".
  assert.throws(() => new Channel({ sendKey, receiveKey, onMessage: () => {} }), /already used by a transfer/)
})
