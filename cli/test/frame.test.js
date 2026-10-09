'use strict'

// The framing and message layers, tested at the seam where an untrusted
// peer meets our buffers.
//
// Framing has been load-bearing since the loopback milestone and never had a test of its
// own -- it was covered only transitively, by 10 MB transfers that happen
// to exercise the happy path. That is enough to catch "it does not work"
// and nothing else: a decoder that mis-handles a split header, or buffers
// without bound, moves 10 MB perfectly and fails on the day a peer is
// hostile or a network is slow.
//
// Lives in cli/test/ following code-proof.test.js's precedent of testing
// engine internals from the one package that has a test runner wired up.

const test = require('node:test')
const assert = require('node:assert/strict')
const crypto = require('node:crypto')

const {
  encodeFrame,
  FrameDecoder,
  DEFAULT_MAX_FRAME_SIZE,
  encodeMessage,
  decodeMessage,
  cancelBody,
  decodeCancelReason,
  sanitizeReason,
  TYPE_MANIFEST,
  TYPE_CHUNK
} = require('@ad-hal/engine')

// Collects whole payloads out of a decoder, so each test asserts on
// message boundaries rather than on byte counts.
function collector (options) {
  /** @type {Buffer[]} */
  const frames = []
  const decoder = new FrameDecoder((payload) => frames.push(Buffer.from(payload)), options)
  return { frames, decoder }
}

test('a frame split across arbitrary chunk boundaries is reassembled', () => {
  const payload = crypto.randomBytes(300)
  const frame = encodeFrame(payload)

  // Every possible split, including ones that cut the 4-byte header in
  // half -- the case a decoder that peeks at the length before checking it
  // has arrived gets wrong, and the case a single 'data' event never
  // produces on localhost but does across a real network.
  for (let cut = 0; cut <= frame.length; cut++) {
    const { frames, decoder } = collector()
    decoder.push(frame.subarray(0, cut))
    decoder.push(frame.subarray(cut))
    assert.equal(frames.length, 1, `split at ${cut} should yield exactly one frame`)
    assert.deepEqual(frames[0], payload)
  }
})

test('frames coalesced into one chunk are all delivered, in order', () => {
  const payloads = [crypto.randomBytes(1), crypto.randomBytes(64), crypto.randomBytes(7)]
  const { frames, decoder } = collector()

  decoder.push(Buffer.concat(payloads.map(encodeFrame)))

  assert.equal(frames.length, 3)
  assert.deepEqual(frames, payloads)
})

test('an exact-boundary push delivers the frame and leaves nothing buffered', () => {
  const payload = crypto.randomBytes(128)
  const { frames, decoder } = collector()

  decoder.push(encodeFrame(payload))
  assert.deepEqual(frames, [payload])

  // A decoder holding a stale remainder would emit a bogus frame here.
  decoder.push(encodeFrame(Buffer.from('second')))
  assert.equal(frames.length, 2)
  assert.deepEqual(frames[1], Buffer.from('second'))
})

test('a zero-length frame is a frame, not an end-of-stream marker', () => {
  const { frames, decoder } = collector()
  decoder.push(encodeFrame(Buffer.alloc(0)))
  assert.equal(frames.length, 1)
  assert.equal(frames[0].length, 0)
})

test('an oversize declared length is rejected immediately, not buffered toward it', () => {
  // The bug this pins: a length is four bytes from an untrusted peer, so a
  // peer may declare 0xFFFFFFFF. With no bound the decoder accumulates
  // toward 4 GB waiting for a body that never comes. Proving code
  // knowledge (the code proof) does not make a peer well-behaved.
  const header = Buffer.alloc(4)
  header.writeUInt32BE(0xffffffff, 0)

  const { frames, decoder } = collector()
  assert.throws(
    () => decoder.push(header),
    (/** @type {any} */ err) => {
      assert.equal(err.code, 'ERR_PROTOCOL')
      assert.equal(err.length, 0xffffffff)
      return true
    }
  )
  assert.equal(frames.length, 0)

  // "Promptly" is the whole point: the four header bytes alone are enough
  // to reject, with no body in hand.
  assert.ok(DEFAULT_MAX_FRAME_SIZE < 0xffffffff)
})

test('the size bound sits above a real chunk frame and is configurable', () => {
  // A 64 KB chunk plus its tag must pass comfortably, or the bound would
  // break ordinary transfers rather than hostile ones.
  const chunkFrame = encodeMessage(TYPE_CHUNK, crypto.randomBytes(64 * 1024))
  const { frames, decoder } = collector()
  decoder.push(chunkFrame)
  assert.equal(frames.length, 1)

  const tight = collector({ maxFrameSize: 16 })
  assert.throws(() => tight.decoder.push(encodeFrame(crypto.randomBytes(17))), /exceeds the 16 byte maximum/)
})

// --- the type tag --------------------------------------------------------

test('a message round-trips through one allocation with its tag intact', () => {
  const body = crypto.randomBytes(1000)
  const frame = encodeMessage(TYPE_CHUNK, body)

  // The frame's declared length must cover the tag as well as the body,
  // or every frame after the first would be read one byte out of phase.
  assert.equal(frame.readUInt32BE(0), body.length + 1)
  assert.equal(frame.length, 4 + 1 + body.length)

  const { frames, decoder } = collector()
  decoder.push(frame)
  const decoded = decodeMessage(frames[0])
  assert.equal(decoded.type, TYPE_CHUNK)
  assert.deepEqual(decoded.body, body)
})

test('an empty body is a valid message; an empty payload is not', () => {
  const decoded = decodeMessage(encodeMessage(TYPE_MANIFEST, Buffer.alloc(0)).subarray(4))
  assert.equal(decoded.type, TYPE_MANIFEST)
  assert.equal(decoded.body.length, 0)

  assert.throws(() => decodeMessage(Buffer.alloc(0)), (/** @type {any} */ err) => {
    assert.equal(err.code, 'ERR_PROTOCOL')
    assert.match(err.message, /no type tag/)
    return true
  })
})

test('the reserved 0x00 tag reports a desynced stream, not an unsupported feature', () => {
  // These are different problems with different fixes, and 0x00 is what a
  // length read out of the middle of a payload most often produces.
  assert.throws(() => decodeMessage(Buffer.from([0x00, 0x01])), (/** @type {any} */ err) => {
    assert.equal(err.code, 'ERR_PROTOCOL')
    assert.match(err.message, /out of sync/)
    return true
  })

  assert.throws(() => decodeMessage(Buffer.from([0x42])), (/** @type {any} */ err) => {
    assert.equal(err.code, 'ERR_PROTOCOL')
    assert.match(err.message, /unknown message type 0x42/)
    return true
  })
})

test('an untagged manifest, from before type tags, is named as version skew', () => {
  // A build from before the tag existed wrote bare JSON as the payload, so
  // the first byte is '{'. Saying "unknown type 0x7b" would send whoever
  // reads it hunting a corruption bug; the fix is to redeploy.
  const legacy = Buffer.from(JSON.stringify({ type: 'manifest', name: 'a.bin' }), 'utf8')
  assert.throws(() => decodeMessage(legacy), (/** @type {any} */ err) => {
    assert.equal(err.code, 'ERR_PROTOCOL')
    assert.match(err.message, /build from before message type tags/)
    assert.match(err.message, /[Rr]edeploy both sides/)
    return true
  })
})

test('a cancel reason round-trips, and a hostile one is defanged', () => {
  // A body, not a frame: under v2 the frame is sealed by the channel, so
  // what message.js owns is the reason's encoding and nothing around it.
  assert.equal(decodeCancelReason(cancelBody('changed my mind')), 'changed my mind')

  // The reason is printed straight into a terminal, so it is untrusted
  // input in the place that is easiest to forget.
  assert.equal(sanitizeReason('a[2Kfake\nline'), 'a [2Kfake line')
  assert.ok(Buffer.byteLength(sanitizeReason('x'.repeat(10000)), 'utf8') <= 256)

  // A malformed body must not turn a clean cancel back into a mystery.
  assert.equal(decodeCancelReason(Buffer.from('not json')), '')
  assert.equal(decodeCancelReason(Buffer.from(JSON.stringify({ reason: 42 }))), '')
})
