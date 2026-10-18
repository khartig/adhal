'use strict'

// Minimal length-prefixed framing so a manifest (JSON) and raw file chunks
// can share one TCP stream without ambiguity. Each frame is:
//   [4-byte big-endian length][payload bytes]
// This is intentionally dumb for the loopback milestone (localhost, zero NAT).
//
// IT WAS EXPECTED TO BE REPLACED, AND IT WAS NOT. This comment used to say
// the Hyperswarm work would swap the transport for a Hyperswarm/Protomux
// channel. That never happened: Hyperswarm landed and this framing was
// carried over onto the encrypted stream unchanged. W10 then settled the
// question rather than leaving it forward-looking -- protomux@3.12.0 has
// no priority, preempt, or urgent path, so a CANCEL on a second channel
// would queue behind already-written chunk bytes exactly as it does here,
// and under v2's AEAD channel it would double-frame. The dependency is
// gone; see PROTOCOL.md section 8.2. This module stays transport-agnostic
// because that is what lets it sit under both.
//
// WHAT DELIBERATELY DID NOT LAND HERE. The failure-reporting work gives every payload a
// one-byte type tag, so CANCEL is distinguishable from file bytes. That
// tag lives in ./message.js, not here, because this module's value is that
// it has no opinion about its contents: it is the piece that stayed
// correct and untouched through the failure-reporting work, and folding the protocol into
// it would spend that. See ./message.js for the full argument.
//
// What did land here is a size bound, which is a framing concern and
// nothing else -- see maxFrameSize below.

const HEADER_SIZE = 4

// A declared length is four bytes from an untrusted peer, so its range is
// 0 to 0xFFFFFFFF. Without a bound, a peer that declares 0xFFFFFFFF makes
// this decoder buffer toward 4 GB waiting for a frame that will never
// arrive -- a peer that proved it knows the code is not thereby
// well-behaved, and nothing else in the stack caps this.
//
// 1 MiB is far above any frame a correct sender produces (a chunk is 64 KB
// plus a one-byte tag; a manifest is a few hundred bytes) and far below
// anything that threatens the process. It is a ceiling on absurdity, not a
// tuning parameter: raise it if chunkSize ever grows, and keep the gap.
const DEFAULT_MAX_FRAME_SIZE = 1024 * 1024

class FrameLengthError extends Error {
  /**
   * @param {number} length the length the peer declared
   * @param {number} max
   */
  constructor (length, max) {
    super(`frame length ${length} exceeds the ${max} byte maximum`)
    this.name = 'FrameLengthError'
    // Matches the engine's error vocabulary (see ./errors.js) without this
    // module having to depend on it -- framing predates that file and is
    // reused by callers that want nothing else from the engine.
    this.code = 'ERR_PROTOCOL'
    this.length = length
    this.max = max
  }
}

function encodeFrame (payload) {
  const header = Buffer.alloc(HEADER_SIZE)
  header.writeUInt32BE(payload.length, 0)
  return Buffer.concat([header, payload])
}

class FrameDecoder {
  /**
   * @param {(payload: Buffer) => void} onFrame
   * @param {{ maxFrameSize?: number }} [options]
   */
  constructor (onFrame, { maxFrameSize = DEFAULT_MAX_FRAME_SIZE } = {}) {
    this._onFrame = onFrame
    this._buffer = Buffer.alloc(0)
    this._maxFrameSize = maxFrameSize
  }

  push (chunk) {
    this._buffer = this._buffer.length > 0
      ? Buffer.concat([this._buffer, chunk])
      : chunk

    while (true) {
      if (this._buffer.length < HEADER_SIZE) return

      const length = this._buffer.readUInt32BE(0)
      // Checked against the *declared* length, before waiting for any of
      // the body, so an absurd header costs one comparison rather than
      // accumulating until the process dies.
      if (length > this._maxFrameSize) throw new FrameLengthError(length, this._maxFrameSize)
      if (this._buffer.length < HEADER_SIZE + length) return

      const payload = this._buffer.subarray(HEADER_SIZE, HEADER_SIZE + length)
      this._buffer = this._buffer.subarray(HEADER_SIZE + length)
      this._onFrame(payload)
    }
  }
}

module.exports = { encodeFrame, FrameDecoder, FrameLengthError, HEADER_SIZE, DEFAULT_MAX_FRAME_SIZE }
