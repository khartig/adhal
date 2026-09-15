'use strict'

// Minimal length-prefixed framing so a manifest (JSON) and raw file chunks
// can share one TCP stream without ambiguity. Each frame is:
//   [4-byte big-endian length][payload bytes]
// This is intentionally dumb for item 1 (localhost, zero NAT). Item 2+
// swaps the transport for a Hyperswarm/Protomux channel; this module is
// transport-agnostic so it keeps working either way.

const HEADER_SIZE = 4

function encodeFrame (payload) {
  const header = Buffer.alloc(HEADER_SIZE)
  header.writeUInt32BE(payload.length, 0)
  return Buffer.concat([header, payload])
}

class FrameDecoder {
  constructor (onFrame) {
    this._onFrame = onFrame
    this._buffer = Buffer.alloc(0)
  }

  push (chunk) {
    this._buffer = this._buffer.length > 0
      ? Buffer.concat([this._buffer, chunk])
      : chunk

    while (true) {
      if (this._buffer.length < HEADER_SIZE) return

      const length = this._buffer.readUInt32BE(0)
      if (this._buffer.length < HEADER_SIZE + length) return

      const payload = this._buffer.subarray(HEADER_SIZE, HEADER_SIZE + length)
      this._buffer = this._buffer.subarray(HEADER_SIZE + length)
      this._onFrame(payload)
    }
  }
}

module.exports = { encodeFrame, FrameDecoder, HEADER_SIZE }
