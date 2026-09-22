'use strict'

// Reassembles handshake messages from however many chunks the transport
// chooses to deliver them in.
//
// The constant-byte handshake this descends from could read its whole
// message out of `socket.once('data')`, because one byte cannot arrive
// split. Nothing in v2's handshake is one byte: HELLO is 51 to 179 bytes,
// REPLY 66 to 194, CONFIRM 32. Each can arrive split across chunks, and
// can equally arrive coalesced with whatever follows it, so "the first
// chunk is the message" is not true in either direction. Taking bytes by
// count rather than by chunk is the same discipline ./frame.js applies to
// the transfer itself.
//
// WHY THIS IS ITS OWN MODULE. It used to live in ./proof.js, which v2
// deletes: the HMAC code proof bound to the Noise session was correct for
// v1 and is wrong for v2 (PROTOCOL.md section 3.3). This class was the one
// part of that file with nothing to do with the proof, and it has two
// callers that do not otherwise share anything -- ./swarm.js and
// ../scratch-serve.js. It has no protocol opinions at all, which is why it
// survived the wire break unchanged.

class MessageReader {
  constructor () {
    /** @type {Buffer} */
    this._buffer = Buffer.alloc(0)
  }

  /** @param {Buffer} chunk */
  push (chunk) {
    this._buffer = this._buffer.length > 0
      ? Buffer.concat([this._buffer, chunk])
      : chunk
  }

  // Returns exactly `size` bytes and consumes them, or null if that many
  // have not arrived yet -- in which case nothing is consumed and the
  // caller should wait for more data.
  /**
   * @param {number} size
   * @returns {Buffer | null}
   */
  take (size) {
    if (this._buffer.length < size) return null
    const taken = this._buffer.subarray(0, size)
    this._buffer = this._buffer.subarray(size)
    return taken
  }

  // How many bytes are waiting. Callers that read a length-prefixed message
  // need this to decide whether the body has arrived without consuming the
  // prefix first -- v2's HELLO and REPLY are both length-prefixed, and
  // taking the prefix before the body is complete would lose it.
  /** @returns {number} */
  get buffered () {
    return this._buffer.length
  }

  // Peeks at `size` bytes without consuming them. The length prefix of a
  // variable-length message has to be read to know how much more to wait
  // for, and re-reading it on the next chunk is cheaper than holding
  // half-parsed state across calls.
  /**
   * @param {number} size
   * @returns {Buffer | null}
   */
  peek (size) {
    if (this._buffer.length < size) return null
    return this._buffer.subarray(0, size)
  }

  // Bytes that arrived after the last complete message, or null. These
  // belong to whatever comes next on the stream and must be handed on
  // rather than dropped -- see `pending` in ./transfer.js.
  /**
   * @returns {Buffer | null}
   */
  rest () {
    return this._buffer.length > 0 ? this._buffer : null
  }
}

module.exports = { MessageReader }
