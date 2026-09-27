'use strict'

const crypto = require('node:crypto')
const { TransferError } = require('./errors')
const { FrameDecoder, HEADER_SIZE, DEFAULT_MAX_FRAME_SIZE } = require('./frame')
const { decodeMessage, TAG_SIZE } = require('./message')

// The v2 AEAD channel (PROTOCOL.md sections 3.4 and 5). Every frame after
// the handshake is sealed:
//
//   frame  = [4-byte BE length][sealed]
//   sealed = AEAD(k_dir, nonce, [1-byte type][body], aad = [4-byte BE length])
//
// WHY THIS EXISTS AT ALL, given that Noise is already underneath. Not for
// secrecy -- Hyperswarm's NoiseSecretStream already provides that. It is so
// that authentication stops depending on which transport carried the bytes
// (section 3.3). v1 bound its code proof to the Noise session's public
// keys, which is correct for v1 and wrong for v2: a relayed connection, or
// a browser one, has different or absent Noise keys, and the binding would
// have to be reinvented per transport. Keying the channel from the PAKE
// transcript instead means the relay is a pipe and cannot be a party, and
// there is one property to reason about rather than one per transport.
//
// WIRED INTO ./transfer.js, which builds one per transfer and has no
// unsealed mode: sendFile and receiveFile both refuse to start without the
// keys. It shipped a commit earlier tested and unused, following
// ./cpace.js's precedent, and that gap is now closed.

// The length prefix is OUTSIDE the ciphertext, deliberately, and section 5
// is explicit about why: the decoder has to be able to reject an absurd
// declared length before buffering toward it. A declared length is four
// untrusted bytes, and a peer announcing 0xFFFFFFFF would otherwise make
// the decoder accumulate toward 4 GB.
//
// BUT IT IS INSIDE THE TAG, as associated data. Outside the ciphertext so
// it can be read first; bound by the authenticator so that no byte on the
// wire after the handshake is unauthenticated. Before W15a it was neither
// encrypted nor authenticated, and the argument for that was that a
// rewritten length re-delimits the stream so the frame it points at cannot
// open anyway. True, but it made the channel's integrity a property of the
// framing rather than of the AEAD, and "every byte is authenticated" is a
// claim a reviewer can check in one line where the other took a paragraph.
//
// The receiver never trusts a length it has not already used: FrameDecoder
// consumed exactly `sealed.length` bytes after the header, so the header
// it read is rebuilt from that length in _open rather than threaded
// through. The two are the same four bytes by construction.

// ChaCha20-Poly1305's Poly1305 authenticator. Node ships the cipher with a
// 16-byte tag (verified in getCiphers/authTagLength on the Node 24 this was
// written against), so v2's AEAD needs no new dependency.
const AEAD_TAG_SIZE = 16

// The AEAD's key size, and its nonce's. 12 bytes is ChaCha20-Poly1305's
// only nonce length in Node's implementation.
const KEY_SIZE = 32
const NONCE_SIZE = 12

// The nonce is 4 zero bytes followed by an 8-byte big-endian counter, so
// the counter occupies the low half and the leading bytes are reserved.
// Counting from zero in a fixed-width field is what makes "never reused
// within a drop" checkable by inspection rather than by argument.
const NONCE_COUNTER_OFFSET = 4

// The largest body a CHUNK may carry, as an EQUATION and never a second
// literal. This is v1's off-by-one, and section 5 records it because it
// cost a real debugging session: MAX_CHUNK_SIZE and the frame cap were both
// written as 1024 * 1024, but encodeMessage prefixes a one-byte type tag,
// so a chunk of exactly the maximum permitted size produced a
// 1048577-byte frame that the peer refused with ERR_PROTOCOL. The manifest
// validated and the first chunk died. It stayed latent only because both
// CLIs use the 64 KB default.
//
// v2 has one more term than v1 did -- the Poly1305 authenticator -- so
// there are now two different things called "tag" in the budget, and they
// are named apart on purpose:
//
//   TAG_SIZE      = 1    the message type byte, INSIDE the seal
//   AEAD_TAG_SIZE = 16   the authenticator, added BY the seal
//   nonce                implicit, a per-direction counter; not on the wire
//
// ChaCha20-Poly1305 is a stream cipher, so the ciphertext is exactly as
// long as the plaintext and the 16 bytes are the authenticator alone --
// there is no block-padding term to forget.
/**
 * @param {number} [maxFrameSize]
 * @returns {number} 1048559 at the 1 MiB default
 */
function maxChunkSize (maxFrameSize = DEFAULT_MAX_FRAME_SIZE) {
  return maxFrameSize - TAG_SIZE - AEAD_TAG_SIZE
}

// The smallest byte count that could possibly be a sealed frame: an empty
// body with its type tag, plus the authenticator. Anything shorter cannot
// open, and rejecting it here keeps a malformed length from reaching the
// cipher at all.
const MIN_SEALED_SIZE = TAG_SIZE + AEAD_TAG_SIZE

/**
 * @param {string} message
 * @param {Record<string, any>} [extra]
 * @returns {InstanceType<typeof TransferError>}
 */
function protocolError (message, extra) {
  return new TransferError('ERR_PROTOCOL', message, extra)
}

// One direction of the channel, and the ONLY thing that may hold a counter.
//
// NONCE REUSE IS THE CATASTROPHIC FAILURE MODE FOR THIS CONSTRUCTION --
// under ChaCha20-Poly1305 two frames sealed under one (key, nonce) pair
// leak the XOR of their plaintexts and, worse, give up the Poly1305 key,
// after which a peer's frames can be forged at will. So the counter is not
// a parameter: there is no way for a caller to supply, reset, or share one.
// Each Nonces instance owns exactly one, starts it at zero, and only ever
// moves it forward.
//
// Note what that rules out by construction. A caller cannot re-key a
// direction without building a new instance, so "reconnect and carry on
// from the old counter" -- the shape resume would reach for -- is not
// expressible here. Under v2 a resumed transfer re-runs the PAKE and gets
// fresh keys, so there is nothing to carry.
class Nonces {
  constructor () {
    this._counter = 0n
    this._nonce = Buffer.alloc(NONCE_SIZE)
  }

  /**
   * The next nonce, consumed. The returned buffer is reused between calls,
   * so a caller must not retain it past the seal or open it is used for --
   * which is why this is private to the module.
   * @returns {Buffer}
   */
  next () {
    // Unreachable in practice: at the 1 MiB frame cap, 2^64 frames is more
    // data than any drop will ever carry. Asserted anyway rather than left
    // to wrap, because a silently wrapped counter is exactly the reuse the
    // rest of this class is built to make impossible.
    if (this._counter > 0xffffffffffffffffn) {
      throw protocolError('the frame counter for this direction is exhausted')
    }
    this._nonce.writeBigUInt64BE(this._counter, NONCE_COUNTER_OFFSET)
    this._counter++
    return this._nonce
  }

  /** @returns {bigint} how many frames this direction has produced */
  get count () {
    return this._counter
  }
}

// The frame header, which is also the associated data: the sealed length,
// 4 bytes big-endian, exactly as ./frame.js writes and reads it.
/**
 * @param {number} sealedLength
 * @returns {Buffer}
 */
function lengthHeader (sealedLength) {
  const header = Buffer.allocUnsafe(HEADER_SIZE)
  header.writeUInt32BE(sealedLength, 0)
  return header
}

/**
 * @param {Buffer} key
 * @param {string} what
 */
function checkKey (key, what) {
  if (!Buffer.isBuffer(key) || key.length !== KEY_SIZE) {
    throw new TypeError(`${what} must be a ${KEY_SIZE}-byte Buffer`)
  }
}

// Both directions of one connection's channel.
//
// Two keys, never one. k_r2s and k_s2r are derived separately from the ISK
// (section 3.2), so the two directions cannot be confused for each other:
// a frame sealed by the receiver cannot be replayed back at it, because the
// receiver only ever opens under the other key. That is the same defence
// v1's "s"/"r" role tags provided for its proof, moved to where the traffic
// is. With a single shared key, direction-independent counters would
// collide on frame 0 and reuse a nonce immediately.
class Channel {
  /**
   * @param {{
   *   sendKey: Buffer,
   *   receiveKey: Buffer,
   *   onMessage: (type: number, body: Buffer) => void,
   *   maxFrameSize?: number
   * }} options
   *   `sendKey`/`receiveKey` are this side's own view: a receiver sends
   *   under k_r2s and receives under k_s2r, and a sender does the reverse.
   *   Passing the same buffer for both is refused -- see below.
   */
  constructor ({ sendKey, receiveKey, onMessage, maxFrameSize = DEFAULT_MAX_FRAME_SIZE }) {
    checkKey(sendKey, 'sendKey')
    checkKey(receiveKey, 'receiveKey')
    // A caller that wired one key into both directions would get two
    // counters starting at zero under one key, i.e. guaranteed nonce reuse
    // on the very first frame in each direction. It is a plausible mistake
    // -- both keys come out of one HKDF call site -- and it is silent, so
    // it is refused here rather than trusted not to happen.
    if (sendKey.equals(receiveKey)) {
      throw new TypeError(
        'sendKey and receiveKey must differ: one key for both directions means ' +
        'the same (key, nonce) pair seals a frame in each direction, which is ' +
        'the one failure this construction cannot survive'
      )
    }
    if (typeof onMessage !== 'function') {
      throw new TypeError('onMessage must be a function')
    }

    this._sendKey = sendKey
    this._receiveKey = receiveKey
    this._maxFrameSize = maxFrameSize
    this._out = new Nonces()
    this._in = new Nonces()
    // Set by any failure to open, and never cleared. See _open: without
    // this latch "a failed open is terminal" is a claim a comment makes
    // and the code does not keep.
    this._failed = false
    this.maxChunk = maxChunkSize(maxFrameSize)

    // Reuses ./frame.js unchanged, which is the point of that module
    // having no opinion about its contents: the length bound, the
    // buffering and the "an absurd header costs one comparison" behaviour
    // are all already correct and already tested.
    this._decoder = new FrameDecoder((sealed) => {
      const { type, body } = this._open(sealed)
      onMessage(type, body)
    }, { maxFrameSize })
  }

  /**
   * Seals one message into a complete frame, ready to write.
   *
   * @param {number} type one of message.js's TYPE_* constants
   * @param {Buffer} body
   * @returns {Buffer}
   */
  seal (type, body) {
    if (!Buffer.isBuffer(body)) throw new TypeError('body must be a Buffer')
    // Checked against the same budget the peer's decoder will enforce, so
    // an oversize body fails here -- where the caller can see which of its
    // own frames was too big -- rather than as an ERR_PROTOCOL from the
    // far end after the bytes are already on the wire. This is the check
    // whose absence produced v1's validated-manifest-then-dead-chunk.
    if (body.length > this.maxChunk) {
      throw protocolError(
        `a ${body.length}-byte body exceeds the ${this.maxChunk}-byte maximum ` +
        `(frame cap ${this._maxFrameSize} less a ${TAG_SIZE}-byte type tag and a ` +
        `${AEAD_TAG_SIZE}-byte authenticator)`,
        { bytes: body.length, max: this.maxChunk }
      )
    }

    // message.js's encodeMessage prepends the type tag AND the frame
    // length in one allocation, which is right for v1's cleartext frames
    // and wrong here: only the bytes between them get sealed, and the
    // length has to be written after the seal because the authenticator
    // changes the size. So the tagged plaintext is built here and the
    // length prefix comes from encodeFrame at the end.
    const plaintext = Buffer.allocUnsafe(TAG_SIZE + body.length)
    plaintext[0] = type
    body.copy(plaintext, TAG_SIZE)

    // The length is known before sealing -- ChaCha20 adds no padding, only
    // the authenticator -- so the header can be bound into the tag it
    // precedes.
    const header = lengthHeader(plaintext.length + AEAD_TAG_SIZE)
    const cipher = crypto.createCipheriv('chacha20-poly1305', this._sendKey, this._out.next(), {
      authTagLength: AEAD_TAG_SIZE
    })
    cipher.setAAD(header)
    return Buffer.concat([header, cipher.update(plaintext), cipher.final(), cipher.getAuthTag()])
  }

  /**
   * Feeds received bytes in. Calls `onMessage` once per complete frame, in
   * order, possibly several times for one chunk and possibly not at all.
   *
   * Throws rather than reporting: a frame that will not open is not a
   * recoverable condition, and once one has failed this channel refuses
   * everything after it. See _open.
   *
   * @param {Buffer} chunk
   */
  push (chunk) {
    if (this._failed) throw this._deadError()
    this._decoder.push(chunk)
  }

  /** @returns {{ sent: bigint, received: bigint }} frame counts per direction */
  get frames () {
    return { sent: this._out.count, received: this._in.count }
  }

  /**
   * @returns {InstanceType<typeof TransferError>}
   */
  _deadError () {
    return protocolError(
      'this channel already failed to open a frame and refuses to carry on: ' +
      'continuing past an authentication failure would silently skip the frame ' +
      'that failed',
      { framesReceived: this._in.count }
    )
  }

  /**
   * @param {Buffer} sealed
   * @returns {{ type: number, body: Buffer }}
   */
  _open (sealed) {
    if (sealed.length < MIN_SEALED_SIZE) {
      this._failed = true
      throw protocolError(
        `a ${sealed.length}-byte frame is too short to be sealed ` +
        `(at least ${MIN_SEALED_SIZE}: a type tag and a ${AEAD_TAG_SIZE}-byte authenticator)`
      )
    }

    const tagAt = sealed.length - AEAD_TAG_SIZE
    const decipher = crypto.createDecipheriv('chacha20-poly1305', this._receiveKey, this._in.next(), {
      authTagLength: AEAD_TAG_SIZE
    })
    decipher.setAAD(lengthHeader(sealed.length))
    decipher.setAuthTag(sealed.subarray(tagAt))

    let plaintext
    try {
      plaintext = Buffer.concat([
        decipher.update(sealed.subarray(0, tagAt)),
        decipher.final()
      ])
    } catch (err) {
      this._failed = true
      // EVERY WAY THIS FAILS LOOKS THE SAME FROM HERE, AND THAT IS
      // CORRECT. A flipped bit, a truncated frame, a rewritten length, a
      // frame replayed or reordered (the counter no longer matches), a
      // frame sealed in the other direction, and a deliberate forgery are
      // one event: the authenticator did not verify. The message says so without
      // guessing which, because guessing wrong is worse than not saying --
      // and because a peer that can choose between those outcomes must not
      // learn which one it achieved.
      //
      // Note this is also where a desynchronised stream now surfaces. v1
      // reserved type 0x00 as its desync sentinel and could catch a
      // mis-framed payload by its tag; under v2 the tag is inside the seal,
      // so desync presents here first -- earlier and less ambiguously than
      // 0x00 ever did. 0x00 stays reserved for the case where a frame does
      // open and still carries it.
      //
      // AND IT IS TERMINAL, which is what `_failed` above enforces. The
      // counter advancing does NOT make it terminal -- that was the
      // mistake this latch fixes. It makes it *recoverable*: the counter
      // and the decoder's buffer are both left correctly positioned for
      // the peer's next frame, so a caller that caught this error and
      // carried on would silently SKIP the frame that failed and keep
      // going. Against a forged or corrupted CHUNK that is a hole in the
      // output file, caught later by the SHA-256 -- integrity by
      // accident, reported as a hash mismatch rather than as tampering.
      // Against a forged CANCEL or CHECKPOINT it is a no-op.
      //
      // Both callers -- sendFile's and receiveFile's onData in
      // ./transfer.js -- do treat a throw as fatal, so the latch changes
      // nothing today. It exists because that is a
      // caller convention and this is a security boundary: the natural
      // next edit -- a per-frame try/catch added to tolerate an
      // unexpected-but-benign message type, of which v2 has just added
      // five -- would turn the convention into a silent truncation. The
      // rest of this module holds itself to making the dangerous thing
      // inexpressible rather than merely discouraged (see Nonces), and
      // this is the same standard applied to the same class of mistake.
      //
      // Offering a resynchronisation window would be the other way to go
      // and is worse: it means holding state an attacker can aim at, and
      // under UDX/Noise (reliable and ordered) there is no benign reason
      // to need one.
      throw protocolError(
        'a frame failed to authenticate: it or its length was altered, or it was truncated, replayed, ' +
        'reordered, or sealed for the other direction. The channel is keyed by ' +
        'the PAKE transcript, so this cannot be a wrong-code failure -- the ' +
        'handshake would not have completed',
        { cause: err, framesReceived: this._in.count }
      )
    }

    // The type tag is validated by message.js, so the vocabulary lives in
    // one place: 0x00 stays reserved and always invalid, and an unknown tag
    // is named rather than guessed at.
    return decodeMessage(plaintext)
  }
}

module.exports = {
  Channel,
  maxChunkSize,
  AEAD_TAG_SIZE,
  KEY_SIZE,
  NONCE_SIZE,
  MIN_SEALED_SIZE
}
