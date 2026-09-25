'use strict'

const { TransferError } = require('./errors')

// A one-byte type tag on the front of every frame payload, so that the
// stream carries messages rather than just bytes:
//
//   frame   = [4-byte BE length][payload]     <- ./frame.js, unchanged
//   payload = [1-byte type][body]             <- here
//
// WHY NOW, AND WHY NOT IN frame.js. Before this, a frame was "the manifest
// if it is the first one, file bytes otherwise". That is enough to move a
// file and nothing else: there is no way to say CANCEL, because any frame
// that is not the manifest is already defined to be file content. The failure-reporting work
// needs exactly that, and v2 needs more messages still, so a type space
// that does not exist by then costs two wire breaks instead of one. This
// was the second break after the code proof's handshake and the last cheap
// moment to take it.
//
// (This comment used to name those further messages as "ack-by-index,
// resume-from". PROTOCOL.md section 4.1 refuted the first half: UDX under
// Noise is already reliable and ordered, so a per-chunk acknowledgement
// re-implements a guarantee the transport gives for free and costs a round
// trip per chunk to do it. What resume needs is a durable offset, which is
// CHECKPOINT{offset} below, sent periodically after an fsync rather than
// per chunk.)
//
// It lives here rather than in ./frame.js on purpose. The framer stays a
// pure length-prefixer that knows nothing about what it carries -- it is
// reused unchanged by anything that needs delimiting, and it stayed
// correct through items 1-4 precisely because it has no protocol opinions.
// ./transfer.js never calls encodeFrame directly, which is what makes
// "every frame is typed" true without the framer having to enforce it.
//
// Cost: one byte per 64 KB chunk, and encodeMessage does the length
// prefix, the tag and the copy in a single allocation, so a chunk still
// costs exactly one copy -- the same as before the tag existed.

// The tag's own width, exported because it is the term that was missing
// from the frame-size budget. `encodeMessage` declares a frame length of
// `TAG_SIZE + body.length`, so a chunk of exactly the frame cap produces a
// frame one byte over it. See MAX_CHUNK_SIZE in ./transfer.js, which is
// now derived from this rather than stated independently.
const TAG_SIZE = 1

// 0x00 is reserved and always invalid. That is the point of it: a stream
// that has desynchronised, or been truncated mid-frame, most often
// presents as a length header read out of the middle of a payload, and
// zero bytes are what padding and lengths are full of. Reserving it makes
// that fail loudly on the first frame rather than parse as garbage and
// only surface later as a hash mismatch.
const TYPE_RESERVED = 0x00
const TYPE_MANIFEST = 0x01
const TYPE_CHUNK = 0x02
const TYPE_CANCEL = 0x03

// v2's additions (PROTOCOL.md section 4). Named here as soon as the number
// space is settled, ahead of anything sending them, for one reason: a type
// that is not in TYPE_NAMES is reported as "unknown message type 0x04",
// which reads like a corrupt stream. Named, the same frame is refused as
// "receiver sent ACCEPT during a transfer" -- see ./transfer.js, whose
// dispatch is exhaustive by exclusion and therefore already declines
// everything it does not handle.
//
// So this commit makes the v1 transfer path refuse them ACCURATELY rather
// than making it handle them. The handling lands with the accept gate,
// streaming and resume in W11's second pass.
const TYPE_ACCEPT = 0x04 // {resumeFrom} -- the accept step and resume, one message
const TYPE_DECLINE = 0x05 // {reason}
const TYPE_CHECKPOINT = 0x06 // {offset} -- R->S, periodic, post-fsync
const TYPE_RESULT = 0x07 // {ok, sha256} | {error}
const TYPE_END = 0x08 // {sha256} -- streaming trailer, when size was null

const TYPE_NAMES = new Map([
  [TYPE_MANIFEST, 'MANIFEST'],
  [TYPE_CHUNK, 'CHUNK'],
  [TYPE_CANCEL, 'CANCEL'],
  [TYPE_ACCEPT, 'ACCEPT'],
  [TYPE_DECLINE, 'DECLINE'],
  [TYPE_CHECKPOINT, 'CHECKPOINT'],
  [TYPE_RESULT, 'RESULT'],
  [TYPE_END, 'END']
])

// An untagged manifest from a pre-item-5 build starts with '{' (0x7b),
// because that build wrote bare JSON as the whole payload. That is a
// version skew, not a corrupt stream, and the two have completely
// different fixes -- so it is named rather than left to be inferred from a
// confusing "unknown tag" message. Same reasoning as PROOF_FAILED in
// ./proof.js: the one failure whose cause is knowable should say so.
const LEGACY_MANIFEST_FIRST_BYTE = 0x7b

/**
 * @param {number} type one of the TYPE_* constants
 * @param {Buffer} body
 * @returns {Buffer} a complete frame, ready to write
 */
function encodeMessage (type, body) {
  const out = Buffer.allocUnsafe(4 + 1 + body.length)
  out.writeUInt32BE(1 + body.length, 0)
  out[4] = type
  body.copy(out, 5)
  return out
}

/**
 * Splits a frame payload into its tag and body.
 * @param {Buffer} payload
 * @returns {{ type: number, body: Buffer }}
 */
function decodeMessage (payload) {
  if (payload.length < 1) {
    throw new TransferError('ERR_PROTOCOL', 'received an empty frame (no type tag)')
  }

  const type = payload[0]
  if (TYPE_NAMES.has(type)) return { type, body: payload.subarray(1) }

  if (type === LEGACY_MANIFEST_FIRST_BYTE) {
    throw new TransferError(
      'ERR_PROTOCOL',
      'the peer is running a pre-item-5 build: it sent an untagged manifest. ' +
      'Redeploy both sides to the same version -- this is a version skew, not ' +
      'a corrupt transfer'
    )
  }
  if (type === TYPE_RESERVED) {
    throw new TransferError(
      'ERR_PROTOCOL',
      'received a frame with the reserved type 0x00, which means the stream ' +
      'is out of sync (a truncated or mis-framed message), not that the peer ' +
      'sent something unsupported'
    )
  }
  throw new TransferError('ERR_PROTOCOL', `unknown message type 0x${type.toString(16).padStart(2, '0')}`)
}

// A cancelling peer's reason is printed straight into a terminal, so it is
// untrusted input in the one place that is easy to forget: cap it, and
// strip anything that could move the cursor, clear the screen, or forge a
// second log line.
const MAX_REASON_BYTES = 256

/**
 * @param {unknown} reason
 * @returns {string}
 */
function sanitizeReason (reason) {
  if (typeof reason !== 'string') return ''
  // eslint-disable-next-line no-control-regex
  const stripped = reason.replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ')
  const capped = Buffer.from(stripped, 'utf8').subarray(0, MAX_REASON_BYTES).toString('utf8')
  // A multi-byte character can be cut in half by the byte cap above;
  // toString leaves U+FFFD behind for the fragment, which is fine to show
  // but not worth trailing whitespace around.
  return capped.trim()
}

/**
 * @param {string} [reason]
 * @returns {Buffer} a complete CANCEL frame
 */
function encodeCancel (reason = '') {
  return encodeMessage(TYPE_CANCEL, Buffer.from(JSON.stringify({ reason: sanitizeReason(reason) }), 'utf8'))
}

/**
 * Never throws: a peer that is cancelling has already told us what we
 * needed to know, and refusing to act on a malformed reason string would
 * turn a clean cancel back into the mystery disconnect this item exists to
 * eliminate.
 * @param {Buffer} body
 * @returns {string}
 */
function decodeCancelReason (body) {
  try {
    const parsed = JSON.parse(body.toString('utf8'))
    return sanitizeReason(parsed && parsed.reason)
  } catch {
    return ''
  }
}

// RESULT is the receiver's verdict on the whole file, sent after it has
// verified the digest and published under the real name (PROTOCOL.md
// section 4.2). Two shapes, and nothing else:
//
//   {ok: true, sha256}   the digest the receiver computed
//   {error}              why it could not keep the file
const SHA256_HEX = /^[0-9a-f]{64}$/

/**
 * @param {{ ok: true, sha256: string } | { error: string }} result
 * @returns {Buffer} a complete RESULT frame
 */
function encodeResult (result) {
  const body = 'error' in result
    ? { error: sanitizeReason(result.error) }
    : { ok: true, sha256: result.sha256 }
  return encodeMessage(TYPE_RESULT, Buffer.from(JSON.stringify(body), 'utf8'))
}

/**
 * THROWS, unlike decodeCancelReason, and the asymmetry is deliberate. A
 * cancel that cannot be parsed has still said "stop". A RESULT that cannot
 * be parsed has said nothing, and the one thing the sender must never do
 * is count a verdict it could not read as a success.
 * @param {Buffer} body
 * @returns {{ ok: true, sha256: string } | { ok: false, error: string }}
 */
function decodeResult (body) {
  let parsed
  try {
    parsed = JSON.parse(body.toString('utf8'))
  } catch (err) {
    throw new TransferError('ERR_PROTOCOL', `the receiver's RESULT is not valid JSON: ${err.message}`)
  }
  if (parsed && parsed.ok === true && typeof parsed.sha256 === 'string' && SHA256_HEX.test(parsed.sha256)) {
    return { ok: true, sha256: parsed.sha256 }
  }
  if (parsed && typeof parsed.error === 'string' && parsed.ok !== true) {
    return { ok: false, error: sanitizeReason(parsed.error) }
  }
  throw new TransferError('ERR_PROTOCOL', 'the receiver\'s RESULT is neither {ok, sha256} nor {error}')
}

module.exports = {
  encodeMessage,
  decodeMessage,
  encodeCancel,
  decodeCancelReason,
  encodeResult,
  decodeResult,
  sanitizeReason,
  TAG_SIZE,
  TYPE_RESERVED,
  TYPE_MANIFEST,
  TYPE_CHUNK,
  TYPE_CANCEL,
  TYPE_ACCEPT,
  TYPE_DECLINE,
  TYPE_CHECKPOINT,
  TYPE_RESULT,
  TYPE_END,
  TYPE_NAMES
}
