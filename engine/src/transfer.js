'use strict'

const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const { DEFAULT_MAX_FRAME_SIZE } = require('./frame')
const { Channel, maxChunkSize } = require('./channel')
const { TransferError, abortError } = require('./errors')
const { displayName, safeWriteName } = require('./names')
const {
  cancelBody,
  decodeCancelReason,
  resultBody,
  decodeResult,
  acceptBody,
  decodeAccept,
  declineBody,
  decodeDecline,
  DECLINE_CODES,
  checkpointBody,
  decodeCheckpoint,
  endBody,
  decodeEnd,
  prefixBody,
  decodePrefix,
  PREFIX_BOUNDARY,
  sanitizeReason,
  TYPE_MANIFEST,
  TYPE_CHUNK,
  TYPE_CANCEL,
  TYPE_ACCEPT,
  TYPE_DECLINE,
  TYPE_CHECKPOINT,
  TYPE_RESULT,
  TYPE_END,
  TYPE_PREFIX,
  TYPE_NAMES
} = require('./message')

// Manifest v2 (PROTOCOL.md section 4), and exactly these fields. A field
// outside this list is refused rather than ignored: a manifest field is
// forever, so the set is closed and a new one is a new `v`. That is also
// how `mode` and `caps` left the draft -- neither had a definition, and a
// field nobody can say the meaning of is one two implementations will
// disagree about. See section 4 for the reasoning in full.
const MANIFEST_VERSION = 2
const MANIFEST_FIELDS = ['v', 'name', 'size', 'sha256', 'blockSize']

// 64 KB balances syscall/frame overhead against memory use; revisit once
// large-file testing lands.
const DEFAULT_CHUNK_SIZE = 64 * 1024

// Upper bound on a manifest's declared chunkSize. Not a tuning knob: it
// exists so a peer cannot declare something absurd and have us believe it.
//
// DERIVED, NOT STATED, and that is the fix for a real off-by-one. This
// used to read `1024 * 1024`, exactly equal to frame.js's cap on a frame's
// declared payload length -- but `encodeMessage` prefixes a one-byte type
// tag, so the payload carrying a maximum-size chunk is 1048577 bytes and
// the peer refuses it with ERR_PROTOCOL. A sender using the largest chunk
// size this very function *permits* therefore had its manifest validated
// and then died on its first chunk. Latent only because both CLIs use the
// 64 KB default and nothing ever set it near the cap.
//
// Writing it as a subtraction means the two constants cannot drift apart
// again: raise the frame cap and this follows.
//
// v2 added a term: every frame is now sealed, and the Poly1305
// authenticator costs 16 bytes of the same budget. So this is no longer
// `DEFAULT_MAX_FRAME_SIZE - TAG_SIZE` (1048575) but ./channel.js's
// equation, 1048559 at the 1 MiB default -- taken from there rather than
// restated here, which is the same lesson applied to the new term.
const MAX_CHUNK_SIZE = maxChunkSize(DEFAULT_MAX_FRAME_SIZE)

// An absurdity ceiling on a declared size, applied when the caller names
// no policy of its own. It is NOT the product's size limit -- that is an
// accept-screen decision a human should see -- and it is deliberately far
// above any drop this tool is used for today: at the ~1 MB/s measured on
// a real cross-ISP path, 8 GiB is about two hours of transfer.
//
// What it stops is the case the review found and a probe confirmed: with
// no cap passed, `validateManifest` accepted a manifest declaring
// 9007199254740991 bytes (9 PB) and the receiver went on to open a file
// and start a free-space check against a number no disk can satisfy.
// Pass `maxSize: null` to opt out explicitly; omitting it gets this.
const DEFAULT_MAX_SIZE = 8 * 1024 * 1024 * 1024

// How long the receiver will wait for a manifest that never comes, and
// then for any progress at all once the transfer is running.
//
// The hole these close: the code proof (proof.js) tells us the peer knows
// the drop code, and nothing more. A peer can prove, then send nothing,
// forever -- the receiver has no timer of its own once acceptOnce has
// handed the socket over, so it simply sits there with the file open. A
// slow loris costs the attacker one proven connection and costs us the
// drop. Both surface as ERR_STALLED so the log distinguishes "they went
// quiet" from "the socket died" (ERR_CONNECTION).
const MANIFEST_TIMEOUT_MS = 30000
const PROGRESS_TIMEOUT_MS = 60000

// How long a cancelling side waits for its CANCEL to reach the wire before
// it gives up and rejects locally.
//
// It is a window rather than a fixed sleep: `write`'s callback fires when
// the bytes have actually flushed, and this is only the backstop for a
// socket that is wedged. Without any window at all the message is simply
// lost -- the caller tears the socket down the moment we reject, and the
// peer sees a reset. That is the same lesson swarm-send.js already records
// about end() versus waiting for 'close', arrived at from the other side.
const CANCEL_FLUSH_MS = 250

// How long the sender waits, after its last byte, for the receiver's
// RESULT.
//
// This replaced a fixed 5s close wait in both callers, and the
// measurement that retired it is worth keeping: 100 trials across a
// Starlink receiver and a firewalled Comcast sender, where the sender
// scored 100/100 and the receiver 94. All six failures were trials whose
// 5s wait ran out -- the sender destroyed the swarm with 0.3 to 4.2 MB of
// "sent" data still undelivered, and the receiver saw "connection reset by
// peer". Of the 91 trials whose wait ended in a close, none failed.
//
// So this is NOT the drain budget. The sender cannot see delivery, only
// hand-off, and whatever the transport has buffered drains at the path's
// rate. The receiver is the side that can see progress, and it already
// fails ERR_STALLED after PROGRESS_TIMEOUT_MS without any -- then closes,
// which the sender sees. This timer is only for a receiver that vanished
// without the transport noticing, so it sits well above that: a transfer
// still draining legitimately after two minutes would need a backlog of
// several MB on a path under ~35 KB/s.
const RESULT_TIMEOUT_MS = 2 * PROGRESS_TIMEOUT_MS

// How long the sender waits, after its MANIFEST, for ACCEPT or DECLINE.
//
// The receiver answers as soon as it has checked the name, the size and
// the free space and opened the partial, which is milliseconds -- unless a
// caller's onOffer hook is asking a person, and that is the case this
// budget is sized for. The receiver does not time itself out while its own
// hook is deciding (that is not the peer stalling), so this is the only
// bound on an offer nobody answers. 0 waits indefinitely, for a caller
// whose accept screen should wait as long as the person does.
const ACCEPT_TIMEOUT_MS = 5 * 60 * 1000

// How often a resumable receive fsyncs and reports CHECKPOINT. Seconds, not
// bytes, and five of them: PROTOCOL.md section 8.3 measured fsync as a
// near-fixed device round trip (~7-19 ms at p50 whatever was written), so
// a byte interval costs 1% on one link and 90% on another, while a time
// interval costs ~0.25% on every link and loses at most five seconds of
// work to a crash. A receiver-local choice, not a wire one.
const CHECKPOINT_INTERVAL_MS = 5000

// What the peer is told when this side refuses an offer or a file, in
// DECLINE{reason} or RESULT{error}.
//
// A TransferError's message is written for either side to read. Anything
// else is a local fault, and its message names local paths --
// "EACCES: permission denied, open '/Users/<name>/Downloads/x.part'" --
// which is the receiver's username and directory layout, handed to a
// peer whose only credential is knowing the code. That peer gets the
// error's code and nothing else. The free-space figure is withheld for the
// same reason: the sender needs to know it did not fit, not how full the
// receiver's disk is.
/** @param {any} err */
function reasonForPeer (err) {
  if (err instanceof TransferError) {
    if (err.code === 'ERR_NO_SPACE') return `the receiver does not have ${/** @type {any} */ (err).size} bytes free`
    return err.message
  }
  return `the receiver could not take the file (${err && typeof err.code === 'string' ? err.code : 'internal error'})`
}

// The DECLINE code for the same error: its own code when it is one the
// receiver declines with, and ERR_RECEIVER_FAILED for everything else. A
// local fault's errno stays in the prose only (reasonForPeer), because
// "EACCES" is an operating system's vocabulary, not this protocol's.
/** @param {any} err */
function declineCodeFor (err) {
  return err instanceof TransferError && DECLINE_CODES.includes(err.code) ? err.code : 'ERR_RECEIVER_FAILED'
}

function hashFile (filePath) {
  return hashFileWithPrefixes(filePath).then(({ sha256 }) => sha256)
}

// The whole-file digest the manifest carries, and on the same single read
// the digest of every PREFIX_BOUNDARY-aligned prefix: `prefixes[k - 1]` is
// the SHA-256 of the first k * PREFIX_BOUNDARY bytes. These are what the
// sender answers a resume's PREFIX from (PROTOCOL.md section 7.5), so a
// resumed transfer never re-reads the part of the file it skips. 32 bytes
// per MiB: 256 KB at the 8 GiB default cap.
//
// A read chunk does not respect the boundaries, so it is split at them;
// `hash.copy()` finalises a snapshot without disturbing the running state.
/**
 * @param {string} filePath
 * @returns {Promise<{ sha256: string, prefixes: Buffer[] }>}
 */
function hashFileWithPrefixes (filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256')
    /** @type {Buffer[]} */
    const prefixes = []
    let position = 0
    const stream = fs.createReadStream(filePath)
    stream.on('data', (/** @type {Buffer} */ chunk) => {
      let offset = 0
      while (offset < chunk.length) {
        const take = Math.min(chunk.length - offset, PREFIX_BOUNDARY - (position % PREFIX_BOUNDARY))
        hash.update(chunk.subarray(offset, offset + take))
        offset += take
        position += take
        if (position % PREFIX_BOUNDARY === 0) prefixes.push(hash.copy().digest())
      }
    })
    stream.on('end', () => resolve({ sha256: hash.digest('hex'), prefixes }))
    stream.on('error', reject)
  })
}

// Writes one frame and waits for it to flush, capped. Never rejects: a
// CANCEL that could not be delivered still has to cancel locally, and a
// RESULT that could not be delivered does not change what happened to the
// file. The sender reports the missing RESULT for itself.
//
// "Flushed" is local: handed to the transport, not received. That is
// enough here only because neither caller destroys the socket right after
// -- see the close waits in cli/src/swarm-receive.js and swarm-send.js.
/**
 * @param {any} socket
 * @param {Buffer} frame
 * @returns {Promise<void>}
 */
function writeFlushed (socket, frame) {
  return new Promise((resolve) => {
    let done = false
    const finish = () => {
      if (done) return
      done = true
      clearTimeout(timer)
      socket.removeListener('error', finish)
      resolve()
    }
    const timer = setTimeout(finish, CANCEL_FLUSH_MS)
    // Unref so a write on an already-dead socket cannot hold the process
    // open for the length of the window.
    if (typeof timer.unref === 'function') timer.unref()
    // The receiver writes RESULT after it has detached its own 'error'
    // listener, so a socket that dies under this write must not surface
    // as an uncaught exception.
    socket.once('error', finish)
    try {
      socket.write(frame, finish)
    } catch {
      finish()
    }
  })
}

/**
 * @param {any} socket
 * @param {InstanceType<typeof Channel>} channel
 * @param {string} reason
 */
function writeCancel (socket, channel, reason) {
  return writeFlushed(socket, channel.seal(TYPE_CANCEL, cancelBody(reason)))
}

// EVERY FRAME AFTER THE HANDSHAKE IS SEALED (PROTOCOL.md section 3.4), and
// both halves of the transfer build their channel here so that neither
// can be called without one.
//
// Required, not defaulted, for the same reason acceptOnce requires a
// secret: the failure mode of quietly carrying on without keys is the
// hole this exists to close. There is no cleartext mode to fall back to,
// so a caller that was not updated for v2 fails here, loudly, before it
// touches the file or the socket -- rather than writing frames its peer
// cannot open, or, worse, frames nobody had to authenticate.
//
// The keys are this side's view, as acceptOnce/connectOnce (./swarm.js)
// and acceptStream/connectStream (./stream-handshake.js) return them.
/**
 * @param {{ sendKey?: Buffer, receiveKey?: Buffer }} keys
 * @param {(type: number, body: Buffer) => void} onMessage
 * @returns {InstanceType<typeof Channel>}
 */
function openChannel ({ sendKey, receiveKey }, onMessage) {
  if (sendKey === undefined || receiveKey === undefined) {
    throw new TypeError(
      'sendKey and receiveKey are required: every v2 frame is sealed under the ' +
      'channel keys the handshake derives, and there is no unsealed mode'
    )
  }
  return new Channel({ sendKey, receiveKey, onMessage })
}

// Normalizes the engine's progress contract in one place, so both
// directions make the same promises and neither has to remember them.
//
// THE CONTRACT: one event per chunk, unthrottled, plus a guaranteed first
// call at `bytes: 0` and a guaranteed final call at `bytes === total`.
// `bytes` never decreases. Nothing is throttled here and no rate, ETA or
// percentage is computed, because the engine cannot know whether the
// consumer is a 10 Hz terminal bar, an assertion in a test, or a log line
// -- all three are real consumers today, and only the first wants
// throttling. Presentation belongs in the CLI, the same split as code.js
// owning the code value while cli/src/qr.js owns the drawing.
//
// A stream has no total until it ends, and says so with `total: null` on
// every event. `final` has no total to jump to, so for a stream it emits
// nothing new: the last per-chunk event already was the final count.
/**
 * @param {((p: { bytes: number, total: number | null }) => void) | undefined} onProgress
 * @param {number | null} total
 */
function progressReporter (onProgress, total) {
  if (!onProgress) return { emit: () => {}, final: () => {} }
  let last = -1
  const emit = (bytes) => {
    if (bytes === last) return
    last = bytes
    onProgress({ bytes, total })
  }
  emit(0)
  return { emit, final: () => emit(total === null ? last : total) }
}

// Offers the file with one MANIFEST, waits for the receiver's ACCEPT, then
// sends the file as CHUNK frames. `socket` is any writable+readable duplex
// stream (net.Socket for the loopback milestone; a Hyperswarm
// NoiseSecretStream from the Hyperswarm work onward -- not a Protomux
// channel, which W10 ruled out; see PROTOCOL.md section 8.2).
//
// NO FILE BYTE MOVES BEFORE THE RECEIVER SAYS YES. Until the accept gate
// the manifest and the chunks went out back to back, so the receiver's only
// way to refuse a file -- too big, a name it will not write, a person who
// did not want it -- was to hang up after the sender had started
// uploading, and the sender saw a dropped connection with no reason
// attached. Now a refusal is DECLINE{reason}, it arrives before the read
// stream is even opened, and the sender reports it as ERR_DECLINED.
//
// Four phases, in order, and every inbound message is judged against the
// one we are in:
//
//   offer    MANIFEST sent; only ACCEPT, DECLINE or CANCEL may arrive
//   prefix   the receiver proposed a resume and we sent PREFIX (section
//            7.5); only its final ACCEPT, DECLINE or CANCEL may arrive.
//            Skipped when the first ACCEPT says 0
//   send     accepted; only CANCEL may arrive
//   result   every byte handed off; only RESULT or CANCEL may arrive
//
// RESOLVING MEANS THE RECEIVER HAS THE FILE. After the last chunk this
// waits for the receiver's RESULT (PROTOCOL.md section 4.2), and resolves
// only on {ok} carrying the digest we sent. Before RESULT it resolved on
// hand-off, and both callers papered over the gap with a 5s close wait
// that lost 6 of 100 real transfers -- see RESULT_TIMEOUT_MS.
//
// `onProgress` is still hand-off, not delivery: the bar can read 100%
// while the receiver is at 90%. It is this promise, not the bar, that
// means delivered.
//
// Every frame in both directions goes through one Channel, sealed under
// k_s2r and opened under k_r2s. The order frames are sealed in is the
// order they are written in -- seal and write are adjacent and
// synchronous at every call site below -- which is what keeps the nonce
// counter in step with the peer's.
/**
 * @param {any} socket
 * @param {string} filePath
 * @param {{
 *   sendKey: Buffer,
 *   receiveKey: Buffer,
 *   caps?: string[],
 *   onCheckpoint?: (c: { offset: number, total: number }) => void,
 *   chunkSize?: number,
 *   signal?: AbortSignal,
 *   onProgress?: (p: { bytes: number, total: number }) => void,
 *   pending?: Buffer | null,
 *   acceptTimeout?: number,
 *   resultTimeout?: number
 * }} [options]
 *   `sendKey`/`receiveKey` are this side's channel keys, as connectOnce
 *   returns them; see openChannel.
 *   `caps` is the capability list the same handshake returned. With
 *   `resume` in it the receiver may answer ACCEPT{resumeFrom > 0}, and the
 *   file is sent from there; without it such an ACCEPT is refused.
 *   `onCheckpoint` hears each offset the receiver reports as fsynced --
 *   delivery, where onProgress is only hand-off.
 *   `chunkSize` is declared to the receiver as the manifest's `blockSize`.
 *   `pending` is any payload the readiness handshake read off the socket
 *   before handing it over -- see connectOnce in ./swarm.js.
 *   `acceptTimeout` and `resultTimeout` are in ms; 0 waits indefinitely.
 */
async function sendFile (socket, filePath, options = /** @type {any} */ ({})) {
  const { chunkSize = DEFAULT_CHUNK_SIZE } = options
  return offerAndSend(socket, options, async () => {
    const stat = await fs.promises.stat(filePath)
    const size = stat.size
    const { sha256, prefixes } = await hashFileWithPrefixes(filePath)
    return {
      name: path.basename(filePath),
      size,
      sha256,
      // What PREFIX carries for a resumeFrom the sender has already checked
      // is on a boundary or is the whole file (onAccept). The whole file's
      // prefix digest is the manifest's own.
      prefixDigest: (/** @type {number} */ n) => n === size ? Buffer.from(sha256, 'hex') : prefixes[n / PREFIX_BOUNDARY - 1],
      // stat, hashFile and createReadStream are three separate reads of a
      // file that nothing stops changing underneath us. Capping the read at
      // the size we hashed and declared means a file that GREW mid-send is
      // sent as the manifest describes rather than overrunning it; a file
      // that SHRANK is caught by the assertion after 'end'. Before this, a
      // shrunk file resolved *successfully* having sent short, and the
      // receiver was left waiting for bytes that were never coming.
      //
      // `start` is the receiver's resumeFrom: a resumed transfer reads the
      // file from there, and the bytes before it are never read again.
      open: (start) => fs.createReadStream(filePath, { highWaterMark: chunkSize, start, end: size - 1 })
    }
  })
}

// Streams `readable` to the receiver as one file of unknown length
// (PROTOCOL.md section 4.3): `tar c dir | quay send -`. The manifest says
// size: null and sha256: null, the digest is computed while reading, and
// END{sha256} carries it once `readable` ends. Everything else -- the
// offer, the accept gate, RESULT -- is sendFile's, because it is the same
// state machine with a different source.
//
// THE FIRST USE OF A NEGOTIATED CAPABILITY. `caps` is the list the
// handshake returned (acceptOnce/connectOnce, acceptStream/connectStream),
// and without `stream` in it this refuses before writing anything: the
// receiver would only decline, and section 3.2's trap #3 says what a party
// acts on must follow from the transcript, not from hope.
//
// Nothing is read from `readable` before ACCEPT, so a declined stream
// leaves its producer where it was. Not resumable, and that falls out of
// section 7.2 rather than being a separate decision: there is no declared
// digest for a prefix to be checked against.
/**
 * @param {any} socket
 * @param {import('stream').Readable} readable
 * @param {{
 *   name: string,
 *   caps: string[],
 *   sendKey: Buffer,
 *   receiveKey: Buffer,
 *   chunkSize?: number,
 *   signal?: AbortSignal,
 *   onProgress?: (p: { bytes: number, total: number | null }) => void,
 *   pending?: Buffer | null,
 *   acceptTimeout?: number,
 *   resultTimeout?: number
 * }} options
 *   `name` is what the receiver is offered; the sender has no file to take
 *   one from.
 * @returns {Promise<{ name: string, size: number, sha256: string, resumedFrom: number }>}
 *   `resumedFrom` is always 0: a stream is never resumed.
 */
async function sendStream (socket, readable, options) {
  const { name, caps } = options || /** @type {any} */ ({})
  return offerAndSend(socket, options, async () => {
    if (typeof name !== 'string') throw new TypeError('sendStream needs a name to offer the stream under')
    if (!Array.isArray(caps) || !caps.includes('stream')) {
      throw new TransferError(
        'ERR_PROTOCOL',
        'the receiver did not negotiate the "stream" capability, so a transfer of unknown length cannot be offered to it',
        { capability: 'stream' }
      )
    }
    return { name, size: null, sha256: null, open: () => readable }
  })
}

// The sender's half of every transfer: the offer, the accept gate, the
// chunks, END for a stream, and RESULT. `describe` supplies what is being
// sent, and is called only after the keys, the chunk size and the abort
// signal have been checked, so a caller that got one of those wrong is told
// so before the file is hashed or the stream is touched.
/**
 * @param {any} socket
 * @param {any} options see sendFile and sendStream
 * @param {() => Promise<{ name: string, size: number | null, sha256: string | null, prefixDigest?: (n: number) => Buffer, open: (start: number) => import('stream').Readable }>} describe
 * @returns {Promise<{ name: string, size: number, sha256: string, resumedFrom: number }>}
 */
async function offerAndSend (socket, {
  sendKey,
  receiveKey,
  caps = [],
  onCheckpoint,
  chunkSize = DEFAULT_CHUNK_SIZE,
  signal,
  onProgress,
  pending,
  acceptTimeout = ACCEPT_TIMEOUT_MS,
  resultTimeout = RESULT_TIMEOUT_MS
} = /** @type {any} */ ({}), describe) {
  // The inbound handler is installed once the transfer is under way; until
  // then nothing can arrive, because nothing is being read.
  /** @type {(type: number, body: Buffer) => void} */
  let onInbound = () => {}
  // First, before the abort check and any filesystem work, so a caller
  // without keys is told so rather than succeeding at a cancel.
  const channel = openChannel({ sendKey, receiveKey }, (type, body) => onInbound(type, body))

  // The receiver refuses a manifest declaring more than MAX_CHUNK_SIZE, and
  // the channel refuses to seal a larger body -- so a chunk size above it
  // cannot produce a working transfer, and is refused here, where the
  // caller can see it, rather than from inside the read stream's 'data'
  // handler, where a throw has no one to reach.
  if (!Number.isSafeInteger(chunkSize) || chunkSize <= 0 || chunkSize > MAX_CHUNK_SIZE) {
    throw new RangeError(`chunkSize must be 1..${MAX_CHUNK_SIZE}, got ${chunkSize}`)
  }

  // Before any filesystem work, so an already-cancelled transfer costs
  // nothing and cannot half-open a file.
  if (signal && signal.aborted) throw abortError(0, signal.reason)

  const source = await describe()
  const { size } = source
  const streamed = size === null

  const manifest = {
    v: MANIFEST_VERSION,
    name: source.name,
    size,
    sha256: source.sha256,
    blockSize: chunkSize
  }

  if (signal && signal.aborted) throw abortError(0, signal.reason)

  const progress = progressReporter(onProgress, size)
  let sent = 0
  // What RESULT must confirm: the declared digest for a file, and for a
  // stream the one computed while reading, known only at its end.
  let expected = source.sha256
  const streamHash = streamed ? crypto.createHash('sha256') : null
  // Where the receiver asked to start, and the highest offset it has
  // since reported fsynced. Both absolute file offsets.
  let resumedFrom = 0
  let durable = 0

  // A raw TCP net.Socket (the loopback path) tolerates ignoring write()'s backpressure
  // signal because the OS gives it deep send buffers. Hyperswarm's
  // encrypted duplex (the Hyperswarm transport onward) does not -- blasting writes without
  // pausing on a false return / waiting for 'drain' overwhelms it and the
  // connection resets partway through a multi-MB file. Pause/resume the
  // read stream to respect it.
  await new Promise((resolve, reject) => {
    let settled = false
    /** @type {(() => void) | null} */
    let onDrain = null
    /** @type {'offer' | 'prefix' | 'send' | 'result'} */
    let phase = 'offer'
    // One timer, for whichever wait we are in: the offer's answer, then
    // the RESULT. Never both, because the phases do not overlap.
    /** @type {NodeJS.Timeout | null} */
    let timer = null
    /** @type {import('stream').Readable | null} */
    let readStream = null

    const clearTimer = () => {
      if (timer) clearTimeout(timer)
      timer = null
    }
    const armTimer = (/** @type {number} */ ms, /** @type {() => Error} */ makeError) => {
      clearTimer()
      if (!ms) return
      timer = setTimeout(() => fail(makeError()), ms)
      if (typeof timer.unref === 'function') timer.unref()
    }

    const cleanup = () => {
      clearTimer()
      socket.removeListener('error', onError)
      socket.removeListener('end', onClosed)
      socket.removeListener('close', onClosed)
      if (onDrain) socket.removeListener('drain', onDrain)
      if (signal) signal.removeEventListener('abort', onAbort)
      if (readStream) readStream.destroy()
      socket.removeListener('data', onData)
    }

    // First settle wins, so a simultaneous cancel has each side reporting
    // its own -- two logs that cannot disagree about who cancelled.
    const fail = (err) => {
      if (settled) return
      settled = true
      cleanup()
      reject(err)
    }
    const done = () => {
      if (settled) return
      settled = true
      cleanup()
      resolve(undefined)
    }

    const onError = (err) => fail(err)

    // Before RESULT, a sender never listened for the close at all: it had
    // nothing left to wait for once its writes were accepted. Now a close
    // before RESULT is the failure the trials measured, and it has to say
    // which part of the transfer it cut off.
    function onClosed () {
      if (settled) return
      const message = {
        offer: 'the receiver disconnected before answering the offer; no file bytes were sent',
        prefix: 'the receiver disconnected while checking the prefix it asked to resume from; no file bytes were sent',
        send: streamed
          ? `the receiver disconnected after ${sent} bytes of the stream were sent`
          : `the receiver disconnected after ${sent} of ${size} bytes were sent`,
        result: 'the receiver disconnected after every byte was sent but before confirming the file; whether it was saved is unknown'
      }[phase]
      fail(new TransferError('ERR_CONNECTION', message, { bytes: sent, size, phase }))
    }

    function onAccept (body) {
      const { resumeFrom } = decodeAccept(body)

      // The receiver's final answer, after checking our PREFIX (PROTOCOL.md
      // section 7.5): the offset it proposed if its prefix matched, 0 if it
      // did not and it has discarded it. Nothing else -- in particular not
      // a different non-zero offset, which would be a prefix nobody checked.
      if (phase === 'prefix') {
        if (resumeFrom !== resumedFrom && resumeFrom !== 0) {
          throw new TransferError(
            'ERR_PROTOCOL',
            `the receiver answered its prefix check with resumeFrom ${resumeFrom}; only ${resumedFrom} (a match) or 0 (start over) is valid`
          )
        }
        beginSend(resumeFrom)
        return
      }

      // A non-zero offset is the receiver saying it already holds that
      // prefix (PROTOCOL.md section 7). Honoured only where resume can
      // mean something, and refused -- never ignored -- everywhere else:
      // starting at 0 against a receiver that kept a prefix would append
      // the whole file to it.
      if (resumeFrom !== 0) {
        if (streamed) {
          throw new TransferError('ERR_PROTOCOL', `the receiver asked to resume a stream from byte ${resumeFrom}; a stream cannot be resumed`)
        }
        if (!caps.includes('resume')) {
          throw new TransferError('ERR_PROTOCOL', `the receiver asked to resume from byte ${resumeFrom}, but the handshake did not negotiate resume`)
        }
        if (resumeFrom > /** @type {number} */ (size)) {
          throw new TransferError('ERR_PROTOCOL', `the receiver asked to resume from byte ${resumeFrom}, past the ${size} bytes offered`)
        }
        // Section 7.5's alignment rule, which is what lets PREFIX be
        // answered from the digests recorded while hashing.
        if (resumeFrom % PREFIX_BOUNDARY !== 0 && resumeFrom !== size) {
          throw new TransferError(
            'ERR_PROTOCOL',
            `the receiver asked to resume from byte ${resumeFrom}, which is neither a multiple of ${PREFIX_BOUNDARY} nor the whole file`
          )
        }
        // Not yet: the offset is a proposal until the receiver has checked
        // it against our own prefix. The phase changes BEFORE the write, so
        // an answer delivered inside socket.write is judged as one.
        resumedFrom = resumeFrom
        phase = 'prefix'
        armTimer(acceptTimeout, () => new TransferError(
          'ERR_STALLED',
          `the receiver has not answered its prefix check after ${acceptTimeout}ms; no file bytes were sent`,
          { bytes: 0, size, phase: 'prefix' }
        ))
        const digest = /** @type {(n: number) => Buffer} */ (source.prefixDigest)(resumeFrom)
        socket.write(channel.seal(TYPE_PREFIX, prefixBody({ sha256: digest.toString('hex') })))
        return
      }
      beginSend(0)
    }

    /** @param {number} from */
    function beginSend (from) {
      resumedFrom = from
      durable = from
      clearTimer()
      phase = 'send'
      startSending(from)
    }

    function awaitResult () {
      progress.final()
      phase = 'result'
      armTimer(resultTimeout, () => new TransferError(
        'ERR_STALLED',
        `the receiver has not confirmed the file ${resultTimeout}ms after the last byte was sent; whether it was saved is unknown`,
        { bytes: sent, size, phase: 'result' }
      ))
    }

    function onResult (body) {
      const result = decodeResult(body)
      if ('error' in result) {
        throw new TransferError(
          'ERR_RECEIVER_FAILED',
          result.error ? `the receiver could not keep the file: ${result.error}` : 'the receiver could not keep the file',
          { peerReason: result.error, bytes: sent }
        )
      }
      // Only a broken or hostile receiver reaches this: an honest one that
      // computed a different digest refuses the file and says so in
      // {error}, the branch above.
      if (result.sha256 !== expected) {
        throw new TransferError(
          'ERR_HASH_MISMATCH',
          `the receiver confirmed a digest that is not the one sent (sent ${expected}, receiver reports ${result.sha256})`,
          { expected, actual: result.sha256, bytes: sent, reportedBy: 'receiver' }
        )
      }
      done()
    }

    function onAbort () {
      if (settled) return
      // Written before we reject, and given a window to flush, because the
      // caller tears the socket down as soon as it sees our rejection.
      // Teardown stays the caller's job -- this function does not own the
      // socket it was handed.
      const bytes = sent
      writeCancel(socket, channel, (signal && typeof signal.reason === 'string') ? signal.reason : 'cancelled by sender')
        .then(() => fail(abortError(bytes, signal && signal.reason)))
    }

    // The sender now READS, which it never did before the failure-reporting work: a CANCEL
    // from the receiver has to be distinguishable from the socket dying,
    // and that is the whole point of the item. See ./swarm.js connectOnce,
    // which hands back `pending` for exactly this reason.
    //
    // A frame that fails to open throws out of channel.push, and onData
    // turns that into a failed send: a forged RESULT is not a verdict.
    onInbound = (type, body) => {
      if (settled) return
      if (type === TYPE_CANCEL) {
        const peerReason = decodeCancelReason(body)
        throw new TransferError(
          'ERR_CANCELLED_PEER',
          peerReason ? `the receiver cancelled: ${peerReason}` : 'the receiver cancelled the transfer',
          { peerReason, bytes: sent }
        )
      }
      if (phase === 'offer' || phase === 'prefix') {
        if (type === TYPE_ACCEPT) {
          onAccept(body)
          return
        }
        if (type === TYPE_DECLINE) {
          // `.code` stays ERR_DECLINED: section 10's codes say how THIS
          // side's drop ended, and the sender's file was not an unsafe
          // name or a full disk. The receiver's reason for it is
          // `.declineCode`, for anything automated to switch on.
          const { reason: peerReason, code: declineCode } = decodeDecline(body)
          throw new TransferError(
            'ERR_DECLINED',
            peerReason ? `the receiver declined the file: ${peerReason}` : 'the receiver declined the file',
            { peerReason, declineCode, bytes: 0 }
          )
        }
        throw new TransferError(
          'ERR_PROTOCOL',
          phase === 'prefix'
            ? `receiver sent ${TYPE_NAMES.get(type)} before answering its prefix check; only ACCEPT, DECLINE or CANCEL is expected`
            : `receiver sent ${TYPE_NAMES.get(type)} before answering the offer; only ACCEPT, DECLINE or CANCEL is expected`
        )
      }
      if (type === TYPE_CHECKPOINT) {
        onCheckpointFrame(body)
        return
      }
      if (type === TYPE_RESULT) {
        if (phase !== 'result') {
          throw new TransferError('ERR_PROTOCOL', `the receiver sent RESULT after ${sent}${streamed ? '' : ` of ${size}`} bytes, before the file was complete`)
        }
        onResult(body)
        return
      }
      throw new TransferError(
        'ERR_PROTOCOL',
        `receiver sent ${TYPE_NAMES.get(type)} during a transfer; only CANCEL or RESULT is expected`
      )
    }

    // The receiver's durable offset. It is part of the resume capability
    // (section 3.2) and only means something for a transfer that could be
    // resumed, so it is refused elsewhere. It may only move forward, and
    // never past what we have sent -- a receiver cannot have fsynced bytes
    // that have not been handed to it.
    function onCheckpointFrame (body) {
      if (streamed || !caps.includes('resume')) {
        throw new TransferError('ERR_PROTOCOL', 'the receiver sent CHECKPOINT, which only a resumable transfer carries')
      }
      const { offset } = decodeCheckpoint(body)
      if (offset < durable || offset > sent) {
        throw new TransferError(
          'ERR_PROTOCOL',
          `the receiver reported ${offset} bytes durable, outside ${durable}..${sent} (its last checkpoint to what has been sent)`
        )
      }
      durable = offset
      if (onCheckpoint) onCheckpoint({ offset, total: /** @type {number} */ (size) })
    }

    function onData (chunk) {
      try {
        channel.push(chunk)
      } catch (err) {
        fail(err)
      }
    }

    // Called once, on ACCEPT. The source is not opened or read before
    // this, so a declined offer never touches a file again after the hash,
    // and never takes a byte from a stream's producer.
    /** @param {number} start the receiver's resumeFrom */
    function startSending (start) {
      sent = start
      progress.emit(sent)
      // Nothing left to send: an empty file, or a receiver that already
      // holds every byte and is about to verify them.
      if (sent === size) {
        awaitResult()
        return
      }

      const stream = source.open(start)
      readStream = stream

      stream.on('data', (/** @type {Buffer} */ chunk) => {
        if (settled) return
        // A file's read stream never yields more than its highWaterMark,
        // which is chunkSize. A caller's stream yields whatever its
        // producer wrote, so a chunk is split to the blockSize the manifest
        // declared -- the receiver refuses anything larger.
        let ok = true
        for (let offset = 0; offset < chunk.length; offset += chunkSize) {
          const piece = chunk.subarray(offset, offset + chunkSize)
          /** @type {Buffer} */
          let frame
          try {
            frame = channel.seal(TYPE_CHUNK, piece)
          } catch (err) {
            // chunkSize is validated above, so this is the counter-exhaustion
            // assertion or a bug -- either way a failed send, not a crash.
            fail(err)
            return
          }
          if (streamHash) streamHash.update(piece)
          sent += piece.length
          // The last declared byte: from here the receiver may answer, so
          // the RESULT phase starts BEFORE the write that lets it. A
          // transport that delivers synchronously -- the test duplex does
          // -- hands RESULT back inside socket.write, and a sender still in
          // the send phase refuses it as early.
          if (!streamed && sent === size) awaitResult()
          ok = socket.write(frame) && ok
        }
        if (phase === 'send') progress.emit(sent)
        if (!ok) {
          stream.pause()
          onDrain = () => {
            onDrain = null
            stream.resume()
          }
          socket.once('drain', onDrain)
        }
      })
      stream.on('end', () => {
        if (settled) return
        if (streamHash) {
          // The digest the manifest could not carry. Sealed straight after
          // the last chunk, so nothing can come between them, and after
          // entering the RESULT phase for the reason given above.
          expected = streamHash.digest('hex')
          /** @type {Buffer} */
          let end
          try {
            end = channel.seal(TYPE_END, endBody({ sha256: expected }))
          } catch (err) {
            fail(err)
            return
          }
          awaitResult()
          socket.write(end)
          return
        }
        // Already awaiting RESULT if every declared byte was read, so
        // what is left is only the file that shrank underneath us.
        if (phase === 'result') return
        fail(new TransferError(
          'ERR_SIZE_MISMATCH',
          `read ${sent} bytes but the manifest declared ${size}: the file changed while it was being sent`,
          { bytes: sent, size }
        ))
      })
      stream.on('error', fail)
    }

    socket.on('error', onError)
    socket.on('data', onData)
    socket.on('end', onClosed)
    socket.on('close', onClosed)
    if (signal) signal.addEventListener('abort', onAbort, { once: true })

    // The offer, written only once every listener that could hear its
    // answer is attached.
    socket.write(channel.seal(TYPE_MANIFEST, Buffer.from(JSON.stringify(manifest), 'utf8')))
    armTimer(acceptTimeout, () => new TransferError(
      'ERR_STALLED',
      `the receiver has not answered the offer after ${acceptTimeout}ms; no file bytes were sent`,
      { bytes: 0, size, phase: 'offer' }
    ))

    if (pending && pending.length > 0) onData(pending)
    // A handshake that paused the socket to hold the gap before this
    // listener existed -- connectStream does -- left it paused, and
    // attaching a 'data' listener does NOT resume a stream that was
    // explicitly paused. Without this the sender never reads the
    // receiver's answer and waits out the accept timeout on an offer that
    // was accepted. connectOnce never paused, which is why this was not
    // needed until there were two handshakes; receiveFile has always done
    // the same.
    if (typeof socket.resume === 'function') socket.resume()
  })

  return { name: manifest.name, size: sent, sha256: /** @type {string} */ (expected), resumedFrom }
}

// --- manifest validation -------------------------------------------------

// Every field a peer sends is untrusted input, and this is the first thing
// the failure-reporting work checks because the manifest is the one message that decides what
// happens on our filesystem.
/**
 * @param {any} manifest
 * @param {number | null | undefined} maxSize
 *   omitted gets DEFAULT_MAX_SIZE; `null` opts out of any cap, which a
 *   caller has to say on purpose.
 */
function validateManifest (manifest, maxSize) {
  const invalid = (field, detail) => new TransferError(
    'ERR_MANIFEST_INVALID',
    `manifest field ${field} is invalid: ${detail}`,
    { field }
  )

  if (manifest === null || typeof manifest !== 'object' || Array.isArray(manifest)) throw invalid('(root)', 'not an object')
  // First, so a v1 peer is told its version is wrong rather than that its
  // `type` and `chunkSize` fields are unknown. A version that is present
  // and wrong is a peer we cannot safely parse; saying so beats guessing
  // at its layout.
  if (manifest.v !== MANIFEST_VERSION) {
    throw invalid('v', `unsupported manifest version ${JSON.stringify(manifest.v)} (this build speaks v${MANIFEST_VERSION})`)
  }
  // Closed, not open: see MANIFEST_FIELDS. Object.keys sees an own
  // "__proto__" that JSON.parse created, so that is refused here too.
  for (const key of Object.keys(manifest)) {
    if (!MANIFEST_FIELDS.includes(key)) throw invalid(key, 'not a manifest v2 field')
  }
  if (typeof manifest.name !== 'string') throw invalid('name', 'not a string')
  // null is streaming (section 4.3), and it is not the same as absent: a
  // manifest that omits `size` is malformed, not a stream.
  if (manifest.size !== null && (!Number.isSafeInteger(manifest.size) || manifest.size < 0)) {
    throw invalid('size', `expected a non-negative safe integer or null, got ${JSON.stringify(manifest.size)}`)
  }
  if (manifest.sha256 !== null && (typeof manifest.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(manifest.sha256))) {
    throw invalid('sha256', 'not a lowercase 64-character hex digest, or null')
  }
  // Both or neither. Section 4.3 defines those two shapes and no others:
  // a declared file is checked against both, a stream against END's
  // digest. A length without a digest would be a transfer with nothing to
  // verify it against until END, which is a stream that lied about being
  // one.
  if ((manifest.size === null) !== (manifest.sha256 === null)) {
    throw invalid('sha256', 'size and sha256 must both be declared, or both be null for a streamed transfer')
  }
  if (!Number.isSafeInteger(manifest.blockSize) || manifest.blockSize <= 0 || manifest.blockSize > MAX_CHUNK_SIZE) {
    throw invalid('blockSize', `expected 1..${MAX_CHUNK_SIZE}, got ${JSON.stringify(manifest.blockSize)}`)
  }
  // A CAP APPLIES UNLESS ONE IS REFUSED. This used to read "optional, and
  // off by default: the engine enforces no size cap of its own", on the
  // argument that a limit is product policy for the accept screen. The
  // argument is still right about *where the product's limit lives* and
  // was wrong about the default: with nothing passed, a manifest
  // declaring 9 PB validated cleanly. Defaulting to no cap means every
  // caller that forgets one is unprotected, and both CLIs forgot.
  //
  // `null` is the opt-out, and it has to be written down.
  const cap = maxSize === undefined ? DEFAULT_MAX_SIZE : maxSize
  if (cap !== null && manifest.size !== null && manifest.size > cap) {
    throw invalid('size', `${manifest.size} bytes exceeds the ${cap} byte limit this receiver was given`)
  }
}

// Turns a manifest's declared name into a name we are willing to write,
// or refuses. Layered deliberately: shape first, then a resolved-path
// assertion, because neither alone is convincing.
//
// The shape checks now live in ./names.js, with the display sanitiser
// that has to agree with them -- the two were separate concerns right up
// until the moment a name was refused, at which point the refusal message
// printed the hostile name raw. The resolved-path assertion stays here,
// because it is about this directory rather than about the name, and it
// backstops the shape checks against anything they did not anticipate.
// That is the failure mode that matters: this function being wrong writes
// a file wherever a peer points it.
//
// The code proof stopped a stranger from reaching the receiver at all. It
// did nothing about a peer that knows the code and aims at ~/.bashrc, and
// `path.join(outputDir, manifest.name)` aimed wherever it was told.
/**
 * @param {string} outputDir
 * @param {string} declaredName
 * @param {{ platform?: NodeJS.Platform | string }} [options]
 * @returns {{ name: string, outputPath: string }}
 */
function safeOutputName (outputDir, declaredName, options = {}) {
  const name = safeWriteName(declaredName, options)

  const unsafe = (detail) => new TransferError(
    'ERR_UNSAFE_NAME',
    `refusing the peer's filename ${JSON.stringify(displayName(declaredName))}: ${detail}`,
    { declaredName, detail }
  )

  const resolvedDir = path.resolve(outputDir)
  // A resolved root ('/' or 'C:\\') already ends in a separator; appending
  // another would make every legitimate name fail the prefix test.
  const prefix = resolvedDir.endsWith(path.sep) ? resolvedDir : resolvedDir + path.sep
  const outputPath = path.resolve(resolvedDir, name)
  if (!outputPath.startsWith(prefix)) {
    throw unsafe('it resolves outside the output directory')
  }

  return { name, outputPath }
}

// --- landing the file without destroying another one ---------------------

// THE DEFAULT USED TO BE OVERWRITE, and it was written down as a decision
// rather than an oversight: "overwrite / suffix / prompt is an accept-
// screen question, and the accept screen is Phase B. Deciding it here
// would mean deciding it twice."
//
// That reasoning is wrong in a way worth recording, because it is a
// tempting shape of argument. It treats the choice as cosmetic -- which
// of several acceptable outcomes do we present -- when the status quo
// while waiting for the UI was *destroying an existing file*. And the
// output directory defaults to `process.cwd()`, so "inside the output
// directory" was never a synonym for "safe": a peer holding the drop code
// could name its file `.zshrc`, `package.json` or `id_rsa` and replace
// whatever was in the directory the receiver happened to be launched
// from. A UI cannot fix that later for every headless and scripted
// caller, so the safe default belongs in the engine and the accept screen
// can still offer Replace on top of it.
const MAX_SUFFIX_ATTEMPTS = 1000

/**
 * `report.pdf` -> `report (1).pdf`, `report (2).pdf`, ...
 * The extension is preserved rather than appended-past, because a name
 * whose extension moved is a name the OS opens with the wrong program.
 * @param {string} outputPath
 * @param {number} n
 */
function suffixed (outputPath, n) {
  const dir = path.dirname(outputPath)
  const ext = path.extname(outputPath)
  const stem = path.basename(outputPath, ext)
  return path.join(dir, `${stem} (${n})${ext}`)
}

/**
 * Publishes the verified `.part` under its final name without ever
 * replacing a file we did not create.
 *
 * `fs.rename` cannot do this: POSIX rename() silently clobbers its
 * destination, and libuv's Windows implementation passes
 * MOVEFILE_REPLACE_EXISTING, so it clobbers there too. `link()` is the
 * primitive that refuses -- it fails with EEXIST rather than overwriting,
 * atomically, so two receivers racing for one name cannot both win. The
 * unlink afterwards drops our own `.part`, leaving one file.
 *
 * Filesystems without hard links (FAT, some network mounts) fail with
 * EPERM/ENOSYS/EXDEV. There the fallback is check-then-rename, which is
 * racy against another process by a few microseconds and is still right
 * about the case that matters: a file that was already sitting there.
 *
 * @param {string} partPath
 * @param {string} outputPath
 * @param {{ replace?: boolean }} options
 * @returns {Promise<string>} the path actually written
 */
async function publish (partPath, outputPath, { replace = false }) {
  if (replace) {
    await fs.promises.rename(partPath, outputPath)
    return outputPath
  }

  let linkable = true
  for (let n = 0; n <= MAX_SUFFIX_ATTEMPTS; n++) {
    const candidate = n === 0 ? outputPath : suffixed(outputPath, n)

    if (linkable) {
      try {
        await fs.promises.link(partPath, candidate)
        await fs.promises.unlink(partPath)
        return candidate
      } catch (err) {
        if (err.code === 'EEXIST') continue
        if (err.code !== 'EPERM' && err.code !== 'ENOSYS' && err.code !== 'EXDEV' && err.code !== 'ENOTSUP') throw err
        // No hard links here. Fall through to the racy path and stay on
        // it for the remaining candidates rather than retrying link().
        linkable = false
      }
    }

    try {
      await fs.promises.access(candidate)
      continue // it exists; try the next suffix
    } catch {
      await fs.promises.rename(partPath, candidate)
      return candidate
    }
  }

  throw new TransferError(
    'ERR_EXISTS',
    `refusing to overwrite ${JSON.stringify(path.basename(outputPath))}: ${MAX_SUFFIX_ATTEMPTS} suffixed names are all taken`,
    { outputPath }
  )
}

/**
 * Opens the partial exclusively. O_EXCL is doing two jobs: it refuses to
 * reuse a `.part` left by another live receiver, and -- the reason it is
 * not merely tidy -- open(O_CREAT|O_EXCL) refuses to follow a symlink, so
 * a pre-planted `<name>.part` pointing at ~/.ssh/authorized_keys cannot
 * turn "write into the output directory" into "write anywhere".
 *
 * A crashed receiver leaves a `.part` behind, and with O_EXCL a plain
 * retry would then fail forever -- so a taken name is suffixed rather
 * than refused. This is the FRESH path. A resumable transfer first tries
 * reopenPartial on the unsuffixed name, which cannot use O_EXCL and so
 * makes its own checks; only if that finds nothing it trusts does this
 * run, and the suffixed partial it opens is never kept for resuming.
 *
 * @param {string} outputPath
 * @returns {Promise<{ stream: fs.WriteStream, partPath: string, handle: fs.promises.FileHandle }>}
 */
async function openPartial (outputPath) {
  for (let n = 0; n <= MAX_SUFFIX_ATTEMPTS; n++) {
    const partPath = n === 0 ? `${outputPath}.part` : `${outputPath}.part.${n}`
    let handle
    try {
      handle = await fs.promises.open(partPath, 'wx')
    } catch (err) {
      if (err.code === 'EEXIST') continue
      throw err
    }
    // The handle's own stream, not `createWriteStream(path)`: reopening
    // by path would discard the exclusive open we just won and race the
    // symlink back in. Closing the stream closes the handle.
    return { stream: handle.createWriteStream(), partPath, handle }
  }
  throw new TransferError(
    'ERR_EXISTS',
    `cannot open a partial file for ${JSON.stringify(path.basename(outputPath))}: every candidate .part name is taken`,
    { outputPath }
  )
}

/**
 * Finds a partial worth resuming, or says there is none. Never throws: a
 * partial that is absent, unreadable or suspect is simply not resumed,
 * and the caller opens a fresh one beside it.
 *
 * THE PARTIAL IS NOT TRUSTED, and PROTOCOL.md section 7.2 is the reason.
 * The `.part` name is predictable, so anything that can write to the
 * output directory can put something there. Three checks stand between
 * that and a write outside it, each on the open descriptor rather than
 * the path, so nothing can be swapped in between check and use:
 *
 *   - O_NOFOLLOW: a planted symlink fails to open (ELOOP) instead of being
 *     followed to ~/.ssh/authorized_keys. openPartial gets the same
 *     protection from O_EXCL; appending to an existing file cannot use
 *     O_EXCL, so it needs this instead.
 *   - one link: a planted HARD link to a file elsewhere on the volume opens
 *     cleanly and is a regular file -- nlink is the only thing that tells
 *     it apart, and appending to it would write into the other file.
 *   - no longer than the offer: a longer file is not a prefix of this one.
 *
 * What survives is re-hashed into a fresh SHA-256 whose state the transfer
 * carries forward -- but only up to `length`, the largest PREFIX_BOUNDARY
 * multiple it holds, or the whole file if it holds every byte. That is the
 * offset ACCEPT proposes, and PROTOCOL.md section 7.5 restricts it so the
 * sender can answer PREFIX without re-reading. Whatever lies past `length`
 * is cut off when the transfer adopts the partial, never before.
 *
 * Re-hashing does NOT prove the prefix belongs to this file; a whole-file
 * digest cannot vouch for a prefix. The sender's PREFIX does, checked in
 * receiveFile before the partial is adopted, and a prefix that fails it is
 * truncated to nothing and the transfer starts at zero. The final digest
 * comparison still runs regardless.
 *
 * `length` may be 0: a partial under one boundary is still the primary
 * `.part`, reused and truncated rather than left beside a fresh `.part.1`
 * that no later offer would look for.
 *
 * Windows has no O_NOFOLLOW, and there an lstat on the path is the
 * fallback: racy against another process, and still right about a link
 * that was already sitting there.
 *
 * @param {string} outputPath
 * @param {number} size the offer's declared size
 * @returns {Promise<{ handle: fs.promises.FileHandle, partPath: string, length: number, hash: crypto.Hash } | null>}
 */
async function reopenPartial (outputPath, size) {
  const partPath = `${outputPath}.part`
  const noFollow = fs.constants.O_NOFOLLOW || 0
  let handle
  try {
    if (!noFollow && (await fs.promises.lstat(partPath)).isSymbolicLink()) return null
    handle = await fs.promises.open(partPath, fs.constants.O_RDWR | noFollow)
  } catch {
    return null
  }
  try {
    const stat = await handle.stat()
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > size) {
      await handle.close()
      return null
    }
    const length = stat.size === size ? size : stat.size - (stat.size % PREFIX_BOUNDARY)
    const hash = crypto.createHash('sha256')
    const buffer = Buffer.allocUnsafe(PREFIX_BOUNDARY)
    let position = 0
    while (position < length) {
      const { bytesRead } = await handle.read(buffer, 0, Math.min(buffer.length, length - position), position)
      // Shorter than it said: not a partial worth a proposal. Starting from
      // what was read would propose an offset off the boundary.
      if (bytesRead === 0) {
        await handle.close()
        return null
      }
      hash.update(buffer.subarray(0, bytesRead))
      position += bytesRead
    }
    return { handle, partPath, length, hash }
  } catch {
    await handle.close().catch(() => {})
    return null
  }
}

/**
 * Refuses a transfer that cannot possibly fit, before it opens anything.
 *
 * Deliberately advisory: `statfs` is missing on some platforms and lies
 * on others (compression, quotas, reservations), so a failure to measure
 * is not a failure to transfer. What it catches is the honest case --
 * being told to receive more bytes than the disk has -- which otherwise
 * surfaces as ENOSPC partway through, after the sender has spent the
 * upload.
 *
 * @param {string} dir
 * @param {number} size
 */
async function checkFreeSpace (dir, size) {
  if (typeof fs.promises.statfs !== 'function') return
  let free
  try {
    const stats = await fs.promises.statfs(dir)
    free = Number(stats.bavail) * Number(stats.bsize)
  } catch {
    return
  }
  if (!Number.isFinite(free) || free <= 0) return
  if (size > free) {
    throw new TransferError(
      'ERR_NO_SPACE',
      `the peer declared ${size} bytes but only ${Math.floor(free)} are free in the output directory`,
      { size, free: Math.floor(free) }
    )
  }
}

// Reads manifest + chunk frames off `socket` and writes the file into
// `outputDir`, verifying it before it is visible under its real name.
// This is step D6 of the data path -- "receiver verifies the full-file
// hash; publish under the real name only then".
//
// Once, this function computed a digest, returned it, and compared it to
// nothing. Only engine/scratch-trials.js ever did the comparison, so the
// measurement harness verified integrity and neither CLI did.
//
// WHAT STAGE 0 ADDED, and the shape of the hole in each case. Every one
// of these was reachable by a peer that had already passed the code
// proof, which is the point: proving you know the drop code makes you the
// intended peer, not a trustworthy one.
//
//   - It no longer overwrites. See `publish`.
//   - The partial is opened O_EXCL, so a planted symlink cannot redirect
//     the write. See `openPartial`.
//   - A declared size is capped and checked against free space before
//     anything is opened.
//   - `writeStream.write()`'s return value is honoured. It was discarded,
//     so a sender faster than the receiver's disk grew an unbounded queue
//     in memory -- the sender has had this treatment since the Hyperswarm work and the
//     receiver never did.
//   - A peer that proves and then goes silent is timed out rather than
//     waited on forever.
//
// And under v2, every frame is opened by a Channel keyed from the PAKE
// transcript before anything above sees it. A frame that fails to
// authenticate -- altered, replayed, reordered, or from anyone who did not
// complete the handshake -- fails the receive as ERR_PROTOCOL at that
// frame, rather than being written to the partial and caught at the end
// as a hash mismatch.
//
// THE ACCEPT GATE. A MANIFEST is an offer, and this side answers it with
// ACCEPT or DECLINE before the sender may send a byte of the file. Every
// refusal that used to end in a bare close -- an unsafe name, a size over
// the cap, no free space, a .part that cannot be opened -- is now a
// DECLINE carrying the reason, so the sender reports why rather than
// "the receiver disconnected". `onOffer` is the caller's say in it: the
// hook an accept screen, or a scripted policy, answers.
//
// The order is fixed and it is the order of cost: validate the manifest
// and the name (free), ask onOffer, check free space, open the partial,
// and only then ACCEPT. So a declined offer creates nothing on disk, and
// an ACCEPT means the file is already open and ready for the first chunk.
/**
 * @param {any} socket
 * @param {string} outputDir
 * @param {{
 *   sendKey: Buffer,
 *   receiveKey: Buffer,
 *   caps?: string[],
 *   onOffer?: (offer: { name: string, declaredName: string, size: number | null, sha256: string | null, blockSize: number }) => boolean | string | Promise<boolean | string>,
 *   onManifest?: (manifest: any, accepted: { resumeFrom: number }) => void,
 *   pending?: Buffer | null,
 *   signal?: AbortSignal,
 *   onProgress?: (p: { bytes: number, total: number | null }) => void,
 *   maxSize?: number | null,
 *   replace?: boolean,
 *   platform?: NodeJS.Platform | string,
 *   manifestTimeout?: number,
 *   progressTimeout?: number,
 *   checkpointInterval?: number,
 *   checkSpace?: boolean
 * }} [options]
 *   `sendKey`/`receiveKey` are this side's channel keys, as acceptOnce
 *   returns them; see openChannel.
 *   `caps` is the capability list the same handshake returned. A streamed
 *   offer (size: null) is declined unless it contains `stream`.
 *   `maxSize` caps a stream too, counted as it arrives, since a stream
 *   declares no size to check up front.
 *   `onOffer` decides whether to take the file, after the engine's own
 *   checks have passed. `true` accepts; `false` declines; a string
 *   declines with that string as the reason the sender is shown. Anything
 *   else declines too -- an accept screen whose hook forgot to return must
 *   not have said yes. Omitted, every offer that passes the checks is
 *   accepted, which is what both CLIs want today.
 *   `onManifest` is a notification, after the offer is accepted, with
 *   `{ resumeFrom }` as its second argument.
 *   `caps` containing `resume` also makes a declared-size transfer
 *   resumable: an earlier `<name>.part` is re-hashed, checked against the
 *   sender's PREFIX, and continued on a match or restarted on a miss, a
 *   CHECKPOINT is sent every `checkpointInterval` ms, and an interrupted
 *   transfer keeps its partial (reported as `err.partial`).
 *   `pending` is any payload the readiness handshake read off the socket
 *   before handing it over -- see acceptOnce in ./swarm.js, which pauses
 *   the socket and returns leftover bytes rather than swallowing them.
 *   `replace: true` opts back in to overwriting an existing file.
 *   Timeouts are in ms; 0 disables one.
 * @returns {Promise<{ name: string, declaredName: string, size: number, sha256: string, path: string, resumedFrom: number }>}
 */
function receiveFile (socket, outputDir, {
  sendKey,
  receiveKey,
  caps = [],
  onOffer,
  onManifest,
  pending,
  signal,
  onProgress,
  maxSize,
  replace = false,
  platform,
  manifestTimeout = MANIFEST_TIMEOUT_MS,
  progressTimeout = PROGRESS_TIMEOUT_MS,
  checkpointInterval = CHECKPOINT_INTERVAL_MS,
  checkSpace = true
} = /** @type {any} */ ({})) {
  return new Promise((resolve, reject) => {
    // First, as in sendFile: a caller without keys is refused before the
    // abort check or any listener, and the throw becomes this rejection.
    const channel = openChannel({ sendKey, receiveKey }, onMessage)

    /** @type {any} */
    let manifest = null
    /** @type {fs.WriteStream | null} */
    let writeStream = null
    /** @type {crypto.Hash | null} */
    let hash = null
    let received = 0
    let declaredName = ''
    let name = ''
    /** @type {string | null} */
    let outputPath = null
    /** @type {string | null} */
    let partPath = null
    let settled = false
    // offered: a MANIFEST has arrived. accepted: we have answered ACCEPT.
    // Between the two the sender may send nothing but CANCEL, which is
    // what lets this function hold no frames while it decides -- the
    // deferral queue v1 needed for chunks racing the open is gone, because
    // under the accept gate a chunk in that window is a protocol error.
    let offered = false
    let accepted = false
    // ACCEPT{resumeFrom > 0} has gone out and the sender's PREFIX has not
    // yet come back (PROTOCOL.md section 7.5). The offer is still not
    // answered: the partial is still the earlier attempt's.
    let awaitingPrefix = false
    // The open, as something cleanup can wait on -- see discardPartial.
    /** @type {Promise<void> | null} */
    let openingPromise = null
    /** @type {{ emit: (n: number) => void, final: () => void }} */
    let progress = { emit: () => {}, final: () => {} }
    /** @type {NodeJS.Timeout | null} */
    let stallTimer = null
    // Resume (PROTOCOL.md section 7). `resumable` is decided once, when
    // the offer is considered: the handshake negotiated resume and the
    // manifest declared a size. `resumeFrom` is the prefix we already held
    // and re-hashed; `durable` the highest offset fsynced and reported.
    let resumable = false
    // True when the partial was reopened from an earlier attempt rather
    // than created by this one. See discardPartial.
    let reusedPartial = false
    let resumeFrom = 0
    let durable = 0
    /** @type {fs.promises.FileHandle | null} */
    let fileHandle = null
    /** @type {NodeJS.Timeout | null} */
    let checkpointTimer = null
    let checkpointing = false

    if (signal && signal.aborted) {
      reject(abortError(0, signal.reason))
      return
    }

    // One timer, rearmed on every sign of life, covering both stalls: the
    // manifest that never arrives and the transfer that stops mid-file.
    // They are one mechanism because they are one attack -- a peer that
    // holds the connection open and sends nothing -- and differ only in
    // the budget and the sentence.
    const armStall = (/** @type {number} */ ms, /** @type {string} */ what) => {
      if (stallTimer) clearTimeout(stallTimer)
      stallTimer = null
      if (!ms) return
      stallTimer = setTimeout(() => {
        if (settled) return
        fail(new TransferError(
          'ERR_STALLED',
          `the sender proved it knows the drop code and then ${what} for ${ms}ms`,
          { bytes: received, size: manifest ? manifest.size : null }
        ), null, true)
      }, ms)
      // A stall timer must never be the reason the process stays alive.
      if (typeof stallTimer.unref === 'function') stallTimer.unref()
    }

    const detach = () => {
      if (stallTimer) clearTimeout(stallTimer)
      stallTimer = null
      if (checkpointTimer) clearInterval(checkpointTimer)
      checkpointTimer = null
      socket.removeListener('data', onData)
      socket.removeListener('error', onSocketError)
      socket.removeListener('end', onClosed)
      socket.removeListener('close', onClosed)
      // On the write stream, not the socket: that is where it was
      // attached, and the pair has to match or the listener outlives the
      // transfer that owns it.
      if (writeStream) writeStream.removeListener('drain', onWriteDrain)
      if (signal) signal.removeEventListener('abort', onAbort)
    }

    // Deletes the partial -- the default for every failure except the one
    // keepPartial covers, and always for a digest mismatch, because bytes
    // known to be wrong must never be left looking resumable.
    const discardPartial = async () => {
      // An abort can land while the partial is still being opened, and
      // `partPath` is only assigned once the open has won. Checking it
      // first meant cleanup looked at a null, decided there was nothing
      // to delete, and returned -- and then the open completed and
      // created the file, after the promise had already rejected. The
      // receiver was left with a `.part` on disk that nothing owned.
      //
      // That is the intermittent failure in cli/test/cancel.test.js's
      // simultaneous-cancel case: not a slow filesystem, and not the test
      // reading the directory too early (the file is still there a
      // hundred milliseconds later), but cleanup racing an open it did
      // not know was in flight. Waiting for the open to settle is what
      // makes `partPath` trustworthy.
      if (openingPromise) await openingPromise.catch(() => {})
      if (!partPath) return
      // NOT OURS TO DELETE YET. Before ACCEPT, a reopened partial is still
      // the earlier, interrupted attempt's: this offer only opened it to
      // re-hash. Deleting it here meant a sender that cancelled, or a
      // connection that dropped, while the prefix was being hashed
      // destroyed exactly the bytes resume exists to keep. Close it and
      // leave it. After ACCEPT the transfer has adopted it, and a failure
      // that discards discards it too.
      if (reusedPartial && !accepted) {
        if (writeStream && !writeStream.closed) {
          await new Promise((done) => {
            writeStream.once('close', done)
            writeStream.destroy()
          })
        } else if (!writeStream && fileHandle) {
          // Not adopted, so no stream owns the descriptor yet.
          await fileHandle.close().catch(() => {})
        }
        return
      }
      // Wait for the stream to be genuinely closed before unlinking. A
      // failure arriving in the same tick as the open -- an over-read on
      // the very first chunk, say -- can otherwise unlink before the open
      // has settled, and the file reappears a moment later.
      if (writeStream && !writeStream.closed) {
        await new Promise((done) => {
          writeStream.once('close', done)
          writeStream.destroy()
        })
      }
      await fs.promises.rm(partPath, { force: true }).catch(() => {})
    }

    // WHICH FAILURES LEAVE A PARTIAL BEHIND, and the rule is narrow on
    // purpose. Resume exists for a transfer that was INTERRUPTED -- the
    // connection dropped, or the sender went silent -- so only those keep
    // their bytes, and only when the transfer could be resumed at all:
    // resume negotiated, a declared size, and the partial under the one
    // name a later offer will look for. A cancel, from either side, means
    // "I do not want this", and still discards. So does every failure that
    // makes the bytes themselves suspect: a digest or size mismatch, a
    // protocol error. A crash keeps its partial without asking, because no
    // cleanup runs at all.
    /** @param {boolean} interrupted */
    const keepsPartial = (interrupted) =>
      interrupted && resumable && accepted && received > 0 && partPath === `${outputPath}.part`

    // Closes the partial and leaves it for a later offer to resume. end(),
    // not destroy(): whatever the stream still buffers belongs on disk.
    const keepPartial = async () => {
      if (openingPromise) await openingPromise.catch(() => {})
      if (writeStream && !writeStream.closed) {
        await new Promise((done) => {
          writeStream.once('close', done)
          writeStream.end()
        })
      }
    }

    // First settle wins, on both sides, so a simultaneous cancel has each
    // end reporting its own rather than the two logs contradicting.
    //
    // `notice` is a frame to tell the sender before reporting locally --
    // a DECLINE, or a CANCEL for a stream past the cap -- so the two sides
    // cannot disagree about why the transfer ended. It is written after
    // `settled` is set, so nothing that arrives during the flush can act
    // on a transfer already over.
    //
    // `interrupted` marks the failures that leave a resumable partial; see
    // keepsPartial. It is passed by the three call sites that mean it --
    // a close, a socket error and a stall -- rather than inferred from an
    // error code, so a new failure path discards unless it says otherwise.
    function fail (err, notice = null, interrupted = false) {
      if (settled) return
      settled = true
      detach()
      const told = notice ? writeFlushed(socket, notice) : Promise.resolve()
      const cleanup = keepsPartial(interrupted) ? keepPartial : discardPartial
      told.then(cleanup).then(() => {
        if (keepsPartial(interrupted) && err && typeof err === 'object') {
          err.partial = { path: partPath, bytes: received }
        }
        reject(err)
      }, () => reject(err))
    }

    // Every way an offer ends without an ACCEPT goes through here, so
    // every one of them reaches the sender as DECLINE{reason}.
    function decline (err) {
      if (settled) return
      /** @type {Buffer | null} */
      let notice = null
      try {
        notice = channel.seal(TYPE_DECLINE, declineBody(reasonForPeer(err), declineCodeFor(err)))
      } catch {
        // The counter-exhaustion assertion: nothing can be sealed, so the
        // sender is told nothing and sees the close.
      }
      fail(err, notice)
    }

    function onSocketError (err) {
      fail(err, null, true)
    }

    // The infinite hang this closes: the only listeners used to be 'data'
    // and 'error', so a sender that vanished mid-transfer -- the routine
    // outcome on a flaky punch -- left this promise pending forever. No
    // error, no timeout, no exit. 'close' is settled-guarded because it
    // also fires on the normal path, after we have already resolved.
    function onClosed () {
      if (settled) return
      const message = accepted
        ? manifest.size === null
          ? `the sender disconnected after ${received} bytes of a stream, before its END`
          : `the sender disconnected after ${received} of ${manifest.size} bytes`
        : offered
          ? 'the sender disconnected before its offer was answered'
          : 'the sender disconnected before sending a manifest'
      fail(new TransferError('ERR_CONNECTION', message, { bytes: received, size: manifest ? manifest.size : null }), null, true)
    }

    function onAbort () {
      if (settled) return
      const bytes = received
      writeCancel(socket, channel, (signal && typeof signal.reason === 'string') ? signal.reason : 'cancelled by receiver')
        .then(() => fail(abortError(bytes, signal && signal.reason)))
    }

    // Paired with the pause in handleMessage: the receiver's disk is now
    // allowed to push back on the network, which is the same contract the
    // sender has honoured since the Hyperswarm work and the receiver never did.
    function onWriteDrain () {
      if (settled) return
      if (typeof socket.resume === 'function') socket.resume()
    }

    // Everything between a MANIFEST arriving and ACCEPT going out. Throws
    // to decline; the caller turns any throw into a DECLINE.
    /** @param {Buffer} body */
    async function consider (body) {
      let parsed
      try {
        parsed = JSON.parse(body.toString('utf8'))
      } catch (err) {
        throw new TransferError('ERR_MANIFEST_INVALID', `manifest is not valid JSON: ${err.message}`, { field: null })
      }

      // Everything is checked before a single filesystem call, so a
      // manifest we are going to refuse never creates, truncates or
      // touches anything.
      validateManifest(parsed, maxSize)
      // A stream (size: null) is taken only if the handshake negotiated
      // it. The check is against the transcript's result, never against
      // anything the manifest says about itself -- section 3.2's trap #3,
      // and the reason manifest v2 has no caps field.
      if (parsed.size === null && !caps.includes('stream')) {
        throw new TransferError(
          'ERR_MANIFEST_INVALID',
          'manifest field size is invalid: null (a stream) needs the "stream" capability, which the handshake did not negotiate',
          { field: 'size' }
        )
      }
      const safe = safeOutputName(outputDir, parsed.name, { platform })

      manifest = parsed
      declaredName = parsed.name
      name = safe.name
      outputPath = safe.outputPath

      if (onOffer) {
        const verdict = await onOffer({
          name: safe.name,
          declaredName: parsed.name,
          size: parsed.size,
          sha256: parsed.sha256,
          blockSize: parsed.blockSize
        })
        if (settled) return
        if (verdict !== true) {
          const reason = typeof verdict === 'string' ? sanitizeReason(verdict) : ''
          throw new TransferError(
            'ERR_DECLINED',
            reason || 'the receiver declined the file',
            { reason, local: true }
          )
        }
      }

      openingPromise = beginFile(parsed, safe)
      await openingPromise
    }

    // Refuse what cannot fit, then take the partial: an earlier one to
    // resume if there is one we can trust to be ours, otherwise a fresh
    // one, exclusively.
    async function beginFile (parsed, safe) {
      resumable = caps.includes('resume') && parsed.size !== null
      const prior = resumable ? await reopenPartial(safe.outputPath, parsed.size) : null
      // A stream declares nothing to check. Its bytes are capped by
      // maxSize as they arrive, and a disk that fills fails the write.
      // A resumed file needs room only for what is still to come.
      if (checkSpace && parsed.size !== null) {
        try {
          await checkFreeSpace(path.dirname(safe.outputPath), parsed.size - (prior ? prior.length : 0))
        } catch (err) {
          if (prior) await prior.handle.close().catch(() => {})
          throw err
        }
      }
      progress = progressReporter(onProgress, parsed.size)
      if (prior) {
        // Opened and re-hashed, not yet adopted: no stream, and nothing
        // written or truncated, until the offer is finally answered. See
        // adopt.
        reusedPartial = true
        fileHandle = prior.handle
        partPath = prior.partPath
        resumeFrom = prior.length
        hash = prior.hash
        return
      }
      const opened = await openPartial(safe.outputPath)
      fileHandle = opened.handle
      partPath = opened.partPath
      hash = crypto.createHash('sha256')
      attachWriteStream(opened.stream)
    }

    /** @param {fs.WriteStream} stream */
    function attachWriteStream (stream) {
      writeStream = stream
      received = resumeFrom
      durable = resumeFrom
      writeStream.on('error', (err) => fail(err))
      writeStream.on('drain', onWriteDrain)
      progress.emit(received)
    }

    // The reopened partial becomes this transfer's, from `from`: the
    // offset the sender's PREFIX confirmed, or 0 when it did not match (or
    // the partial held less than one boundary). Truncated first, on the
    // descriptor that passed reopenPartial's checks, so a tail past the
    // confirmed prefix -- or a whole prefix that was not this file's --
    // can never sit behind the bytes about to be written.
    /** @param {number} from */
    async function adopt (from) {
      const handle = /** @type {fs.promises.FileHandle} */ (fileHandle)
      await handle.truncate(from)
      if (from === 0) hash = crypto.createHash('sha256')
      resumeFrom = from
      attachWriteStream(handle.createWriteStream({ start: from }))
    }

    // The offer's final answer: ACCEPT{from}, with everything that follows
    // from it. Synchronous for a fresh partial, so nothing changes about
    // when a fresh transfer's ACCEPT goes out.
    /** @param {number} from */
    function commit (from) {
      if (settled) return
      if (reusedPartial) {
        openingPromise = adopt(from)
        openingPromise.then(() => answerAccept(from), (err) => decline(err))
        return
      }
      answerAccept(from)
    }

    /** @param {number} from */
    function answerAccept (from) {
      if (settled) return
      accepted = true
      socket.write(channel.seal(TYPE_ACCEPT, acceptBody({ resumeFrom: from })))
      armStall(progressTimeout, 'sent nothing further')
      if (resumable && checkpointInterval) {
        checkpointTimer = setInterval(checkpoint, checkpointInterval)
        if (typeof checkpointTimer.unref === 'function') checkpointTimer.unref()
      }
      if (onManifest) onManifest(manifest, { resumeFrom: from })
      // An empty file, or a prefix that already holds every byte.
      if (received === manifest.size) finalize(manifest.sha256)
    }

    // Section 7.5: the sender's digest of its own first resumeFrom bytes,
    // against ours. A match adopts the prefix; anything else starts over,
    // silently -- a stale or planted partial is not the person's doing and
    // not an error to show them. Compared in constant time as a matter of
    // hygiene: the digest is not secret from the sender, but nothing about
    // the receiver's partial should leak through how long a check took.
    /** @param {Buffer} body */
    function onPrefix (body) {
      const theirs = Buffer.from(decodePrefix(body).sha256, 'hex')
      awaitingPrefix = false
      // Our work from here, not the sender's stall.
      armStall(0, '')
      const ours = /** @type {crypto.Hash} */ (hash).copy().digest()
      commit(crypto.timingSafeEqual(ours, theirs) ? resumeFrom : 0)
    }

    // Section 8.3: every CHECKPOINT_INTERVAL_MS of transfer, fsync what has
    // actually reached the file and report it. Skipped when nothing new
    // was written, so a stalled transfer does not fsync on a timer. The
    // offset is bytesWritten -- what the file descriptor has taken -- not
    // `received`, which also counts what the write stream still buffers.
    function checkpoint () {
      if (settled || checkpointing || !writeStream || !fileHandle) return
      const target = resumeFrom + writeStream.bytesWritten
      if (target <= durable) return
      checkpointing = true
      fileHandle.datasync().then(() => {
        checkpointing = false
        if (settled) return
        durable = target
        socket.write(channel.seal(TYPE_CHECKPOINT, checkpointBody({ offset: target })))
      }, () => {
        // The stream closed under the fsync (the transfer ended): there is
        // nothing left to report.
        checkpointing = false
      })
    }

    /**
     * @param {number} type
     * @param {Buffer} body
     */
    function handleMessage (type, body) {
      if (settled) return

      if (type === TYPE_CANCEL) {
        const peerReason = decodeCancelReason(body)
        throw new TransferError(
          'ERR_CANCELLED_PEER',
          peerReason ? `the sender cancelled: ${peerReason}` : 'the sender cancelled the transfer',
          { peerReason, bytes: received }
        )
      }

      if (!accepted) {
        if (awaitingPrefix && type === TYPE_PREFIX) {
          onPrefix(body)
          return
        }
        if (awaitingPrefix) {
          throw new TransferError(
            'ERR_PROTOCOL',
            `the sender sent ${TYPE_NAMES.get(type)} while a resume was being checked; only PREFIX or CANCEL is expected`
          )
        }
        if (offered) {
          throw new TransferError(
            'ERR_PROTOCOL',
            `the sender sent ${TYPE_NAMES.get(type)} before its offer was answered; only CANCEL may precede ACCEPT`
          )
        }
        if (type !== TYPE_MANIFEST) {
          throw new TransferError('ERR_PROTOCOL', `expected a MANIFEST frame first, got ${TYPE_NAMES.get(type)}`)
        }
        offered = true
        // Our decision, not the peer's stall: an accept screen may take a
        // person minutes, and timing the sender out for our own slowness
        // would blame the wrong side. The sender bounds this wait instead
        // (ACCEPT_TIMEOUT_MS).
        armStall(0, '')
        consider(body).then(
          () => {
            if (settled) return
            if (resumeFrom === 0) {
              commit(0)
              return
            }
            // A proposal, not yet a resume: the prefix is trusted only once
            // the sender's PREFIX has vouched for it. The state changes
            // BEFORE the write, so a PREFIX delivered inside socket.write
            // is judged as one.
            awaitingPrefix = true
            armStall(progressTimeout, 'never sent the PREFIX its resume needs')
            socket.write(channel.seal(TYPE_ACCEPT, acceptBody({ resumeFrom })))
          },
          (err) => decline(err)
        )
        return
      }

      if (type === TYPE_END) {
        // Only a stream ends this way. A declared file ends on its last
        // byte, and an END there would be a second, unverifiable claim
        // about a digest the manifest already made.
        if (manifest.size !== null) {
          throw new TransferError('ERR_PROTOCOL', 'the sender sent END for a transfer whose size it had declared')
        }
        finalize(decodeEnd(body).sha256)
        return
      }

      if (type !== TYPE_CHUNK) {
        throw new TransferError('ERR_PROTOCOL', `expected ${manifest.size === null ? 'a CHUNK or END' : 'a CHUNK'} frame, got ${TYPE_NAMES.get(type)}`)
      }

      // The manifest's blockSize is a claim about how the sender chunks,
      // and a claim nothing checks is not worth carrying. The channel
      // already bounds a frame; this bounds it to what was declared.
      if (body.length > manifest.blockSize) {
        throw new TransferError(
          'ERR_PROTOCOL',
          `the sender sent a ${body.length}-byte chunk, over the ${manifest.blockSize}-byte blockSize its manifest declared`
        )
      }

      // Refused, not truncated. A correct sender cannot over-read its own
      // manifest, so truncate-and-accept would hide a real bug -- and
      // would mean accepting an unbounded number of bytes from a peer that
      // proved it knows the code but is not thereby well-behaved.
      if (manifest.size !== null && received + body.length > manifest.size) {
        throw new TransferError(
          'ERR_SIZE_MISMATCH',
          `the sender sent more than the ${manifest.size} bytes its manifest declared`,
          { bytes: received + body.length, size: manifest.size }
        )
      }
      // A stream's only size check. The sender is not at fault -- it
      // promised no length -- so it is told, with CANCEL, rather than left
      // to report a mystery disconnect.
      const cap = maxSize === undefined ? DEFAULT_MAX_SIZE : maxSize
      if (manifest.size === null && cap !== null && received + body.length > cap) {
        const over = new TransferError(
          'ERR_SIZE_MISMATCH',
          `the stream passed the ${cap} byte limit this receiver was given`,
          { bytes: received + body.length, size: null, limit: cap }
        )
        fail(over, channel.seal(TYPE_CANCEL, cancelBody(reasonForPeer(over))))
        return
      }

      received += body.length
      hash.update(body)
      // THE RETURN VALUE IS THE POINT. Discarding it let a sender on a
      // fast link outrun a slow disk and queue the difference in memory,
      // unbounded -- the one direction of backpressure the code did not
      // implement. Pausing the socket is what turns "the disk is behind"
      // into "the network slows down" instead of "the process grows".
      if (!writeStream.write(body) && typeof socket.pause === 'function') socket.pause()
      progress.emit(received)
      armStall(progressTimeout, 'stopped sending')

      if (received === manifest.size) finalize(manifest.sha256)
    }

    // `expected` is the digest to verify against: the manifest's for a
    // declared file, END's for a stream. Section 4.3: a missing sha256 in
    // the manifest means "the digest arrives at the end", never "no check".
    /** @param {string} expected */
    function finalize (expected) {
      if (settled) return
      settled = true
      detach()

      // Every byte is in, so the sender is now waiting on RESULT and on
      // nothing else. Undo any backpressure pause from handleMessage -- its
      // resume went with detach() -- or the sender's end never arrives
      // and the caller's close wait runs out for no reason.
      if (typeof socket.resume === 'function') socket.resume()

      // Every outcome from here on is told to the sender before it is
      // reported locally, so the two sides cannot disagree about it.
      const refuse = (err) => {
        writeFlushed(socket, channel.seal(TYPE_RESULT, resultBody({ error: reasonForPeer(err) }))).then(() => reject(err))
      }

      const digest = hash.digest('hex')
      // Unconditional: this is the comparison the data path always
      // specified and nothing in the shipping code ever performed.
      if (digest !== expected) {
        // A prefix that was not ours no longer reaches here: the sender's
        // PREFIX caught it before a byte was sent (section 7.5). What is
        // left is a remainder that did not match -- a file that changed
        // on the sender mid-send, or a sender that lied in PREFIX -- and
        // this comparison stays unconditional for exactly that. Discarding
        // below is what makes the retry start clean.
        const mismatch = new TransferError(
          'ERR_HASH_MISMATCH',
          `the received file does not match the ${manifest.size === null ? 'digest the stream ended with' : "manifest's digest"} (expected ${expected}, got ${digest})` +
            (resumeFrom > 0 ? `; it was resumed from byte ${resumeFrom}, and that partial has been discarded, so a retry starts from the beginning` : ''),
          { expected, actual: digest, bytes: received, resumedFrom: resumeFrom }
        )
        discardPartial().then(() => refuse(mismatch), (err) => refuse(err))
        return
      }

      writeStream.end(() => {
        // Link-then-unlink rather than rename, so a file we did not
        // create is never destroyed. See `publish`.
        publish(partPath, outputPath, { replace }).then(
          (finalPath) => {
            progress.final()
            // After the publish, not after the digest: {ok} tells the
            // sender the file is on disk under its name, and a publish
            // that fails must not have been confirmed first.
            writeFlushed(socket, channel.seal(TYPE_RESULT, resultBody({ ok: true, sha256: digest }))).then(() => resolve({
              name: path.basename(finalPath),
              declaredName,
              size: received,
              sha256: digest,
              path: finalPath,
              resumedFrom: resumeFrom
            }))
          },
          (err) => discardPartial().then(() => refuse(err), () => refuse(err))
        )
      })
    }

    // Called by the channel once per frame that opened, in order. A frame
    // that did not open never reaches here: channel.push throws, and
    // onData turns that into fail().
    /**
     * @param {number} type
     * @param {Buffer} body
     */
    function onMessage (type, body) {
      if (settled) return
      handleMessage(type, body)
    }

    function onData (chunk) {
      try {
        channel.push(chunk)
      } catch (err) {
        fail(err)
      }
    }

    socket.on('data', onData)
    socket.on('error', onSocketError)
    socket.on('end', onClosed)
    socket.on('close', onClosed)
    if (signal) signal.addEventListener('abort', onAbort, { once: true })

    armStall(manifestTimeout, 'never sent a manifest')

    // Feed the handshake's leftover bytes through the same path as live
    // data, before resuming, so frame order is preserved.
    if (pending && pending.length > 0) onData(pending)
    // acceptOnce paused the socket to hold the gap between resolving and
    // this listener being attached. Harmless when it never paused (the
    // plain TCP path passes no `pending` and does not pause). The socket
    // stays flowing while an offer is considered, so a CANCEL sent during
    // it is heard; nothing else may arrive then.
    if (typeof socket.resume === 'function') socket.resume()
  })
}

module.exports = {
  sendFile,
  sendStream,
  receiveFile,
  hashFile,
  safeOutputName,
  validateManifest,
  DEFAULT_CHUNK_SIZE,
  MAX_CHUNK_SIZE,
  DEFAULT_MAX_SIZE,
  MANIFEST_TIMEOUT_MS,
  PROGRESS_TIMEOUT_MS,
  ACCEPT_TIMEOUT_MS,
  RESULT_TIMEOUT_MS,
  CHECKPOINT_INTERVAL_MS,
  MANIFEST_VERSION
}
