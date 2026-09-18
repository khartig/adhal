'use strict'

const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const { FrameDecoder } = require('./frame')
const { TransferError, abortError } = require('./errors')
const {
  encodeMessage,
  decodeMessage,
  encodeCancel,
  decodeCancelReason,
  TYPE_MANIFEST,
  TYPE_CHUNK,
  TYPE_CANCEL,
  TYPE_NAMES
} = require('./message')

// 64 KB balances syscall/frame overhead against memory use; revisit once
// item 6 (resume) and large-file testing (doc section 9, item 6) land.
const DEFAULT_CHUNK_SIZE = 64 * 1024

// Upper bound on a manifest's declared chunkSize. Not a tuning knob: it
// exists so a peer cannot declare something absurd and have us believe it.
// The framing layer's own bound (frame.js) is what actually protects
// memory; this just keeps the manifest internally plausible.
const MAX_CHUNK_SIZE = 1024 * 1024

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

function hashFile (filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256')
    const stream = fs.createReadStream(filePath)
    stream.on('data', (chunk) => hash.update(chunk))
    stream.on('end', () => resolve(hash.digest('hex')))
    stream.on('error', reject)
  })
}

// Writes a CANCEL and waits for it to flush, capped. Never rejects: we are
// already on a failure path, and a cancel that could not be delivered
// still has to cancel locally.
/**
 * @param {any} socket
 * @param {string} reason
 * @returns {Promise<void>}
 */
function writeCancel (socket, reason) {
  return new Promise((resolve) => {
    let done = false
    const finish = () => {
      if (done) return
      done = true
      clearTimeout(timer)
      resolve()
    }
    const timer = setTimeout(finish, CANCEL_FLUSH_MS)
    // Unref so a cancel on an already-dead socket cannot hold the process
    // open for the length of the window.
    if (typeof timer.unref === 'function') timer.unref()
    try {
      socket.write(encodeCancel(reason), finish)
    } catch {
      finish()
    }
  })
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
/**
 * @param {((p: { bytes: number, total: number }) => void) | undefined} onProgress
 * @param {number} total
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
  return { emit, final: () => emit(total) }
}

// Sends one manifest frame (JSON) followed by the file as chunk frames.
// `socket` is any writable+readable duplex stream (net.Socket for item 1;
// a Hyperswarm/Protomux channel from item 2 onward).
//
// HONEST LIMIT ON `onProgress` HERE. The sender's `bytes` counts what has
// been handed to the transport, not what the receiver has stored. The two
// diverge by whatever is in flight, so a sender's bar can legitimately
// read 100% while the receiver is still at 90%, and a transfer that dies
// in that gap dies after the sender looked finished. Nothing in the
// protocol can close that today: acknowledgement by index is item 6. Do
// not present this number as delivery confirmation.
/**
 * @param {any} socket
 * @param {string} filePath
 * @param {{
 *   chunkSize?: number,
 *   signal?: AbortSignal,
 *   onProgress?: (p: { bytes: number, total: number }) => void,
 *   pending?: Buffer | null
 * }} [options]
 *   `pending` is any payload the readiness handshake read off the socket
 *   before handing it over -- see connectOnce in ./swarm.js.
 */
async function sendFile (socket, filePath, { chunkSize = DEFAULT_CHUNK_SIZE, signal, onProgress, pending } = {}) {
  // Before any filesystem work, so an already-cancelled transfer costs
  // nothing and cannot half-open a file.
  if (signal && signal.aborted) throw abortError(0, signal.reason)

  const stat = await fs.promises.stat(filePath)
  const size = stat.size
  const sha256 = await hashFile(filePath)

  const manifest = {
    v: 1,
    type: 'manifest',
    name: path.basename(filePath),
    size,
    chunkSize,
    sha256
  }

  if (signal && signal.aborted) throw abortError(0, signal.reason)

  socket.write(encodeMessage(TYPE_MANIFEST, Buffer.from(JSON.stringify(manifest), 'utf8')))

  const progress = progressReporter(onProgress, size)
  let sent = 0

  // A raw TCP net.Socket (item 1) tolerates ignoring write()'s backpressure
  // signal because the OS gives it deep send buffers. Hyperswarm's
  // encrypted duplex (item 2+) does not -- blasting writes without
  // pausing on a false return / waiting for 'drain' overwhelms it and the
  // connection resets partway through a multi-MB file. Pause/resume the
  // read stream to respect it.
  await new Promise((resolve, reject) => {
    let settled = false
    /** @type {(() => void) | null} */
    let onDrain = null

    // stat, hashFile and createReadStream are three separate reads of a
    // file that nothing stops changing underneath us. Capping the read at
    // the size we hashed and declared means a file that GREW mid-send is
    // sent as the manifest describes rather than overrunning it; a file
    // that SHRANK is caught by the assertion after 'end'. Before this, a
    // shrunk file resolved *successfully* having sent short, and the
    // receiver was left waiting for bytes that were never coming.
    const readStream = size > 0
      ? fs.createReadStream(filePath, { highWaterMark: chunkSize, end: size - 1 })
      : null

    const cleanup = () => {
      socket.removeListener('error', onError)
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

    function onAbort () {
      if (settled) return
      // Written before we reject, and given a window to flush, because the
      // caller tears the socket down as soon as it sees our rejection.
      // Teardown stays the caller's job -- this function does not own the
      // socket it was handed.
      const bytes = sent
      writeCancel(socket, (signal && typeof signal.reason === 'string') ? signal.reason : 'cancelled by sender')
        .then(() => fail(abortError(bytes, signal && signal.reason)))
    }

    // The sender now READS, which it never did before item 5: a CANCEL
    // from the receiver has to be distinguishable from the socket dying,
    // and that is the whole point of the item. See ./swarm.js connectOnce,
    // which hands back `pending` for exactly this reason.
    const inbound = new FrameDecoder((payload) => {
      if (settled) return
      const { type, body } = decodeMessage(payload)
      if (type !== TYPE_CANCEL) {
        throw new TransferError(
          'ERR_PROTOCOL',
          `receiver sent ${TYPE_NAMES.get(type)} during a transfer; only CANCEL is expected`
        )
      }
      const peerReason = decodeCancelReason(body)
      throw new TransferError(
        'ERR_CANCELLED_PEER',
        peerReason ? `the receiver cancelled: ${peerReason}` : 'the receiver cancelled the transfer',
        { peerReason, bytes: sent }
      )
    })

    function onData (chunk) {
      try {
        inbound.push(chunk)
      } catch (err) {
        fail(err)
      }
    }

    socket.on('error', onError)
    socket.on('data', onData)
    if (signal) signal.addEventListener('abort', onAbort, { once: true })
    if (pending && pending.length > 0) onData(pending)

    if (!readStream) {
      progress.final()
      done()
      return
    }

    readStream.on('data', (/** @type {Buffer} */ chunk) => {
      if (settled) return
      const ok = socket.write(encodeMessage(TYPE_CHUNK, chunk))
      sent += chunk.length
      progress.emit(sent)
      if (!ok) {
        readStream.pause()
        onDrain = () => {
          onDrain = null
          readStream.resume()
        }
        socket.once('drain', onDrain)
      }
    })
    readStream.on('end', () => {
      if (settled) return
      if (sent !== size) {
        fail(new TransferError(
          'ERR_SIZE_MISMATCH',
          `read ${sent} bytes but the manifest declared ${size}: the file changed while it was being sent`,
          { bytes: sent, size }
        ))
        return
      }
      progress.final()
      done()
    })
    readStream.on('error', fail)
  })

  return { name: manifest.name, size, sha256 }
}

// --- manifest validation -------------------------------------------------

// Every field a peer sends is untrusted input, and this is the first thing
// item 5 checks because the manifest is the one message that decides what
// happens on our filesystem.
/**
 * @param {any} manifest
 * @param {number | undefined} maxSize
 */
function validateManifest (manifest, maxSize) {
  const invalid = (field, detail) => new TransferError(
    'ERR_MANIFEST_INVALID',
    `manifest field ${field} is invalid: ${detail}`,
    { field }
  )

  if (manifest === null || typeof manifest !== 'object') throw invalid('(root)', 'not an object')
  if (manifest.type !== 'manifest') throw invalid('type', `expected "manifest", got ${JSON.stringify(manifest.type)}`)
  // A version that is present and wrong is a peer we cannot safely parse;
  // saying so beats guessing at its layout.
  if (manifest.v !== 1) throw invalid('v', `unsupported manifest version ${JSON.stringify(manifest.v)} (this build speaks v1)`)
  if (typeof manifest.name !== 'string') throw invalid('name', 'not a string')
  if (!Number.isSafeInteger(manifest.size) || manifest.size < 0) {
    throw invalid('size', `expected a non-negative safe integer, got ${JSON.stringify(manifest.size)}`)
  }
  if (!Number.isSafeInteger(manifest.chunkSize) || manifest.chunkSize <= 0 || manifest.chunkSize > MAX_CHUNK_SIZE) {
    throw invalid('chunkSize', `expected 1..${MAX_CHUNK_SIZE}, got ${JSON.stringify(manifest.chunkSize)}`)
  }
  if (typeof manifest.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(manifest.sha256)) {
    throw invalid('sha256', 'not a lowercase 64-character hex digest')
  }
  // Optional, and off by default: the engine enforces no size cap of its
  // own. The 50 MB v1 limit is product policy (plan section 4) and belongs
  // at the accept screen, where a human can see it and decide.
  if (maxSize !== undefined && manifest.size > maxSize) {
    throw invalid('size', `${manifest.size} bytes exceeds the ${maxSize} byte limit this receiver was given`)
  }
}

// Names Windows treats as devices no matter what directory they are in, so
// `aux.txt` is not an ordinary file there. Windows also strips trailing
// dots and spaces before resolving, which makes `CON.` and `CON ` the same
// thing as `CON` -- so the check is done against the stripped stem, or the
// evasion is free.
const WINDOWS_RESERVED = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/i

// Turns a manifest's declared name into a name we are willing to write,
// or refuses. Layered deliberately: shape first, then a resolved-path
// assertion, because neither alone is convincing.
//
// The shape checks reject the obvious attacks legibly, and reject them the
// same way on every platform -- `path.basename('..\\..\\x')` is 'x' on
// Windows but the whole string on POSIX, so a single basename() call
// silently means different things depending on where it runs. The resolved
// -path assertion then backstops the shape checks against anything they
// did not anticipate, which is the failure mode that matters: this
// function being wrong writes a file wherever a peer points it.
//
// Item 4 stopped a stranger from reaching the receiver at all. It did
// nothing about a peer that knows the code and aims at ~/.bashrc, and
// `path.join(outputDir, manifest.name)` aimed wherever it was told.
/**
 * @param {string} outputDir
 * @param {string} declaredName
 * @returns {{ name: string, outputPath: string }}
 */
function safeOutputName (outputDir, declaredName) {
  const unsafe = (detail) => new TransferError(
    'ERR_UNSAFE_NAME',
    `refusing the peer's filename ${JSON.stringify(declaredName)}: ${detail}`,
    { declaredName }
  )

  if (declaredName.length === 0) throw unsafe('it is empty')
  if (Buffer.byteLength(declaredName, 'utf8') > 255) throw unsafe('it is longer than 255 bytes')
  if (declaredName.includes(' ')) throw unsafe('it contains a NUL byte')
  if (declaredName.includes('/') || declaredName.includes('\\')) throw unsafe('it contains a path separator')
  if (declaredName === '.' || declaredName === '..') throw unsafe('it is a directory reference')

  // A leading dot is NOT stripped. `.bashrc` as a *filename inside the
  // output directory* is a legitimate thing to send, and mangling it would
  // be the kind of helpfulness that makes a tool untrustworthy. What makes
  // `../../.bashrc` dangerous is the traversal, which is already refused
  // above, not the dot.
  let name = declaredName

  // Reserved device names are renamed rather than refused. Windows ships
  // first, and telling someone their file cannot be received because it is
  // called `aux.txt` is hostile when prefixing one character makes it
  // work. The caller is told both names, so nothing is hidden: `name` is
  // what was written, `declaredName` is what was asked for.
  const stem = name.replace(/[. ]+$/, '').split('.')[0]
  if (WINDOWS_RESERVED.test(stem)) name = `_${name}`

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

// Reads manifest + chunk frames off `socket` and writes the file into
// `outputDir`, verifying it before it is visible under its real name.
// This is step 6 of the doc's v1 data path -- "receiver verifies the
// full-file hash; atomic rename into Downloads" -- which was written down
// in item 1 and only implemented here.
//
// Until item 5 this function computed a digest, returned it, and compared
// it to nothing. Only engine/scratch-trials.js ever did the comparison, so
// the measurement harness verified integrity and neither CLI did: a
// corrupted file was written into the output directory under its final
// name and reported as a success.
//
// FILENAME COLLISIONS ARE DELIBERATELY NOT HANDLED. fs.rename overwrites
// an existing destination, exactly as createWriteStream did before. That
// is a decision, not an oversight: overwrite / suffix / prompt is an
// accept-screen question, and plan section 6 puts the accept screen in
// Phase B. Deciding it here would mean deciding it twice.
/**
 * @param {any} socket
 * @param {string} outputDir
 * @param {{
 *   onManifest?: (manifest: any) => void,
 *   pending?: Buffer | null,
 *   signal?: AbortSignal,
 *   onProgress?: (p: { bytes: number, total: number }) => void,
 *   maxSize?: number
 * }} [options]
 *   `pending` is any payload the readiness handshake read off the socket
 *   before handing it over -- see acceptOnce in ./swarm.js, which pauses
 *   the socket and returns leftover bytes rather than swallowing them.
 * @returns {Promise<{ name: string, declaredName: string, size: number, sha256: string, path: string }>}
 */
function receiveFile (socket, outputDir, { onManifest, pending, signal, onProgress, maxSize } = {}) {
  return new Promise((resolve, reject) => {
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
    /** @type {{ emit: (n: number) => void, final: () => void }} */
    let progress = { emit: () => {}, final: () => {} }

    if (signal && signal.aborted) {
      reject(abortError(0, signal.reason))
      return
    }

    const detach = () => {
      socket.removeListener('data', onData)
      socket.removeListener('error', onSocketError)
      socket.removeListener('end', onClosed)
      socket.removeListener('close', onClosed)
      if (signal) signal.removeEventListener('abort', onAbort)
    }

    // Deletes the partial. Item 6 flips this to keep-by-default once an
    // offset sidecar makes a partial resumable -- but a hash mismatch will
    // delete even then, because bytes known to be wrong must never be left
    // looking resumable.
    const discardPartial = async () => {
      if (!partPath) return
      // Wait for the stream to be genuinely closed before unlinking.
      // createWriteStream opens the file asynchronously, so a failure that
      // arrives in the same tick as the manifest -- an over-read on the
      // very first chunk, say -- can otherwise unlink before the open has
      // even happened, and the file reappears a moment later. Node defers
      // a WriteStream's destroy until any pending open settles, so 'close'
      // is the point after which the path is stable.
      if (writeStream && !writeStream.closed) {
        await new Promise((done) => {
          writeStream.once('close', done)
          writeStream.destroy()
        })
      }
      await fs.promises.rm(partPath, { force: true }).catch(() => {})
    }

    // First settle wins, on both sides, so a simultaneous cancel has each
    // end reporting its own rather than the two logs contradicting.
    function fail (err) {
      if (settled) return
      settled = true
      detach()
      discardPartial().then(() => reject(err), () => reject(err))
    }

    function onSocketError (err) {
      fail(err)
    }

    // The infinite hang this closes: before item 5 the only listeners were
    // 'data' and 'error', so a sender that vanished mid-transfer -- the
    // routine outcome on a flaky punch -- left this promise pending
    // forever. No error, no timeout, no exit; the receiver simply sat
    // there. 'close' is settled-guarded because it also fires on the
    // normal path, after we have already resolved.
    function onClosed () {
      if (settled) return
      fail(new TransferError(
        'ERR_CONNECTION',
        manifest
          ? `the sender disconnected after ${received} of ${manifest.size} bytes`
          : 'the sender disconnected before sending a manifest',
        { bytes: received, size: manifest ? manifest.size : null }
      ))
    }

    function onAbort () {
      if (settled) return
      const bytes = received
      writeCancel(socket, (signal && typeof signal.reason === 'string') ? signal.reason : 'cancelled by receiver')
        .then(() => fail(abortError(bytes, signal && signal.reason)))
    }

    const decoder = new FrameDecoder((payload) => {
      if (settled) return

      const { type, body } = decodeMessage(payload)

      if (type === TYPE_CANCEL) {
        const peerReason = decodeCancelReason(body)
        throw new TransferError(
          'ERR_CANCELLED_PEER',
          peerReason ? `the sender cancelled: ${peerReason}` : 'the sender cancelled the transfer',
          { peerReason, bytes: received }
        )
      }

      if (!manifest) {
        if (type !== TYPE_MANIFEST) {
          throw new TransferError('ERR_PROTOCOL', `expected a MANIFEST frame first, got ${TYPE_NAMES.get(type)}`)
        }
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
        const safe = safeOutputName(outputDir, parsed.name)

        manifest = parsed
        declaredName = parsed.name
        name = safe.name
        outputPath = safe.outputPath
        // `.part` is predictable rather than random on purpose: item 6 has
        // to find this file again to resume it.
        partPath = `${outputPath}.part`

        writeStream = fs.createWriteStream(partPath)
        writeStream.on('error', (err) => fail(err))
        hash = crypto.createHash('sha256')
        progress = progressReporter(onProgress, manifest.size)

        if (onManifest) onManifest(manifest)
        if (manifest.size === 0) finalize()
        return
      }

      if (type !== TYPE_CHUNK) {
        throw new TransferError('ERR_PROTOCOL', `expected a CHUNK frame, got ${TYPE_NAMES.get(type)}`)
      }

      // Refused, not truncated. A correct sender cannot over-read its own
      // manifest, so truncate-and-accept would hide a real bug -- and
      // would mean accepting an unbounded number of bytes from a peer that
      // proved it knows the code but is not thereby well-behaved.
      if (received + body.length > manifest.size) {
        throw new TransferError(
          'ERR_SIZE_MISMATCH',
          `the sender sent more than the ${manifest.size} bytes its manifest declared`,
          { bytes: received + body.length, size: manifest.size }
        )
      }

      received += body.length
      hash.update(body)
      writeStream.write(body)
      progress.emit(received)

      if (received === manifest.size) finalize()
    })

    function finalize () {
      if (settled) return
      settled = true
      detach()

      const digest = hash.digest('hex')
      // Unconditional, and the reason the whole item exists: this is the
      // comparison the data path always specified and nothing in the
      // shipping code ever performed.
      if (digest !== manifest.sha256) {
        discardPartial().then(
          () => reject(new TransferError(
            'ERR_HASH_MISMATCH',
            `the received file does not match the manifest's digest (expected ${manifest.sha256}, got ${digest})`,
            { expected: manifest.sha256, actual: digest, bytes: received }
          )),
          (err) => reject(err)
        )
        return
      }

      writeStream.end(() => {
        // Same directory, so the rename is atomic: the file never exists
        // under its real name in a half-written or unverified state.
        fs.promises.rename(partPath, outputPath).then(
          () => {
            progress.final()
            resolve({ name, declaredName, size: manifest.size, sha256: digest, path: outputPath })
          },
          (err) => discardPartial().then(() => reject(err), () => reject(err))
        )
      })
    }

    function onData (chunk) {
      try {
        decoder.push(chunk)
      } catch (err) {
        fail(err)
      }
    }

    socket.on('data', onData)
    socket.on('error', onSocketError)
    socket.on('end', onClosed)
    socket.on('close', onClosed)
    if (signal) signal.addEventListener('abort', onAbort, { once: true })

    // Feed the handshake's leftover bytes through the same path as live
    // data, before resuming, so frame order is preserved.
    if (pending && pending.length > 0) onData(pending)
    // acceptOnce paused the socket to hold the gap between resolving and
    // this listener being attached. Harmless when it never paused (item
    // 1's plain TCP path passes no `pending` and does not pause).
    if (typeof socket.resume === 'function') socket.resume()
  })
}

module.exports = {
  sendFile,
  receiveFile,
  hashFile,
  safeOutputName,
  validateManifest,
  DEFAULT_CHUNK_SIZE,
  MAX_CHUNK_SIZE
}
