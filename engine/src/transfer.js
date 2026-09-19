'use strict'

const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const { FrameDecoder, DEFAULT_MAX_FRAME_SIZE } = require('./frame')
const { TransferError, abortError } = require('./errors')
const { displayName, safeWriteName } = require('./names')
const {
  encodeMessage,
  decodeMessage,
  encodeCancel,
  decodeCancelReason,
  TAG_SIZE,
  TYPE_MANIFEST,
  TYPE_CHUNK,
  TYPE_CANCEL,
  TYPE_NAMES
} = require('./message')

// 64 KB balances syscall/frame overhead against memory use; revisit once
// resume (W11) and large-file testing land.
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
const MAX_CHUNK_SIZE = DEFAULT_MAX_FRAME_SIZE - TAG_SIZE

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
// `socket` is any writable+readable duplex stream (net.Socket for the loopback milestone;
// a Hyperswarm NoiseSecretStream from the Hyperswarm work onward -- not a
// Protomux channel, which W10 ruled out; see PROTOCOL.md section 8.2).
//
// HONEST LIMIT ON `onProgress` HERE. The sender's `bytes` counts what has
// been handed to the transport, not what the receiver has stored. The two
// diverge by whatever is in flight, so a sender's bar can legitimately
// read 100% while the receiver is still at 90%, and a transfer that dies
// in that gap dies after the sender looked finished. Nothing in the
// protocol can close that today: acknowledgement by index is resume (W11). Do
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

    // The sender now READS, which it never did before the failure-reporting work: a CANCEL
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
  if (cap !== null && manifest.size > cap) {
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
 * than refused. Resume (W11) does not lose anything here: a `.part`
 * prefix cannot be trusted after a restart anyway, which is why W9 makes
 * resume re-hash the prefix instead of assuming the file on disk is ours.
 *
 * @param {string} outputPath
 * @returns {Promise<{ stream: fs.WriteStream, partPath: string }>}
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
    return { stream: handle.createWriteStream(), partPath }
  }
  throw new TransferError(
    'ERR_EXISTS',
    `cannot open a partial file for ${JSON.stringify(path.basename(outputPath))}: every candidate .part name is taken`,
    { outputPath }
  )
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
/**
 * @param {any} socket
 * @param {string} outputDir
 * @param {{
 *   onManifest?: (manifest: any) => void,
 *   pending?: Buffer | null,
 *   signal?: AbortSignal,
 *   onProgress?: (p: { bytes: number, total: number }) => void,
 *   maxSize?: number | null,
 *   replace?: boolean,
 *   platform?: NodeJS.Platform | string,
 *   manifestTimeout?: number,
 *   progressTimeout?: number,
 *   checkSpace?: boolean
 * }} [options]
 *   `pending` is any payload the readiness handshake read off the socket
 *   before handing it over -- see acceptOnce in ./swarm.js, which pauses
 *   the socket and returns leftover bytes rather than swallowing them.
 *   `replace: true` opts back in to overwriting an existing file.
 *   Timeouts are in ms; 0 disables one.
 * @returns {Promise<{ name: string, declaredName: string, size: number, sha256: string, path: string }>}
 */
function receiveFile (socket, outputDir, {
  onManifest,
  pending,
  signal,
  onProgress,
  maxSize,
  replace = false,
  platform,
  manifestTimeout = MANIFEST_TIMEOUT_MS,
  progressTimeout = PROGRESS_TIMEOUT_MS,
  checkSpace = true
} = {}) {
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
    // True from the moment a manifest is accepted until the file is open.
    // Opening is asynchronous (free space, then an exclusive create) and
    // the frame decoder is not, so frames that arrive -- or are already
    // sitting in the decoder's buffer -- during that window are held here
    // rather than hitting a null writeStream.
    let opening = false
    /** @type {Buffer[]} */
    const deferred = []
    /** @type {{ emit: (n: number) => void, final: () => void }} */
    let progress = { emit: () => {}, final: () => {} }
    /** @type {NodeJS.Timeout | null} */
    let stallTimer = null

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
        ))
      }, ms)
      // A stall timer must never be the reason the process stays alive.
      if (typeof stallTimer.unref === 'function') stallTimer.unref()
    }

    const detach = () => {
      if (stallTimer) clearTimeout(stallTimer)
      stallTimer = null
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

    // Deletes the partial. Resume (W11) flips this to keep-by-default --
    // but a hash mismatch will delete even then, because bytes known to
    // be wrong must never be left looking resumable.
    const discardPartial = async () => {
      if (!partPath) return
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

    // The infinite hang this closes: the only listeners used to be 'data'
    // and 'error', so a sender that vanished mid-transfer -- the routine
    // outcome on a flaky punch -- left this promise pending forever. No
    // error, no timeout, no exit. 'close' is settled-guarded because it
    // also fires on the normal path, after we have already resolved.
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

    // Paired with the pause in handleFrame: the receiver's disk is now
    // allowed to push back on the network, which is the same contract the
    // sender has honoured since the Hyperswarm work and the receiver never did.
    function onWriteDrain () {
      if (settled) return
      if (typeof socket.resume === 'function') socket.resume()
    }

    // Everything that happens once a manifest has been accepted but
    // before a byte may be written: refuse what cannot fit, then take the
    // partial exclusively. Both are async, hence the deferral dance.
    async function beginFile (parsed, safe) {
      if (checkSpace) await checkFreeSpace(path.dirname(safe.outputPath), parsed.size)
      const opened = await openPartial(safe.outputPath)
      writeStream = opened.stream
      partPath = opened.partPath
      writeStream.on('error', (err) => fail(err))
      writeStream.on('drain', onWriteDrain)
      hash = crypto.createHash('sha256')
      progress = progressReporter(onProgress, parsed.size)
    }

    function handleFrame (payload) {
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
        const safe = safeOutputName(outputDir, parsed.name, { platform })

        manifest = parsed
        declaredName = parsed.name
        name = safe.name
        outputPath = safe.outputPath

        // Hold the stream while the file is opened, and hold any frames
        // the decoder has already parsed out of this same chunk.
        opening = true
        if (typeof socket.pause === 'function') socket.pause()
        armStall(progressTimeout, 'sent nothing further')

        beginFile(parsed, safe).then(
          () => {
            if (settled) return
            opening = false
            if (onManifest) onManifest(manifest)
            try {
              while (deferred.length > 0 && !settled) handleFrame(deferred.shift())
            } catch (err) {
              fail(err)
              return
            }
            if (settled) return
            if (manifest.size === 0) {
              finalize()
              return
            }
            if (typeof socket.resume === 'function') socket.resume()
          },
          (err) => fail(err)
        )
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
      // THE RETURN VALUE IS THE POINT. Discarding it let a sender on a
      // fast link outrun a slow disk and queue the difference in memory,
      // unbounded -- the one direction of backpressure the code did not
      // implement. Pausing the socket is what turns "the disk is behind"
      // into "the network slows down" instead of "the process grows".
      if (!writeStream.write(body) && typeof socket.pause === 'function') socket.pause()
      progress.emit(received)
      armStall(progressTimeout, 'stopped sending')

      if (received === manifest.size) finalize()
    }

    function finalize () {
      if (settled) return
      settled = true
      detach()

      const digest = hash.digest('hex')
      // Unconditional: this is the comparison the data path always
      // specified and nothing in the shipping code ever performed.
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
        // Link-then-unlink rather than rename, so a file we did not
        // create is never destroyed. See `publish`.
        publish(partPath, outputPath, { replace }).then(
          (finalPath) => {
            progress.final()
            resolve({
              name: path.basename(finalPath),
              declaredName,
              size: manifest.size,
              sha256: digest,
              path: finalPath
            })
          },
          (err) => discardPartial().then(() => reject(err), () => reject(err))
        )
      })
    }

    const decoder = new FrameDecoder((payload) => {
      if (settled) return
      if (opening) {
        // Copied, not referenced: the decoder hands out subarrays of a
        // buffer it goes on to replace, and these outlive this tick.
        deferred.push(Buffer.from(payload))
        return
      }
      handleFrame(payload)
    })

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

    armStall(manifestTimeout, 'never sent a manifest')

    // Feed the handshake's leftover bytes through the same path as live
    // data, before resuming, so frame order is preserved.
    if (pending && pending.length > 0) onData(pending)
    // acceptOnce paused the socket to hold the gap between resolving and
    // this listener being attached. Harmless when it never paused (the
    // plain TCP path passes no `pending` and does not pause). Skipped
    // while a file is being opened -- beginFile resumes instead.
    if (!opening && typeof socket.resume === 'function') socket.resume()
  })
}

module.exports = {
  sendFile,
  receiveFile,
  hashFile,
  safeOutputName,
  validateManifest,
  DEFAULT_CHUNK_SIZE,
  MAX_CHUNK_SIZE,
  DEFAULT_MAX_SIZE,
  MANIFEST_TIMEOUT_MS,
  PROGRESS_TIMEOUT_MS
}
