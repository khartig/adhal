#!/usr/bin/env node
'use strict'

// The Hyperswarm work sender half. Usage: swarm-send.js <code> <filePath>
//
// A filePath of '-' streams stdin instead (PROTOCOL.md section 4.3), so
// `tar c dir | swarm-send.js <code> - --name=dir.tar` works: the receiver
// is offered a file of unknown length and verifies it against the digest
// that arrives when stdin ends. --name is what it is offered under
// (default "stdin"), since a pipe has no name of its own.
//
// The code may be five words (the drop code) in any casing or separator
// style, or the QR payload pasted verbatim -- 'ADHAL2:ACID-ACORN-...' --
// since that decodes to the same thing a scanner would hand a UI. See
// engine/src/resolve-code.js for how that is distinguished from an opaque secret.
//
// See swarm-receive.js for the ADHAL_BOOTSTRAP override.

const { createSwarm, connectOnce, sendFile, sendStream, resolveCode, displayName } = require('@ad-hal/engine')

const { createProgressReporter } = require('./progress')
const { installCancelHandler } = require('./signals')
const { describeError, isCancellation } = require('./report')
const { readCode } = require('./read-code')

function parseBootstrap () {
  const raw = process.env.ADHAL_BOOTSTRAP
  return raw ? JSON.parse(raw) : undefined
}

// See swarm-receive.js for why the public-DHT default is this generous.
function joinTimeout () {
  const raw = process.env.ADHAL_JOIN_TIMEOUT
  if (!raw) return 120000
  const parsed = Number(raw)
  if (!Number.isFinite(parsed) || parsed < 0) {
    throw new TypeError(`ADHAL_JOIN_TIMEOUT must be a non-negative number, got ${raw}`)
  }
  return parsed
}

// ADHAL_REFRESH_INTERVAL overrides how often we re-run our own DHT
// announce/lookup, in ms (0 disables it, leaving Hyperswarm's internal
// 10-minute schedule). See engine/src/swarm.js REFRESH_INTERVAL: the 4s
// default is validated only for two peers on one machine, and on a
// cross-ISP path a continuous re-announce is a suspect for churning
// holepunch relay state.
function refreshInterval () {
  const raw = process.env.ADHAL_REFRESH_INTERVAL
  if (raw === undefined) return undefined
  const parsed = Number(raw)
  if (!Number.isFinite(parsed) || parsed < 0) {
    throw new TypeError(`ADHAL_REFRESH_INTERVAL must be a non-negative number, got ${raw}`)
  }
  return parsed
}

async function main () {
  const argv = process.argv.slice(2)
  // `--unsafe-opaque` opts in to non-word codes; see resolveCode. Pulled
  // out before the positionals so it can appear anywhere.
  const allowOpaque = argv.includes('--unsafe-opaque')
  const positional = argv.filter((a) => !a.startsWith('--') || a === '--code-stdin')
  const [codeArg, filePathArg] = positional
  const nameFlag = argv.find((a) => a.startsWith('--name='))
  const streamName = nameFlag ? nameFlag.slice('--name='.length) : 'stdin'

  if (!codeArg || !filePathArg) {
    console.error('Usage: swarm-send.js <code> <filePath>')
    console.error('       swarm-send.js - <filePath>            read the code from stdin')
    console.error('       swarm-send.js <code> - [--name=<name>]  stream stdin as the file')
    console.error('       swarm-send.js <code> <filePath> --unsafe-opaque')
    process.exitCode = 1
    return
  }
  const streaming = filePathArg === '-'
  // One stdin, two possible uses. Reading the code line first would take
  // it out of the data, and the receiver would verify a stream that
  // silently began at the second line.
  if (streaming && codeArg === '-') {
    console.error('[swarm-send] stdin can carry the code or the data, not both: pass the code as an argument when streaming')
    process.exitCode = 1
    return
  }
  // Typing a file into the terminal by hand is never what was meant, and
  // the transfer would sit waiting for an EOF nobody knows to send.
  if (streaming && process.stdin.isTTY) {
    console.error('[swarm-send] refusing to stream from a terminal: pipe the data in, e.g. tar c dir | swarm-send.js <code> -')
    process.exitCode = 1
    return
  }

  let codeInput
  try {
    codeInput = await readCode({ argvCode: codeArg, label: 'swarm-send' })
  } catch (err) {
    console.error(`[swarm-send] ${err.message}`)
    process.exitCode = 1
    return
  }

  // A mistyped word is reported here, before any network work, rather than
  // surfacing 120 seconds later as a peer-discovery timeout.
  let topic, code, nameplate, secret
  try {
    ({ topic, code, nameplate, secret } = resolveCode(codeInput, { allowOpaque: allowOpaque || undefined }))
  } catch (err) {
    console.error(`[swarm-send] ${err.message}`)
    process.exitCode = 1
    return
  }
  // Echo only the NAMEPLATE when the input needed normalizing, so a code
  // pasted as a QR payload or with odd separators visibly resolved to the
  // same rendezvous the other device is showing.
  //
  // THE SECRET IS NOT PRINTED, and that is the whole point of this line
  // having been rewritten. It used to echo the full canonical code, which
  // meant the three secret words went to stdout on exactly the inputs
  // ./read-code.js exists to protect: a pasted QR payload and a code
  // pasted out of a chat client both differ from canonical form, so
  // `swarm-send - file` -- the mode whose entire purpose is that the
  // secret never lands anywhere persistent -- wrote it into scrollback,
  // tmux and script logs, and CI output. A sender has no reason to
  // display the code at all: it is not showing it to anybody.
  if (code !== codeInput) console.log(`[swarm-send] code resolved to nameplate ${nameplate} (secret not shown)`)

  const swarm = createSwarm({ bootstrap: parseBootstrap() })
  const cancel = installCancelHandler({ label: 'swarm-send' })
  const progress = createProgressReporter({ label: 'swarm-send' })
  /** @type {Error | null} */
  let socketError = null
  console.log(`[swarm-send] joining topic ${topic.toString('hex')} (refresh=${refreshInterval() ?? 4000}ms, timeout=${joinTimeout()}ms)`)

  try {
    // Set once connectOnce resolves; see swarm-receive.js.
    let paired = false
    const { socket, peerInfo, pending, sendKey, receiveKey, caps } = await connectOnce(swarm, topic, {
      // Proves the peer knows the drop secret before we transmit a byte of
      // the file to it. The topic alone is public once the receiver
      // announces -- it commits to the nameplate, which is a rendezvous
      // label and not a secret -- so without this we would hand the file to
      // whoever answered first. See engine/src/handshake.js.
      nameplate,
      secret,
      timeout: joinTimeout(),
      refreshInterval: refreshInterval(),
      // Ctrl-C while still looking for a peer. This is the likeliest
      // moment for someone to give up -- it is the part of a drop that
      // can sit for two minutes with nothing to show -- and until the failure-reporting work
      // there was no way to cancel it.
      signal: cancel.signal,
      // See swarm-receive.js: without these, "connected to several peers
      // that all died before confirming" is indistinguishable from
      // "never found anyone".
      onCandidate: (info) => {
        console.log(`[swarm-send] candidate ${info.publicKey.toString('hex').slice(0, 12)}..., awaiting HELLO`)
      },
      // See swarm-receive.js: after pairing, only counted failures arrive.
      onCandidateDropped: (info, reason) => {
        const who = `candidate ${info.publicKey.toString('hex').slice(0, 12)}...`
        console.log(paired
          ? `[swarm-send] ${who} failed to prove the code during the transfer (${reason}); it counts toward this drop's attempt limit`
          : `[swarm-send] ${who} dropped before proving (${reason}); still looking`)
      },
      onDropTaken: (info) => {
        console.log(`[swarm-send] another receiver (${info.publicKey.toString('hex').slice(0, 12)}...) also has this code; it was told the drop is taken. If you gave the code to only one person, someone else has it.`)
      }
    })
    paired = true
    console.log(`[swarm-send] connected to ${peerInfo.publicKey.toString('hex').slice(0, 12)}...`)
    // Without a listener, a late socket-level error (e.g. after the
    // transfer completes, while tearing down) throws as an uncaught
    // exception instead of something we can handle gracefully.
    //
    // Silent once we are cancelling, and that is the whole point of item
    // 5 rather than tidiness: tearing down a cancelled transfer reliably
    // produces "connection reset by peer", which is byte for byte what a
    // dead hole punch looks like. Printing it right after "cancelled"
    // would hand back exactly the ambiguity the CANCEL frame was added to
    // remove.
    //
    // RECORDED RATHER THAN PRINTED, because printing it immediately is
    // how a deliberate cancel ended up followed by "connection reset by
    // peer" -- byte for byte what a dead hole punch looks like, and the
    // exact ambiguity the CANCEL frame exists to remove. A socket that
    // dies while a cancelled or completed transfer tears down explains
    // nothing; one that dies during a transfer that then failed for an
    // unclear reason explains a great deal, so it is reported there.
    socket.on('error', (err) => { socketError = err })

    const options = {
      // The channel keys the handshake just derived. Every frame from here
      // on is sealed under them, so authentication no longer rests on the
      // Noise session that happens to carry the bytes.
      sendKey,
      receiveKey,
      // Anything the receiver coalesced after its proof. Ordinarily
      // empty, but a CANCEL could be in there, and dropping it would lose
      // exactly the message the CANCEL frame exists to deliver.
      pending,
      signal: cancel.signal,
      onProgress: progress.onProgress
    }
    const result = streaming
      // The capability list the handshake negotiated: sendStream refuses
      // unless it contains "stream".
      ? await sendStream(socket, process.stdin, { ...options, name: streamName, caps })
      // caps here too: with "resume" negotiated the receiver may already
      // hold a prefix from an interrupted drop, and the file is sent from
      // there.
      : await sendFile(socket, filePathArg, { ...options, caps })
    progress.close()
    // Our own file's name, not a peer-supplied one -- but printed
    // through the same sanitiser anyway, so there is one rule for names
    // reaching a terminal rather than one rule and an exception.
    console.log(`[swarm-send] done: ${displayName(result.name)}`)
    if (result.resumedFrom > 0) {
      console.log(`[swarm-send] resumed: the receiver already held ${result.resumedFrom} of ${result.size} bytes from an earlier attempt`)
    }
    console.log(`[swarm-send] sha256: ${result.sha256}`)
    // sendFile resolves only on the receiver's RESULT carrying this same
    // digest, so this line is the receiver's claim, not our hope.
    console.log(`[swarm-send] verified: the receiver confirmed all ${result.size} bytes with the same digest`)

    // The file is confirmed, so nothing below can lose data. This wait
    // used to be the only thing standing between "sent" and "delivered",
    // and its 5s fallback was the cause of 6 in 100 real transfers
    // failing on the receiver -- see RESULT_TIMEOUT_MS in
    // engine/src/transfer.js. It is kept as courtesy: ending cleanly
    // lets the receiver's own close wait finish now rather than by timer.
    socket.end()
    /** @type {Promise<void>} */
    const closed = new Promise((resolve) => {
      const timer = setTimeout(resolve, 5000)
      socket.once('close', () => {
        clearTimeout(timer)
        resolve()
      })
    })
    await closed
  } catch (err) {
    progress.close()
    console.error(`[swarm-send] ${describeError(err)}`)
    if (socketError && !isCancellation(err)) {
      console.error(`[swarm-send] the socket also reported: ${socketError.message}`)
    }
    // A cancellation already set 130/143 in the signal handler. Flattening
    // it to 1 would throw away the distinction this item is about.
    if (!cancel.cancelled()) process.exitCode = 1
  } finally {
    cancel.dispose()
    await swarm.destroy()
  }
}

main()
