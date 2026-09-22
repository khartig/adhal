#!/usr/bin/env node
'use strict'

// The Hyperswarm work sender half. Usage: swarm-send.js <code> <filePath>
//
// The code may be five words (the drop code) in any casing or separator
// style, or the QR payload pasted verbatim -- 'QUAY2:ACID-ACORN-...' --
// since that decodes to the same thing a scanner would hand a UI. See
// engine/src/resolve-code.js for how that is distinguished from an opaque secret.
//
// See swarm-receive.js for the QUAY_BOOTSTRAP override.

const { createSwarm, connectOnce, sendFile, resolveCode, displayName } = require('@quay/engine')

const { createProgressReporter } = require('./progress')
const { installCancelHandler } = require('./signals')
const { describeError, isCancellation } = require('./report')
const { readCode } = require('./read-code')

function parseBootstrap () {
  const raw = process.env.QUAY_BOOTSTRAP
  return raw ? JSON.parse(raw) : undefined
}

// See swarm-receive.js for why the public-DHT default is this generous.
function joinTimeout () {
  const raw = process.env.QUAY_JOIN_TIMEOUT
  if (!raw) return 120000
  const parsed = Number(raw)
  if (!Number.isFinite(parsed) || parsed < 0) {
    throw new TypeError(`QUAY_JOIN_TIMEOUT must be a non-negative number, got ${raw}`)
  }
  return parsed
}

// QUAY_REFRESH_INTERVAL overrides how often we re-run our own DHT
// announce/lookup, in ms (0 disables it, leaving Hyperswarm's internal
// 10-minute schedule). See engine/src/swarm.js REFRESH_INTERVAL: the 4s
// default is validated only for two peers on one machine, and on a
// cross-ISP path a continuous re-announce is a suspect for churning
// holepunch relay state.
function refreshInterval () {
  const raw = process.env.QUAY_REFRESH_INTERVAL
  if (raw === undefined) return undefined
  const parsed = Number(raw)
  if (!Number.isFinite(parsed) || parsed < 0) {
    throw new TypeError(`QUAY_REFRESH_INTERVAL must be a non-negative number, got ${raw}`)
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

  if (!codeArg || !filePathArg) {
    console.error('Usage: swarm-send.js <code> <filePath>')
    console.error('       swarm-send.js - <filePath>            read the code from stdin')
    console.error('       swarm-send.js <code> <filePath> --unsafe-opaque')
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
  // Echo the canonical form when it differs, so a code that was pasted as
  // a QR payload or with odd separators visibly normalized to the same
  // words the other device is showing.
  if (code !== codeInput) console.log(`[swarm-send] code: ${code}`)

  const swarm = createSwarm({ bootstrap: parseBootstrap() })
  const cancel = installCancelHandler({ label: 'swarm-send' })
  const progress = createProgressReporter({ label: 'swarm-send' })
  /** @type {Error | null} */
  let socketError = null
  console.log(`[swarm-send] joining topic ${topic.toString('hex')} (refresh=${refreshInterval() ?? 4000}ms, timeout=${joinTimeout()}ms)`)

  try {
    const { socket, peerInfo, pending } = await connectOnce(swarm, topic, {
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
      onCandidateDropped: (info, reason) => {
        console.log(`[swarm-send] candidate ${info.publicKey.toString('hex').slice(0, 12)}... dropped before proving (${reason}); still looking`)
      }
    })
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

    const result = await sendFile(socket, filePathArg, {
      // Anything the receiver coalesced after its proof. Ordinarily
      // empty, but a CANCEL could be in there, and dropping it would lose
      // exactly the message the CANCEL frame exists to deliver.
      pending,
      signal: cancel.signal,
      onProgress: progress.onProgress
    })
    progress.close()
    // Our own file's name, not a peer-supplied one -- but printed
    // through the same sanitiser anyway, so there is one rule for names
    // reaching a terminal rather than one rule and an exception.
    console.log(`[swarm-send] done: ${displayName(result.name)}`)
    console.log(`[swarm-send] sha256: ${result.sha256}`)
    // Honest about what this number is: bytes handed to the transport,
    // not bytes the receiver has stored and verified. Acknowledgement by
    // index is resume (W11).
    console.log(`[swarm-send] sent ${result.size} bytes; the receiver's own "verified" line is the authoritative one`)

    // End our write side, then wait for the socket to fully close (i.e.,
    // the receiver has also ended its side, per swarm-receive.js) before
    // tearing the swarm down. Destroying right after our own end() only
    // guarantees a *local* flush, not that the receiver actually got the
    // last bytes -- doing so caused "connection reset by peer" on the
    // receiver mid-transfer. Falls back to a timeout so a hung close
    // can't wedge the process.
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
