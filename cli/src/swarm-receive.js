#!/usr/bin/env node
'use strict'

// Hyperswarm receiver half: "same CLI over Hyperswarm on one LAN." Reuses
// the exact manifest/chunk protocol from the loopback milestone
// (engine/src/transfer.js);
// only the transport changes, from a bare TCP socket to an end-to-end
// Noise-encrypted Hyperswarm connection.
//
// Usage: see --help, in ./usage.js. This is the `ad-hal-receive` bin.
//
// With no code, or with --new, one is generated and shown as both five
// words and a QR symbol. An explicit code comes from stdin (`-`), or from
// argv only with --code-on-argv (./read-code.js). It may be five words in any
// casing/separator style, or an opaque secret -- see
// engine/src/resolve-code.js for why both are accepted, how they are told
// apart, and why an opaque one voids v2's central property.
//
// ADHAL_BOOTSTRAP=<json bootstrap array> overrides the DHT bootstrap nodes
// -- used by the automated test to run against an isolated local testnet
// instead of the public DHT.
//
// --stdout writes the file to stdout, for `ad-hal-receive --stdout | tar
// x`, and moves every other line to stderr. --json replaces the human
// lines with the event stream in ./events.js. Both are the contract in
// docs/CLI-CONTRACT.md, and the first thing that contract says is the one
// to remember here: with --stdout, the bytes are verified only once this
// process exits 0.

const path = require('path')
const fs = require('fs')
const { createSwarm, acceptOnce, receiveFile, closeAfterResult, generateCode, encodeQrPayload, resolveCode, displayName, KNOWN_CAPS } = require('@ad-hal/engine')

const { printQr } = require('./qr')
const { readCode } = require('./read-code')
const { createProgressReporter } = require('./progress')
const { installCancelHandler } = require('./signals')
const { describeError, isCancellation } = require('./report')
const { parseBootstrap } = require('./env')
const { createConsent, riskWarning } = require('./consent')
const { createContentionMonitor } = require('./contention')
const { createEventStream, peerId, version } = require('./events')
const { usage, NOT_ANONYMOUS } = require('./usage')


// ADHAL_JOIN_TIMEOUT overrides how long we wait for a peer, in ms (0
// disables the timeout). 30s is deliberate: on the public DHT a join that
// is going to work lands in ~5-7s, and one that has hit the
// lookup-before-announce race described in engine/src/swarm.js never
// recovers no matter how long you wait -- measured, a 120s budget rescued
// zero stuck runs. So a longer default just makes failures slower to
// report. The override exists for diagnosing slow networks.
function joinTimeout () {
  const raw = process.env.ADHAL_JOIN_TIMEOUT
  if (!raw) return 30000
  const parsed = Number(raw)
  if (!Number.isFinite(parsed) || parsed < 0) {
    throw new TypeError(`ADHAL_JOIN_TIMEOUT must be a non-negative number, got ${raw}`)
  }
  return parsed
}

// ADHAL_MAX_SIZE overrides the largest transfer this receiver will accept,
// in bytes. `0` means no limit at all and has to be written down, because
// with no cap a manifest declaring 9 PB validates cleanly and the only
// thing standing between the receiver and that number is the free-space
// check. The engine's own default (8 GiB) applies when this is unset.
function maxSize () {
  const raw = process.env.ADHAL_MAX_SIZE
  if (raw === undefined) return undefined
  const parsed = Number(raw)
  if (!Number.isFinite(parsed) || parsed < 0) {
    throw new TypeError(`ADHAL_MAX_SIZE must be a non-negative number, got ${raw}`)
  }
  return parsed === 0 ? null : parsed
}

// Splits argv into an optional code and an optional output directory.
// `--new` is explicit rather than inferred so that the one-positional form
// stays unambiguously "that's a code", exactly as the Hyperswarm CLI defined it: a bare
// path and a bare code are not reliably distinguishable, and guessing wrong
// would silently save into a directory named after a word.
const KNOWN_FLAGS = new Set(['--new', '--insecure-opaque-code', '--replace', '--code-stdin', '--verbose', '--yes', '--code-on-argv', '--stdout', '--json', '--help'])

function parseArgs (argv) {
  const flags = argv.filter((a) => a.startsWith('--'))
  const positional = argv.filter((a) => !a.startsWith('--'))
  const wantsNew = flags.includes('--new')

  for (const flag of flags) {
    if (!KNOWN_FLAGS.has(flag)) throw new Error(`unknown flag ${flag}`)
  }

  const common = {
    allowOpaque: flags.includes('--insecure-opaque-code'),
    // Opt back in to overwriting an existing file. Off by default: see
    // `publish` in engine/src/transfer.js for why the old overwrite
    // default was a security bug rather than a UI question.
    replace: flags.includes('--replace'),
    fromStdin: flags.includes('--code-stdin'),
    verbose: flags.includes('--verbose'),
    // Accept the offer without asking; see ./consent.js.
    yes: flags.includes('--yes'),
    allowArgv: flags.includes('--code-on-argv'),
    // The file to stdout, everything else to stderr; see the top.
    toStdout: flags.includes('--stdout'),
    json: flags.includes('--json'),
    help: flags.includes('--help')
  }

  const parsed = wantsNew
    ? { codeArg: null, outputDirArg: positional[0], ...common }
    : { codeArg: positional[0] || null, outputDirArg: positional[1], ...common }
  if (positional.length > (wantsNew ? 1 : 2)) throw new Error('too many arguments')
  // One place for the bytes. --replace is about a file that already
  // exists, and stdout has none.
  if (parsed.toStdout && parsed.outputDirArg !== undefined) throw new Error('--stdout takes the place of an output directory; pass one or the other')
  if (parsed.toStdout && parsed.replace) throw new Error('--replace has nothing to replace with --stdout')
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
  let parsed
  try {
    parsed = parseArgs(argv)
  } catch (err) {
    // Asked for by flag, so honored even when the flags did not parse:
    // a script that passed --json reads events, not prose.
    if (argv.includes('--json')) {
      createEventStream({ role: 'receive', stream: argv.includes('--stdout') ? process.stderr : process.stdout })
        .failed({ code: 'ERR_USAGE' }, err.message)
    } else {
      console.error(`[swarm-receive] ${err.message}`)
      console.error(usage('swarm-receive'))
    }
    process.exitCode = 1
    return
  }
  if (parsed.help) {
    console.log(usage('swarm-receive'))
    return
  }

  // WHERE EACH KIND OF OUTPUT GOES (docs/CLI-CONTRACT.md sections 2-3).
  // With --stdout, stdout carries the file's bytes and nothing else, so
  // the human lines move to stderr; with --json, the events go wherever
  // the file does not, and the human lines are not written at all.
  const humanOut = parsed.toStdout ? process.stderr : process.stdout
  const events = parsed.json
    ? createEventStream({ role: 'receive', stream: parsed.toStdout ? process.stderr : process.stdout })
    : null
  const say = events ? () => {} : (/** @type {string} */ line = '') => { humanOut.write(`${line}\n`) }
  /** @type {Array<{ kind: string, message: string }>} warnings raised before `start` */
  const held = []
  const sayError = events ? () => {} : (/** @type {string} */ line) => { process.stderr.write(`${line}\n`) }
  /**
   * A failure before the drop began. `code` is CLI-level (CONTRACT
   * section 4), since none of these touched the network.
   * @param {string} code
   * @param {any} err
   */
  const refuse = (code, err) => {
    if (events) events.failed({ code }, err.message)
    else sayError(`[swarm-receive] ${err.message}`)
    process.exitCode = 1
  }

  // Binary on a terminal is never what was meant: the mirror of
  // ad-hal-send refusing to stream from one.
  if (parsed.toStdout && process.stdout.isTTY) {
    refuse('ERR_USAGE', new Error('refusing to write a file to a terminal: redirect or pipe stdout, e.g. ad-hal-receive --stdout | tar x'))
    return
  }

  let timeout, refresh
  try {
    timeout = joinTimeout()
    refresh = refreshInterval()
  } catch (err) {
    refuse('ERR_USAGE', err)
    return
  }

  // A generated code is the default: the code generator exists because
  // hand-typing a code on both machines was the friction worth removing.
  // `--code-stdin` is the other way in, for a code that must not touch
  // the shell history or the process table -- see ./read-code.js.
  const generated = parsed.codeArg === null && !parsed.fromStdin
  let resolved
  try {
    const input = generated
      ? generateCode()
      : await readCode({
        argvCode: parsed.fromStdin ? '-' : parsed.codeArg,
        label: 'swarm-receive',
        allowArgv: parsed.allowArgv,
        // Held, not emitted: the code is read before `start`, which the
        // contract puts first (CLI-CONTRACT.md section 3.2).
        warn: events
          ? (line) => { held.push({ kind: 'code-on-argv', message: line.replace(/^\[swarm-receive\] note: /, '') }) }
          : undefined
      })
    resolved = resolveCode(input, { allowOpaque: parsed.allowOpaque || undefined })
  } catch (err) {
    refuse('ERR_CODE_INVALID', err)
    return
  }
  const { code, topic, nameplate, secret } = resolved

  let bootstrap
  try {
    bootstrap = parseBootstrap()
  } catch (err) {
    refuse('ERR_USAGE', err)
    return
  }

  const outputDir = parsed.toStdout ? null : parsed.outputDirArg ? path.resolve(parsed.outputDirArg) : process.cwd()
  if (outputDir) await fs.promises.mkdir(outputDir, { recursive: true })
  // A reader that goes away mid-file is reported through the transfer
  // (ERR_OUTPUT_CLOSED); one that goes away after it must not be an
  // uncaught exception.
  if (parsed.toStdout) process.stdout.on('error', () => {})

  const swarm = createSwarm({ bootstrap })
  const cancel = installCancelHandler({ label: 'swarm-receive', log: say })
  const progress = events
    ? { onProgress: events.onProgress, close: events.flushProgress, log: () => {} }
    : createProgressReporter({ label: 'swarm-receive', stream: humanOut })
  /** @type {Error | null} */
  let socketError = null
  if (events) {
    events.emit('start', { version, time: new Date().toISOString(), joinTimeout: timeout, refreshInterval: refresh ?? 4000, stdout: parsed.toStdout })
    events.emit('warning', { kind: 'not-anonymous', message: NOT_ANONYMOUS })
    for (const warning of held) events.emit('warning', warning)
  }
  // The topic is a commitment to the nameplate, and this line lands in
  // scrollback, CI logs, and bug reports. It is shown only when asked for
  // (Q-17); the nameplate itself is already on screen in the code.
  say(`[swarm-receive] joining topic${parsed.verbose ? ` ${topic.toString('hex')}` : ''} (refresh=${refresh ?? 4000}ms, timeout=${timeout}ms)`)
  // Q-09: before anything connects, so nobody learns it afterwards.
  say(`[swarm-receive] note: ${NOT_ANONYMOUS}`)
  const contention = createContentionMonitor({
    label: 'swarm-receive',
    log: events
      ? (_line, { message, ...counts }) => events.emit('warning', { kind: 'contention', message, ...counts })
      : say
  })
  const consent = createConsent({ yes: parsed.yes, ask: !events, label: 'swarm-receive', log: say, signal: cancel.signal })

  try {
    // Set once acceptOnce resolves; the late-candidate callbacks above
    // read it, because they keep firing after that.
    let paired = false
    const { socket, peerInfo, pending, sendKey, receiveKey, caps } = await acceptOnce(swarm, topic, {
      // Announcing the topic makes the NAMEPLATE public; the secret stays
      // private, and it is what proves a peer is the intended one rather
      // than a stranger who walked the DHT. Without it we would accept a
      // file from anyone and write it into `outputDir`.
      //
      // Under v2 the topic commits only to the nameplate, so the secret is
      // not recoverable from anything an observer can obtain -- a guess
      // costs a live protocol run against this process, which counts them
      // (PROTOCOL.md section 6). See engine/src/handshake.js.
      nameplate,
      secret,
      timeout,
      refreshInterval: refresh,
      // Stdout has no partial to resume from, so this receiver does not
      // offer to. The sender then sends from byte 0, and never waits on a
      // CHECKPOINT nobody will send.
      caps: parsed.toStdout ? KNOWN_CAPS.filter((/** @type {string} */ c) => c !== 'resume') : undefined,
      // Ctrl-C while waiting for a peer -- which, for a receiver showing
      // a QR code, is almost the whole of its life. Before that work, this
      // was the one state with no way out but killing the process, and
      // the sender then saw a reset indistinguishable from a dead punch.
      signal: cancel.signal,
      // Log each candidate and each discarded one. A drop that fails
      // because peers connect and then vanish looks identical to one that
      // found nobody unless these lines are visible.
      onCandidate: (info) => {
        if (events) events.emit('candidate', { peer: peerId(info) })
        say(`[swarm-receive] candidate ${info.publicKey.toString('hex').slice(0, 12)}..., sent HELLO, awaiting REPLY`)
      },
      // After pairing, the engine reports only failures it COUNTED -- a
      // peer guessing at the code while the transfer runs -- so the line
      // stops saying "still waiting", which is no longer true.
      onCandidateDropped: (info, reason, code, counted) => {
        if (events) events.emit('candidate-dropped', { peer: peerId(info), code: code ?? null, counted: Boolean(counted), paired })
        const who = `candidate ${info.publicKey.toString('hex').slice(0, 12)}...`
        say(paired
          ? `[swarm-receive] ${who} failed to prove the code during the transfer (${reason}); it counts toward this drop's attempt limit`
          : `[swarm-receive] ${who} dropped before proving (${reason}); still waiting`)
        // The pattern, once there is one (Q-04); see ./contention.js.
        contention.dropped(info, reason, code)
      },
      // A second peer proved the code after we paired, and was told the
      // drop is taken. The race is invisible to this human otherwise, and
      // it means someone other than the intended sender holds the code.
      onDropTaken: (info) => {
        if (events) events.emit('drop-taken', { peer: peerId(info) })
        say(`[swarm-receive] another peer (${info.publicKey.toString('hex').slice(0, 12)}...) also has this code and tried to send; it was told the drop is taken. If you gave the code to only one person, someone else has it.`)
      },
      // Only now are we actually discoverable. The sender must not start
      // looking before this point -- see engine/src/swarm.js. This is
      // therefore also the first moment the code may be shown to a human,
      // which is why the QR is printed here and not before the join:
      // showing it earlier invites exactly the lookup-before-announce race
      // that engine/src/swarm.js documents. demo-swarm.js waits for this
      // line before spawning the sender.
      onAnnounced: () => {
        if (events) {
          events.emit('announced')
          // The secret, in the event stream: the same exposure as the
          // human output's, which prints it for a person to read out
          // (CLI-CONTRACT.md section 3.2).
          if (generated) events.emit('code', { code, payload: encodeQrPayload(code) })
        }
        say('[swarm-receive] announced, waiting for a peer...')
        if (generated && !events) {
          say()
          printQr(encodeQrPayload(code), say)
          say()
          say(`  scan the code above, or type:  ${code}`)
          say()
        }
      }
    })
    paired = true
    contention.paired()
    if (events) events.emit('paired', { peer: peerId(peerInfo) })
    say(`[swarm-receive] connection from ${peerInfo.publicKey.toString('hex').slice(0, 12)}...`)
    // Without a listener, a late socket-level error (e.g. after the
    // transfer completes, while tearing down) throws as an uncaught
    // exception instead of something we can handle gracefully.
    //
    // Silent once we are canceling, and that is the whole point of item
    // 5 rather than tidiness: tearing down a canceled transfer reliably
    // produces "connection reset by peer", which is byte for byte what a
    // dead hole punch looks like. Printing it right after "canceled"
    // would hand back exactly the ambiguity the CANCEL frame was added to
    // remove.
    //
    // RECORDED RATHER THAN PRINTED, because printing it immediately is
    // how a deliberate cancel ended up followed by "connection reset by
    // peer" -- byte for byte what a dead hole punch looks like, and the
    // exact ambiguity the CANCEL frame exists to remove. A socket that
    // dies while a canceled or completed transfer tears down explains
    // nothing; one that dies during a transfer that then failed for an
    // unclear reason explains a great deal, so it is reported there.
    socket.on('error', (err) => { socketError = err })

    const result = await receiveFile(socket, outputDir, {
      // The channel keys the handshake derived; every frame is opened
      // under them. See swarm-send.js.
      sendKey,
      receiveKey,
      // What the same handshake negotiated. A streamed offer is declined
      // unless "stream" is in it.
      caps,
      // The file's bytes, as they arrive, in place of a directory.
      sink: parsed.toStdout ? process.stdout : undefined,
      // Bytes the handshake read alongside the ACK, if the sender
      // coalesced them; dropping these would corrupt the first frame.
      pending,
      signal: cancel.signal,
      onProgress: progress.onProgress,
      // Off unless asked for. The engine now refuses to replace a file it
      // did not create, and lands `report (1).pdf` beside the original
      // instead -- so the flag is the only way back to the old behavior.
      replace: parsed.replace,
      // Explicit rather than relying on the engine's default, so the
      // number a receiver enforces is visible at the call site and one
      // env var away from being changed for a legitimate large drop.
      maxSize: maxSize(),
      // A person says yes before anything is written, unless --yes said it
      // for them (Q-02). The engine has already refused what it would
      // refuse anyway, so nobody is asked about an unsafe name.
      onOffer: (offer) => {
        if (events) {
          const risk = riskWarning(offer.name)
          events.emit('offer', { name: offer.name, declaredName: offer.declaredName, size: offer.size, sha256: offer.sha256, partial: offer.partial, risk })
          if (risk) events.emit('warning', { kind: 'risky-name', message: risk })
        }
        return consent.onOffer(offer)
      },
      onManifest: (manifest, { resumeFrom }) => {
        if (events) events.emit('accepted', { resumeFrom })
        // THE FIRST PEER-CHOSEN STRING THIS PROCESS PRINTS. Straight to a
        // terminal, before anything has validated that it is printable.
        // A name carrying ESC or a bidi override forged whatever it liked
        // on this line until displayName existed.
        progress.log(`[swarm-receive] manifest: ${displayName(manifest.name)} (${manifest.size === null ? 'streamed, size unknown until it ends' : `${manifest.size} bytes`})`)
        // A partial from an interrupted drop was found, re-hashed, and is
        // being continued. It is verified with the rest at the end: if it
        // was not this file's, the digest says so and it is discarded.
        if (resumeFrom > 0) progress.log(`[swarm-receive] resuming from byte ${resumeFrom} of an earlier, interrupted attempt`)
      }
    })

    progress.close()
    say(`[swarm-receive] done: ${displayName(result.name)}`)
    say(`[swarm-receive] sha256: ${result.sha256}`)
    // The line that turns plan phase-1 bar the drop-code work from an eyeball
    // comparison of two hex strings into an assertion the receiver makes
    // for itself. Until that work, this comparison happened nowhere that
    // shipped.
    say('[swarm-receive] verified: the file matches the sender\'s manifest digest')
    if (result.name !== result.declaredName) {
      // Covers both reasons the name can differ -- the write policy
      // transformed it, or an existing file meant it landed suffixed --
      // and shows the peer's original so nothing is silently substituted.
      say(`[swarm-receive] renamed: the peer asked for ${JSON.stringify(displayName(result.declaredName))}`)
    }
    say(result.path === null ? '[swarm-receive] written to stdout' : `[swarm-receive] saved to: ${result.path}`)
    // See `publish` in engine/src/transfer.js (Q-19).
    if (result.published === 'check-then-rename') {
      const note = 'this filesystem has no hard links, so the file was landed with a check-then-rename; ' +
        'another process creating the same name at that instant could have been overwritten. Prefer an output directory on a local disk.'
      if (events) events.emit('warning', { kind: 'check-then-rename', message: note })
      say(`[swarm-receive] note: ${note}`)
    }

    // receiveFile has written RESULT, but "written" is a local flush.
    // Destroying now could drop it and leave the sender reporting an
    // unconfirmed file -- the same mistake the sender used to make with
    // the last chunks. So end, and wait until the transport confirms the
    // sender has RESULT and the sender closes in reply. The bound only
    // covers a sender that vanished: the file is already verified and
    // saved. See closeAfterResult in engine/src/transfer.js.
    const { outcome } = await closeAfterResult(socket)
    const acknowledged = outcome !== 'lost' && outcome !== 'timeout'
    if (!acknowledged) {
      say('[swarm-receive] note: the sender never acknowledged the confirmation, so it may report the file as unconfirmed. The file here is complete and verified.')
    }
    // Last, after the close wait, so it can say whether the sender heard
    // (CLI-CONTRACT.md section 3.2).
    if (events) {
      events.emit('done', {
        name: result.name,
        declaredName: result.declaredName,
        size: result.size,
        sha256: result.sha256,
        resumedFrom: result.resumedFrom,
        path: result.path,
        published: result.published,
        acknowledged
      })
    }
  } catch (err) {
    // First, so the reason does not land on the question's line.
    consent.close()
    progress.close()
    const message = describeError(err)
    const alsoSocket = socketError && !isCancellation(err) ? socketError.message : null
    if (events) {
      events.failed(err, message, alsoSocket ? { socketError: alsoSocket } : {})
    } else {
      sayError(`[swarm-receive] ${message}`)
      if (alsoSocket) sayError(`[swarm-receive] the socket also reported: ${alsoSocket}`)
    }
    if (!cancel.cancelled()) process.exitCode = 1
  } finally {
    // A question still on screen after the transfer ended some other way.
    consent.close()
    cancel.dispose()
    await swarm.destroy()
  }
}

main()
