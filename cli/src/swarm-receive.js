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

const path = require('path')
const fs = require('fs')
const { createSwarm, acceptOnce, receiveFile, generateCode, encodeQrPayload, resolveCode, displayName } = require('@ad-hal/engine')

const { printQr } = require('./qr')
const { readCode } = require('./read-code')
const { createProgressReporter } = require('./progress')
const { installCancelHandler } = require('./signals')
const { describeError, isCancellation } = require('./report')
const { parseBootstrap } = require('./env')
const { createConsent } = require('./consent')
const { createContentionMonitor } = require('./contention')
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
const KNOWN_FLAGS = new Set(['--new', '--insecure-opaque-code', '--replace', '--code-stdin', '--verbose', '--yes', '--code-on-argv', '--help'])

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
    help: flags.includes('--help')
  }

  if (wantsNew) {
    if (positional.length > 1) throw new Error('too many arguments')
    return { codeArg: null, outputDirArg: positional[0], ...common }
  }
  if (positional.length > 2) throw new Error('too many arguments')
  return { codeArg: positional[0] || null, outputDirArg: positional[1], ...common }
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
  let parsed
  try {
    parsed = parseArgs(process.argv.slice(2))
  } catch (err) {
    console.error(`[swarm-receive] ${err.message}`)
    console.error(usage('swarm-receive'))
    process.exitCode = 1
    return
  }
  if (parsed.help) {
    console.log(usage('swarm-receive'))
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
      : await readCode({ argvCode: parsed.fromStdin ? '-' : parsed.codeArg, label: 'swarm-receive', allowArgv: parsed.allowArgv })
    resolved = resolveCode(input, { allowOpaque: parsed.allowOpaque || undefined })
  } catch (err) {
    console.error(`[swarm-receive] ${err.message}`)
    process.exitCode = 1
    return
  }
  const { code, topic, nameplate, secret } = resolved

  let bootstrap
  try {
    bootstrap = parseBootstrap()
  } catch (err) {
    console.error(`[swarm-receive] ${err.message}`)
    process.exitCode = 1
    return
  }

  const outputDir = parsed.outputDirArg ? path.resolve(parsed.outputDirArg) : process.cwd()
  await fs.promises.mkdir(outputDir, { recursive: true })

  const swarm = createSwarm({ bootstrap })
  const cancel = installCancelHandler({ label: 'swarm-receive' })
  const progress = createProgressReporter({ label: 'swarm-receive' })
  /** @type {Error | null} */
  let socketError = null
  // The topic is a commitment to the nameplate, and this line lands in
  // scrollback, CI logs and bug reports. It is shown only when asked for
  // (Q-17); the nameplate itself is already on screen in the code.
  console.log(`[swarm-receive] joining topic${parsed.verbose ? ` ${topic.toString('hex')}` : ''} (refresh=${refreshInterval() ?? 4000}ms, timeout=${joinTimeout()}ms)`)
  // Q-09: before anything connects, so nobody learns it afterwards.
  console.log(`[swarm-receive] note: ${NOT_ANONYMOUS}`)
  const contention = createContentionMonitor({ label: 'swarm-receive' })
  const consent = createConsent({ yes: parsed.yes, label: 'swarm-receive', signal: cancel.signal })

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
      timeout: joinTimeout(),
      refreshInterval: refreshInterval(),
      // Ctrl-C while waiting for a peer -- which, for a receiver showing
      // a QR code, is almost the whole of its life. Before that work, this
      // was the one state with no way out but killing the process, and
      // the sender then saw a reset indistinguishable from a dead punch.
      signal: cancel.signal,
      // Log each candidate and each discarded one. A drop that fails
      // because peers connect and then vanish looks identical to one that
      // found nobody unless these lines are visible.
      onCandidate: (info) => {
        console.log(`[swarm-receive] candidate ${info.publicKey.toString('hex').slice(0, 12)}..., sent HELLO, awaiting REPLY`)
      },
      // After pairing, the engine reports only failures it COUNTED -- a
      // peer guessing at the code while the transfer runs -- so the line
      // stops saying "still waiting", which is no longer true.
      onCandidateDropped: (info, reason, code) => {
        const who = `candidate ${info.publicKey.toString('hex').slice(0, 12)}...`
        console.log(paired
          ? `[swarm-receive] ${who} failed to prove the code during the transfer (${reason}); it counts toward this drop's attempt limit`
          : `[swarm-receive] ${who} dropped before proving (${reason}); still waiting`)
        // The pattern, once there is one (Q-04); see ./contention.js.
        contention.dropped(info, reason, code)
      },
      // A second peer proved the code after we paired, and was told the
      // drop is taken. The race is invisible to this human otherwise, and
      // it means someone other than the intended sender holds the code.
      onDropTaken: (info) => {
        console.log(`[swarm-receive] another peer (${info.publicKey.toString('hex').slice(0, 12)}...) also has this code and tried to send; it was told the drop is taken. If you gave the code to only one person, someone else has it.`)
      },
      // Only now are we actually discoverable. The sender must not start
      // looking before this point -- see engine/src/swarm.js. This is
      // therefore also the first moment the code may be shown to a human,
      // which is why the QR is printed here and not before the join:
      // showing it earlier invites exactly the lookup-before-announce race
      // that engine/src/swarm.js documents. demo-swarm.js waits for this
      // line before spawning the sender.
      onAnnounced: () => {
        console.log('[swarm-receive] announced, waiting for a peer...')
        if (generated) {
          console.log()
          printQr(encodeQrPayload(code))
          console.log()
          console.log(`  scan the code above, or type:  ${code}`)
          console.log()
        }
      }
    })
    paired = true
    contention.paired()
    console.log(`[swarm-receive] connection from ${peerInfo.publicKey.toString('hex').slice(0, 12)}...`)
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

    const result = await receiveFile(socket, outputDir, {
      // The channel keys the handshake derived; every frame is opened
      // under them. See swarm-send.js.
      sendKey,
      receiveKey,
      // What the same handshake negotiated. A streamed offer is declined
      // unless "stream" is in it.
      caps,
      // Bytes the handshake read alongside the ACK, if the sender
      // coalesced them; dropping these would corrupt the first frame.
      pending,
      signal: cancel.signal,
      onProgress: progress.onProgress,
      // Off unless asked for. The engine now refuses to replace a file it
      // did not create, and lands `report (1).pdf` beside the original
      // instead -- so the flag is the only way back to the old behaviour.
      replace: parsed.replace,
      // Explicit rather than relying on the engine's default, so the
      // number a receiver enforces is visible at the call site and one
      // env var away from being changed for a legitimate large drop.
      maxSize: maxSize(),
      // A person says yes before anything is written, unless --yes said it
      // for them (Q-02). The engine has already refused what it would
      // refuse anyway, so nobody is asked about an unsafe name.
      onOffer: consent.onOffer,
      onManifest: (manifest, { resumeFrom }) => {
        // THE FIRST PEER-CHOSEN STRING THIS PROCESS PRINTS. Straight to a
        // terminal, before anything has validated that it is printable.
        // A name carrying ESC or a bidi override forged whatever it liked
        // on this line until displayName existed.
        console.log(`[swarm-receive] manifest: ${displayName(manifest.name)} (${manifest.size === null ? 'streamed, size unknown until it ends' : `${manifest.size} bytes`})`)
        // A partial from an interrupted drop was found, re-hashed, and is
        // being continued. It is verified with the rest at the end: if it
        // was not this file's, the digest says so and it is discarded.
        if (resumeFrom > 0) console.log(`[swarm-receive] resuming from byte ${resumeFrom} of an earlier, interrupted attempt`)
      }
    })

    progress.close()
    console.log(`[swarm-receive] done: ${displayName(result.name)}`)
    console.log(`[swarm-receive] sha256: ${result.sha256}`)
    // The line that turns plan phase-1 bar the drop-code work from an eyeball
    // comparison of two hex strings into an assertion the receiver makes
    // for itself. Until that work, this comparison happened nowhere that
    // shipped.
    console.log('[swarm-receive] verified: the file matches the sender\'s manifest digest')
    if (result.name !== result.declaredName) {
      // Covers both reasons the name can differ -- the write policy
      // transformed it, or an existing file meant it landed suffixed --
      // and shows the peer's original so nothing is silently substituted.
      console.log(`[swarm-receive] renamed: the peer asked for ${JSON.stringify(displayName(result.declaredName))}`)
    }
    console.log(`[swarm-receive] saved to: ${result.path}`)
    // See `publish` in engine/src/transfer.js (Q-19).
    if (result.published === 'check-then-rename') {
      console.log('[swarm-receive] note: this filesystem has no hard links, so the file was landed with a check-then-rename; ' +
        'another process creating the same name at that instant could have been overwritten. Prefer an output directory on a local disk.')
    }

    // receiveFile has written RESULT, but "written" is a local flush.
    // Destroying now could drop it and leave the sender reporting an
    // unconfirmed file -- the same mistake the sender used to make with
    // the last chunks. So end, and wait for the sender's end in reply,
    // which it sends once it has read RESULT. The timeout only bounds a
    // sender that vanished: the file is already verified and saved.
    socket.end()
    await new Promise((resolve) => {
      const timer = setTimeout(resolve, 5000)
      socket.once('close', () => {
        clearTimeout(timer)
        resolve(undefined)
      })
    })
  } catch (err) {
    // First, so the reason does not land on the question's line.
    consent.close()
    progress.close()
    console.error(`[swarm-receive] ${describeError(err)}`)
    if (socketError && !isCancellation(err)) {
      console.error(`[swarm-receive] the socket also reported: ${socketError.message}`)
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
