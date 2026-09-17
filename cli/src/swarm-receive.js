#!/usr/bin/env node
'use strict'

// Item 2 receiver half: "same CLI over Hyperswarm on one LAN." Reuses the
// exact manifest/chunk protocol from item 1 (engine/src/transfer.js);
// only the transport changes, from a bare TCP socket to an end-to-end
// Noise-encrypted Hyperswarm connection.
//
// Usage: swarm-receive.js [code] [outputDir]
//        swarm-receive.js --new [outputDir]
//
// With no code, or with --new, one is generated (item 3) and shown as both
// six words and a QR symbol. An explicit code may be six words in any
// casing/separator style, or an opaque secret -- see ./resolve-code.js for
// why both are accepted and how they are told apart.
//
// QUAY_BOOTSTRAP=<json bootstrap array> overrides the DHT bootstrap nodes
// -- used by the automated test to run against an isolated local testnet
// instead of the public DHT.

const path = require('path')
const fs = require('fs')
const { createSwarm, acceptOnce, receiveFile, generateCode, encodeQrPayload } = require('@quay/engine')
const { resolveCode } = require('./resolve-code')
const { printQr } = require('./qr')

function parseBootstrap () {
  const raw = process.env.QUAY_BOOTSTRAP
  return raw ? JSON.parse(raw) : undefined
}

// QUAY_JOIN_TIMEOUT overrides how long we wait for a peer, in ms (0
// disables the timeout). 30s is deliberate: on the public DHT a join that
// is going to work lands in ~5-7s, and one that has hit the
// lookup-before-announce race described in engine/src/swarm.js never
// recovers no matter how long you wait -- measured, a 120s budget rescued
// zero stuck runs. So a longer default just makes failures slower to
// report. The override exists for diagnosing slow networks.
function joinTimeout () {
  const raw = process.env.QUAY_JOIN_TIMEOUT
  if (!raw) return 30000
  const parsed = Number(raw)
  if (!Number.isFinite(parsed) || parsed < 0) {
    throw new TypeError(`QUAY_JOIN_TIMEOUT must be a non-negative number, got ${raw}`)
  }
  return parsed
}

// Splits argv into an optional code and an optional output directory.
// `--new` is explicit rather than inferred so that the one-positional form
// stays unambiguously "that's a code", exactly as item 2 defined it: a bare
// path and a bare code are not reliably distinguishable, and guessing wrong
// would silently save into a directory named after a word.
function parseArgs (argv) {
  const flags = argv.filter((a) => a.startsWith('--'))
  const positional = argv.filter((a) => !a.startsWith('--'))
  const wantsNew = flags.includes('--new')

  for (const flag of flags) {
    if (flag !== '--new') throw new Error(`unknown flag ${flag}`)
  }

  if (wantsNew) {
    if (positional.length > 1) throw new Error('too many arguments')
    return { codeArg: null, outputDirArg: positional[0] }
  }
  if (positional.length > 2) throw new Error('too many arguments')
  return { codeArg: positional[0] || null, outputDirArg: positional[1] }
}

async function main () {
  let parsed
  try {
    parsed = parseArgs(process.argv.slice(2))
  } catch (err) {
    console.error(`[swarm-receive] ${err.message}`)
    console.error('Usage: swarm-receive.js [code] [outputDir]')
    console.error('       swarm-receive.js --new [outputDir]')
    process.exitCode = 1
    return
  }

  // A generated code is the default: item 3 exists because hand-typing a
  // code on both machines was the friction worth removing.
  const generated = parsed.codeArg === null
  let resolved
  try {
    resolved = resolveCode(generated ? generateCode() : parsed.codeArg)
  } catch (err) {
    console.error(`[swarm-receive] ${err.message}`)
    process.exitCode = 1
    return
  }
  const { code, topic } = resolved

  const outputDir = parsed.outputDirArg ? path.resolve(parsed.outputDirArg) : process.cwd()
  await fs.promises.mkdir(outputDir, { recursive: true })

  const swarm = createSwarm({ bootstrap: parseBootstrap() })
  console.log(`[swarm-receive] joining topic ${topic.toString('hex')}...`)

  try {
    const { socket, peerInfo, pending } = await acceptOnce(swarm, topic, {
      timeout: joinTimeout(),
      // Log each candidate and each discarded one. A drop that fails
      // because peers connect and then vanish looks identical to one that
      // found nobody unless these lines are visible.
      onCandidate: (info) => {
        console.log(`[swarm-receive] candidate ${info.publicKey.toString('hex').slice(0, 12)}..., sent READY, awaiting ACK`)
      },
      onCandidateDropped: (info, reason) => {
        console.log(`[swarm-receive] candidate ${info.publicKey.toString('hex').slice(0, 12)}... dropped before ACK (${reason}); still waiting`)
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
    console.log(`[swarm-receive] connection from ${peerInfo.publicKey.toString('hex').slice(0, 12)}...`)
    // Without a listener, a late socket-level error (e.g. after transfer
    // completes, while tearing down) throws as an uncaught exception
    // instead of something we can handle gracefully.
    socket.on('error', (err) => console.error('[swarm-receive] socket error:', err.message))

    const result = await receiveFile(socket, outputDir, {
      // Bytes the handshake read alongside the ACK, if the sender
      // coalesced them; dropping these would corrupt the first frame.
      pending,
      onManifest: (manifest) => {
        console.log(`[swarm-receive] manifest: ${manifest.name} (${manifest.size} bytes)`)
      }
    })

    console.log(`[swarm-receive] done: ${result.name}`)
    console.log(`[swarm-receive] sha256: ${result.sha256}`)
    console.log(`[swarm-receive] saved to: ${result.path}`)

    // Signal the sender we're fully done reading so it knows it's safe
    // to tear its side down too (see swarm-send.js).
    await new Promise((resolve) => socket.end(resolve))
  } catch (err) {
    console.error('[swarm-receive] error:', err.message)
    process.exitCode = 1
  } finally {
    await swarm.destroy()
  }
}

main()
