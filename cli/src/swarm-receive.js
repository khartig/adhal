#!/usr/bin/env node
'use strict'

// Item 2 receiver half: "same CLI over Hyperswarm on one LAN." Reuses the
// exact manifest/chunk protocol from item 1 (engine/src/transfer.js);
// only the transport changes, from a bare TCP socket to an end-to-end
// Noise-encrypted Hyperswarm connection.
//
// Usage: swarm-receive.js <code> [outputDir]
//
// QUAY_BOOTSTRAP=<json bootstrap array> overrides the DHT bootstrap nodes
// -- used by the automated test to run against an isolated local testnet
// instead of the public DHT.

const path = require('path')
const fs = require('fs')
const { createSwarm, acceptOnce, topicFromCode, receiveFile } = require('@quay/engine')

function parseBootstrap () {
  const raw = process.env.QUAY_BOOTSTRAP
  return raw ? JSON.parse(raw) : undefined
}

async function main () {
  const [, , code, outputDirArg] = process.argv
  if (!code) {
    console.error('Usage: swarm-receive.js <code> [outputDir]')
    process.exitCode = 1
    return
  }

  const outputDir = outputDirArg ? path.resolve(outputDirArg) : process.cwd()
  await fs.promises.mkdir(outputDir, { recursive: true })

  const topic = topicFromCode(code)
  const swarm = createSwarm({ bootstrap: parseBootstrap() })
  console.log(`[swarm-receive] joining topic ${topic.toString('hex')}, waiting for a peer...`)

  try {
    const { socket, peerInfo } = await acceptOnce(swarm, topic)
    console.log(`[swarm-receive] connection from ${peerInfo.publicKey.toString('hex').slice(0, 12)}...`)
    // Without a listener, a late socket-level error (e.g. after transfer
    // completes, while tearing down) throws as an uncaught exception
    // instead of something we can handle gracefully.
    socket.on('error', (err) => console.error('[swarm-receive] socket error:', err.message))

    const result = await receiveFile(socket, outputDir, {
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
