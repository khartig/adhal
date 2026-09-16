#!/usr/bin/env node
'use strict'

// Item 2 sender half. Usage: swarm-send.js <code> <filePath>
// See swarm-receive.js for the QUAY_BOOTSTRAP override.

const { createSwarm, connectOnce, topicFromCode, sendFile } = require('@quay/engine')

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

async function main () {
  const [, , code, filePathArg] = process.argv
  if (!code || !filePathArg) {
    console.error('Usage: swarm-send.js <code> <filePath>')
    process.exitCode = 1
    return
  }

  const topic = topicFromCode(code)
  const swarm = createSwarm({ bootstrap: parseBootstrap() })
  console.log(`[swarm-send] joining topic ${topic.toString('hex')}, looking for a peer...`)

  try {
    const { socket, peerInfo } = await connectOnce(swarm, topic, { timeout: joinTimeout() })
    console.log(`[swarm-send] connected to ${peerInfo.publicKey.toString('hex').slice(0, 12)}...`)
    // See swarm-receive.js: without a listener, a late socket-level error
    // throws as an uncaught exception instead of something catchable.
    socket.on('error', (err) => console.error('[swarm-send] socket error:', err.message))

    const result = await sendFile(socket, filePathArg)
    console.log(`[swarm-send] done: ${result.name}`)
    console.log(`[swarm-send] sha256: ${result.sha256}`)

    // End our write side, then wait for the socket to fully close (i.e.
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
    console.error('[swarm-send] error:', err.message)
    process.exitCode = 1
  } finally {
    await swarm.destroy()
  }
}

main()
