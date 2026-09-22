#!/usr/bin/env node
'use strict'

// Human-facing demo of the Hyperswarm milestone:
// "Same CLI over Hyperswarm on one LAN." Unlike the automated test, this
// uses the real public Hyperswarm/hyperdht bootstrap nodes (no
// QUAY_BOOTSTRAP override), so it needs internet access and demonstrates
// genuine topic-based discovery + Noise-encrypted hole-punching, not just
// an isolated local testnet. Run with: npm run demo:swarm [sizeInMb]

const path = require('node:path')
const os = require('node:os')
const fs = require('node:fs')
const crypto = require('node:crypto')
const { spawn } = require('node:child_process')

const { generateCode, encodeQrPayload } = require('@quay/engine')
const { printQr } = require('./qr')

const RECEIVE_SCRIPT = path.join(__dirname, 'swarm-receive.js')
const SEND_SCRIPT = path.join(__dirname, 'swarm-send.js')

/** @returns {Promise<void>} */
function waitForExit (child, label) {
  return new Promise((resolve, reject) => {
    child.on('exit', (code) => {
      if (code === 0) resolve()
      else reject(new Error(`${label} exited with code ${code}`))
    })
    child.on('error', reject)
  })
}

/** @returns {Promise<void>} */
function waitForPattern (child, pattern) {
  return new Promise((resolve, reject) => {
    child.stdout.on('data', (chunk) => {
      if (pattern.test(chunk.toString('utf8'))) resolve()
    })
    child.once('error', reject)
  })
}

async function main () {
  const sizeMb = Number(process.argv[2] || 10)
  const size = sizeMb * 1024 * 1024
  // A real word code rather than the opaque hex this used to generate, so
  // the demo shows what a real drop actually puts on screen -- five words
  // under v2, of which only the first two reach the topic.
  //
  // (This comment used to add that swarm-lan.test.js still drove the
  // opaque path "so both stay exercised". That stopped being true when
  // that test switched to generateCode() as well: opaque codes are now
  // exercised only by the engine/scratch-*.js diagnostics and
  // code.test.js, which is the right place for a path that voids v2's
  // central property -- see resolveCode.)
  const code = generateCode()
  const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'quay-swarm-demo-'))
  const sourcePath = path.join(tmpDir, 'demo-file.bin')
  const outputDir = path.join(tmpDir, 'received')

  console.log(`[demo] generating ${sizeMb} MB random file at ${sourcePath}`)
  await fs.promises.writeFile(sourcePath, crypto.randomBytes(size))
  console.log('[demo] one-time code for this run:')
  console.log()
  printQr(encodeQrPayload(code))
  console.log()
  console.log(`  ${code}`)
  console.log()

  const receiveProc = spawn(process.execPath, [RECEIVE_SCRIPT, code, outputDir], { stdio: ['ignore', 'pipe', 'inherit'] })
  receiveProc.stdout.pipe(process.stdout)

  // Wait for the receiver's announcement to flush, not merely for it to have
  // joined. Starting the sender before the receiver is discoverable loses
  // a race that Hyperswarm only retries every 10-12 minutes, which looked
  // like a flat ~50% "timed-out looking for a peer" failure rate on the
  // public DHT. See engine/src/swarm.js REFRESH_INTERVAL.
  await waitForPattern(receiveProc, /announced, waiting for a peer/)

  const sendProc = spawn(process.execPath, [SEND_SCRIPT, code, sourcePath], { stdio: 'inherit' })

  await Promise.all([
    waitForExit(sendProc, 'send'),
    waitForExit(receiveProc, 'receive')
  ])

  await fs.promises.rm(tmpDir, { recursive: true, force: true })
  console.log('[demo] done -- compare the two sha256 lines above; they should match')
}

main().catch((err) => {
  console.error('[demo] failed:', err.message)
  process.exitCode = 1
})
