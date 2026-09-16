#!/usr/bin/env node
'use strict'

// Human-facing demo of item 2 (docs/Refined-Implementation-Plan.md section 4):
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
  const code = crypto.randomBytes(8).toString('hex')
  const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'quay-swarm-demo-'))
  const sourcePath = path.join(tmpDir, 'demo-file.bin')
  const outputDir = path.join(tmpDir, 'received')

  console.log(`[demo] generating ${sizeMb} MB random file at ${sourcePath}`)
  await fs.promises.writeFile(sourcePath, crypto.randomBytes(size))
  console.log(`[demo] one-time code for this run: ${code}`)

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
