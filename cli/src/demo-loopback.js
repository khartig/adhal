#!/usr/bin/env node
'use strict'

// Human-facing demo of item 1 (docs/Refined-Implementation-Plan.md section 4):
// two processes on one machine, localhost pipe, send N MB, print SHA-256
// on both sides. Run with: npm run demo:loopback [sizeInMb]

const path = require('node:path')
const os = require('node:os')
const fs = require('node:fs')
const crypto = require('node:crypto')
const { spawn } = require('node:child_process')

const RECEIVE_SCRIPT = path.join(__dirname, 'receive.js')
const SEND_SCRIPT = path.join(__dirname, 'send.js')

function waitForExit (child, label) {
  return new Promise((resolve, reject) => {
    child.on('exit', (code) => {
      if (code === 0) resolve()
      else reject(new Error(`${label} exited with code ${code}`))
    })
    child.on('error', reject)
  })
}

async function main () {
  const sizeMb = Number(process.argv[2] || 10)
  const size = sizeMb * 1024 * 1024
  const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'quay-demo-'))
  const sourcePath = path.join(tmpDir, 'demo-file.bin')
  const outputDir = path.join(tmpDir, 'received')

  console.log(`[demo] generating ${sizeMb} MB random file at ${sourcePath}`)
  await fs.promises.writeFile(sourcePath, crypto.randomBytes(size))

  const receiveProc = spawn(process.execPath, [RECEIVE_SCRIPT, '0', outputDir], {
    stdio: ['ignore', 'pipe', 'inherit']
  })

  const boundPort = await new Promise((resolve, reject) => {
    receiveProc.stdout.on('data', (chunk) => {
      const text = chunk.toString('utf8')
      process.stdout.write(text)
      const match = text.match(/listening on 127\.0\.0\.1:(\d+)/)
      if (match) resolve(match[1])
    })
    receiveProc.once('error', reject)
  })

  const sendProc = spawn(process.execPath, [SEND_SCRIPT, boundPort, sourcePath], { stdio: 'inherit' })

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
