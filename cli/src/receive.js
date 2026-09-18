#!/usr/bin/env node
'use strict'

// Item 1 receiver half: "two processes on one machine, localhost pipe."
// Usage: receive.js <port> [outputDir]
//   port=0 asks the OS for a free port; the bound port is printed so a
//   wrapper script/test can pick it up.

const net = require('net')
const path = require('path')
const fs = require('fs')
const { receiveFile } = require('@quay/engine')

const { createProgressReporter } = require('./progress')
const { installCancelHandler } = require('./signals')
const { describeError } = require('./report')

async function main () {
  const [, , portArg, outputDirArg] = process.argv
  const port = portArg === undefined ? NaN : Number(portArg)

  if (Number.isNaN(port)) {
    console.error('Usage: receive.js <port> [outputDir]')
    process.exitCode = 1
    return
  }

  const outputDir = outputDirArg ? path.resolve(outputDirArg) : process.cwd()
  await fs.promises.mkdir(outputDir, { recursive: true })

  const cancel = installCancelHandler({ label: 'receive' })

  const server = net.createServer((socket) => {
    console.log(`[receive] connection from ${socket.remoteAddress}:${socket.remotePort}`)
    const progress = createProgressReporter({ label: 'receive' })

    receiveFile(socket, outputDir, {
      signal: cancel.signal,
      onProgress: progress.onProgress,
      onManifest: (manifest) => {
        console.log(`[receive] manifest: ${manifest.name} (${manifest.size} bytes)`)
      }
    }).then((result) => {
      progress.close()
      console.log(`[receive] done: ${result.name}`)
      // Every one of these three lines now means something it did not
      // before. The digest was compared against the sender's manifest
      // rather than merely computed; the file was renamed into place only
      // after that comparison passed; and the name is the one we chose,
      // which may differ from the one the peer asked for.
      console.log(`[receive] sha256: ${result.sha256}`)
      console.log('[receive] verified: the file matches the sender\'s manifest digest')
      if (result.name !== result.declaredName) {
        console.log(`[receive] renamed: the peer asked for ${JSON.stringify(result.declaredName)}`)
      }
      console.log(`[receive] saved to: ${result.path}`)
      server.close()
    }).catch((err) => {
      progress.close()
      console.error(`[receive] ${describeError(err)}`)
      if (!cancel.cancelled()) process.exitCode = 1
      // Closing on the new terminal errors is what stops a receiver
      // sitting on a bound port after a transfer it has already given up
      // on -- before item 5 several of these could not happen at all,
      // because the receive simply never settled.
      server.close()
      socket.destroy()
    }).finally(() => cancel.dispose())
  })

  server.on('error', (err) => {
    console.error('[receive] server error:', err.message)
    process.exitCode = 1
  })

  server.listen(port, '127.0.0.1', () => {
    const address = /** @type {import('net').AddressInfo} */ (server.address())
    console.log(`[receive] listening on 127.0.0.1:${address.port}`)
  })
}

main()
