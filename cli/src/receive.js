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

  const server = net.createServer((socket) => {
    console.log(`[receive] connection from ${socket.remoteAddress}:${socket.remotePort}`)

    receiveFile(socket, outputDir, {
      onManifest: (manifest) => {
        console.log(`[receive] manifest: ${manifest.name} (${manifest.size} bytes)`)
      }
    }).then((result) => {
      console.log(`[receive] done: ${result.name}`)
      console.log(`[receive] sha256: ${result.sha256}`)
      console.log(`[receive] saved to: ${result.path}`)
      server.close()
    }).catch((err) => {
      console.error('[receive] error:', err.message)
      process.exitCode = 1
      server.close()
    })
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
