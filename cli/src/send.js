#!/usr/bin/env node
'use strict'

// Item 1 sender half: "send 10 MB, print SHA-256."
// Usage: send.js <port> <filePath>

const net = require('net')
const { sendFile } = require('@quay/engine')

async function main () {
  const [, , portArg, filePathArg] = process.argv
  const port = portArg === undefined ? NaN : Number(portArg)

  if (Number.isNaN(port) || !filePathArg) {
    console.error('Usage: send.js <port> <filePath>')
    process.exitCode = 1
    return
  }

  const socket = net.createConnection({ host: '127.0.0.1', port })

  socket.on('connect', async () => {
    console.log(`[send] connected to 127.0.0.1:${port}`)
    try {
      const result = await sendFile(socket, filePathArg)
      console.log(`[send] done: ${result.name}`)
      console.log(`[send] sha256: ${result.sha256}`)
      socket.end()
    } catch (err) {
      console.error('[send] error:', err.message)
      process.exitCode = 1
      socket.destroy()
    }
  })

  socket.on('error', (err) => {
    console.error('[send] socket error:', err.message)
    process.exitCode = 1
  })
}

main()
