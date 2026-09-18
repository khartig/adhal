#!/usr/bin/env node
'use strict'

// Item 1 sender half: "send 10 MB, print SHA-256."
// Usage: send.js <port> <filePath>

const net = require('net')
const { sendFile } = require('@quay/engine')

const { createProgressReporter } = require('./progress')
const { installCancelHandler } = require('./signals')
const { describeError } = require('./report')

async function main () {
  const [, , portArg, filePathArg] = process.argv
  const port = portArg === undefined ? NaN : Number(portArg)

  if (Number.isNaN(port) || !filePathArg) {
    console.error('Usage: send.js <port> <filePath>')
    process.exitCode = 1
    return
  }

  const socket = net.createConnection({ host: '127.0.0.1', port })
  const cancel = installCancelHandler({ label: 'send' })
  const progress = createProgressReporter({ label: 'send' })

  socket.on('connect', async () => {
    console.log(`[send] connected to 127.0.0.1:${port}`)
    try {
      const result = await sendFile(socket, filePathArg, {
        signal: cancel.signal,
        onProgress: progress.onProgress
      })
      progress.close()
      console.log(`[send] done: ${result.name}`)
      console.log(`[send] sha256: ${result.sha256}`)
      socket.end()
    } catch (err) {
      progress.close()
      console.error(`[send] ${describeError(err)}`)
      // A cancellation is not a failure, and the exit code for it was
      // already set by the signal handler (130/143). Overwriting it with
      // 1 would lose the distinction the whole item is about.
      if (!cancel.cancelled()) process.exitCode = 1
      socket.destroy()
    } finally {
      cancel.dispose()
    }
  })

  socket.on('error', (err) => {
    console.error('[send] socket error:', err.message)
    process.exitCode = 1
  })
}

main()
