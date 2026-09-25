#!/usr/bin/env node
'use strict'

// Loopback sender half: "send 10 MB, print SHA-256."
// Usage: send.js <port> <code|-> <filePath>
//
// <code> is the drop code receive.js printed. Pass `-` to read it from
// stdin instead, which keeps it out of the shell history and `ps` -- see
// ./read-code.js. The handshake is the same CPace exchange swarm-send.js
// runs, over plain TCP; see receive.js for why.

const net = require('net')
const { sendFile, connectStream, resolveCode } = require('@quay/engine')

const { createProgressReporter } = require('./progress')
const { installCancelHandler } = require('./signals')
const { describeError } = require('./report')
const { readCode } = require('./read-code')

async function main () {
  const [, , portArg, codeArg, filePathArg] = process.argv
  const port = portArg === undefined ? NaN : Number(portArg)

  if (Number.isNaN(port) || !codeArg || !filePathArg) {
    console.error('Usage: send.js <port> <code|-> <filePath>')
    process.exitCode = 1
    return
  }

  let nameplate, secret
  try {
    ({ nameplate, secret } = resolveCode(await readCode({ argvCode: codeArg, label: 'send' })))
  } catch (err) {
    console.error(`[send] ${err.message}`)
    process.exitCode = 1
    return
  }

  const socket = net.createConnection({ host: '127.0.0.1', port })
  const cancel = installCancelHandler({ label: 'send' })
  const progress = createProgressReporter({ label: 'send' })

  socket.on('connect', async () => {
    console.log(`[send] connected to 127.0.0.1:${port}`)
    try {
      const { pending, sendKey, receiveKey } = await connectStream(socket, { nameplate, secret, signal: cancel.signal })
      console.log('[send] handshake confirmed; the channel is sealed')
      const result = await sendFile(socket, filePathArg, {
        sendKey,
        receiveKey,
        pending,
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

  // Also the sink for the gap between connectStream and sendFile, when
  // neither has a listener attached -- see receive.js.
  socket.on('error', (err) => {
    console.error('[send] socket error:', err.message)
    process.exitCode = 1
  })
}

main()
