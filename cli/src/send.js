#!/usr/bin/env node
'use strict'

// Loopback sender half: "send 10 MB, print SHA-256."
// Usage: send.js <port> <-|code> <filePath|-> [--code-on-argv]
//
// TEST-ONLY (Q-13), like receive.js: it dials 127.0.0.1, and the
// `ad-hal-send` bin is swarm-send.js.
//
// A filePath of '-' streams stdin, offered as "stdin" -- see
// swarm-send.js. Not together with a code of '-': there is one stdin, so a
// stream takes its code from argv, with --code-on-argv.
//
// The code is the drop code receive.js printed, read from stdin (`-`), or
// from argv only with --code-on-argv -- see ./read-code.js. The handshake
// is the same CPace exchange swarm-send.js runs, over plain TCP; see
// receive.js for why.

const net = require('net')
const { sendFile, sendStream, connectStream, resolveCode } = require('@ad-hal/engine')

const { createProgressReporter } = require('./progress')
const { installCancelHandler } = require('./signals')
const { describeError } = require('./report')
const { readCode } = require('./read-code')
const { usage } = require('./usage')

async function main () {
  const argv = process.argv.slice(2)
  const [portArg, codeArg, filePathArg] = argv.filter((a) => !a.startsWith('--'))
  const port = portArg === undefined ? NaN : Number(portArg)

  if (argv.includes('--help')) {
    console.log(usage('send'))
    return
  }
  if (Number.isNaN(port) || !codeArg || !filePathArg) {
    console.error(usage('send'))
    process.exitCode = 1
    return
  }
  const streaming = filePathArg === '-'
  if (streaming && codeArg === '-') {
    console.error('[send] stdin can carry the code or the data, not both: when streaming, pass the code as an argument, with --code-on-argv')
    process.exitCode = 1
    return
  }

  let nameplate, secret
  try {
    ({ nameplate, secret } = resolveCode(await readCode({ argvCode: codeArg, label: 'send', allowArgv: argv.includes('--code-on-argv') })))
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
      const { pending, sendKey, receiveKey, caps } = await connectStream(socket, { nameplate, secret, signal: cancel.signal })
      console.log('[send] handshake confirmed; the channel is sealed')
      const options = { sendKey, receiveKey, pending, signal: cancel.signal, onProgress: progress.onProgress }
      const result = streaming
        ? await sendStream(socket, process.stdin, { ...options, name: 'stdin', caps })
        : await sendFile(socket, filePathArg, { ...options, caps })
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
