#!/usr/bin/env node
'use strict'

// The loopback milestone receiver half: "two processes on one machine, localhost pipe."
// Usage: receive.js <port> [outputDir] [--yes]
//   port=0 asks the OS for a free port; the bound port is printed so a
//   wrapper script/test can pick it up, and so is a freshly generated drop
//   code, which send.js needs.
//
// TEST-ONLY (Q-13). It listens on 127.0.0.1 and nowhere else, and exists
// for the tests and the loopback demo. It is not a published bin: the
// `ad-hal-receive` bin is swarm-receive.js. It still asks before accepting,
// like that one, so the tests exercise the same consent path.
//
// SINCE v2 THIS RUNS THE SAME PAKE AS THE SWARM PATH, over plain TCP. It
// used to write cleartext frames with no authentication at all, which was
// tolerable only because nothing but 127.0.0.1 could reach it. Under v2
// every frame is sealed under keys from the handshake, and there is no
// unsealed mode for this demo to use -- which is the point: the channel is
// keyed from the PAKE transcript, not the transport (PROTOCOL.md section
// 3.3), so a TCP socket with no Noise underneath gets exactly the same
// guarantee as a Hyperswarm connection. This script is the demonstration.

const net = require('net')
const path = require('path')
const fs = require('fs')
const { receiveFile, acceptStream, generateCode, resolveCode } = require('@ad-hal/engine')

const { createProgressReporter } = require('./progress')
const { installCancelHandler } = require('./signals')
const { describeError } = require('./report')
const { createConsent } = require('./consent')
const { usage } = require('./usage')

async function main () {
  const argv = process.argv.slice(2)
  const [portArg, outputDirArg] = argv.filter((a) => !a.startsWith('--'))
  const port = portArg === undefined ? NaN : Number(portArg)

  if (argv.includes('--help')) {
    console.log(usage('receive'))
    return
  }
  if (Number.isNaN(port)) {
    console.error(usage('receive'))
    process.exitCode = 1
    return
  }

  const outputDir = outputDirArg ? path.resolve(outputDirArg) : process.cwd()
  await fs.promises.mkdir(outputDir, { recursive: true })

  const { code, nameplate, secret } = resolveCode(generateCode())
  const cancel = installCancelHandler({ label: 'receive' })
  const consent = createConsent({ yes: argv.includes('--yes'), label: 'receive', signal: cancel.signal })

  const server = net.createServer((socket) => {
    // ONE CONNECTION, ONE ATTEMPT. The server stops accepting as soon as
    // the first peer arrives, and a failed handshake ends the drop rather
    // than waiting for another try. That is an attempt cap of one --
    // tighter than the swarm path's (PROTOCOL.md section 6), and right for
    // a single-shot demo where there is no DHT noise to tolerate.
    server.close()
    console.log(`[receive] connection from ${socket.remoteAddress}:${socket.remotePort}`)
    // acceptStream and receiveFile each attach an 'error' listener of
    // their own and report through it. This sink covers the gap between
    // them, and teardown after, where an unheard reset would otherwise
    // crash the process rather than be reported.
    socket.on('error', () => {})
    const progress = createProgressReporter({ label: 'receive' })

    acceptStream(socket, { nameplate, secret, signal: cancel.signal })
      .then(({ pending, sendKey, receiveKey, caps }) => {
        console.log('[receive] handshake confirmed; the channel is sealed')
        return receiveFile(socket, outputDir, {
          sendKey,
          receiveKey,
          caps,
          pending,
          signal: cancel.signal,
          onProgress: progress.onProgress,
          onOffer: consent.onOffer,
          onManifest: (manifest, { resumeFrom }) => {
            console.log(`[receive] manifest: ${manifest.name} (${manifest.size === null ? 'streamed, size unknown until it ends' : `${manifest.size} bytes`})`)
            if (resumeFrom > 0) console.log(`[receive] resuming from byte ${resumeFrom} of an earlier, interrupted attempt`)
          }
        })
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
        if (result.published === 'check-then-rename') {
          console.log('[receive] note: no hard links on this filesystem, so the file was landed with a racy check-then-rename (see engine/src/transfer.js, publish)')
        }
      }).catch((err) => {
        consent.close()
        progress.close()
        console.error(`[receive] ${describeError(err)}`)
        if (!cancel.cancelled()) process.exitCode = 1
        socket.destroy()
      }).finally(() => {
        consent.close()
        cancel.dispose()
      })
  })

  // A cancel before anyone connects has nothing else listening for it:
  // acceptStream and receiveFile watch the signal, but neither exists yet.
  // Without this the first Ctrl-C or SIGTERM aborted a signal nobody held
  // and the process sat on its port until a second one -- which is how a
  // test's `kill()` on a receiver whose sender had failed left both the
  // receiver and the test runner alive indefinitely.
  cancel.signal.addEventListener('abort', () => {
    if (!server.listening) return
    console.error('[receive] cancelled before a sender connected')
    server.close()
    cancel.dispose()
  }, { once: true })

  server.on('error', (err) => {
    console.error('[receive] server error:', err.message)
    process.exitCode = 1
  })

  server.listen(port, '127.0.0.1', () => {
    const address = /** @type {import('net').AddressInfo} */ (server.address())
    console.log(`[receive] listening on 127.0.0.1:${address.port}`)
    console.log(`[receive] code: ${code}`)
  })
}

main()
