#!/usr/bin/env node
'use strict'

// The conformance adapter for @ad-hal/engine: the contract in
// conformance/src/harness.js (and docs/CONFORMANCE.md), implemented with
// the engine's own stream handshake and transfer functions.
//
//   engine.js receive --connect <host:port> --dir <dir> [--cancel-after <bytes>]
//   engine.js send    --connect <host:port> --file <path> [--stream] [--cancel-after <bytes>]
//
// The code arrives in ADHAL_CONFORMANCE_NAMEPLATE and
// ADHAL_CONFORMANCE_SECRET. One connection, one attempt: this is the
// loopback CLIs' shape (cli/src/send.js, receive.js) without the prompt,
// the progress bar, or the human-facing report, so that what reaches the
// harness is the engine and nothing the CLI adds around it.
//
// THE OUTCOME LINE. Exactly one JSON line on stdout, as the process ends:
// {"ok":true} or {"ok":false,"code":"..."}, where the code is the
// engine's own `.code`. Nothing else is written to stdout; diagnostics go
// to stderr, where the harness quotes them when a scenario fails.
//
// --cancel-after N cancels locally once the transfer has moved at least N
// bytes, through the same AbortSignal the CLIs' Ctrl-C handler uses, so the
// CANCEL the harness sees is the one a person's interrupt would send.

const net = require('node:net')
const fs = require('node:fs')
const path = require('node:path')
const { acceptStream, connectStream, receiveFile, sendFile, sendStream, closeAfterResult } = require('@ad-hal/engine')

/** @param {string[]} argv */
function parse (argv) {
  const [role, ...rest] = argv
  /** @type {Record<string, string | true>} */
  const flags = {}
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]
    if (!a.startsWith('--')) throw new Error(`unexpected argument ${a}`)
    const key = a.slice(2)
    if (key === 'stream') flags[key] = true
    else flags[key] = rest[++i]
  }
  return { role, flags }
}

/** @type {net.Socket | null} */
let socket = null

/** @param {any} outcome */
function finish (outcome) {
  process.stdout.write(`${JSON.stringify(outcome)}\n`)
  process.exitCode = outcome.ok ? 0 : 1
}

// HOW THE CONNECTION IS LET GO, which on plain TCP decides whether the last
// frame arrives. A socket destroyed with unread bytes in its receive
// buffer closes with a RST, and a RST lets the peer's stack discard what
// it had received and not yet delivered -- the CANCEL or RESULT this side
// has just written among it. The harness measured that: 3 of 60 receiver
// cancels lost their CANCEL when this adapter destroyed at once.
// writeFlushed in engine/src/transfer.js says the same from the engine's
// side ("neither caller destroys the socket right after"), and the CLIs
// wait accordingly.
//
// So the adapter does what they do. After a successful receive,
// closeAfterResult, as cli/src/swarm-receive.js does. Otherwise end the
// write side, keep reading so nothing is left unread, and wait for the
// peer's close before destroying, bounded: 5 s after a send, as
// cli/src/swarm-send.js waits, and 2 s after a failure.
/** @param {net.Socket} s @param {number} ms */
function lingerThenDestroy (s, ms) {
  return new Promise((resolve) => {
    if (s.destroyed) return resolve(undefined)
    const timer = setTimeout(() => { s.destroy(); resolve(undefined) }, ms)
    s.once('close', () => { clearTimeout(timer); resolve(undefined) })
    s.resume()
    s.end()
  })
}

async function main () {
  const { role, flags } = parse(process.argv.slice(2))
  const nameplate = process.env.ADHAL_CONFORMANCE_NAMEPLATE
  const secret = process.env.ADHAL_CONFORMANCE_SECRET
  if (!nameplate || !secret) throw new Error('ADHAL_CONFORMANCE_NAMEPLATE and ADHAL_CONFORMANCE_SECRET must be set')
  const [host, port] = String(flags.connect).split(':')
  const cancelAfter = flags['cancel-after'] === undefined ? null : Number(flags['cancel-after'])

  socket = net.connect({ host, port: Number(port) })
  // acceptStream/connectStream and the transfer each attach their own
  // 'error' listener; this covers the gap between them, as the loopback
  // CLIs' does.
  socket.on('error', () => {})
  await new Promise((resolve, reject) => {
    socket.once('connect', resolve)
    socket.once('error', reject)
  })

  const controller = new AbortController()
  const onProgress = (/** @type {{ bytes: number }} */ { bytes }) => {
    if (cancelAfter !== null && bytes >= cancelAfter && !controller.signal.aborted) controller.abort()
  }

  try {
    if (role === 'receive') {
      const dir = path.resolve(String(flags.dir))
      const { pending, sendKey, receiveKey, caps } = await acceptStream(socket, { nameplate, secret })
      await receiveFile(socket, dir, { sendKey, receiveKey, caps, pending, signal: controller.signal, onProgress })
      finish({ ok: true })
      await closeAfterResult(socket)
      socket.destroy()
    } else if (role === 'send') {
      const file = String(flags.file)
      const { pending, sendKey, receiveKey, caps } = await connectStream(socket, { nameplate, secret })
      const options = { sendKey, receiveKey, caps, pending, signal: controller.signal, onProgress }
      if (flags.stream) {
        await sendStream(socket, fs.createReadStream(file), { ...options, name: path.basename(file) })
      } else {
        await sendFile(socket, file, options)
      }
      finish({ ok: true })
      await lingerThenDestroy(socket, 5000)
    } else {
      throw new Error(`role must be send or receive, got ${role}`)
    }
  } catch (err) {
    process.stderr.write(`${err && err.stack ? err.stack : err}\n`)
    finish({ ok: false, code: (err && err.code) || 'ERR_UNKNOWN' })
    await lingerThenDestroy(socket, 2000)
  }
}

main().catch((err) => {
  process.stderr.write(`${err && err.stack ? err.stack : err}\n`)
  finish({ ok: false, code: 'ERR_ADAPTER' })
  if (socket) socket.destroy()
})
