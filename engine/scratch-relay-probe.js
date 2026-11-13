'use strict'

// Diagnostic: can THIS machine reach a relay by its key, over the public DHT?
//
//   node engine/scratch-relay-probe.js <relay-key> [--expect=<host>]
//
// It does what hyperdht does first when it relays a drop: a bare
// `dht.connect(relayKey)` (lib/connect.js, relayConnection). It prints how
// long the connection took, and the address and port the relay answered
// from, so you can check the key belongs to the server you think it does
// (--expect=<host> makes a mismatch fail). It does not pair through the
// relay or send any drop data. For that, see "Trying a relay" in
// docs/TESTING.md.
//
// A failure here explains a relayed drop that never pairs: the key is
// wrong, the relay is not announced on the DHT, or UDP to it is blocked.

const HyperDHT = require('hyperdht')
const { parseRelayKey } = require('./src/relay-key')

const TIMEOUT_MS = 20000

async function main () {
  const keyArg = process.argv.slice(2).find((a) => !a.startsWith('--'))
  const expectArg = process.argv.find((a) => a.startsWith('--expect='))
  const expect = expectArg ? expectArg.slice('--expect='.length) : null
  if (!keyArg) {
    console.error('usage: node engine/scratch-relay-probe.js <relay-key> [--expect=<host>]')
    process.exitCode = 2
    return
  }
  const key = parseRelayKey(keyArg)

  const dht = new HyperDHT()
  const started = Date.now()
  try {
    await dht.fullyBootstrapped()
    const bootstrappedMs = Date.now() - started
    const socket = dht.connect(key)
    socket.on('error', () => {})
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`no connection to the relay within ${TIMEOUT_MS}ms`)), TIMEOUT_MS)
      socket.once('open', () => { clearTimeout(timer); resolve(undefined) })
      socket.once('error', (/** @type {any} */ err) => { clearTimeout(timer); reject(err) })
      socket.once('close', () => { clearTimeout(timer); reject(new Error('the connection closed before it opened')) })
    })
    const raw = socket.rawStream
    // No RTT: UDX has not sampled one yet when the socket opens, so it
    // would read 0. connectMs is the measured round trips, Noise included.
    const result = {
      ok: true,
      bootstrappedMs,
      connectMs: Date.now() - started - bootstrappedMs,
      relayHost: raw && raw.remoteHost,
      relayPort: raw && raw.remotePort,
      thisSideNat: { randomized: dht.randomized, firewalled: dht.firewalled }
    }
    socket.destroy()
    if (expect && result.relayHost !== expect && result.relayHost !== `::ffff:${expect}`) {
      console.log(JSON.stringify({ ...result, ok: false, error: `the relay answered from ${result.relayHost}, not ${expect}` }))
      process.exitCode = 1
      return
    }
    console.log(JSON.stringify(result))
  } catch (err) {
    const e = /** @type {any} */ (err)
    console.log(JSON.stringify({ ok: false, error: `${e.code ? `${e.code}: ` : ''}${e.message}`, ms: Date.now() - started }))
    process.exitCode = 1
  } finally {
    await dht.destroy()
  }
}

main()
