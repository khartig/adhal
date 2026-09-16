'use strict'
// Diagnostic: is a topic announce visible from THIS machine, and can we
// reach the peer that announced it?
//
// Separates the two failures that both look like "timed out looking for a
// peer" in swarm-send.js:
//   (a) the announce is not visible here at all  -> discovery problem
//   (b) the announce is visible but connect fails -> holepunch/NAT problem
//
// Usage: node scratch-lookup.js <topic-hex> [--connect]
//
// WARNING: --connect is destructive to a live receiver. Dialing its public
// key produces a real connection, which satisfies acceptOnce's "first peer
// wins" and hands swarm-receive.js a socket that never sends a manifest.
// The receiver then errors out and exits. Restart the receiver after any
// --connect probe, and never point --connect at a receiver you are about
// to send to.

const DHT = require('hyperdht')
const os = require('node:os')

const topicHex = process.argv[2]
const tryConnect = process.argv.includes('--connect')
if (!topicHex || topicHex.length !== 64) {
  console.error('Usage: scratch-lookup.js <topic-hex> [--connect]')
  process.exit(1)
}

const topic = Buffer.from(topicHex, 'hex')
const t0 = Date.now()
const log = (...a) => console.log(`+${((Date.now() - t0) / 1000).toFixed(1)}s`, ...a)

async function main () {
  // Print which machine this actually ran on -- when the same probe is run
  // on two boxes, it's otherwise easy to misattribute output.
  log(`host machine: ${os.hostname()} (${os.platform()}/${os.arch()}) node ${process.version}`)

  const node = new DHT()
  await node.ready()
  // node.host is the public address the DHT itself observed for us, which
  // is the number that matters here -- no curl or firewall tooling needed.
  // If two machines report the same host, they are behind the same NAT and
  // the punch between them needs router hairpinning.
  log(`dht ready: host=${node.host}:${node.port} firewalled=${node.firewalled}`)

  log(`looking up topic ${topicHex.slice(0, 16)}...`)
  /** @type {Array<{ publicKey: Buffer, relayAddresses: Array<object> }>} */
  const found = []
  const seen = new Set()

  for await (const result of node.lookup(topic)) {
    for (const peer of result.peers || []) {
      const key = peer.publicKey.toString('hex')
      if (seen.has(key)) continue
      seen.add(key)
      found.push(peer)
      log(`FOUND announce by ${key.slice(0, 16)}... ` +
        `relays=${(peer.relayAddresses || []).length}`)
      for (const r of peer.relayAddresses || []) {
        log(`   relay addr: ${r.host}:${r.port}`)
      }
    }
  }

  log(`lookup finished: ${found.length} peer(s) announced under this topic`)

  if (found.length === 0) {
    log('>> DIAGNOSIS: the announce is NOT visible from here.')
    log('   Either the announcing process is no longer running, or its')
    log('   announce never propagated. Check the receiver is still alive.')
  } else if (tryConnect) {
    for (const peer of found) {
      log(`dialing ${peer.publicKey.toString('hex').slice(0, 16)}...`)
      const socket = node.connect(peer.publicKey)
      const outcome = await new Promise((resolve) => {
        const timer = setTimeout(() => resolve('TIMEOUT after 20s'), 20000)
        socket.on('open', () => { clearTimeout(timer); resolve('CONNECTED') })
        socket.on('error', (err) => { clearTimeout(timer); resolve(`ERROR ${err.message}`) })
      })
      log(`   -> ${outcome}`)
      socket.destroy()
      if (outcome === 'CONNECTED') {
        log('>> DIAGNOSIS: discovery AND connect both work. The failure is')
        log('   in the hyperswarm/app layer, not the DHT.')
      } else {
        log('>> DIAGNOSIS: announce is visible but the connection failed.')
        log('   This is a holepunch/NAT problem -- what the relay (item 9) fixes.')
      }
    }
  } else {
    log('   (re-run with --connect to test whether the peer is dialable)')
  }

  await node.destroy()
}

main().catch((err) => {
  console.error('failed:', err.message)
  process.exit(1)
})
