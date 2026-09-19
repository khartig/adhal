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
// --connect is now safe to point at a live receiver. It used to be
// destructive: a raw dial satisfied acceptOnce's "first peer wins", handed
// swarm-receive.js a socket that never sent a manifest, and wedged it.
// Since the readiness handshake landed (see engine/src/swarm.js), a dial
// that never answers the receiver's challenge is logged and discarded, and
// the receiver stays joined and keeps waiting. The code proof's code proof closes
// the door the rest of the way: a dial armed with nothing but the topic --
// which is exactly what walking the DHT gives you, and what this tool
// demonstrates -- can no longer complete the handshake at all.
//
// So a CONNECTED result here no longer proves a *drop* would work -- it
// proves discovery and hole punching work. If this succeeds while
// swarm-send.js still times out, the failure is above the DHT, and the
// sender's own timeout message will now say so.

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
        log('   This is a holepunch/NAT problem -- what a relay would fix.')
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
