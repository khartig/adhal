'use strict'
// Diagnostic: reproduce swarm-send.js's join with full visibility into
// Hyperswarm's peer bookkeeping, to see whether it discovers the peer at
// all and what it decides to do about it.
//
// Raw dht.lookup()+connect() already succeeds on this path, so if this
// fails the problem is in the hyperswarm layer, not the DHT.
//
// Usage: node scratch-hs-dial.js <topic-hex> [--client-only]
//
// WARNING: destructive to a live swarm-receive.js -- a successful
// connection satisfies its acceptOnce and it will exit. Restart it after.

const Hyperswarm = require('hyperswarm')
const os = require('node:os')

const topicHex = process.argv[2]
const clientOnly = process.argv.includes('--client-only')
if (!topicHex || topicHex.length !== 64) {
  console.error('Usage: scratch-hs-dial.js <topic-hex> [--client-only]')
  process.exit(1)
}

const topic = Buffer.from(topicHex, 'hex')
const t0 = Date.now()
const log = (...a) => console.log(`+${((Date.now() - t0) / 1000).toFixed(1)}s`, ...a)

function dumpPeers (swarm) {
  if (swarm.peers.size === 0) return log('  peers: (none discovered)')
  for (const [id, info] of swarm.peers) {
    log(`  peer ${id.slice(0, 12)}: ` +
      `attempts=${info.attempts} banned=${info.banned} proven=${info.proven} ` +
      `queued=${info._queued} tried=${info.tried} ` +
      `relays=${(info.relayAddresses || []).length}`)
  }
}

async function main () {
  log(`host machine: ${os.hostname()} (${os.platform()})`)
  const swarm = new Hyperswarm()

  await swarm.dht.ready()
  log(`dht ready: host=${swarm.dht.host}:${swarm.dht.port} firewalled=${swarm.dht.firewalled}`)
  log(`joining ${clientOnly ? 'client-only' : 'server+client (the swarm-send.js default)'}`)

  swarm.on('connection', (socket, peerInfo) => {
    log(`*** CONNECTION from ${peerInfo.publicKey.toString('hex').slice(0, 12)} ***`)
    socket.on('error', (err) => log(`socket error: ${err.message}`))
    socket.once('data', (chunk) => log(`received ${chunk.length} byte(s) -- READY handshake`))
  })

  const discovery = clientOnly
    ? swarm.join(topic, { server: false, client: true })
    : swarm.join(topic)

  discovery.flushed().then(
    () => log('discovery flushed'),
    (err) => log(`discovery flush failed: ${err.message}`)
  )

  const interval = setInterval(() => {
    log(`tick: connections=${swarm.connections.size} peers=${swarm.peers.size} connecting=${swarm.connecting}`)
    dumpPeers(swarm)
  }, 15000)

  setTimeout(async () => {
    clearInterval(interval)
    log('giving up after 90s')
    dumpPeers(swarm)
    await swarm.destroy()
    process.exit(0)
  }, 90000)
}

main().catch((err) => {
  console.error('failed:', err.message)
  process.exit(1)
})
