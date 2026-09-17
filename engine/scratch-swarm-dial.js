'use strict'
// Diagnostic for "the DHT works but a drop never connects".
//
// engine/scratch-lookup.js answers questions about the DHT: is the announce
// visible, is the peer dialable with a raw hyperdht connect. When it says
// CONNECTED and swarm-send.js still times out having logged no candidates,
// the gap is Hyperswarm itself -- between discovery finding a record and a
// 'connection' event coming out the other side -- and nothing in that gap
// is observable by default.
//
// In particular, Hyperswarm SWALLOWS CLIENT DIAL ERRORS. In
// hyperswarm/index.js `_connect`, the only 'error' handler on an outbound
// connection sets peerInfo.forceRelaying and returns; the error is never
// logged, re-emitted, or counted. A dial that fails for any reason is
// therefore completely silent, which is why a failing sender prints
// nothing but its eventual timeout.
//
// This tool wraps swarm.dht.connect to print those errors, reports the
// counters Hyperswarm does keep (swarm.stats, swarm.peers, PeerInfo state),
// and runs an independent raw dial to each discovered peer from a second
// DHT node in the same process -- so "raw dial works, Hyperswarm dial
// fails" is observed at one instant on one network path rather than
// inferred from two runs minutes apart.
//
// Usage: node scratch-swarm-dial.js <topic-hex> [--seconds 60]
//
// Non-destructive: it never answers the receiver's ACK, so a live
// swarm-receive.js logs it as a dropped candidate and keeps waiting.

const DHT = require('hyperdht')
const os = require('node:os')
const { createSwarm } = require('./src/swarm')

const topicHex = process.argv[2]
const secondsFlag = process.argv.indexOf('--seconds')
const RUN_SECONDS = secondsFlag === -1 ? 60 : Number(process.argv[secondsFlag + 1])

if (!topicHex || !/^[0-9a-f]{64}$/i.test(topicHex)) {
  console.error('Usage: scratch-swarm-dial.js <topic-hex> [--seconds 60]')
  console.error('Get the topic from: node cli/src/code.js <six-word-code>')
  process.exit(1)
}

const topic = Buffer.from(topicHex, 'hex')
const t0 = Date.now()
const log = (...a) => console.log(`+${((Date.now() - t0) / 1000).toFixed(1)}s`, ...a)
const short = (buf) => buf.toString('hex').slice(0, 12)

async function main () {
  log(`host machine: ${os.hostname()} (${os.platform()}/${os.arch()}) node ${process.version}`)

  const swarm = createSwarm()
  await swarm.dht.ready()
  log(`hyperswarm dht ready: host=${swarm.dht.host}:${swarm.dht.port} firewalled=${swarm.dht.firewalled}`)
  log(`my swarm key: ${short(swarm.keyPair.publicKey)}, maxParallel=${swarm.maxParallel}`)
  log(`topic: ${topicHex}`)

  // --- expose the errors hyperswarm discards -------------------------------
  const rawDialErrors = []
  const origConnect = swarm.dht.connect.bind(swarm.dht)
  swarm.dht.connect = (publicKey, opts = {}) => {
    const relays = opts.relayAddresses ? opts.relayAddresses.length : 0
    log(`>> hyperswarm dialing ${short(publicKey)} (relayAddresses=${relays}, relayThrough=${!!opts.relayThrough})`)
    const socket = origConnect(publicKey, opts)
    socket.on('error', (err) => {
      rawDialErrors.push(err.code || err.message)
      log(`   !! DIAL ERROR ${short(publicKey)}: ${err.code || '(no code)'} -- ${err.message}`)
      log('      (hyperswarm/index.js _connect discards this; it is only visible here)')
    })
    socket.on('open', () => log(`   dial OPEN to ${short(publicKey)}`))
    socket.on('close', () => log(`   dial closed to ${short(publicKey)}`))
    return socket
  }

  swarm.on('connection', (socket, peerInfo) => {
    log(`*** CONNECTION from ${short(peerInfo.publicKey)} (client=${peerInfo.client}) ***`)
    log('    a real drop would now exchange READY/ACK; this tool deliberately does not')
    socket.on('error', () => {})
    // Report what the receiver sends us, which should be READY (0x01).
    socket.once('data', (chunk) => {
      log(`    first byte from peer: 0x${chunk[0].toString(16)} (READY is 0x1)`)
    })
  })

  // --- join exactly as the sender does -------------------------------------
  const discovery = swarm.join(topic)
  const refresher = setInterval(() => {
    discovery.refresh({ client: true, server: true }).catch(() => {})
  }, 4000)

  discovery.flushed().then(
    () => log('our own announce flushed (we are now discoverable too)'),
    (err) => log(`announce failed: ${err.message}`)
  )

  // --- independent raw dial, same process, same moment ---------------------
  const probe = new DHT()
  await probe.ready()
  log(`probe dht ready: host=${probe.host}:${probe.port} firewalled=${probe.firewalled}`)

  const rawTested = new Set()
  async function rawDial (publicKey) {
    const key = publicKey.toString('hex')
    if (rawTested.has(key)) return
    rawTested.add(key)
    log(`-- raw hyperdht dial to ${short(publicKey)} (control, bypasses hyperswarm)`)
    const socket = probe.connect(publicKey)
    socket.on('error', (err) => log(`   raw dial FAILED: ${err.code || err.message}`))
    socket.once('open', () => {
      log(`   raw dial CONNECTED to ${short(publicKey)}`)
      log('   >> if hyperswarm never opens but this does, the fault is in hyperswarm, not the network')
      socket.destroy()
    })
  }

  // --- report the counters hyperswarm does keep ----------------------------
  let lastSummary = ''
  const poll = setInterval(() => {
    const s = swarm.stats.connects
    const summary = `peers=${swarm.peers.size} connecting=${swarm.connecting} connections=${swarm.connections.size} ` +
      `client(attempted=${s.client.attempted} opened=${s.client.opened} closed=${s.client.closed}) ` +
      `server(opened=${s.server.opened} closed=${s.server.closed}) updates=${swarm.stats.updates}`
    if (summary !== lastSummary) {
      log(summary)
      lastSummary = summary
    }

    for (const peerInfo of swarm.peers.values()) {
      log(`   peer ${short(peerInfo.publicKey)}: attempts=${peerInfo.attempts} banned=${peerInfo.banned} ` +
        `proven=${peerInfo.proven} queued=${peerInfo.queued} tried=${peerInfo.tried} ` +
        `priority=${peerInfo.priority} relays=${peerInfo.relayAddresses ? peerInfo.relayAddresses.length : 0}`)
      rawDial(peerInfo.publicKey)
    }
  }, 3000)

  setTimeout(async () => {
    clearInterval(poll)
    clearInterval(refresher)
    const s = swarm.stats.connects

    log('')
    log('=== DIAGNOSIS ===')
    if (swarm.peers.size === 0) {
      log('Hyperswarm never surfaced ANY peer for this topic.')
      log('Discovery is the problem, not the dial. If scratch-lookup.js finds')
      log('an announce for the same topic, hyperswarm\'s lookup is not seeing')
      log('what a raw lookup sees -- suspect the topic differing between the')
      log('two sides, or an announce that expired between the two runs.')
    } else if (s.client.attempted === 0) {
      log(`Hyperswarm found ${swarm.peers.size} peer(s) but attempted ZERO dials.`)
      log('The dial was gated, not failed. In hyperswarm/index.js that means')
      log('_shouldConnect() or _connect() refused: check banned/proven above,')
      log('maxParallel, maxClientConnections, or _allConnections already')
      log('holding this key.')
    } else if (s.client.opened === 0) {
      log(`Hyperswarm attempted ${s.client.attempted} dial(s), none opened.`)
      log(`Dial errors seen: ${rawDialErrors.length ? rawDialErrors.join(', ') : '(none surfaced)'}`)
      log('These are the errors hyperswarm normally hides. If the raw control')
      log('dial above CONNECTED while these failed, the difference is in how')
      log('hyperswarm dials (its own keyPair, relayAddresses from the announce,')
      log('relayThrough) -- not in network reachability.')
    } else {
      log(`Hyperswarm opened ${s.client.opened} client connection(s).`)
      log('The transport layer is fine; a failing drop is then above this,')
      log('in the READY/ACK handshake or the transfer itself.')
    }

    await swarm.destroy()
    await probe.destroy()
    process.exit(0)
  }, RUN_SECONDS * 1000)

  log(`running for ${RUN_SECONDS}s...`)
}

main().catch((err) => {
  console.error('failed:', err.message)
  process.exit(1)
})
