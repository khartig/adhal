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
// Usage: node scratch-swarm-dial.js <topic-hex | code> [--seconds 60] [--connect-once]
//
// A 64-hex topic is enough for the default mode, which only observes
// dials. --connect-once needs the CODE, not just the topic: the real
// connectOnce now has to prove it knows the code (item 4,
// engine/src/proof.js), and the topic alone -- which is public once the
// receiver announces -- cannot produce that proof. That is the point of
// the proof, so this tool is not given a way around it.
//
// --connect-once replaces this tool's own bare 'connection' listener with
// the REAL connectOnce() from engine/src/swarm.js, wired to the same
// logging. That is the apples-to-apples comparison: without the flag, a
// success proves only that Hyperswarm can reach the peer; with it, a
// success means the engine's own code path completed the readiness
// handshake and the code proof. If the plain run connects and the
// --connect-once run does not, the fault is in our code, and this narrows
// it to connectOnce without needing another cross-network round trip.
//
// Pair it with `node engine/scratch-serve.js <code>` on the far side,
// which reports whether the handshake actually completed.
//
// Non-destructive by default: without --connect-once it never answers the
// receiver's challenge, so a live swarm-receive.js logs it as a dropped
// candidate and keeps waiting.

const DHT = require('hyperdht')
const os = require('node:os')
const { createSwarm, connectOnce } = require('./src/swarm')
const { resolveCode } = require('./src/resolve-code')
const { dropKey } = require('./src/proof')

const target = process.argv[2]
const secondsFlag = process.argv.indexOf('--seconds')
const RUN_SECONDS = secondsFlag === -1 ? 60 : Number(process.argv[secondsFlag + 1])
const USE_CONNECT_ONCE = process.argv.includes('--connect-once')

if (!target) {
  console.error('Usage: scratch-swarm-dial.js <topic-hex | code> [--seconds 60] [--connect-once]')
  console.error('Get the topic from: node cli/src/code.js <six-word-code>')
  process.exit(1)
}

// Either input works for observing dials; only a code can produce the
// proof --connect-once needs. Told apart by shape, for the reason
// engine/src/resolve-code.js gives: guessing would hash a mistyped code
// into a valid-but-wrong topic and present as a discovery failure.
const isTopicHex = /^[0-9a-f]{64}$/i.test(target)
if (isTopicHex && USE_CONNECT_ONCE) {
  console.error('--connect-once needs the code, not a topic hex: the real')
  console.error('connectOnce must prove it knows the code (engine/src/proof.js),')
  console.error('and the topic is public once the receiver announces it.')
  process.exit(1)
}

const topic = isTopicHex ? Buffer.from(target, 'hex') : resolveCode(target).topic
const key = isTopicHex ? null : dropKey(resolveCode(target).code)
const topicHex = topic.toString('hex')
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

  let handshakeOutcome = 'not attempted'
  let refresher = null

  if (USE_CONNECT_ONCE) {
    // Let the engine's own code own the join, the listener and the
    // handshake, so a failure here is a failure of the real sender.
    log('MODE: using the REAL connectOnce() from engine/src/swarm.js')
    connectOnce(swarm, topic, {
      key,
      timeout: RUN_SECONDS * 1000,
      onCandidate: (info) => log(`   connectOnce candidate ${short(info.publicKey)}, awaiting READY + challenge`),
      onCandidateDropped: (info, reason) => log(`   connectOnce dropped ${short(info.publicKey)} before proving (${reason})`)
    }).then(
      ({ socket, peerInfo }) => {
        handshakeOutcome = 'RESOLVED'
        log(`*** connectOnce RESOLVED with ${short(peerInfo.publicKey)} ***`)
        log('    the engine completed the handshake and the code proof')
        socket.on('error', () => {})
        // end(), not destroy(). connectOnce writes its proof immediately
        // before resolving, and destroy() discards unflushed bytes -- which
        // threw that write away and made the far side report "connection
        // reset by peer" instead of confirming the handshake, defeating the
        // whole point of this mode.
        socket.end()
      },
      (err) => {
        handshakeOutcome = `REJECTED: ${err.message}`
        log(`*** connectOnce REJECTED: ${err.message} ***`)
      }
    )
  } else {
    swarm.on('connection', (socket, peerInfo) => {
      log(`*** CONNECTION from ${short(peerInfo.publicKey)} (client=${peerInfo.client}) ***`)
      log('    a real drop would now exchange the code proof; this tool deliberately does not')
      socket.on('error', () => {})
      // Report what the receiver sends us, which should be READY (0x01).
      socket.once('data', (chunk) => {
        log(`    first byte from peer: 0x${chunk[0].toString(16)} (READY is 0x1)`)
      })
    })

    // --- join exactly as the sender does -----------------------------------
    const discovery = swarm.join(topic)
    refresher = setInterval(() => {
      discovery.refresh({ client: true, server: true }).catch(() => {})
    }, 4000)

    discovery.flushed().then(
      () => log('our own announce flushed (we are now discoverable too)'),
      (err) => log(`announce failed: ${err.message}`)
    )
  }

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
    if (refresher) clearInterval(refresher)
    const s = swarm.stats.connects

    log('')
    log('=== DIAGNOSIS ===')
    if (USE_CONNECT_ONCE) {
      log(`connectOnce outcome: ${handshakeOutcome}`)
      log('Compare against a run WITHOUT --connect-once: if that one opens a')
      log('connection and this one does not, the fault is in our engine code,')
      log('not in Hyperswarm or the network.')
      log('')
    }
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
