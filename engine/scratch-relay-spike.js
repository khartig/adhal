'use strict'

// SPIKE, not shipping code: does Holepunch's blind-relay, through
// hyperdht's own relayThrough, carry an Adhal drop between two peers whose
// hole punch fails, and how does it stand against THREAT-MODEL.md section
// 8's merge gates? Runs on an isolated hyperdht testnet; nothing touches
// the public DHT.
//
//   node engine/scratch-relay-spike.js
//
// Each scenario prints one JSON line. The swarm is built the way
// createSwarm builds it (fresh key pair, 16 parallel dials, an 'error'
// sink), plus a relayThrough that only answers when Hyperswarm forces it:
// that is, on the retry after a punch-class failure, never because this
// side's NAT is randomized.

const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const crypto = require('node:crypto')
const Hyperswarm = require('hyperswarm')
const HyperDHT = require('hyperdht')
const createTestnet = require('hyperdht/testnet')
const NoiseWrap = require('hyperdht/lib/noise-wrap.js')
const BlindRelay = require(require.resolve('blind-relay', { paths: [path.dirname(require.resolve('hyperdht'))] }))
const {
  acceptOnce, connectOnce, sendFile, receiveFile, closeAfterResult,
  generateCode, splitCode, topicFromNameplate, KNOWN_CAPS
} = require('./src')

const SIZE = 8 * 1024 * 1024

/** A blind-relay server on the testnet, recording what it is shown. */
async function startRelay (bootstrap) {
  const dht = new HyperDHT({ bootstrap })
  const relay = new BlindRelay.Server({
    createStream: (/** @type {any} */ opts) => dht.createRawStream({ ...opts, framed: true })
  })
  /** @type {any[]} */
  const pairs = []
  /** @type {any[]} */
  const links = []
  const server = dht.createServer({ holepunch: () => true }, (/** @type {any} */ socket) => {
    socket.on('error', () => {})
    const session = relay.accept(socket, { id: socket.remotePublicKey })
    session.on('error', () => {})
    session.on('pair', (/** @type {boolean} */ isInitiator, /** @type {Buffer} */ token, /** @type {any} */ stream) => {
      pairs.push({ isInitiator, token: token.toString('hex'), peer: socket.remotePublicKey.toString('hex').slice(0, 8) })
      links.push(stream)
    })
  })
  const keyPair = HyperDHT.keyPair()
  await server.listen(keyPair)
  const address = server.address()
  return {
    publicKey: keyPair.publicKey,
    port: address && address.port,
    relay,
    pairs,
    links,
    async destroy () { await relay.close().catch(() => {}); await server.close(); await dht.destroy() }
  }
}

/**
 * A swarm as createSwarm makes it, plus the relay rule under test.
 * @param {any} bootstrap
 * @param {{ relay?: Buffer | null, failPunch?: boolean, refuseRelay?: boolean }} opts
 */
function makeSwarm (bootstrap, { relay = null, failPunch = false, refuseRelay = false }) {
  /** @type {any[]} */
  const asked = []
  const swarm = new Hyperswarm({
    keyPair: HyperDHT.keyPair(),
    maxParallel: 16,
    // Ephemeral, as a NAT'd peer is: otherwise on a 5-node testnet the
    // peer's own node sits in the routing table, the handshake reaches it
    // directly (hyperdht's `direct`), and it connects without a punch.
    ...(failPunch ? { dht: new HyperDHT({ bootstrap, ephemeral: true }) } : { bootstrap }),
    ...(relay ? { relayThrough: (/** @type {boolean} */ force) => { asked.push(!!force); return force ? relay : null } } : {})
  })
  swarm.on('connection', (/** @type {any} */ s) => { s.on('error', () => {}) })
  // On a testnet every node is unfirewalled on localhost, so the dialed
  // side answers FIREWALL.OPEN and no punch is attempted at all. Reporting
  // no remote address is how a firewalled node looks to hyperdht (dht-rpc
  // remoteAddress()), and it sends both sides down the punch path.
  if (failPunch) swarm.dht.remoteAddress = () => null
  // The candidate wrapper for refusing a relay the PEER names: clear
  // relayThrough from the peer's decoded handshake payload, on both the
  // dialed side (the server's createHandshake) and the dialing side
  // (dht.connect's createHandshake, below).
  /** @type {any} */
  let createHandshake
  if (refuseRelay) {
    createHandshake = (/** @type {any} */ keyPair, /** @type {any} */ remotePublicKey) => {
      const h = new NoiseWrap(keyPair, remotePublicKey)
      const recv = h.recv.bind(h)
      h.recv = (/** @type {any} */ buf) => {
        const payload = recv(buf)
        if (payload && payload.relayThrough) { refusedRelays.push(1); payload.relayThrough = null }
        return payload
      }
      return h
    }
    swarm.server.createHandshake = createHandshake
  }
  /** @type {number[]} */
  const refusedRelays = []
  /** @type {string[]} */
  const dialErrors = []
  /** @type {string[]} */
  const punchHook = []
  const connect = swarm.dht.connect.bind(swarm.dht)
  swarm.dht.connect = (/** @type {any} */ key, /** @type {any} */ o = {}) => {
    // Forcing the failure: refuse to punch, skip the LAN shortcut, and skip
    // fast-open, whose first probe to the server's address gets through on
    // localhost before the holepunch hook is ever consulted.
    // Never the relay itself: the peers reach it with dht.connect too, and it
    // must be reachable without a punch.
    const toRelay = relay && Buffer.isBuffer(key) && key.equals(relay)
    if (createHandshake) o = { ...o, createHandshake }
    const conn = connect(key, failPunch && !toRelay ? { ...o, holepunch: (/** @type {number} */ rf, /** @type {number} */ lf) => { punchHook.push(`${rf}/${lf}`); return false }, localConnection: false, fastOpen: false } : o)
    conn.on('error', (/** @type {any} */ err) => { dialErrors.push(`${err && err.code}:${err && err.message}`) })
    return conn
  }
  return { swarm, asked, dialErrors, punchHook, refusedRelays }
}

async function scenario (name, bootstrap, { senderRelay = false, receiverRelay = false, failPunch = false, cutAfterBytes = 0, receiverRefuses = false }) {
  const relay = await startRelay(bootstrap)
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'adhal-relay-spike-'))
  const src = path.join(dir, 'src.bin')
  const out = path.join(dir, 'out')
  await fs.promises.mkdir(out)
  const bytes = crypto.randomBytes(SIZE)
  await fs.promises.writeFile(src, bytes)

  const rx = makeSwarm(bootstrap, { relay: receiverRelay ? relay.publicKey : null, failPunch, refuseRelay: receiverRefuses })
  const tx = makeSwarm(bootstrap, { relay: senderRelay ? relay.publicKey : null, failPunch })
  const code = generateCode()
  const { secret, nameplate } = splitCode(code)
  const topic = topicFromNameplate(nameplate)
  const started = Date.now()
  /** @type {any} */
  const result = { name, senderRelay, receiverRelay, failPunch }
  /** @type {NodeJS.Timeout | null} */
  let sampler = null
  try {
    const accepting = acceptOnce(rx.swarm, topic, { secret, nameplate, timeout: 60000, caps: KNOWN_CAPS })
    const connecting = connectOnce(tx.swarm, topic, { secret, nameplate, timeout: 60000 })
    const [a, c] = await Promise.all([accepting, connecting])
    result.pairedMs = Date.now() - started
    const raw = c.socket.rawStream
    result.senderRemotePort = raw && raw.remotePort
    result.relayPort = relay.port
    result.viaRelay = !!raw && raw.remotePort === relay.port

    // How a byte cap could be enforced: do UDX's counters on the relay's
    // own streams move while relayTo forwards in native code?
    /** @type {number[]} */
    const samples = []
    let cut = false
    sampler = setInterval(() => {
      const seen = relay.links.reduce((n, s) => n + (s.bytesReceived || 0), 0)
      samples.push(seen)
      if (cutAfterBytes && !cut && seen >= cutAfterBytes) {
        cut = true
        result.cutAtBytes = seen
        for (const s of relay.links) s.destroy()
      }
    }, 50)

    const [sent, received] = await Promise.allSettled([
      sendFile(c.socket, src, { sendKey: c.sendKey, receiveKey: c.receiveKey, caps: c.caps, pending: c.pending }),
      receiveFile(a.socket, out, { sendKey: a.sendKey, receiveKey: a.receiveKey, caps: a.caps, pending: a.pending })
        .then(async (r) => { await closeAfterResult(a.socket).catch(() => {}); return r })
    ])
    result.sent = sent.status === 'fulfilled' ? 'ok' : (sent.reason.code || sent.reason.message)
    result.received = received.status === 'fulfilled' ? 'ok' : (received.reason.code || received.reason.message)
    if (received.status === 'fulfilled') {
      result.hashOk = received.value.sha256 === crypto.createHash('sha256').update(bytes).digest('hex')
    }
    result.relayCounterSamples = [samples[0], samples[Math.floor(samples.length / 2)], samples[samples.length - 1]]
  } catch (err) {
    result.error = /** @type {any} */ (err).code || String(err)
  } finally {
    if (sampler) clearInterval(sampler)
    result.totalMs = Date.now() - started
    result.relayStats = { matched: relay.relay.stats.pairings.matched, requested: relay.relay.stats.pairings.requested, pending: relay.relay.stats.pairings.pending, streams: relay.relay.stats.streams.opened }
    result.tokens = relay.pairs.map((p) => `${p.isInitiator ? 'I' : 'R'}:${p.token.slice(0, 12)}`)
    result.senderAsked = tx.asked
    result.receiverAsked = rx.asked
    result.senderDialErrors = [...new Set(tx.dialErrors)]
    result.receiverDialErrors = [...new Set(rx.dialErrors)]
    result.punchHook = { tx: tx.punchHook.length, rx: rx.punchHook.length }
    result.receiverRefusedRelays = rx.refusedRelays.length
    await Promise.allSettled([rx.swarm.destroy(), tx.swarm.destroy()])
    await relay.destroy()
    fs.rmSync(dir, { recursive: true, force: true })
  }
  console.log(JSON.stringify(result))
}

async function main () {
  const testnet = await createTestnet(5)
  const only = process.argv[2]
  /** @type {Array<[string, any]>} */
  const scenarios = [
    ['gate6-direct-works-relay-unused', { senderRelay: true, receiverRelay: true }],
    ['punch-fails-no-relay', { failPunch: true }],
    ['punch-fails-sender-relay', { senderRelay: true, failPunch: true }],
    ['punch-fails-receiver-relay', { receiverRelay: true, failPunch: true }],
    ['punch-fails-both-relay', { senderRelay: true, receiverRelay: true, failPunch: true }],
    ['refuse-receiver-strips-peer-relay', { senderRelay: true, failPunch: true, receiverRefuses: true }],
    ['refuse-control-wrapper-without-relay', { receiverRefuses: true }],
    ['gate5-relay-cuts-at-2MiB', { senderRelay: true, failPunch: true, cutAfterBytes: 2 * 1024 * 1024 }]
  ]
  try {
    for (const [name, opts] of scenarios) {
      if (only && !name.includes(only)) continue
      await scenario(name, testnet.bootstrap, opts)
    }
  } finally {
    await testnet.destroy()
  }
}

main().catch((err) => { console.error(err); process.exit(1) })
