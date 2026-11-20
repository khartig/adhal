'use strict'

// A blind-relay server and a peer whose hole punch always fails, on a
// hyperdht testnet: what a test needs to see a connection relayed.
// Worked out in engine/scratch-relay-spike.js, which has the reasoning for
// each of the three things makePunchFailing does to a peer.
//
// Not in cli/test/ for the reason duplex-pair.js gives.

const path = require('node:path')
const HyperDHT = require('hyperdht')

// Neither is the CLI's own dependency: Hyperswarm is the engine's, and
// blind-relay is hyperdht's. Each is resolved from where it is depended
// on, so a test runs the copy the engine does.
/** @type {any} */
const Hyperswarm = require(require.resolve('hyperswarm', { paths: [path.dirname(require.resolve('@ad-hal/engine'))] }))
const BlindRelay = require(require.resolve('blind-relay', { paths: [path.dirname(require.resolve('hyperdht'))] }))

/**
 * A blind-relay server listening on the testnet.
 *
 * With `tamper`, it is a relay whose operator changed it: blind-relay's own
 * server and pairing protocol, but the bytes it relays pass through
 * `tamper` on their way, so a test can alter them. blind-relay forwards
 * inside udx-native (`relayTo`), where JavaScript never sees a byte, so
 * this replaces `relayTo` on each stream it opens with a forwarder in
 * JavaScript. `fromInitiator` says which end of the pair wrote the chunk.
 *
 * With `takeOver`, it forwards nothing: once both ends of a pair are
 * connected, `takeOver` is handed the two relay-side streams, and the
 * token that paired them, to speak on as a party itself.
 *
 * With `cutAfterBytes`, it relays as blind-relay does, natively, and ends
 * a pairing once either of its streams has received more than that many
 * bytes: a relay with a byte cap of its own, as a relay host can have.
 * udx-native counts natively relayed bytes on the relay's own streams,
 * which is what makes the cap possible without forwarding in JavaScript.
 * `cuts` counts the pairings it ended.
 *
 * @param {Array<{ host: string, port: number }>} bootstrap
 * @param {{
 *   tamper?: (chunk: Buffer, from: { fromInitiator: boolean }) => Buffer,
 *   takeOver?: (legs: { initiator: any, responder: any, token: Buffer }) => void,
 *   cutAfterBytes?: number
 * }} [options]
 */
async function startRelay (bootstrap, { tamper, takeOver, cutAfterBytes } = {}) {
  const dht = new HyperDHT({ bootstrap })
  /** @type {WeakMap<object, boolean>} each relay-side stream's end of the pair */
  const initiatorOf = new WeakMap()
  /** @type {Map<string, any[]>} takeOver's half-arrived pairs, by token */
  const pairing = new Map()
  /** @type {Buffer[]} the token of every pairing, in order: a reused token appears twice */
  const tokens = []
  /** @type {Set<string>} pairings one of whose two sessions has emitted 'pair' */
  const halfEmitted = new Set()
  /** @type {Map<string, any[]>} cutAfterBytes: each pairing's relay-side streams */
  const capped = new Map()
  /** @type {Set<NodeJS.Timeout>} */
  const capTimers = new Set()
  const counters = { cuts: 0 }
  /** @param {string} key @param {any} stream */
  const watchForCap = (key, stream) => {
    const legs = capped.get(key) || []
    legs.push(stream)
    capped.set(key, legs)
    if (legs.length < 2) return
    const timer = setInterval(() => {
      if (!legs.some((leg) => leg.bytesReceived > /** @type {number} */ (cutAfterBytes))) return
      clearInterval(timer)
      capTimers.delete(timer)
      capped.delete(key)
      counters.cuts++
      for (const leg of legs) leg.destroy()
    }, 10)
    capTimers.add(timer)
  }
  const relay = new BlindRelay.Server({
    createStream: (/** @type {any} */ opts) => {
      // framed: hyperdht's secret stream frames its messages, and a
      // pass-through relay keeps the packet boundaries it was given. The
      // tampering relay terminates each leg, and its peers are raw streams.
      const stream = dht.createRawStream(tamper || takeOver ? opts : { ...opts, framed: true })
      if (takeOver) {
        stream.relayTo = () => {}
      } else if (tamper) {
        stream.relayTo = (/** @type {any} */ remote) => {
          // A relay-side stream is connected to its client only when the
          // first packet from that client arrives (blind-relay's firewall
          // hook), and a UDX stream cannot be written before that. Hold
          // what arrives for it until then.
          /** @type {Buffer[] | null} */
          let held = remote.connected ? null : []
          if (held) {
            remote.once('connect', () => {
              for (const chunk of /** @type {Buffer[]} */ (held)) remote.write(chunk)
              held = null
            })
          }
          stream.on('data', (/** @type {Buffer} */ chunk) => {
            const out = tamper(chunk, { fromInitiator: /** @type {boolean} */ (initiatorOf.get(stream)) })
            if (held) held.push(out)
            else remote.write(out)
          })
          stream.on('end', () => {
            if (held) remote.once('connect', () => remote.end())
            else remote.end()
          })
          // A leg that closes takes the other with it, so a peer that hangs
          // up is heard as a hang-up at the far end, not as silence.
          stream.on('close', () => remote.destroy())
        }
      }
      return stream
    }
  })
  /** @type {Set<string>} hex public keys of everyone who opened a session */
  const sessionPeers = new Set()
  const server = dht.createServer((/** @type {any} */ socket) => {
    socket.on('error', () => {})
    sessionPeers.add(socket.remotePublicKey.toString('hex'))
    // The channel id has to be the CLIENT's key: that is what hyperdht's
    // client side opens its blind-relay channel with.
    const session = relay.accept(socket, { id: socket.remotePublicKey })
    session.on('error', () => {})
    // Emitted once both streams are linked and before either can carry a
    // byte: the pair is confirmed to the clients in the same tick.
    session.on('pair', (/** @type {boolean} */ isInitiator, /** @type {Buffer} */ token, /** @type {any} */ stream) => {
      initiatorOf.set(stream, isInitiator)
      // Both ends' sessions emit the pair, one after the other in the same
      // tick, with the one token: count the pairing once.
      const seen = token.toString('hex')
      if (halfEmitted.delete(seen) === false) {
        halfEmitted.add(seen)
        tokens.push(Buffer.from(token))
      }
      if (cutAfterBytes !== undefined) watchForCap(seen, stream)
      if (!takeOver) return
      const key = token.toString('hex')
      const legs = pairing.get(key) || []
      legs[+isInitiator] = stream
      pairing.set(key, legs)
      if (!legs[0] || !legs[1]) return
      pairing.delete(key)
      // A relay-side stream cannot be written until its client's first
      // packet has connected it (see the forwarder above).
      const connected = (/** @type {any} */ leg) => leg.connected ? Promise.resolve() : new Promise((resolve) => leg.once('connect', resolve))
      Promise.all(legs.map(connected)).then(() => takeOver({ initiator: legs[1], responder: legs[0], token }))
    })
  })
  const keyPair = HyperDHT.keyPair()
  await server.listen(keyPair)
  return {
    publicKey: keyPair.publicKey,
    port: /** @type {any} */ (server.address()).port,
    stats: relay.stats,
    sessionPeers,
    tokens,
    get cuts () { return counters.cuts },
    async destroy () {
      for (const timer of capTimers) clearInterval(timer)
      await relay.close().catch(() => {})
      await server.close()
      await dht.destroy()
    }
  }
}

/**
 * A Hyperswarm peer that cannot hole-punch, so any connection it makes is
 * either relayed or nothing. Its own DHT node is ephemeral and reports no
 * remote address, as a NAT'd peer's does, and its dials refuse to punch and
 * skip the LAN shortcut and fast-open, all of which connect directly on a
 * testnet. A dial to `relay` itself is left alone: a relay must be
 * reachable without a punch.
 * @param {Array<{ host: string, port: number }>} bootstrap
 * @param {{ relay?: Buffer | null }} [options] `relay` is named on every
 *   dial this peer makes, when given.
 */
function makePunchFailing (bootstrap, { relay = null } = {}) {
  const dht = new HyperDHT({ bootstrap, ephemeral: true })
  dht.remoteAddress = () => null
  const swarm = new Hyperswarm({
    keyPair: HyperDHT.keyPair(),
    dht,
    ...(relay ? { relayThrough: () => relay } : {})
  })
  swarm.on('connection', (/** @type {any} */ socket) => { socket.on('error', () => {}) })
  const connect = dht.connect.bind(dht)
  dht.connect = (/** @type {any} */ key, /** @type {any} */ opts = {}) => {
    const toRelay = relay && Buffer.isBuffer(key) && key.equals(relay)
    return connect(key, toRelay ? opts : { ...opts, holepunch: () => false, localConnection: false, fastOpen: false })
  }
  return swarm
}

/**
 * One end of a stream through the relay with no Noise session on it: the
 * steps hyperdht's relayConnection (lib/connect.js, 6.36.0) takes, less the
 * secret stream it starts on the result. The two ends agree on `token` and
 * on which of them is the initiator, as hyperdht's two sides do through the
 * peer handshake. Only the control connection to the relay is encrypted;
 * the relayed stream carries exactly the bytes written to it.
 *
 * @param {any} dht
 * @param {Buffer} relayKey
 * @param {{ isInitiator: boolean, token: Buffer }} options
 * @returns {Promise<{ stream: any, close: () => void }>}
 */
async function pairThroughRelay (dht, relayKey, { isInitiator, token }) {
  const relaySocket = dht.connect(relayKey)
  relaySocket.on('error', () => {})
  const client = BlindRelay.Client.from(relaySocket, { id: relaySocket.publicKey })
  const stream = dht.createRawStream()
  stream.on('error', () => {})
  const close = () => {
    stream.destroy()
    relaySocket.destroy()
  }
  try {
    /** @type {Buffer} */
    const remoteId = await new Promise((resolve, reject) => {
      client.pair(isInitiator, token, stream).on('error', reject).on('data', resolve)
    })
    const { remotePort, remoteHost, socket } = relaySocket.rawStream
    stream.connect(socket, remoteId, remotePort, remoteHost)
    // One datagram, so the relay connects its end of this leg now rather
    // than at this side's first write: the receiver writes first, and its
    // HELLO has to have somewhere to go. hyperdht's secret stream gets the
    // same from its own first message. A datagram is not stream data, so
    // the peer never reads it.
    stream.trySend(Buffer.from([0]))
  } catch (err) {
    close()
    throw err
  }
  return { stream, close }
}

module.exports = { startRelay, makePunchFailing, pairThroughRelay, BlindRelay }
