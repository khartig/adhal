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
 * @param {Array<{ host: string, port: number }>} bootstrap
 */
async function startRelay (bootstrap) {
  const dht = new HyperDHT({ bootstrap })
  const relay = new BlindRelay.Server({
    createStream: (/** @type {any} */ opts) => dht.createRawStream({ ...opts, framed: true })
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
  })
  const keyPair = HyperDHT.keyPair()
  await server.listen(keyPair)
  return {
    publicKey: keyPair.publicKey,
    port: /** @type {any} */ (server.address()).port,
    stats: relay.stats,
    sessionPeers,
    async destroy () {
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

module.exports = { startRelay, makePunchFailing }
