'use strict'

const Hyperswarm = require('hyperswarm')

// A lone byte the server side sends once its connection is confirmed
// stable. See acceptOnce/connectOnce below for why this exists.
const READY = Buffer.from([0x01])

// engine owns all Holepunch join logic (see engine/package.json); cli/
// only ever imports from @quay/engine, never hyperswarm/hyperdht directly.
// `bootstrap` lets tests point at an isolated hyperdht testnet (see
// hyperdht/testnet) instead of the public DHT. Plain client nodes should
// NOT force `ephemeral: false` -- per hyperdht's own isolated-network
// guidance, that's reserved for the one or two persistent nodes that
// provide the network's routing infrastructure (the testnet's own bootstrap
// node already is one); regular peers just point at that bootstrap.
/**
 * @param {{ bootstrap?: Array<{ host: string, port: number }> }} [options]
 */
function createSwarm ({ bootstrap } = {}) {
  return new Hyperswarm(bootstrap ? { bootstrap } : {})
}

// Joins `topic` and resolves with the first peer to connect. One drop,
// one peer -- item 2 doesn't need to handle multiple simultaneous peers.
//
// Both accept/connect join with the (default) server:true, client:true --
// matching Hyperswarm's own basic README example. An earlier version of
// this code split roles asymmetrically (receiver server-only, sender
// client-only), which turned out to break the connection: the server
// side's 'connection' event never fired even though the client believed
// it had connected. Verified empirically against an isolated hyperdht
// testnet; joining symmetrically on both sides fixed it.
/**
 * @param {InstanceType<typeof Hyperswarm>} swarm
 * @param {Buffer} topic
 * @param {{ timeout?: number }} [options]
 */
function acceptOnce (swarm, topic, { timeout = 30000 } = {}) {
  return new Promise((resolve, reject) => {
    let settled = false

    const timer = timeout
      ? setTimeout(() => {
        if (settled) return
        settled = true
        reject(new Error(`timed out after ${timeout}ms waiting for a peer`))
      }, timeout)
      : null

    swarm.on('connection', function onConnection (socket, peerInfo) {
      if (settled) return
      settled = true
      if (timer) clearTimeout(timer)
      swarm.removeListener('connection', onConnection)
      // The server side's 'connection' event only fires once the
      // UDX/Noise session is fully confirmed (verified empirically: the
      // client side's event fires earlier/optimistically, and if the
      // client starts writing before the server-side confirmation is
      // truly done, the server never sees the connection at all). Signal
      // readiness so connectOnce's sender knows it's now safe to write.
      socket.write(READY)
      resolve({ socket, peerInfo })
    })

    const discovery = swarm.join(topic)
    discovery.flushed().catch((err) => {
      if (settled) return
      settled = true
      if (timer) clearTimeout(timer)
      reject(err)
    })
  })
}

// Joins `topic` and resolves once connected to the first peer it finds.
// See acceptOnce's comment for why this joins symmetrically rather than
// client-only.
/**
 * @param {InstanceType<typeof Hyperswarm>} swarm
 * @param {Buffer} topic
 * @param {{ timeout?: number }} [options]
 */
function connectOnce (swarm, topic, { timeout = 30000 } = {}) {
  return new Promise((resolve, reject) => {
    let settled = false

    const timer = timeout
      ? setTimeout(() => {
        if (settled) return
        settled = true
        reject(new Error(`timed out after ${timeout}ms looking for a peer`))
      }, timeout)
      : null

    swarm.on('connection', function onConnection (socket, peerInfo) {
      if (settled) return
      settled = true
      if (timer) clearTimeout(timer)
      swarm.removeListener('connection', onConnection)
      // Wait for the server's READY byte (see acceptOnce) before handing
      // the socket back -- writing immediately after this event fires
      // can prevent the server from ever confirming the connection.
      socket.once('data', () => resolve({ socket, peerInfo }))
    })

    swarm.join(topic)
  })
}

module.exports = { createSwarm, acceptOnce, connectOnce }
