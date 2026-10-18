'use strict'

// A raw Hyperswarm node for the tests that play a peer by hand -- a dead
// candidate, a guesser, a replayer -- over a DHT testnet.
//
// WHY NOT JUST createSwarm AND join. On a testnet every peer shares one
// address, and hyperdht's LAN shortcut then races its holepunch: often
// enough, a connection is reported open whose far end hyperdht has
// already discarded (UNANSWERED_CONNECTION_MS in engine/src/swarm.js has
// the mechanism). The engine drops such a connection after 5 s. A raw
// peer does not, and the two together can livelock: the side under test
// dials the peer, gets a dead connection, and Hyperswarm's duplicate
// tie-break then refuses every live dial the peer makes back, because it
// prefers the dead one. That was the intermittent hang in handshake.test.js
// ("the receiver CLI reports a dropped candidate"), traced in W15d.
//
// So a test peer:
//   - joins CLIENT-ONLY. It never announces, so the side under test never
//     dials it and never holds a dead connection to it. It still dials,
//     which is all any of these peers need, and a probe that does not
//     announce is what scratch-lookup.js --connect looks like anyway.
//   - drops its own dead connections, as the engine does, so its swarm
//     frees the slot and redials.
//   - re-runs discovery, so a redial happens after Hyperswarm's own retry
//     schedule has given up.
//
// THE REDIAL IS NOT ONLY AFTER A DEAD CONNECTION. Once the side under test
// drops a live one, this peer dials again and gets a fresh HELLO. A peer
// whose act must happen once -- a guesser, whose every REPLY is a counted
// failure -- has to guard that itself; attempts.test.js's guessers burned
// a cap early before they did.
//
// Not in cli/test/ for the reason duplex-pair.js gives.

const { createSwarm } = require('@ad-hal/engine')

const DEAD_MS = 2000
const REFRESH_MS = 2000

/**
 * @param {Array<{ host: string, port: number }>} bootstrap
 * @param {Buffer} topic
 * @param {(socket: any, peerInfo: any) => void} onConnection called for
 *   every connection, dead ones included: a dead one simply never delivers
 *   any data, and is destroyed after DEAD_MS.
 * @returns {{ swarm: any, flushed: Promise<void> }}
 */
function joinAsPeer (bootstrap, topic, onConnection) {
  const swarm = createSwarm({ bootstrap })
  swarm.on('connection', (/** @type {any} */ socket, /** @type {any} */ peerInfo) => {
    socket.on('error', () => {})
    const dead = setTimeout(() => {
      if (socket.rawStream && socket.rawStream.packetsReceived === 0) socket.destroy()
    }, DEAD_MS)
    dead.unref()
    socket.once('close', () => clearTimeout(dead))
    onConnection(socket, peerInfo)
  })
  const discovery = swarm.join(topic, { server: false, client: true })
  const refresh = setInterval(() => { discovery.refresh({ client: true, server: false }).catch(() => {}) }, REFRESH_MS)
  refresh.unref()
  const destroy = swarm.destroy.bind(swarm)
  swarm.destroy = (/** @type {any[]} */ ...args) => {
    clearInterval(refresh)
    return destroy(...args)
  }
  return { swarm, flushed: discovery.flushed() }
}

/**
 * Waits for `promise`, but not forever: a test peer that never reaches the
 * side under test fails with a sentence that says where to look, instead
 * of hanging the suite until the runner's timeout.
 * @template T
 * @param {Promise<T>} promise
 * @param {number} ms
 * @param {string} what
 * @returns {Promise<T>}
 */
function within (promise, ms, what) {
  /** @type {NodeJS.Timeout | undefined} */
  let timer
  const timeout = new Promise((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(
      `${what} did not happen within ${ms}ms. On a testnet this is most likely the pairing race ` +
      'UNANSWERED_CONNECTION_MS describes (engine/src/swarm.js), not the behavior under test'
    )), ms)
  })
  return /** @type {Promise<T>} */ (Promise.race([promise, timeout]).finally(() => clearTimeout(timer)))
}

module.exports = { joinAsPeer, within }
