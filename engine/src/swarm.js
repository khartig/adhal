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

// How often we re-run our own DHT lookup while waiting for a peer.
//
// Hyperswarm's PeerDiscovery only re-queries on its own REFRESH_INTERVAL
// of 10 minutes plus up to 2 minutes of jitter (see
// hyperswarm/lib/peer-discovery.js). A topic announce is not instantly
// visible network-wide: it propagates to the nodes closest to the topic,
// and a lookup only finds it if it happens to query a node that already
// has the record. So if both sides join at the same moment, the loser of
// that race finds nothing and then sits idle for ten-plus minutes.
//
// Measured on a home NAT with both peers starting simultaneously: the
// connection either completed in ~5s or never completed at all -- 5 of 11
// runs succeeded, and raising the timeout from 30s to 120s did not rescue
// a single stuck run. Gating the client on the server's announce having
// flushed made 4 of 4 runs succeed. Re-querying on our own much shorter
// schedule fixes the same race without depending on who started first.
const REFRESH_INTERVAL = 4000

// Re-runs the DHT lookup/announce for `discovery` every REFRESH_INTERVAL
// until `isSettled()` reports we're done. Returns a stop function.
//
// Refresh errors are deliberately swallowed: a single failed re-query is
// transient and shouldn't abort a drop that the next tick may complete.
// The caller's timeout remains the backstop for "never connected".
/**
 * @param {{ refresh: (opts?: object) => Promise<unknown> }} discovery
 * @param {() => boolean} isSettled
 */
function keepRefreshing (discovery, isSettled) {
  const timer = setInterval(() => {
    if (isSettled()) return
    discovery.refresh({ client: true, server: true }).catch(() => {})
  }, REFRESH_INTERVAL)
  return () => clearInterval(timer)
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
//
// `onAnnounced` fires once our announce has flushed, i.e. once we are
// actually discoverable. Callers should wait for it before telling a
// human the drop code is ready to use -- showing the code earlier invites
// exactly the lookup-before-announce race described above.
/**
 * @param {InstanceType<typeof Hyperswarm>} swarm
 * @param {Buffer} topic
 * @param {{ timeout?: number, onAnnounced?: () => void }} [options]
 */
function acceptOnce (swarm, topic, { timeout = 30000, onAnnounced } = {}) {
  return new Promise((resolve, reject) => {
    let settled = false
    /** @type {(() => void) | null} */
    let stopRefreshing = null

    const finish = () => {
      settled = true
      if (timer) clearTimeout(timer)
      if (stopRefreshing) stopRefreshing()
    }

    const timer = timeout
      ? setTimeout(() => {
        if (settled) return
        finish()
        reject(new Error(`timed out after ${timeout}ms waiting for a peer`))
      }, timeout)
      : null

    swarm.on('connection', function onConnection (socket, peerInfo) {
      if (settled) return
      finish()
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
    stopRefreshing = keepRefreshing(discovery, () => settled)

    discovery.flushed().then(
      () => {
        if (settled) return
        if (onAnnounced) onAnnounced()
      },
      (err) => {
        if (settled) return
        finish()
        reject(err)
      }
    )
  })
}

// Joins `topic` and resolves once connected to the first peer it finds.
// See acceptOnce's comment for why this joins symmetrically rather than
// client-only, and see REFRESH_INTERVAL for why this re-queries the DHT
// on its own schedule instead of trusting Hyperswarm's 10-minute one.
/**
 * @param {InstanceType<typeof Hyperswarm>} swarm
 * @param {Buffer} topic
 * @param {{ timeout?: number }} [options]
 */
function connectOnce (swarm, topic, { timeout = 30000 } = {}) {
  return new Promise((resolve, reject) => {
    let settled = false
    /** @type {(() => void) | null} */
    let stopRefreshing = null

    const finish = () => {
      settled = true
      if (timer) clearTimeout(timer)
      if (stopRefreshing) stopRefreshing()
    }

    const timer = timeout
      ? setTimeout(() => {
        if (settled) return
        finish()
        swarm.removeListener('connection', onConnection)
        reject(new Error(`timed out after ${timeout}ms looking for a peer`))
      }, timeout)
      : null

    // Note this stays armed until the READY byte actually arrives, not
    // just until a 'connection' event fires. A peer can connect and then
    // die before confirming, and that must not hang the drop forever.
    function onConnection (socket, peerInfo) {
      if (settled) return

      // A connection can fail between the 'connection' event and the
      // server's READY byte -- observed as "connection reset by peer"
      // when the server side never confirmed the session. With no 'error'
      // listener attached during that window, the NoiseSecretStream emits
      // an uncaught 'error' and takes the whole process down.
      //
      // Treat it as "this candidate didn't work out", not as a fatal drop
      // failure: drop the dead socket, stay joined, and keep waiting for
      // the next candidate until the timeout fires.
      const detach = () => {
        socket.removeListener('error', onSocketError)
        socket.removeListener('data', onReady)
      }

      function onSocketError () {
        detach()
        socket.destroy()
      }

      // Wait for the server's READY byte (see acceptOnce) before handing
      // the socket back -- writing immediately after the 'connection'
      // event can prevent the server from ever confirming the connection.
      function onReady () {
        if (settled) return
        detach()
        finish()
        swarm.removeListener('connection', onConnection)
        resolve({ socket, peerInfo })
      }

      socket.once('error', onSocketError)
      socket.once('data', onReady)
    }

    swarm.on('connection', onConnection)

    const discovery = swarm.join(topic)
    stopRefreshing = keepRefreshing(discovery, () => settled)
  })
}

module.exports = { createSwarm, acceptOnce, connectOnce }
