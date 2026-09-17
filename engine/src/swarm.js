'use strict'

const Hyperswarm = require('hyperswarm')

// The two-byte readiness handshake. The server writes READY once its
// connection is confirmed stable; the client answers ACK once it has seen
// it. Only after ACK does either side treat the peer as real.
//
// The ACK half was added after a cross-ISP failure that neither side
// reported honestly. The receiver used to resolve on its *first*
// 'connection' event -- clear its timeout, remove its listener, write
// READY, and hand the socket to receiveFile. The sender, by contrast, had
// already been hardened against a peer that connects and then dies before
// confirming (see connectOnce): it discards that candidate and keeps
// waiting. So a half-failed punch, which is routine on a firewalled CGNAT
// path, left the two sides in permanently incompatible states -- the
// sender patiently dialing again, the receiver already committed to a dead
// socket, listener gone and timer cleared, unable to ever answer. Every
// subsequent dial connected at the DHT/UDX layer and then hung, and the
// sender blamed it on "looking for a peer" when it had in fact found
// several.
//
// Measured on Starlink -> Comcast: hyperdht discovery and a raw dial both
// succeeded (engine/scratch-lookup.js --connect reported CONNECTED) while
// swarm-send.js timed out after 120s with no bytes transferred.
//
// With ACK, "this candidate confirmed" is a state both sides agree on, so
// both can discard a candidate that fails and wait for the next one. It is
// also where item 4's challenge-response HMAC belongs, replacing this
// constant byte with a proof that the peer knows the drop code.
const READY = Buffer.from([0x01])
const ACK = Buffer.from([0x02])

// How many connection attempts Hyperswarm may have in flight at once.
//
// Hyperswarm's own default is MAX_PARALLEL = 3 (hyperswarm/index.js), and
// it gates new dials on `connecting < maxParallel`. That is too tight for
// this product, because a drop topic routinely accumulates *stale*
// announces: a DHT announce outlives the process that made it, so every
// abandoned or timed-out drop leaves a dead peer advertised under the
// topic until the record expires.
//
// Dialing a dead peer is not cheap -- a holepunch to a process that is no
// longer there took 10-17s to abort when measured. And Hyperswarm only
// deprioritizes a peer once `attempts > 3` (hyperswarm/lib/peer-info.js),
// i.e. after roughly four such rounds. So with only three slots, three
// stale records are enough to starve a genuinely live peer of any slot at
// all: observed as `swarm-send.js` timing out for 120s against a topic
// carrying three dead announces, on the same network path where a freshly
// generated topic connected in 9s.
//
// Raising this does not make the dead dials any faster; it just stops them
// from crowding out the live peer.
const MAX_PARALLEL = 16

// engine owns all Holepunch join logic (see engine/package.json); cli/
// only ever imports from @quay/engine, never hyperswarm/hyperdht directly.
// `bootstrap` lets tests point at an isolated hyperdht testnet (see
// hyperdht/testnet) instead of the public DHT. Plain client nodes should
// NOT force `ephemeral: false` -- per hyperdht's own isolated-network
// guidance, that's reserved for the one or two persistent nodes that
// provide the network's routing infrastructure (the testnet's own bootstrap
// node already is one); regular peers just point at that bootstrap.
/**
 * @param {{ bootstrap?: Array<{ host: string, port: number }>, maxParallel?: number }} [options]
 */
function createSwarm ({ bootstrap, maxParallel = MAX_PARALLEL } = {}) {
  return new Hyperswarm({
    maxParallel,
    ...(bootstrap ? { bootstrap } : {})
  })
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
//
// CAUTION, AND WHY THIS IS NOW CONFIGURABLE: the evidence behind 4000 is
// entirely from peers on ONE machine (`demo:swarm` spawns both locally),
// where the hole punch is trivial. It is only validated as a fix for the
// *client*-side lookup race.
//
// For a peer joined with `server: true`, `PeerDiscovery._refresh()` issues
// a DHT *announce*, not a lookup (hyperswarm/lib/peer-discovery.js picks
// `dht.announce` over `dht.lookup` when announcing). Re-announcing every
// four seconds therefore re-registers holepunch relay state continuously,
// and a sender that harvested relay addresses from one announce may be
// punching against state that has already been replaced. That costs
// nothing when both peers are local and relay state is irrelevant; on two
// firewalled NATs across ISPs it is a live suspect for a punch that fails
// silently on both sides.
//
// QUAY_REFRESH_INTERVAL exists to test that without editing code: set it
// to 30000 to match scratch-serve.js (which is observed to accept
// cross-ISP connections), or 0 to fall back to Hyperswarm's own 10-minute
// schedule. Do not change this default until there is cross-ISP evidence
// for the new value.
const REFRESH_INTERVAL = 4000

// Re-runs the DHT lookup/announce for `discovery` every `interval` ms
// until `isSettled()` reports we're done. Returns a stop function.
// `interval: 0` disables our own refreshing entirely, leaving Hyperswarm's
// internal schedule as the only one.
//
// Refresh errors are deliberately swallowed: a single failed re-query is
// transient and shouldn't abort a drop that the next tick may complete.
// The caller's timeout remains the backstop for "never connected".
/**
 * @param {{ refresh: (opts?: object) => Promise<unknown> }} discovery
 * @param {() => boolean} isSettled
 * @param {number} [interval]
 */
function keepRefreshing (discovery, isSettled, interval = REFRESH_INTERVAL) {
  if (!interval) return () => {}
  const timer = setInterval(() => {
    if (isSettled()) return
    discovery.refresh({ client: true, server: true }).catch(() => {})
  }, interval)
  return () => clearInterval(timer)
}

// Distinguishes the two ways a join can time out, because they have
// nothing to do with each other and the old message ("timed out looking
// for a peer") described only the first while being emitted for both.
//
// Zero candidates means discovery genuinely found nobody: wrong code, or
// the other side is not running or has not announced yet. One or more
// candidates means the DHT and the punch both worked and the handshake did
// not -- a completely different investigation, and the one that actually
// cost a debugging session.
function timeoutMessage (phase, timeout, candidates) {
  if (candidates === 0) {
    return `timed out after ${timeout}ms ${phase}: no peer ever connected ` +
      '(check both sides are using the same code, and that the other side ' +
      'has printed its "announced" line)'
  }
  return `timed out after ${timeout}ms ${phase}: ${candidates} peer(s) connected ` +
    'but none completed the readiness handshake -- discovery and hole punching ' +
    'worked, so this is a handshake or application-layer failure, not a DHT one'
}

// Joins `topic` and resolves with the first peer to complete the readiness
// handshake. One drop, one peer -- item 2 doesn't need to handle multiple
// simultaneous peers, but it does need to survive peers that connect and
// then vanish, which is what the READY/ACK exchange is for.
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
 * @param {{
 *   timeout?: number,
 *   refreshInterval?: number,
 *   onAnnounced?: () => void,
 *   onCandidate?: (peerInfo: any) => void,
 *   onCandidateDropped?: (peerInfo: any, reason: string) => void
 * }} [options]
 * @returns {Promise<{ socket: any, peerInfo: any, pending: Buffer | null }>}
 */
function acceptOnce (swarm, topic, { timeout = 30000, refreshInterval = REFRESH_INTERVAL, onAnnounced, onCandidate, onCandidateDropped } = {}) {
  return new Promise((resolve, reject) => {
    let settled = false
    let candidates = 0
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
        reject(new Error(timeoutMessage('waiting for a peer', timeout, candidates)))
      }, timeout)
      : null

    function onConnection (socket, peerInfo) {
      if (settled) return
      candidates++
      if (onCandidate) onCandidate(peerInfo)

      const detach = () => {
        socket.removeListener('error', onFailed)
        socket.removeListener('close', onFailed)
        socket.removeListener('data', onAck)
      }

      // A candidate that dies before confirming is discarded, not fatal:
      // stay joined, keep the timeout armed, and wait for the next dial.
      // 'close' matters as much as 'error' here -- a punch that quietly
      // goes away never raises an error at all, and treating that as
      // success is precisely the bug this function used to have.
      function onFailed (err) {
        if (settled) return
        detach()
        socket.destroy()
        if (onCandidateDropped) {
          onCandidateDropped(peerInfo, err ? err.message : 'closed before confirming')
        }
      }

      function onAck (chunk) {
        if (settled) return
        if (chunk.length === 0 || chunk[0] !== ACK[0]) {
          onFailed(new Error(`expected ACK, got 0x${chunk.length ? chunk[0].toString(16) : '??'}`))
          return
        }
        detach()
        // Stop the flow until the caller has attached its own reader.
        // Removing a 'data' listener does not pause a stream, so without
        // this, bytes arriving in the gap between resolving and
        // receiveFile attaching would be dropped on the floor.
        socket.pause()
        finish()
        swarm.removeListener('connection', onConnection)
        // The sender may have coalesced the start of its manifest into the
        // same chunk as the ACK. Hand those bytes back rather than
        // swallowing them; receiveFile takes them as `pending`.
        const pending = chunk.length > 1 ? chunk.subarray(1) : null
        resolve({ socket, peerInfo, pending })
      }

      socket.once('error', onFailed)
      socket.once('close', onFailed)
      socket.once('data', onAck)

      // The server side's 'connection' event only fires once the
      // UDX/Noise session is fully confirmed (verified empirically: the
      // client side's event fires earlier/optimistically, and if the
      // client starts writing before the server-side confirmation is
      // truly done, the server never sees the connection at all). Signal
      // readiness so connectOnce's sender knows it's now safe to write.
      socket.write(READY)
    }

    swarm.on('connection', onConnection)

    const discovery = swarm.join(topic)
    stopRefreshing = keepRefreshing(discovery, () => settled, refreshInterval)

    discovery.flushed().then(
      () => {
        if (settled) return
        if (onAnnounced) onAnnounced()
      },
      (err) => {
        if (settled) return
        finish()
        swarm.removeListener('connection', onConnection)
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
 * @param {{
 *   timeout?: number,
 *   refreshInterval?: number,
 *   onCandidate?: (peerInfo: any) => void,
 *   onCandidateDropped?: (peerInfo: any, reason: string) => void
 * }} [options]
 * @returns {Promise<{ socket: any, peerInfo: any }>}
 */
function connectOnce (swarm, topic, { timeout = 30000, refreshInterval = REFRESH_INTERVAL, onCandidate, onCandidateDropped } = {}) {
  return new Promise((resolve, reject) => {
    let settled = false
    let candidates = 0
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
        reject(new Error(timeoutMessage('looking for a peer', timeout, candidates)))
      }, timeout)
      : null

    // Note this stays armed until the READY byte actually arrives, not
    // just until a 'connection' event fires. A peer can connect and then
    // die before confirming, and that must not hang the drop forever.
    function onConnection (socket, peerInfo) {
      if (settled) return
      candidates++
      if (onCandidate) onCandidate(peerInfo)

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
        socket.removeListener('error', onFailed)
        socket.removeListener('close', onFailed)
        socket.removeListener('data', onReady)
      }

      function onFailed (err) {
        if (settled) return
        detach()
        socket.destroy()
        if (onCandidateDropped) {
          onCandidateDropped(peerInfo, err ? err.message : 'closed before confirming')
        }
      }

      // Wait for the server's READY byte (see acceptOnce) before handing
      // the socket back -- writing immediately after the 'connection'
      // event can prevent the server from ever confirming the connection.
      function onReady (chunk) {
        if (settled) return
        if (chunk.length === 0 || chunk[0] !== READY[0]) {
          onFailed(new Error(`expected READY, got 0x${chunk.length ? chunk[0].toString(16) : '??'}`))
          return
        }
        detach()
        finish()
        swarm.removeListener('connection', onConnection)
        // Answer before resolving, so the receiver is released into
        // receiveFile by the time sendFile starts writing the manifest.
        socket.write(ACK)
        resolve({ socket, peerInfo })
      }

      socket.once('error', onFailed)
      socket.once('close', onFailed)
      socket.once('data', onReady)
    }

    swarm.on('connection', onConnection)

    const discovery = swarm.join(topic)
    stopRefreshing = keepRefreshing(discovery, () => settled, refreshInterval)
  })
}

// timeoutMessage is exported for tests: asserting both of its branches
// end to end would mean racing a real peer against a real timeout, which
// is exactly the kind of timing-dependent test that fails only under load.
module.exports = { createSwarm, acceptOnce, connectOnce, timeoutMessage }
