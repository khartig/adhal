'use strict'

const Hyperswarm = require('hyperswarm')
const {
  makeNonce,
  bindPeers,
  proveRole,
  proofMatches,
  MessageReader,
  NONCE_SIZE,
  PROOF_SIZE,
  PROOF_FAILED
} = require('./proof')

// The readiness handshake, which is also the code-proof exchange (item 4,
// data path step 3). The receiver writes READY once its connection is
// confirmed stable; three messages later both sides have proven to each
// other that they know the drop code, and only then does either treat the
// peer as real.
//
//   receiver -> sender:  READY || nonceR                    (1 + 32 bytes)
//   sender   -> receiver: proof("s", nonceR) || nonceS      (32 + 32 bytes)
//   receiver -> sender:  proof("r", nonceS)                 (32 bytes)
//
// where proof() is HMAC under a key derived from the code and bound to
// this Noise session -- see ./proof.js, which carries the reasoning for
// every part of that construction, including why it is mutual and what it
// deliberately does not defend against.
//
// This replaces a constant ACK byte that proved nothing, and it keeps that
// byte's structure exactly: same round trips, same "this candidate
// confirmed" state, same discard-and-keep-waiting response when a
// candidate fails. A peer that fails the proof is discarded by the identical
// path as a peer whose punch died, so the resilience below is reused rather
// than duplicated -- it is only the reason string that differs.
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
// With a confirming answer, "this candidate confirmed" is a state both
// sides agree on, so both can discard a candidate that fails and wait for
// the next one.
const READY = Buffer.from([0x01])

// Exact sizes of the three messages. The old handshake could read each of
// its messages out of a single `socket.once('data')`, because a one-byte
// message cannot arrive split. These can -- and can arrive coalesced with
// what follows -- so both sides read by byte count via MessageReader
// instead of assuming one chunk is one message.
const HELLO_SIZE = 1 + NONCE_SIZE
const SENDER_PROOF_SIZE = PROOF_SIZE + NONCE_SIZE

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
    'worked, so this is a handshake or application-layer failure, not a DHT one ' +
    '(the per-candidate lines say which of them failed the code proof)'
}

// Joins `topic` and resolves with the first peer to complete the readiness
// handshake *and* prove it knows the code. One drop, one peer -- item 2
// doesn't need to handle multiple simultaneous peers, but it does need to
// survive peers that connect and then vanish, and peers that connect
// without any right to, which is what the exchange above is for.
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
 *   key: Buffer,
 *   timeout?: number,
 *   refreshInterval?: number,
 *   onAnnounced?: () => void,
 *   onCandidate?: (peerInfo: any) => void,
 *   onCandidateDropped?: (peerInfo: any, reason: string) => void
 * }} options not optional, because `key` is not: see below
 *   `key` is the drop key from dropKey(code) -- see ./proof.js
 * @returns {Promise<{ socket: any, peerInfo: any, pending: Buffer | null }>}
 */
function acceptOnce (swarm, topic, { key, timeout = 30000, refreshInterval = REFRESH_INTERVAL, onAnnounced, onCandidate, onCandidateDropped }) {
  // Required, not defaulted. A missing key can only mean a caller that was
  // not updated for item 4, and the failure mode of quietly carrying on
  // without one is the exact hole this function exists to close: it would
  // accept any stranger who found the topic, silently and forever.
  if (!Buffer.isBuffer(key)) {
    throw new TypeError('acceptOnce requires a drop key (see dropKey in ./proof.js)')
  }
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

      // Fresh per candidate, so a proof harvested from one attempt is
      // worthless against the next. That matters here more than it might
      // look: a topic routinely accumulates several dials (see
      // MAX_PARALLEL), so "the same challenge twice" would otherwise be a
      // normal occurrence rather than an exotic one.
      const nonceR = makeNonce()
      const reader = new MessageReader()
      /** @type {{ receiver: Buffer, sender: Buffer }} */
      let peers

      const detach = () => {
        socket.removeListener('error', onFailed)
        socket.removeListener('close', onFailed)
        socket.removeListener('data', onData)
      }

      // A candidate that dies before confirming is discarded, not fatal:
      // stay joined, keep the timeout armed, and wait for the next dial.
      // 'close' matters as much as 'error' here -- a punch that quietly
      // goes away never raises an error at all, and treating that as
      // success is precisely the bug this function used to have.
      //
      // A candidate that fails the proof takes this same path, deliberately:
      // an attacker must not be able to end a drop just by connecting to it
      // and failing. It is reported with PROOF_FAILED so it is
      // distinguishable in the log from a dead punch.
      function onFailed (err) {
        if (settled) return
        detach()
        socket.destroy()
        if (onCandidateDropped) {
          onCandidateDropped(peerInfo, err ? err.message : 'closed before confirming')
        }
      }

      function onData (chunk) {
        if (settled) return
        reader.push(chunk)
        const message = reader.take(SENDER_PROOF_SIZE)
        if (!message) return // still arriving; wait for the rest

        const theirProof = message.subarray(0, PROOF_SIZE)
        const nonceS = message.subarray(PROOF_SIZE)
        if (!proofMatches(proveRole(key, 'sender', nonceR, peers), theirProof)) {
          onFailed(new Error(PROOF_FAILED))
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
        // Answer the sender's challenge. Written before resolving so the
        // sender is released into sendFile only after we are on our way
        // into receiveFile.
        socket.write(proveRole(key, 'receiver', nonceS, peers))
        // Anything the sender coalesced after its proof. It cannot be
        // manifest bytes in a correct exchange -- the sender does not write
        // those until our answer arrives -- but handing leftovers back
        // rather than swallowing them is the contract receiveFile's
        // `pending` was built on, and it stays honest if that order ever
        // changes.
        resolve({ socket, peerInfo, pending: reader.rest() })
      }

      socket.once('error', onFailed)
      socket.once('close', onFailed)

      try {
        peers = bindPeers(socket, 'receiver')
      } catch (err) {
        onFailed(err)
        return
      }

      socket.on('data', onData)

      // The server side's 'connection' event only fires once the
      // UDX/Noise session is fully confirmed (verified empirically: the
      // client side's event fires earlier/optimistically, and if the
      // client starts writing before the server-side confirmation is
      // truly done, the server never sees the connection at all). Signal
      // readiness so connectOnce's sender knows it's now safe to write,
      // and carry our challenge in the same message.
      socket.write(Buffer.concat([READY, nonceR]))
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
 *   key: Buffer,
 *   timeout?: number,
 *   refreshInterval?: number,
 *   onCandidate?: (peerInfo: any) => void,
 *   onCandidateDropped?: (peerInfo: any, reason: string) => void
 * }} options not optional, because `key` is not: see below
 *   `key` is the drop key from dropKey(code) -- see ./proof.js
 * @returns {Promise<{ socket: any, peerInfo: any }>}
 */
function connectOnce (swarm, topic, { key, timeout = 30000, refreshInterval = REFRESH_INTERVAL, onCandidate, onCandidateDropped }) {
  // See acceptOnce: required rather than defaulted, because carrying on
  // without a key would silently hand a file to whoever answered.
  if (!Buffer.isBuffer(key)) {
    throw new TypeError('connectOnce requires a drop key (see dropKey in ./proof.js)')
  }
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
      const reader = new MessageReader()
      /** @type {{ receiver: Buffer, sender: Buffer }} */
      let peers
      /** @type {Buffer | null} */
      let nonceS = null

      const detach = () => {
        socket.removeListener('error', onFailed)
        socket.removeListener('close', onFailed)
        socket.removeListener('data', onData)
      }

      function onFailed (err) {
        if (settled) return
        detach()
        socket.destroy()
        if (onCandidateDropped) {
          onCandidateDropped(peerInfo, err ? err.message : 'closed before confirming')
        }
      }

      // Two reads, in order, off one listener: the receiver's READY and
      // challenge, then its answer to ours. Waiting for READY before
      // writing anything is load-bearing beyond the proof -- writing
      // immediately after the 'connection' event can prevent the server
      // from ever confirming the connection (see acceptOnce).
      function onData (chunk) {
        if (settled) return
        reader.push(chunk)

        if (nonceS === null) {
          const hello = reader.take(HELLO_SIZE)
          if (!hello) return
          if (hello[0] !== READY[0]) {
            onFailed(new Error(`expected READY, got 0x${hello[0].toString(16)}`))
            return
          }
          // Answer their challenge and issue ours in one message, so this
          // stays the same number of round trips as the constant-byte
          // handshake it replaces.
          nonceS = makeNonce()
          socket.write(Buffer.concat([
            proveRole(key, 'sender', hello.subarray(1), peers),
            nonceS
          ]))
        }

        // Falls through in the same tick when both messages arrived
        // coalesced; otherwise returns and waits.
        const theirProof = reader.take(PROOF_SIZE)
        if (!theirProof) return
        if (!proofMatches(proveRole(key, 'receiver', nonceS, peers), theirProof)) {
          onFailed(new Error(PROOF_FAILED))
          return
        }

        detach()
        finish()
        swarm.removeListener('connection', onConnection)
        // No `pending` counterpart to acceptOnce's: the receiver writes
        // nothing after this proof until the transfer is over, and sendFile
        // never reads. Leftover bytes here would mean a peer that both
        // proved itself and then talked out of turn.
        resolve({ socket, peerInfo })
      }

      socket.once('error', onFailed)
      socket.once('close', onFailed)

      try {
        peers = bindPeers(socket, 'sender')
      } catch (err) {
        onFailed(err)
        return
      }

      socket.on('data', onData)
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
