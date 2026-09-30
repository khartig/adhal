'use strict'

const Hyperswarm = require('hyperswarm')
const HyperDHT = require('hyperdht')
const { TransferError, abortError } = require('./errors')
const { MessageReader } = require('./reader')
const { Initiator, Responder, assertHandshakeInputs, ERR_CONFIRMATION } = require('./handshake')
const { AttemptCap, sidReusedError, ERR_SID_REUSED } = require('./attempts')
const { Channel } = require('./channel')
const { TYPE_DECLINE, declineBody, ERR_DROP_TAKEN } = require('./message')

// The readiness handshake, which is also v2's PAKE exchange. The receiver
// writes HELLO once its connection is confirmed stable; three messages
// later both sides have proven to each other that they know the drop
// secret, and only then does either treat the peer as real.
//
//   receiver -> sender:  HELLO   [len][version][sid][Ya][caps_r]
//   sender   -> receiver: REPLY  [len][Yb][confirmS][caps_s]
//   receiver -> sender:  CONFIRM [confirmR]                    (32 bytes)
//
// where the derivation is CPACE-X25519-SHA512 under the ad-hal parameter
// mapping in ./handshake.js, which carries the reasoning for every part of
// that construction -- including the four things PROTOCOL.md section 3.2
// says an implementation must get right, and which of them this file is
// responsible for (trap #1: the per-connection scalars below).
//
// WHAT THIS REPLACED, AND WHY. v1 exchanged HMACs over nonces, keyed by
// the whole code and bound to the Noise session. Both halves of that were
// wrong for v2. Keying on the whole code was useless as a defence, because
// v1's topic was hash(code || salt) and a receiver must announce it --
// so an attacker could grind candidate codes offline and never touch a
// peer. Binding to the Noise session made security depend on which
// transport carried the bytes, which a relay or a browser would have to
// reinvent (section 3.3).
//
// WHAT IS UNCHANGED, AND IT IS THE POINT. Same three messages, same
// first-read and first-write points, same "this candidate confirmed"
// state, same discard-and-keep-waiting response when a candidate fails. A
// peer that fails its confirmation is discarded by the identical path as a
// peer whose punch died, so the resilience below is reused rather than
// duplicated -- it is only the reason string and the countability (W11d)
// that differ. Section 3.1 explains why not moving those points matters:
// Hyperswarm's duplicate tie-break destroys a connection that has written
// but not yet read.
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
//
// The message sizes are no longer compile-time constants here: HELLO and
// REPLY are length-prefixed because `caps` is variable-length, so
// ./handshake.js reads the prefix and bounds the body itself. Both sides
// still read by byte count via MessageReader rather than assuming one
// chunk is one message -- nothing in v2's handshake is one byte, so every
// message can arrive split or coalesced with what follows.

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

// How long a single candidate may take to finish the readiness handshake
// before we give up on it and wait for the next one.
//
// Without this, every candidate socket lived until the swarm itself was
// destroyed. The join timeout covers the drop as a whole, so nothing
// hung -- but a peer that connects and then simply stops talking held a
// connection slot, and its socket, for the entire remaining budget. With
// MAX_PARALLEL at 16 and a topic that routinely accumulates stale
// announces (see above), that is a cheap way for one misbehaving peer to
// occupy the slots a live one needs.
//
// 15s is well above the worst handshake latency measured on a real
// cross-ISP path (connect median 3.0s, p90 4.3s) and well below the 30s
// receiver / 120s sender join budgets, so a dropped candidate still
// leaves room for several more.
const HANDSHAKE_TIMEOUT_MS = 15000

// How long a candidate's connection may go without receiving a single UDX
// packet before it is treated as dead. Much shorter than the handshake
// budget, because it is not a budget for the peer: it is a test of whether
// the far end of the connection exists at all.
//
// IT OFTEN DOES NOT, AND hyperdht REPORTS IT OPEN ANYWAY (found in W15d).
// When both peers sit behind one address -- one machine, or one LAN --
// hyperdht's client races a LAN shortcut against a holepunch. The server
// side, meanwhile, aborts the holepunch when its NAT analysis comes back
// unstable, and its abort destroys the raw stream the LAN shortcut was
// about to use (hyperdht@6.34.0, lib/server.js, `_onpeerholepunch` ->
// `_abort`). If the client's LAN ping has already succeeded, the client
// opens onto a stream that no longer exists: 'connection' fires, our HELLO
// is written, and every packet it sends is dropped until UDX gives up with
// "connection timed out", 13 s later. The server never emits 'connection'
// at all. On a single-process testnet this was 6 of 16 pairings, each
// ~18.6 s instead of ~4 s; a counterfactual that stops the server's abort
// destroying the stream made it 0 of 16.
//
// And Hyperswarm then PREFERS the dead connection. Its duplicate tie-break
// (hyperswarm/index.js, _handleServerConnection) keeps an existing
// connection unless it has both read and written, and a dead one has read
// nothing -- so while it exists, every live dial from the peer is
// destroyed as a duplicate. When the side holding it is the expected
// initiator this can become a livelock rather than a delay: its own
// redials die the same way, and the peer's are refused, until the peer
// gives up. Traced as the intermittent hang in handshake.test.js (4 of
// 12 runs, every one this sequence), and as two engine processes on one
// testnet taking 14-78 s to pair (median ~24 s over 10).
//
// A live connection is never silent for long. Its far end surfaced it
// because a packet arrived, and answers our first packet with its
// secret-stream header and an ack, so a client-side stream receives
// something within about one round trip -- ~100 ms measured on the
// testnet -- and a server-side one has already received something. A
// stream that has received NOTHING is the one case this catches, and it
// is not a slow peer, so it is safe to drop early. Dropping it removes it
// from Hyperswarm's connection set, which is what lets the next live dial
// through. With it, the two-process case paired in 4-34 s (median ~7 s
// over 10) and the handshake.test.js hang went to 1 of 12. It shortens the
// dead window; it does not close it, since a redial can die the same way.
//
// 5 s is about fifty round trips on a slow path and still well under
// UDX's own 13 s. It has not been measured cross-ISP, because the event
// has not been seen there -- it needs a shared address -- and a false
// positive costs a redial, not the drop.
const UNANSWERED_CONNECTION_MS = 5000

// engine owns all Holepunch join logic (see engine/package.json); cli/
// only ever imports from @ad-hal/engine, never hyperswarm/hyperdht directly.
// `bootstrap` lets tests point at an isolated hyperdht testnet (see
// hyperdht/testnet) instead of the public DHT. Plain client nodes should
// NOT force `ephemeral: false` -- per hyperdht's own isolated-network
// guidance, that's reserved for the one or two persistent nodes that
// provide the network's routing infrastructure (the testnet's own bootstrap
// node already is one); regular peers just point at that bootstrap.
//
// A FRESH ANNOUNCE KEYPAIR PER SWARM, GENERATED HERE (THREAT-MODEL.md
// section 4, Q-12). Every DHT node near the topic sees the public key a
// swarm announces under. If two drops ever shared one, those nodes could
// link them, and "nothing links two drops" would be false in records other
// people hold. Until W15b this held only because Hyperswarm happens to
// generate a keypair when none is passed. That is a library default, not
// a decision, and a default can change in an upgrade. So the key is made
// here, explicitly, and a caller cannot pass one in: a persistent device
// identity (a future "keep this device") belongs inside the authenticated
// channel and never in front of the DHT.
/**
 * @param {{ bootstrap?: Array<{ host: string, port: number }>, maxParallel?: number }} [options]
 */
function createSwarm (options = {}) {
  if (options && 'keyPair' in options) {
    throw new TypeError(
      'createSwarm does not take a keyPair: every drop announces under a fresh one, ' +
      'so that DHT nodes cannot link two drops (THREAT-MODEL.md section 4)'
    )
  }
  const { bootstrap, maxParallel = MAX_PARALLEL } = options
  const swarm = new Hyperswarm({
    keyPair: HyperDHT.keyPair(),
    maxParallel,
    ...(bootstrap ? { bootstrap } : {})
  })

  // A no-op 'error' sink on every connection, and it is load-bearing
  // rather than tidy.
  //
  // An 'error' event with no listener is a process-killing uncaught
  // exception in Node. A Hyperswarm connection can emit one at any time
  // -- "connection reset by peer" is routine on a flaky punch -- and
  // there are windows where nothing of ours is listening: before the
  // application attaches its handler, and after acceptOnce/connectOnce
  // have removed their 'connection' listener while the swarm goes on
  // accepting dials until it is destroyed. Sockets from that second
  // window are the ones that reset during teardown.
  //
  // Observed as an intermittent test failure -- "a resource generated
  // asynchronous activity after the test ended ... connection reset by
  // peer" -- which reproduces on the pre-Stage-0 tree, so it predates
  // this work. It matters more now that CI exists: a suite that is
  // randomly red teaches people to ignore it.
  //
  // This hides nothing. Extra 'error' listeners do not displace the
  // application's own, so anything that wants to report an error still
  // receives it; both CLIs attach one and both still print what they
  // get. What it removes is the default behaviour of letting one dead
  // candidate socket kill the process -- which is the same lesson
  // acceptOnce/connectOnce already learned about discarding a failed
  // candidate rather than treating it as fatal.
  swarm.on('connection', (socket) => { socket.on('error', () => {}) })

  return swarm
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
// ADHAL_REFRESH_INTERVAL exists to test that without editing code: set it
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
    '(the per-candidate lines say which of them failed the PAKE confirmation)'
}

// The same distinction, carried as a code rather than as prose.
//
// engine/scratch-trials.js classified these two outcomes by regex-matching
// the sentences above, which made the project's own measurement instrument
// depend on their wording. The message stays exactly as it was -- it is
// the useful thing for a human to read -- and the code is what anything
// automated should switch on. See engine/src/errors.js.
/**
 * @param {string} phase
 * @param {number} timeout
 * @param {number} candidates
 */
function timeoutError (phase, timeout, candidates) {
  return new TransferError(
    candidates === 0 ? 'ERR_NO_PEER' : 'ERR_NO_HANDSHAKE',
    timeoutMessage(phase, timeout, candidates),
    { candidates, timeout }
  )
}

// AFTER PAIRING, A LATE CANDIDATE IS TOLD THE DROP IS TAKEN (PROTOCOL.md
// section 4, DECLINE; W15a). The code is a bearer capability, so a second
// person holding it -- a forwarded code, one read off a shared screen, or
// someone racing the intended peer -- can complete the handshake just as
// the first did. Before this, whoever confirmed second was simply never
// answered and waited out its own timeout with no idea why, while the
// winner's human had no idea there had been a race at all.
//
// Now both acceptOnce and connectOnce keep answering candidates after they
// resolve. A late candidate runs the SAME handshake code as the one that
// paired -- same per-connection scalars, same deadline, same backoff, same
// sid check, same attempt cap -- so there is no second implementation to
// drift. One that confirms is sent a single sealed frame,
// DECLINE{code: ERR_DROP_TAKEN}, and closed. Only a peer that proved the
// secret learns the drop was taken, which is exactly the audience that
// needs to: the other human in the race.
//
// A late candidate that fails its confirmation is still counted: guessing
// does not become free because a transfer is running. If that burns the
// cap, answering stops -- the transfer already under way is not touched.
//
// Answering stops when the caller calls `stopAnswering()` from the
// resolved value, or when it destroys the swarm, which every CLI does in a
// `finally` once the transfer ends.

// How long a late candidate's socket is given to flush the DECLINE before
// it is destroyed. Only bounds a peer that never closes its end.
const LATE_FLUSH_MS = 2000

const DROP_TAKEN_REASON = 'this drop code has already been used by another peer'

// A second connection from the peer we paired with is Hyperswarm's own
// duplicate-connection handling, not a candidate, and is left alone.
/**
 * @param {any} peerInfo
 * @param {any} paired
 * @returns {boolean}
 */
function samePeer (peerInfo, paired) {
  const a = peerInfo && peerInfo.publicKey
  const b = paired && paired.publicKey
  return Boolean(a && b && Buffer.isBuffer(a) && a.equals(b))
}

// Seals the one frame a late candidate gets and closes. `first` is any
// handshake message that must precede it -- the receiver's CONFIRM, without
// which the late sender never finishes its handshake to read the DECLINE.
/**
 * @param {any} socket
 * @param {{ sendKey: Buffer, receiveKey: Buffer }} keys
 * @param {Buffer | null} first
 */
function declineLate (socket, { sendKey, receiveKey }, first) {
  socket.on('error', () => {})
  const channel = new Channel({ sendKey, receiveKey, onMessage: () => {} })
  if (first) socket.write(first)
  socket.end(channel.seal(TYPE_DECLINE, declineBody(DROP_TAKEN_REASON, ERR_DROP_TAKEN)))
  // The one frame this connection will ever carry is sealed (Q-18).
  channel.wipe()
  const timer = setTimeout(() => socket.destroy(), LATE_FLUSH_MS)
  if (typeof timer.unref === 'function') timer.unref()
  socket.once('close', () => clearTimeout(timer))
}

// Arms UNANSWERED_CONNECTION_MS for one candidate: `onDead` runs if its UDX
// stream has received no packet by then. Only a Hyperswarm connection has
// a raw stream to ask, so anything else (a test's duplex pair) is left to
// the handshake deadline alone.
/**
 * @param {any} socket
 * @param {number} ms
 * @param {(err: Error) => void} onDead
 * @returns {NodeJS.Timeout | null}
 */
function watchForAnswer (socket, ms, onDead) {
  if (!ms || !socket.rawStream || typeof socket.rawStream.packetsReceived !== 'number') return null
  const timer = setTimeout(() => {
    const raw = socket.rawStream
    if (raw && raw.packetsReceived === 0) {
      onDead(new Error(
        `opened, but no packet arrived from the peer within ${ms}ms: its end of the ` +
        'connection is gone (see UNANSWERED_CONNECTION_MS in engine/src/swarm.js)'
      ))
    }
  }, ms)
  if (typeof timer.unref === 'function') timer.unref()
  return timer
}

// Joins `topic` and resolves with the first peer to complete the readiness
// handshake *and* prove it knows the code. One drop, one peer -- the Hyperswarm work
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
 *   secret: string,
 *   nameplate: string,
 *   timeout?: number,
 *   refreshInterval?: number,
 *   handshakeTimeout?: number,
 *   unansweredTimeout?: number,
 *   signal?: AbortSignal,
 *   onAnnounced?: () => void,
 *   onCandidate?: (peerInfo: any) => void,
 *   attemptCap?: InstanceType<typeof AttemptCap>,
 *   onCandidateDropped?: (peerInfo: any, reason: string, code?: string) => void,
 *   onDropTaken?: (peerInfo: any) => void
 * }} options not optional, because `secret` and `nameplate` are not
 *   `attemptCap` counts failed confirmations for THIS drop (section 6);
 *   one is created per join, so burning it burns only this drop.
 *   `unansweredTimeout` is UNANSWERED_CONNECTION_MS unless a test needs
 *   otherwise; 0 turns the check off, leaving the handshake deadline.
 *   `secret` and `nameplate` are the two halves of the drop code -- see
 *   splitCode in ./code.js and resolveCode in ./resolve-code.js. The
 *   secret is the PAKE password and must be the canonical form.
 *   `onDropTaken` hears each late candidate that proved the secret and
 *   was told the drop is taken (see declineLate); after pairing, a late
 *   candidate that fails is reported through `onCandidateDropped` only if
 *   its failure was counted.
 * @returns {Promise<{
 *   socket: any, peerInfo: any, pending: Buffer | null,
 *   sendKey: Buffer, receiveKey: Buffer, caps: string[],
 *   stopAnswering: () => void
 * }>}
 *   `sendKey`/`receiveKey` are this side's directional channel keys
 *   (k_r2s and k_s2r respectively for a receiver). Pass both to
 *   receiveFile, which seals every frame under them. `stopAnswering`
 *   stops telling late candidates the drop is taken.
 */
function acceptOnce (swarm, topic, { secret, nameplate, timeout = 30000, refreshInterval = REFRESH_INTERVAL, handshakeTimeout = HANDSHAKE_TIMEOUT_MS, unansweredTimeout = UNANSWERED_CONNECTION_MS, attemptCap = new AttemptCap(), signal, onAnnounced, onCandidate, onCandidateDropped, onDropTaken }) {
  // Validated up front rather than per connection, and required rather
  // than defaulted. A missing secret can only mean a caller that was not
  // updated for v2, and the failure mode of quietly carrying on without
  // one is the exact hole this function exists to close: it would accept
  // any stranger who found the topic, silently and forever.
  //
  // Up front matters as much as strict: the per-connection construction
  // below would throw identically for every candidate, so a bad secret
  // would present as "every peer failed the handshake" -- the most
  // expensive misdiagnosis available, because it looks like a network
  // problem.
  assertHandshakeInputs(secret, nameplate)
  return new Promise((resolve, reject) => {
    let settled = false
    // Separate from `settled`: pairing settles the promise but keeps the
    // listener, so late candidates can be told the drop is taken. Every
    // per-candidate check below is on this, not on `settled`.
    let listening = true
    /** @type {any} */
    let paired = null
    let candidates = 0
    /** @type {(() => void) | null} */
    let stopRefreshing = null

    const stopListening = () => {
      listening = false
      swarm.removeListener('connection', onConnection)
    }

    const finish = () => {
      settled = true
      if (timer) clearTimeout(timer)
      if (stopRefreshing) stopRefreshing()
      if (signal) signal.removeEventListener('abort', onAbort)
    }

    // Waiting for a peer is the likeliest moment for a human to give up --
    // it is the only part of a drop that can take 30 seconds with nothing
    // to show -- and until that work there was no path to cancel it at all.
    //
    // CAREFUL: this removes OUR listener, stops OUR timer, and rejects. It
    // must not destroy the swarm. The swarm belongs to the caller, which
    // may still need it (and does: every CLI destroys it in a `finally`,
    // after this rejection has propagated).
    function onAbort () {
      if (settled) return
      finish()
      stopListening()
      reject(abortError(0, signal.reason))
    }

    const timer = timeout
      ? setTimeout(() => {
        if (settled) return
        finish()
        stopListening()
        reject(timeoutError('waiting for a peer', timeout, candidates))
      }, timeout)
      : null

    function onConnection (socket, peerInfo) {
      if (!listening) return
      if (paired && samePeer(peerInfo, paired)) return
      candidates++
      if (!paired && onCandidate) onCandidate(peerInfo)

      // SECTION 3.2 TRAP #1, AND THE LINE THAT SATISFIES IT. Constructing
      // the Initiator here -- inside the per-connection handler -- is what
      // makes `ya` and `sid` per connection rather than per drop. Draft
      // section 9.9 makes scalar reuse a MUST NOT, and this engine is
      // unusually exposed to it: a topic routinely accumulates several
      // dials (see MAX_PARALLEL) and Hyperswarm produces two connections
      // per peer, so hoisting this out of the handler to save 2 ms would
      // not be an exotic slip -- reuse would be the ordinary case.
      //
      // It is also why ./handshake.js offers no way to inject a scalar or
      // a sid: there is no correct caller for one.
      const handshake = new Initiator({ secret, nameplate })
      const reader = new MessageReader()
      /** @type {NodeJS.Timeout | null} */
      let helloTimer = null

      // See HANDSHAKE_TIMEOUT_MS: a candidate that goes quiet mid-
      // handshake is dropped on its own schedule rather than holding a
      // connection slot until the whole drop times out.
      //
      // The attempt cap's backoff is added to the budget rather than
      // spent out of it. Without that, a delayed HELLO could be dropped
      // before it was even written -- the defence would be timing out its
      // own handshakes and reporting them as peers that never confirmed.
      const candidateBudget = handshakeTimeout
        ? handshakeTimeout + attemptCap.delayMs()
        : 0
      const deadline = candidateBudget
        ? setTimeout(() => onFailed(new Error(`did not complete the handshake within ${candidateBudget}ms`)), candidateBudget)
        : null
      if (deadline && typeof deadline.unref === 'function') deadline.unref()
      // A connection whose far end hyperdht already discarded; see
      // UNANSWERED_CONNECTION_MS. Not counted: it is not a peer at all.
      const unanswered = watchForAnswer(socket, unansweredTimeout, (err) => onFailed(err))

      const detach = () => {
        if (deadline) clearTimeout(deadline)
        if (unanswered) clearTimeout(unanswered)
        if (helloTimer) clearTimeout(helloTimer)
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
      // A candidate that fails its confirmation takes this same path. It is
      // reported with CONFIRMATION_FAILED, and with a code, so that it is
      // distinguishable in the log from a dead punch -- and so that W11d
      // can count the one without counting the other. Counting dropped
      // candidates would let the DHT's own stale announces burn a
      // legitimate drop (section 6).
      function onFailed (err) {
        if (!listening) return
        // THE ONE THING THAT IS COUNTED, and the check is on the CODE
        // rather than the message: a confirmation failure means a peer
        // reached the nameplate without the secret, which is either
        // somebody guessing or a mistyped code. Everything else arriving
        // here -- a dead punch, a socket reset, a candidate that went
        // quiet -- is network noise and must not be counted, or the DHT's
        // own stale announces would burn a legitimate drop (section 6).
        const counted = Boolean(err && err.code === ERR_CONFIRMATION)
        const burned = counted ? attemptCap.fail() : false
        detach()
        // detach() just removed the only 'error' listener, and destroy()
        // on a NoiseSecretStream can emit one asynchronously -- "connection
        // reset by peer", arriving after we have stopped listening, which
        // Node then raises as an uncaughtException and which the test
        // runner reports as "a resource generated asynchronous activity
        // after the test ended".
        //
        // Mostly latent while onFailed was only reached from 'error' or
        // 'close' (the socket was already dead, so destroy had nothing to
        // report). The per-candidate deadline changed that: it fires on a
        // socket that is alive but slow, and destroying a live stream is
        // exactly the case that emits. The sink stays for the socket's
        // remaining life because there is no longer anyone to tell.
        socket.on('error', () => {})
        socket.destroy()
        // After pairing, only a counted failure is worth a line: dead punches
        // mid-transfer would only interleave with the progress bar.
        if (onCandidateDropped && (!paired || counted)) {
          onCandidateDropped(
            peerInfo,
            err ? err.message : 'closed before confirming',
            err ? err.code : undefined
          )
        }

        // Burning the drop happens HERE rather than inside the counter,
        // because there are listeners and timers to unwind first and
        // throwing from a counter would skip them. Reported after the
        // dropped-candidate line, so a log reads in the order things
        // happened: the hundredth failure, then the drop ending.
        if (burned) {
          stopListening()
          if (paired) return // the transfer under way is not ours to end
          finish()
          reject(attemptCap.error())
        }
      }

      function onData (chunk) {
        if (!listening) return
        reader.push(chunk)

        /** @type {ReturnType<InstanceType<typeof Initiator>['readReply']>} */
        let confirmed
        try {
          confirmed = handshake.readReply(reader)
        } catch (err) {
          // Covers a failed confirmation, a malformed or non-canonical
          // caps field, a REPLY whose declared length is out of range, and
          // the draft's neutral-element abort. All of them mean "this
          // candidate is not the peer", and all take the discard path.
          onFailed(err)
          return
        }
        if (!confirmed) return // still arriving; wait for the rest

        detach()
        if (paired) {
          // CONFIRM first: the late sender cannot read a sealed frame until
          // its own handshake has completed.
          declineLate(socket, confirmed, confirmed.confirm)
          if (onDropTaken) onDropTaken(peerInfo)
          return
        }
        // Stop the flow until the caller has attached its own reader.
        // Removing a 'data' listener does not pause a stream, so without
        // this, bytes arriving in the gap between resolving and
        // receiveFile attaching would be dropped on the floor.
        socket.pause()
        finish()
        paired = peerInfo
        // CONFIRM. Written before resolving so the sender is released into
        // sendFile only after we are on our way into receiveFile.
        socket.write(confirmed.confirm)
        // Anything the sender coalesced after its REPLY. It cannot be
        // manifest bytes in a correct exchange -- the sender does not write
        // those until our CONFIRM arrives -- but handing leftovers back
        // rather than swallowing them is the contract receiveFile's
        // `pending` was built on, and it stays honest if that order ever
        // changes. Those leftovers would be sealed frames: everything after
        // CONFIRM is, so receiveFile opens them under the keys below.
        resolve({
          socket,
          peerInfo,
          pending: reader.rest(),
          sendKey: confirmed.sendKey,
          receiveKey: confirmed.receiveKey,
          caps: confirmed.caps,
          stopAnswering: stopListening
        })
      }

      socket.once('error', onFailed)
      socket.once('close', onFailed)
      socket.on('data', onData)

      // The server side's 'connection' event only fires once the
      // UDX/Noise session is fully confirmed (verified empirically: the
      // client side's event fires earlier/optimistically, and if the
      // client starts writing before the server-side confirmation is
      // truly done, the server never sees the connection at all). Signal
      // readiness so connectOnce's sender knows it's now safe to write,
      // and carry Ya, the sid and our capabilities in the same message.
      //
      // Delayed by the attempt cap's backoff once anything has failed. A
      // DELAY, not a refusal: declining to talk during a backoff window
      // would discard the legitimate sender along with the guesser, and
      // the legitimate sender is the one that cannot retry a thousand
      // times. A guess needs this HELLO, so delaying it is what makes
      // guessing cost wall-clock time. See engine/src/attempts.js.
      const backoff = attemptCap.delayMs()
      if (backoff === 0) {
        socket.write(handshake.hello())
      } else {
        helloTimer = setTimeout(() => {
          if (!listening || socket.destroyed) return
          socket.write(handshake.hello())
        }, backoff)
        if (typeof helloTimer.unref === 'function') helloTimer.unref()
      }
    }

    swarm.on('connection', onConnection)

    if (signal) {
      if (signal.aborted) {
        stopListening()
        // finish() as well as removing the listener: without it the join
        // timer stayed armed after an already-aborted signal short-
        // circuited the join, holding the event loop open for the full
        // budget on a drop that had already been abandoned.
        finish()
        reject(abortError(0, signal.reason))
        return
      }
      signal.addEventListener('abort', onAbort, { once: true })
    }

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
        stopListening()
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
 *   secret: string,
 *   nameplate: string,
 *   timeout?: number,
 *   refreshInterval?: number,
 *   handshakeTimeout?: number,
 *   unansweredTimeout?: number,
 *   attemptCap?: InstanceType<typeof AttemptCap>,
 *   signal?: AbortSignal,
 *   onCandidate?: (peerInfo: any) => void,
 *   onCandidateDropped?: (peerInfo: any, reason: string, code?: string) => void,
 *   onDropTaken?: (peerInfo: any) => void
 * }} options not optional, because `secret` and `nameplate` are not
 *   `unansweredTimeout` is as for acceptOnce.
 *   `attemptCap` is where the SENDER's extra duty lives: as well as
 *   counting failed confirmations it remembers the sid values it has seen
 *   for this nameplate, and treats a repeat as a failed attempt. That is
 *   section 3.2's mitigation for a receiver-chosen sid, and it is why that
 *   choice is acceptable at all.
 * @returns {Promise<{
 *   socket: any, peerInfo: any, pending: Buffer | null,
 *   sendKey: Buffer, receiveKey: Buffer, caps: string[],
 *   stopAnswering: () => void
 * }>}
 *   For a sender, `sendKey` is k_s2r and `receiveKey` is k_r2s -- the
 *   mirror of acceptOnce's view. Pass both to sendFile. `onDropTaken` and
 *   `stopAnswering` are as for acceptOnce: a sender that has paired tells
 *   a second receiver the drop is taken.
 */
function connectOnce (swarm, topic, { secret, nameplate, timeout = 30000, refreshInterval = REFRESH_INTERVAL, handshakeTimeout = HANDSHAKE_TIMEOUT_MS, unansweredTimeout = UNANSWERED_CONNECTION_MS, attemptCap = new AttemptCap(), signal, onCandidate, onCandidateDropped, onDropTaken }) {
  // See acceptOnce: required rather than defaulted, and validated up
  // front, because carrying on without a secret would silently hand a file
  // to whoever answered.
  assertHandshakeInputs(secret, nameplate)
  return new Promise((resolve, reject) => {
    let settled = false
    // Separate from `settled`: pairing settles the promise but keeps the
    // listener, so late candidates can be told the drop is taken. Every
    // per-candidate check below is on this, not on `settled`.
    let listening = true
    /** @type {any} */
    let paired = null
    let candidates = 0
    /** @type {(() => void) | null} */
    let stopRefreshing = null

    const stopListening = () => {
      listening = false
      swarm.removeListener('connection', onConnection)
    }

    const finish = () => {
      settled = true
      if (timer) clearTimeout(timer)
      if (stopRefreshing) stopRefreshing()
      if (signal) signal.removeEventListener('abort', onAbort)
    }

    // See acceptOnce's onAbort: removes our listener and our timer, never
    // touches the caller's swarm.
    function onAbort () {
      if (settled) return
      finish()
      stopListening()
      reject(abortError(0, signal.reason))
    }

    const timer = timeout
      ? setTimeout(() => {
        if (settled) return
        finish()
        stopListening()
        reject(timeoutError('looking for a peer', timeout, candidates))
      }, timeout)
      : null

    // Note this stays armed until the READY byte actually arrives, not
    // just until a 'connection' event fires. A peer can connect and then
    // die before confirming, and that must not hang the drop forever.
    function onConnection (socket, peerInfo) {
      if (!listening) return
      if (paired && samePeer(peerInfo, paired)) return
      candidates++
      if (!paired && onCandidate) onCandidate(peerInfo)

      // A connection can fail between the 'connection' event and the
      // server's READY byte -- observed as "connection reset by peer"
      // when the server side never confirmed the session. With no 'error'
      // listener attached during that window, the NoiseSecretStream emits
      // an uncaught 'error' and takes the whole process down.
      //
      // Treat it as "this candidate didn't work out", not as a fatal drop
      // failure: drop the dead socket, stay joined, and keep waiting for
      // the next candidate until the timeout fires.
      // Per connection, for the reason acceptOnce's copy of this spells
      // out: `yb` must not be reused across candidates, and a sender dials
      // every candidate it discovers.
      const handshake = new Responder({ secret, nameplate })
      const reader = new MessageReader()
      let replied = false
      /** @type {NodeJS.Timeout | null} */
      let replyTimer = null

      // See HANDSHAKE_TIMEOUT_MS, and acceptOnce's copy of this --
      // including why the backoff is added to the budget rather than spent
      // out of it.
      const candidateBudget = handshakeTimeout
        ? handshakeTimeout + attemptCap.delayMs()
        : 0
      const deadline = candidateBudget
        ? setTimeout(() => onFailed(new Error(`did not complete the handshake within ${candidateBudget}ms`)), candidateBudget)
        : null
      if (deadline && typeof deadline.unref === 'function') deadline.unref()
      // See acceptOnce's copy, and UNANSWERED_CONNECTION_MS.
      const unanswered = watchForAnswer(socket, unansweredTimeout, (err) => onFailed(err))

      const detach = () => {
        if (deadline) clearTimeout(deadline)
        if (unanswered) clearTimeout(unanswered)
        if (replyTimer) clearTimeout(replyTimer)
        socket.removeListener('error', onFailed)
        socket.removeListener('close', onFailed)
        socket.removeListener('data', onData)
      }

      function onFailed (err) {
        if (!listening) return
        // See acceptOnce's copy: only a confirmation failure or a reused
        // sid is counted, never a dead punch or a reset socket.
        const counted = Boolean(err && (err.code === ERR_CONFIRMATION || err.code === ERR_SID_REUSED))
        const burned = counted ? attemptCap.fail() : false
        detach()
        // detach() just removed the only 'error' listener, and destroy()
        // on a NoiseSecretStream can emit one asynchronously -- "connection
        // reset by peer", arriving after we have stopped listening, which
        // Node then raises as an uncaughtException and which the test
        // runner reports as "a resource generated asynchronous activity
        // after the test ended".
        //
        // Mostly latent while onFailed was only reached from 'error' or
        // 'close' (the socket was already dead, so destroy had nothing to
        // report). The per-candidate deadline changed that: it fires on a
        // socket that is alive but slow, and destroying a live stream is
        // exactly the case that emits. The sink stays for the socket's
        // remaining life because there is no longer anyone to tell.
        socket.on('error', () => {})
        socket.destroy()
        // After pairing, only a counted failure is worth a line: dead punches
        // mid-transfer would only interleave with the progress bar.
        if (onCandidateDropped && (!paired || counted)) {
          onCandidateDropped(
            peerInfo,
            err ? err.message : 'closed before confirming',
            err ? err.code : undefined
          )
        }

        if (burned) {
          stopListening()
          if (paired) return // the transfer under way is not ours to end
          finish()
          reject(attemptCap.error())
        }
      }

      // Two reads, in order, off one listener: the receiver's HELLO, then
      // its CONFIRM. Waiting for HELLO before writing anything is
      // load-bearing beyond the handshake -- writing immediately after the
      // 'connection' event can prevent the server from ever confirming the
      // connection (see acceptOnce).
      function onData (chunk) {
        if (!listening) return
        reader.push(chunk)

        /** @type {ReturnType<InstanceType<typeof Responder>['readConfirm']>} */
        let confirmed
        try {
          if (!replied) {
            const answer = handshake.readHello(reader)
            if (!answer) return
            replied = true

            // SECTION 3.2'S MITIGATION FOR A RECEIVER-CHOSEN sid, and the
            // reason that departure from the draft is acceptable. The
            // draft recommends a sid contributed by both parties; here the
            // receiver must compute the generator before it can send Ya,
            // so a jointly contributed sid would cost a round trip and the
            // receiver could not write first -- which section 3.1 shows is
            // load-bearing for Hyperswarm's duplicate tie-break. The
            // message shape wins, and the sender remembers instead. That
            // turns sid reuse from invisible into countable.
            //
            // Note what a repeat does NOT mean: a 16-byte CSPRNG value
            // does not repeat by chance, but a buggy peer reusing one
            // lands here too. Either way it is something a correct peer
            // never does, so the reason says "reused" rather than
            // "attacked".
            if (attemptCap.seenSid(answer.sid)) {
              onFailed(sidReusedError(answer.sid))
              return
            }

            // REPLY carries Yb, our confirmation and our capabilities in
            // one message, so this stays the same number of round trips as
            // the v1 handshake it replaces.
            //
            // Delayed by the attempt cap's backoff once something has
            // failed -- a delay rather than a refusal, for the reason
            // acceptOnce's copy of this gives. A guess against a sender
            // needs this REPLY.
            const backoff = attemptCap.delayMs()
            if (backoff === 0) {
              socket.write(answer.reply)
            } else {
              replyTimer = setTimeout(() => {
                if (!listening || socket.destroyed) return
                socket.write(answer.reply)
              }, backoff)
              if (typeof replyTimer.unref === 'function') replyTimer.unref()
            }
          }

          // Falls through in the same tick when both messages arrived
          // coalesced; otherwise returns and waits.
          confirmed = handshake.readConfirm(reader)
        } catch (err) {
          // A version skew, a malformed or non-canonical caps field, an
          // out-of-range length, the neutral-element abort, or a failed
          // confirmation. Every one means this candidate is not the peer.
          onFailed(err)
          return
        }
        if (!confirmed) return

        detach()
        if (paired) {
          declineLate(socket, confirmed, null)
          if (onDropTaken) onDropTaken(peerInfo)
          return
        }
        // Paused until sendFile attaches its reader, as acceptOnce does for
        // receiveFile. It used to matter less: the receiver wrote nothing
        // until it had the MANIFEST. A receiver that paired with someone
        // else now writes DECLINE{ERR_DROP_TAKEN} straight after CONFIRM,
        // and without the pause it could arrive while sendFile is still
        // hashing the file, with no listener, and be lost -- leaving the
        // losing sender to report a disconnect instead of the reason.
        socket.pause()
        finish()
        paired = peerInfo
        // Leftovers are handed back, exactly as acceptOnce does.
        //
        // This used to read "sendFile never reads, so leftover bytes would
        // mean a peer that talked out of turn". The failure-reporting work made that false:
        // the sender now runs a decoder of its own so that a receiver's
        // CANCEL is distinguishable from the socket dying. The receiver
        // still writes nothing in the ordinary case, so `pending` is
        // almost always empty -- but "almost always" is not a contract,
        // and swallowing a coalesced CANCEL would lose precisely the
        // message this item exists to deliver.
        resolve({
          socket,
          peerInfo,
          pending: reader.rest(),
          sendKey: confirmed.sendKey,
          receiveKey: confirmed.receiveKey,
          caps: confirmed.caps,
          stopAnswering: stopListening
        })
      }

      socket.once('error', onFailed)
      socket.once('close', onFailed)
      socket.on('data', onData)
    }

    swarm.on('connection', onConnection)

    // THIS REGISTRATION WAS MISSING, and nothing caught it for four
    // items. `onAbort` was written, `finish()` removed it, the `signal`
    // option was documented in the JSDoc, and swarm-send.js passed one in
    // with a comment explaining why cancelling here matters -- but no
    // line ever attached it, so the signal was inert. acceptOnce (above)
    // had the equivalent line all along, which is exactly why the gap was
    // invisible: the receiver's Ctrl-C worked, so the feature looked
    // shipped.
    //
    // Measured before the fix, with a 500ms abort against a 5000ms
    // budget: acceptOnce rejected at 502ms, connectOnce ran the full
    // 5001ms and then reported ERR_NO_PEER. For a sender that is up to
    // two minutes of a Ctrl-C doing nothing at all -- and README.md,
    // ARCHITECTURE.md and swarm-send.js all described the opposite as
    // working. There is now a test on the sender side (cancel.test.js),
    // which is the thing whose absence let this survive.
    if (signal) {
      if (signal.aborted) {
        stopListening()
        finish()
        reject(abortError(0, signal.reason))
        return
      }
      signal.addEventListener('abort', onAbort, { once: true })
    }

    const discovery = swarm.join(topic)
    stopRefreshing = keepRefreshing(discovery, () => settled, refreshInterval)
  })
}

// timeoutMessage is exported for tests: asserting both of its branches
// end to end would mean racing a real peer against a real timeout, which
// is exactly the kind of timing-dependent test that fails only under load.
module.exports = { createSwarm, acceptOnce, connectOnce, timeoutMessage, timeoutError, HANDSHAKE_TIMEOUT_MS, UNANSWERED_CONNECTION_MS }
