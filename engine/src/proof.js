'use strict'

const crypto = require('crypto')

// Item 4, and step 3 of the v1 data path: prove the peer knows the drop
// code. This module is the proof itself; ./swarm.js is the exchange.
//
// THE THREAT. A topic is hash(code || app-salt), and a receiver has to
// announce that topic on the DHT to be findable at all. So the topic is
// public from the moment a drop starts -- readable by anyone walking the
// DHT, which is precisely what engine/scratch-lookup.js does. The code is
// not public. Until this module existed, the readiness handshake's ACK was
// the constant byte 0x02, which proves nothing: a stranger who scraped the
// topic could complete the handshake and be treated as the intended peer.
//
// It has to be mutual, because both directions are exposed:
//   - the sender must not transmit a file to someone who merely found the
//     topic;
//   - the receiver must not accept a file, and write it into ~/Downloads,
//     from one.
//
// WHAT THIS DOES NOT DO: it does not make a weak code strong. A six-word
// code carries ~62 bits (see ./code.js) and the announced topic already
// commits to it, so an attacker holding the topic can grind candidate
// codes offline against hash(code || salt) whether or not this handshake
// exists. Deriving K from the code therefore adds no exposure the topic
// had not already created -- and equally cannot remove it. Short-lived
// topics are the answer to grinding, and that is item 7's job, not this
// one's.
const KEY_INFO = 'quay-drop-v1'
const KEY_SIZE = 32

// 32 bytes of nonce is well past what is needed to make a repeat
// impossible in practice; it is cheap, and the whole handshake is 129
// bytes, so there is nothing to gain by trimming it.
const NONCE_SIZE = 32

// HMAC-SHA256 output. Fixed and public, which is what lets the reader
// below wait for an exact byte count.
const PROOF_SIZE = 32

// Domain-separation tags, so the two directions of the exchange produce
// provably different proofs over the same nonce. Without them an attacker
// could take one side's proof and present it back to the other as its own
// -- the classic reflection, and the reason this is two tags rather than
// one shared MAC.
const ROLE_TAGS = {
  sender: Buffer.from('s', 'utf8'),
  receiver: Buffer.from('r', 'utf8')
}

// The single reason string for "this peer could not prove it knows the
// code". Exported because it is the one candidate discard that is not a
// flaky hole punch: every other reason means the network gave up, this one
// means the peer is not who it should be. engine/src/swarm.js hands it to
// onCandidateDropped and the CLIs print it, so it never presents as a NAT
// problem.
//
// Note what it cannot mean: a mistyped code. The topic and the key are
// both derived from the code, so a peer that reached us on this topic at
// all necessarily derived the same key -- get a word wrong and the two
// sides land on unrelated topics and never meet (see ./topic.js), which
// surfaces as the zero-candidate timeout instead. So a proof failure is
// always one of exactly two things, and the message names both: a stranger
// who scraped the topic off the DHT, or a peer still running a build from
// before this handshake existed.
const PROOF_FAILED = 'failed the code proof -- either a peer that found ' +
  'the topic without knowing the code, or a build from before the proof ' +
  'existed (it is a wire-format change; both sides must be redeployed)'

// K = HKDF(code, "quay-drop-v1"). Derived on both sides, never transmitted.
//
// The code must be the *canonical* form -- what resolveCode returns, not
// what a human typed. HKDF has no notion of "nearly the same input", so
// 'ACID-ACORN-...' on one device and 'acid acorn ...' on the other yield
// unrelated keys and a proof that fails for no visible reason. That is the
// same trap ./topic.js documents for hashing, with a worse failure mode:
// there the two peers never find each other, here they find each other and
// then reject each other.
//
// The salt is empty rather than app-salt on purpose: the info string
// already separates this key from any other use of the same code, and an
// empty salt keeps the derivation reproducible from nothing but the code.
/**
 * @param {string} code canonical code (see resolveCode) or opaque secret
 * @returns {Buffer} 32-byte drop key
 */
function dropKey (code) {
  if (typeof code !== 'string' || code.length === 0) {
    throw new TypeError('code must be a non-empty string')
  }
  return Buffer.from(
    crypto.hkdfSync('sha256', Buffer.from(code, 'utf8'), Buffer.alloc(0), KEY_INFO, KEY_SIZE)
  )
}

/**
 * @returns {Buffer} a fresh nonce, one per connection attempt
 */
function makeNonce () {
  return crypto.randomBytes(NONCE_SIZE)
}

// Binds a proof to the Noise session it was produced on, by naming both
// peers' public keys.
//
// WHY THIS IS HERE AND NOT IN THE ORIGINAL SKETCH. Nonces and domain tags
// alone stop replay and reflection, but they do not stop relaying, because
// an attacker can get an honest peer to answer a challenge on its behalf.
// Concretely, with an unbound proof:
//
//   1. Attacker A announces on the topic and connects to receiver R.
//      R sends READY || nonceR.
//   2. A now poses as a *receiver* to the honest sender S -- which will
//      dial A, since S dials every candidate it discovers -- and replays
//      READY || nonceR at it.
//   3. S, believing it is talking to the real receiver, answers
//      HMAC(K, "s" || nonceR): a valid sender proof over R's own nonce.
//   4. A forwards it to R, which accepts. Repeat in the other direction
//      with A's nonce and A is a full relay between S and R.
//
// Every nonce there is fresh and every tag is correct, so neither defence
// fires. What breaks it is that the proof must be worthless off the
// connection it was made on. A cannot borrow S's public key (it has no
// private half -- the Noise handshake would fail), so the proof S makes on
// the A<->S session is bound to (A, S) and R is expecting one bound to
// (R, A). Step 4 fails.
//
// Keys are ordered by role, not sorted, so both sides agree on the order
// without negotiating it: each knows which end of the drop it is.
/**
 * @param {{ publicKey?: Buffer, remotePublicKey?: Buffer }} socket
 *   a Hyperswarm NoiseSecretStream; both fields are populated by the time
 *   the 'connection' event fires
 * @param {'sender' | 'receiver'} role this side's own role
 * @returns {{ receiver: Buffer, sender: Buffer }}
 */
function bindPeers (socket, role) {
  const own = socket.publicKey
  const remote = socket.remotePublicKey
  if (!own || !remote) {
    throw new Error('cannot bind a code proof: socket has no Noise public keys')
  }
  return role === 'receiver'
    ? { receiver: own, sender: remote }
    : { receiver: remote, sender: own }
}

// proof = HMAC(K, role-tag || nonce || receiverPk || senderPk)
//
// `role` is who *produces* this proof, which is not always the caller:
// each side computes its own proof to send and the other side's to expect.
/**
 * @param {Buffer} key
 * @param {'sender' | 'receiver'} role the side producing this proof
 * @param {Buffer} nonce the nonce being answered, i.e. the other side's
 * @param {{ receiver: Buffer, sender: Buffer }} peers see bindPeers
 * @returns {Buffer} PROOF_SIZE bytes
 */
function proveRole (key, role, nonce, peers) {
  const tag = ROLE_TAGS[role]
  if (!tag) throw new TypeError(`unknown role ${role}`)
  const hmac = crypto.createHmac('sha256', key)
  hmac.update(tag)
  hmac.update(nonce)
  hmac.update(peers.receiver)
  hmac.update(peers.sender)
  return hmac.digest()
}

// Constant-time comparison. The length check is not itself a leak --
// PROOF_SIZE is fixed and public -- but it is required, because
// timingSafeEqual throws rather than returning false on a length mismatch,
// and a peer that sends the wrong number of bytes must be rejected, not
// crash the process.
/**
 * @param {Buffer} expected
 * @param {Buffer} actual
 * @returns {boolean}
 */
function proofMatches (expected, actual) {
  if (!Buffer.isBuffer(actual) || actual.length !== expected.length) return false
  return crypto.timingSafeEqual(expected, actual)
}

// Reassembles fixed-size handshake messages from however many chunks the
// transport chooses to deliver them in.
//
// The constant-byte handshake this replaces could read its whole message
// out of `socket.once('data')`, because one byte cannot arrive split. A
// 64-byte proof-plus-nonce can, and can equally arrive coalesced with
// whatever follows it, so "the first chunk is the message" is no longer
// true in either direction. Taking bytes by count rather than by chunk is
// the same discipline ./frame.js applies to the transfer itself.
class MessageReader {
  constructor () {
    this._buffer = Buffer.alloc(0)
  }

  push (chunk) {
    this._buffer = this._buffer.length > 0
      ? Buffer.concat([this._buffer, chunk])
      : chunk
  }

  // Returns exactly `size` bytes and consumes them, or null if that many
  // have not arrived yet -- in which case nothing is consumed and the
  // caller should wait for more data.
  /**
   * @param {number} size
   * @returns {Buffer | null}
   */
  take (size) {
    if (this._buffer.length < size) return null
    const taken = this._buffer.subarray(0, size)
    this._buffer = this._buffer.subarray(size)
    return taken
  }

  // Bytes that arrived after the last complete message, or null. These
  // belong to whatever comes next on the stream and must be handed on
  // rather than dropped -- see `pending` in ./transfer.js.
  /**
   * @returns {Buffer | null}
   */
  rest () {
    return this._buffer.length > 0 ? this._buffer : null
  }
}

module.exports = {
  dropKey,
  makeNonce,
  bindPeers,
  proveRole,
  proofMatches,
  MessageReader,
  KEY_INFO,
  KEY_SIZE,
  NONCE_SIZE,
  PROOF_SIZE,
  PROOF_FAILED
}
