'use strict'

const crypto = require('hypercore-crypto')

// The Hyperswarm topic, per PROTOCOL.md section 2:
//
//   topic = BLAKE2b-256("adhal-v2:topic" || nameplate)
//
// WHAT CHANGED FROM v1, AND WHY IT IS THE POINT OF v2. v1 hashed the whole
// code: topic = hash(v1 prefix || code). A receiver must announce its
// topic on the DHT to be findable at all -- engine/scratch-lookup.js walks
// the DHT and reads exactly that -- so v1's announce published a
// commitment to the entire code, and an attacker holding it could grind
// candidate codes offline at whatever rate its hardware allowed, never
// touching a peer and never being counted.
//
// Under v2 the topic commits only to the NAMEPLATE, which is not a secret
// and is public the moment the receiver announces. The secret half of the
// code is hashed into nothing an observer can obtain: it is the PAKE
// password (see ./handshake.js), so a guess costs a live protocol run
// against a peer that is counting (PROTOCOL.md section 6). There is no
// offline target left.
//
// So the security property here is negative and easy to break by accident:
// THE SECRET MUST NEVER REACH THIS FUNCTION. Passing the whole code would
// restore v1's grindable topic exactly, and nothing downstream could tell.
// The one caller that deliberately does this is the opaque-code path in
// ./resolve-code.js, which says so in those words and is gated behind
// --unsafe-opaque.
const TOPIC_PREFIX = 'adhal-v2:topic'

// `hypercore-crypto.hash` is BLAKE2b-256 -- checked against the published
// digest of "abc" (bddd813c...52319) rather than assumed from the name, so
// section 2's derivation needs no new dependency.
//
// The prefix is concatenated with no separator, per section 2's
// literal `"adhal-v2:topic" || nameplate`. The byte string for the nameplate
// 'acid-acorn' is therefore "adhal-v2:topicacid-acorn". That is unambiguous
// only because the prefix is a fixed length and the word charset excludes
// ':' -- worth stating, because "hash a prefix and a value" with a
// variable-length prefix is how domain separation gets quietly lost.
//
// v1 and v2 topics cannot collide: the prefixes differ, so a v1 peer and a
// v2 peer simply never meet, and the failure surfaces as ERR_NO_PEER
// rather than as a corrupt frame.
/**
 * @param {string} nameplate the canonical public half of a drop code (see
 *   splitCode in ./code.js), or an opaque secret string
 * @returns {Buffer} 32 bytes
 */
function topicFromNameplate (nameplate) {
  if (typeof nameplate !== 'string' || nameplate.length === 0) {
    throw new TypeError('nameplate must be a non-empty string')
  }
  return blake2b256(Buffer.from(`${TOPIC_PREFIX}${nameplate}`, 'utf8'))
}

// The hash itself, exported so that the conformance vectors can check the
// two claims the derivation rests on *separately* (PROTOCOL.md section 11):
//
//   - that this really is BLAKE2b-256, by running the published digest of
//     "abc" through it -- an external acceptance criterion, not a value
//     this repo chose;
//   - that topicFromNameplate's input really is the prefix concatenated
//     with the nameplate and nothing else, by building that byte string in
//     the test and hashing it here.
//
// Without the split, a vector file could only pin the composite digest, and
// a change of hash function and a change of input construction would be
// indistinguishable from each other and from a deliberate revision.
//
// NOT for deriving anything else. Every other key and digest in v2 comes
// from the CPace transcript (./handshake.js) or from ./cpace.js; this is
// the topic's hash and has no other caller.
/**
 * @param {Buffer} bytes
 * @returns {Buffer} 32 bytes
 */
function blake2b256 (bytes) {
  return crypto.hash(bytes)
}

module.exports = { topicFromNameplate, blake2b256, TOPIC_PREFIX }
