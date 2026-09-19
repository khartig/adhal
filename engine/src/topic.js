'use strict'

const crypto = require('hypercore-crypto')

// Both peers derive the same 32-byte Hyperswarm topic from a shared secret
// string, per docs/ARCHITECTURE.md step 1:
//   topic = hash(code || app-salt)
const APP_SALT = 'quay-v1'

// This function hashes exactly the string it is given; it does no
// normalization of its own, so that opaque hex demo codes keep
// working unchanged.
//
// That means a six-word code (the drop code) MUST be run through
// `parseCode` from ./code.js first. A hash has no notion of "nearly the
// same input": feed it 'ACID-ACORN-...' on one device and 'acid acorn ...'
// on the other and the two peers land on unrelated topics and simply never
// see each other -- which presents as the peer-discovery timeout from
// ./swarm.js rather than as anything resembling a typo.
/**
 * @param {string} code canonical code (see parseCode) or opaque secret string
 * @param {{ salt?: string }} [options]
 * @returns {Buffer}
 */
function topicFromCode (code, { salt = APP_SALT } = {}) {
  if (typeof code !== 'string' || code.length === 0) {
    throw new TypeError('code must be a non-empty string')
  }
  return crypto.hash(Buffer.from(`${salt}:${code}`, 'utf8'))
}

module.exports = { topicFromCode, APP_SALT }
