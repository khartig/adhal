'use strict'

const crypto = require('hypercore-crypto')

// Placeholder for the real 6-word/QR capability code (item 3). Item 2 only
// needs both peers to derive the same 32-byte Hyperswarm topic from a
// shared secret string, per docs/ARCHITECTURE.md step 1:
//   topic = hash(code || app-salt)
const APP_SALT = 'quay-v1'

/**
 * @param {string} code
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
