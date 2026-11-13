'use strict'

// --relay=<key>, shared by both swarm CLIs, for the reason env.js is one
// file. The key is a relay's public key (parseRelayKey in the engine), and
// the relay is used only after a hole punch to the peer fails
// (relayOnlyAfterFailedPunch in engine/src/swarm.js).
//
// `=` and never a space, as with --name=: every argument not starting with
// `--` is a positional, so `--relay <key>` would hand the key to the code
// or the file slot. A bare --relay is therefore refused, rather than run
// with no relay, which is what the user would not notice until two
// randomized NATs failed to connect.

const { parseRelayKey } = require('@ad-hal/engine')

/**
 * @param {string[]} argv
 * @returns {Buffer | null} the relay's key, or null without --relay
 */
function relayFlag (argv) {
  if (argv.includes('--relay')) {
    throw new Error('--relay takes its key after an equals sign: --relay=<key>')
  }
  const given = argv.filter((a) => a.startsWith('--relay='))
  if (given.length === 0) return null
  if (given.length > 1) throw new Error('--relay was given more than once; pass one relay')
  try {
    return parseRelayKey(given[0].slice('--relay='.length))
  } catch (err) {
    throw new Error(`--relay: ${/** @type {Error} */ (err).message}`)
  }
}

module.exports = { relayFlag }
