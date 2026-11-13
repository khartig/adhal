'use strict'

// Loaded with `node --require` into a CLI a test spawns: every HyperDHT in
// that process becomes one whose hole punch always fails, so a connection
// it makes is relayed or nothing. The same three changes as makePunchFailing
// in ./relay.js, which says why each is needed on a testnet: an ephemeral
// node, no remote address (so it looks firewalled), and peer dials that
// refuse to punch and skip the LAN shortcut and fast-open.
//
// Peer dials are told apart from relay dials the way watchRelayDials in
// engine/src/swarm.js tells them apart: Hyperswarm passes a keyPair, and
// hyperdht's own dial to a relay passes no options. A relay must stay
// reachable without a punch.
//
// A preload, not an option in the CLIs: nothing in shipping code exists
// only to break it.

const Module = require('node:module')

/** @type {any} */
const loader = Module
const load = loader._load
/** @type {any} */
let PunchFailingDHT = null

loader._load = function (/** @type {string} */ request, /** @type {any[]} */ ...rest) {
  const exported = load.call(this, request, ...rest)
  if (request !== 'hyperdht') return exported
  if (!PunchFailingDHT) {
    PunchFailingDHT = class extends exported {
      constructor (/** @type {any} */ opts = {}) {
        super({ ...opts, ephemeral: true })
      }

      remoteAddress () {
        return null
      }

      connect (/** @type {any} */ publicKey, /** @type {any} */ opts) {
        if (!opts || opts.keyPair === undefined) return super.connect(publicKey, opts)
        return super.connect(publicKey, { ...opts, holepunch: () => false, localConnection: false, fastOpen: false })
      }
    }
  }
  return PunchFailingDHT
}
