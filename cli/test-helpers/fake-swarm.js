'use strict'

// acceptOnce and connectOnce over an in-memory swarm. Everything they
// decide about a candidate -- count it, drop it, delay it, pair with it --
// happens on the socket they are handed, so a fake swarm that hands them
// one end of a duplex pair tests exactly those decisions, without the DHT.
// That makes the rules testable every time, in milliseconds, and without
// the testnet's pairing race (docs/history/WORK-RECORD.md, W15d; see
// UNANSWERED_CONNECTION_MS in engine/src/swarm.js).
//
// Not in cli/test/ for the reason duplex-pair.js gives.

const crypto = require('node:crypto')
const { EventEmitter } = require('node:events')
const { duplexPair } = require('./duplex-pair')

class FakeSwarm extends EventEmitter {
  join () {
    return { flushed: () => Promise.resolve(), refresh: () => Promise.resolve() }
  }

  /**
   * A candidate arrives. `play` is handed the far end, to act the peer,
   * and the near end, which is what the swarm gives acceptOnce/connectOnce
   * -- destroying it with an error is how a test says "the transport
   * reported the connection reset".
   *
   * @param {(far: any, near: any) => void} play
   * @returns {{ far: any, near: any }}
   */
  candidate (play) {
    const [near, far] = duplexPair()
    near.on('error', () => {})
    far.on('error', () => {})
    const peerInfo = { publicKey: crypto.randomBytes(32) }
    play(far, near)
    this.emit('connection', near, peerInfo)
    return { far, near }
  }
}

module.exports = { FakeSwarm }
