'use strict'

// Two duplex streams cross-wired to each other: what one writes, the other
// reads. Stands in for a socket in the transfer tests.
//
// WHY NOT A REAL SOCKET. Everything the failure-reporting work added -- hash verification,
// name safety, over-read, early close, cancel -- is decided entirely by
// what arrives on the stream, so a real transport would add a DHT, a
// hole punch, and a Noise session to tests whose subject is none of those.
// It would also add flake: the network tests in this suite already need
// retries and 30-second budgets. These run in milliseconds and cannot
// fail intermittently.
//
// This directory is deliberately NOT cli/test/: `node --test` treats every
// .js file under a `test` directory as a test file, so a helper placed
// there is reported as an empty passing test and inflates the count.

const { Duplex } = require('node:stream')

class Side extends Duplex {
  constructor () {
    super()
    /** @type {Side | null} */
    this.peer = null
  }

  _read () {}

  _write (chunk, _encoding, callback) {
    if (this.peer && !this.peer.destroyed) this.peer.push(chunk)
    callback()
  }

  // end() on one side must surface as 'end' on the other, or the
  // early-close path -- the one that used to hang forever -- would never
  // be reachable from a test.
  _final (callback) {
    if (this.peer && !this.peer.destroyed) this.peer.push(null)
    callback()
  }

  // An abrupt destroy is how a vanished peer actually presents: no FIN
  // handshake, the far side simply stops existing.
  _destroy (err, callback) {
    if (this.peer && !this.peer.destroyed) this.peer.push(null)
    callback(err)
  }
}

/** @returns {[Side, Side]} */
function duplexPair () {
  const a = new Side()
  const b = new Side()
  a.peer = b
  b.peer = a
  return [a, b]
}

module.exports = { duplexPair }
