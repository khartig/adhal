'use strict'

// The v2 channel from a test's side of the stream.
//
// Every frame sendFile and receiveFile exchange is sealed (PROTOCOL.md
// section 3.4), so a test that plays the peer by hand has to seal and open
// too -- a cleartext frame written at receiveFile now fails to
// authenticate, which is the point. These helpers stand in for the
// handshake: the keys are random rather than PAKE-derived, because what
// these tests exercise is the transfer, and the handshake has its own
// suite (pake-handshake.test.js) that checks the keys it derives against
// a Channel.
//
// Not in cli/test/ for the reason duplex-pair.js gives.

const crypto = require('node:crypto')
const { Channel } = require('@quay/engine')
const { duplexPair } = require('./duplex-pair')

/**
 * A fresh pair of directional keys, and each side's view of them: the
 * receiver sends under k_r2s and receives under k_s2r, and the sender does
 * the reverse. Spread a view into sendFile/receiveFile's options.
 *
 * @returns {{
 *   receiver: { sendKey: Buffer, receiveKey: Buffer },
 *   sender: { sendKey: Buffer, receiveKey: Buffer }
 * }}
 */
function channelKeys () {
  const r2s = crypto.randomBytes(32)
  const s2r = crypto.randomBytes(32)
  return {
    receiver: { sendKey: r2s, receiveKey: s2r },
    sender: { sendKey: s2r, receiveKey: r2s }
  }
}

/**
 * A hand-rolled peer on `socket`, speaking the sealed channel under `view`.
 * `send` seals one message and writes it; every frame the far side writes
 * is opened and recorded in `received`, and handed to `onMessage` if given.
 *
 * A frame that fails to open is recorded in `errors` rather than thrown: a
 * throw from a 'data' listener would take the test process down instead of
 * failing the one test.
 *
 * @param {any} socket
 * @param {{ sendKey: Buffer, receiveKey: Buffer }} view
 * @param {{ onMessage?: (type: number, body: Buffer) => void }} [options]
 */
function sealedPeer (socket, view, { onMessage } = {}) {
  /** @type {Array<{ type: number, body: Buffer }>} */
  const received = []
  /** @type {any[]} */
  const errors = []
  const channel = new Channel({
    ...view,
    onMessage: (type, body) => {
      received.push({ type, body })
      if (onMessage) onMessage(type, body)
    }
  })
  socket.on('data', (/** @type {Buffer} */ chunk) => {
    try {
      channel.push(chunk)
    } catch (err) {
      errors.push(err)
    }
  })
  return {
    channel,
    received,
    errors,
    /**
     * @param {number} type
     * @param {Buffer} body
     */
    send: (type, body) => socket.write(channel.seal(type, body))
  }
}

/**
 * The shape most receiver tests want: a stream for receiveFile, the keys to
 * give it, and a hand-rolled sender on the other end. Spread `keys` into
 * receiveFile's options; `send` seals a message at it; `received` collects
 * what it writes back (CANCEL, RESULT).
 */
function sealedSender () {
  const [peer, socket] = duplexPair()
  const keys = channelKeys()
  const tx = sealedPeer(peer, keys.sender)
  return { peer, socket, keys: keys.receiver, send: tx.send, received: tx.received, errors: tx.errors }
}

module.exports = { channelKeys, sealedPeer, sealedSender }
