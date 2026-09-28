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
const { Channel, TYPE_MANIFEST, TYPE_CHUNK, TYPE_ACCEPT, TYPE_DECLINE } = require('@ad-hal/engine')
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
//
// EACH SIDE GETS ITS OWN COPIES, as it does from a real handshake, where the
// two views are derived on two machines. A transfer wipes the keys it was
// handed when it ends (Channel#wipe), so two sides sharing one Buffer would
// have the first to finish zero the other's keys mid-transfer -- which
// failed resume.test.js about one run in eight before this copy existed.
function channelKeys () {
  const r2s = crypto.randomBytes(32)
  const s2r = crypto.randomBytes(32)
  return {
    receiver: { sendKey: Buffer.from(r2s), receiveKey: Buffer.from(s2r) },
    sender: { sendKey: Buffer.from(s2r), receiveKey: Buffer.from(r2s) }
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
 * what it writes back (ACCEPT, DECLINE, CANCEL, RESULT).
 *
 * `offer` is the well-behaved sender's opening: MANIFEST, then the chunks
 * only once the receiver has answered ACCEPT, as the accept gate requires.
 * It resolves with the answer, `{ type, body }` with the body JSON-decoded.
 * A test that means to break the gate uses `send` directly.
 */
function sealedSender () {
  const [peer, socket] = duplexPair()
  const keys = channelKeys()
  /** @type {(a: { type: number, body: any }) => void} */
  let answered = () => {}
  /** @type {Promise<{ type: number, body: any }>} */
  const answer = new Promise((resolve) => { answered = resolve })
  const tx = sealedPeer(peer, keys.sender, {
    onMessage: (type, body) => {
      if (type === TYPE_ACCEPT || type === TYPE_DECLINE) answered({ type, body: JSON.parse(body.toString('utf8')) })
    }
  })
  /**
   * @param {object | Buffer} manifest an object is JSON-encoded; a Buffer is sent as-is
   * @param {...Buffer} chunks
   */
  const offer = async (manifest, ...chunks) => {
    tx.send(TYPE_MANIFEST, Buffer.isBuffer(manifest) ? manifest : Buffer.from(JSON.stringify(manifest), 'utf8'))
    const reply = await answer
    if (reply.type === TYPE_ACCEPT) for (const chunk of chunks) tx.send(TYPE_CHUNK, chunk)
    return reply
  }
  return { peer, socket, keys: keys.receiver, send: tx.send, offer, answer, received: tx.received, errors: tx.errors }
}

module.exports = { channelKeys, sealedPeer, sealedSender }
