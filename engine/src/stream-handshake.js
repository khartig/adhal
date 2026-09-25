'use strict'

const { MessageReader } = require('./reader')
const { Initiator, Responder, assertHandshakeInputs } = require('./handshake')
const { TransferError, abortError } = require('./errors')
const { HANDSHAKE_TIMEOUT_MS } = require('./swarm')

// The v2 handshake over one already-connected duplex stream, with no swarm
// around it.
//
// WHY THIS EXISTS. PROTOCOL.md section 3.3 moved channel binding off the
// Noise session and onto the PAKE transcript so that "security stops
// depending on which transport carried the bytes". ./swarm.js is one
// transport; this is the proof that the claim is true of others. The
// loopback CLI (cli/src/send.js, receive.js) runs it over plain TCP on
// 127.0.0.1 -- no Noise at all underneath -- and the channel it keys is
// exactly as strong as the one over Hyperswarm, because nothing about it
// came from the transport.
//
// WHAT IT DELIBERATELY DOES NOT DO, relative to acceptOnce/connectOnce.
// Those manage a stream of candidate peers: discard the dead ones, count
// the failed confirmations (./attempts.js), back off. Here there is one
// stream and one attempt. A failed confirmation rejects, and the caller
// decides what a failure costs -- the loopback receiver treats it as the
// end of the drop, which is an attempt cap of one: strictly tighter than
// section 6's. The message logic itself is not duplicated: Initiator and
// Responder are the same classes swarm.js uses, so the parameter mapping
// exists in one place.
//
// The socket is NOT destroyed on failure. The caller lent it and still
// owns it; this removes its own listeners and rejects.

/**
 * Drives one side of the handshake to completion or failure.
 *
 * @param {any} socket
 * @param {{ timeout: number, signal?: AbortSignal, role: string }} options
 * @param {(reader: InstanceType<typeof MessageReader>) => ({ sendKey: Buffer, receiveKey: Buffer, caps: string[] } | null)} step
 *   called with the reader on every chunk; returns the settled keys once
 *   the handshake completes, null while it is still arriving, and throws
 *   if it fails.
 * @param {() => void} [start] writes this side's opening message, if any
 * @returns {Promise<{ pending: Buffer | null, sendKey: Buffer, receiveKey: Buffer, caps: string[] }>}
 */
function drive (socket, { timeout, signal, role }, step, start) {
  return new Promise((resolve, reject) => {
    if (signal && signal.aborted) {
      reject(abortError(0, signal.reason))
      return
    }

    const reader = new MessageReader()
    let settled = false

    const timer = timeout
      ? setTimeout(() => fail(new TransferError(
        'ERR_STALLED',
        `the ${role} handshake did not complete within ${timeout}ms`,
        { phase: 'handshake', role }
      )), timeout)
      : null
    if (timer && typeof timer.unref === 'function') timer.unref()

    function detach () {
      if (timer) clearTimeout(timer)
      socket.removeListener('data', onData)
      socket.removeListener('error', fail)
      socket.removeListener('end', onClosed)
      socket.removeListener('close', onClosed)
      if (signal) signal.removeEventListener('abort', onAbort)
    }

    /** @param {any} err */
    function fail (err) {
      if (settled) return
      settled = true
      detach()
      reject(err)
    }

    // `phase` tells the CLI's report that no transfer had started, so it
    // does not speak of bytes received or a partial discarded.
    function onClosed () {
      fail(new TransferError(
        'ERR_CONNECTION',
        `the peer disconnected before the ${role} handshake completed`,
        { phase: 'handshake', role }
      ))
    }

    function onAbort () {
      fail(abortError(0, signal && signal.reason))
    }

    /** @param {Buffer} chunk */
    function onData (chunk) {
      if (settled) return
      reader.push(chunk)
      let done
      try {
        done = step(reader)
      } catch (err) {
        fail(err)
        return
      }
      if (!done) return
      settled = true
      detach()
      // Held until the caller attaches its own reader, for the reason
      // acceptOnce gives: removing a 'data' listener does not pause a
      // stream, and anything arriving in the gap would be lost.
      if (typeof socket.pause === 'function') socket.pause()
      resolve({ pending: reader.rest(), sendKey: done.sendKey, receiveKey: done.receiveKey, caps: done.caps })
    }

    socket.on('data', onData)
    socket.once('error', fail)
    socket.once('end', onClosed)
    socket.once('close', onClosed)
    if (signal) signal.addEventListener('abort', onAbort, { once: true })
    if (typeof socket.resume === 'function') socket.resume()
    if (start) start()
  })
}

/**
 * The receiver's side (CPace initiator): writes HELLO, reads REPLY, writes
 * CONFIRM. Resolves with this side's channel keys -- k_r2s to send under,
 * k_s2r to receive under -- ready for receiveFile.
 *
 * @param {any} socket
 * @param {{ secret: string, nameplate: string, timeout?: number, signal?: AbortSignal }} options
 */
function acceptStream (socket, { secret, nameplate, timeout = HANDSHAKE_TIMEOUT_MS, signal }) {
  // Up front, as acceptOnce does, so a bad secret is a TypeError about the
  // caller rather than a confirmation failure blamed on the peer.
  assertHandshakeInputs(secret, nameplate)
  // One Initiator per stream: its scalar and sid are per connection
  // (section 3.2 trap #1), and this call is one connection.
  const handshake = new Initiator({ secret, nameplate })
  return drive(socket, { timeout, signal, role: 'receiver' }, (reader) => {
    const confirmed = handshake.readReply(reader)
    if (!confirmed) return null
    // CONFIRM goes out before resolving, so the sender is released into
    // sendFile only once we are on our way into receiveFile.
    socket.write(confirmed.confirm)
    return confirmed
  }, () => socket.write(handshake.hello()))
}

/**
 * The sender's side (CPace responder): reads HELLO, writes REPLY, reads
 * CONFIRM. Resolves with k_s2r to send under and k_r2s to receive under,
 * ready for sendFile.
 *
 * @param {any} socket
 * @param {{ secret: string, nameplate: string, timeout?: number, signal?: AbortSignal }} options
 */
function connectStream (socket, { secret, nameplate, timeout = HANDSHAKE_TIMEOUT_MS, signal }) {
  assertHandshakeInputs(secret, nameplate)
  const handshake = new Responder({ secret, nameplate })
  let replied = false
  return drive(socket, { timeout, signal, role: 'sender' }, (reader) => {
    if (!replied) {
      const answer = handshake.readHello(reader)
      if (!answer) return null
      replied = true
      socket.write(answer.reply)
    }
    // CONFIRM depends on our REPLY, so it never arrives with HELLO and
    // this returns null the first time through. It is read here, rather
    // than in a separate branch, so the chunk that does carry it takes
    // the same path as connectOnce's.
    return handshake.readConfirm(reader)
  })
}

module.exports = { acceptStream, connectStream }
