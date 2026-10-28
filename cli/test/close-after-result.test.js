'use strict'

// closeAfterResult (engine/src/transfer.js): how a receiver that has sent
// RESULT waits before tearing down.
//
// WHY THIS FILE EXISTS. Both receivers used to end the socket and wait a
// flat 5s for the sender's close. On 2026-10-12 a 10 MB drop took 63s on
// a degraded path: the receiver saved the file, sent RESULT, gave up on
// the close after 5s, and destroyed its swarm, and the sender -- still
// waiting for RESULT -- reported "connection reset by peer". The wait now
// follows the transport's acknowledgment instead of a timer, so the
// fakes below control `flush()` directly: when it resolves is most of the
// subject. The rest is telling the sender's end of stream, the only
// reply that means it read RESULT, from a connection that merely closed.

const test = require('node:test')
const assert = require('node:assert/strict')
const { EventEmitter } = require('node:events')

const { closeAfterResult } = require('@ad-hal/engine')
const { duplexPair } = require('../test-helpers/duplex-pair')

/** A socket whose flush() settles when the test says. */
function flushable () {
  const [socket, peer] = duplexPair()
  /** @type {(ok: boolean) => void} */
  let settleFlush = () => {}
  const flushed = new Promise((resolve) => { settleFlush = resolve })
  Object.assign(socket, { flush: () => flushed })
  peer.resume()
  return { socket, peer, ack: () => settleFlush(true) }
}

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

test('a sender that ends in reply ends the wait at once', async () => {
  const { socket, peer, ack } = flushable()
  const waited = closeAfterResult(socket, { deliveryTimeout: 2000, grace: 2000 })
  ack()
  await wait(10)
  peer.end()

  const { outcome, ms, acked } = await waited
  assert.equal(outcome, 'closed')
  assert.equal(acked, true)
  assert.ok(ms < 1000, `took ${ms}ms`)
})

test('an acknowledgment slower than the old 5s window is still waited for', async () => {
  // The 2026-10-12 trial, scaled down: delivery is confirmed only after a
  // delay longer than the grace window, and the sender then ends. A fixed
  // timer of `grace` would have given up first.
  const { socket, peer, ack } = flushable()
  const waited = closeAfterResult(socket, { deliveryTimeout: 1000, grace: 100 })
  await wait(300)
  ack()
  await wait(20)
  peer.end()

  assert.equal((await waited).outcome, 'closed')
})

test('a connection that dies after RESULT is lost, not closed by the sender', async () => {
  // 2026-10-13, run A trial 10, scaled down: the receiver's connection
  // closed 2.2 s after RESULT with no end from the sender, which never got
  // RESULT. This used to be reported as 'closed', and counted as the
  // sender's reply.
  const { socket } = flushable()
  const waited = closeAfterResult(socket, { deliveryTimeout: 1000, grace: 1000 })
  await wait(20)
  socket.destroy(Object.assign(new Error('connection timed out'), { code: 'ETIMEDOUT' }))

  const { outcome, acked, error } = await waited
  assert.equal(outcome, 'lost')
  assert.equal(acked, false)
  assert.equal(error, 'connection timed out')
})

test('a connection that dies after the transport confirmed RESULT is acked, not lost', async () => {
  const { socket, ack } = flushable()
  const waited = closeAfterResult(socket, { deliveryTimeout: 1000, grace: 1000 })
  ack()
  await wait(20)
  socket.destroy()

  const { outcome, acked } = await waited
  assert.equal(outcome, 'acked')
  assert.equal(acked, true)
})

test('an end that arrived before the wait began still counts as the reply', async () => {
  // In-memory transports deliver synchronously, so a sender's end can land
  // before closeAfterResult is called at all, and its 'end' event with it.
  const { socket, peer } = flushable()
  peer.end()
  await wait(10)
  const { outcome } = await closeAfterResult(socket, { deliveryTimeout: 1000, grace: 1000 })
  assert.equal(outcome, 'closed')
})

test('an acknowledged RESULT with no end in reply finishes after the grace window', async () => {
  const { socket, ack } = flushable()
  const waited = closeAfterResult(socket, { deliveryTimeout: 1000, grace: 50 })
  ack()

  const { outcome, ms } = await waited
  assert.equal(outcome, 'acked')
  assert.ok(ms < 500, `took ${ms}ms`)
  socket.destroy()
})

test('a RESULT the transport never acknowledges times out, and says so', async () => {
  const { socket } = flushable()
  const { outcome, acked } = await closeAfterResult(socket, { deliveryTimeout: 50, grace: 1000 })
  assert.equal(outcome, 'timeout')
  assert.equal(acked, false)
  socket.destroy()
})

test('a transport with no flush() falls back to the grace window', async () => {
  const [socket, peer] = duplexPair()
  peer.resume()
  const { outcome } = await closeAfterResult(socket, { deliveryTimeout: 1000, grace: 50 })
  assert.equal(outcome, 'acked')
  socket.destroy()
})

test('a socket already gone is lost unless the sender had ended it', async () => {
  const [gone] = duplexPair()
  gone.destroy()
  await wait(0)
  assert.equal((await closeAfterResult(gone)).outcome, 'lost')

  const [ended, peer] = duplexPair()
  peer.end()
  ended.resume()
  await wait(10)
  ended.destroy()
  await wait(0)
  assert.equal((await closeAfterResult(ended)).outcome, 'closed')
})

// --- what the transport says, read literally ------------------------------

test('a flush that fails, or reports the socket going, is not an acknowledgment', async () => {
  // flush() is the only delivery signal there is, so only a flush that
  // resolves true may count as one. A rejected flush and a flush that
  // answers false both mean the socket is on its way out, and a close
  // after either is a connection that died with RESULT unconfirmed.
  for (const flush of [() => Promise.reject(new Error('flush failed')), () => Promise.resolve(false)]) {
    const [socket, peer] = duplexPair()
    Object.assign(socket, { flush })
    peer.resume()
    const waited = closeAfterResult(socket, { deliveryTimeout: 1000, grace: 1000 })
    await wait(20)
    socket.destroy()

    const { outcome, acked } = await waited
    assert.equal(outcome, 'lost')
    assert.equal(acked, false)
  }
})

test('a socket error with no message is still reported as something', async () => {
  // `error` goes into the receiver's log beside the outcome. An error
  // whose message is empty must not turn into an empty string there,
  // which reads as "no error" to anyone scanning for one.
  const { socket } = flushable()
  const waited = closeAfterResult(socket, { deliveryTimeout: 1000, grace: 1000 })
  await wait(20)
  socket.destroy(new Error())

  const { outcome, error } = await waited
  assert.equal(outcome, 'lost')
  assert.equal(error, 'Error')
})

test('an end that was never read still counts as the reply on a socket already gone', async () => {
  // Nothing read the socket, so its 'end' event never fired and
  // readableEnded is false -- but the sender's end of stream did arrive,
  // and the stream's state says so. That state is the only record of it.
  const [socket, peer] = duplexPair()
  peer.end()
  await wait(10)
  socket.destroy()
  await wait(0)
  assert.equal(socket.readableEnded, false, 'the premise: no end event was emitted')
  assert.equal((await closeAfterResult(socket)).outcome, 'closed')
})

// A socket with a streamx stream's readable state (the Hyperswarm socket):
// no readableEnded, `ended` once the end of stream is delivered, and
// `ending` in the moment before. The Node duplex pair above has neither
// `ending` nor streamx's ordering, so the cases that hinge on them are
// played here by hand.
function streamxLike ({ ended = false } = {}) {
  const socket = /** @type {any} */ (new EventEmitter())
  socket.destroyed = false
  socket._readableState = { ended, ending: false }
  socket.resume = () => {}
  socket.end = () => {}
  return socket
}

test('on a streamx socket, an end delivered before the wait began counts as the reply', async () => {
  // Hyperswarm's socket has no readableEnded, so the readable state is
  // the only way to see an end whose event fired before this was called.
  const socket = streamxLike({ ended: true })
  const waited = closeAfterResult(socket, { deliveryTimeout: 1000, grace: 1000 })
  await wait(10)
  socket.emit('close')
  assert.equal((await waited).outcome, 'closed')
})

test('on a streamx socket, an end still being delivered when the close lands counts as the reply', async () => {
  // streamx marks the end as `ending` before it emits 'end'. A close in
  // that window comes with no end event, and the state is all there is.
  const socket = streamxLike()
  const waited = closeAfterResult(socket, { deliveryTimeout: 1000, grace: 1000 })
  await wait(10)
  socket._readableState.ending = true
  socket.emit('close')
  assert.equal((await waited).outcome, 'closed')
})

test('on a streamx socket, a close with no end is not the sender\'s reply', async () => {
  // The 2026-10-13 trial again, on the transport it happened on: a
  // connection that died after RESULT, with no end from the sender, is
  // not "closed by sender", whatever else it is.
  const socket = streamxLike()
  socket.flush = () => new Promise(() => {})
  const waited = closeAfterResult(socket, { deliveryTimeout: 1000, grace: 1000 })
  await wait(10)
  socket.emit('close')
  const { outcome, acked } = await waited
  assert.equal(outcome, 'lost')
  assert.equal(acked, false)
})
