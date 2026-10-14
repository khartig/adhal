'use strict'

// closeAfterResult (engine/src/transfer.js): how a receiver that has sent
// RESULT waits before tearing down.
//
// WHY THIS FILE EXISTS. Both receivers used to end the socket and wait a
// flat 5s for the sender's close. On 2026-10-12 a 10 MB drop took 63s on
// a degraded path: the receiver saved the file, sent RESULT, gave up on
// the close after 5s and destroyed its swarm, and the sender -- still
// waiting for RESULT -- reported "connection reset by peer". The wait now
// follows the transport's acknowledgement instead of a timer, so the
// fakes below control `flush()` directly: when it resolves is the whole
// subject.

const test = require('node:test')
const assert = require('node:assert/strict')

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

test('a sender that closes in reply ends the wait at once', async () => {
  const { socket, peer, ack } = flushable()
  const waited = closeAfterResult(socket, { deliveryTimeout: 2000, grace: 2000 })
  ack()
  await wait(10)
  peer.end()
  socket.destroy()

  const { outcome, ms } = await waited
  assert.equal(outcome, 'closed')
  assert.ok(ms < 1000, `took ${ms}ms`)
})

test('an acknowledgement slower than the old 5s window is still waited for', async () => {
  // The 2026-10-12 trial, scaled down: delivery is confirmed only after a
  // delay longer than the grace window, and the sender then closes. A
  // fixed timer of `grace` would have given up first.
  const { socket, ack } = flushable()
  const waited = closeAfterResult(socket, { deliveryTimeout: 1000, grace: 100 })
  await wait(300)
  ack()
  await wait(20)
  socket.destroy()

  assert.equal((await waited).outcome, 'closed')
})

test('an acknowledged RESULT with no close in reply ends after the grace window', async () => {
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
  const { outcome } = await closeAfterResult(socket, { deliveryTimeout: 50, grace: 1000 })
  assert.equal(outcome, 'timeout')
  socket.destroy()
})

test('a transport with no flush() falls back to the grace window', async () => {
  const [socket, peer] = duplexPair()
  peer.resume()
  const { outcome } = await closeAfterResult(socket, { deliveryTimeout: 1000, grace: 50 })
  assert.equal(outcome, 'acked')
  socket.destroy()
})

test('a socket already gone is reported closed without waiting', async () => {
  const [socket] = duplexPair()
  socket.destroy()
  await wait(0)
  assert.deepEqual(await closeAfterResult(socket), { outcome: 'closed', ms: 0 })
})
