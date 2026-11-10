'use strict'

// --refuse-peer-relay: a relay the PEER names is refused, and the relay
// never hears from this side (refusePeerRelays in engine/src/swarm.js;
// docs/THREAT-MODEL.md section 8; docs/UPSTREAM-HYPERDHT.md section 1).
//
// The refusal rides on two hyperdht internals, so these tests are what
// says whether it still works after an upgrade. Each has a control that
// fails if the setup could not have detected a relay at all: without one,
// "nothing was relayed" passes just as well on a testnet that connects
// everything directly.

const test = require('node:test')
const assert = require('node:assert/strict')
const createTestnet = require('hyperdht/testnet')
const HyperDHT = require('hyperdht')
const NoiseWrap = require('hyperdht/lib/noise-wrap.js')

const { createSwarm, refusePeerRelays, onPeerRelayRefused, topicFromNameplate, splitCode, generateCode } = require('@ad-hal/engine')
const { slow } = require('../test-helpers/tiers')
const { startRelay, makePunchFailing } = require('../test-helpers/relay')

/** One handshake through hyperdht's own Noise wrapper, the dialer naming a relay. */
function handshakeNamingRelay (/** @type {(kp: any, rpk: any) => any} */ createResponder) {
  const server = HyperDHT.keyPair()
  const client = HyperDHT.keyPair()
  const relay = { publicKey: HyperDHT.keyPair().publicKey, token: Buffer.alloc(32, 7) }
  const initiator = new NoiseWrap(client, server.publicKey)
  const responder = createResponder(server, null)
  const message = initiator.send({
    error: 0,
    firewall: 0,
    holepunch: null,
    addresses4: [],
    addresses6: [],
    udx: { reusableSocket: false, id: 1, seq: 0 },
    secretStream: {},
    relayThrough: relay
  })
  return { payload: responder.recv(message), relay }
}

test('a swarm refusing peer relays clears the relay a dialer names', async (t) => {
  const swarm = createSwarm({ refusePeerRelay: true })
  t.after(() => swarm.destroy())
  const refusals = /** @type {number[]} */ ([])
  onPeerRelayRefused(swarm, (n) => refusals.push(n))

  const { payload } = handshakeNamingRelay(swarm.server.createHandshake)
  assert.equal(payload.relayThrough, null, 'the relay the dialer named is gone before hyperdht reads it')
  assert.deepEqual(refusals, [1])
})

test('a swarm that does not refuse leaves the relay a dialer names in place', async (t) => {
  // The control: the handshake above really carries a relay.
  const swarm = createSwarm()
  t.after(() => swarm.destroy())
  const refusals = /** @type {number[]} */ ([])
  onPeerRelayRefused(swarm, (n) => refusals.push(n))

  const { payload, relay } = handshakeNamingRelay(swarm.server.createHandshake)
  assert.ok(payload.relayThrough, 'the payload names a relay')
  assert.ok(Buffer.from(payload.relayThrough.publicKey).equals(relay.publicKey))
  assert.deepEqual(refusals, [])
})

/**
 * A dialer that cannot punch and names `relay`, dialing a listener that
 * cannot punch either, on one topic. Resolves once `until` holds, or
 * rejects after `ms`.
 * @param {any} t
 * @param {{ refuse: boolean, until: (state: any) => boolean, ms: number }} options
 */
async function dialThroughRelay (t, { refuse, until, ms }) {
  const testnet = await createTestnet(5)
  t.after(() => testnet.destroy())
  const relay = await startRelay(testnet.bootstrap)
  t.after(() => relay.destroy())

  const listener = makePunchFailing(testnet.bootstrap)
  t.after(() => listener.destroy())
  const state = { relay, refused: 0, relayedConnections: 0, connections: 0 }
  if (refuse) {
    refusePeerRelays(listener)
    onPeerRelayRefused(listener, (n) => { state.refused = n })
  }
  listener.on('connection', (/** @type {any} */ socket) => {
    state.connections++
    if (socket.rawStream && socket.rawStream.remotePort === relay.port) state.relayedConnections++
  })

  const dialer = makePunchFailing(testnet.bootstrap, { relay: relay.publicKey })
  t.after(() => dialer.destroy())

  const topic = topicFromNameplate(splitCode(generateCode()).nameplate)
  // The listener only listens and the dialer only dials, so the one relay
  // decision under test is the listener's.
  await listener.join(topic, { server: true, client: false }).flushed()
  dialer.join(topic, { server: false, client: true })

  const started = Date.now()
  while (!until(state)) {
    if (Date.now() - started > ms) throw new Error(`timed out: ${JSON.stringify({ ...state, relay: relay.stats.pairings })}`)
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
  // The live object, not a copy: the caller may wait and look again.
  return Object.assign(state, { listenerKey: listener.dht.defaultKeyPair.publicKey.toString('hex') })
}

test('without the refusal, a listener pairs through the relay its dialer names', slow, async (t) => {
  // The control for the next test: on this setup, a relay is really used.
  const state = await dialThroughRelay(t, {
    refuse: false,
    until: (s) => s.relayedConnections > 0,
    ms: 30000
  })
  assert.ok(state.relay.stats.pairings.matched >= 1)
  assert.ok(state.relay.sessionPeers.has(state.listenerKey), 'the listener opened a session with the relay')
})

test('with the refusal, the relay never pairs and never hears from the listener', slow, async (t) => {
  const state = await dialThroughRelay(t, {
    refuse: true,
    // The dialer asked the relay to pair, and the listener refused it at
    // least once; then long enough for a pairing to have completed, which
    // takes about 1 s on a testnet once both sides ask.
    until: (s) => s.refused > 0 && s.relay.stats.pairings.requested > 0,
    ms: 30000
  })
  await new Promise((resolve) => setTimeout(resolve, 5000))

  assert.equal(state.relay.stats.pairings.matched, 0, 'no pair was ever matched')
  assert.equal(state.relay.stats.streams.opened, 0, 'no bytes had anywhere to go')
  assert.equal(state.relayedConnections, 0)
  assert.equal(state.relay.sessionPeers.has(state.listenerKey), false, 'the listener never contacted the relay')
})
