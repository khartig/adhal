'use strict'

// The per-drop announce key (THREAT-MODEL.md section 4, Q-12).
//
// Nothing links two drops only if no DHT-visible value is shared between
// them, and the announce public key is the obvious candidate. It is fresh
// per drop because engine/src/swarm.js's createSwarm generates one for
// every swarm and refuses a caller's. Before W15b that was an unstated
// Hyperswarm default, and nothing tested it: a library upgrade, or a
// well-meant "keep this device" feature passing a stored keypair, would
// have made every drop by one user linkable, silently.

const test = require('node:test')
const assert = require('node:assert/strict')
const createTestnet = require('hyperdht/testnet')

const { createSwarm, acceptOnce, connectOnce, generateCode, splitCode, topicFromNameplate } = require('@ad-hal/engine')
const { slow } = require('../test-helpers/tiers')

test('every swarm gets its own announce keypair, and a caller cannot supply one', async (t) => {
  // An empty bootstrap list: no network is touched.
  const a = createSwarm({ bootstrap: [] })
  const b = createSwarm({ bootstrap: [] })
  t.after(() => Promise.all([a.destroy(), b.destroy()]))

  assert.equal(a.keyPair.publicKey.length, 32)
  assert.equal(a.keyPair.publicKey.equals(b.keyPair.publicKey), false, 'two drops, two keys')

  const stored = { publicKey: Buffer.alloc(32, 1), secretKey: Buffer.alloc(64, 1) }
  assert.throws(
    () => createSwarm(/** @type {any} */ ({ bootstrap: [], keyPair: stored })),
    /does not take a keyPair/,
    'a persistent identity must never be what the DHT sees'
  )
})

test('two drops from one process are seen under different keys by the peer', slow, async (t) => {
  const testnet = await createTestnet(3)
  t.after(() => testnet.destroy())

  /** @type {Buffer[]} */
  const seen = []
  /** @type {Buffer[]} */
  const own = []
  for (let drop = 0; drop < 2; drop++) {
    const halves = splitCode(generateCode())
    const topic = topicFromNameplate(halves.nameplate)
    const receiver = createSwarm({ bootstrap: testnet.bootstrap })
    const sender = createSwarm({ bootstrap: testnet.bootstrap })
    /** @type {(value?: any) => void} */
    let announced = () => {}
    const ready = new Promise((resolve) => { announced = resolve })
    const accepted = acceptOnce(receiver, topic, { ...halves, timeout: 60000, onAnnounced: () => announced() })
    await ready
    const [rx, tx] = await Promise.all([accepted, connectOnce(sender, topic, { ...halves, timeout: 60000 })])
    for (const side of [rx, tx]) {
      side.socket.on('error', () => {})
      side.socket.destroy()
    }
    // What the sender saw is what the DHT saw: the receiver's announce key.
    seen.push(tx.peerInfo.publicKey)
    own.push(receiver.keyPair.publicKey)
    await Promise.all([receiver.destroy(), sender.destroy()])
  }

  assert.ok(seen[0].equals(own[0]) && seen[1].equals(own[1]), 'the key a peer sees is the one createSwarm generated')
  assert.equal(seen[0].equals(seen[1]), false, 'one receiver, two drops, two unlinkable keys')
})
