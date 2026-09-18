'use strict'

// Item 4 / data path step 3: a peer must prove it knows the drop code.
//
// The threat these tests pin down is not hypothetical, and the repo already
// contains the tool that demonstrates it: a receiver has to announce
// hash(code || salt) on the DHT to be findable, `engine/scratch-lookup.js`
// walks the DHT and finds exactly that, and before this handshake the
// answer to READY was the constant byte 0x02. So anyone who scraped a
// topic could complete the handshake and be handed a file -- or hand one
// over, into the other side's ~/Downloads.
//
// Four ways to fail the proof are covered, because they fail for four
// different reasons and a fix for one is not a fix for another:
//
//   wrong code  -- no key at all; the base case
//   reflected   -- has the real key, but replays one direction's proof
//                  into the other. Defeated by the "s"/"r" domain tags.
//   replayed    -- has a real proof captured off an earlier exchange.
//                  Defeated by the per-attempt nonces.
//   relayed     -- gets an honest peer to answer a challenge on its
//                  behalf. Defeated by binding the proof to the Noise
//                  session. See bindPeers in engine/src/proof.js for why
//                  the first three defences do not cover this one.
//
// The unit tests come first and isolate one defence each, which is the only
// way to know *which* check rejected a proof; the network tests then show
// the whole thing holding up inside a real swarm, and -- just as
// importantly -- that a rejected attacker does not consume the receiver.

const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('node:path')
const os = require('node:os')
const fs = require('node:fs')
const crypto = require('node:crypto')
const createTestnet = require('hyperdht/testnet')

const {
  createSwarm,
  acceptOnce,
  connectOnce,
  topicFromCode,
  generateCode,
  sendFile,
  receiveFile,
  dropKey,
  makeNonce,
  bindPeers,
  proveRole,
  proofMatches,
  MessageReader,
  NONCE_SIZE,
  PROOF_SIZE
} = require('@quay/engine')

const HELLO_SIZE = 1 + NONCE_SIZE
const SENDER_PROOF_SIZE = PROOF_SIZE + NONCE_SIZE
const READY = 0x01

// Stand-in public keys for the unit tests, which are about the HMAC input
// and not about Hyperswarm.
const PEERS = { receiver: Buffer.alloc(32, 0xaa), sender: Buffer.alloc(32, 0xbb) }
const OTHER_PEERS = { receiver: Buffer.alloc(32, 0xaa), sender: Buffer.alloc(32, 0xcc) }

test('the key comes from the code, not the topic, and is stable across callers', () => {
  const code = generateCode()
  assert.deepEqual(dropKey(code), dropKey(code), 'both peers must derive the same key')
  assert.notDeepEqual(dropKey(code), dropKey(generateCode()))
  assert.equal(dropKey(code).length, 32)

  // The key must not be derivable from what an attacker actually has. The
  // topic is public once announced; the code is not.
  const topic = topicFromCode(code)
  assert.notDeepEqual(dropKey(code), topic)

  // Canonicalization is the caller's job, and getting it wrong is a real
  // hazard rather than a theoretical one: this is the same trap topic.js
  // documents, except here the two peers *do* find each other and then
  // reject each other, which reads like an attack rather than a typo.
  assert.notDeepEqual(dropKey(code), dropKey(code.toUpperCase()))
})

test('a valid proof verifies, and nothing else does', () => {
  const key = dropKey(generateCode())
  const nonce = makeNonce()
  const good = proveRole(key, 'sender', nonce, PEERS)

  assert.ok(proofMatches(proveRole(key, 'sender', nonce, PEERS), good))
  assert.equal(good.length, PROOF_SIZE)

  // Wrong code: the base case the whole item exists for.
  const wrongKey = dropKey(generateCode())
  assert.ok(!proofMatches(proveRole(wrongKey, 'sender', nonce, PEERS), good))

  // Truncated and over-long answers are rejected rather than throwing.
  // timingSafeEqual raises on a length mismatch, so without an explicit
  // length check a peer could take the process down by answering with the
  // wrong number of bytes.
  assert.ok(!proofMatches(good, good.subarray(0, PROOF_SIZE - 1)))
  assert.ok(!proofMatches(good, Buffer.concat([good, Buffer.from([0])])))
  assert.ok(!proofMatches(good, Buffer.alloc(0)))
})

test('the domain tags stop one direction\'s proof being reflected into the other', () => {
  const key = dropKey(generateCode())
  const nonce = makeNonce()

  const senderProof = proveRole(key, 'sender', nonce, PEERS)
  const receiverProof = proveRole(key, 'receiver', nonce, PEERS)

  // Same key, same nonce, same session: only the tag differs. Without the
  // tags these would be byte-identical, and an attacker could take whatever
  // one side emitted and present it back as its own proof.
  assert.notDeepEqual(senderProof, receiverProof)
  assert.ok(!proofMatches(senderProof, receiverProof))
  assert.ok(!proofMatches(receiverProof, senderProof))
})

test('the nonces stop a proof being replayed onto a later attempt', () => {
  const key = dropKey(generateCode())
  const first = makeNonce()
  const second = makeNonce()

  // Everything held constant except the challenge, so this test can only
  // fail if nonce freshness is what broke.
  const captured = proveRole(key, 'sender', first, PEERS)
  assert.ok(!proofMatches(proveRole(key, 'sender', second, PEERS), captured))
  assert.ok(proofMatches(proveRole(key, 'sender', first, PEERS), captured))
})

test('binding to the session stops a proof obtained from an honest peer being relayed', () => {
  const key = dropKey(generateCode())
  const nonce = makeNonce()

  // The attack this closes, in full, is in bindPeers's comment. The shape
  // of it: an attacker gets the honest sender to answer the honest
  // receiver's challenge, on the attacker's own connection, and forwards
  // the result. Every nonce is fresh and every tag is right, so those two
  // defences pass it through. What stops it is that a proof made on one
  // Noise session must be worthless on another -- the attacker cannot
  // borrow the honest sender's public key, having no private half.
  const onOneSession = proveRole(key, 'sender', nonce, PEERS)
  const expectedOnAnother = proveRole(key, 'sender', nonce, OTHER_PEERS)
  assert.ok(!proofMatches(expectedOnAnother, onOneSession))

  // And the role ordering must not be sortable-into-agreement by accident:
  // swapping which key is the receiver's has to change the proof, or a
  // proof from the A<->S session would verify on the R<->A one.
  const swapped = proveRole(key, 'sender', nonce, { receiver: PEERS.sender, sender: PEERS.receiver })
  assert.ok(!proofMatches(swapped, onOneSession))
})

test('a fixed-size message is read by byte count, not per chunk', () => {
  // The constant-byte handshake could read a whole message out of one
  // 'data' event. A 64-byte one cannot rely on that in either direction:
  // it may arrive split, or coalesced with what follows.
  const reader = new MessageReader()
  const message = crypto.randomBytes(SENDER_PROOF_SIZE)
  const trailing = Buffer.from('manifest-ish')

  reader.push(message.subarray(0, 10))
  assert.equal(reader.take(SENDER_PROOF_SIZE), null, 'must not consume a partial message')
  reader.push(message.subarray(10))
  reader.push(trailing)

  assert.deepEqual(reader.take(SENDER_PROOF_SIZE), message)
  assert.deepEqual(reader.rest(), trailing, 'bytes after the message must be handed on, not dropped')
  assert.equal(new MessageReader().rest(), null)
})

// --- network tests -------------------------------------------------------

// A peer that speaks the handshake by hand, so a test can send proofs the
// engine would never produce. `read(n)` resolves with exactly n bytes.
async function scriptedPeer (bootstrap, topic, script) {
  const swarm = createSwarm({ bootstrap })
  /** @type {Promise<any>} */
  const ran = new Promise((resolve, reject) => {
    swarm.on('connection', (socket, peerInfo) => {
      socket.on('error', () => {})
      const reader = new MessageReader()
      /** @type {{ size: number, resolve: (b: Buffer) => void } | null} */
      let waiting = null

      socket.on('data', (chunk) => {
        reader.push(chunk)
        if (!waiting) return
        const message = reader.take(waiting.size)
        if (!message) return
        const pending = waiting
        waiting = null
        pending.resolve(message)
      })

      const read = (size) => new Promise((done) => {
        const buffered = reader.take(size)
        if (buffered) return done(buffered)
        waiting = { size, resolve: done }
      })

      script({ socket, peerInfo, read }).then(resolve, reject)
    })
  })

  const discovery = swarm.join(topic)
  await discovery.flushed()
  return { swarm, ran }
}

function waitFor (predicate, what, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const start = Date.now()
    const timer = setInterval(() => {
      if (predicate()) { clearInterval(timer); resolve(undefined) } else if (Date.now() - start > timeoutMs) {
        clearInterval(timer)
        reject(new Error(`timed out waiting for ${what}`))
      }
    }, 20)
  })
}

// Reads the receiver's READY + challenge, then answers with whatever
// `forge` produces. Returns once those bytes are on the wire.
function answerWith (forge) {
  return async ({ socket, read }) => {
    const hello = await read(HELLO_SIZE)
    assert.equal(hello[0], READY, 'the receiver should open with READY')
    const nonceR = hello.subarray(1)
    socket.write(forge({ socket, nonceR }))
    return { answered: true }
  }
}

test('a peer that found the topic but cannot prove the code is rejected, and the receiver keeps waiting', async (t) => {
  const testnet = await createTestnet(3)
  t.after(() => testnet.destroy())

  const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'quay-proof-'))
  t.after(() => fs.rmSync(tmpDir, { recursive: true, force: true }))

  const sourcePath = path.join(tmpDir, 'source.bin')
  const outputDir = path.join(tmpDir, 'received')
  await fs.promises.mkdir(outputDir, { recursive: true })
  const payload = crypto.randomBytes(128 * 1024)
  await fs.promises.writeFile(sourcePath, payload)
  const expected = crypto.createHash('sha256').update(payload).digest('hex')

  // Everything the attackers get is what walking the DHT would give them:
  // the topic. Only the honest sender is given the code.
  const code = generateCode()
  const topic = topicFromCode(code)
  const key = dropKey(code)

  const receiveSwarm = createSwarm({ bootstrap: testnet.bootstrap })
  t.after(() => receiveSwarm.destroy())

  /** @type {string[]} */
  const dropped = []
  let announce
  const announced = new Promise((resolve) => { announce = resolve })

  const accepted = acceptOnce(receiveSwarm, topic, {
    key,
    timeout: 120000,
    onAnnounced: () => announce(),
    onCandidateDropped: (info, reason) => dropped.push(reason)
  })
  await announced

  // Each attacker connects, is rejected, and leaves before the next one
  // arrives. Leaving matters: a swarm that stays joined keeps getting
  // re-dialed, and three of them camped on one topic starve the honest
  // sender of the parallel-dial slots engine/src/swarm.js documents -- 21
  // candidates and no completed drop, when first measured. That crowding is
  // real, but it is a MAX_PARALLEL question and not this test's subject.
  const proofFailures = () => dropped.filter((r) => /failed the code proof/.test(r)).length

  async function expectRejected (what, forge) {
    const before = proofFailures()
    const peer = await scriptedPeer(testnet.bootstrap, topic, answerWith(forge))
    try {
      await peer.ran
      await waitFor(() => proofFailures() > before, `the ${what} peer to be rejected`)
    } finally {
      await peer.swarm.destroy()
    }
  }

  // 1. Wrong code: the stranger from scratch-lookup.js, who has the topic
  //    and nothing else. It has to guess at a key.
  await expectRejected('wrong-code', ({ socket, nonceR }) => Buffer.concat([
    proveRole(dropKey(generateCode()), 'sender', nonceR, bindPeers(socket, 'sender')),
    makeNonce()
  ]))

  // 2. Reflected: this one is *given the real key*, so it is a strictly
  //    stronger attacker than any real one -- and it still fails, because
  //    it produces the receiver's own side of the exchange instead of the
  //    sender's. Only the domain tag distinguishes the two.
  await expectRejected('reflected-proof', ({ socket, nonceR }) => Buffer.concat([
    proveRole(key, 'receiver', nonceR, bindPeers(socket, 'sender')),
    makeNonce()
  ]))

  // 3. Junk of the right length, to confirm the size check rejects rather
  //    than throws -- a peer must not be able to kill the process by
  //    answering with the wrong number of bytes.
  await expectRejected('junk-proof', () => crypto.randomBytes(SENDER_PROOF_SIZE))

  assert.ok(proofFailures() >= 3, `expected three rejected proofs, got ${JSON.stringify(dropped)}`)

  // The point of discarding rather than failing: three attackers in a row
  // must not cost the receiver its drop. A genuine sender still completes.
  const sendSwarm = createSwarm({ bootstrap: testnet.bootstrap })
  t.after(() => sendSwarm.destroy())

  const [{ socket: rxSocket, pending }, { socket: txSocket }] = await Promise.all([
    accepted,
    connectOnce(sendSwarm, topic, { key, timeout: 120000 })
  ])
  rxSocket.on('error', () => {})
  txSocket.on('error', () => {})

  const [received, sent] = await Promise.all([
    receiveFile(rxSocket, outputDir, { pending }),
    sendFile(txSocket, sourcePath)
  ])

  assert.equal(sent.sha256, expected)
  assert.equal(received.sha256, expected, 'the drop completed despite three rejected peers')
  const onDisk = crypto.createHash('sha256').update(await fs.promises.readFile(received.path)).digest('hex')
  assert.equal(onDisk, expected)
})

test('a proof captured off a real exchange cannot be replayed at a receiver', async (t) => {
  const testnet = await createTestnet(3)
  t.after(() => testnet.destroy())

  const code = generateCode()
  const topic = topicFromCode(code)
  const key = dropKey(code)

  // Phase 1: capture a genuine sender proof. Posing as the receiver is how
  // an attacker would harvest one in practice -- announce on the topic and
  // let the real sender dial you -- so that is how the test does it.
  /** @type {Buffer | null} */
  let captured = null
  const fakeReceiver = await scriptedPeer(testnet.bootstrap, topic, async ({ socket, read }) => {
    socket.write(Buffer.concat([Buffer.from([READY]), makeNonce()]))
    captured = Buffer.from(await read(SENDER_PROOF_SIZE))
    // Never answer: the honest sender discards us and keeps looking, which
    // is the behaviour handshake.test.js covers from the other side.
    socket.destroy()
    return { captured: true }
  })
  t.after(() => fakeReceiver.swarm.destroy())

  const senderSwarm = createSwarm({ bootstrap: testnet.bootstrap })
  t.after(() => senderSwarm.destroy())
  // Expected to time out -- we only ever wanted its proof. Short budget so
  // the test does not sit waiting for a drop that cannot complete.
  const abandoned = connectOnce(senderSwarm, topic, { key, timeout: 20000 }).catch((err) => err)

  await waitFor(() => captured !== null, 'a genuine sender proof to capture')
  assert.equal(captured.length, SENDER_PROOF_SIZE)
  await fakeReceiver.swarm.destroy()
  await abandoned

  // Phase 2: replay those exact bytes at a real receiver, on a fresh
  // connection. The captured proof answered a different challenge on a
  // different session, and is worthless on this one.
  const receiveSwarm = createSwarm({ bootstrap: testnet.bootstrap })
  t.after(() => receiveSwarm.destroy())

  /** @type {string[]} */
  const dropped = []
  let announce
  const announced = new Promise((resolve) => { announce = resolve })

  // Nothing should ever satisfy this receiver. Recorded rather than
  // asserted inside the handler, so a replay that *worked* is reported as a
  // test failure below instead of as an unhandled rejection after the test
  // has already passed.
  let completed = false
  acceptOnce(receiveSwarm, topic, {
    key,
    timeout: 60000,
    onAnnounced: () => announce(),
    onCandidateDropped: (info, reason) => dropped.push(reason)
  }).then(() => { completed = true }, () => {})
  await announced

  const replayer = await scriptedPeer(testnet.bootstrap, topic, answerWith(() => captured))
  t.after(() => replayer.swarm.destroy())
  await replayer.ran

  await waitFor(
    () => dropped.some((r) => /failed the code proof/.test(r)),
    'the replayed proof to be rejected'
  )
  assert.equal(completed, false, 'a replayed proof must not complete the handshake')
})

test('the handshake refuses to run without a key at all', () => {
  // A caller that was not updated for item 4 must fail loudly. Defaulting
  // the key would restore the exact hole this file is about, silently.
  const topic = topicFromCode(generateCode())
  const swarm = createSwarm()
  // Deliberately mistyped: the point is the runtime guard, which is what
  // protects a caller that is not being typechecked (the scratch tools) or
  // one built before item 4.
  /** @type {any} */
  const noKey = { timeout: 1 }
  try {
    assert.throws(() => acceptOnce(swarm, topic, noKey), /requires a drop key/)
    assert.throws(() => connectOnce(swarm, topic, noKey), /requires a drop key/)
  } finally {
    swarm.destroy()
  }
})
