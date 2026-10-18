'use strict'

// The security properties W15d pins (docs/history/WORK-RECORD.md), one test per
// property, each run against the code that ships rather than a model of it.
//
// Three of the six were already pinned when W15b landed, by the tests
// that closed them. They are not repeated here; this table is where to
// find them, so the list stays whole in one place:
//
//   Q-03  every advertised capability has a handler      here
//   Q-01  channel nonces never repeat, either direction  here
//   Q-12  two drops from one process announce under      announce-key.test.js
//         different public keys
//   Q-14  the attempt cap counts confirmation failures   here (fast, every
//         and every REPLY not answered by a valid        rule); attempts.test.js
//         CONFIRM, never silent or dropped candidates,   (the same over a DHT)
//         and applies its backoff
//   Q-15  opaque codes are never on by default           code.test.js, "opaque
//                                                        codes are off unless..."
//   Q-11  a manifest body of ESC[2J, and a field         hardening.test.js, "a
//         carrying U+202E, reach the terminal escaped    manifest that is not
//                                                        JSON..." and "a hostile
//                                                        manifest key or value..."
//
// Every test below was checked by breaking the property on purpose and
// watching it go red; the note on each says what was broken.

const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('node:path')
const os = require('node:os')
const fs = require('node:fs')
const crypto = require('node:crypto')
const { Readable } = require('node:stream')

const {
  sendFile,
  sendStream,
  receiveFile,
  acceptOnce,
  connectOnce,
  AttemptCap,
  Initiator,
  Responder,
  MessageReader,
  KNOWN_CAPS,
  HELLO_FIXED,
  REPLY_FIXED,
  LENGTH_PREFIX_SIZE,
  CONFIRM_SIZE,
  ERR_CONFIRMATION,
  ERR_SID_REUSED,
  ERR_REPLY_UNANSWERED,
  PREFIX_BOUNDARY,
  NONCE_SIZE,
  generateCode,
  splitCode
} = require('@ad-hal/engine')
const { duplexPair } = require('../test-helpers/duplex-pair')
const { channelKeys } = require('../test-helpers/sealed')
const { FakeSwarm } = require('../test-helpers/fake-swarm')

const MiB = 1024 * 1024
const sha = (/** @type {Buffer} */ bytes) => crypto.createHash('sha256').update(bytes).digest('hex')

async function fixture (t, label, body) {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), `adhal-${label}-`))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const sourcePath = path.join(dir, 'payload.bin')
  const outputDir = path.join(dir, 'out')
  await fs.promises.mkdir(outputDir)
  await fs.promises.writeFile(sourcePath, body)
  return { sourcePath, outputDir, partPath: path.join(outputDir, 'payload.bin.part') }
}

/** @param {any} promise */
async function settle (promise) {
  return promise.then((value) => ({ ok: true, value }), (error) => ({ ok: false, error }))
}

// --- Q-03: every advertised capability has a handler ----------------------

// One row per capability, and a row is two transfers: one where the
// handshake negotiated the capability and the behavior it names happens,
// and one where it did not and that behavior is refused. "Has a handler"
// means both halves -- a capability that changed nothing when negotiated
// would pass the second half alone, and one that was acted on without
// being negotiated would pass the first.
//
// A GAP IS A MISSING ROW. The test below fails if KNOWN_CAPS names a token
// this table does not, so adding a capability to the handshake without a
// behavior to go with it cannot land quietly. That is how Q-03 was found:
// both tokens were advertised in W11 before either was acted on.
const CAPABILITY_ROWS = {
  /** @param {any} t */
  async resume (t) {
    // Negotiated: a partial holding the first boundary is resumed from it.
    const body = crypto.randomBytes(2 * MiB)
    {
      const f = await fixture(t, 'q03-resume-on', body)
      await fs.promises.writeFile(f.partPath, body.subarray(0, PREFIX_BOUNDARY))
      const [tx, rx] = duplexPair()
      const keys = channelKeys()
      const [sent, received] = await Promise.all([
        sendFile(tx, f.sourcePath, { ...keys.sender, caps: ['resume'] }),
        receiveFile(rx, f.outputDir, { ...keys.receiver, caps: ['resume'] })
      ])
      assert.equal(received.resumedFrom, PREFIX_BOUNDARY, 'with resume negotiated, the partial is resumed')
      assert.equal(sent.resumedFrom, PREFIX_BOUNDARY)
      assert.equal(sha(await fs.promises.readFile(received.path)), sha(body))
    }
    // Not negotiated: the same partial is ignored, and the file is sent whole.
    {
      const f = await fixture(t, 'q03-resume-off', body)
      await fs.promises.writeFile(f.partPath, body.subarray(0, PREFIX_BOUNDARY))
      const [tx, rx] = duplexPair()
      const keys = channelKeys()
      const [sent, received] = await Promise.all([
        sendFile(tx, f.sourcePath, { ...keys.sender, caps: [] }),
        receiveFile(rx, f.outputDir, { ...keys.receiver, caps: [] })
      ])
      assert.equal(received.resumedFrom, 0, 'without resume, nothing is resumed')
      assert.equal(sent.resumedFrom, 0)
      assert.equal(sha(await fs.promises.readFile(received.path)), sha(body))
    }
  },

  /** @param {any} t */
  async stream (t) {
    const body = crypto.randomBytes(100 * 1024)
    // Negotiated: a transfer of unknown length arrives, verified.
    {
      const f = await fixture(t, 'q03-stream-on', Buffer.alloc(0))
      const [tx, rx] = duplexPair()
      const keys = channelKeys()
      const [, received] = await Promise.all([
        sendStream(tx, Readable.from([body]), { ...keys.sender, name: 'piped.bin', caps: ['stream'] }),
        receiveFile(rx, f.outputDir, { ...keys.receiver, caps: ['stream'] })
      ])
      assert.equal(received.sha256, sha(body), 'with stream negotiated, a stream is received')
    }
    // Not negotiated: refused on both sides, each on its own authority.
    {
      const [tx] = duplexPair()
      const keys = channelKeys()
      const sent = await settle(sendStream(tx, Readable.from([body]), { ...keys.sender, name: 'piped.bin', caps: [] }))
      assert.equal(sent.ok, false)
      assert.equal(sent.error.code, 'ERR_PROTOCOL', 'the sender will not offer a stream it did not negotiate')
    }
    {
      // A sender that offers one anyway -- negotiated on its side only --
      // is declined by a receiver that did not negotiate it.
      const f = await fixture(t, 'q03-stream-off', Buffer.alloc(0))
      const [tx, rx] = duplexPair()
      const keys = channelKeys()
      const [sent, received] = await Promise.all([
        settle(sendStream(tx, Readable.from([body]), { ...keys.sender, name: 'piped.bin', caps: ['stream'] })),
        settle(receiveFile(rx, f.outputDir, { ...keys.receiver, caps: [] }))
      ])
      assert.equal(received.ok, false)
      assert.equal(received.error.code, 'ERR_MANIFEST_INVALID')
      assert.equal(sent.ok, false)
      assert.equal(sent.error.code, 'ERR_DECLINED')
    }
  }
}

test('Q-03: the handshake advertises exactly the capabilities this table has a row for', () => {
  // Broken on purpose: adding 'foo' to KNOWN_CAPS fails the first assertion.
  assert.deepEqual([...KNOWN_CAPS].sort(), Object.keys(CAPABILITY_ROWS).sort())

  // And what goes on the wire by default is that set, in both directions.
  // The canonical encoding (sorted, comma-joined) is section 3.2's.
  const { secret, nameplate } = splitCode(generateCode())
  const initiator = new Initiator({ secret, nameplate })
  const hello = initiator.hello()
  const capsR = hello.subarray(LENGTH_PREFIX_SIZE + HELLO_FIXED).toString('utf8')
  assert.equal(capsR, [...KNOWN_CAPS].sort().join(','), 'the receiver advertises KNOWN_CAPS')

  const responder = new Responder({ secret, nameplate })
  const reader = new MessageReader()
  reader.push(hello)
  const { reply } = /** @type {{ reply: Buffer }} */ (responder.readHello(reader))
  const capsS = reply.subarray(LENGTH_PREFIX_SIZE + REPLY_FIXED).toString('utf8')
  assert.equal(capsS, [...KNOWN_CAPS].sort().join(','), 'the sender advertises KNOWN_CAPS')
})

for (const cap of Object.keys(CAPABILITY_ROWS)) {
  // Broken on purpose: for `stream`, dropping the caps check in consider()
  // (transfer.js) fails the receiver half; for `resume`, making beginFile
  // ignore caps fails the "not negotiated" half.
  test(`Q-03: "${cap}" changes behavior when negotiated, and is refused when not`, (t) => CAPABILITY_ROWS[cap](t))
}

// --- Q-01: channel nonces never repeat -----------------------------------

// Records every ChaCha20-Poly1305 seal and open the process performs, as
// (key, nonce) pairs, with the key copied at the moment of use -- a
// transfer wipes its keys when it ends, so a reference would read zeros.
function recordAead () {
  /** @type {Array<{ key: string, nonce: string }>} */
  const seals = []
  /** @type {Array<{ key: string, nonce: string }>} */
  const opens = []
  const realCipher = crypto.createCipheriv
  const realDecipher = crypto.createDecipheriv
  const note = (/** @type {any[]} */ list, /** @type {string} */ alg, /** @type {any} */ key, /** @type {any} */ iv) => {
    if (alg === 'chacha20-poly1305') list.push({ key: Buffer.from(key).toString('hex'), nonce: Buffer.from(iv).toString('hex') })
  }
  // @ts-ignore -- a test spy on the module object the engine calls through
  crypto.createCipheriv = function (alg, key, iv, opts) { note(seals, alg, key, iv); return realCipher.call(this, alg, key, iv, opts) }
  // @ts-ignore
  crypto.createDecipheriv = function (alg, key, iv, opts) { note(opens, alg, key, iv); return realDecipher.call(this, alg, key, iv, opts) }
  return {
    seals,
    opens,
    restore () {
      crypto.createCipheriv = realCipher
      crypto.createDecipheriv = realDecipher
    }
  }
}

// Passes the first `bytes` a side writes straight through, then holds the
// rest until release(). Writable calls _write one chunk at a time, so
// holding that chunk's callback holds everything behind it, in order.
/**
 * @param {import('node:stream').Duplex} side
 * @param {number} bytes
 */
function holdAfter (side, bytes) {
  const write = side._write.bind(side)
  let passed = 0
  /** @type {(() => void) | null} */
  let held = null
  let released = false
  side._write = (chunk, encoding, callback) => {
    if (released || passed < bytes) {
      passed += chunk.length
      return write(chunk, encoding, callback)
    }
    held = () => write(chunk, encoding, callback)
  }
  return {
    release () {
      released = true
      const next = held
      held = null
      if (next) next()
    }
  }
}

/** @param {number} n */
const nonceFor = (n) => {
  const nonce = Buffer.alloc(NONCE_SIZE)
  nonce.writeBigUInt64BE(BigInt(n), NONCE_SIZE - 8)
  return nonce.toString('hex')
}

test('Q-01: no (key, nonce) pair is ever sealed twice, in either direction, across a whole resumed transfer', async (t) => {
  // A resumed transfer, so that every message type either side seals is on
  // the wire at least once: MANIFEST, ACCEPT twice, PREFIX, CHUNKs,
  // CHECKPOINTs, and RESULT.
  //
  // Broken on purpose: removing `this._counter++` from Nonces#next
  // (channel.js) fails this test and nothing else here -- both sides then
  // agree on nonce 0 for every frame, so the transfer itself succeeds.
  // That is exactly why it needs a test of its own.
  const body = crypto.randomBytes(3 * MiB)
  const f = await fixture(t, 'q01', body)
  await fs.promises.writeFile(f.partPath, body.subarray(0, 2 * PREFIX_BOUNDARY))
  const keys = channelKeys()
  const s2r = keys.sender.sendKey.toString('hex')
  const r2s = keys.receiver.sendKey.toString('hex')

  const aead = recordAead()
  t.after(() => aead.restore())
  const [tx, rx] = duplexPair()
  // A CHECKPOINT waits on a timer and then an fsync, so left to race, a
  // disk whose fsync is slower than the rest of the transfer -- ext4 under
  // the full suite -- lets the transfer finish with none sealed. Hold the
  // second half of the resumed tail until the sender has heard one.
  const tail = holdAfter(tx, 512 * 1024)
  /** @type {number[]} */
  const checkpoints = []
  const [sent, received] = await Promise.all([
    sendFile(tx, f.sourcePath, {
      ...keys.sender,
      caps: ['resume'],
      chunkSize: 16 * 1024,
      onCheckpoint: ({ offset }) => {
        checkpoints.push(offset)
        tail.release()
      }
    }),
    receiveFile(rx, f.outputDir, { ...keys.receiver, caps: ['resume'], checkpointInterval: 2 })
  ])
  aead.restore()

  assert.equal(received.resumedFrom, 2 * PREFIX_BOUNDARY, 'the transfer took the resume path')
  assert.equal(sent.sha256, sha(body))
  assert.ok(checkpoints.length > 0, 'at least one CHECKPOINT was sealed, so the receiver sealed more than its answers')

  // Exactly two keys sealed anything, one per direction, and they differ.
  const keysUsed = new Set(aead.seals.map((s) => s.key))
  assert.deepEqual([...keysUsed].sort(), [r2s, s2r].sort())

  for (const [label, key] of [['sender (k_s2r)', s2r], ['receiver (k_r2s)', r2s]]) {
    const nonces = aead.seals.filter((s) => s.key === key).map((s) => s.nonce)
    assert.equal(new Set(nonces).size, nonces.length, `${label} sealed some nonce twice`)
    // Not only distinct: the counter from zero, in order, with nothing
    // skipped -- which is what lets the peer open them at all.
    assert.deepEqual(nonces, nonces.map((_, i) => nonceFor(i)), `${label} nonces are not 0, 1, 2, ...`)
    // And every frame sealed under this key was opened once, under this
    // key, in the same order: the other side's counter kept step.
    const opened = aead.opens.filter((o) => o.key === key).map((o) => o.nonce)
    assert.deepEqual(opened, nonces, `${label}: what was opened is not what was sealed`)
  }
})

test('Q-01: a second transfer cannot be run under keys a first one has used', async (t) => {
  // The other half of "never repeats": a fresh Channel starts its counter
  // at zero, so reusing keys across two transfers would reuse every nonce.
  // Keys are single-use instead (Q-18) -- a transfer wipes them, and a
  // Channel refuses wiped keys. Broken on purpose: removing the all-zeros
  // check in checkKey (channel.js) fails this test.
  const f = await fixture(t, 'q01-reuse', crypto.randomBytes(64 * 1024))
  const keys = channelKeys()
  {
    const [tx, rx] = duplexPair()
    await Promise.all([sendFile(tx, f.sourcePath, { ...keys.sender }), receiveFile(rx, f.outputDir, { ...keys.receiver })])
  }
  const [tx] = duplexPair()
  const again = await settle(sendFile(tx, f.sourcePath, { ...keys.sender }))
  assert.equal(again.ok, false)
  assert.match(again.error.message, /already used by a transfer/)
})

// --- Q-14: what the attempt cap counts, and what it does not -------------

// acceptOnce and connectOnce over an in-memory swarm: see
// test-helpers/fake-swarm.js. attempts.test.js runs the same rules over a
// testnet.

// What each kind of candidate does with the far end of its connection.
const peers = {
  /** A sender that knows `secret`: answers HELLO, then reads CONFIRM. */
  sender: (/** @type {string} */ secret, /** @type {string} */ nameplate) => (/** @type {any} */ far) => {
    const responder = new Responder({ secret, nameplate })
    const reader = new MessageReader()
    let replied = false
    far.on('data', (/** @type {Buffer} */ chunk) => {
      reader.push(chunk)
      if (!replied) {
        const answer = responder.readHello(reader)
        if (!answer) return
        replied = true
        far.write(answer.reply)
      }
    })
  },
  /** Takes HELLO, then the transport reports the connection reset. */
  dropped: () => (/** @type {any} */ far, /** @type {any} */ near) => {
    far.once('data', () => near.destroy(Object.assign(new Error('connection reset by peer'), { code: 'ECONNRESET' })))
  },
  /** Connects and never says anything, and never hangs up. */
  silent: () => () => {},
  /** A receiver: sends HELLO, and CONFIRM if it can compute one. */
  receiver: (/** @type {string} */ secret, /** @type {string} */ nameplate, /** @type {Buffer | null} */ hello = null) => (/** @type {any} */ far) => {
    const initiator = new Initiator({ secret, nameplate })
    const reader = new MessageReader()
    far.on('data', (/** @type {Buffer} */ chunk) => {
      reader.push(chunk)
      let confirmed = null
      try {
        confirmed = initiator.readReply(reader)
      } catch {
        // Its secret is wrong: it cannot confirm, so it sends what a
        // guesser would -- 32 bytes that are not the MAC.
        far.write(crypto.randomBytes(CONFIRM_SIZE))
        return
      }
      if (confirmed) far.write(confirmed.confirm)
    })
    far.write(hello || initiator.hello())
  }
}

/** Collects onCandidateDropped reports and lets a test wait for the next. */
function dropLog () {
  /** @type {Array<{ reason: string, code: string | undefined }>} */
  const drops = []
  /** @type {Array<() => void>} */
  const waiters = []
  return {
    drops,
    onCandidateDropped: (/** @type {any} */ _info, /** @type {string} */ reason, /** @type {string | undefined} */ code) => {
      drops.push({ reason, code })
      const w = waiters.shift()
      if (w) w()
    },
    next: () => new Promise((resolve) => { waiters.push(() => resolve(undefined)) })
  }
}

test('Q-14: the receiver counts failed confirmations, never silent or dropped candidates, and delays after a failure', async () => {
  const { secret, nameplate } = splitCode(generateCode())
  const wrong = splitCode(generateCode()).secret
  const swarm = new FakeSwarm()
  const cap = new AttemptCap({ max: 3, baseDelayMs: 300 })
  const log = dropLog()
  const paired = acceptOnce(/** @type {any} */ (swarm), Buffer.alloc(32), {
    secret, nameplate, attemptCap: cap, handshakeTimeout: 150, refreshInterval: 0, timeout: 30000, onCandidateDropped: log.onCandidateDropped
  })

  // Network noise, twice each. Broken on purpose: counting every onFailed
  // (dropping the ERR_CONFIRMATION check in swarm.js) fails the first
  // assertion below.
  for (const play of [peers.dropped(), peers.silent(), peers.dropped(), peers.silent()]) {
    const next = log.next()
    swarm.candidate(play)
    await next
  }
  assert.equal(cap.attempts, 0, 'a dropped or silent candidate is never counted')
  assert.deepEqual(log.drops.map((d) => d.code), ['ECONNRESET', undefined, 'ECONNRESET', undefined])
  assert.match(log.drops[1].reason, /did not complete the handshake within 150ms/, 'the silent one was dropped by the deadline')

  // With nothing counted there is no backoff: HELLO goes out at once.
  {
    const started = Date.now()
    const { far } = swarm.candidate(() => {})
    await new Promise((resolve) => far.once('data', resolve))
    assert.ok(Date.now() - started < 100, `HELLO took ${Date.now() - started}ms with nothing failed`)
    far.destroy()
  }

  // A peer with the nameplate and the wrong secret is counted.
  {
    const next = log.next()
    swarm.candidate(peers.sender(wrong, nameplate))
    await next
  }
  assert.equal(cap.attempts, 1)
  assert.equal(log.drops.at(-1)?.code, ERR_CONFIRMATION)

  // And from then on the next HELLO waits out the backoff. Broken on
  // purpose: writing HELLO without the delay in acceptOnce fails this.
  {
    const started = Date.now()
    const { far } = swarm.candidate(() => {})
    await new Promise((resolve) => far.once('data', resolve))
    const waited = Date.now() - started
    assert.ok(waited >= 280, `HELLO went out ${waited}ms after connecting; the backoff is ${cap.delayMs()}ms`)
    far.destroy()
  }

  // The drop is still live for the peer that knows the code.
  swarm.candidate(peers.sender(secret, nameplate))
  const rx = await paired
  rx.stopAnswering()
  assert.equal(cap.attempts, 1)
})

test('Q-14: the burn is the cap\'s last failed confirmation, and nothing else', async () => {
  const { secret, nameplate } = splitCode(generateCode())
  const wrong = splitCode(generateCode()).secret
  const swarm = new FakeSwarm()
  const cap = new AttemptCap({ max: 2, baseDelayMs: 1 })
  const log = dropLog()
  let over = false
  const paired = settle(acceptOnce(/** @type {any} */ (swarm), Buffer.alloc(32), {
    secret, nameplate, attemptCap: cap, handshakeTimeout: 150, refreshInterval: 0, timeout: 30000, onCandidateDropped: log.onCandidateDropped
  })).then((result) => { over = true; return result })

  // Noise on both sides of the first failure, so that counting noise would
  // burn the drop before the second failure arrives. Broken on purpose:
  // counting every onFailed ends the join at the second candidate.
  const noise = [peers.silent(), peers.dropped(), peers.silent(), peers.dropped()]
  const candidates = [noise[0], peers.sender(wrong, nameplate), noise[1], noise[2], noise[3]]
  for (const [i, play] of candidates.entries()) {
    const next = log.next()
    swarm.candidate(play)
    // Or the join ended: a cap that burned early must fail here, not leave
    // this loop waiting for a candidate nobody reports.
    await Promise.race([next, paired])
    await new Promise((resolve) => setImmediate(resolve))
    assert.equal(over, false, `the drop ended after candidate ${i + 1} of ${candidates.length}, before the second failed confirmation`)
  }
  swarm.candidate(peers.sender(wrong, nameplate))
  const result = await paired
  assert.equal(result.ok, false)
  assert.equal(result.error.code, 'ERR_ATTEMPT_CAP')
  assert.equal(result.error.attempts, 2)
  assert.equal(log.drops.length, 6, 'every candidate was reported, the burning one included')
})

test('Q-14: the sender counts every run it sent REPLY that did not confirm, and never a candidate it did not answer', async () => {
  const { secret, nameplate } = splitCode(generateCode())
  const wrong = splitCode(generateCode()).secret
  const swarm = new FakeSwarm()
  const cap = new AttemptCap({ max: 10, baseDelayMs: 1 })
  const log = dropLog()
  const paired = connectOnce(/** @type {any} */ (swarm), Buffer.alloc(32), {
    secret, nameplate, attemptCap: cap, handshakeTimeout: 150, refreshInterval: 0, timeout: 30000, onCandidateDropped: log.onCandidateDropped
  })
  const reset = () => Object.assign(new Error('connection reset by peer'), { code: 'ECONNRESET' })

  // Candidates that were never sent REPLY have tested nothing, and are the
  // DHT's stale announces and dead punches that section 6 must not count:
  // one resets before HELLO, one resets halfway through it, one is silent.
  const deadBeforeHello = () => (/** @type {any} */ _far, /** @type {any} */ near) => { near.destroy(reset()) }
  const deadMidHello = () => (/** @type {any} */ far, /** @type {any} */ near) => {
    far.write(new Initiator({ secret, nameplate }).hello().subarray(0, 20))
    setImmediate(() => near.destroy(reset()))
  }
  for (const play of [deadBeforeHello(), deadMidHello(), peers.silent()]) {
    const next = log.next()
    swarm.candidate(play)
    await next
  }
  assert.equal(cap.attempts, 0, 'a candidate that was never sent REPLY is never counted')

  // A guesser that reads REPLY, checks its one guess against confirmS
  // offline, and hangs up instead of sending a wrong CONFIRM. Before
  // section 12.5's fix this was "never counted", and a guesser could repeat
  // it with no limit. Broken on purpose: settling the reservation as
  // confirmed in connectOnce's onFailed fails this.
  const guessAndHangUp = () => (/** @type {any} */ far, /** @type {any} */ near) => {
    far.write(new Initiator({ secret: wrong, nameplate }).hello())
    far.once('data', () => near.destroy(reset()))
  }
  {
    const next = log.next()
    swarm.candidate(guessAndHangUp())
    await next
    assert.equal(log.drops.at(-1)?.code, ERR_REPLY_UNANSWERED)
    assert.equal(cap.attempts, 1, 'reading REPLY and hanging up is counted')
  }
  // The same guesser going quiet after REPLY instead is counted when the
  // per-candidate deadline ends it.
  {
    const next = log.next()
    swarm.candidate((far) => far.write(new Initiator({ secret: wrong, nameplate }).hello()))
    await next
    assert.equal(log.drops.at(-1)?.code, ERR_REPLY_UNANSWERED)
    assert.match(log.drops.at(-1)?.reason ?? '', /did not complete the handshake within/)
    assert.equal(cap.attempts, 2)
  }

  // A receiver with the wrong secret cannot confirm: counted once, not once
  // for the bad CONFIRM and again for the reservation.
  {
    const next = log.next()
    swarm.candidate(peers.receiver(wrong, nameplate))
    await next
    assert.equal(log.drops.at(-1)?.code, ERR_CONFIRMATION)
    assert.equal(cap.attempts, 3)
  }
  // A HELLO replayed on a second connection: the first run read REPLY and
  // hung up, the second reuses its sid and is refused before REPLY.
  {
    const hello = new Initiator({ secret, nameplate }).hello()
    const first = log.next()
    swarm.candidate((far, near) => { far.write(hello); far.once('data', () => near.destroy()) })
    await first
    assert.equal(log.drops.at(-1)?.code, ERR_REPLY_UNANSWERED)
    const second = log.next()
    swarm.candidate((far) => far.write(hello))
    await second
    assert.equal(log.drops.at(-1)?.code, ERR_SID_REUSED)
  }
  assert.equal(cap.attempts, 5, 'two hang-ups after REPLY, a failed confirmation, a replay, a reused sid')
  assert.equal(cap.pending, 0, 'every reservation was settled')

  // The receiver that knows the code pairs, and its own run costs nothing.
  swarm.candidate(peers.receiver(secret, nameplate))
  const tx = await paired
  assert.equal(cap.attempts, 5)
  assert.equal(cap.pending, 0, 'a confirmed run releases its reservation')
  tx.stopAnswering()
})

test('Q-14: no more REPLYs reach guessers than the cap allows, however many arrive at once', async () => {
  // Counting runs when they end lets every run in flight read REPLY first:
  // 301 guessers connecting together all read it against a cap of 100.
  // The sender reserves an attempt before each REPLY instead. Broken on
  // purpose: making AttemptCap#charge always return true fails this.
  const { secret, nameplate } = splitCode(generateCode())
  const swarm = new FakeSwarm()
  const max = 5
  const cap = new AttemptCap({ max, baseDelayMs: 1 })
  const guessers = 3 * max
  let replies = 0
  let ended = 0
  /** @type {() => void} */
  let allEnded = () => {}
  const done = new Promise((resolve) => { allEnded = () => resolve(undefined) })
  const result = settle(connectOnce(/** @type {any} */ (swarm), Buffer.alloc(32), {
    // A short join timeout, so a sender that never burns fails in seconds.
    secret, nameplate, attemptCap: cap, handshakeTimeout: 150, refreshInterval: 0, timeout: 3000,
    onCandidateDropped: () => { if (++ended === guessers) allEnded() }
  }))

  for (let i = 0; i < guessers; i++) {
    swarm.candidate((far, near) => {
      far.write(new Initiator({ secret: splitCode(generateCode()).secret, nameplate }).hello())
      far.once('data', () => { replies++; near.destroy() })
    })
  }
  await Promise.race([done, result])
  const { ok, error } = await result
  assert.equal(ok, false)
  assert.equal(error.code, 'ERR_ATTEMPT_CAP')
  assert.equal(replies, max, `${replies} guessers read REPLY; the cap is ${max}`)
})
