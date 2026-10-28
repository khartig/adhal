'use strict'

// The attempt cap (PROTOCOL.md section 6).
//
// Two halves, and the second matters more than the first. The cap has to
// fire on guessing -- and it has to NOT fire on anything else, because a
// cap that goes off on network noise converts an intermittent transport
// problem into a permanent one and blames it on an attacker who is not
// there. Stale DHT announces routinely produce dead candidates, and three
// of them were once enough to starve every connection slot in this repo,
// so "never count a dropped candidate" is the load-bearing negative.
//
// This is also the file that pins section 6's deliberate reversal of a v1
// rule: v1 held that an attacker must not be able to end a drop by
// connecting and failing. Under v2 it can, after 100 failed guesses. If
// that is ever changed back, this file should be what argues with the
// change -- unlimited guessing against ~38.8 bits is the alternative.

const test = require('node:test')
const assert = require('node:assert/strict')
const crypto = require('node:crypto')
const createTestnet = require('hyperdht/testnet')

const {
  AttemptCap,
  attemptCapError,
  sidReusedError,
  replyUnansweredError,
  ERR_SID_REUSED,
  ERR_REPLY_UNANSWERED,
  MAX_ATTEMPTS,
  MAX_DELAY_MS,
  BASE_DELAY_MS,
  MAX_REMEMBERED_SIDS,
  createSwarm,
  acceptOnce,
  connectOnce,
  topicFromNameplate,
  generateCode,
  splitCode,
  Responder,
  Initiator,
  MessageReader,
  ERR_CONFIRMATION,
  LENGTH_PREFIX_SIZE
} = require('@ad-hal/engine')
const { describeError } = require('../src/report')
const { slow } = require('../test-helpers/tiers')
const { joinAsPeer, within } = require('../test-helpers/test-peer')

test('the cap is section 6\'s number and burns only on the last attempt', () => {
  assert.equal(MAX_ATTEMPTS, 100, 'section 6 says 100')

  const cap = new AttemptCap()
  for (let i = 1; i < MAX_ATTEMPTS; i++) {
    assert.equal(cap.fail(), false, `attempt ${i} must not burn the drop`)
    assert.equal(cap.exhausted, false)
  }
  assert.equal(cap.fail(), true, 'the hundredth must burn it')
  assert.equal(cap.exhausted, true)
  assert.equal(cap.attempts, MAX_ATTEMPTS)
})

test('the backoff is exponential, starts at zero, and is capped against real budgets', () => {
  const cap = new AttemptCap()

  // Nothing has failed, so a legitimate peer is answered immediately.
  // This is the case that matters most: the defense must be invisible
  // until there is something to defend against.
  assert.equal(cap.delayMs(), 0)

  cap.fail()
  assert.equal(cap.delayMs(), BASE_DELAY_MS)
  cap.fail()
  assert.equal(cap.delayMs(), BASE_DELAY_MS * 2)
  cap.fail()
  assert.equal(cap.delayMs(), BASE_DELAY_MS * 4)

  // And it saturates rather than growing without bound. The ceiling is
  // chosen against two real budgets, so this asserts the relationship and
  // not just the number: it has to leave a delayed-but-legitimate
  // candidate time to finish inside the 15 s per-candidate handshake
  // budget, and not time out a sender arriving inside the receiver's 30 s
  // join budget.
  while (!cap.exhausted) cap.fail()
  assert.equal(cap.delayMs(), MAX_DELAY_MS)
  assert.ok(MAX_DELAY_MS < 15000, 'the backoff must not exceed the per-candidate handshake budget')
  assert.ok(MAX_DELAY_MS * 2 < 30000, 'nor consume the receiver\'s join budget')

  // The whole point, stated as a number: 100 guesses are not free.
  const totalMs = Array.from({ length: MAX_ATTEMPTS }, (_, i) =>
    Math.min(MAX_DELAY_MS, BASE_DELAY_MS * 2 ** i)
  ).reduce((a, b) => a + b, 0)
  assert.ok(totalMs > 5 * 60 * 1000, `100 attempts should cost minutes, got ${totalMs}ms`)
})

test('a repeated sid is detected, and the set that remembers them is bounded', () => {
  const cap = new AttemptCap()
  const sid = crypto.randomBytes(16)

  assert.equal(cap.seenSid(sid), false, 'the first sighting is not a repeat')
  assert.equal(cap.seenSid(sid), true)
  // A copy with the same bytes must count as the same sid: it is compared
  // by value, not by identity.
  assert.equal(cap.seenSid(Buffer.from(sid)), true)
  assert.equal(cap.seenSid(crypto.randomBytes(16)), false)

  // Detecting a repeat must not itself count an attempt -- swarm.js
  // decides that, so that the counter has exactly one place it advances.
  assert.equal(cap.attempts, 0)

  // BOUNDED, or this module is a memory DoS in the one file whose job is
  // resisting abuse: a peer opens connections cheaply and each one carries
  // a fresh sid, so an unbounded set grows with attacker effort.
  const bounded = new AttemptCap({ maxSids: 4 })
  const sids = Array.from({ length: 5 }, () => crypto.randomBytes(16))
  for (const s of sids) assert.equal(bounded.seenSid(s), false)

  // The honest cost of the bound, asserted rather than left implicit: the
  // oldest is evicted, so a repeat of an evicted sid goes undetected.
  assert.equal(bounded.seenSid(sids[0]), false, 'the oldest was evicted, so this reads as new')
  assert.equal(bounded.seenSid(sids[4]), true, 'the newest is still remembered')
  assert.ok(MAX_REMEMBERED_SIDS > MAX_ATTEMPTS * 10,
    'the real bound must be far above the attempts the cap even permits')
})

test('a reservation counts unless it is confirmed, and reservations cannot outrun the cap', () => {
  // The sender reserves an attempt before each REPLY, because REPLY lets
  // whoever reads it test one guess (PROTOCOL.md section 12.5, step 4).
  const cap = new AttemptCap({ max: 3, baseDelayMs: 10 })

  assert.equal(cap.charge(), true)
  assert.equal(cap.settle(true), false)
  assert.equal(cap.attempts, 0, 'a run that confirmed costs nothing')
  assert.equal(cap.pending, 0)

  assert.equal(cap.charge(), true)
  assert.equal(cap.settle(false), false)
  assert.equal(cap.attempts, 1, 'a run that read REPLY and did not confirm is counted')

  // In flight: two reservations fill the cap with the one failure, so a
  // third REPLY is refused rather than sent. Counting only when runs end
  // would let every run in flight read REPLY first.
  assert.equal(cap.charge(), true)
  assert.equal(cap.charge(), true)
  assert.equal(cap.charge(), false, 'no room: failures plus reservations already fill the cap')
  assert.equal(cap.pending, 2)
  // Reservations do not slow anyone: only settled failures feed the backoff,
  // so a real receiver's duplicate connection is not delayed by it.
  assert.equal(cap.delayMs(), 10)

  assert.equal(cap.settle(true), false, 'the real peer confirms and frees its place')
  assert.equal(cap.charge(), true, 'and the place can be reserved again')
  assert.equal(cap.settle(false), false)
  assert.equal(cap.settle(false), true, 'the failure that reaches the cap burns the drop')
  assert.equal(cap.exhausted, true)
  assert.equal(cap.pending, 0)
})

test('the error carries the code section 10 specifies, and the counts with it', () => {
  const err = /** @type {any} */ (attemptCapError(100))
  assert.equal(err.code, 'ERR_ATTEMPT_CAP')
  assert.equal(err.name, 'TransferError')
  assert.equal(err.attempts, 100)
  assert.equal(err.max, MAX_ATTEMPTS)
  // The message must say someone was guessing -- it is the one code in
  // section 10's table that means that, and the only one whose message
  // should say so.
  assert.match(err.message, /guessing/)
  assert.match(err.message, /must not be reused|spent/)

  const reused = sidReusedError(Buffer.alloc(16, 0xab))
  assert.equal(reused.code, ERR_SID_REUSED)
  // Named as a reuse, not as an attack: a 16-byte CSPRNG value does not
  // repeat by chance, but a buggy peer reusing one lands here too.
  assert.match(reused.message, /reused the session id/)
  assert.match(reused.message, /MUST NOT/)

  // A REPLY left unanswered keeps the socket error that ended it as its
  // cause, and invents none when the connection simply closed.
  const reset = new Error('connection reset by peer')
  const unanswered = /** @type {any} */ (replyUnansweredError(reset))
  assert.equal(unanswered.code, ERR_REPLY_UNANSWERED)
  assert.equal(unanswered.cause, reset)
  assert.match(unanswered.message, /connection reset by peer/)
  assert.ok(!('cause' in replyUnansweredError()), 'no cause when nothing failed')
})

test('the CLI reports the cap as a report, not as a generic error', () => {
  // Before this case existed, ERR_ATTEMPT_CAP would have fallen through to
  // `error: <message>` and received the least prose of any failure -- which
  // is backwards for the only outcome a human has to act on beyond
  // retrying.
  const described = describeError(attemptCapError(100))

  assert.match(described, /burned/)
  assert.match(described, /somebody was guessing/i)
  assert.match(described, /not a network problem/i)
  // The instruction that matters: retrying with the same code hands the
  // guesser its next hundred attempts.
  assert.match(described, /not retry with the same code/i)
  assert.match(described, /Generate a new one/i)
  assert.doesNotMatch(described, /^error: /, 'it must not fall through to the generic branch')

  // And it must not be reworded into the generic branch by accident: a
  // code with no case still gets the fallback, which is what makes the
  // switch safe to extend.
  assert.match(describeError({ code: 'ERR_SOMETHING_NEW', message: 'x' }), /^error: x/)
})

// --- what must NOT be counted --------------------------------------------

test('a dropped candidate is never counted, however many of them there are', slow, async (t) => {
  // THE LOAD-BEARING NEGATIVE. Stale DHT announces outlive the process that
  // made them, so a topic accumulates dead candidates as a matter of
  // course -- measured in this repo, three were once enough to starve every
  // connection slot. Counting them would let the DHT's own garbage burn a
  // legitimate drop, and the human would be told somebody was guessing.
  const testnet = await createTestnet(3)
  t.after(() => testnet.destroy())

  const { nameplate, secret } = splitCode(generateCode())
  const topic = topicFromNameplate(nameplate)

  const receiveSwarm = createSwarm({ bootstrap: testnet.bootstrap })
  t.after(() => receiveSwarm.destroy())

  // A cap of 2, so that if dropped candidates were counted at all, three
  // dead peers would burn this drop and the assertions below would fail
  // loudly rather than subtly.
  const cap = new AttemptCap({ max: 2 })
  /** @type {string[]} */
  const codes = []
  let announce
  const announced = new Promise((resolve) => { announce = resolve })

  const accepted = acceptOnce(receiveSwarm, topic, {
    nameplate,
    secret,
    attemptCap: cap,
    timeout: 60000,
    onAnnounced: () => announce(),
    onCandidateDropped: (info, reason, code) => codes.push(code || 'none')
  })
  await announced

  // Three peers that connect, take the HELLO, and vanish -- exactly what a
  // half-failed punch and a scratch-lookup.js --connect probe look like.
  for (let i = 0; i < 3; i++) {
    /** @type {(v?: any) => void} */
    let saw = () => {}
    const sawHello = new Promise((resolve) => { saw = resolve })
    const dead = joinAsPeer(testnet.bootstrap, topic, (socket) => {
      socket.once('data', () => { saw(); socket.destroy() })
    })
    t.after(() => dead.swarm.destroy())
    await dead.flushed
    await within(sawHello, 45000, `dead peer ${i + 1}'s HELLO`)
    await dead.swarm.destroy()
  }

  assert.equal(cap.attempts, 0, `dead candidates must not be counted, got ${cap.attempts}`)
  assert.equal(cap.exhausted, false)
  assert.equal(codes.includes(ERR_CONFIRMATION), false, 'none of them failed a confirmation')

  // And the drop is still live: a genuine sender completes.
  const sendSwarm = createSwarm({ bootstrap: testnet.bootstrap })
  t.after(() => sendSwarm.destroy())
  const [rx, tx] = await Promise.all([
    accepted,
    connectOnce(sendSwarm, topic, { nameplate, secret, timeout: 60000 })
  ])
  rx.socket.on('error', () => {})
  tx.socket.on('error', () => {})
  assert.deepEqual(rx.sendKey, tx.receiveKey, 'the drop survived three dead candidates')
  rx.socket.destroy()
  tx.socket.destroy()
})

test('failed confirmations are counted, and the drop is burned with ERR_ATTEMPT_CAP', slow, async (t) => {
  // The positive case, and the reversal of v1's rule: a peer that knows the
  // nameplate but not the secret CAN end this drop. Deliberately, per
  // section 6 -- the alternative is unlimited guessing against ~38.8 bits.
  const testnet = await createTestnet(3)
  t.after(() => testnet.destroy())

  const { nameplate, secret } = splitCode(generateCode())
  const topic = topicFromNameplate(nameplate)

  const receiveSwarm = createSwarm({ bootstrap: testnet.bootstrap })
  t.after(() => receiveSwarm.destroy())

  // Two attempts, and a backoff of zero: the schedule is unit-tested
  // above, and making a network test wait out a real backoff would only
  // buy flake.
  const cap = new AttemptCap({ max: 2, baseDelayMs: 0, maxDelayMs: 0 })
  /** @type {string[]} */
  const codes = []
  let announce
  const announced = new Promise((resolve) => { announce = resolve })

  const accepted = acceptOnce(receiveSwarm, topic, {
    nameplate,
    secret,
    attemptCap: cap,
    timeout: 60000,
    onAnnounced: () => announce(),
    onCandidateDropped: (info, reason, code) => codes.push(code || 'none')
  }).then(
    () => ({ ok: true, err: /** @type {any} */ (null) }),
    (/** @type {any} */ err) => ({ ok: false, err })
  )
  await announced

  // Guessers: each runs a real, correctly formed handshake against a
  // wrong secret. That is the only attack v2 leaves, and it buys exactly
  // one guess per run -- which is what makes counting the runs sufficient.
  for (let i = 0; i < 2; i++) {
    /** @type {(v?: any) => void} */
    let replied = () => {}
    const answered = new Promise((resolve) => { replied = resolve })
    // ONE guess per guesser, whatever its swarm does. joinAsPeer redials
    // after the receiver drops a connection, and a second REPLY from the
    // same guesser would be a second counted failure -- burning a cap of
    // 2 before guesser 2 had run, which is how this failed as first
    // written.
    let guessed = false
    const guesser = joinAsPeer(testnet.bootstrap, topic, (socket) => {
      if (guessed) { socket.destroy(); return }
      const reader = new MessageReader()
      const wrong = new Responder({ nameplate, secret: splitCode(generateCode()).secret })
      socket.on('data', (chunk) => {
        if (guessed) return
        reader.push(chunk)
        const answer = wrong.readHello(reader)
        if (!answer) return
        guessed = true
        socket.write(answer.reply)
        replied()
      })
    })
    t.after(() => guesser.swarm.destroy())
    await guesser.flushed
    await within(answered, 45000, `guesser ${i + 1}'s REPLY`)
    // Give the receiver a moment to judge the REPLY before tearing down,
    // so the count is observed rather than raced.
    await new Promise((resolve) => setTimeout(resolve, 250))
    await guesser.swarm.destroy()
  }

  const outcome = await accepted
  assert.equal(outcome.ok, false, 'the drop must be burned, not completed')
  assert.equal(outcome.err.code, 'ERR_ATTEMPT_CAP')
  assert.equal(outcome.err.attempts, 2)
  assert.equal(cap.exhausted, true)
  assert.equal(codes.filter((c) => c === ERR_CONFIRMATION).length, 2)
})

test('the backoff actually delays the receiver\'s HELLO, measured', slow, async (t) => {
  // THE SCHEDULE IS UNIT-TESTED ABOVE; THIS TESTS THE WIRING, which is a
  // different claim and was the one security behavior here that would
  // otherwise rest on reading the code. `delayMs()` returning 1500 proves
  // nothing if swarm.js never consults it.
  //
  // Measured from the PEER's own 'connection' event rather than from the
  // join, so DHT discovery and hole punching fall outside the interval --
  // they take seconds and would swamp the signal. A naive
  // measure-from-join version of this test passes whether or not the
  // backoff exists, which is worse than no test.
  const testnet = await createTestnet(3)
  t.after(() => testnet.destroy())

  const DELAY = 1500

  /** @param {number} failures */
  async function timeToHello (failures) {
    const { nameplate, secret } = splitCode(generateCode())
    const topic = topicFromNameplate(nameplate)
    const rxSwarm = createSwarm({ bootstrap: testnet.bootstrap })
    t.after(() => rxSwarm.destroy())

    const cap = new AttemptCap({ baseDelayMs: DELAY, maxDelayMs: DELAY })
    for (let i = 0; i < failures; i++) cap.fail()
    assert.equal(cap.delayMs(), failures === 0 ? 0 : DELAY)

    let announce
    const announced = new Promise((resolve) => { announce = resolve })
    acceptOnce(rxSwarm, topic, {
      nameplate,
      secret,
      attemptCap: cap,
      timeout: 30000,
      onAnnounced: () => announce()
    }).catch(() => {})
    await announced

    // Measured per connection, so a dead one (see test-helpers/test-peer.js)
    // simply never resolves and the next, live, one does.
    return within(new Promise((resolve) => {
      const peer = joinAsPeer(testnet.bootstrap, topic, (socket) => {
        const connectedAt = Date.now()
        socket.once('data', () => resolve(Date.now() - connectedAt))
      })
      t.after(() => peer.swarm.destroy())
    }), 45000, 'the HELLO being timed')
  }

  const clean = await timeToHello(0)
  const delayed = await timeToHello(1)
  t.diagnostic(`connection -> HELLO: ${clean}ms clean, ${delayed}ms after one failure`)

  // Nothing has failed, so a legitimate peer is answered at once. This is
  // the half that matters most: the defense must be invisible until there
  // is something to defend against.
  assert.ok(clean < 500, `an unpenalized peer waited ${clean}ms for HELLO`)

  // And after one failure it waits, by about the configured amount. The
  // band is generous on the upper side (timers overshoot under load) and
  // tight on the lower, because the lower bound is the assertion: a
  // backoff that is not applied shows up as a value near `clean`.
  assert.ok(delayed >= DELAY - 100, `expected roughly ${DELAY}ms of backoff, waited ${delayed}ms`)
  assert.ok(delayed - clean > DELAY / 2, `the delta was only ${delayed - clean}ms, so the backoff is not what caused it`)
})

test('a sender treats a reused sid as a failed attempt', slow, async (t) => {
  // Section 3.2's mitigation for a receiver-chosen sid, and the reason that
  // departure from the draft is acceptable: the receiver must compute the
  // generator before it can send Ya, so a jointly contributed sid would
  // cost a round trip the message shape cannot afford. The sender
  // remembers instead, which turns reuse from invisible into countable.
  const testnet = await createTestnet(3)
  t.after(() => testnet.destroy())

  const { nameplate, secret } = splitCode(generateCode())
  const topic = topicFromNameplate(nameplate)

  const sendSwarm = createSwarm({ bootstrap: testnet.bootstrap })
  t.after(() => sendSwarm.destroy())

  const cap = new AttemptCap({ max: 2, baseDelayMs: 0, maxDelayMs: 0 })
  /** @type {string[]} */
  const codes = []

  const connected = connectOnce(sendSwarm, topic, {
    nameplate,
    secret,
    attemptCap: cap,
    timeout: 60000,
    // Short, because the replayer never answers the REPLY: its first
    // connection has a legitimate-looking sid and therefore sits until
    // this deadline. The default 15 s would make this test the slowest in
    // the suite for no extra coverage -- what is being measured is the
    // reuse check on the connections that follow.
    handshakeTimeout: 2000,
    onCandidateDropped: (info, reason, code) => codes.push(code || 'none')
  }).then(
    () => ({ ok: true, err: /** @type {any} */ (null) }),
    (/** @type {any} */ err) => ({ ok: false, err })
  )

  // One HELLO, reused. Built from a real Initiator so everything except
  // the sid's freshness is correct -- the sender must reject it on the sid
  // alone, before any question of whether the secret matches.
  const probe = new Initiator({ nameplate, secret })
  const hello = probe.hello()

  let helloed = 0
  const replayer = joinAsPeer(testnet.bootstrap, topic, (socket) => {
    helloed++
    socket.write(hello)
  })
  t.after(() => replayer.swarm.destroy())
  await replayer.flushed

  const outcome = await connected
  assert.ok(helloed >= 1, 'the replayer must have sent at least one HELLO')
  assert.equal(outcome.ok, false)
  assert.equal(outcome.err.code, 'ERR_ATTEMPT_CAP',
    `expected the cap to fire, got ${outcome.err.code}: ${outcome.err.message}`)
  assert.ok(
    codes.filter((c) => c === ERR_SID_REUSED).length >= 1,
    `expected a reused-sid drop, got ${JSON.stringify(codes)}`
  )
  // The FIRST HELLO is legitimate as far as the sid check goes -- only
  // repeats count -- so the first candidate must have been dropped for
  // failing its confirmation or not at all, never for reuse.
  assert.equal(LENGTH_PREFIX_SIZE, 2, 'the HELLO replayed above is length-prefixed')
})
