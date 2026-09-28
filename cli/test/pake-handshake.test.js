'use strict'

// The v2 handshake: a peer must confirm it knows the drop SECRET.
//
// This replaces code-proof.test.js, which covered v1's HMAC proof. The
// threat it pinned down is unchanged and still not hypothetical -- the repo
// contains the tool that demonstrates it, engine/scratch-lookup.js walks
// the DHT and reads announced topics -- but what is announced has changed,
// and so has what a rejected peer learns.
//
// UNDER v1 a topic was hash(code || salt), so announcing published a
// commitment to the whole code and an attacker could grind candidates
// offline at full speed. The HMAC proof could not fix that; it could only
// stop a stranger completing the exchange. UNDER v2 the topic commits to
// the nameplate alone, and the secret is a PAKE password: a wrong guess
// yields one bit -- "no" -- per live protocol run against a peer that is
// counting (PROTOCOL.md section 6, implemented in W11d).
//
// So the attacker model is different in a way worth stating, because it
// changes what a test can assert. v1 had four distinguishable failures
// (wrong code, reflected, replayed, relayed) because its proof had four
// separable defences. v2 has one: the transcript either matches or it does
// not. What is worth testing is therefore not "which defence fired" but
// that every distinct attack collapses into that single outcome, and that
// the transcript really does cover everything section 3.2 says it covers.
//
// The unit tests come first and drive both roles over a duplex pair; the
// network tests then show the whole thing holding up inside a real swarm --
// which the duplex pair cannot do, because it cannot reproduce Hyperswarm's
// several-candidates-per-drop and two-connections-per-peer behaviour, and
// that is exactly what section 3.2's trap #1 is about.

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
  topicFromNameplate,
  generateCode,
  splitCode,
  sendFile,
  receiveFile,
  Initiator,
  Responder,
  MessageReader,
  encodeCaps,
  parseCaps,
  effectiveCaps,
  deriveAll,
  confirmationMatches,
  Channel,
  KNOWN_CAPS,
  CONFIRM_SIZE,
  SID_SIZE,
  MAX_CAPS_BYTES,
  ERR_CONFIRMATION,
  LENGTH_PREFIX_SIZE,
  HELLO_FIXED,
  ELEMENT_SIZE
} = require('@ad-hal/engine')
const { slow } = require('../test-helpers/tiers')

// Runs both halves of the handshake against each other in memory, feeding
// each side's output straight into the other's reader. Returns what both
// sides derived, so a test can compare them.
/**
 * @param {{ receiver?: object, sender?: object }} [override]
 *   per-role option overrides, e.g. a different secret on one side
 */
function exchange (override = {}) {
  const code = generateCode()
  const { nameplate, secret } = splitCode(code)
  const initiator = new Initiator({ nameplate, secret, ...override.receiver })
  const responder = new Responder({ nameplate, secret, ...override.sender })

  const atSender = new MessageReader()
  const atReceiver = new MessageReader()

  atSender.push(initiator.hello())
  const reply = responder.readHello(atSender)
  assert.ok(reply, 'HELLO arrived whole, so REPLY must be produced')

  atReceiver.push(reply.reply)
  const confirmed = initiator.readReply(atReceiver)
  assert.ok(confirmed, 'REPLY arrived whole')

  atSender.push(confirmed.confirm)
  const settled = responder.readConfirm(atSender)
  assert.ok(settled, 'CONFIRM arrived whole')

  return { code, nameplate, secret, initiator, responder, receiver: confirmed, sender: settled }
}

test('both sides derive the same pair of channel keys', () => {
  const { receiver, sender } = exchange()

  // The property everything else rests on. If these diverge, both
  // confirmations would have failed -- so reaching here already proves
  // agreement; asserting it directly is what tells a future reader WHICH
  // value disagreed when something breaks. The ISK itself is no longer
  // handed out: the handshake wipes it once the keys are derived (Q-18),
  // and its value is pinned by handshake-vectors.test.js instead.

  // Directional, and mirrored: the receiver sends under k_r2s, which is
  // what the sender receives under.
  assert.deepEqual(receiver.sendKey, sender.receiveKey, 'k_r2s')
  assert.deepEqual(receiver.receiveKey, sender.sendKey, 'k_s2r')
  assert.notDeepEqual(receiver.sendKey, receiver.receiveKey, 'the two directions must differ')
  assert.equal(receiver.sendKey.length, 32)

  // And the keys are usable: a Channel built from each side's view round
  // trips. This is the assertion that would catch the two halves being
  // swapped, which no amount of comparing buffers to each other would.
  /** @type {Buffer[]} */
  const got = []
  const rx = new Channel({ ...receiver, onMessage: (type, body) => got.push(body) })
  const tx = new Channel({ ...sender, onMessage: () => {} })
  rx.push(tx.seal(0x01, Buffer.from('from the sender', 'utf8')))
  assert.equal(got[0].toString('utf8'), 'from the sender')
})

test('a wrong secret fails, and fails at the confirmation rather than earlier', () => {
  // The base case. Note what it is NOT: a wrong nameplate would put the
  // two peers on different topics and they would never meet, which
  // presents as the zero-candidate timeout. A wrong SECRET is the case
  // where they do meet -- so this is what both a mistyped code and an
  // actual guess look like, and the two are indistinguishable by design.
  const code = generateCode()
  const { nameplate, secret } = splitCode(code)
  const wrong = splitCode(generateCode()).secret

  const initiator = new Initiator({ nameplate, secret })
  const responder = new Responder({ nameplate, secret: wrong })

  const atSender = new MessageReader()
  atSender.push(initiator.hello())
  // The responder gets all the way to a REPLY: it cannot detect the
  // mismatch, because a PAKE gives it nothing to compare against. That is
  // the shape of the guarantee -- a wrong guess buys one round trip and
  // one bit of information.
  const reply = responder.readHello(atSender)
  assert.ok(reply, 'the responder cannot tell, and must answer anyway')

  const atReceiver = new MessageReader()
  atReceiver.push(reply.reply)
  assert.throws(() => initiator.readReply(atReceiver), /** @param {any} err */ (err) => {
    assert.equal(err.code, ERR_CONFIRMATION)
    assert.match(err.message, /failed the PAKE confirmation/)
    // The message must name both possibilities, because under v2 they are
    // genuinely indistinguishable and claiming otherwise would send
    // someone hunting an attacker who is really a typo.
    assert.match(err.message, /mistyped code|guessing/)
    return true
  })
})

test('one direction\'s confirmation cannot stand in for the other\'s', () => {
  // v1's reflection attack, in v2's terms. confirmS and confirmR are
  // computed over the SAME transcript under the SAME key, differing only in
  // their role label -- which is exactly the construction that WOULD be
  // reflectable if the labels were dropped. Draft section 9.4 suggests each
  // party MAC only its own message; section 3.2 deviates from that, so this
  // is the test that pays for the deviation.
  //
  // ASSERTED AT THE DERIVATION, NOT ON THE WIRE, and the reason is worth
  // recording because the obvious wire-level test does not test this. To
  // splice confirmR into a REPLY an attacker must first HAVE confirmR for
  // that same transcript -- and the only party who can produce one is a
  // party that already completed the transcript. Substituting a confirmR
  // taken from a different session is a replay, covered separately below
  // and rejected because the transcripts differ; it would pass even with
  // the labels removed, so it proves nothing about reflection. The labels
  // are what makes the two MACs differ over IDENTICAL input, so identical
  // input is what has to be fed in.
  const sid = Buffer.alloc(SID_SIZE, 0x5a)
  const K = Buffer.alloc(32, 0x3c)
  const transcript = Buffer.from('a transcript, byte for byte the same for both', 'utf8')

  const derived = deriveAll(sid, K, transcript)
  assert.notDeepEqual(derived.confirmS, derived.confirmR,
    'same key, same transcript, different role label -- these must differ')
  assert.equal(confirmationMatches(derived.confirmS, derived.confirmR), false)
  assert.equal(confirmationMatches(derived.confirmR, derived.confirmS), false)
  assert.ok(confirmationMatches(derived.confirmS, deriveAll(sid, K, transcript).confirmS),
    'and the derivation must be deterministic, or nothing above means anything')

  // The MAC key is separated from the channel keys too, so a confirmation
  // cannot be produced by anyone holding only traffic keys.
  assert.notDeepEqual(derived.macKey, derived.kR2S)
  assert.notDeepEqual(derived.macKey, derived.kS2R)
  assert.notDeepEqual(derived.kR2S, derived.kS2R)
})

test('the sender rejects a CONFIRM of the wrong length rather than throwing', () => {
  // timingSafeEqual raises on a length mismatch, so without an explicit
  // length check a peer could take the process down by answering with the
  // wrong number of bytes. Same hazard v1's proofMatches guarded, in the
  // one place it still applies -- CONFIRM is the only fixed-size message
  // left, so a short one is not caught by a length prefix.
  const code = generateCode()
  const { nameplate, secret } = splitCode(code)
  const initiator = new Initiator({ nameplate, secret })
  const responder = new Responder({ nameplate, secret })

  const atSender = new MessageReader()
  atSender.push(initiator.hello())
  responder.readHello(atSender)

  // Too short: readConfirm must wait rather than reject, because a
  // partial message is not a bad one.
  atSender.push(crypto.randomBytes(CONFIRM_SIZE - 1))
  assert.equal(responder.readConfirm(atSender), null, 'a partial CONFIRM must not be judged')

  // Completed with junk: now it is a full-length wrong answer.
  atSender.push(crypto.randomBytes(1))
  assert.throws(() => responder.readConfirm(atSender), /** @param {any} err */ (err) => {
    assert.equal(err.code, ERR_CONFIRMATION)
    return true
  })
})

test('ya, yb and sid are per connection, never per drop', () => {
  // SECTION 3.2 TRAP #1, and the one this engine is most exposed to: a
  // receiver gets several candidate peers per drop and TWO connections per
  // peer, so reuse would be the ordinary case rather than an exotic slip.
  // Draft section 9.9 makes it a MUST NOT.
  const { nameplate, secret } = splitCode(generateCode())

  const sids = new Set()
  const yas = new Set()
  for (let i = 0; i < 20; i++) {
    const one = new Initiator({ nameplate, secret })
    sids.add(one.sid.toString('hex'))
    // Ya is not exported, so it is read off the wire -- which is the
    // representation an attacker would see anyway.
    const body = one.hello().subarray(LENGTH_PREFIX_SIZE)
    yas.add(body.subarray(1 + SID_SIZE, HELLO_FIXED).toString('hex'))
  }
  assert.equal(sids.size, 20, 'every connection must sample a fresh sid')
  assert.equal(yas.size, 20, 'every connection must sample a fresh ya, hence a fresh Ya')

  // And there is deliberately no way to inject either: a caller that could
  // supply a scalar or a sid is a caller that can reuse one.
  const injected = /** @type {any} */ ({ nameplate, secret, sid: Buffer.alloc(SID_SIZE, 7), ya: Buffer.alloc(32, 7) })
  const ignored = new Initiator(injected)
  assert.notEqual(ignored.sid.toString('hex'), Buffer.alloc(SID_SIZE, 7).toString('hex'))
})

test('the same secret with a different nameplate derives different keys', () => {
  // CI = lv_cat("adhal-v2", nameplate), so the nameplate is bound into the
  // generator. Without that, two drops sharing a secret would be
  // interchangeable -- and a nameplate is public, so an attacker could
  // move a captured transcript between rendezvous points.
  const secret = splitCode(generateCode()).secret
  const a = exchange({ receiver: { nameplate: 'acid-acorn', secret }, sender: { nameplate: 'acid-acorn', secret } })
  const b = exchange({ receiver: { nameplate: 'zero-zesty', secret }, sender: { nameplate: 'zero-zesty', secret } })
  assert.notDeepEqual(a.receiver.sendKey, b.receiver.sendKey)
})

test('two runs of one drop derive different keys, because sid is fresh', () => {
  // No two connections for the same drop may share channel keys, or a
  // frame captured from one could be replayed into another -- and the
  // per-direction nonces both start at zero.
  const { nameplate, secret } = splitCode(generateCode())
  const first = exchange({ receiver: { nameplate, secret }, sender: { nameplate, secret } })
  const second = exchange({ receiver: { nameplate, secret }, sender: { nameplate, secret } })
  assert.notDeepEqual(first.receiver.sendKey, second.receiver.sendKey)
  assert.notDeepEqual(first.receiver.receiveKey, second.receiver.receiveKey)
})

// --- capabilities ---------------------------------------------------------

test('caps encode canonically: deduplicated, sorted bytewise, comma-joined', () => {
  // SECTION 3.2 TRAP #2. Two implementations that order the same set
  // differently derive different keys and fail EVERY handshake -- and the
  // failure is indistinguishable from an attack, which is the worst way
  // for an interoperability bug to present. So the encoding is fixed here
  // and the order a caller happens to list them in must not matter.
  assert.equal(encodeCaps(['stream', 'resume']).toString('utf8'), 'resume,stream')
  assert.equal(encodeCaps(['resume', 'stream']).toString('utf8'), 'resume,stream')
  assert.equal(encodeCaps(['stream', 'resume', 'stream']).toString('utf8'), 'resume,stream')
  assert.equal(encodeCaps([]).length, 0, 'the empty set is zero-length, not an empty string token')

  // Bytewise ascending, which for this charset means digits before
  // letters and '-' (0x2d) before both.
  assert.equal(encodeCaps(['b', 'a1', '0z']).toString('utf8'), '0z,a1,b')

  for (const bad of ['', 'Resume', 'a_b', 'a,b', '-lead', 'trail-', 'a'.repeat(17), 'ü']) {
    assert.throws(() => encodeCaps([bad]), TypeError, `${JSON.stringify(bad)} must be refused`)
  }
  assert.throws(() => encodeCaps(['a'.repeat(16), 'b'.repeat(16), 'c'.repeat(16),
    'd'.repeat(16), 'e'.repeat(16), 'f'.repeat(16), 'g'.repeat(16), 'h'.repeat(16)]),
  /over the 128-byte cap/)
})

test('a non-canonical caps field from a peer is refused, not normalised', () => {
  // Refusing rather than re-sorting is the point of having a canonical
  // form: if unsorted bytes were accepted and normalised, the transcript
  // would contain bytes no encoder produces, and a second implementation
  // could not reproduce it.
  assert.deepEqual(parseCaps(Buffer.from('resume,stream', 'utf8')), ['resume', 'stream'])
  assert.deepEqual(parseCaps(Buffer.alloc(0)), [])

  for (const bad of ['stream,resume', 'resume,resume', 'resume,', ',resume', 'resume,,stream', 'Resume']) {
    assert.throws(
      () => parseCaps(Buffer.from(bad, 'utf8')),
      /** @param {any} err */ (err) => {
        assert.equal(err.code, 'ERR_PROTOCOL')
        assert.match(err.message, /non-canonical|malformed/)
        return true
      },
      `${JSON.stringify(bad)} must be refused`
    )
  }
  assert.throws(() => parseCaps(Buffer.alloc(MAX_CAPS_BYTES + 1, 0x61)), /over the 128-byte cap/)
})

test('an unknown capability stays bound in the transcript and is merely ignored', () => {
  // SECTION 3.2 TRAP #3, AND THE RULE THAT MAKES IT HOLD: each side hashes
  // the peer's caps bytes VERBATIM as received, never a re-serialisation of
  // its own parsed view. That is what lets v2.1 add a capability without
  // breaking a v2 peer -- and what stops a party negotiating down from a
  // received value while MACing the original, which would reintroduce the
  // downgrade the transcript exists to prevent.
  const { nameplate, secret } = splitCode(generateCode())
  const future = ['resume', 'stream', 'teleport']

  const done = exchange({
    receiver: { nameplate, secret },
    sender: { nameplate, secret, caps: future }
  })

  // The handshake completes: an unknown token is not an error.
  assert.deepEqual(done.receiver.sendKey, done.sender.receiveKey)

  // But it is not acted on. The effective set is the intersection,
  // restricted to what this build knows.
  assert.deepEqual(done.receiver.caps.sort(), ['resume', 'stream'])
  assert.equal(done.receiver.caps.includes('teleport'), false)

  // And it IS bound: the same exchange without the unknown token derives a
  // different ISK, which is only possible if those bytes reached the
  // transcript. This is the assertion that fails if a future refactor
  // "helpfully" filters unknown tokens before hashing.
  const without = exchange({
    receiver: { nameplate, secret },
    sender: { nameplate, secret, caps: ['resume', 'stream'] }
  })
  assert.notDeepEqual(done.sender.sendKey, without.sender.sendKey)
})

test('a stripped capability is detected, because caps are inside the transcript', () => {
  // Detection, not prevention, and section 3.2 is explicit that this is
  // the only outcome available to a one-round-trip PAKE: the handshake
  // aborts rather than silently falling back. An attacker who strips a
  // capability makes the two sides derive different keys, so both
  // confirmations fail.
  const { nameplate, secret } = splitCode(generateCode())

  const initiator = new Initiator({ nameplate, secret, caps: ['resume', 'stream'] })
  const responder = new Responder({ nameplate, secret, caps: ['resume', 'stream'] })

  const atSender = new MessageReader()
  const hello = initiator.hello()

  // Rewrite HELLO in flight so the sender sees a receiver that supports
  // only `resume` -- a canonical encoding, so nothing structural catches
  // it. Only the transcript can.
  const downgraded = Buffer.concat([
    Buffer.alloc(LENGTH_PREFIX_SIZE),
    hello.subarray(LENGTH_PREFIX_SIZE, LENGTH_PREFIX_SIZE + HELLO_FIXED),
    Buffer.from('resume', 'utf8')
  ])
  downgraded.writeUInt16BE(downgraded.length - LENGTH_PREFIX_SIZE, 0)

  atSender.push(downgraded)
  const reply = /** @type {any} */ (responder.readHello(atSender))

  // The sender answered, believing the downgraded set. The receiver MACed
  // what it actually sent, so the confirmation does not match.
  const atReceiver = new MessageReader()
  atReceiver.push(reply.reply)
  assert.throws(() => initiator.readReply(atReceiver), /** @param {any} err */ (err) => {
    assert.equal(err.code, ERR_CONFIRMATION)
    return true
  })
})

test('the effective capability set is a pure function of the two transcript values', () => {
  assert.deepEqual(effectiveCaps(['resume', 'stream'], ['resume']), ['resume'])
  assert.deepEqual(effectiveCaps(['resume'], ['resume', 'stream']), ['resume'])
  assert.deepEqual(effectiveCaps([], ['resume', 'stream']), [])
  assert.deepEqual(effectiveCaps(KNOWN_CAPS, KNOWN_CAPS).sort(), ['resume', 'stream'])
  // A token neither side knows cannot become effective even if both
  // declare it, which is what keeps "declared" and "implemented" separate.
  assert.deepEqual(effectiveCaps(['teleport'], ['teleport']), [])
})

// --- malformed and hostile messages --------------------------------------

test('a wire-version skew is named rather than left to present as corruption', () => {
  // Section 9 asks a v2 implementation meeting a v1 peer to name the skew.
  // A v1 receiver opened with READY (0x01) then a 32-byte nonce, so its
  // first byte reaches the responder as a version of 1.
  const { nameplate, secret } = splitCode(generateCode())
  const responder = new Responder({ nameplate, secret })

  const body = Buffer.concat([Buffer.from([0x01]), crypto.randomBytes(HELLO_FIXED - 1)])
  const framed = Buffer.concat([Buffer.alloc(LENGTH_PREFIX_SIZE), body])
  framed.writeUInt16BE(body.length, 0)

  const reader = new MessageReader()
  reader.push(framed)
  assert.throws(() => responder.readHello(reader), /** @param {any} err */ (err) => {
    assert.match(err.message, /wire version 0x01/)
    assert.match(err.message, /version skew, not a corrupt stream/)
    assert.match(err.message, /redeploy both sides/)
    return true
  })
})

test('a declared body length outside the permitted range is refused before buffering', () => {
  // These are the least trustworthy bytes the engine ever reads: nothing
  // in the handshake is authenticated yet. So the bound is checked against
  // the DECLARED length, before waiting for any of the body -- otherwise a
  // peer can make us buffer toward a length it never intends to fill.
  const { nameplate, secret } = splitCode(generateCode())

  for (const declared of [0, 1, HELLO_FIXED - 1, 0xffff]) {
    const reader = new MessageReader()
    const header = Buffer.alloc(LENGTH_PREFIX_SIZE)
    header.writeUInt16BE(declared, 0)
    reader.push(header)
    assert.throws(
      () => new Responder({ nameplate, secret }).readHello(reader),
      /HELLO declared a \d+-byte body, outside the permitted/,
      `a declared length of ${declared} must be refused`
    )
  }

  // And a legal length whose body has not arrived is NOT an error: the
  // reader must wait, with the prefix left intact so the next chunk
  // retries cleanly.
  const waiting = new MessageReader()
  const ok = Buffer.alloc(LENGTH_PREFIX_SIZE)
  ok.writeUInt16BE(HELLO_FIXED, 0)
  waiting.push(ok)
  assert.equal(new Responder({ nameplate, secret }).readHello(waiting), null)
  assert.equal(waiting.buffered, LENGTH_PREFIX_SIZE, 'the prefix must not be consumed')
})

test('the neutral element is refused, which is the draft\'s mandatory abort', () => {
  // X25519 returns the all-zero neutral element for a dozen specific
  // u-coordinates whatever the scalar. A peer that sends one learns nothing
  // but would otherwise force both sides onto a key it also knows. The
  // twelve inputs are in cpace-vectors.test.js; this is the check that the
  // abort is reachable through the handshake and not only through cpace.js.
  const { nameplate, secret } = splitCode(generateCode())
  const initiator = new Initiator({ nameplate, secret })

  // Yb = 0 is the simplest of the low-order inputs.
  const body = Buffer.concat([
    Buffer.alloc(ELEMENT_SIZE), // Yb: the neutral element
    crypto.randomBytes(CONFIRM_SIZE),
    Buffer.from('resume,stream', 'utf8')
  ])
  const framed = Buffer.concat([Buffer.alloc(LENGTH_PREFIX_SIZE), body])
  framed.writeUInt16BE(body.length, 0)

  const reader = new MessageReader()
  reader.push(framed)
  assert.throws(() => initiator.readReply(reader), /** @param {any} err */ (err) => {
    assert.equal(err.code, 'ERR_CPACE_NEUTRAL')
    return true
  })
})

test('a handshake message split one byte at a time still completes', () => {
  // Nothing in v2's handshake is one byte, so every message can arrive
  // split -- and the length-prefixed ones can split between their prefix
  // and their body, which is the case a naive reader gets wrong.
  const { nameplate, secret } = splitCode(generateCode())
  const initiator = new Initiator({ nameplate, secret })
  const responder = new Responder({ nameplate, secret })

  const atSender = new MessageReader()
  const hello = initiator.hello()
  /** @type {any} */
  let reply = null
  for (const byte of hello) {
    atSender.push(Buffer.from([byte]))
    reply = reply || responder.readHello(atSender)
  }
  assert.ok(reply, 'HELLO must be assembled from single bytes')

  const atReceiver = new MessageReader()
  /** @type {any} */
  let confirmed = null
  for (const byte of reply.reply) {
    atReceiver.push(Buffer.from([byte]))
    confirmed = confirmed || initiator.readReply(atReceiver)
  }
  assert.ok(confirmed, 'REPLY must be assembled from single bytes')

  // And coalesced with trailing bytes: what follows the handshake belongs
  // to the caller and must be handed back, not swallowed.
  const trailing = Buffer.from('first-frame-ish', 'utf8')
  atSender.push(Buffer.concat([confirmed.confirm, trailing]))
  assert.ok(responder.readConfirm(atSender))
  assert.deepEqual(atSender.rest(), trailing)
})

test('the secret must be canonical, and the nameplate must not be passed as one', () => {
  // SECTION 3.2 TRAP #4. The QR payload's uppercase and the whole code are
  // the two mistakes that actually happen, and both would derive a
  // different generator and fail every handshake for no visible reason --
  // which reads as a network problem.
  const { nameplate, secret } = splitCode(generateCode())
  assert.throws(() => new Initiator({ nameplate, secret: secret.toUpperCase() }), /canonical form/)
  assert.throws(() => new Responder({ nameplate, secret: 'acre acts afar' }), /canonical form/)
  for (const bad of ['', undefined, null, 42]) {
    assert.throws(() => new Initiator({ nameplate, secret: /** @type {any} */ (bad) }), TypeError)
    assert.throws(() => new Responder({ nameplate: /** @type {any} */ (bad), secret }), TypeError)
  }
})

test('the handshake refuses to run without a secret at all', () => {
  // A caller that was not updated for v2 must fail loudly, and at the
  // JOIN rather than per candidate. Defaulting would restore the exact
  // hole this file is about; failing per candidate would present as
  // "every peer failed the handshake", which looks like a NAT problem and
  // is the most expensive misdiagnosis available here.
  const topic = topicFromNameplate('acid-acorn')
  const swarm = createSwarm()
  /** @type {any} */
  const noSecret = { timeout: 1 }
  try {
    assert.throws(() => acceptOnce(swarm, topic, noSecret), TypeError)
    assert.throws(() => connectOnce(swarm, topic, noSecret), TypeError)
    // And a plausible half-update: the nameplate supplied, the secret not.
    assert.throws(() => acceptOnce(swarm, topic, /** @type {any} */ ({ nameplate: 'acid-acorn' })), /secret/)
  } finally {
    swarm.destroy()
  }
})

// --- network tests -------------------------------------------------------

// A peer that speaks the handshake by hand, so a test can send REPLYs the
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

      script({ socket, peerInfo, read, reader }).then(resolve, reject)
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

// Reads the receiver's HELLO, then answers with whatever `forge` produces.
// Returns once those bytes are on the wire.
//
// `onHello` exists so a test can collect the sid the receiver chose for
// this connection. That value is not exposed by acceptOnce -- deliberately,
// since nothing in the product needs it -- and reading it off the wire is
// how an attacker would see it anyway.
function answerWith (forge, onHello) {
  return async ({ socket, read }) => {
    const prefix = await read(LENGTH_PREFIX_SIZE)
    const hello = await read(prefix.readUInt16BE(0))
    assert.equal(hello[0], 0x02, 'the receiver should open with wire version 2')
    if (onHello) onHello(hello)
    socket.write(forge({ socket, hello }))
    return { answered: true }
  }
}

test('a peer with the nameplate but not the secret is rejected, and the receiver keeps waiting', slow, async (t) => {
  const testnet = await createTestnet(3)
  t.after(() => testnet.destroy())

  const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'adhal-pake-'))
  t.after(() => fs.rmSync(tmpDir, { recursive: true, force: true }))

  const sourcePath = path.join(tmpDir, 'source.bin')
  const outputDir = path.join(tmpDir, 'received')
  await fs.promises.mkdir(outputDir, { recursive: true })
  const payload = crypto.randomBytes(128 * 1024)
  await fs.promises.writeFile(sourcePath, payload)
  const expected = crypto.createHash('sha256').update(payload).digest('hex')

  // Everything the attackers get is what walking the DHT would give them:
  // the topic, and therefore the nameplate it commits to. Only the honest
  // sender is given the secret. That is a materially weaker starting
  // position than v1's, where the announced topic committed to the whole
  // code -- which is the point of the format change.
  const code = generateCode()
  const { nameplate, secret } = splitCode(code)
  const topic = topicFromNameplate(nameplate)

  const receiveSwarm = createSwarm({ bootstrap: testnet.bootstrap })
  t.after(() => receiveSwarm.destroy())

  /** @type {string[]} */
  const codes = []
  /** @type {Buffer[]} */
  const sidsSeen = []
  let announce
  const announced = new Promise((resolve) => { announce = resolve })

  const accepted = acceptOnce(receiveSwarm, topic, {
    nameplate,
    secret,
    timeout: 120000,
    onAnnounced: () => announce(),
    onCandidateDropped: (info, reason, code) => codes.push(code || 'none')
  })
  await announced

  // Each attacker connects, is rejected, and leaves before the next one
  // arrives. Leaving matters: a swarm that stays joined keeps getting
  // re-dialed, and three of them camped on one topic starve the honest
  // sender of the parallel-dial slots engine/src/swarm.js documents.
  //
  // Counted off the CODE, not the message. v1's equivalent test matched
  // /failed the code proof/, which coupled it to prose -- the same
  // coupling engine/src/errors.js exists to remove.
  const confirmationFailures = () => codes.filter((c) => c === ERR_CONFIRMATION).length

  async function expectRejected (what, forge) {
    const before = confirmationFailures()
    const peer = await scriptedPeer(
      testnet.bootstrap,
      topic,
      answerWith(forge, (hello) => sidsSeen.push(Buffer.from(hello.subarray(1, 1 + SID_SIZE))))
    )
    try {
      await peer.ran
      await waitFor(() => confirmationFailures() > before, `the ${what} peer to be rejected`)
    } finally {
      await peer.swarm.destroy()
    }
  }

  // 1. Wrong secret: the stranger from scratch-lookup.js, who scraped the
  //    topic and knows the nameplate it commits to. It runs a real,
  //    correctly formed handshake against a guessed secret -- which is the
  //    only attack v2 leaves, and it buys exactly one guess.
  await expectRejected('wrong-secret', ({ hello }) => {
    const responder = new Responder({ nameplate, secret: splitCode(generateCode()).secret })
    const reader = new MessageReader()
    const framed = Buffer.alloc(LENGTH_PREFIX_SIZE + hello.length)
    framed.writeUInt16BE(hello.length, 0)
    hello.copy(framed, LENGTH_PREFIX_SIZE)
    reader.push(framed)
    return /** @type {any} */ (responder.readHello(reader)).reply
  })

  // 2. Junk of a legal length, to confirm the MAC comparison rejects
  //    rather than throws: a peer must not be able to kill the process by
  //    answering with plausible garbage.
  await expectRejected('junk-reply', () => {
    const body = Buffer.concat([
      crypto.randomBytes(ELEMENT_SIZE),
      crypto.randomBytes(CONFIRM_SIZE),
      Buffer.from('resume,stream', 'utf8')
    ])
    const framed = Buffer.alloc(LENGTH_PREFIX_SIZE + body.length)
    framed.writeUInt16BE(body.length, 0)
    body.copy(framed, LENGTH_PREFIX_SIZE)
    return framed
  })

  assert.ok(confirmationFailures() >= 2, `expected two rejected peers, got ${JSON.stringify(codes)}`)

  // Every sid the receiver used across those candidates must differ --
  // section 3.2 trap #1, checked against a REAL swarm because the duplex
  // pair cannot produce several candidates per drop, and per-drop caching
  // is precisely the optimisation the draft forbids.
  //
  // Read off the HELLOs the attackers received, so this measures what the
  // receiver actually put on the wire rather than what it says it did.
  assert.ok(sidsSeen.length >= 2, `expected a HELLO per candidate, saw ${sidsSeen.length}`)
  const sidHexes = new Set(sidsSeen.map((sid) => sid.toString('hex')))
  assert.equal(sidHexes.size, sidsSeen.length, 'no sid may be reused across connections')
  for (const sid of sidsSeen) {
    assert.equal(sid.length, SID_SIZE)
    assert.notEqual(sid.toString('hex'), Buffer.alloc(SID_SIZE).toString('hex'), 'a sid must be sampled, not zero')
  }

  // The point of discarding rather than failing: rejected attackers must
  // not cost the receiver its drop. A genuine sender still completes.
  const sendSwarm = createSwarm({ bootstrap: testnet.bootstrap })
  t.after(() => sendSwarm.destroy())

  const [rx, tx] = await Promise.all([
    accepted,
    connectOnce(sendSwarm, topic, { nameplate, secret, timeout: 120000 })
  ])
  rx.socket.on('error', () => {})
  tx.socket.on('error', () => {})

  // The two sides agreed on the channel keys over a real transport, which
  // is the thing the duplex-pair tests above cannot show.
  assert.deepEqual(rx.sendKey, tx.receiveKey, 'k_r2s must agree across a real connection')
  assert.deepEqual(rx.receiveKey, tx.sendKey, 'k_s2r must agree across a real connection')
  assert.deepEqual(rx.caps.sort(), ['resume', 'stream'])

  // And the transfer runs sealed under exactly those keys. If either side
  // passed the wrong half, the first frame would fail to open.
  const [received, sent] = await Promise.all([
    receiveFile(rx.socket, outputDir, { sendKey: rx.sendKey, receiveKey: rx.receiveKey, pending: rx.pending }),
    sendFile(tx.socket, sourcePath, { sendKey: tx.sendKey, receiveKey: tx.receiveKey })
  ])

  assert.equal(sent.sha256, expected)
  assert.equal(received.sha256, expected, 'the drop completed despite the rejected peers')
  const onDisk = crypto.createHash('sha256').update(await fs.promises.readFile(received.path)).digest('hex')
  assert.equal(onDisk, expected)
})

test('a REPLY captured off a real exchange cannot be replayed at a receiver', slow, async (t) => {
  const testnet = await createTestnet(3)
  t.after(() => testnet.destroy())

  const code = generateCode()
  const { nameplate, secret } = splitCode(code)
  const topic = topicFromNameplate(nameplate)

  // Phase 1: capture a genuine sender REPLY. Posing as the receiver is how
  // an attacker would harvest one in practice -- announce on the topic and
  // let the real sender dial you -- so that is how the test does it.
  //
  // Note the attacker gets to choose the sid here, which is the weak point
  // section 3.2 names and accepts. What it does NOT get is a second
  // password guess: testing one still costs CDH(g_guess, Yb).
  /** @type {Buffer | null} */
  let captured = null
  /** @type {Buffer | null} */
  let capturedSid = null
  const fakeReceiver = await scriptedPeer(testnet.bootstrap, topic, async ({ socket, read }) => {
    const probe = new Initiator({ nameplate, secret })
    capturedSid = probe.sid
    socket.write(probe.hello())
    const prefix = await read(LENGTH_PREFIX_SIZE)
    const body = await read(prefix.readUInt16BE(0))
    captured = Buffer.concat([prefix, body])
    // Never answer: the honest sender discards us and keeps looking, which
    // is the behaviour handshake.test.js covers from the other side.
    socket.destroy()
    return { captured: true }
  })
  t.after(() => fakeReceiver.swarm.destroy())

  const senderSwarm = createSwarm({ bootstrap: testnet.bootstrap })
  t.after(() => senderSwarm.destroy())
  // Expected to time out -- we only ever wanted its REPLY. Short budget so
  // the test does not sit waiting for a drop that cannot complete.
  const abandoned = connectOnce(senderSwarm, topic, { nameplate, secret, timeout: 20000 }).catch((err) => err)

  await waitFor(() => captured !== null, 'a genuine REPLY to capture')
  await fakeReceiver.swarm.destroy()
  await abandoned

  // Phase 2: replay those exact bytes at a real receiver, on a fresh
  // connection. The captured REPLY answered a HELLO carrying a different
  // sid and a different Ya, so its confirmation covers a transcript this
  // receiver never produced.
  const receiveSwarm = createSwarm({ bootstrap: testnet.bootstrap })
  t.after(() => receiveSwarm.destroy())

  /** @type {string[]} */
  const codes = []
  let announce
  const announced = new Promise((resolve) => { announce = resolve })

  // Nothing should ever satisfy this receiver. Recorded rather than
  // asserted inside the handler, so a replay that *worked* is reported as a
  // test failure below instead of as an unhandled rejection after the test
  // has already passed.
  let completed = false
  acceptOnce(receiveSwarm, topic, {
    nameplate,
    secret,
    timeout: 60000,
    onAnnounced: () => announce(),
    onCandidateDropped: (info, reason, code) => codes.push(code || 'none')
  }).then(() => { completed = true }, () => {})
  await announced

  const replayer = await scriptedPeer(testnet.bootstrap, topic, answerWith(() => captured))
  t.after(() => replayer.swarm.destroy())
  await replayer.ran

  await waitFor(
    () => codes.includes(ERR_CONFIRMATION),
    'the replayed REPLY to be rejected'
  )
  assert.equal(completed, false, 'a replayed REPLY must not complete the handshake')
  assert.ok(capturedSid, 'the capture really happened through a full HELLO')
})

// --- secrets are wiped once used (Q-18) ------------------------------------

const isZero = (/** @type {Buffer} */ b) => b.every((byte) => byte === 0)

test('the handshake zeroes its scalar and password bytes, on success and on a wrong secret', () => {
  // Best effort, and white-box on purpose: the private fields are the
  // thing being wiped, and nothing public would show it.
  const done = exchange()
  assert.ok(isZero(/** @type {any} */ (done.initiator)._ya), 'the receiver\'s scalar')
  assert.ok(isZero(/** @type {any} */ (done.responder)._secret), 'the sender\'s password bytes')
  assert.equal(isZero(done.receiver.sendKey), false, 'the channel keys are the caller\'s, and intact')

  // A failed confirmation wipes as well: a guesser's run leaves nothing.
  const { nameplate, secret } = splitCode(generateCode())
  const initiator = new Initiator({ nameplate, secret })
  const responder = new Responder({ nameplate, secret: splitCode(generateCode()).secret })
  const atSender = new MessageReader()
  const atReceiver = new MessageReader()
  atSender.push(initiator.hello())
  atReceiver.push(/** @type {any} */ (responder.readHello(atSender)).reply)
  assert.throws(() => initiator.readReply(atReceiver), (err) => /** @type {any} */ (err).code === ERR_CONFIRMATION)
  assert.ok(isZero(/** @type {any} */ (initiator)._ya))
  assert.ok(isZero(/** @type {any} */ (responder)._secret))
})
