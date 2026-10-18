'use strict'

// PROTOCOL.md section 4.4, the transfer state machine, as a table: every
// message type, sent in every state of both roles, against the real
// sendFile and receiveFile. A cell is either `ok` -- the state accepts the
// message and the transfer carries on -- or the error code the transfer
// must fail with.
//
// WHY A TABLE. accept-gate.test.js, resume.test.js, and stream.test.js each
// test the refusals someone thought of. This tests the refusals nobody
// had to think of: a state and a message type with no cell is a failure
// here (see "every cell is specified"), so a gap is a missing row rather
// than a missing thought. The section 4.4 table and this one are the same
// table; change one and the other must follow.
//
// Every body sent is VALID for its type, so a refusal is about the state
// and never about the body. Malformed bodies are the fuzz harness's job
// (fuzz.test.js), and handshake-phase states are in negative-vectors.test.js.

const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('node:path')
const os = require('node:os')
const fs = require('node:fs')
const crypto = require('node:crypto')

const {
  sendFile,
  receiveFile,
  acceptBody,
  declineBody,
  cancelBody,
  checkpointBody,
  resultBody,
  endBody,
  prefixBody,
  PREFIX_BOUNDARY,
  TYPE_RESERVED,
  TYPE_MANIFEST,
  TYPE_CHUNK,
  TYPE_CANCEL,
  TYPE_ACCEPT,
  TYPE_DECLINE,
  TYPE_CHECKPOINT,
  TYPE_RESULT,
  TYPE_END,
  TYPE_PREFIX
} = require('@ad-hal/engine')
const { duplexPair } = require('../test-helpers/duplex-pair')
const { channelKeys, sealedPeer } = require('../test-helpers/sealed')

const MiB = 1024 * 1024
const SMALL = Buffer.from('ad-hal state machine')
const LARGE_SIZE = 2 * MiB
const sha = (/** @type {Buffer} */ bytes) => crypto.createHash('sha256').update(bytes).digest('hex')
const json = (/** @type {any} */ value) => Buffer.from(JSON.stringify(value), 'utf8')
const tick = (ms = 0) => new Promise((resolve) => setTimeout(resolve, ms))

/** @param {any} promise */
function settle (promise) {
  const state = { done: false, ok: false, value: /** @type {any} */ (null), error: /** @type {any} */ (null) }
  state.promise = promise.then(
    (value) => Object.assign(state, { done: true, ok: true, value }),
    (error) => Object.assign(state, { done: true, ok: false, error })
  )
  return /** @type {typeof state & { promise: Promise<any> }} */ (state)
}

/** @param {() => boolean} ready @param {string} what */
async function until (ready, what) {
  for (let i = 0; i < 300; i++) {
    if (ready()) return
    await tick(5)
  }
  throw new Error(`timed out waiting for ${what}`)
}

// --- the messages ---------------------------------------------------------

// One valid instance of every message type, plus the two that are not
// types at all: 0x00, reserved, and 0x0a, the first unassigned number.
// DECLINE appears twice because ERR_DROP_TAKEN is the one DECLINE with a
// meaning of its own (section 4.0). `ctx` supplies what a body has to
// agree with to be valid: the file's digest, the offset proposed.
const MESSAGES = {
  'MANIFEST': { type: TYPE_MANIFEST, body: () => json({ v: 2, name: 'other.bin', size: 10, sha256: sha(Buffer.alloc(10)), blockSize: 65536 }) },
  'CHUNK': { type: TYPE_CHUNK, body: () => Buffer.from('0123456789') },
  'CANCEL': { type: TYPE_CANCEL, body: () => cancelBody('changed my mind') },
  'ACCEPT': { type: TYPE_ACCEPT, body: (/** @type {any} */ ctx) => acceptBody({ resumeFrom: ctx.proposed || 0 }) },
  'DECLINE': { type: TYPE_DECLINE, body: () => declineBody('no thanks', 'ERR_DECLINED') },
  'DECLINE{ERR_DROP_TAKEN}': { type: TYPE_DECLINE, body: () => declineBody('taken', 'ERR_DROP_TAKEN') },
  'CHECKPOINT': { type: TYPE_CHECKPOINT, body: (/** @type {any} */ ctx) => checkpointBody({ offset: ctx.durable || 0 }) },
  'RESULT': { type: TYPE_RESULT, body: (/** @type {any} */ ctx) => resultBody({ ok: true, sha256: ctx.sha256 }) },
  'END': { type: TYPE_END, body: (/** @type {any} */ ctx) => endBody({ sha256: ctx.streamed || sha(Buffer.from('0123456789')) }) },
  'PREFIX': { type: TYPE_PREFIX, body: (/** @type {any} */ ctx) => prefixBody({ sha256: ctx.prefixSha || sha(Buffer.alloc(0)) }) },
  '0x00 (reserved)': { type: TYPE_RESERVED, body: () => json({}) },
  '0x0a (unassigned)': { type: 0x0a, body: () => json({}) }
}

// --- the table (PROTOCOL.md section 4.4) ----------------------------------

const P = 'ERR_PROTOCOL'
const C = 'ERR_CANCELLED_PEER'

/** @param {Record<string, string>} cells @returns {Record<string, string>} */
const row = (cells) => ({
  'MANIFEST': P, 'CHUNK': P, 'CANCEL': C, 'ACCEPT': P, 'DECLINE': P, 'DECLINE{ERR_DROP_TAKEN}': P,
  'CHECKPOINT': P, 'RESULT': P, 'END': P, 'PREFIX': P, '0x00 (reserved)': P, '0x0a (unassigned)': P,
  ...cells
})

// What each state accepts; everything else in its row is the default of
// `row` above: CANCEL ends the transfer as the peer's cancel, and any
// other message is a protocol error.
const TABLE = {
  receiver: {
    'awaiting offer': row({ 'MANIFEST': 'ok', 'DECLINE{ERR_DROP_TAKEN}': 'ERR_DROP_TAKEN' }),
    'considering': row({}),
    'prefix check': row({ 'PREFIX': 'ok' }),
    'receiving': row({ 'CHUNK': 'ok' }),
    'receiving a stream': row({ 'CHUNK': 'ok', 'END': 'ok' }),
    // After RESULT the receiver has settled and stopped reading: nothing
    // that arrives is acted on, CANCEL included.
    'done': Object.fromEntries(Object.keys(MESSAGES).map((m) => [m, 'ignored']))
  },
  sender: {
    'offered': row({ 'ACCEPT': 'ok', 'DECLINE': 'ERR_DECLINED', 'DECLINE{ERR_DROP_TAKEN}': 'ERR_DROP_TAKEN' }),
    'prefix sent': row({ 'ACCEPT': 'ok', 'DECLINE': 'ERR_DECLINED' }),
    'sending': row({ 'CHECKPOINT': 'ok' }),
    'sending, resume not negotiated': row({}),
    'awaiting result': row({ 'CHECKPOINT': 'ok', 'RESULT': 'ok' }),
    'done': Object.fromEntries(Object.keys(MESSAGES).map((m) => [m, 'ignored']))
  }
}

// --- driving each role into each state ------------------------------------

async function tmpDir (/** @type {any} */ t) {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'adhal-state-'))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  return dir
}

const LARGE = crypto.randomBytes(LARGE_SIZE)

// Each returns { peer, outcome, ctx }: `peer` is the hand-rolled other
// side, already in position; `outcome` is the settled-state of the real
// function under test; `ctx` is what a valid body in this state agrees
// with. `hold` is released after the case, for states that wait on the
// test.
/** @type {Record<string, (t: any) => Promise<any>>} */
const RECEIVER_STATES = {
  async 'awaiting offer' (t) {
    return receiver(await tmpDir(t), {})
  },
  async 'considering' (t) {
    /** @type {() => void} */
    let release = () => {}
    let asked = false
    const r = receiver(await tmpDir(t), {
      onOffer: () => { asked = true; return new Promise((resolve) => { release = () => resolve(true) }) }
    })
    r.peer.send(TYPE_MANIFEST, json({ v: 2, name: 'held.bin', size: SMALL.length, sha256: sha(SMALL), blockSize: 65536 }))
    await until(() => asked, 'onOffer')
    t.after(() => release())
    return r
  },
  async 'prefix check' (t) {
    const dir = await tmpDir(t)
    await fs.promises.writeFile(path.join(dir, 'large.bin.part'), LARGE.subarray(0, PREFIX_BOUNDARY))
    const r = receiver(dir, { caps: ['resume'] })
    r.peer.send(TYPE_MANIFEST, json({ v: 2, name: 'large.bin', size: LARGE.length, sha256: sha(LARGE), blockSize: 65536 }))
    await until(() => r.peer.received.some((f) => f.type === TYPE_ACCEPT), 'the resume proposal')
    r.ctx.prefixSha = sha(LARGE.subarray(0, PREFIX_BOUNDARY))
    return r
  },
  async 'receiving' (t) {
    const r = receiver(await tmpDir(t), {})
    r.peer.send(TYPE_MANIFEST, json({ v: 2, name: 'large.bin', size: LARGE.length, sha256: sha(LARGE), blockSize: 65536 }))
    await until(() => r.peer.received.some((f) => f.type === TYPE_ACCEPT), 'ACCEPT')
    return r
  },
  async 'receiving a stream' (t) {
    const r = receiver(await tmpDir(t), { caps: ['stream'] })
    r.peer.send(TYPE_MANIFEST, json({ v: 2, name: 'piped.bin', size: null, sha256: null, blockSize: 65536 }))
    await until(() => r.peer.received.some((f) => f.type === TYPE_ACCEPT), 'ACCEPT')
    // What an END here must carry to be valid: the digest of what has
    // arrived, which is nothing yet.
    r.ctx.streamed = sha(Buffer.alloc(0))
    return r
  },
  async 'done' (t) {
    const r = receiver(await tmpDir(t), {})
    r.peer.send(TYPE_MANIFEST, json({ v: 2, name: 'small.bin', size: SMALL.length, sha256: sha(SMALL), blockSize: 65536 }))
    await until(() => r.peer.received.some((f) => f.type === TYPE_ACCEPT), 'ACCEPT')
    r.peer.send(TYPE_CHUNK, SMALL)
    await until(() => r.outcome.done, 'the receive to finish')
    assert.equal(r.outcome.ok, true, 'the receive finished cleanly before the case')
    return r
  }
}

/** @param {string} dir @param {any} options */
function receiver (dir, options) {
  const [far, near] = duplexPair()
  const keys = channelKeys()
  const peer = sealedPeer(far, keys.sender)
  const heard = { progress: 0, checkpoints: 0 }
  const outcome = settle(receiveFile(near, dir, { ...keys.receiver, onProgress: ({ bytes }) => { heard.progress = bytes }, ...options }))
  return { peer, outcome, heard, ctx: /** @type {any} */ ({ sha256: sha(SMALL) }), near, far, accept: /** @type {null | (() => void)} */ (null) }
}

/** @type {Record<string, (t: any) => Promise<any>>} */
const SENDER_STATES = {
  async 'offered' (t) {
    const s = await sender(t, SMALL, {})
    await until(() => s.peer.received.some((f) => f.type === TYPE_MANIFEST), 'MANIFEST')
    return s
  },
  async 'prefix sent' (t) {
    const s = await sender(t, LARGE, { caps: ['resume'] })
    await until(() => s.peer.received.some((f) => f.type === TYPE_MANIFEST), 'MANIFEST')
    s.peer.send(TYPE_ACCEPT, acceptBody({ resumeFrom: PREFIX_BOUNDARY }))
    await until(() => s.peer.received.some((f) => f.type === TYPE_PREFIX), 'PREFIX')
    s.ctx.proposed = PREFIX_BOUNDARY
    return s
  },
  // No wait between ACCEPT and the case's message: the file's read stream
  // opens asynchronously, so the message is judged in the send phase with
  // nothing yet sent. `durable` 0 is then the only valid checkpoint.
  async 'sending' (t) {
    const s = await sender(t, LARGE, { caps: ['resume'] })
    await until(() => s.peer.received.some((f) => f.type === TYPE_MANIFEST), 'MANIFEST')
    s.accept = () => s.peer.send(TYPE_ACCEPT, acceptBody({ resumeFrom: 0 }))
    return s
  },
  async 'sending, resume not negotiated' (t) {
    const s = await sender(t, LARGE, { caps: [] })
    await until(() => s.peer.received.some((f) => f.type === TYPE_MANIFEST), 'MANIFEST')
    s.accept = () => s.peer.send(TYPE_ACCEPT, acceptBody({ resumeFrom: 0 }))
    return s
  },
  async 'awaiting result' (t) {
    const s = await sender(t, SMALL, { caps: ['resume'] })
    await until(() => s.peer.received.some((f) => f.type === TYPE_MANIFEST), 'MANIFEST')
    s.peer.send(TYPE_ACCEPT, acceptBody({ resumeFrom: 0 }))
    await until(() => s.peer.received.filter((f) => f.type === TYPE_CHUNK).reduce((n, f) => n + f.body.length, 0) === SMALL.length, 'every chunk')
    s.ctx.durable = SMALL.length
    return s
  },
  async 'done' (t) {
    const s = await sender(t, SMALL, {})
    await until(() => s.peer.received.some((f) => f.type === TYPE_MANIFEST), 'MANIFEST')
    s.peer.send(TYPE_ACCEPT, acceptBody({ resumeFrom: 0 }))
    await until(() => s.peer.received.some((f) => f.type === TYPE_CHUNK), 'the chunk')
    s.peer.send(TYPE_RESULT, resultBody({ ok: true, sha256: sha(SMALL) }))
    await until(() => s.outcome.done, 'the send to finish')
    assert.equal(s.outcome.ok, true, 'the send finished cleanly before the case')
    return s
  }
}

/** @param {any} t @param {Buffer} body @param {any} options */
async function sender (t, body, options) {
  const dir = await tmpDir(t)
  const sourcePath = path.join(dir, body === SMALL ? 'small.bin' : 'large.bin')
  await fs.promises.writeFile(sourcePath, body)
  const [near, far] = duplexPair()
  const keys = channelKeys()
  const peer = sealedPeer(far, keys.receiver)
  const heard = { progress: 0, checkpoints: 0 }
  const outcome = settle(sendFile(near, sourcePath, { ...keys.sender, onCheckpoint: () => { heard.checkpoints++ }, ...options }))
  return { peer, outcome, heard, ctx: /** @type {any} */ ({ sha256: sha(body) }), near, far, accept: /** @type {null | (() => void)} */ (null) }
}

// --- the cases ------------------------------------------------------------

// What "ok" has to show. Not refusing is not enough: a state that silently
// dropped a message would pass that. Each accepted message has an effect
// the other side, or the caller, can see, and the case waits for it.
/** @type {Record<string, Record<string, (s: any, before: number) => boolean>>} */
const EVIDENCE = {
  receiver: {
    'MANIFEST': (s, before) => s.peer.received.length > before, // answered
    'PREFIX': (s, before) => s.peer.received.slice(before).some((/** @type {any} */ f) => f.type === TYPE_ACCEPT), // the final answer
    'CHUNK': (s) => s.heard.progress === 10, // written
    'END': (s) => s.outcome.done && s.outcome.ok // verified and published
  },
  sender: {
    'ACCEPT': (s, before) => s.peer.received.slice(before).some((/** @type {any} */ f) => f.type === TYPE_CHUNK), // the file follows
    'CHECKPOINT': (s) => s.heard.checkpoints === 1, // reported to the caller
    'RESULT': (s) => s.outcome.done && s.outcome.ok // the send resolves
  }
}

test('every cell is specified: each state of each role has an outcome for every message', () => {
  const messages = Object.keys(MESSAGES).sort()
  for (const [role, states] of Object.entries(TABLE)) {
    const drivers = role === 'receiver' ? RECEIVER_STATES : SENDER_STATES
    assert.deepEqual(Object.keys(states).sort(), Object.keys(drivers).sort(), `${role}: every state in the table can be reached, and every reachable state is in the table`)
    for (const [state, cells] of Object.entries(states)) {
      assert.deepEqual(Object.keys(cells).sort(), messages, `${role} / ${state} has no cell for some message`)
    }
  }
})

for (const [role, states] of Object.entries(TABLE)) {
  const drivers = role === 'receiver' ? RECEIVER_STATES : SENDER_STATES
  for (const [state, cells] of Object.entries(states)) {
    for (const [name, expected] of Object.entries(cells)) {
      test(`${role} / ${state} / ${name} -> ${expected}`, async (t) => {
        const s = await drivers[state](t)
        t.after(() => { s.near.destroy(); s.far.destroy() })
        const message = MESSAGES[name]
        const sentBefore = s.peer.received.length
        if (s.accept) s.accept()
        s.peer.send(message.type, message.body(s.ctx))

        if (expected === 'ok') {
          const shown = EVIDENCE[role][name]
          assert.ok(shown, `no evidence is defined for ${role} accepting ${name}`)
          await until(() => shown(s, sentBefore) || (s.outcome.done && !s.outcome.ok), `${name} to take effect in ${state}`)
          assert.ok(!s.outcome.done || s.outcome.ok, `${name} was refused in ${state}: ${s.outcome.error && s.outcome.error.message}`)
          return
        }
        if (expected === 'ignored') {
          await tick(30)
          assert.equal(s.outcome.ok, true, 'the finished transfer stays finished')
          assert.equal(s.peer.received.length, sentBefore, 'nothing was said in answer')
          return
        }
        await until(() => s.outcome.done, `${role} to refuse ${name}`)
        assert.equal(s.outcome.ok, false, `${name} was accepted in ${state}`)
        assert.equal(s.outcome.error.code, expected, `${name} in ${state}: ${s.outcome.error.message}`)
      })
    }
  }
}
