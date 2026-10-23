'use strict'

// The scenarios the harness runs. PROTOCOL.md section 11 names five -- the
// handshake, a normal transfer, a cancel, a resume, and a streaming
// transfer -- and each is run with the implementation under test (IUT) in
// both roles. After them come the negative vectors (frames-negative.json,
// handshake-negative.json) and the state machine's refusals (section 4.4),
// replayed against a live IUT rather than against this repository's engine
// in-process, which is what makes them usable by a second implementation.
//
// IDs: R- scenarios drive an IUT receiver (the harness sends), S- ones an
// IUT sender (the harness receives). Every scenario states the sections it
// checks. Every frame the IUT sends is also checked by SealedPeer.next
// (conformance/src/harness.js) whatever the scenario is about.
//
// NOT HERE, and why. A repeated sid (ERR_SID_REUSED) and the attempt cap
// need many connections to one drop, and the adapter contract is one
// connection; they are the join's behavior, not the stream's, and
// cli/test/negative-vectors.test.js and attempts.test.js cover this
// implementation's. Timeouts (ERR_STALLED) would make a run take minutes.
// Checkpoint cadence is a receiver-local tuning decision (section 8.3), so
// a CHECKPOINT is checked for validity whenever one arrives, never
// required.

const crypto = require('node:crypto')
const fs = require('node:fs')
const path = require('node:path')

const wire = require('./wire')
const {
  fail,
  readHello,
  reply,
  hello,
  readReply,
  readFor,
  SealedPeer,
  expectOutcome,
  flipLastBit
} = require('./harness')
const HANDSHAKE_NEGATIVE = require('../vectors/handshake-negative.json')

const { TYPE, PREFIX_BOUNDARY, MAX_CHUNK } = wire
const KIB = 1024
const MIB = 1024 * 1024
const BLOCK = 64 * KIB

// --- driving a receiver (the harness sends) -------------------------------

/**
 * Starts an IUT receiver and completes the handshake as an honest sender,
 * checking HELLO and CONFIRM.
 * @param {any} t
 * @param {{ caps?: string[], dir?: string, args?: string[] }} [o]
 */
async function asSender (t, { caps, dir, args = [] } = {}) {
  const out = dir || await t.dir()
  const s = await t.start('receiver', ['--dir', out, ...args])
  const h = await readHello(s.conn)
  const r = reply(h, { ...s.code, caps })
  await s.conn.write(r.bytes)
  const confirm = await readFor(s.conn, wire.CONFIRM_SIZE, 'CONFIRM')
  if (!crypto.timingSafeEqual(confirm, r.keys.confirmR)) fail('CONFIRM does not verify as confirmR', 'section 3.2')
  const peer = new SealedPeer(s.conn, { sendKey: r.keys.kS2R, receiveKey: r.keys.kR2S, caps: r.caps, iut: 'receiver' })
  return { s, peer, dir: out, hello: h }
}

/**
 * @param {{ name: string, data: Buffer, sha256: string }} file
 * @param {{ blockSize?: number, stream?: boolean }} [o]
 */
function manifestOf (file, { blockSize = BLOCK, stream = false } = {}) {
  return stream
    ? { v: 2, name: file.name, size: null, sha256: null, blockSize }
    : { v: 2, name: file.name, size: file.data.length, sha256: file.sha256, blockSize }
}

/**
 * Checks each CHECKPOINT an IUT receiver sends (section 7.4): only on a
 * resumable transfer, a non-negative integer, never backwards, and never
 * past what the harness has sent.
 * @param {InstanceType<typeof SealedPeer>} peer
 * @param {{ sized: boolean }} o
 */
function checkpointWatcher (peer, { sized }) {
  let last = 0
  const w = {
    sent: 0,
    /** @param {any} f */
    check (f) {
      if (!sized || !peer.caps.includes('resume')) fail('a CHECKPOINT on a transfer that is not resumable', 'section 7.4')
      const offset = f.json.offset
      if (!Number.isSafeInteger(offset) || offset < 0) fail(`CHECKPOINT ${JSON.stringify(f.json)} is not a non-negative integer offset`, 'section 4')
      if (offset < last) fail(`CHECKPOINT moved backwards, ${last} to ${offset}`, 'section 7.4')
      if (offset > w.sent) fail(`CHECKPOINT ${offset} is past the ${w.sent} bytes sent`, 'section 7.4')
      last = offset
    }
  }
  return w
}

/**
 * Sends data[from..] as CHUNKs of blockSize. False if the IUT went away.
 * @param {InstanceType<typeof SealedPeer>} peer @param {Buffer} data
 * @param {{ from?: number, to?: number, blockSize?: number, watcher?: { sent: number } }} [o]
 */
async function sendChunks (peer, data, { from = 0, to = data.length, blockSize = BLOCK, watcher } = {}) {
  for (let off = from; off < to; off += blockSize) {
    const end = Math.min(off + blockSize, to)
    if (!await peer.send(TYPE.CHUNK, data.subarray(off, end))) return false
    if (watcher) watcher.sent = end
  }
  return true
}

/**
 * The receiver's answer to an offer: an ACCEPT with this resumeFrom.
 * @param {InstanceType<typeof SealedPeer>} peer @param {number} resumeFrom @param {any} [watcher]
 */
async function expectAccept (peer, resumeFrom, watcher) {
  const f = await peer.expect(TYPE.ACCEPT, watcher ? { allow: [TYPE.CHECKPOINT], onAllowed: (x) => watcher.check(x) } : {})
  if (!Number.isSafeInteger(f.json.resumeFrom) || f.json.resumeFrom < 0) fail(`ACCEPT ${JSON.stringify(f.json)} carries no non-negative integer resumeFrom`, 'section 4')
  if (f.json.resumeFrom !== resumeFrom) fail(`ACCEPT{resumeFrom: ${f.json.resumeFrom}}, expected ${resumeFrom}`, 'sections 4.0 and 7.5')
  return f
}

/**
 * RESULT{ok, sha256} with the file's digest, then nothing more (the
 * receiver is done and sends nothing after RESULT), and the close.
 * @param {InstanceType<typeof SealedPeer>} peer @param {string} sha256 @param {any} watcher
 */
async function expectResultOk (peer, sha256, watcher) {
  const f = await peer.expect(TYPE.RESULT, { allow: [TYPE.CHECKPOINT], onAllowed: (x) => watcher.check(x) })
  if (f.json.ok !== true || f.json.sha256 !== sha256) fail(`RESULT ${JSON.stringify(f.json)}, expected {ok: true, sha256: "${sha256}"}`, 'section 4.2')
  // As an honest sender does once it has read RESULT{ok}: end its side,
  // which is the receiver's signal that the verdict arrived.
  peer.conn.end()
  const after = await peer.drain()
  if (after.length) fail(`the receiver sent ${after.map((x) => x.name).join(', ')} after RESULT`, 'section 4.4')
}

/**
 * The output directory holds exactly the published file, intact.
 * @param {string} dir @param {{ name: string, data: Buffer }} file
 */
async function expectPublished (dir, file) {
  const entries = (await fs.promises.readdir(dir)).sort()
  if (entries.length !== 1 || entries[0] !== file.name) fail(`the output directory holds ${JSON.stringify(entries)}, expected only ${JSON.stringify(file.name)}`, 'sections 4.2 and 7.4')
  const got = await fs.promises.readFile(path.join(dir, file.name))
  if (!got.equals(file.data)) fail(`the published ${file.name} differs from what was sent (${got.length} bytes, expected ${file.data.length})`, 'section 4.2')
}

/** @param {string} dir */
async function expectEmpty (dir) {
  const entries = await fs.promises.readdir(dir)
  if (entries.length) fail(`the output directory holds ${JSON.stringify(entries)}; a refused or canceled drop must leave nothing`, 'sections 4.0 and 7.4')
}

/**
 * After the IUT refuses: whatever it still sends must be well formed, it
 * must close, and it must end with `code` and write nothing.
 * @param {any} sp the asSender/asReceiver result
 * @param {string} code
 * @param {{ dir?: string, frames?: (f: any[]) => void }} [o]
 */
async function expectRefusal (sp, code, { dir, frames } = {}) {
  const sent = await sp.peer.drain()
  if (frames) frames(sent)
  expectOutcome(await sp.s.outcome(), { code })
  if (dir) await expectEmpty(dir)
}

// --- driving a sender (the harness receives) ------------------------------

/**
 * Starts an IUT sender and completes the handshake as an honest receiver,
 * checking that the sender writes nothing before HELLO and that its REPLY
 * verifies.
 * @param {any} t
 * @param {{ caps?: string[], file: { path: string }, args?: string[] }} o
 */
async function asReceiver (t, { caps, file, args = [] }) {
  const s = await t.start('sender', ['--file', file.path, ...args])
  if (!await s.conn.quietFor(200)) fail('the sender wrote before reading HELLO; the receiver writes first', 'section 3.1')
  const h = hello({ ...s.code, caps })
  await s.conn.write(h.bytes)
  const r = await readReply(s.conn, h)
  await s.conn.write(r.keys.confirmR)
  const peer = new SealedPeer(s.conn, { sendKey: r.keys.kR2S, receiveKey: r.keys.kS2R, caps: r.caps, iut: 'sender' })
  return { s, peer }
}

/**
 * The sender's MANIFEST, checked against section 4.0, and that no file
 * byte follows it before the harness answers.
 * @param {any} sp @param {{ name: string, data: Buffer, sha256: string }} file
 * @param {{ stream?: boolean }} [o]
 */
async function expectManifest (sp, file, { stream = false } = {}) {
  const f = await sp.peer.expect(TYPE.MANIFEST)
  const m = f.json
  const fields = Object.keys(m).sort()
  if (JSON.stringify(fields) !== JSON.stringify(wire.MANIFEST_FIELDS)) fail(`MANIFEST has the fields ${JSON.stringify(fields)}; the set is closed: ${wire.MANIFEST_FIELDS.join(', ')}`, 'section 4.0')
  if (m.v !== 2) fail(`MANIFEST v is ${JSON.stringify(m.v)}, not 2`, 'section 4.0')
  if (m.name !== file.name) fail(`MANIFEST name is ${JSON.stringify(m.name)}, the file is ${JSON.stringify(file.name)}`, 'section 4.0')
  if (!Number.isSafeInteger(m.blockSize) || m.blockSize < 1 || m.blockSize > MAX_CHUNK) fail(`MANIFEST blockSize ${JSON.stringify(m.blockSize)} is outside 1..${MAX_CHUNK}`, 'sections 4.0 and 5')
  if (stream) {
    if (m.size !== null || m.sha256 !== null) fail(`a streamed MANIFEST declares size ${JSON.stringify(m.size)} and sha256 ${JSON.stringify(m.sha256)}; both must be null`, 'section 4.3')
  } else {
    if (m.size !== file.data.length) fail(`MANIFEST size is ${JSON.stringify(m.size)}, the file has ${file.data.length} bytes`, 'section 4.0')
    if (m.sha256 !== file.sha256) fail(`MANIFEST sha256 is ${JSON.stringify(m.sha256)}, not the file's lowercase hex digest`, 'section 4.0')
  }
  if (!await sp.s.conn.quietFor(300)) fail('the sender sent more after MANIFEST without waiting for an answer', 'section 4.0')
  return m
}

/**
 * Reads CHUNKs until `bytes` have arrived (or, for a stream, until END),
 * each no larger than blockSize. Returns what arrived and, for a stream,
 * END's body.
 * @param {InstanceType<typeof SealedPeer>} peer @param {any} m @param {{ bytes?: number, stream?: boolean }} o
 */
async function receiveChunks (peer, m, { bytes = 0, stream = false }) {
  /** @type {Buffer[]} */
  const parts = []
  let got = 0
  while (stream || got < bytes) {
    const f = await peer.next({ what: stream ? 'CHUNK or END' : 'CHUNK' })
    if (stream && f.type === TYPE.END) return { data: Buffer.concat(parts), end: f.json }
    if (f.type !== TYPE.CHUNK) fail(`expected CHUNK, the sender sent ${f.name}`, 'section 4.4')
    if (f.body.length > m.blockSize) fail(`a ${f.body.length}-byte CHUNK, over the manifest's blockSize ${m.blockSize}`, 'sections 4.0 and 4.3')
    parts.push(f.body)
    got += f.body.length
    if (!stream && got > bytes) fail(`the sender sent ${got} bytes, past the ${bytes} expected`, 'section 4.4')
  }
  return { data: Buffer.concat(parts), end: null }
}

/**
 * The harness's RESULT{ok}, and the sender then succeeds having sent
 * nothing more.
 * @param {any} sp @param {string} sha256
 */
async function finishSend (sp, sha256) {
  await sp.peer.send(TYPE.RESULT, { ok: true, sha256 })
  const after = await sp.peer.drain()
  if (after.length) fail(`the sender sent ${after.map((/** @type {any} */ x) => x.name).join(', ')} after the last byte`, 'section 4.4')
  expectOutcome(await sp.s.outcome(), { ok: true })
}

// --- frames built wrong on purpose -----------------------------------------

/**
 * A frame sealed without its length as associated data: the pre-W15a
 * construction, under the right key and counter.
 * @param {InstanceType<typeof wire.Sealer>} sealer @param {number} type @param {Buffer} body
 */
function sealWithoutAad (sealer, type, body) {
  const plaintext = Buffer.concat([Buffer.from([type]), body])
  const nonce = Buffer.alloc(12)
  nonce.writeBigUInt64BE(sealer.counter++, 4)
  const cipher = crypto.createCipheriv('chacha20-poly1305', sealer.key, nonce, { authTagLength: 16 })
  const header = Buffer.alloc(4)
  header.writeUInt32BE(plaintext.length + 16, 0)
  return Buffer.concat([header, cipher.update(plaintext), cipher.final(), cipher.getAuthTag()])
}

/** @param {Buffer} frame @param {number} delta */
function rewriteLength (frame, delta) {
  const sealed = frame.subarray(4)
  const body = delta > 0 ? Buffer.concat([sealed, Buffer.alloc(delta)]) : sealed.subarray(0, sealed.length + delta)
  const header = Buffer.alloc(4)
  header.writeUInt32BE(body.length, 0)
  return Buffer.concat([header, body])
}

const json = (/** @type {any} */ v) => Buffer.from(JSON.stringify(v), 'utf8')

// --- the scenarios ---------------------------------------------------------

/** @type {Array<{ id: string, title: string, refs: string, run: (t: any) => Promise<void> }>} */
const scenarios = []
/** @param {string} id @param {string} title @param {string} refs @param {(t: any) => Promise<void>} run */
const scenario = (id, title, refs, run) => { scenarios.push({ id, title, refs, run }) }

// --- the five, with the IUT as receiver ----------------------------------

scenario('R-handshake', 'receiver: HELLO, CONFIRM, and silence until the offer', '3.1, 3.2, 4.4', async (t) => {
  const file = await t.file({ size: KIB })
  const sp = await asSender(t)
  if (!await sp.s.conn.quietFor(300)) fail('the receiver sent a frame before any MANIFEST arrived', 'section 4.4, awaiting offer')
  const w = checkpointWatcher(sp.peer, { sized: true })
  await sp.peer.send(TYPE.MANIFEST, manifestOf(file))
  await expectAccept(sp.peer, 0, w)
  await sendChunks(sp.peer, file.data, { watcher: w })
  await expectResultOk(sp.peer, file.sha256, w)
  expectOutcome(await sp.s.outcome(), { ok: true })
  await expectPublished(sp.dir, file)
})

scenario('R-transfer', 'receiver: a 3 MiB file, published intact', '4.0, 4.2, 5', async (t) => {
  const file = await t.file({ size: 3 * MIB + 7 })
  const sp = await asSender(t)
  const w = checkpointWatcher(sp.peer, { sized: true })
  await sp.peer.send(TYPE.MANIFEST, manifestOf(file))
  await expectAccept(sp.peer, 0, w)
  await sendChunks(sp.peer, file.data, { watcher: w })
  await expectResultOk(sp.peer, file.sha256, w)
  expectOutcome(await sp.s.outcome(), { ok: true })
  await expectPublished(sp.dir, file)
})

scenario('R-transfer-empty', 'receiver: an empty file', '4.0, 4.2', async (t) => {
  const file = await t.file({ size: 0, name: 'empty.bin' })
  const sp = await asSender(t)
  const w = checkpointWatcher(sp.peer, { sized: true })
  await sp.peer.send(TYPE.MANIFEST, manifestOf(file))
  await expectAccept(sp.peer, 0, w)
  await expectResultOk(sp.peer, file.sha256, w)
  expectOutcome(await sp.s.outcome(), { ok: true })
  await expectPublished(sp.dir, file)
})

scenario('R-transfer-max-chunk', 'receiver: chunks of exactly the largest size a frame can carry', '5', async (t) => {
  const file = await t.file({ size: 2 * MAX_CHUNK + 5 })
  const sp = await asSender(t)
  const w = checkpointWatcher(sp.peer, { sized: true })
  await sp.peer.send(TYPE.MANIFEST, manifestOf(file, { blockSize: MAX_CHUNK }))
  await expectAccept(sp.peer, 0, w)
  await sendChunks(sp.peer, file.data, { blockSize: MAX_CHUNK, watcher: w })
  await expectResultOk(sp.peer, file.sha256, w)
  expectOutcome(await sp.s.outcome(), { ok: true })
  await expectPublished(sp.dir, file)
})

scenario('R-cancel-by-peer', 'receiver: the sender cancels mid-transfer', '4.4, 7.4', async (t) => {
  const file = await t.file({ size: 2 * MIB })
  const sp = await asSender(t)
  await sp.peer.send(TYPE.MANIFEST, manifestOf(file))
  await expectAccept(sp.peer, 0)
  await sendChunks(sp.peer, file.data, { to: 256 * KIB })
  await sp.peer.send(TYPE.CANCEL, { reason: 'conformance: the sender cancels' })
  await expectRefusal(sp, 'ERR_CANCELLED_PEER', { dir: sp.dir })
})

scenario('R-cancel-local', 'receiver: the receiver cancels, and says so with CANCEL', '4, 4.4, 7.4', async (t) => {
  const file = await t.file({ size: 8 * MIB })
  const sp = await asSender(t, { args: ['--cancel-after', String(128 * KIB)] })
  const w = checkpointWatcher(sp.peer, { sized: true })
  await sp.peer.send(TYPE.MANIFEST, manifestOf(file))
  await expectAccept(sp.peer, 0, w)
  // Sending and reading at once: the receiver's CANCEL arrives while
  // chunks are still going out, and a write to a closed socket is expected.
  const sending = sendChunks(sp.peer, file.data, { watcher: w })
  const cancel = await sp.peer.expect(TYPE.CANCEL, { allow: [TYPE.CHECKPOINT], onAllowed: (x) => w.check(x), timeout: 15000 })
  if (typeof cancel.json.reason !== 'string') fail(`CANCEL ${JSON.stringify(cancel.json)} carries no reason string`, 'section 4')
  await sending
  await expectRefusal(sp, 'ABORT_ERR', { dir: sp.dir })
})

/**
 * Session one of a resume: 2.5 MiB of `file` sent, then the connection
 * closed. Returns the size of the partial it left.
 * @param {any} t @param {string} dir @param {{ name: string, data: Buffer, sha256: string }} file
 */
async function interrupted (t, dir, file) {
  const sp = await asSender(t, { dir })
  const w = checkpointWatcher(sp.peer, { sized: true })
  await sp.peer.send(TYPE.MANIFEST, manifestOf(file))
  await expectAccept(sp.peer, 0, w)
  await sendChunks(sp.peer, file.data, { to: 2.5 * MIB, watcher: w })
  sp.s.conn.end()
  const frames = await sp.peer.drain()
  for (const f of frames) if (f.type === TYPE.CHECKPOINT) w.check(f); else fail(`the receiver sent ${f.name} when the connection closed`, 'section 4.4')
  expectOutcome(await sp.s.outcome(), { code: 'ERR_CONNECTION' })
  const part = path.join(dir, `${file.name}.part`)
  const entries = await fs.promises.readdir(dir)
  if (JSON.stringify(entries) !== JSON.stringify([`${file.name}.part`])) fail(`after an interrupted resumable transfer the directory holds ${JSON.stringify(entries)}, expected only ${file.name}.part`, 'section 7.4')
  const kept = await fs.promises.readFile(part)
  if (!kept.equals(file.data.subarray(0, kept.length))) fail('the kept partial is not a prefix of what was sent', 'section 7.4')
  return kept.length
}

/** The largest boundary a partial reaches, or the size if it is complete (section 7.5). @param {number} kept @param {number} size */
const proposalFor = (kept, size) => kept === size ? size : Math.floor(kept / PREFIX_BOUNDARY) * PREFIX_BOUNDARY

scenario('R-resume', 'receiver: an interrupted transfer resumes from a checked prefix', '7.4, 7.5', async (t) => {
  const dir = await t.dir()
  const file = await t.file({ size: 3.5 * MIB })
  const kept = await interrupted(t, dir, file)
  const n = proposalFor(kept, file.data.length)
  if (n === 0) fail(`the partial kept only ${kept} bytes of the 2.5 MiB sent, under one boundary`, 'section 7.4')

  const sp = await asSender(t, { dir })
  const w = checkpointWatcher(sp.peer, { sized: true })
  w.sent = n
  await sp.peer.send(TYPE.MANIFEST, manifestOf(file))
  await expectAccept(sp.peer, n, w)
  await sp.peer.send(TYPE.PREFIX, { sha256: wire.sha256(file.data.subarray(0, n)) })
  await expectAccept(sp.peer, n, w)
  await sendChunks(sp.peer, file.data, { from: n, watcher: w })
  await expectResultOk(sp.peer, file.sha256, w)
  expectOutcome(await sp.s.outcome(), { ok: true })
  await expectPublished(dir, file)
})

scenario('R-resume-mismatch', 'receiver: a prefix that does not match restarts from zero, silently', '7.2, 7.5', async (t) => {
  const dir = await t.dir()
  const file = await t.file({ size: 3.5 * MIB })
  const kept = await interrupted(t, dir, file)
  const n = proposalFor(kept, file.data.length)
  // A newer file under the same name and size: the realistic cause.
  const newer = await t.file({ size: file.data.length, name: file.name })

  const sp = await asSender(t, { dir })
  const w = checkpointWatcher(sp.peer, { sized: true })
  await sp.peer.send(TYPE.MANIFEST, manifestOf(newer))
  await expectAccept(sp.peer, n, w)
  await sp.peer.send(TYPE.PREFIX, { sha256: wire.sha256(newer.data.subarray(0, n)) })
  await expectAccept(sp.peer, 0, w)
  await sendChunks(sp.peer, newer.data, { watcher: w })
  await expectResultOk(sp.peer, newer.sha256, w)
  expectOutcome(await sp.s.outcome(), { ok: true })
  await expectPublished(dir, newer)
})

scenario('R-resume-not-negotiated', 'receiver: without resume, an interrupted transfer keeps no partial', '7.4', async (t) => {
  const file = await t.file({ size: 3 * MIB })
  const sp = await asSender(t, { caps: ['stream'] })
  const w = checkpointWatcher(sp.peer, { sized: true })
  await sp.peer.send(TYPE.MANIFEST, manifestOf(file))
  await expectAccept(sp.peer, 0, w)
  await sendChunks(sp.peer, file.data, { to: 2 * MIB, watcher: w })
  sp.s.conn.end()
  await expectRefusal(sp, 'ERR_CONNECTION', { dir: sp.dir, frames: (fs) => fs.forEach((f) => w.check(f)) })
})

scenario('R-stream', 'receiver: a stream of unknown length, verified by END', '4.3', async (t) => {
  const file = await t.file({ size: 2 * MIB + 3 })
  const sp = await asSender(t)
  const w = checkpointWatcher(sp.peer, { sized: false })
  await sp.peer.send(TYPE.MANIFEST, manifestOf(file, { stream: true }))
  await expectAccept(sp.peer, 0, w)
  await sendChunks(sp.peer, file.data, { watcher: w })
  await sp.peer.send(TYPE.END, { sha256: file.sha256 })
  await expectResultOk(sp.peer, file.sha256, w)
  expectOutcome(await sp.s.outcome(), { ok: true })
  await expectPublished(sp.dir, file)
})

scenario('R-stream-not-negotiated', 'receiver: a stream offered without stream negotiated is declined', '4.0, 4.3', async (t) => {
  const file = await t.file({ size: KIB })
  const sp = await asSender(t, { caps: ['resume'] })
  await sp.peer.send(TYPE.MANIFEST, manifestOf(file, { stream: true }))
  const d = await sp.peer.expect(TYPE.DECLINE)
  if (d.json.code !== 'ERR_MANIFEST_INVALID') fail(`DECLINE ${JSON.stringify(d.json)}, expected code ERR_MANIFEST_INVALID`, 'section 4.0')
  await expectRefusal(sp, 'ERR_MANIFEST_INVALID', { dir: sp.dir })
})

// --- the five, with the IUT as sender ------------------------------------

scenario('S-handshake', 'sender: reads first, REPLY verifies, MANIFEST is the first frame', '3.1, 3.2, 4.0', async (t) => {
  const file = await t.file({ size: KIB })
  const sp = await asReceiver(t, { file })
  const m = await expectManifest(sp, file)
  await sp.peer.send(TYPE.ACCEPT, { resumeFrom: 0 })
  const { data } = await receiveChunks(sp.peer, m, { bytes: file.data.length })
  if (!data.equals(file.data)) fail('the bytes sent differ from the file', 'section 4.2')
  await finishSend(sp, file.sha256)
})

scenario('S-transfer', 'sender: a 3 MiB file, nothing before ACCEPT, chunks within blockSize', '4.0, 4.2, 4.3, 5', async (t) => {
  const file = await t.file({ size: 3 * MIB + 7 })
  const sp = await asReceiver(t, { file })
  const m = await expectManifest(sp, file)
  await sp.peer.send(TYPE.ACCEPT, { resumeFrom: 0 })
  const { data } = await receiveChunks(sp.peer, m, { bytes: file.data.length })
  if (wire.sha256(data) !== file.sha256) fail('the bytes sent do not hash to the manifest\'s digest', 'section 4.2')
  await finishSend(sp, file.sha256)
})

scenario('S-transfer-empty', 'sender: an empty file', '4.0, 4.2', async (t) => {
  const file = await t.file({ size: 0, name: 'empty.bin' })
  const sp = await asReceiver(t, { file })
  await expectManifest(sp, file)
  await sp.peer.send(TYPE.ACCEPT, { resumeFrom: 0 })
  await finishSend(sp, file.sha256)
})

scenario('S-cancel-by-peer', 'sender: the receiver cancels mid-transfer', '4.4', async (t) => {
  const file = await t.file({ size: 4 * MIB })
  const sp = await asReceiver(t, { file })
  const m = await expectManifest(sp, file)
  await sp.peer.send(TYPE.ACCEPT, { resumeFrom: 0 })
  await receiveChunks(sp.peer, m, { bytes: m.blockSize })
  await sp.peer.send(TYPE.CANCEL, { reason: 'conformance: the receiver cancels' })
  await expectRefusal(sp, 'ERR_CANCELLED_PEER', {
    frames: (fs) => { for (const f of fs) if (f.type !== TYPE.CHUNK) fail(`the sender sent ${f.name} after the receiver canceled`, 'section 4.4') }
  })
})

scenario('S-cancel-local', 'sender: the sender cancels, and says so with CANCEL', '4, 4.4', async (t) => {
  const file = await t.file({ size: 8 * MIB })
  const sp = await asReceiver(t, { file, args: ['--cancel-after', String(128 * KIB)] })
  const m = await expectManifest(sp, file)
  await sp.peer.send(TYPE.ACCEPT, { resumeFrom: 0 })
  for (;;) {
    const f = await sp.peer.next({ what: 'CHUNK or CANCEL', timeout: 15000 })
    if (f.type === TYPE.CANCEL) {
      if (typeof f.json.reason !== 'string') fail(`CANCEL ${JSON.stringify(f.json)} carries no reason string`, 'section 4')
      break
    }
    if (f.type !== TYPE.CHUNK) fail(`expected CHUNK or CANCEL, the sender sent ${f.name}`, 'section 4.4')
    if (f.body.length > m.blockSize) fail('a CHUNK over blockSize', 'section 4.0')
  }
  await expectRefusal(sp, 'ABORT_ERR')
})

scenario('S-resume', 'sender: proves its prefix, then sends from the agreed offset', '7.4, 7.5', async (t) => {
  const file = await t.file({ size: 2.5 * MIB })
  const sp = await asReceiver(t, { file })
  const m = await expectManifest(sp, file)
  await sp.peer.send(TYPE.ACCEPT, { resumeFrom: MIB })
  const p = await sp.peer.expect(TYPE.PREFIX)
  if (p.json.sha256 !== wire.sha256(file.data.subarray(0, MIB))) fail(`PREFIX ${JSON.stringify(p.json)} is not the SHA-256 of the sender's first 1 MiB`, 'section 7.5')
  if (!await sp.s.conn.quietFor(300)) fail('the sender sent more after PREFIX without waiting for the answer', 'section 7.5')
  await sp.peer.send(TYPE.ACCEPT, { resumeFrom: MIB })
  const { data } = await receiveChunks(sp.peer, m, { bytes: file.data.length - MIB })
  if (!data.equals(file.data.subarray(MIB))) fail('the bytes sent after a resume are not the file from the agreed offset', 'section 7.5')
  await finishSend(sp, file.sha256)
})

scenario('S-resume-restart', 'sender: a receiver that answers PREFIX with ACCEPT{0} gets the whole file', '7.5', async (t) => {
  const file = await t.file({ size: 2.5 * MIB })
  const sp = await asReceiver(t, { file })
  const m = await expectManifest(sp, file)
  await sp.peer.send(TYPE.ACCEPT, { resumeFrom: 2 * MIB })
  const p = await sp.peer.expect(TYPE.PREFIX)
  if (p.json.sha256 !== wire.sha256(file.data.subarray(0, 2 * MIB))) fail('PREFIX is not the SHA-256 of the sender\'s first 2 MiB', 'section 7.5')
  await sp.peer.send(TYPE.ACCEPT, { resumeFrom: 0 })
  const { data } = await receiveChunks(sp.peer, m, { bytes: file.data.length })
  if (!data.equals(file.data)) fail('after ACCEPT{0} the sender did not send the whole file from zero', 'section 7.5')
  await finishSend(sp, file.sha256)
})

scenario('S-resume-whole', 'sender: a resume at the whole size sends PREFIX = the manifest digest and no chunks', '7.5', async (t) => {
  const file = await t.file({ size: 1.5 * MIB })
  const sp = await asReceiver(t, { file })
  await expectManifest(sp, file)
  await sp.peer.send(TYPE.ACCEPT, { resumeFrom: file.data.length })
  const p = await sp.peer.expect(TYPE.PREFIX)
  if (p.json.sha256 !== file.sha256) fail('PREFIX for the whole file is not the manifest\'s sha256', 'section 7.5')
  await sp.peer.send(TYPE.ACCEPT, { resumeFrom: file.data.length })
  await finishSend(sp, file.sha256)
})

scenario('S-stream', 'sender: size and sha256 null, chunks, then END with the digest', '4.3', async (t) => {
  const file = await t.file({ size: 2 * MIB + 3 })
  const sp = await asReceiver(t, { file, args: ['--stream'] })
  const m = await expectManifest(sp, file, { stream: true })
  await sp.peer.send(TYPE.ACCEPT, { resumeFrom: 0 })
  const { data, end } = await receiveChunks(sp.peer, m, { stream: true })
  if (!data.equals(file.data)) fail('the streamed bytes differ from the source', 'section 4.3')
  if (!end || end.sha256 !== file.sha256) fail(`END ${JSON.stringify(end)} does not carry the stream's SHA-256`, 'section 4.3')
  await finishSend(sp, file.sha256)
})

scenario('S-stream-not-negotiated', 'sender: without stream negotiated, a stream is not offered', '4.3', async (t) => {
  const file = await t.file({ size: KIB })
  const sp = await asReceiver(t, { file, caps: ['resume'], args: ['--stream'] })
  const frames = await sp.peer.drain()
  if (frames.some((f) => f.type === TYPE.MANIFEST)) fail('the sender offered a stream to a receiver that did not negotiate stream', 'section 4.3')
  const outcome = await sp.s.outcome()
  if (outcome.ok) fail('the sender reported success for a stream it could not offer')
})

// --- negative frame vectors against a live receiver -----------------------
//
// frames-negative.json's twelve, sealed under the live session's keys
// instead of the fixed ones. The receiver must fail with the code given
// and write nothing.

/**
 * @param {string} id @param {string} title @param {string} code
 * @param {(sp: any, sealer: InstanceType<typeof wire.Sealer>, manifest: any) => Promise<void>} inject
 * @param {{ end?: boolean }} [o]
 */
function receiverRefuses (id, title, code, inject, { end = false } = {}) {
  scenario(id, `receiver refuses: ${title}`, '4.4, 5', async (t) => {
    const file = await t.file({ size: 3 })
    const sp = await asSender(t)
    await inject(sp, sp.peer.sealer, manifestOf(file))
    if (end) sp.s.conn.end()
    await expectRefusal(sp, code, { dir: sp.dir })
  })
}

receiverRefuses('R-neg-chunk-first', 'CHUNK before MANIFEST', 'ERR_PROTOCOL', (sp) => sp.peer.send(TYPE.CHUNK, Buffer.from('abc')))
receiverRefuses('R-neg-reserved', 'a sealed 0x00 tag', 'ERR_PROTOCOL', (sp) => sp.peer.send(0x00, json({})))
receiverRefuses('R-neg-unassigned', 'a sealed unassigned tag (0x0a)', 'ERR_PROTOCOL', (sp) => sp.peer.send(0x0a, json({})))
receiverRefuses('R-neg-oversize', 'a header declaring 1 MiB + 1', 'ERR_PROTOCOL', (sp) => sp.peer.sendRaw(Buffer.from('00100001', 'hex')))
receiverRefuses('R-neg-too-short', 'a declared length too short to be sealed', 'ERR_PROTOCOL', (sp) => sp.peer.sendRaw(Buffer.from('00000010' + '00'.repeat(16), 'hex')))
receiverRefuses('R-neg-truncated-prefix', 'a truncated length prefix, then the close', 'ERR_CONNECTION', (sp) => sp.peer.sendRaw(Buffer.from('000000', 'hex')), { end: true })
receiverRefuses('R-neg-length-plus', 'a rewritten length (+1)', 'ERR_PROTOCOL', (sp, sealer, m) => sp.peer.sendRaw(rewriteLength(sealer.seal(TYPE.MANIFEST, json(m)), 1)))
receiverRefuses('R-neg-length-minus', 'a rewritten length (-1)', 'ERR_PROTOCOL', (sp, sealer, m) => sp.peer.sendRaw(rewriteLength(sealer.seal(TYPE.MANIFEST, json(m)), -1)))
receiverRefuses('R-neg-no-aad', 'a frame sealed without its length as associated data', 'ERR_PROTOCOL', (sp, sealer, m) => sp.peer.sendRaw(sealWithoutAad(sealer, TYPE.MANIFEST, json(m))))
receiverRefuses('R-neg-reflected', 'a frame sealed for the other direction', 'ERR_PROTOCOL', async (sp) => {
  // Under k_r2s, the receiver's own sending key, at counter 0.
  const reflected = new wire.Sealer(sp.peer.opener.key).seal(TYPE.MANIFEST, json({ v: 2, name: 'x', size: 0, sha256: wire.sha256(Buffer.alloc(0)), blockSize: BLOCK }))
  await sp.peer.sendRaw(reflected)
})
receiverRefuses('R-neg-replay', 'the MANIFEST replayed', 'ERR_PROTOCOL', async (sp, sealer, m) => {
  const frame = sealer.seal(TYPE.MANIFEST, json(m))
  await sp.peer.sendRaw(frame)
  await sp.peer.sendRaw(frame)
})
receiverRefuses('R-neg-prefix-unasked', 'PREFIX when no resume was proposed', 'ERR_PROTOCOL', async (sp, _sealer, m) => {
  await sp.peer.send(TYPE.MANIFEST, m)
  await expectAccept(sp.peer, 0)
  await sp.peer.send(TYPE.PREFIX, { sha256: m.sha256 })
})

// --- the state machine's refusals against a live receiver ------------------

receiverRefuses('R-neg-second-manifest', 'a second MANIFEST', 'ERR_PROTOCOL', async (sp, _sealer, m) => {
  await sp.peer.send(TYPE.MANIFEST, m)
  await sp.peer.send(TYPE.MANIFEST, m)
})
receiverRefuses('R-neg-end-sized', 'END on a transfer that declared its size', 'ERR_PROTOCOL', async (sp, _sealer, m) => {
  await sp.peer.send(TYPE.MANIFEST, { ...m, size: 6, sha256: wire.sha256(Buffer.from('abcabc')) })
  await expectAccept(sp.peer, 0)
  await sp.peer.send(TYPE.CHUNK, Buffer.from('abc'))
  await sp.peer.send(TYPE.END, { sha256: m.sha256 })
})
receiverRefuses('R-neg-chunk-over-block', 'a CHUNK larger than blockSize', 'ERR_PROTOCOL', async (sp, _sealer, m) => {
  const data = Buffer.alloc(2048, 1)
  await sp.peer.send(TYPE.MANIFEST, { ...m, size: data.length, sha256: wire.sha256(data), blockSize: 1024 })
  await expectAccept(sp.peer, 0)
  await sp.peer.send(TYPE.CHUNK, data)
})
receiverRefuses('R-neg-chunk-past-size', 'bytes past the declared size', 'ERR_SIZE_MISMATCH', async (sp, _sealer, m) => {
  await sp.peer.send(TYPE.MANIFEST, m)
  await expectAccept(sp.peer, 0)
  await sp.peer.send(TYPE.CHUNK, Buffer.from('abcd'))
})
receiverRefuses('R-neg-sender-decline', 'a DECLINE from the sender that is not ERR_DROP_TAKEN', 'ERR_PROTOCOL', (sp) => sp.peer.send(TYPE.DECLINE, { reason: 'no', code: 'ERR_DECLINED' }))
receiverRefuses('R-neg-manifest-extra-field', 'a MANIFEST with a field outside the closed set', 'ERR_MANIFEST_INVALID', async (sp, _sealer, m) => {
  await sp.peer.send(TYPE.MANIFEST, { ...m, mode: 420 })
  const d = await sp.peer.expect(TYPE.DECLINE)
  if (d.json.code !== 'ERR_MANIFEST_INVALID') fail(`DECLINE ${JSON.stringify(d.json)}, expected code ERR_MANIFEST_INVALID`, 'section 4.0')
})
receiverRefuses('R-neg-manifest-v1', 'a MANIFEST with v: 1', 'ERR_MANIFEST_INVALID', async (sp, _sealer, m) => {
  await sp.peer.send(TYPE.MANIFEST, { ...m, v: 1 })
  const d = await sp.peer.expect(TYPE.DECLINE)
  if (d.json.code !== 'ERR_MANIFEST_INVALID') fail(`DECLINE ${JSON.stringify(d.json)}, expected code ERR_MANIFEST_INVALID`, 'section 4.0')
})
receiverRefuses('R-neg-manifest-half-stream', 'a MANIFEST with a size and no digest', 'ERR_MANIFEST_INVALID', async (sp, _sealer, m) => {
  await sp.peer.send(TYPE.MANIFEST, { ...m, sha256: null })
  const d = await sp.peer.expect(TYPE.DECLINE)
  if (d.json.code !== 'ERR_MANIFEST_INVALID') fail(`DECLINE ${JSON.stringify(d.json)}, expected code ERR_MANIFEST_INVALID`, 'section 4.0')
})

scenario('R-neg-wrong-digest', 'receiver refuses: bytes that do not match the declared digest, and says so in RESULT', '4.2, 4.4, 7.4', async (t) => {
  const file = await t.file({ size: 256 * KIB })
  const sp = await asSender(t)
  await sp.peer.send(TYPE.MANIFEST, manifestOf(file))
  await expectAccept(sp.peer, 0)
  const altered = flipLastBit(file.data)
  await sendChunks(sp.peer, altered)
  await expectRefusal(sp, 'ERR_HASH_MISMATCH', {
    dir: sp.dir,
    frames: (fs) => {
      const r = fs.find((f) => f.type === TYPE.RESULT)
      if (!r || typeof r.json.error !== 'string' || r.json.ok === true) fail(`expected RESULT{error}, the receiver sent ${JSON.stringify(fs.map((f) => f.json))}`, 'section 4.4')
    }
  })
})

scenario('R-neg-stream-wrong-digest', 'receiver refuses: a stream whose END digest does not match', '4.3, 4.4', async (t) => {
  const file = await t.file({ size: 256 * KIB })
  const sp = await asSender(t)
  await sp.peer.send(TYPE.MANIFEST, manifestOf(file, { stream: true }))
  await expectAccept(sp.peer, 0)
  await sendChunks(sp.peer, file.data)
  await sp.peer.send(TYPE.END, { sha256: wire.sha256(Buffer.from('not the stream')) })
  await expectRefusal(sp, 'ERR_HASH_MISMATCH', {
    dir: sp.dir,
    frames: (fs) => {
      if (!fs.some((f) => f.type === TYPE.RESULT && typeof f.json.error === 'string')) fail('expected RESULT{error}', 'section 4.4')
    }
  })
})

scenario('R-drop-taken', 'receiver: DECLINE{ERR_DROP_TAKEN} as the first frame', '4.0, 4.4', async (t) => {
  const sp = await asSender(t)
  await sp.peer.send(TYPE.DECLINE, { reason: 'conformance: already paired', code: 'ERR_DROP_TAKEN' })
  await expectRefusal(sp, 'ERR_DROP_TAKEN', { dir: sp.dir })
})

// --- handshake vectors against a live receiver ------------------------------

/**
 * A REPLY transformed as `o` says; the receiver must refuse it with
 * `code` and send nothing derived from K: no CONFIRM, no frame.
 * @param {string} id @param {string} title @param {string} code @param {any} o
 */
function receiverRefusesReply (id, title, code, o) {
  scenario(id, `receiver refuses: ${title}`, '3.1, 3.2, 4.4, 6', async (t) => {
    const dir = await t.dir()
    const s = await t.start('receiver', ['--dir', dir])
    const h = await readHello(s.conn)
    await s.conn.write(typeof o === 'function' ? o(h, s.code) : reply(h, { ...s.code, ...o }).bytes)
    if (!await s.conn.closes()) fail('the receiver sent bytes after a REPLY it should have refused; it must send nothing derived from K until confirmS verifies', 'sections 3.2 and 6')
    expectOutcome(await s.outcome(), { code })
    await expectEmpty(dir)
  })
}

receiverRefusesReply('R-hs-wrong-confirm', 'a REPLY whose confirmS does not verify', 'ERR_PAKE_CONFIRMATION', { flipConfirmS: true })
receiverRefusesReply('R-hs-stripped-hello', 'capabilities stripped from HELLO in transit', 'ERR_PAKE_CONFIRMATION', { capsRSeenAs: 'stream' })
receiverRefusesReply('R-hs-stripped-reply', 'capabilities stripped from REPLY in transit', 'ERR_PAKE_CONFIRMATION', { capsSSentAs: 'stream' })
receiverRefusesReply('R-hs-reply-short', 'a REPLY body under 64 bytes', 'ERR_PROTOCOL', () => Buffer.concat([Buffer.from('003f', 'hex'), crypto.randomBytes(63)]))
HANDSHAKE_NEGATIVE.nonCanonicalCaps.forEach((/** @type {string} */ caps, /** @type {number} */ i) => {
  receiverRefusesReply(`R-hs-caps-${i + 1}`, `non-canonical caps_s ${JSON.stringify(caps)}`, 'ERR_PROTOCOL', { capsSRaw: Buffer.from(caps, 'utf8') })
})

// --- handshake vectors against a live sender -------------------------------

/**
 * A HELLO, or a CONFIRM, the sender must refuse with `code`.
 * @param {string} id @param {string} title @param {string} code
 * @param {{ hello?: any, rawHello?: () => Buffer, confirm?: (keys: any) => Buffer }} o
 *   With `confirm`, the HELLO is honest and the CONFIRM is the one given;
 *   the sender must then send no sealed frame. Without it, the sender must
 *   not answer HELLO at all.
 */
function senderRefuses (id, title, code, o) {
  scenario(id, `sender refuses: ${title}`, '3.1, 3.2, 4.4', async (t) => {
    const file = await t.file({ size: KIB })
    const s = await t.start('sender', ['--file', file.path])
    if (o.confirm) {
      const h = hello({ ...s.code })
      await s.conn.write(h.bytes)
      const r = await readReply(s.conn, h)
      await s.conn.write(o.confirm(r.keys))
      if (!await s.conn.closes()) fail('the sender sent bytes after a CONFIRM it should have refused', 'section 3.2')
    } else {
      await s.conn.write(o.rawHello ? o.rawHello() : hello({ ...s.code, ...o.hello }).bytes)
      if (!await s.conn.closes()) fail('the sender answered a HELLO it should have refused', 'sections 3.1 and 4.4')
    }
    expectOutcome(await s.outcome(), { code })
  })
}

senderRefuses('S-hs-v1', 'a v1 opening (version 0x01)', 'ERR_PROTOCOL', { hello: { version: 0x01 } })
senderRefuses('S-hs-hello-short', 'a HELLO body under 49 bytes', 'ERR_PROTOCOL', { rawHello: () => Buffer.concat([Buffer.from('0030', 'hex'), Buffer.from([2]), crypto.randomBytes(47)]) })
senderRefuses('S-hs-sealed-first', 'a sealed frame where HELLO belongs', 'ERR_PROTOCOL', { rawHello: () => Buffer.from(require('../vectors/frames-negative.json').sealed.manifest.hex, 'hex') })
senderRefuses('S-hs-wrong-confirm', 'a CONFIRM that does not verify', 'ERR_PAKE_CONFIRMATION', { confirm: (k) => flipLastBit(k.confirmR) })
senderRefuses('S-hs-reflected', 'its own confirmS returned as CONFIRM', 'ERR_PAKE_CONFIRMATION', { confirm: (k) => k.confirmS })
HANDSHAKE_NEGATIVE.nonCanonicalCaps.forEach((/** @type {string} */ caps, /** @type {number} */ i) => {
  senderRefuses(`S-hs-caps-${i + 1}`, `non-canonical caps_r ${JSON.stringify(caps)}`, 'ERR_PROTOCOL', { hello: { capsRaw: Buffer.from(caps, 'utf8') } })
})

// --- the state machine's refusals against a live sender --------------------

/**
 * After the MANIFEST, the harness answers as `answer` does; the sender
 * must fail with `code`.
 * @param {string} id @param {string} title @param {string} code
 * @param {(sp: any, m: any, file: any) => Promise<void>} answer
 * @param {{ size?: number, caps?: string[], args?: string[] }} [o]
 */
function senderFails (id, title, code, answer, { size = 2.5 * MIB, caps, args = [] } = {}) {
  scenario(id, `sender refuses: ${title}`, '4.4, 7.4, 7.5', async (t) => {
    const file = await t.file({ size })
    const sp = await asReceiver(t, { file, caps, args })
    const m = await expectManifest(sp, file, { stream: args.includes('--stream') })
    await answer(sp, m, file)
    await expectRefusal(sp, code)
  })
}

senderFails('S-neg-accept-off-boundary', 'ACCEPT{resumeFrom} off the 1 MiB boundary', 'ERR_PROTOCOL', (sp) => sp.peer.send(TYPE.ACCEPT, { resumeFrom: 1000 }))
senderFails('S-neg-accept-past-size', 'ACCEPT{resumeFrom} past the offered size', 'ERR_PROTOCOL', (sp) => sp.peer.send(TYPE.ACCEPT, { resumeFrom: 3 * MIB }))
senderFails('S-neg-accept-no-resume', 'ACCEPT{resumeFrom > 0} without resume negotiated', 'ERR_PROTOCOL', (sp) => sp.peer.send(TYPE.ACCEPT, { resumeFrom: MIB }), { caps: ['stream'] })
senderFails('S-neg-accept-stream', 'ACCEPT{resumeFrom > 0} for a stream', 'ERR_PROTOCOL', (sp) => sp.peer.send(TYPE.ACCEPT, { resumeFrom: MIB }), { args: ['--stream'] })
senderFails('S-neg-prefix-third-offset', 'an answer to PREFIX naming a third offset', 'ERR_PROTOCOL', async (sp) => {
  await sp.peer.send(TYPE.ACCEPT, { resumeFrom: 2 * MIB })
  await sp.peer.expect(TYPE.PREFIX)
  await sp.peer.send(TYPE.ACCEPT, { resumeFrom: MIB })
})
senderFails('S-neg-chunk-from-receiver', 'a CHUNK from the receiver', 'ERR_PROTOCOL', (sp) => sp.peer.send(TYPE.CHUNK, Buffer.from('abc')))
senderFails('S-neg-decline', 'DECLINE, with the receiver\'s code', 'ERR_DECLINED', (sp) => sp.peer.send(TYPE.DECLINE, { reason: 'conformance: no space', code: 'ERR_NO_SPACE' }))
senderFails('S-drop-taken', 'DECLINE{ERR_DROP_TAKEN} in answer to the offer', 'ERR_DROP_TAKEN', (sp) => sp.peer.send(TYPE.DECLINE, { reason: 'conformance: already paired', code: 'ERR_DROP_TAKEN' }))
senderFails('S-neg-result-error', 'RESULT{error} after the last byte', 'ERR_RECEIVER_FAILED', async (sp, m, file) => {
  await sp.peer.send(TYPE.ACCEPT, { resumeFrom: 0 })
  await receiveChunks(sp.peer, m, { bytes: file.data.length })
  await sp.peer.send(TYPE.RESULT, { error: 'conformance: the receiver failed' })
})
senderFails('S-neg-result-wrong-digest', 'RESULT{ok} with a digest other than the one sent', 'ERR_HASH_MISMATCH', async (sp, m, file) => {
  await sp.peer.send(TYPE.ACCEPT, { resumeFrom: 0 })
  await receiveChunks(sp.peer, m, { bytes: file.data.length })
  await sp.peer.send(TYPE.RESULT, { ok: true, sha256: wire.sha256(Buffer.from('something else')) })
})
senderFails('S-neg-checkpoint-backwards', 'a CHECKPOINT that moves backwards', 'ERR_PROTOCOL', async (sp, m) => {
  await sp.peer.send(TYPE.ACCEPT, { resumeFrom: 0 })
  await receiveChunks(sp.peer, m, { bytes: 2 * m.blockSize })
  await sp.peer.send(TYPE.CHECKPOINT, { offset: 2 * m.blockSize })
  await sp.peer.send(TYPE.CHECKPOINT, { offset: m.blockSize })
})
senderFails('S-neg-checkpoint-past-sent', 'a CHECKPOINT past what was sent', 'ERR_PROTOCOL', async (sp, m, file) => {
  await sp.peer.send(TYPE.ACCEPT, { resumeFrom: 0 })
  await sp.peer.send(TYPE.CHECKPOINT, { offset: file.data.length + 1 })
})
senderFails('S-neg-checkpoint-no-resume', 'a CHECKPOINT without resume negotiated', 'ERR_PROTOCOL', async (sp, m) => {
  await sp.peer.send(TYPE.ACCEPT, { resumeFrom: 0 })
  await receiveChunks(sp.peer, m, { bytes: m.blockSize })
  await sp.peer.send(TYPE.CHECKPOINT, { offset: m.blockSize })
}, { caps: ['stream'] })
senderFails('S-neg-result-early', 'RESULT before the last byte', 'ERR_PROTOCOL', async (sp, m, file) => {
  await sp.peer.send(TYPE.ACCEPT, { resumeFrom: 0 })
  // Read one chunk and then stop reading, so the sender is held mid-file
  // by backpressure when RESULT arrives.
  await receiveChunks(sp.peer, m, { bytes: m.blockSize })
  sp.s.conn.pause()
  await new Promise((resolve) => setTimeout(resolve, 200))
  await sp.peer.send(TYPE.RESULT, { ok: true, sha256: file.sha256 })
}, { size: 64 * MIB })

module.exports = { scenarios }
