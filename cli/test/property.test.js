'use strict'

// Property-based tests (Q-06, deferred to W12 by decision 6): claims about
// every input of a shape, checked on generated inputs and shrunk to a
// small counterexample when one fails (cli/test-helpers/property.js).
//
// WHAT EACH IS CHECKED AGAINST. A property that compares a function with
// itself -- decode(encode(x)) == x and nothing else -- passes for a codec
// that is wrong in the same way twice, the self-consistency trap
// cpace-vectors.test.js opens with. So every property here has an
// independent side:
//
//   - conformance/src/wire.js, the harness's second implementation of the
//     wire format, which shares no code with engine/src. The channel, the
//     caps encoding, and LEB128 are checked against it differentially:
//     the engine and wire.js must agree on every input, including which
//     inputs they refuse.
//   - a rule restated from PROTOCOL.md in this file: the manifest's
//     section 4.0, the code normalization of section 2, the reason
//     sanitizing of Q-11.
//   - arithmetic the test does itself: the bytes a split must reassemble
//     into, the prefix a resume must prove.
//
// The fuzz harness (fuzz.test.js) asks a different question: does any
// malformed input escape the error vocabulary. These ask whether well-
// formed inputs, and the boundary between well- and malformed, are
// handled exactly as specified.
//
//   ADHAL_PROPERTY_RUNS=<n>     inputs per property (default 100)
//   ADHAL_PROPERTY_SEED=<hex>   replay a failure; it prints the seed

const test = require('node:test')
const assert = require('node:assert/strict')
const crypto = require('node:crypto')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')

const {
  encodeFrame,
  FrameDecoder,
  DEFAULT_MAX_FRAME_SIZE,
  Channel,
  encodeCaps,
  parseCaps,
  parseCode,
  splitCode,
  validateManifest,
  MAX_CHUNK_SIZE,
  safeOutputName,
  sanitizeReason,
  decodeDecline,
  acceptBody,
  decodeAccept,
  checkpointBody,
  decodeCheckpoint,
  sendFile,
  TYPE_MANIFEST,
  TYPE_CHUNK,
  TYPE_ACCEPT,
  TYPE_RESULT,
  TYPE_PREFIX,
  PREFIX_BOUNDARY
} = require('@ad-hal/engine')
const { prependLen } = require('../../engine/src/cpace')
const { WORDS } = require('../../engine/src/wordlist')
const wire = require('../../conformance/src/wire')
const { gen, check, RUNS } = require('../test-helpers/property')
const { duplexPair } = require('../test-helpers/duplex-pair')
const { channelKeys, sealedPeer } = require('../test-helpers/sealed')

const MIB = 1024 * 1024
const sha = (/** @type {Buffer} */ b) => crypto.createHash('sha256').update(b).digest('hex')

/** The code a call refused with, or null if it returned. @param {() => any} fn */
function refusal (fn) {
  try {
    fn()
    return null
  } catch (err) {
    return /** @type {any} */ (err).code || String(err)
  }
}

// --- framing ---------------------------------------------------------------

test('property: however the bytes are split, the decoder yields the same frames', async () => {
  const g = gen.tuple(
    gen.array(gen.bytes({ max: 300 }), { max: 8 }),
    gen.array(gen.int(0, 1 << 20), { max: 12 })
  )
  await check('frame split invariance', g, ([payloads, cuts]) => {
    const stream = Buffer.concat(payloads.map(encodeFrame))
    const at = [...new Set(cuts.map((c) => c % (stream.length + 1)))].sort((a, b) => a - b)
    /** @type {string[]} */
    const got = []
    const decoder = new FrameDecoder((p) => got.push(p.toString('hex')))
    let from = 0
    for (const c of [...at, stream.length]) {
      decoder.push(stream.subarray(from, c))
      from = c
    }
    assert.deepEqual(got, payloads.map((p) => p.toString('hex')))
  })
})

test('property: a declared length is refused on its four bytes exactly when it exceeds the cap', async () => {
  const cap = DEFAULT_MAX_FRAME_SIZE
  const g = gen.oneOf(gen.int(cap - 64, cap + 64), gen.int(0, 0xffffffff))
  await check('frame length cap', g, (length) => {
    const header = Buffer.alloc(4)
    header.writeUInt32BE(length)
    let delivered = 0
    const code = refusal(() => new FrameDecoder(() => { delivered++ }).push(header))
    assert.equal(code, length > cap ? 'ERR_PROTOCOL' : null, `length ${length}`)
    assert.equal(delivered, length === 0 ? 1 : 0, 'a header alone delivers nothing but the empty frame')
  })
})

// --- the sealed channel, against wire.js -----------------------------------

const message = gen.tuple(gen.int(1, 9), gen.bytes({ max: 300 }))

test('property: what the engine seals, the independent opener opens, in order', async () => {
  const g = gen.tuple(gen.bytes({ min: 32, max: 32 }), gen.array(message, { min: 1, max: 10 }))
  await check('channel seal vs wire.Opener', g, ([key, messages]) => {
    const other = Buffer.alloc(32, 0xaa)
    const sealer = new Channel({ sendKey: Buffer.from(key), receiveKey: other, onMessage () {} })
    const opener = new wire.Opener(Buffer.from(key))
    for (const [type, body] of messages) {
      const frame = sealer.seal(type, body)
      const plaintext = opener.open(frame.subarray(0, 4), frame.subarray(4))
      assert.ok(plaintext, 'the frame authenticates under the next counter and its own header')
      assert.equal(plaintext[0], type)
      assert.ok(plaintext.subarray(1).equals(body))
      assert.equal(frame.readUInt32BE(0), body.length + 17, 'the length is type, body, and tag')
    }
  })
})

test('property: what the independent sealer seals, the engine opens, however it arrives', async () => {
  const g = gen.tuple(gen.bytes({ min: 32, max: 32 }), gen.array(message, { min: 1, max: 10 }), gen.array(gen.int(0, 1 << 16), { max: 8 }))
  await check('wire.Sealer vs channel open', g, ([key, messages, cuts]) => {
    const sealer = new wire.Sealer(Buffer.from(key))
    const stream = Buffer.concat(messages.map(([type, body]) => sealer.seal(type, body)))
    /** @type {Array<[number, string]>} */
    const got = []
    const channel = new Channel({ sendKey: Buffer.alloc(32, 0xaa), receiveKey: Buffer.from(key), onMessage: (type, body) => got.push([type, body.toString('hex')]) })
    const at = [...new Set(cuts.map((c) => c % (stream.length + 1)))].sort((a, b) => a - b)
    let from = 0
    for (const c of [...at, stream.length]) {
      channel.push(stream.subarray(from, c))
      from = c
    }
    assert.deepEqual(got, messages.map(([type, body]) => [type, body.toString('hex')]))
  })
})

test('property: a sealed frame with any one bit flipped is never delivered', async () => {
  const g = gen.tuple(gen.bytes({ min: 32, max: 32 }), message, gen.int(0, 1 << 20))
  await check('channel single-bit tamper', g, ([key, [type, body], where]) => {
    const frame = Buffer.from(new wire.Sealer(Buffer.from(key)).seal(type, body))
    const bit = where % (frame.length * 8)
    frame[bit >> 3] ^= 1 << (bit & 7)
    let delivered = 0
    const channel = new Channel({ sendKey: Buffer.alloc(32, 0xaa), receiveKey: Buffer.from(key), onMessage: () => { delivered++ } })
    const code = refusal(() => channel.push(frame))
    assert.equal(delivered, 0, `bit ${bit} flipped and the frame was delivered`)
    // A flip in the length can leave the decoder waiting for bytes that
    // are not coming, which is a close for the transfer to report; any
    // refusal it does make is ERR_PROTOCOL.
    assert.ok(code === null || code === 'ERR_PROTOCOL', `refused with ${code}`)
  })
})

// --- the capability encoding, against wire.js -------------------------------

const token = gen.oneOf(
  gen.element(['resume', 'stream', 'a', 'z9', 'x-y', 'abcdefghijklmnop']),
  gen.map(gen.array(gen.element([...'abc-019']), { min: 1, max: 17 }), (cs) => cs.join(''))
)

test('property: the engine encodes any capability set exactly as wire.js does', async () => {
  const valid = /^[a-z0-9]([a-z0-9-]{0,14}[a-z0-9])?$/
  await check('caps encoding differential', gen.array(token, { max: 12 }), (tokens) => {
    const ours = refusal(() => encodeCaps(tokens))
    const theirs = refusal(() => wire.encodeCaps(tokens))
    assert.equal(ours === null, theirs === null, `one refused and one did not: ${ours} / ${theirs}`)
    if (ours === null) assert.equal(encodeCaps(tokens).toString('hex'), wire.encodeCaps(tokens).toString('hex'))
    if (tokens.every((t) => valid.test(t)) && new Set(tokens).size * 17 <= 128) assert.equal(ours, null, 'a small valid set is encodable')
  })
})

test('property: the engine accepts a peer\'s caps bytes exactly when they are canonical', async () => {
  const piece = gen.element(['resume', 'stream', ',', 'a', '-', 'R', ' ', 'b', 'resume,stream', '\u0000', 'é'])
  const g = gen.map(gen.array(piece, { max: 10 }), (ps) => Buffer.from(ps.join(''), 'utf8'))
  await check('caps parsing differential', g, (bytes) => {
    const theirs = wire.parseCanonicalCaps(bytes)
    const code = refusal(() => parseCaps(bytes))
    if (theirs === null) assert.equal(code, 'ERR_PROTOCOL', `accepted the non-canonical ${JSON.stringify(bytes.toString('utf8'))}`)
    else assert.deepEqual(parseCaps(bytes), theirs)
  })
})

test('property: LEB128 lengths agree with wire.js and decode back', async () => {
  await check('prepend_len differential', gen.oneOf(gen.int(0, 300), gen.int(16000, 17000), gen.int(0, 3 * MIB)), (n) => {
    const data = Buffer.alloc(n)
    const ours = prependLen(data)
    assert.ok(ours.equals(wire.prependLen(data)))
    let value = 0
    let i = 0
    for (let shift = 1; ; shift *= 128) {
      const b = ours[i++]
      value += (b & 0x7f) * shift
      if (!(b & 0x80)) break
    }
    assert.equal(value, n)
    assert.equal(ours.length, i + n)
  })
})

// --- the code (section 2) ----------------------------------------------------

test('property: any casing and separator noise normalizes to the one canonical code', async () => {
  const g = gen.tuple(
    gen.array(gen.int(0, WORDS.length - 1), { min: 5, max: 5 }),
    gen.array(gen.element(['-', '_', '.', ' ', '--', ' \t ', '-_.']), { min: 4, max: 4 }),
    gen.array(gen.int(0, 1), { max: 60 }),
    gen.element(['', ' ', '\t', '  '])
  )
  await check('code normalization', g, ([indices, separators, upper, pad]) => {
    const words = indices.map((i) => WORDS[i])
    let noisy = words.map((w, i) => w + (separators[i] || '')).join('')
    noisy = [...noisy].map((c, i) => upper[i] ? c.toUpperCase() : c).join('')
    const canonical = words.join('-')
    assert.equal(parseCode(pad + noisy + pad), canonical)
    assert.equal(parseCode(canonical), canonical, 'idempotent')
    assert.deepEqual(splitCode(noisy), { nameplate: words.slice(0, 2).join('-'), secret: words.slice(2).join('-') })
  })
})

// --- the manifest (section 4.0), restated ----------------------------------

const FIELD_VALUES = [
  undefined, null, true, 0, -1, 1, 2, 1.5, 3, MAX_CHUNK_SIZE, MAX_CHUNK_SIZE + 1, 2 ** 53, 2 ** 53 - 1, '', 'x', 'report.pdf',
  'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
  'BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD',
  'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015a', [], {}
]

/**
 * Section 4.0, written out again from the spec rather than from
 * validateManifest: the closed field set, v first, and the both-or-neither
 * rule for size and sha256.
 * @param {any} m @param {number | null | undefined} maxSize
 */
function specAccepts (m, maxSize) {
  const isInt = (/** @type {any} */ v) => typeof v === 'number' && Number.isInteger(v) && Math.abs(v) <= Number.MAX_SAFE_INTEGER
  if (m === null || typeof m !== 'object' || Array.isArray(m)) return false
  if (m.v !== 2) return false
  if (Object.keys(m).some((k) => !['v', 'name', 'size', 'sha256', 'blockSize'].includes(k))) return false
  if (typeof m.name !== 'string') return false
  const stream = m.size === null
  if (!stream && !(isInt(m.size) && m.size >= 0)) return false
  if (stream !== (m.sha256 === null)) return false
  if (!stream && !(typeof m.sha256 === 'string' && /^[0-9a-f]{64}$/.test(m.sha256))) return false
  if (!(isInt(m.blockSize) && m.blockSize >= 1 && m.blockSize <= 1048559)) return false
  const cap = maxSize === undefined ? 8 * 1024 ** 3 : maxSize
  if (cap !== null && !stream && m.size > cap) return false
  return true
}

test('property: validateManifest accepts exactly what section 4.0 allows', async () => {
  const field = gen.element(FIELD_VALUES)
  const g = gen.tuple(
    gen.element([2, 2, 2, 1, '2', undefined]),
    field, field, field, field,
    gen.element([undefined, undefined, undefined, 0, 'x']),
    gen.element([undefined, null, 1, 3, 2 ** 40])
  )
  await check('manifest differential', g, ([v, name, size, sha256, blockSize, extra, maxSize]) => {
    /** @type {any} */
    const m = {}
    for (const [k, value] of Object.entries({ v, name, size, sha256, blockSize, extra })) if (value !== undefined) m[k] = value
    const code = refusal(() => validateManifest(m, maxSize))
    assert.equal(code === null, specAccepts(m, maxSize), `${JSON.stringify(m)} with maxSize ${maxSize}: engine ${code === null ? 'accepted' : code}`)
    if (code !== null) assert.equal(code, 'ERR_MANIFEST_INVALID')
  })
})

// --- names a peer can propose ------------------------------------------------

test('property: a peer\'s name never lands outside the output directory', async () => {
  const piece = gen.element(['..', '/', '\\', '.', ' ', 'a', 'CON', 'nul', '\u0000', '‮', 'é', '~', ':', '*', '.part', 'x'.repeat(100), '\u001b[2J'])
  const g = gen.tuple(gen.map(gen.array(piece, { max: 8 }), (ps) => ps.join('')), gen.element(['darwin', 'linux', 'win32']))
  const dir = path.resolve(os.tmpdir(), 'adhal-property-names')
  await check('safeOutputName containment', g, ([declared, platform]) => {
    let out
    try {
      out = safeOutputName(dir, declared, { platform })
    } catch (err) {
      assert.equal(/** @type {any} */ (err).code, 'ERR_UNSAFE_NAME', `refused ${JSON.stringify(declared)} with ${/** @type {any} */ (err).code}`)
      return
    }
    assert.equal(path.dirname(out.outputPath), dir, `${JSON.stringify(declared)} became ${out.outputPath}`)
    assert.equal(path.basename(out.outputPath), out.name)
    assert.ok(out.name.length > 0 && out.name !== '.' && out.name !== '..', `name ${JSON.stringify(out.name)}`)
    assert.ok(!out.name.includes('/') && !out.name.includes('\u0000'), `name ${JSON.stringify(out.name)}`)
    if (platform === 'win32') assert.ok(!/[\\:*]/.test(out.name), `a Windows name ${JSON.stringify(out.name)}`)
    assert.ok(Buffer.byteLength(out.name, 'utf8') <= 255, 'at most 255 bytes')
  })
})

// --- what a peer's words can do to a terminal (Q-11) ------------------------

// A FINDING (W12), FIXED. MAX_REASON_BYTES in engine/src/message.js used
// to slice the UTF-8 bytes, and decoding a character cut in half turned
// its leftover bytes into U+FFFD, which is three: 255 ASCII bytes and an
// emoji sanitized to 258 bytes. Escapes were still stripped, so what a
// peer could put on a terminal was unchanged, but the cap was two bytes
// looser than it said. The cap is now cut at a character boundary.
test('property: a sanitized reason carries no control or bidi character and fits its cap', async () => {
  const unit = gen.oneOf(
    gen.int(0, 0x2ff),
    gen.element([0x1b, 0x7f, 0x85, 0x9b, 0x202a, 0x202e, 0x2066, 0x2069, 0x200b, 0xfeff, 0x1f600, 0x10ffff])
  )
  await check('sanitizeReason', gen.array(unit, { max: 300 }), (points) => {
    const out = sanitizeReason(String.fromCodePoint(...points))
    // eslint-disable-next-line no-control-regex
    assert.ok(!/[\u0000-\u001f\u007f-\u009f‪-‮⁦-⁩]/.test(out), JSON.stringify(out))
    assert.ok(Buffer.byteLength(out, 'utf8') <= 256)
    assert.equal(out, out.trim())
    // And nothing more is dropped than the cap requires: the longest run of
    // whole characters that fits, counted here a code point at a time
    // rather than by scanning bytes, as sanitizeReason does.
    let kept = ''
    for (const cp of points) {
      const c = cp <= 0x1f || (cp >= 0x7f && cp <= 0x9f) || (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069) ? ' ' : String.fromCodePoint(cp)
      if (Buffer.byteLength(kept + c, 'utf8') > 256) break
      kept += c
    }
    assert.equal(out, kept.trim())
  })
})

test('property: a DECLINE code is either of the specified shape or absent', async () => {
  const g = gen.tuple(gen.element(['ERR_NO_SPACE', 'ERR_', 'err_x', 'ERR_\u001b', `ERR_${'A'.repeat(48)}`, `ERR_${'A'.repeat(49)}`, 7, null, ['ERR_X']]), gen.element(['why', 3, null]))
  await check('decodeDecline code shape', g, ([code, reason]) => {
    const decoded = decodeDecline(Buffer.from(JSON.stringify({ reason, code }), 'utf8'))
    const shaped = typeof code === 'string' && /^ERR_[A-Z0-9_]{1,48}$/.test(code)
    assert.equal(decoded.code, shaped ? code : null)
  })
})

test('property: ACCEPT and CHECKPOINT carry exactly the non-negative safe integers', async () => {
  const g = gen.element([0, 1, 2 ** 53 - 1, 2 ** 53, -1, 1.5, '1', null, Infinity])
  await check('offset bodies', g, (n) => {
    const body = Buffer.from(JSON.stringify({ resumeFrom: n, offset: n }), 'utf8')
    const ok = Number.isSafeInteger(n) && /** @type {number} */ (n) >= 0
    assert.equal(refusal(() => decodeAccept(body)), ok ? null : 'ERR_PROTOCOL')
    assert.equal(refusal(() => decodeCheckpoint(body)), ok ? null : 'ERR_PROTOCOL')
    if (ok) {
      assert.equal(decodeAccept(acceptBody({ resumeFrom: /** @type {number} */ (n) })).resumeFrom, n)
      assert.equal(decodeCheckpoint(checkpointBody({ offset: /** @type {number} */ (n) })).offset, n)
    }
  })
})

// --- resume's boundary arithmetic (section 7.5) -----------------------------

/**
 * Drives a real sendFile with a hand-played receiver that proposes
 * `proposal` and answers PREFIX with `answer` (the proposal or 0).
 * @param {Buffer} data @param {number} proposal @param {(n: number) => number} answer
 */
async function resumeAgainst (data, proposal, answer) {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'adhal-property-resume-'))
  try {
    const file = path.join(dir, 'payload.bin')
    await fs.promises.writeFile(file, data)
    const [tx, rx] = duplexPair()
    const keys = channelKeys()
    /** @type {string | null} */
    let prefix = null
    let start = 0
    /** @type {Buffer[]} */
    const chunks = []
    let answered = false
    const result = () => peer.send(TYPE_RESULT, Buffer.from(JSON.stringify({ ok: true, sha256: sha(data) })))
    const got = () => chunks.reduce((n, c) => n + c.length, 0)
    const peer = sealedPeer(rx, keys.receiver, {
      onMessage: (type, body) => {
        if (type === TYPE_MANIFEST) {
          peer.send(TYPE_ACCEPT, acceptBody({ resumeFrom: proposal }))
        } else if (type === TYPE_PREFIX) {
          prefix = JSON.parse(body.toString('utf8')).sha256
          start = answer(proposal)
          answered = true
          peer.send(TYPE_ACCEPT, acceptBody({ resumeFrom: start }))
          // Resumed at the whole size: there is nothing left to send, so
          // the verdict is due at once.
          if (start === data.length) result()
        } else if (type === TYPE_CHUNK) {
          chunks.push(Buffer.from(body))
          if (answered && got() === data.length - start) result()
        }
      }
    })
    // Short timeouts: a receiver this test forgot to answer should fail the
    // property in seconds, not after the two-minute RESULT wait.
    const outcome = await sendFile(tx, file, { ...keys.sender, caps: ['resume'], acceptTimeout: 5000, resultTimeout: 5000 }).then(() => null, (err) => err)
    return { outcome, prefix, start, sent: Buffer.concat(chunks) }
  } finally {
    await fs.promises.rm(dir, { recursive: true, force: true })
  }
}

// Sizes on and beside the boundaries, where a resume's arithmetic is
// decided, and anywhere in between.
const size = gen.oneOf(
  gen.map(gen.tuple(gen.int(0, 4), gen.int(-1, 1)), ([k, d]) => Math.max(0, k * MIB + d)),
  gen.int(0, 4.5 * MIB)
)
const RESUME_RUNS = Math.max(5, Math.ceil(RUNS / 8))

test('property: a valid resume proves the right prefix and sends exactly the rest', async () => {
  const g = gen.tuple(size, gen.int(0, 10), gen.int(0, 1))
  await check('resume from a valid proposal', g, async ([n, pick, restart]) => {
    const data = crypto.randomBytes(n)
    const valid = [...Array.from({ length: Math.floor(n / PREFIX_BOUNDARY) }, (_, k) => (k + 1) * PREFIX_BOUNDARY), ...(n > 0 ? [n] : [])]
    if (valid.length === 0) return
    const proposal = valid[pick % valid.length]
    const r = await resumeAgainst(data, proposal, (p) => restart ? 0 : p)
    assert.equal(r.outcome, null, `sendFile failed: ${r.outcome && r.outcome.message}`)
    assert.equal(r.prefix, sha(data.subarray(0, proposal)), `PREFIX for ${proposal} of ${n}`)
    assert.ok(r.sent.equals(data.subarray(r.start)), `sent from ${r.start}`)
  }, { runs: RESUME_RUNS })
})

test('property: a proposal off the boundary, and not the whole file, is refused', async () => {
  const g = gen.tuple(gen.int(1, 3.5 * MIB), gen.int(1, 3.5 * MIB))
  await check('resume from an invalid proposal', g, async ([n, proposal]) => {
    if (proposal % PREFIX_BOUNDARY === 0 && proposal <= n) return
    if (proposal === n) return
    const r = await resumeAgainst(crypto.randomBytes(n), proposal, (p) => p)
    assert.equal(r.outcome && r.outcome.code, 'ERR_PROTOCOL', `proposal ${proposal} of ${n}`)
    assert.equal(r.prefix, null, 'no PREFIX for a proposal it refused')
  }, { runs: RESUME_RUNS })
})
