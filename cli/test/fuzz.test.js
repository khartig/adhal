'use strict'

// A seeded random-mutation fuzz harness over every parser that reads peer
// bytes (W15d and its decision 6, docs/history/WORK-RECORD.md): the framer, the channel,
// every message decoder, manifest validation, filename handling and the
// three handshake readers.
//
// ONE PROPERTY, checked on every input: it is either accepted, or refused
// with an error from the protocol's vocabulary -- a `.code` in PROTOCOL.md
// section 10's table, or one of the handshake's two per-candidate codes.
// Never a TypeError, a RangeError or anything else that means the parser
// met a case it did not handle; never a hang (each target is synchronous,
// so a hang is a test timeout); and never buffering past a declared cap.
//
// The refusals are not all TransferErrors, and that is deliberate rather
// than drift: frame.js's FrameLengthError does not depend on errors.js, and
// the handshake's refusals are plain Errors with a code (handshake.js,
// handshakeError). What callers and the CLI branch on is `.code`, so that
// is what the property checks.
//
// No new dependency (decision 6): the generator and mutators are here.
// Mutation, not generation: each target starts from valid messages the
// engine itself produces and damages them, which reaches the checks past
// the first one far more often than random bytes would.
//
// Budget: ADHAL_FUZZ_ITERATIONS per target (default below, the fast tier)
// and ADHAL_FUZZ_SEED. A failure prints the seed and the iteration, which
// is all it takes to replay it:
//
//   ADHAL_FUZZ_SEED=<seed> node --test cli/test/fuzz.test.js
//   pnpm fuzz        # the long run: 100000 iterations per target

const test = require('node:test')
const assert = require('node:assert/strict')
const crypto = require('node:crypto')

const {
  FrameDecoder,
  encodeFrame,
  HEADER_SIZE,
  Channel,
  decodeMessage,
  decodeCancelReason,
  decodeResult,
  decodeAccept,
  decodeDecline,
  decodeCheckpoint,
  decodeEnd,
  decodePrefix,
  cancelBody,
  resultBody,
  acceptBody,
  declineBody,
  checkpointBody,
  endBody,
  prefixBody,
  validateManifest,
  DEFAULT_MAX_SIZE,
  MAX_CHUNK_SIZE,
  safeOutputName,
  displayName,
  Initiator,
  Responder,
  MessageReader,
  LENGTH_PREFIX_SIZE,
  HELLO_MAX_BODY,
  REPLY_MAX_BODY,
  generateCode,
  splitCode
} = require('@ad-hal/engine')

const ITERATIONS = Number(process.env.ADHAL_FUZZ_ITERATIONS || 2000)
const SEED = process.env.ADHAL_FUZZ_SEED || crypto.randomBytes(4).toString('hex')

// The refusals a peer's bytes may produce. Anything else escaping a parser
// is a finding.
const VOCABULARY = new Set([
  'ERR_PROTOCOL',
  'ERR_MANIFEST_INVALID',
  'ERR_UNSAFE_NAME',
  'ERR_PAKE_CONFIRMATION'
])

// --- the generator --------------------------------------------------------

// mulberry32, seeded from the hex seed: small, fast, and reproducible
// across platforms, which Math.random is not.
function rng (/** @type {string} */ seed) {
  let a = parseInt(seed.slice(0, 8).padEnd(8, '0'), 16) >>> 0
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
  const int = (/** @type {number} */ n) => Math.floor(next() * n)
  return {
    int,
    pick: (/** @type {any[]} */ list) => list[int(list.length)],
    bytes: (/** @type {number} */ n) => Buffer.from(Array.from({ length: n }, () => int(256)))
  }
}

// Values that sit on the boundaries parsers get wrong.
const INTERESTING = [0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff, 0x7b, 0x7d, 0x22, 0x2c, 0x1b, 0x5c]

// JSON values that sit on the boundaries a field check gets wrong: the
// wrong type, the edge of the range, the unsafe integer, the string a
// terminal would act on, and the keys a prototype would.
const VALUES = [
  null, true, false, 0, -0, -1, 1, 1.5, 65536, 1048559, 1048560, 2 ** 53, 2 ** 53 - 1, -(2 ** 53), 1e308,
  '', 'x', '0', 'ERR_DECLINED', 'ERR_drop', 'a'.repeat(300), '\u202e', '\u001b[2J', '../x', 'CON', 'a/b', '.',
  'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
  'BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD',
  [], [1], {}, { a: 1 }
]
const KEYS = ['v', 'name', 'size', 'sha256', 'blockSize', 'ok', 'error', 'reason', 'code', 'resumeFrom', 'offset', '__proto__', 'constructor', 'extra']

/**
 * A mutation that keeps the input JSON: a field replaced, removed or
 * added. Byte mutations alone almost never produce a well-formed object
 * with a hostile value, and those are what field checks exist for.
 * @param {ReturnType<typeof rng>} r @param {Buffer} input
 * @returns {Buffer | null} null if `input` is not a JSON object
 */
function mutateJson (r, input) {
  let value
  try {
    value = JSON.parse(input.toString('utf8'))
  } catch {
    return null
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null
  const keys = Object.keys(value)
  const choice = r.int(3)
  if (choice === 0 && keys.length) value[r.pick(keys)] = r.pick(VALUES)
  else if (choice === 1 && keys.length) delete value[r.pick(keys)]
  else value[r.pick(KEYS)] = r.pick(VALUES)
  // JSON.stringify drops an own __proto__ assigned this way, so it is
  // spliced in as text when chosen: JSON.parse makes it an own key.
  const text = JSON.stringify(value)
  return Buffer.from(r.int(8) === 0 ? text.replace(/^\{/, '{"__proto__":' + JSON.stringify(r.pick(VALUES)) + (text === '{}' ? '' : ',')) : text, 'utf8')
}

/**
 * One mutation of `input`, chosen by `r`; `others` is the corpus, for
 * splicing one valid message into another.
 * @param {ReturnType<typeof rng>} r @param {Buffer} input @param {Buffer[]} others
 */
function mutate (r, input, others) {
  if (r.int(3) === 0) {
    const structured = mutateJson(r, input)
    if (structured) return structured
  }
  const b = Buffer.from(input)
  const at = () => r.int(Math.max(1, b.length))
  switch (r.int(9)) {
    case 0: if (b.length) b[at()] ^= 1 << r.int(8); return b
    case 1: if (b.length) b[at()] = r.pick(INTERESTING); return b
    case 2: if (b.length) b[at()] = r.int(256); return b
    case 3: { const i = at(); return Buffer.concat([b.subarray(0, i), r.bytes(1 + r.int(8)), b.subarray(i)]) }
    case 4: { const i = at(); return Buffer.concat([b.subarray(0, i), b.subarray(i + 1 + r.int(8))]) }
    case 5: return b.subarray(0, r.int(b.length + 1))
    case 6: { const i = at(); const j = at(); return Buffer.concat([b, b.subarray(Math.min(i, j), Math.max(i, j))]) }
    case 7: { const o = r.pick(others); const i = at(); return Buffer.concat([b.subarray(0, i), o.subarray(r.int(o.length + 1))]) }
    default: {
      // A 2- or 4-byte big-endian length somewhere, set to a boundary.
      const width = r.pick([2, 4])
      if (b.length < width) return b
      const i = r.int(b.length - width + 1)
      const value = r.pick([0, 1, 16, 17, 48, 49, 50, 64, 177, 178, 0xffff, 1048576, 1048577, 0xffffffff])
      if (width === 2) b.writeUInt16BE(value & 0xffff, i)
      else b.writeUInt32BE(value >>> 0, i)
      return b
    }
  }
}

/** Splits `input` into random chunks, as a transport may deliver it. */
function chunked (/** @type {ReturnType<typeof rng>} */ r, /** @type {Buffer} */ input) {
  const out = []
  let i = 0
  while (i < input.length) {
    const n = 1 + r.int(Math.min(64, input.length - i))
    out.push(input.subarray(i, i + n))
    i += n
  }
  return out
}

/**
 * Runs `target` on ITERATIONS mutated inputs. `target` may return
 * normally or throw; a throw must carry a code from VOCABULARY.
 * @param {string} name
 * @param {Buffer[]} corpus valid inputs to start from
 * @param {(input: Buffer, r: ReturnType<typeof rng>) => void} target
 * @param {number} [iterations]
 */
function fuzz (name, corpus, target, iterations = ITERATIONS) {
  const r = rng(crypto.createHash('sha256').update(`${SEED}:${name}`).digest('hex'))
  let refused = 0
  for (let i = 0; i < iterations; i++) {
    let input = r.pick(corpus)
    for (let k = 1 + r.int(4); k > 0; k--) input = mutate(r, input, corpus)
    try {
      target(input, r)
    } catch (err) {
      const code = err && /** @type {any} */ (err).code
      if (!VOCABULARY.has(code)) {
        assert.fail(
          `${name}: input ${i} (ADHAL_FUZZ_SEED=${SEED}) threw outside the vocabulary: ` +
          `${err && err.name}: ${err && /** @type {any} */ (err).message} [code ${code}]\n` +
          `input: ${input.toString('hex')}`
        )
      }
      refused++
    }
  }
  if (process.env.ADHAL_FUZZ_STATS) process.stdout.write(`# ${name}: ${iterations - refused} accepted, ${refused} refused\n`)
  return refused
}

const json = (/** @type {any} */ v) => Buffer.from(JSON.stringify(v), 'utf8')
const SHA = crypto.createHash('sha256').update('x').digest('hex')
const MANIFEST = { v: 2, name: 'report.pdf', size: 1048576, sha256: SHA, blockSize: 65536 }

test.after(() => { process.stdout.write(`# fuzz seed ${SEED}, ${ITERATIONS} iterations per target\n`) })

// --- the targets ----------------------------------------------------------

test('fuzz: the framer refuses or delimits, and never buffers past its cap', () => {
  const max = 1024
  const corpus = [
    encodeFrame(Buffer.from('hello')),
    Buffer.concat([encodeFrame(Buffer.alloc(0)), encodeFrame(Buffer.alloc(max))]),
    encodeFrame(crypto.randomBytes(300))
  ]
  fuzz('frame.js', corpus, (input, r) => {
    const decoder = new FrameDecoder((payload) => {
      assert.ok(payload.length <= max, 'a delivered frame is within the cap')
    }, { maxFrameSize: max })
    for (const piece of chunked(r, input)) {
      decoder.push(piece)
      // What it holds waiting is at most one header and one capped body.
      assert.ok(/** @type {any} */ (decoder)._buffer.length <= HEADER_SIZE + max, 'the decoder buffered past its cap')
    }
  })
})

test('fuzz: a sealed channel opens, refuses, and stays refused', () => {
  const s2r = crypto.randomBytes(32)
  const r2s = crypto.randomBytes(32)
  const sender = new Channel({ sendKey: Buffer.from(s2r), receiveKey: Buffer.from(r2s), onMessage () {} })
  const stream = Buffer.concat([
    sender.seal(0x01, json(MANIFEST)),
    sender.seal(0x02, crypto.randomBytes(200)),
    sender.seal(0x08, endBody({ sha256: SHA }))
  ])
  fuzz('channel.js', [stream], (input, r) => {
    const channel = new Channel({ sendKey: Buffer.from(r2s), receiveKey: Buffer.from(s2r), maxFrameSize: 4096, onMessage () {} })
    let failed = null
    for (const piece of chunked(r, input)) {
      try {
        channel.push(piece)
      } catch (err) {
        if (!failed) failed = err
      }
      // THE LATCH: once a frame has failed, nothing after it is accepted.
      if (failed) assert.throws(() => channel.push(Buffer.alloc(1)), { code: 'ERR_PROTOCOL' })
    }
    if (failed) throw failed
  })
})

test('fuzz: every message decoder refuses or returns a well-formed value', () => {
  const bodies = [
    json(MANIFEST), cancelBody('stop'), resultBody({ ok: true, sha256: SHA }), resultBody({ error: 'no' }),
    acceptBody({ resumeFrom: 1048576 }), declineBody('no', 'ERR_DECLINED'), checkpointBody({ offset: 42 }),
    endBody({ sha256: SHA }), prefixBody({ sha256: SHA }), Buffer.from('{"__proto__":{"x":1}}')
  ]
  const printable = (/** @type {string} */ s) => !/[\u0000-\u001f\u007f-\u009f‪-‮⁦-⁩]/.test(s)

  fuzz('decodeMessage', bodies.map((b) => Buffer.concat([Buffer.from([1 + (b[0] % 9)]), b])), (input) => {
    const { type, body } = decodeMessage(input)
    assert.ok(type >= 0x01 && type <= 0x09 && Buffer.isBuffer(body))
  })
  // These two never throw, by design: a garbled CANCEL or DECLINE has
  // still said stop, or no. What they return must be safe to print.
  fuzz('decodeCancelReason', bodies, (input) => {
    const reason = decodeCancelReason(input)
    assert.ok(typeof reason === 'string' && printable(reason) && Buffer.byteLength(reason) <= 256)
  })
  fuzz('decodeDecline', bodies, (input) => {
    const { reason, code } = decodeDecline(input)
    assert.ok(printable(reason))
    assert.ok(code === null || /^ERR_[A-Z0-9_]{1,48}$/.test(code))
  })
  fuzz('decodeResult', bodies, (input) => {
    const result = decodeResult(input)
    assert.ok('error' in result ? printable(result.error) : /^[0-9a-f]{64}$/.test(result.sha256))
  })
  fuzz('decodeAccept', bodies, (input) => {
    const { resumeFrom } = decodeAccept(input)
    assert.ok(Number.isSafeInteger(resumeFrom) && resumeFrom >= 0)
  })
  fuzz('decodeCheckpoint', bodies, (input) => {
    const { offset } = decodeCheckpoint(input)
    assert.ok(Number.isSafeInteger(offset) && offset >= 0)
  })
  for (const [name, decode] of [['decodeEnd', decodeEnd], ['decodePrefix', decodePrefix]]) {
    fuzz(/** @type {string} */ (name), bodies, (input) => {
      assert.match(/** @type {any} */ (decode)(input).sha256, /^[0-9a-f]{64}$/)
    })
  }
})

test('fuzz: manifest validation, and the name that would be written', () => {
  const corpus = [
    json(MANIFEST),
    json({ ...MANIFEST, size: null, sha256: null }),
    json({ ...MANIFEST, name: '../../etc/passwd' }),
    json({ ...MANIFEST, name: 'CON.txt' }),
    json({ ...MANIFEST, name: `a‮b.pdf` })
  ]
  fuzz('validateManifest', corpus, (input) => {
    let parsed
    try {
      parsed = JSON.parse(input.toString('utf8'))
    } catch {
      // receiveFile turns this into ERR_MANIFEST_INVALID before
      // validateManifest runs (transfer.js, consider), so it is a refusal
      // here too -- and counted as one, not as a manifest that passed.
      throw Object.assign(new Error('not JSON'), { code: 'ERR_MANIFEST_INVALID' })
    }
    // The default cap, as receiveFile applies it when given none.
    validateManifest(parsed, undefined)
    // An accepted manifest is one section 4.0 allows, restated here rather
    // than trusted: "never crashes" cannot see a check that is missing and
    // lets a bad value through, and this can. (Two planted bugs -- the
    // name's type check and blockSize's ceiling removed -- passed the
    // crash property alone and fail this.)
    assert.equal(parsed.v, 2)
    assert.ok(Object.keys(parsed).every((k) => ['v', 'name', 'size', 'sha256', 'blockSize'].includes(k)), 'only manifest v2 fields')
    assert.equal(typeof parsed.name, 'string')
    assert.ok(parsed.size === null || (Number.isSafeInteger(parsed.size) && parsed.size >= 0 && parsed.size <= DEFAULT_MAX_SIZE), 'size')
    assert.ok(parsed.sha256 === null || /^[0-9a-f]{64}$/.test(parsed.sha256), 'sha256')
    assert.equal(parsed.size === null, parsed.sha256 === null, 'size and sha256 are both declared or both null')
    assert.ok(Number.isSafeInteger(parsed.blockSize) && parsed.blockSize >= 1 && parsed.blockSize <= MAX_CHUNK_SIZE, 'blockSize')
    for (const platform of ['linux', 'darwin', 'win32']) {
      const { outputPath } = safeOutputName('/srv/drops', parsed.name, { platform })
      assert.ok(outputPath.startsWith('/srv/drops'), 'a name that validated resolves inside the directory')
    }
    // What the CLI would print of it.
    assert.ok(!/[\u0000-\u001f\u007f‮]/.test(displayName(parsed.name)))
  })
})

test('fuzz: the handshake readers refuse or answer, and bound what they wait for', () => {
  // Fewer iterations: an input that parses costs a scalar multiplication.
  const n = Math.max(50, Math.floor(ITERATIONS / 10))
  const code = splitCode(generateCode())
  const hellos = [new Initiator(code).hello(), new Initiator({ ...code, caps: [] }).hello(), new Initiator({ ...code, caps: ['stream'] }).hello()]

  fuzz('Responder.readHello', hellos, (input, r) => {
    const responder = new Responder(code)
    const reader = new MessageReader()
    for (const piece of chunked(r, input)) {
      reader.push(piece)
      const answer = responder.readHello(reader)
      if (answer) return
      // Waiting means a declared length within the cap, and nothing more.
      assert.ok(reader.buffered <= LENGTH_PREFIX_SIZE + HELLO_MAX_BODY, 'the reader waited past the HELLO cap')
    }
  }, n)

  const replies = [0, 1].map(() => {
    const initiator = new Initiator(code)
    const reader = new MessageReader()
    reader.push(initiator.hello())
    return /** @type {any} */ (new Responder(code).readHello(reader)).reply
  })
  fuzz('Initiator.readReply', replies, (input, r) => {
    // A fresh initiator each time, so nothing it read before is reused.
    const initiator = new Initiator(code)
    const reader = new MessageReader()
    for (const piece of chunked(r, input)) {
      reader.push(piece)
      if (initiator.readReply(reader)) return
      assert.ok(reader.buffered <= LENGTH_PREFIX_SIZE + REPLY_MAX_BODY, 'the reader waited past the REPLY cap')
    }
  }, n)

  fuzz('Responder.readConfirm', [crypto.randomBytes(32), Buffer.alloc(32)], (input) => {
    const responder = new Responder(code)
    const reader = new MessageReader()
    reader.push(hellos[0])
    responder.readHello(reader)
    reader.push(input)
    responder.readConfirm(reader)
  }, n)
})
