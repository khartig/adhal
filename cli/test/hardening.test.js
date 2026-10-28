'use strict'

// Stage 0: the things a peer can do to a receiver *after* it has proven
// it knows the drop code.
//
// That is the whole frame for this file. The code proof (proof.js) answers
// exactly one question -- is this the peer the human meant -- and every
// test here is about a peer for which the answer is yes and which is
// hostile anyway. A drop code can be shoulder-surfed, screenshotted,
// forwarded to the wrong chat, or typed by someone who was sent it for a
// different file. "They know the code" is the beginning of the threat
// model, not the end of it.
//
// Each test names the thing that was possible before it existed.

const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('node:path')
const os = require('node:os')
const fs = require('node:fs')
const crypto = require('node:crypto')

const {
  receiveFile,
  safeOutputName,
  safeWriteName,
  displayName,
  MAX_NAME_BYTES,
  MAX_DISPLAY_LENGTH,
  TYPE_CHUNK,
  DEFAULT_MAX_SIZE,
  decodeDecline,
  decodeCancelReason,
  declineBody,
  cancelBody,
  decodeResult,
  resultBody,
  decodeEnd,
  decodePrefix,
  decodeCheckpoint,
  displayText,
  TYPE_MANIFEST,
  TYPE_CANCEL,
  TYPE_RESULT
} = require('@ad-hal/engine')
const { sealedSender } = require('../test-helpers/sealed')
const { assertSameBytes } = require('../test-helpers/bytes')
const { describeError } = require('../src/report')

async function tmpDir (t, label) {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), `adhal-${label}-`))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  return dir
}

function manifestFor (body, overrides = {}) {
  return {
    v: 2,
    name: 'ok.bin',
    size: body.length,
    sha256: crypto.createHash('sha256').update(body).digest('hex'),
    blockSize: 64 * 1024,
    ...overrides
  }
}

function offer (outputDir, manifest, body = null, options = {}) {
  const sender = sealedSender()
  const received = receiveFile(sender.socket, outputDir, { ...sender.keys, ...options })
  const answer = body ? sender.offer(manifest, body) : sender.offer(manifest)
  return { received, answer, peer: sender.peer, socket: sender.socket }
}

/** @param {any} promise
 * @param code
 * @param extra
 */
async function rejectsWith (promise, code, extra = null) {
  const err = await promise.then(
    (value) => { throw new Error(`expected a rejection, resolved with ${JSON.stringify(value)}`) },
    (e) => e
  )
  assert.equal(err.code, code, `expected ${code}, got ${err.code}: ${err.message}`)
  if (extra) extra(err)
  return err
}

// --- names that are hostile without escaping anywhere --------------------

test('a name carrying terminal control or bidi characters is refused', () => {
  // None of these traverse a directory, so the resolved-path assertion
  // that guarded this function waves them all through. They were all
  // ACCEPTED UNCHANGED before Stage 0 -- verified by running the probe,
  // not inferred: newline, ESC, BEL, and the RLO override each landed on
  // disk and in the log exactly as the peer wrote them.
  const dir = path.join(os.tmpdir(), 'adhal-hostile-names')
  const refused = [
    ['evil\nverified: ok', 'forges a second log line'],
    ['a\u001b[2Jb', 'ESC: clears the terminal'],
    ['a\u0007b', 'BEL'],
    ['a\u009bBb', 'C1 CSI, which has no ESC byte in it to grep for'],
    ['inv\u202efdp.exe', 'RLO: displays as invexe.pdf'],
    ['x\u2066y', 'bidi isolate'],
    ['\u0000abc', 'NUL'],
    ['...', 'nothing but dots, which strips to empty'],
    ['   ', 'nothing but spaces']
  ]

  for (const [name, why] of refused) {
    assert.throws(
      () => safeOutputName(dir, name),
      (/** @type {any} */ err) => {
        assert.equal(err.code, 'ERR_UNSAFE_NAME', `${JSON.stringify(name)} (${why}) should be ERR_UNSAFE_NAME`)
        assert.equal(err.declaredName, name)
        // The refusal must say which rule fired. cli/src/report.js used
        // to assert "it points outside the output directory" for every
        // one of these, which is false for all nine.
        assert.equal(typeof err.detail, 'string')
        assert.ok(err.detail.length > 0)
        return true
      },
      `${JSON.stringify(name)} (${why}) must be refused`
    )
  }
})

test('each refusal rule fires on its own, and says which rule it was', () => {
  // The rules overlap on purpose, and that hid them from the tests. A NUL
  // is a control character too, `.` and `..` strip to empty, and an empty
  // name resolves to the output directory itself, which the containment
  // check in safeOutputName refuses. So the test above, which asserts only
  // ERR_UNSAFE_NAME, passed with any one of these rules deleted: the first
  // full mutation run (W12) removed each of them in turn and nothing failed.
  // Pinning `detail` is what makes each rule's absence visible.
  const dir = path.join(os.tmpdir(), 'adhal-hostile-names')
  const rules = [
    ['', 'it is empty'],
    ['\u0000abc', 'it contains a NUL byte'],
    ['.', 'it is a directory reference'],
    ['..', 'it is a directory reference'],
    ['...', 'it is empty once trailing dots and spaces are removed'],
    ['   ', 'it is empty once trailing dots and spaces are removed'],
    ['. .', 'it is empty once trailing dots and spaces are removed'],
    ['x'.repeat(MAX_NAME_BYTES + 1), `it is longer than ${MAX_NAME_BYTES} bytes`]
  ]
  for (const [name, detail] of rules) {
    // Both entry points: safeWriteName is the rule, and safeOutputName is
    // what a receive calls. Through safeOutputName, the containment check
    // would catch '...' had the rule let it through, with a detail that
    // names the wrong reason.
    assert.throws(() => safeWriteName(name), { code: 'ERR_UNSAFE_NAME', detail }, JSON.stringify(name))
    assert.throws(() => safeOutputName(dir, name), { code: 'ERR_UNSAFE_NAME', detail }, JSON.stringify(name))
  }

  // From the wire a name that is not a string never gets here:
  // validateManifest refuses it first. But safeWriteName is exported, and
  // it promises ERR_UNSAFE_NAME for anything it will not write, not a
  // TypeError from reading .length of undefined.
  for (const value of [undefined, null, 42, {}, ['a']]) {
    assert.throws(() => safeWriteName(/** @type {any} */ (value)), { code: 'ERR_UNSAFE_NAME', detail: 'it is not a string' })
  }
})

test('the shortest and longest legitimate names are accepted', () => {
  // Every refusal above fails closed, so a rule drawn one off refuses an
  // honest file rather than letting a hostile one in: a one-letter name,
  // or one of exactly 255 bytes, the filesystem's limit, would be declined.
  const dir = path.join(os.tmpdir(), 'adhal-hostile-names')
  assert.equal(safeWriteName('a'), 'a')
  assert.equal(safeOutputName(dir, 'a').name, 'a')
  assert.equal(safeWriteName('a.'), 'a', 'one character left once the trailing dot goes')
  assert.equal(safeWriteName('x'.repeat(MAX_NAME_BYTES)), 'x'.repeat(MAX_NAME_BYTES))

  // The limit is on bytes, not characters: 'é' is two bytes in UTF-8.
  const atLimit = 'é'.repeat(127) + 'x'
  assert.equal(Buffer.byteLength(atLimit, 'utf8'), MAX_NAME_BYTES)
  assert.equal(safeWriteName(atLimit), atLimit)
  assert.throws(() => safeWriteName('é'.repeat(128)), { code: 'ERR_UNSAFE_NAME', detail: `it is longer than ${MAX_NAME_BYTES} bytes` })
})

test('characters that are illegal or dangerous in a filename are transformed, not refused', () => {
  // Transformed rather than refused because a correct sender could
  // plausibly have meant them -- `report:2026` is a real filename on
  // Linux -- and killing a whole transfer over one punctuation mark is
  // hostile. `foo:stream` is the one that matters: on NTFS that is an
  // alternate data stream, not a file called `foo:stream`.
  const dir = path.join(os.tmpdir(), 'adhal-hostile-names')
  assert.equal(safeOutputName(dir, 'foo:stream').name, 'foo_stream')
  assert.equal(safeOutputName(dir, 'a<b>c|d?e*f"g').name, 'a_b_c_d_e_f_g')

  // Trailing dots and spaces are invisible in every file manager, so
  // `a.exe. ` and `a.exe` look like one name to the person deciding
  // whether to trust the file.
  assert.equal(safeOutputName(dir, 'a.exe. ').name, 'a.exe')
  assert.equal(safeOutputName(dir, 'report.pdf   ').name, 'report.pdf')

  // And the ordinary case is left completely alone.
  assert.equal(safeOutputName(dir, 'holiday photo.jpeg').name, 'holiday photo.jpeg')
  assert.equal(safeOutputName(dir, '.bashrc').name, '.bashrc')
})

test('displayName escapes rather than strips, and never throws', () => {
  // Escaping over stripping is the one judgment call in names.js.
  // Stripping produces a clean-looking string and destroys the evidence:
  // `evil\nverified: ok` would print as `evilverified: ok`, which looks
  // fine and tells the reader nothing.
  assert.equal(displayName('evil\nverified: ok'), 'evil\\nverified: ok')
  assert.equal(displayName('a\u001b[2Jb'), 'a\\u001b[2Jb')
  assert.equal(displayName('inv\u202efdp.exe'), 'inv\\u202efdp.exe')

  // JSON.stringify is the thing people reach for instead, and it is not
  // enough: it passes bidi overrides straight through.
  assert.ok(JSON.stringify('inv\u202efdp.exe').includes('\u202e'), 'JSON.stringify leaves the override in')
  assert.ok(!displayName('inv\u202efdp.exe').includes('\u202e'), 'displayName does not')

  // The escape names the byte that was there. A NUL is the case that
  // matters: a refusal for one prints the name, and must show \u0000,
  // not a neighbor.
  assert.equal(displayName('\u0000abc'), '\\u0000abc')

  // Cut only past the bound: a name exactly MAX_DISPLAY_LENGTH long is
  // shown whole, with no claim that anything was cut.
  assert.equal(displayName('x'.repeat(MAX_DISPLAY_LENGTH)), 'x'.repeat(MAX_DISPLAY_LENGTH))
  assert.equal(displayName('x'.repeat(MAX_DISPLAY_LENGTH + 1)), `${'x'.repeat(MAX_DISPLAY_LENGTH)}... (${MAX_DISPLAY_LENGTH + 1} chars)`)

  // Total, because the moment we most need to print a name is when we
  // are refusing it, and a display path that throws turns one error into
  // two.
  for (const weird of [null, undefined, 42, {}, [], 'x'.repeat(5000)]) {
    assert.equal(typeof displayName(/** @type {any} */ (weird)), 'string')
  }
})

// --- the filesystem -------------------------------------------------------

test('an existing file is never replaced; the drop lands beside it', async (t) => {
  const outputDir = await tmpDir(t, 'harden-overwrite')
  const target = path.join(outputDir, '.zshrc')
  await fs.promises.writeFile(target, 'PRECIOUS')

  // WHAT THIS PREVENTS. The output directory defaults to process.cwd(),
  // and `fs.rename` overwrites -- so any code-holder could replace the
  // `.zshrc`, `package.json`, or `id_rsa` in whatever directory the
  // receiver happened to be launched from. That was written down as a
  // deliberate deferral ("overwrite/suffix/prompt is an accept-screen
  // question"), which treated destroying a file as one acceptable
  // presentation among several.
  const body = Buffer.from('attacker payload')
  const result = await offer(outputDir, manifestFor(body, { name: '.zshrc' }), body).received

  assert.equal(await fs.promises.readFile(target, 'utf8'), 'PRECIOUS', 'the original must survive untouched')
  assert.equal(result.name, '.zshrc (1)')
  assert.equal(result.declaredName, '.zshrc')
  assert.deepEqual(await fs.promises.readFile(result.path), body)
})

test('replace: true is still available for callers that mean it', async (t) => {
  const outputDir = await tmpDir(t, 'harden-replace')
  const target = path.join(outputDir, 'x.bin')
  await fs.promises.writeFile(target, 'OLD')

  const body = Buffer.from('NEW')
  const result = await offer(outputDir, manifestFor(body, { name: 'x.bin' }), body, { replace: true }).received

  assert.equal(result.path, target, 'no suffix when replacing was asked for')
  assert.equal(await fs.promises.readFile(target, 'utf8'), 'NEW')
})

test('a pre-planted .part symlink cannot redirect the write out of the directory', async (t) => {
  const root = await tmpDir(t, 'harden-symlink')
  const outputDir = path.join(root, 'downloads')
  await fs.promises.mkdir(outputDir)
  const outside = path.join(root, 'secret.txt')
  await fs.promises.writeFile(outside, 'ORIGINAL')

  // The `.part` name is predictable by design -- resume has to find it
  // again -- which is exactly what makes it plantable. Anything that can
  // write into the output directory ahead of time (a shared downloads
  // folder, a previous drop, another user) can leave a symlink there.
  // Without O_EXCL, createWriteStream follows it and the "transfer" is a
  // write to wherever it points.
  await fs.promises.symlink(outside, path.join(outputDir, 'loot.bin.part'))

  const body = Buffer.from('redirected payload')
  const result = await offer(outputDir, manifestFor(body, { name: 'loot.bin' }), body).received

  assert.equal(await fs.promises.readFile(outside, 'utf8'), 'ORIGINAL', 'the symlink target must be untouched')
  assert.equal(path.dirname(result.path), outputDir)
  assert.deepEqual(await fs.promises.readFile(result.path), body)
})

// --- sizes ----------------------------------------------------------------

test('an absurd declared size is refused by default, without the caller naming a limit', async (t) => {
  const outputDir = await tmpDir(t, 'harden-size')

  // Verified against the shipping code before the fix: with no maxSize
  // passed, `validateManifest` accepted Number.MAX_SAFE_INTEGER -- about
  // 9 PB -- and the receiver went on to open a file for it. Both CLIs
  // passed no maxSize.
  const body = Buffer.from('x')
  for (const size of [Number.MAX_SAFE_INTEGER, 10 ** 13, DEFAULT_MAX_SIZE + 1]) {
    const { received } = offer(outputDir, manifestFor(body, { size }))
    await rejectsWith(received, 'ERR_MANIFEST_INVALID', (err) => assert.equal(err.field, 'size'))
  }

  assert.deepEqual(await fs.promises.readdir(outputDir), [], 'a refused manifest must not create anything')
})

test('opting out of the size cap is possible but has to be written down', async (t) => {
  const outputDir = await tmpDir(t, 'harden-size-optout')
  const body = Buffer.from('x')

  // `null` disables the cap. The free-space check is then the only thing
  // standing between the receiver and the declared number -- which is
  // the next test, and why the opt-out is explicit rather than the
  // default it used to be.
  let sawManifest = null
  const { received } = offer(outputDir, manifestFor(body, { size: DEFAULT_MAX_SIZE + 1 }), null, {
    maxSize: null,
    // Both off, so this test is about validation and nothing else: the
    // size is larger than any disk, and no bytes ever follow.
    checkSpace: false,
    progressTimeout: 150,
    onManifest: (m) => { sawManifest = m }
  })

  // Getting as far as a stall is the assertion: a manifest that was
  // going to be refused never reaches onManifest, never opens a file, and
  // never arms the progress timer.
  await rejectsWith(received, 'ERR_STALLED')
  assert.ok(sawManifest, 'the oversize manifest must be accepted once the cap is explicitly disabled')
  assert.equal(sawManifest.size, DEFAULT_MAX_SIZE + 1)
})

test('a transfer larger than the free disk is refused before anything is opened', async (t) => {
  const outputDir = await tmpDir(t, 'harden-space')
  const body = Buffer.from('x')

  // Refused up front rather than as an ENOSPC partway through, which
  // matters because the sender has otherwise already spent the upload.
  const { received } = offer(outputDir, manifestFor(body, { size: Number.MAX_SAFE_INTEGER }), null, {
    maxSize: null
  })
  await rejectsWith(received, 'ERR_NO_SPACE', (err) => {
    assert.equal(typeof err.free, 'number')
    assert.ok(err.free >= 0)
  })

  assert.deepEqual(await fs.promises.readdir(outputDir), [], 'nothing, not even a .part')
})

// --- peers that go quiet --------------------------------------------------

test('a peer that proves the code and then sends no manifest is timed out', async (t) => {
  const outputDir = await tmpDir(t, 'harden-loris-manifest')
  const { peer, socket, keys } = sealedSender()

  // The slow loris. Costs the attacker one proven connection and holds
  // the receiver open indefinitely: before this there was no timer at
  // all once acceptOnce handed the socket over, so the receiver simply
  // sat there forever.
  const received = receiveFile(socket, outputDir, { ...keys, manifestTimeout: 150 })
  await rejectsWith(received, 'ERR_STALLED', (err) => {
    assert.match(err.message, /never sent a manifest/)
  })
  assert.ok(peer.writable)
  assert.deepEqual(await fs.promises.readdir(outputDir), [])
})

test('a peer that sends a manifest and then stops mid-file is timed out', async (t) => {
  const outputDir = await tmpDir(t, 'harden-loris-body')
  const body = crypto.randomBytes(4096)

  // Manifest promises 4096 bytes; one chunk of 10 arrives, then silence.
  const { received } = offer(outputDir, manifestFor(body), body.subarray(0, 10), { progressTimeout: 150 })
  await rejectsWith(received, 'ERR_STALLED', (err) => {
    assert.match(err.message, /stopped sending|sent nothing further/)
    assert.equal(err.bytes, 10)
  })

  // ERR_STALLED and not ERR_CONNECTION: the socket is perfectly healthy,
  // the peer is simply not talking. Those need different responses and
  // the log has to tell them apart.
  assert.deepEqual(await fs.promises.readdir(outputDir), [], 'the partial is discarded')
})

test('a healthy transfer is not killed by the stall timers', async (t) => {
  const outputDir = await tmpDir(t, 'harden-no-false-stall')
  const body = crypto.randomBytes(256 * 1024)
  const { socket, keys, send, offer: offerTo } = sealedSender()

  const received = receiveFile(socket, outputDir, { ...keys, manifestTimeout: 2000, progressTimeout: 200 })
  await offerTo(manifestFor(body))

  // Chunks spaced at 60ms against a 200ms budget: slow, but never
  // stalled. The timer must rearm on every chunk, or a merely slow link
  // is reported as an attack.
  const chunk = 32 * 1024
  for (let offset = 0; offset < body.length; offset += chunk) {
    await new Promise((r) => setTimeout(r, 60))
    send(TYPE_CHUNK, body.subarray(offset, offset + chunk))
  }

  const result = await received
  assert.equal(result.size, body.length)
  assertSameBytes(await fs.promises.readFile(result.path), body)
})

// --- backpressure ---------------------------------------------------------

test('a receiver slower than its sender pauses the socket instead of buffering without limit', async (t) => {
  const outputDir = await tmpDir(t, 'harden-backpressure')
  // Comfortably past the write stream's high-water mark, so the disk
  // genuinely falls behind rather than absorbing everything.
  const body = crypto.randomBytes(4 * 1024 * 1024)
  const { socket, keys, send, offer: offerTo } = sealedSender()

  let pauses = 0
  const realPause = socket.pause.bind(socket)
  socket.pause = function () { pauses++; return realPause() }

  const received = receiveFile(socket, outputDir, { ...keys })
  await offerTo(manifestFor(body))
  // Everything at once: the sender's whole file handed over as fast as
  // the stream will take it.
  const chunk = 64 * 1024
  for (let offset = 0; offset < body.length; offset += chunk) {
    send(TYPE_CHUNK, body.subarray(offset, offset + chunk))
  }

  const result = await received

  // THE ASSERTION. `writeStream.write()`'s return value was discarded, so
  // a sender on a fast link outran a slow disk, and the difference piled
  // up in memory, unbounded. The sender has honored this since the Hyperswarm work;
  // the receiver never did.
  assert.ok(pauses > 0, 'the receiver must pause the socket when its disk falls behind')

  // And correctness survives the pausing -- no lost or reordered chunks.
  assert.equal(result.size, body.length)
  assert.equal(result.sha256, crypto.createHash('sha256').update(body).digest('hex'))
  assertSameBytes(await fs.promises.readFile(result.path), body)
})

// --- peer bytes in error messages (Q-11) ----------------------------------
//
// Filenames were already printed through displayName. These are the paths
// that bypassed it: a peer that passed the PAKE could put raw ESC or a bidi
// override into the receiver's terminal through an error message rather
// than a name. Each case checks both layers -- the engine's message and the
// line report.js prints -- because either alone is one missed branch away
// from the bug coming back.

const ESC = '\u001b'
const RLO = '‮'

/** @param {string} text
 * @param what
 */
function assertPrintable (text, what) {
  assert.ok(!text.includes(ESC), `${what} contains a raw ESC: ${JSON.stringify(text)}`)
  assert.ok(!text.includes(RLO), `${what} contains a raw U+202E: ${JSON.stringify(text)}`)
}

test('a manifest that is not JSON is reported by length, not by echoing it', async (t) => {
  const outputDir = await tmpDir(t, 'q11-json')
  const { received } = offer(outputDir, Buffer.from(`${ESC}[2J${ESC}[Hverified: ok`, 'utf8'))
  const err = await rejectsWith(received, 'ERR_MANIFEST_INVALID')
  assertPrintable(err.message, 'the engine message')
  assert.match(err.message, /not valid JSON \(\d+ bytes\)/)
  assert.doesNotMatch(err.message, /verified/, 'none of the body is echoed')
  assertPrintable(describeError(err), 'the printed line')
})

test('a hostile manifest key or value is escaped in the message and in .field', async (t) => {
  const outputDir = await tmpDir(t, 'q11-field')

  // An unknown key is the peer's choice and becomes both part of the
  // message and err.field, which report.js prints.
  {
    const manifest = { ...manifestFor(Buffer.alloc(8)), [`x${RLO}${ESC}[2J`]: 1 }
    const err = await rejectsWith(offer(outputDir, manifest).received, 'ERR_MANIFEST_INVALID')
    assertPrintable(err.message, 'the message for a hostile key')
    assertPrintable(String(err.field), '.field for a hostile key')
    assert.match(err.message, /\\u202e/, 'escaped, not stripped: the reader can see something was there')
    assertPrintable(describeError(err), 'the printed line for a hostile key')
  }

  // A value quoted in the message. JSON.stringify escapes ESC but keeps
  // U+202E raw, which is the gap this closes.
  {
    const manifest = manifestFor(Buffer.alloc(8), { v: `2${RLO}` })
    const err = await rejectsWith(offer(outputDir, manifest).received, 'ERR_MANIFEST_INVALID')
    assertPrintable(err.message, 'the message for a hostile value')
    assertPrintable(describeError(err), 'the printed line for a hostile value')
  }
})

test('a peer reason cannot carry a bidi override, and no decoder echoes a malformed body', () => {
  for (const decoded of [
    decodeDecline(declineBody(`no${RLO}thanks`)).reason,
    decodeCancelReason(cancelBody(`stop${RLO}now`)),
    decodeDecline(Buffer.from(JSON.stringify({ reason: `raw${RLO}${ESC}[2J` }), 'utf8')).reason
  ]) {
    assertPrintable(decoded, 'a peer reason')
  }

  // Every JSON decoder reports a malformed body by its length.
  assert.throws(() => decodeResult(Buffer.from(`${ESC}[2J`, 'utf8')), (err) => {
    assertPrintable(/** @type {Error} */ (err).message, 'a RESULT parse error')
    return /not valid JSON \(4 bytes\)/.test(/** @type {Error} */ (err).message)
  })
})

test('a RESULT is exactly {ok, sha256} or {error}, and anything else is a protocol error', () => {
  // PROTOCOL.md section 7.6. The sender switches on `'error' in result`,
  // so a decoder that got `ok` wrong, or let a third shape through as a
  // receiver failure, would pass every transfer test; the W12 mutation run
  // showed both. Asserted here on the decoder itself, field by field.
  const sha256 = 'ab'.repeat(32)
  assert.deepEqual(decodeResult(resultBody({ ok: true, sha256 })), { ok: true, sha256 })
  assert.deepEqual(decodeResult(resultBody({ error: 'disk full' })), { ok: false, error: 'disk full' })
  assert.deepEqual(decodeResult(Buffer.from('{"ok":false,"error":"disk full"}')), { ok: false, error: 'disk full' })

  // Neither shape: no verdict at all, so never a receiver failure, and
  // never a TypeError from reading a field of null.
  for (const body of ['{}', 'null', '[]', '{"ok":true,"error":"x"}', '{"ok":true}']) {
    assert.throws(() => decodeResult(Buffer.from(body)), { code: 'ERR_PROTOCOL' }, body)
  }
})

test('END and PREFIX carry a sha256 string, and a body that is not JSON says so', () => {
  // `RegExp.test` coerces its argument, so a sha256 wrapped in an array
  // passes the hex check unless the type is checked first; a receiver
  // handed one compared it as a digest and failed outside the error
  // vocabulary (a RangeError from timingSafeEqual, for PREFIX).
  const hex = 'ab'.repeat(32)
  for (const [decode, label] of [[decodeEnd, 'END'], [decodePrefix, 'PREFIX']]) {
    for (const body of ['null', '[]', JSON.stringify({ sha256: [hex] }), JSON.stringify({ sha256: 42 })]) {
      assert.throws(() => /** @type {any} */ (decode)(Buffer.from(body)), { code: 'ERR_PROTOCOL' }, `${label} ${body}`)
    }
    assert.throws(() => /** @type {any} */ (decode)(Buffer.from('{')), { code: 'ERR_PROTOCOL', message: new RegExp(`${label} is not valid JSON \\(1 bytes\\)`) })
  }
  assert.throws(() => decodeCheckpoint(Buffer.from('{')), { code: 'ERR_PROTOCOL', message: /CHECKPOINT is not valid JSON \(1 bytes\)/ })
})

test('describeError escapes the whole line, whatever the error carried', () => {
  // The backstop: an error from anywhere, with peer bytes the engine did
  // not clean, still prints safely.
  const line = describeError({ code: 'ERR_PROTOCOL', message: `bad${ESC}[2J${RLO}frame` })
  assertPrintable(line, 'the printed line')
  assert.match(line, /\\u001b\[2J\\u202e/)
  assert.equal(displayText('a'.repeat(5000)).length < 5000, true, 'bounded, for a string that has somehow grown absurd')
  assert.equal(displayText('x'.repeat(600)), 'x'.repeat(600), 'but not at a filename\'s length: long diagnostics survive whole')
})

// --- the publish fallback is reported (Q-19) ------------------------------

test('a filesystem without hard links still lands the file, and says it used the weaker path', async (t) => {
  // FAT and some network mounts refuse link() with EPERM/ENOSYS/EXDEV. The
  // engine then falls back to check-then-rename, which is racy against a
  // local process creating the same name. The fallback is right to exist;
  // what it must not be is silent.
  const outputDir = await tmpDir(t, 'q19-nolink')
  const body = crypto.randomBytes(4096)

  const normal = await offer(outputDir, manifestFor(body, { name: 'a.bin' }), body).received
  assert.equal(normal.published, 'link', 'hard links are the default path')

  const realLink = fs.promises.link
  fs.promises.link = async () => { throw Object.assign(new Error('operation not permitted'), { code: 'EPERM' }) }
  t.after(() => { fs.promises.link = realLink })

  const fallback = await offer(outputDir, manifestFor(body, { name: 'b.bin' }), body).received
  assert.equal(fallback.published, 'check-then-rename')
  assertSameBytes(await fs.promises.readFile(path.join(outputDir, 'b.bin')), body)

  // And the no-overwrite rule still holds on that path for a file that is
  // already there: it lands beside it.
  const again = await offer(outputDir, manifestFor(body, { name: 'b.bin' }), body).received
  assert.equal(again.name, 'b (1).bin')
  assert.equal(again.published, 'check-then-rename')
})

// --- the receiver's edges, pinned -----------------------------------------
//
// Each of these holds one line of the receiver to exactly what it says,
// at the input where a near miss would behave differently.

/**
 * Settles with `promise`, or fails the test after `ms` rather than leaving
 * it to the runner's timeout: several of the failures pinned below are a
 * receive that never settles.
 * @template T
 * @param {number} ms @param {Promise<T>} promise @param {string} what
 * @returns {Promise<T>}
 */
function within (ms, promise, what) {
  /** @type {NodeJS.Timeout | undefined} */
  let timer
  const late = new Promise((resolve, reject) => { timer = setTimeout(() => reject(new Error(`timed out after ${ms}ms waiting for ${what}`)), ms) })
  return /** @type {Promise<T>} */ (Promise.race([promise, late])).finally(() => clearTimeout(timer))
}

/** @param {Promise<any>} promise @returns {Promise<any>} the rejection, or null if it resolved */
const rejection = (promise) => promise.then(() => null, (err) => err)

test('a manifest that is not a JSON object is refused as one, and the sender is told its offer was at fault', async (t) => {
  // `null`, an array, and a bare number or string all parse as JSON. Each
  // has to be refused at the root, as ERR_MANIFEST_INVALID: read as an
  // object, `null` throws a TypeError, which reaches the sender as
  // ERR_RECEIVER_FAILED -- the receiver blaming itself for a peer's
  // malformed offer -- and the others are reported as a wrong version.
  const outputDir = await tmpDir(t, 'harden-root')
  for (const body of ['null', '[]', '5', '"report.pdf"']) {
    const { received, answer } = offer(outputDir, Buffer.from(body, 'utf8'))
    await rejectsWith(received, 'ERR_MANIFEST_INVALID', (err) => assert.equal(err.field, '(root)', body))
    assert.equal((await answer).body.code, 'ERR_MANIFEST_INVALID', body)
  }
  assert.deepEqual(await fs.promises.readdir(outputDir), [])
})

test('a name that resolves outside the output directory is refused even if the shape checks let it through', () => {
  // The resolved-path assertion in safeOutputName backstops names.js, and
  // nothing a peer can send reaches it: every name that would escape is
  // refused by shape first. So it is tested the only way it can be, with
  // the shape checks replaced by one that waves everything through. The
  // replacement lives in the require cache for the length of this test,
  // and the real modules are put back however it ends.
  const engineSrc = path.dirname(require.resolve('@ad-hal/engine'))
  const namesPath = path.join(engineSrc, 'names.js')
  const transferPath = path.join(engineSrc, 'transfer.js')
  const realNames = require.cache[namesPath]
  const realTransfer = require.cache[transferPath]
  assert.ok(realNames && realTransfer, 'the engine modules are loaded from where this test expects them')
  const dir = path.resolve(os.tmpdir(), 'adhal-containment')
  try {
    require.cache[namesPath] = /** @type {any} */ ({ ...realNames, exports: { ...realNames.exports, safeWriteName: (/** @type {string} */ name) => name } })
    delete require.cache[transferPath]
    const { safeOutputName: lenient } = require(transferPath)
    for (const name of ['../escaped', '../../etc/passwd', path.resolve('/etc/passwd'), '..', '.', '']) {
      assert.throws(() => lenient(dir, name), { code: 'ERR_UNSAFE_NAME', detail: 'it resolves outside the output directory' }, JSON.stringify(name))
    }
    assert.equal(lenient(dir, 'ok.bin').outputPath, path.join(dir, 'ok.bin'), 'and a name that stays put is still taken')
  } finally {
    require.cache[namesPath] = realNames
    require.cache[transferPath] = realTransfer
  }
})

test('the thousandth suffix is still a place to land, and past it the drop is refused and nothing is left behind', async (t) => {
  // MAX_SUFFIX_ATTEMPTS is 1000 and the refusal says so, so `name (1000)`
  // has to be tried. Past it, the publish fails -- the one refusal that
  // comes after every byte has arrived -- and that failure must still
  // settle the receive, tell the sender, and delete the partial, rather
  // than wait on a stream that has already closed.
  const outputDir = await tmpDir(t, 'harden-suffixes')
  fs.writeFileSync(path.join(outputDir, 'a.bin'), '')
  for (let n = 1; n < 1000; n++) fs.writeFileSync(path.join(outputDir, `a (${n}).bin`), '')
  const body = crypto.randomBytes(1000)

  const landed = await within(5000, offer(outputDir, manifestFor(body, { name: 'a.bin', blockSize: 1000 }), body).received, 'the 1000th suffix')
  assert.equal(landed.name, 'a (1000).bin')
  assertSameBytes(await fs.promises.readFile(landed.path), body)

  // Every name is taken now, that one included.
  const { socket, keys, offer: offerTo, received: frames } = sealedSender()
  const refused = within(5000, rejection(receiveFile(socket, outputDir, { ...keys })), 'the refused publish to settle')
  await offerTo(manifestFor(body, { name: 'a.bin', blockSize: 1000 }), body)
  const err = await refused
  assert.equal(err && err.code, 'ERR_EXISTS', err && err.message)
  const results = frames.filter((f) => f.type === TYPE_RESULT).map((f) => decodeResult(f.body))
  assert.equal(results.length, 1)
  assert.equal(results[0].ok, false)
  assert.match(/** @type {any} */ (results[0]).error, /1000 suffixed names are all taken/)
  assert.deepEqual((await fs.promises.readdir(outputDir)).filter((f) => f.includes('.part')), [], 'the partial is discarded')
})

test('every way a filesystem says it has no hard links takes the weaker path, and any other link failure fails the receive', async (t) => {
  // The fallback is for a filesystem that cannot link at all, and each of
  // its four codes means exactly that. Any other failure of link() is a
  // real fault, and renaming the file into place anyway would publish
  // past it.
  const outputDir = await tmpDir(t, 'harden-link-codes')
  const body = crypto.randomBytes(1000)
  let code = ''
  t.mock.method(fs.promises, 'link', async () => { throw Object.assign(new Error(`link failed: ${code}`), { code }) })

  for (code of ['EPERM', 'ENOSYS', 'EXDEV', 'ENOTSUP']) {
    const result = await offer(outputDir, manifestFor(body, { name: `${code}.bin` }), body).received
    assert.equal(result.published, 'check-then-rename', code)
    assertSameBytes(await fs.promises.readFile(path.join(outputDir, `${code}.bin`)), body, code)
  }

  code = 'EIO'
  await rejectsWith(offer(outputDir, manifestFor(body, { name: 'EIO.bin' }), body).received, 'EIO')
  const left = (await fs.promises.readdir(outputDir)).filter((f) => f.startsWith('EIO'))
  assert.deepEqual(left, [], 'neither the file nor its partial')
})

test('the free-space check refuses only what cannot fit, and only when it can measure', async (t) => {
  // Advisory by design: a free count of 0 is a filesystem that cannot
  // say, not a full disk, so it refuses nothing. A file exactly the size
  // of the free space fits. And `checkSpace: false` turns the check off
  // whatever the disk reports.
  const outputDir = await tmpDir(t, 'harden-space-edges')
  const body = crypto.randomBytes(1000)
  let free = 0
  t.mock.method(fs.promises, 'statfs', async () => ({ bavail: free, bsize: 1 }))

  for (const [space, options, outcome] of /** @type {Array<[number, object, string]>} */ ([
    [0, {}, 'taken'],
    [body.length, {}, 'taken'],
    [body.length - 1, {}, 'ERR_NO_SPACE'],
    [1, { checkSpace: false }, 'taken']
  ])) {
    free = space
    const what = `${space} bytes free, ${JSON.stringify(options)}`
    const err = await rejection(offer(outputDir, manifestFor(body, { name: `free-${space}.bin` }), body, options).received)
    assert.equal(err ? err.code : 'taken', outcome, what)
  }
})

test('a peer that leaves before its offer is answered is reported as having sent no bytes', async (t) => {
  // `bytes` is how a log or a retry tells "nothing arrived" from "it died
  // partway", and before ACCEPT nothing can have arrived.
  const outputDir = await tmpDir(t, 'harden-early-bytes')
  {
    const { socket, keys, peer } = sealedSender()
    const received = receiveFile(socket, outputDir, { ...keys })
    peer.destroy()
    await rejectsWith(received, 'ERR_CONNECTION', (err) => assert.equal(err.bytes, 0, 'gone before a manifest'))
  }
  {
    const { socket, keys, send } = sealedSender()
    const received = receiveFile(socket, outputDir, { ...keys, onOffer: () => new Promise(() => {}) })
    send(TYPE_MANIFEST, Buffer.from(JSON.stringify(manifestFor(Buffer.alloc(16))), 'utf8'))
    await new Promise((resolve) => setTimeout(resolve, 20))
    send(TYPE_CANCEL, cancelBody('changed my mind'))
    await rejectsWith(received, 'ERR_CANCELLED_PEER', (err) => assert.equal(err.bytes, 0, 'canceled while the offer was considered'))
  }
})

test('a receive waiting on its peer never holds the process open by itself', async (t) => {
  // The stall timer and the checkpoint interval are unref'd: a caller that
  // abandons a pending receive, or a process that is otherwise done, exits
  // rather than waiting out a 30-second manifest timer. A timer that keeps
  // the event loop alive is listed by getActiveResourcesInfo, and an
  // unref'd one is not.
  const outputDir = await tmpDir(t, 'harden-unref')
  const timers = () => process.getActiveResourcesInfo().filter((r) => r === 'Timeout').length

  {
    const { socket, keys, peer } = sealedSender()
    const before = timers()
    const received = rejection(receiveFile(socket, outputDir, { ...keys, manifestTimeout: 10000 }))
    assert.equal(timers(), before, 'waiting for a manifest')
    peer.destroy()
    assert.equal((await received).code, 'ERR_CONNECTION')
  }
  {
    const { socket, keys, peer, offer: offerTo } = sealedSender()
    const before = timers()
    const received = rejection(receiveFile(socket, outputDir, { ...keys, caps: ['resume'], progressTimeout: 10000, checkpointInterval: 10000 }))
    await offerTo(manifestFor(Buffer.alloc(4096)))
    assert.equal(timers(), before, 'accepted and waiting for the first chunk, with checkpoints armed')
    peer.destroy()
    assert.equal((await received).code, 'ERR_CONNECTION')
  }
})

test('a receive that ends while its disk was pushing back leaves the socket flowing', async (t) => {
  // A 64 KiB chunk is past the write stream's high-water mark, so the last
  // one pauses the socket. Every byte is in by then, and the sender's end
  // has to be heard: a caller waiting for it would otherwise wait forever.
  const outputDir = await tmpDir(t, 'harden-paused-end')
  const body = crypto.randomBytes(256 * 1024)
  const { socket, keys, send, peer, offer: offerTo } = sealedSender()
  const received = receiveFile(socket, outputDir, { ...keys })
  await offerTo(manifestFor(body))
  for (let offset = 0; offset < body.length; offset += 64 * 1024) send(TYPE_CHUNK, body.subarray(offset, offset + 64 * 1024))
  await received

  assert.equal(socket.isPaused(), false)
  const ended = new Promise((resolve) => socket.once('end', resolve))
  peer.end()
  await within(1000, ended, "the sender's end")
})
