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
  displayName,
  TYPE_CHUNK,
  DEFAULT_MAX_SIZE
} = require('@quay/engine')
const { sealedSender } = require('../test-helpers/sealed')

async function tmpDir (t, label) {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), `quay-${label}-`))
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

/** @param {any} promise */
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
  // not inferred: newline, ESC, BEL and the RLO override each landed on
  // disk and in the log exactly as the peer wrote them.
  const dir = path.join(os.tmpdir(), 'quay-hostile-names')
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

test('characters that are illegal or dangerous in a filename are transformed, not refused', () => {
  // Transformed rather than refused because a correct sender could
  // plausibly have meant them -- `report:2026` is a real filename on
  // Linux -- and killing a whole transfer over one punctuation mark is
  // hostile. `foo:stream` is the one that matters: on NTFS that is an
  // alternate data stream, not a file called `foo:stream`.
  const dir = path.join(os.tmpdir(), 'quay-hostile-names')
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
  // Escaping over stripping is the one judgement call in names.js.
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
  // `.zshrc`, `package.json` or `id_rsa` in whatever directory the
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
  // going to be refused never reaches onManifest, never opens a file and
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
  assert.deepEqual(await fs.promises.readFile(result.path), body)
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
  // a sender on a fast link outran a slow disk and the difference piled
  // up in memory, unbounded. The sender has honoured this since the Hyperswarm work;
  // the receiver never did.
  assert.ok(pauses > 0, 'the receiver must pause the socket when its disk falls behind')

  // And correctness survives the pausing -- no lost or reordered chunks.
  assert.equal(result.size, body.length)
  assert.equal(result.sha256, crypto.createHash('sha256').update(body).digest('hex'))
  assert.deepEqual(await fs.promises.readFile(result.path), body)
})
