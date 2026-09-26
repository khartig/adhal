'use strict'

// The manifest is the one message that decides what happens on the
// receiver's filesystem, and until that work it was trusted completely:
// `path.join(outputDir, manifest.name)`, unvalidated, straight into
// createWriteStream.
//
// That is a narrower hole than it looks, and a worse one. The code proof stopped a
// *stranger* from reaching the receiver at all -- so the peer sending this
// manifest has proven it knows the drop code. What the code proof never addressed
// is that knowing the code does not make a peer well-behaved, and a peer
// that names its file `../../.bashrc` was, before these tests, writing
// there. "You accepted a drop" and "you granted arbitrary file write" are
// not the same consent.

const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('node:path')
const os = require('node:os')
const fs = require('node:fs')
const crypto = require('node:crypto')

const { receiveFile, safeOutputName, encodeFrame, TYPE_MANIFEST, TYPE_CHUNK, TYPE_DECLINE } = require('@quay/engine')
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

// Drives a real receiveFile with a hand-built manifest, so the assertions
// are about the shipping code path rather than about a validator called in
// isolation.
function offer (outputDir, manifest, body = null, options = {}) {
  const sender = sealedSender()
  const received = receiveFile(sender.socket, outputDir, { ...sender.keys, ...options })
  const answer = body ? sender.offer(manifest, body) : sender.offer(manifest)
  return { received, answer, peer: sender.peer }
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

// --- name safety ---------------------------------------------------------

test('a traversing filename is refused and nothing is written outside the output directory', async (t) => {
  const root = await tmpDir(t, 'manifest-traversal')
  const outputDir = path.join(root, 'downloads')
  await fs.promises.mkdir(outputDir)

  // The target sits one level above the output directory, inside the
  // temp root, so the test can assert on it without touching the real
  // home directory it stands in for.
  const escaped = path.join(root, 'pwned.bin')
  const body = Buffer.from('owned')

  const { received } = offer(outputDir, manifestFor(body, { name: '../pwned.bin' }), body)
  await rejectsWith(received, 'ERR_UNSAFE_NAME', (err) => {
    assert.equal(err.declaredName, '../pwned.bin')
  })

  // The assertion that actually matters. A rejection that still wrote the
  // file would pass a code check and fail the user.
  assert.equal(fs.existsSync(escaped), false, 'the file must not exist above the output directory')
  assert.deepEqual(await fs.promises.readdir(outputDir), [], 'and nothing partial may be left behind either')
})

test('every shape of unsafe name is refused, on both separators', () => {
  // Unit-level, because the point is which names are refused and the
  // matrix is long. Checked against '\\' as well as '/': path.basename
  // treats a backslash as a separator on Windows and as an ordinary
  // character on POSIX, so a single basename() call would silently mean
  // different things depending on where the receiver runs.
  const dir = path.join(os.tmpdir(), 'quay-names')
  const refused = [
    '../../pwned.bin',
    '..\\..\\pwned.bin',
    '/etc/passwd',
    'C:\\Windows\\system32\\drivers\\etc\\hosts',
    '..',
    '.',
    'a/b',
    'a\\b',
    '',
    'nul\u0000.txt',
    'x'.repeat(256)
  ]

  for (const name of refused) {
    assert.throws(
      () => safeOutputName(dir, name),
      (/** @type {any} */ err) => {
        assert.equal(err.code, 'ERR_UNSAFE_NAME', `${JSON.stringify(name)} should be ERR_UNSAFE_NAME`)
        assert.equal(err.declaredName, name)
        return true
      },
      `${JSON.stringify(name)} must be refused`
    )
  }
})

test('a leading dot is a legitimate filename and is left alone', () => {
  // `.bashrc` is dangerous as `../../.bashrc`, which is refused above. As
  // a name *inside* the output directory it is an ordinary file, and
  // mangling it would be the kind of helpfulness that makes a tool
  // untrustworthy.
  const dir = path.join(os.tmpdir(), 'quay-names')
  const safe = safeOutputName(dir, '.bashrc')
  assert.equal(safe.name, '.bashrc')
  assert.equal(safe.outputPath, path.join(dir, '.bashrc'))
})

test('a Windows device name is renamed on Windows and left alone everywhere else', async (t) => {
  const outputDir = await tmpDir(t, 'manifest-reserved')
  const body = Buffer.from('a file that is legitimately called aux.txt')

  // THE RENAME IS NOW GATED ON THE PLATFORM, and the justification in the
  // code changed with it. It used to be "Windows ships first"; macOS and
  // Linux are the primary targets now, and `_aux.txt` on Linux is pure
  // mangling of a name nothing on Linux objects to. It survives for
  // Windows because a file received there under that name cannot be
  // opened at all.
  const { received } = offer(outputDir, manifestFor(body, { name: 'aux.txt' }), body, { platform: 'win32' })
  const result = await received
  assert.equal(result.name, '_aux.txt')
  assert.equal(result.declaredName, 'aux.txt')
  assert.equal(path.basename(result.path), '_aux.txt')
  assert.deepEqual(await fs.promises.readFile(result.path), body)

  // Passed explicitly rather than read from process.platform, so all
  // three legs of the CI matrix assert both policies instead of each OS
  // only ever exercising its own branch.
  assert.equal(safeOutputName(outputDir, 'aux.txt', { platform: 'linux' }).name, 'aux.txt')
  assert.equal(safeOutputName(outputDir, 'aux.txt', { platform: 'darwin' }).name, 'aux.txt')
})

test('trailing dots and spaces cannot be used to smuggle a device name past the check', () => {
  // Windows strips trailing dots and spaces before resolving a path, so
  // `CON.` and `CON ` are the device `CON`. Checking the raw string would
  // make the rename trivially evadable.
  //
  // Stage 0 strips them outright, on every platform, before the device
  // check even runs -- a trailing dot or space is invisible in every file
  // manager ever written, so it exists only to make two different names
  // look like one. That makes the evasion impossible rather than merely
  // detected, and `CON.` now normalises to `CON` before being renamed.
  const dir = path.join(os.tmpdir(), 'quay-names')
  const win = { platform: 'win32' }
  assert.equal(safeOutputName(dir, 'CON.', win).name, '_CON')
  assert.equal(safeOutputName(dir, 'com1  ', win).name, '_com1')
  assert.equal(safeOutputName(dir, 'LPT9.txt', win).name, '_LPT9.txt')

  // The stripping itself is not Windows-only.
  assert.equal(safeOutputName(dir, 'report.pdf. ', { platform: 'linux' }).name, 'report.pdf')

  // And a name that merely starts with those letters is ordinary.
  assert.equal(safeOutputName(dir, 'console.log', win).name, 'console.log')
  assert.equal(safeOutputName(dir, 'nullable.json', win).name, 'nullable.json')
})

// --- field validation ----------------------------------------------------

test('a manifest field that fails validation is refused before any filesystem call', async (t) => {
  const outputDir = await tmpDir(t, 'manifest-fields')
  const body = Buffer.from('content')

  const cases = [
    ['sha256', { sha256: 'not-a-digest' }],
    ['sha256', { sha256: 'A'.repeat(64) }], // uppercase: one canonical form only
    ['size', { size: -1 }],
    ['size', { size: 1.5 }],
    ['size', { size: Number.MAX_SAFE_INTEGER + 2 }],
    ['size', { size: '100' }],
    // Absent is not null: a manifest that omits `size` is malformed, not a
    // stream. JSON.stringify drops an undefined field entirely.
    ['size', { size: undefined }],
    ['v', { v: 1 }],
    ['v', { v: 3 }],
    ['v', { v: undefined }],
    ['blockSize', { blockSize: 0 }],
    ['blockSize', { blockSize: 64 * 1024 * 1024 }],
    ['blockSize', { blockSize: undefined }],
    ['name', { name: 42 }],
    // One of the two nulls without the other. Section 4.3 defines both and
    // neither; a declared length with no digest has nothing to check it.
    ['sha256', { sha256: null }],
    ['sha256', { size: null }],
    // The closed field set. `type` and `chunkSize` are v1's, and `mode`
    // and `caps` are the two fields the v2 draft listed and never defined
    // -- each is refused by name rather than silently ignored.
    ['type', { type: 'manifest' }],
    ['chunkSize', { chunkSize: 64 * 1024 }],
    ['mode', { mode: 0o644 }],
    ['caps', { caps: ['stream'] }],
    ['__proto__', JSON.parse('{"__proto__": {"polluted": true}}')]
  ]

  for (const [field, override] of cases) {
    const { received, answer } = offer(outputDir, manifestFor(body, override))
    await rejectsWith(received, 'ERR_MANIFEST_INVALID', (err) => {
      assert.equal(err.field, field, `${JSON.stringify(override)} should blame ${field}`)
    })
    // The refusal reaches the sender as a reason, not as a hang-up.
    const reply = await answer
    assert.equal(reply.type, TYPE_DECLINE, `${JSON.stringify(override)} should be declined, not dropped`)
    assert.match(reply.body.reason, new RegExp(`manifest field ${field} is invalid`))
  }

  assert.deepEqual(await fs.promises.readdir(outputDir), [], 'a refused manifest must not create anything')
})

test('a v1 manifest is refused on its version, not on its unfamiliar fields', async (t) => {
  // Exactly what the previous build's sendFile wrote. A v1 sender cannot
  // reach this in practice -- the handshake's version byte names the skew
  // first -- but the manifest is where a second implementation that got
  // the handshake right and the manifest wrong would land, and "version 1"
  // is the sentence that points at the fix.
  const outputDir = await tmpDir(t, 'manifest-v1')
  const body = Buffer.from('content')
  const v1 = {
    v: 1,
    type: 'manifest',
    name: 'ok.bin',
    size: body.length,
    chunkSize: 64 * 1024,
    sha256: crypto.createHash('sha256').update(body).digest('hex')
  }
  const { received } = offer(outputDir, v1)
  await rejectsWith(received, 'ERR_MANIFEST_INVALID', (err) => {
    assert.equal(err.field, 'v')
    assert.match(err.message, /unsupported manifest version 1 \(this build speaks v2\)/)
  })
})

test('a manifest that is not JSON at all is refused as a manifest problem, not a crash', async (t) => {
  const outputDir = await tmpDir(t, 'manifest-json')
  const { socket, keys, send } = sealedSender()
  const received = receiveFile(socket, outputDir, { ...keys })
  send(TYPE_MANIFEST, Buffer.from('{ not json', 'utf8'))
  await rejectsWith(received, 'ERR_MANIFEST_INVALID')
})

test('a chunk before the manifest is a protocol error', async (t) => {
  const outputDir = await tmpDir(t, 'manifest-order')
  const { socket, keys, send } = sealedSender()
  const received = receiveFile(socket, outputDir, { ...keys })
  send(TYPE_CHUNK, Buffer.from('bytes with nowhere to go'))
  await rejectsWith(received, 'ERR_PROTOCOL', (err) => {
    assert.match(err.message, /MANIFEST frame first/)
  })
})

test('the optional maxSize is enforced when given and absent by default', async (t) => {
  const outputDir = await tmpDir(t, 'manifest-maxsize')
  const body = crypto.randomBytes(4096)
  const manifest = manifestFor(body)

  const { socket: socketA, keys: keysA, send: sendA } = sealedSender()
  const capped = receiveFile(socketA, outputDir, { ...keysA, maxSize: 1024 })
  sendA(TYPE_MANIFEST, Buffer.from(JSON.stringify(manifest), 'utf8'))
  await rejectsWith(capped, 'ERR_MANIFEST_INVALID', (err) => assert.equal(err.field, 'size'))

  // The 50 MB v1 cap is product policy for the accept screen, not
  // something the engine should decide on its own.
  const { received } = offer(outputDir, manifest, body)
  assert.equal((await received).size, body.length)
})

// --- version skew --------------------------------------------------------

test('a cleartext frame -- v1\'s, or a pre-item-5 build\'s -- never reaches the manifest parser', async (t) => {
  // THIS TEST USED TO ASSERT THE "REDEPLOY" DIAGNOSIS, and the diagnosis
  // moved rather than disappeared. Under v2 every frame is sealed, so an
  // old build's cleartext frame fails to authenticate before its type byte
  // is ever read -- and in practice an old build never gets this far at
  // all, because the handshake's version byte names the skew first (see
  // "a wire-version skew is named" in pake-handshake.test.js). What is
  // left to pin here is the part that matters for safety: bare JSON on the
  // wire is not a manifest, whatever it says.
  const outputDir = await tmpDir(t, 'manifest-skew')
  const { peer, socket, keys } = sealedSender()
  const received = receiveFile(socket, outputDir, { ...keys })

  // Exactly what an older sender put on the wire: a length-prefixed frame
  // whose payload is bare manifest JSON, with no type tag and no seal.
  const legacy = Buffer.from(JSON.stringify({
    type: 'manifest', name: 'source.bin', size: 5, chunkSize: 65536, sha256: 'a'.repeat(64)
  }), 'utf8')
  peer.write(encodeFrame(legacy))

  await rejectsWith(received, 'ERR_PROTOCOL', (err) => {
    assert.match(err.message, /failed to authenticate/)
  })
  assert.deepEqual(await fs.promises.readdir(outputDir), [], 'an unauthenticated manifest must not create anything')
})
