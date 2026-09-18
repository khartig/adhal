'use strict'

// The manifest is the one message that decides what happens on the
// receiver's filesystem, and until item 5 it was trusted completely:
// `path.join(outputDir, manifest.name)`, unvalidated, straight into
// createWriteStream.
//
// That is a narrower hole than it looks, and a worse one. Item 4 stopped a
// *stranger* from reaching the receiver at all -- so the peer sending this
// manifest has proven it knows the drop code. What item 4 never addressed
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

const { receiveFile, safeOutputName, encodeMessage, encodeFrame, TYPE_MANIFEST, TYPE_CHUNK } = require('@quay/engine')
const { duplexPair } = require('../test-helpers/duplex-pair')

async function tmpDir (t, label) {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), `quay-${label}-`))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  return dir
}

function manifestFor (body, overrides = {}) {
  return {
    v: 1,
    type: 'manifest',
    name: 'ok.bin',
    size: body.length,
    chunkSize: 64 * 1024,
    sha256: crypto.createHash('sha256').update(body).digest('hex'),
    ...overrides
  }
}

// Drives a real receiveFile with a hand-built manifest, so the assertions
// are about the shipping code path rather than about a validator called in
// isolation.
function offer (outputDir, manifest, body = null) {
  const [peer, socket] = duplexPair()
  const received = receiveFile(socket, outputDir)
  peer.write(encodeMessage(TYPE_MANIFEST, Buffer.from(JSON.stringify(manifest), 'utf8')))
  if (body) peer.write(encodeMessage(TYPE_CHUNK, body))
  return { received, peer }
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

test('a Windows device name is renamed rather than refused, and both names are reported', async (t) => {
  const outputDir = await tmpDir(t, 'manifest-reserved')
  const body = Buffer.from('a file that is legitimately called aux.txt')

  const { received } = offer(outputDir, manifestFor(body, { name: 'aux.txt' }), body)
  const result = await received

  // Windows ships first, and refusing a file because of its name when one
  // prefix character makes it work would be hostile. Nothing is hidden:
  // the caller is told what was asked for and what was written.
  assert.equal(result.name, '_aux.txt')
  assert.equal(result.declaredName, 'aux.txt')
  assert.equal(path.basename(result.path), '_aux.txt')
  assert.deepEqual(await fs.promises.readFile(result.path), body)
})

test('trailing dots and spaces cannot be used to smuggle a device name past the check', () => {
  // Windows strips trailing dots and spaces before resolving a path, so
  // `CON.` and `CON ` are the device `CON`. Checking the raw string would
  // make the rename trivially evadable.
  const dir = path.join(os.tmpdir(), 'quay-names')
  assert.equal(safeOutputName(dir, 'CON.').name, '_CON.')
  assert.equal(safeOutputName(dir, 'com1  ').name, '_com1  ')
  assert.equal(safeOutputName(dir, 'LPT9.txt').name, '_LPT9.txt')

  // And a name that merely starts with those letters is ordinary.
  assert.equal(safeOutputName(dir, 'console.log').name, 'console.log')
  assert.equal(safeOutputName(dir, 'nullable.json').name, 'nullable.json')
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
    ['v', { v: 2 }],
    ['v', { v: undefined }],
    ['chunkSize', { chunkSize: 0 }],
    ['chunkSize', { chunkSize: 64 * 1024 * 1024 }],
    ['name', { name: 42 }],
    ['type', { type: 'something-else' }]
  ]

  for (const [field, override] of cases) {
    const { received } = offer(outputDir, manifestFor(body, override))
    await rejectsWith(received, 'ERR_MANIFEST_INVALID', (err) => {
      assert.equal(err.field, field, `${JSON.stringify(override)} should blame ${field}`)
    })
  }

  assert.deepEqual(await fs.promises.readdir(outputDir), [], 'a refused manifest must not create anything')
})

test('a manifest that is not JSON at all is refused as a manifest problem, not a crash', async (t) => {
  const outputDir = await tmpDir(t, 'manifest-json')
  const [peer, socket] = duplexPair()
  const received = receiveFile(socket, outputDir)
  peer.write(encodeMessage(TYPE_MANIFEST, Buffer.from('{ not json', 'utf8')))
  await rejectsWith(received, 'ERR_MANIFEST_INVALID')
})

test('a chunk before the manifest is a protocol error', async (t) => {
  const outputDir = await tmpDir(t, 'manifest-order')
  const [peer, socket] = duplexPair()
  const received = receiveFile(socket, outputDir)
  peer.write(encodeMessage(TYPE_CHUNK, Buffer.from('bytes with nowhere to go')))
  await rejectsWith(received, 'ERR_PROTOCOL', (err) => {
    assert.match(err.message, /MANIFEST frame first/)
  })
})

test('the optional maxSize is enforced when given and absent by default', async (t) => {
  const outputDir = await tmpDir(t, 'manifest-maxsize')
  const body = crypto.randomBytes(4096)
  const manifest = manifestFor(body)

  const [peerA, socketA] = duplexPair()
  const capped = receiveFile(socketA, outputDir, { maxSize: 1024 })
  peerA.write(encodeMessage(TYPE_MANIFEST, Buffer.from(JSON.stringify(manifest), 'utf8')))
  await rejectsWith(capped, 'ERR_MANIFEST_INVALID', (err) => assert.equal(err.field, 'size'))

  // The 50 MB v1 cap is product policy for the accept screen, not
  // something the engine should decide on its own.
  const { received } = offer(outputDir, manifest, body)
  assert.equal((await received).size, body.length)
})

// --- version skew --------------------------------------------------------

test('an untagged manifest from a pre-item-5 build says to redeploy, not that the file is corrupt', async (t) => {
  const outputDir = await tmpDir(t, 'manifest-skew')
  const [peer, socket] = duplexPair()
  const received = receiveFile(socket, outputDir)

  // Exactly what an older sender put on the wire: a length-prefixed frame
  // whose payload is bare manifest JSON, with no type tag in front of it.
  const legacy = Buffer.from(JSON.stringify({
    type: 'manifest', name: 'source.bin', size: 5, chunkSize: 65536, sha256: 'a'.repeat(64)
  }), 'utf8')
  peer.write(encodeFrame(legacy))

  await rejectsWith(received, 'ERR_PROTOCOL', (err) => {
    // The distinction worth paying for: "your two machines are on
    // different builds" sends someone to `git pull`, where "unknown type
    // 0x7b" sends them hunting a corruption bug that does not exist.
    assert.match(err.message, /pre-item-5 build/)
    assert.match(err.message, /[Rr]edeploy both sides/)
  })
})
