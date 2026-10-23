'use strict'

// Every kind of check the harness makes, shown able to fail.
//
// A conformance harness that passes this repository's engine has shown
// only that the two agree. That the agreement means something is shown
// here: a bug is planted in a copy of the engine (tools/sandbox.js; never
// the working tree), the harness is pointed at the copy's adapter, and the
// scenarios that should catch the bug must fail. One plant per kind of
// check: the nonce, the associated data in each direction, the
// confirmations, the caps encoding, the manifest, chunk bounds on each
// side, resume's boundary and prefix digest, RESULT's digest, and a
// CANCEL that never goes out.
//
// Several of these are bugs the engine's own suite cannot see, because the
// engine would be wrong in the same way on both ends. The caps one is the
// clearest: engine/src/handshake.js checks a peer's caps by re-encoding
// them, so an engine that sorted backwards would accept its own backwards
// encoding forever, and every in-process test would pass.

const test = require('node:test')
const assert = require('node:assert/strict')

const { makeSandbox } = require('../../tools/sandbox')
const { runScenarios } = require('../src/harness')
const { scenarios } = require('../src/scenarios')

const slow = process.env.ADHAL_FAST === '1'
  ? { skip: 'slow tier: spawns adapter processes (unset ADHAL_FAST to run it)' }
  : {}

const PLANTS = [
  {
    what: 'the nonce counter starts at 1',
    file: 'engine/src/channel.js',
    find: '    this._counter = 0n\n',
    replace: '    this._counter = 1n\n',
    caught: ['R-transfer', 'S-transfer']
  },
  {
    what: 'frames are sealed without the length as associated data',
    file: 'engine/src/channel.js',
    find: '    cipher.setAAD(header)\n',
    replace: '    void header\n',
    caught: ['S-transfer']
  },
  {
    what: 'frames are opened without the length as associated data',
    file: 'engine/src/channel.js',
    find: '    decipher.setAAD(lengthHeader(sealed.length))\n',
    replace: '',
    caught: ['R-neg-no-aad']
  },
  {
    what: 'confirmS is computed under the confirm-r label',
    file: 'engine/src/handshake.js',
    find: 'const confirmS = hmac(macKey, CONFIRM_S_LABEL, transcript)',
    replace: 'const confirmS = hmac(macKey, CONFIRM_R_LABEL, transcript)',
    caught: ['R-handshake', 'S-handshake']
  },
  {
    what: 'capabilities are sorted descending, and checked against the same wrong order',
    file: 'engine/src/handshake.js',
    find: "Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'))",
    replace: "Buffer.compare(Buffer.from(b, 'utf8'), Buffer.from(a, 'utf8'))",
    caught: ['R-handshake', 'S-handshake']
  },
  {
    what: 'the manifest declares half the chunk size the sender uses',
    file: 'engine/src/transfer.js',
    find: '    blockSize: chunkSize\n',
    replace: '    blockSize: Math.max(1, chunkSize / 2)\n',
    caught: ['S-transfer']
  },
  {
    what: 'the receiver does not hold a CHUNK to the declared blockSize',
    file: 'engine/src/transfer.js',
    find: '      if (body.length > manifest.blockSize) {\n',
    replace: '      if (false) {\n',
    caught: ['R-neg-chunk-over-block']
  },
  {
    what: 'the receiver proposes its partial\'s exact length rather than a boundary',
    file: 'engine/src/transfer.js',
    find: 'const length = stat.size === size ? size : stat.size - (stat.size % PREFIX_BOUNDARY)',
    replace: 'const length = stat.size',
    caught: ['R-resume']
  },
  {
    what: 'PREFIX carries the digest of the next boundary up',
    file: 'engine/src/transfer.js',
    find: 'prefixes[n / PREFIX_BOUNDARY - 1]',
    replace: '(prefixes[n / PREFIX_BOUNDARY] || prefixes[0])',
    caught: ['S-resume']
  },
  {
    what: 'RESULT carries a digest other than the one computed',
    file: 'engine/src/transfer.js',
    find: 'resultBody({ ok: true, sha256: digest })',
    replace: "resultBody({ ok: true, sha256: [...digest].reverse().join('') })",
    caught: ['R-transfer']
  },
  {
    what: 'a sender that cancels locally sends no CANCEL',
    file: 'engine/src/transfer.js',
    find: "      writeCancel(socket, channel, (signal && typeof signal.reason === 'string') ? signal.reason : 'cancelled by sender')\n",
    replace: '      Promise.resolve()\n',
    caught: ['S-cancel-local']
  }
]

/** @param {string[]} adapter @param {string[]} ids */
async function failing (adapter, ids) {
  const selected = scenarios.filter((s) => ids.includes(s.id))
  assert.equal(selected.length, ids.length, `unknown scenario among ${ids.join(', ')}`)
  const results = await runScenarios(adapter, selected)
  return results.filter((r) => !r.ok).map((r) => r.id)
}

test('planted bugs, each caught by the scenarios that check it', { ...slow, timeout: 600000 }, async (t) => {
  const box = makeSandbox({ packages: ['engine', 'conformance'] })
  t.after(() => box.dispose())
  const adapter = [process.execPath, box.path('conformance/adapters/engine.js')]

  // The positive control, so a plant that "is caught" is not a sandbox
  // that cannot run anything.
  const every = [...new Set(PLANTS.flatMap((p) => p.caught))]
  assert.deepEqual(await failing(adapter, every), [], 'the unmutated copy passes every scenario used below')

  for (const plant of PLANTS) {
    const original = box.read(plant.file)
    assert.equal(original.split(plant.find).length, 2, `the plant "${plant.what}" must match exactly once in ${plant.file}`)
    box.write(plant.file, original.replace(plant.find, () => plant.replace))
    try {
      const failed = await failing(adapter, plant.caught)
      assert.deepEqual(failed, plant.caught, `planted: ${plant.what}`)
    } finally {
      box.restore(plant.file)
    }
    assert.equal(box.read(plant.file), original, 'restored from the working tree')
  }
})
