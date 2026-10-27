'use strict'

// Comparing file-sized Buffers without assert.deepEqual.
//
// WHY. When assert/strict's deepEqual FAILS on two Buffers, Node builds
// its message from a diff of the two, and that diff's memory grows with
// the square of their size: an empty Buffer against 1 KiB takes 65 MB,
// against 16 KiB 2.4 GB, and against the 256 KiB to 4 MiB files these
// tests send, more memory than the machine has. The memory is typed arrays
// outside the V8 heap, so --max-old-space-size does not stop it. A passing
// comparison costs nothing, so an ordinary run never shows this. A
// mutant (tools/mutate.js) that breaks a transfer does: runs of it hung a
// 32 GiB laptop three times, at 52, 27, and 15 GiB in three test processes.
//
// So bytes are compared with Buffer.compare, and a mismatch is described
// by what can be said cheaply: both lengths, and where they first differ.
//
// Not in cli/test/ for the reason duplex-pair.js gives.

const assert = require('node:assert/strict')

/**
 * Fails unless `actual` holds the same bytes as `expected`, as
 * assert.deepEqual would, but with a message of fixed size.
 *
 * @param {Uint8Array} actual
 * @param {Uint8Array} expected
 * @param {string} [message] what the comparison means, as for assert
 */
function assertSameBytes (actual, expected, message) {
  const what = message ? `${message}: ` : ''
  // deepEqual compares prototypes too: a Uint8Array is not a Buffer.
  assert.ok(actual instanceof Uint8Array && Object.getPrototypeOf(actual) === Object.getPrototypeOf(expected),
    `${what}not the same kind of byte array as expected`)
  if (Buffer.compare(actual, expected) === 0) return
  const shorter = Math.min(actual.length, expected.length)
  let at = 0
  while (at < shorter && actual[at] === expected[at]) at++
  assert.fail(`${what}${actual.length} bytes where ${expected.length} were expected, the first difference at byte ${at}`)
}

module.exports = { assertSameBytes }
