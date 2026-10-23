'use strict'

// The seeded generator the fuzz harness (cli/test/fuzz.test.js) and the
// property tests (cli/test/property.test.js) both draw from.
//
// mulberry32, seeded from a hex seed: small, fast, and reproducible across
// platforms, which Math.random is not. A failure in either harness prints
// its seed, and the seed is all it takes to replay it.
//
// Not in cli/test/ for the reason duplex-pair.js gives.

/** @param {string} seed hex; the first 8 digits are used */
function rng (seed) {
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
    next,
    int,
    pick: (/** @type {any[]} */ list) => list[int(list.length)],
    bytes: (/** @type {number} */ n) => Buffer.from(Array.from({ length: n }, () => int(256)))
  }
}

module.exports = { rng }
