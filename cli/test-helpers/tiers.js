'use strict'

// Two tiers, so the feedback loop is not always 116 seconds long.
//
// THE PROBLEM. The suite takes ~116s, and essentially all of it is a
// handful of tests that stand up real hyperdht testnets or spawn real CLI
// processes. Everything else -- framing, manifests, names, cancellation
// over duplex pairs, the whole of the Stage 0 hardening -- runs in about
// a second. Stage 0 edits security-critical code, and iterating on
// security-critical code through a two-minute loop is how mistakes get
// made: people batch changes, and batched changes are harder to bisect.
//
// So `QUAY_FAST=1` skips the network/subprocess tier. It is opt-in for
// speed, never for CI: `pnpm test` still runs everything, and the CI
// workflow runs the fast tier first only so an obvious break is reported
// in seconds rather than minutes.
//
// WHY A PER-TEST MARKER RATHER THAN SPLITTING FILES. Four files mix the
// tiers -- cancel, progress, code-proof and handshake each pair fast unit
// assertions with a slow end-to-end one, and the pairing is the point:
// `code-proof.test.js` asserts that a relayed proof fails as a unit AND
// that a real receiver survives three rejected peers. Splitting them
// would put two halves of one argument in two files. Marking the slow
// half is cheaper and keeps the reasoning together.

const FAST_ONLY = process.env.QUAY_FAST === '1'

// Spread into node:test's options slot: test('name', slow, fn).
const slow = FAST_ONLY
  ? { skip: 'slow tier: needs a DHT testnet or a child process (unset QUAY_FAST to run it)' }
  : {}

module.exports = { slow, FAST_ONLY }
