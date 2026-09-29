'use strict'

// Making drop contention visible (Q-04).
//
// Each dropped candidate already gets a line of its own, and that is the
// problem: ten "dropped before proving" lines scroll past looking like
// ten separate network hiccups, when three of them failing CONFIRMATION
// is the one thing in the log a person should act on. So the pattern gets
// a line of its own, once it is a pattern.
//
// TWO KINDS OF FAILURE, kept apart exactly as swarm.js keeps them apart
// for counting:
//   - A failed confirmation: a peer reached the nameplate and did not
//     hold the secret. From one key, most likely the sender mistyped the
//     code. From several keys with no success, it is another drop that
//     happens to share the nameplate, or someone guessing, and the line
//     says so. These count toward the attempt limit.
//   - A silent candidate: connected, then closed or went quiet before the
//     handshake finished. That is nearly always the DHT's stale records
//     or a dead hole punch, and it is NOT counted, because counting it
//     would let the network's own noise burn a legitimate drop
//     (PROTOCOL.md section 6). The line says that too, so nobody reads it
//     as an attack.
//
// Only until pairing. After it, only counted failures are reported at
// all, each with its own line, and "none has proved the code" is no
// longer true.

const { ERR_CONFIRMATION, MAX_ATTEMPTS } = require('@ad-hal/engine')

// When a pattern is worth a line, and then each doubling after it, so a
// long wait under attack reports the attack growing without printing a
// line per candidate.
const CONFIRMATION_THRESHOLD = 3
const SILENT_THRESHOLD = 5

/**
 * @param {{ label: string, log?: (line: string) => void, maxAttempts?: number }} options
 * @returns {{ dropped: (peerInfo: any, reason: string, code?: string) => void, paired: () => void }}
 */
function createContentionMonitor ({ label, log = console.log, maxAttempts = MAX_ATTEMPTS }) {
  let failed = 0
  let silent = 0
  let isPaired = false
  let nextFailedWarning = CONFIRMATION_THRESHOLD
  let nextSilentWarning = SILENT_THRESHOLD
  /** @type {Set<string>} */
  const keys = new Set()

  /**
   * Feed it everything onCandidateDropped hears.
   * @param {any} peerInfo
   * @param {string} _reason
   * @param {string} [code]
   */
  function dropped (peerInfo, _reason, code) {
    if (isPaired) return
    if (code === ERR_CONFIRMATION) {
      failed++
      if (peerInfo && peerInfo.publicKey) keys.add(peerInfo.publicKey.toString('hex'))
      if (failed < nextFailedWarning) return
      nextFailedWarning *= 2
      const limit = `${failed} of the ${maxAttempts} failures this drop allows before it ends`
      log(keys.size > 1
        ? `[${label}] WARNING: ${failed} peers, from ${keys.size} different keys, found this drop and could not prove its code, and none has succeeded. ` +
          'Either another drop is using the same first two words (a code collision), or someone is guessing. ' +
          `That is ${limit}. If your sender is not reporting a wrong code, cancel and use a new one.`
        : `[${label}] WARNING: one peer has failed to prove the code ${failed} times. Most likely the sender has mistyped it: ` +
          `check the code on both sides. That is ${limit}.`)
      return
    }
    silent++
    if (silent < nextSilentWarning) return
    nextSilentWarning *= 2
    log(`[${label}] note: ${silent} candidates connected and went silent before finishing the handshake. ` +
      'That is usually the network (stale DHT records, or hole punches that failed), not an attack, and it does not count toward the attempt limit.')
  }

  return { dropped, paired: () => { isPaired = true } }
}

module.exports = { createContentionMonitor, CONFIRMATION_THRESHOLD, SILENT_THRESHOLD }
