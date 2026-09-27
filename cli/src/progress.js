'use strict'

// Turns the engine's progress events into something a human can read,
// which is the only thing this file does: the engine emits `{ bytes,
// total }` per chunk and computes no percentage, rate or ETA, because it
// cannot know whether its consumer is a terminal, a test or a log. Same
// split as engine/src/code.js owning the code value while cli/src/qr.js
// owns the drawing.
//
// TWO OUTPUT MODES, AND THE CONTRACT BETWEEN THEM:
//
//   TTY      one line, redrawn in place with '\r', throttled to 100 ms,
//            with a guaranteed final render and a closing newline.
//   non-TTY  whole lines at fixed percentage milestones.
//
// Milestones rather than a timer for the non-TTY case, deliberately. A
// timer makes the number of lines depend on how fast the transfer ran, so
// the same code produces different output on a loaded CI box than on a
// laptop -- and any test that asserts on those lines becomes
// load-sensitive, which is to say flaky. Every 25% is the same five lines
// every time.
//
// TWO INVARIANTS THIS FILE MUST KEEP, because the existing test suite
// matches on exact line shapes (/^\[receive\] sha256: [0-9a-f]{64}$/m and
// friends):
//
//   1. No '\r' is ever written to a non-TTY stream. A carriage return in
//      piped output corrupts whatever a test or a log reader does next.
//   2. Progress never shares a line with 'done:', 'sha256:' or 'saved
//      to:'. On a TTY that is what close() is for; off one, every
//      progress write is already a whole line.
//
// A STREAM HAS NO TOTAL (`total: null`, PROTOCOL.md section 4.3). On a TTY
// it gets a running byte count instead of a bar. Off one it gets nothing:
// there are no percentages to make milestones of, and a line per chunk
// would break the reason milestones exist -- output that is the same every
// run. The done/sha256 lines still say how much arrived.

// Redrawing faster than this buys nothing a human can see and costs a
// syscall per chunk -- at 64 KB chunks a fast local transfer emits
// hundreds of events a second.
const REDRAW_MS = 100
const BAR_WIDTH = 24
const MILESTONE_PERCENT = 25

function formatBytes (n) {
  if (n < 1024) return `${n} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let value = n / 1024
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit++
  }
  return `${value.toFixed(value >= 100 ? 0 : 1)} ${units[unit]}`
}

function percentOf (bytes, total) {
  // A zero-byte file is complete the moment it starts; anything else
  // would render as NaN.
  if (total <= 0) return 100
  return Math.floor((bytes / total) * 100)
}

/**
 * @param {{
 *   label: string,
 *   stream?: { isTTY?: boolean, write: (chunk: string) => any },
 *   env?: Record<string, string | undefined>,
 *   now?: () => number
 * }} options
 * @returns {{ onProgress: (p: { bytes: number, total: number | null }) => void, close: () => void }}
 */
function createProgressReporter ({ label, stream = process.stdout, env = process.env, now = Date.now }) {
  // An escape hatch that costs nothing to honour and saves anyone piping
  // this into a log from having to filter it.
  if (env.ADHAL_NO_PROGRESS === '1') {
    return { onProgress: () => {}, close: () => {} }
  }

  const isTty = Boolean(stream.isTTY)
  /** @type {number | null} */
  let lastDrawAt = null
  let lastMilestone = -1
  let drewSomething = false
  let finished = false

  function drawTty (bytes, total) {
    if (total === null) {
      stream.write(`\r\x1b[2K[${label}] ${formatBytes(bytes)} (streaming, size unknown)`)
      drewSomething = true
      return
    }
    const percent = percentOf(bytes, total)
    const filled = Math.round((percent / 100) * BAR_WIDTH)
    const bar = '#'.repeat(filled) + '-'.repeat(BAR_WIDTH - filled)
    const line = `[${label}] [${bar}] ${String(percent).padStart(3)}%  ${formatBytes(bytes)} / ${formatBytes(total)}`
    // Cleared to end of line so a shorter render cannot leave the tail of
    // a longer one behind.
    stream.write(`\r[2K${line}`)
    drewSomething = true
  }

  function drawLine (bytes, total) {
    stream.write(`[${label}] progress: ${percentOf(bytes, total)}% (${bytes}/${total} bytes)\n`)
    drewSomething = true
  }

  function onProgress ({ bytes, total }) {
    if (finished) return
    if (total === null && !isTty) return
    const complete = total !== null && bytes >= total

    if (isTty) {
      const at = now()
      // Two events are never throttled away. The first, or the bar does
      // not appear until 100 ms in -- and on a fast local transfer that
      // can be the whole thing, so it would never appear at all. And the
      // last, because a bar frozen at 97% because the completing event
      // landed inside the window reads as a hang.
      if (lastDrawAt !== null && !complete && at - lastDrawAt < REDRAW_MS) return
      lastDrawAt = at
      drawTty(bytes, total)
      return
    }

    const percent = percentOf(bytes, total)
    const milestone = Math.floor(percent / MILESTONE_PERCENT) * MILESTONE_PERCENT
    if (milestone <= lastMilestone) return
    lastMilestone = milestone
    drawLine(bytes, total)
  }

  // Ends the progress line so the caller's next console.log starts clean.
  // Must be called on every exit path, including cancellation and
  // failure, or an interrupted transfer leaves the cursor mid-bar and the
  // error message lands on top of it.
  function close () {
    if (finished) return
    finished = true
    if (isTty && drewSomething) stream.write('\n')
  }

  return { onProgress, close }
}

module.exports = { createProgressReporter, formatBytes, percentOf }
