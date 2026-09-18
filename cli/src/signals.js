'use strict'

// Ctrl-C, turned into something the far side can understand.
//
// THE PROBLEM THIS SOLVES. Without it, Ctrl-C tears the process down and
// the peer's socket resets. What the peer prints is "connection reset by
// peer" -- byte for byte what a dead hole punch looks like, which is the
// exact confusion item 2 spent a week learning to separate (see
// engine/src/swarm.js's comment about a half-failed punch that neither
// side reported honestly). A deliberate cancellation must not be
// indistinguishable from the failure mode this project has the hardest
// time diagnosing.
//
// So the first signal aborts an AbortController rather than exiting. The
// normal catch/finally path then runs: the engine writes a CANCEL frame
// and waits for it to flush, the CLI ends the socket and destroys the
// swarm, and only then does the process exit with the conventional
// 128+signal code.
//
// The second signal exits immediately. That is not a nicety: swarm.destroy()
// can take seconds, and a Ctrl-C that appears to do nothing is a tool
// people learn to kill -9 instead.
//
// One helper rather than four copies, because four copies of signal
// handling drift, and the copy that drifts is the one nobody tested.

const EXIT_CODES = { SIGINT: 130, SIGTERM: 143 }

/**
 * @param {{ label: string, log?: (line: string) => void, proc?: NodeJS.Process }} options
 * @returns {{ signal: AbortSignal, cancelled: () => boolean, dispose: () => void }}
 */
function installCancelHandler ({ label, log = console.log, proc = process }) {
  const controller = new AbortController()
  let cancelled = false

  /** @type {Array<[NodeJS.Signals, () => void]>} */
  const installed = []

  for (const name of /** @type {NodeJS.Signals[]} */ (Object.keys(EXIT_CODES))) {
    const code = EXIT_CODES[name]
    const handler = () => {
      if (cancelled) {
        // Already tearing down and asked again: stop waiting for a clean
        // exit and go.
        log(`[${label}] second ${name}: exiting now, without waiting for teardown`)
        proc.exit(code)
        return
      }
      cancelled = true
      log(`[${label}] cancelled (${name}): telling the peer and shutting down; press ${name === 'SIGINT' ? 'Ctrl-C' : name} again to exit immediately`)
      // Set here rather than in the catch block so the code is right even
      // if teardown itself throws. A `reason` that is a plain string is
      // what the engine puts in the CANCEL frame for the peer to print.
      proc.exitCode = code
      controller.abort('cancelled at the keyboard')
    }
    proc.on(name, handler)
    installed.push([name, handler])
  }

  return {
    signal: controller.signal,
    cancelled: () => cancelled,
    dispose: () => {
      for (const [name, handler] of installed) proc.removeListener(name, handler)
    }
  }
}

module.exports = { installCancelHandler, EXIT_CODES }
