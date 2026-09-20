'use strict'

// Ctrl-C, turned into something the far side can understand.
//
// THE PROBLEM THIS SOLVES. Without it, Ctrl-C tears the process down and
// the peer's socket resets. What the peer prints is "connection reset by
// peer" -- byte for byte what a dead hole punch looks like, which is the
// exact confusion the Hyperswarm work spent a week learning to separate (see
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
//
// WINDOWS, because two things here are not obvious from the code and one
// of them was believed backwards for a while.
//
//   Ctrl-C works. Node documents 'SIGINT' from the terminal as supported
//   on all platforms: Windows delivers the console Ctrl+C event as
//   SIGINT, so a human pressing it here takes the clean path below
//   exactly as on POSIX. What does *not* work is `child.kill('SIGINT')`,
//   which on Windows is documented as unconditional termination -- a
//   different thing from a console control event, and the reason the
//   end-to-end tests have a separate Windows path.
//
//   SIGBREAK is the Windows-only half of that pair, raised by Ctrl+Break.
//   Unhandled, it tore the process down abruptly and the peer saw a
//   socket reset -- the precise "deliberate cancel is indistinguishable
//   from a dead hole punch" confusion this file exists to prevent. It is
//   handled now, so Ctrl+Break cancels as cleanly as Ctrl-C.
//
//   SIGTERM is registered but can never fire on Windows (Node: "SIGTERM
//   is not supported on Windows, it can be listened on"). Harmless dead
//   weight there, not a bug -- listening costs nothing and keeping the
//   table uniform is worth more than a platform branch.

// 128 + the signal number, the shell convention: SIGINT 2, SIGTERM 15,
// SIGBREAK 21. cli/test/signals.test.js checks 149 against
// os.constants.signals.SIGBREAK where that constant exists, so the number
// is self-checked on the one platform that can confirm it.
const EXIT_CODES = { SIGINT: 130, SIGTERM: 143, SIGBREAK: 149 }

// What to tell someone to press again. Printing the raw signal name told
// a Ctrl+Break user to "press SIGBREAK again".
/** @type {Record<string, string>} */
const KEYSTROKES = { SIGINT: 'Ctrl-C', SIGBREAK: 'Ctrl-Break' }

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
      log(`[${label}] cancelled (${name}): telling the peer and shutting down; press ${KEYSTROKES[name] ?? name} again to exit immediately`)
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
