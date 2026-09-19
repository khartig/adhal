'use strict'

// Getting the drop code into the process without leaving it lying around.
//
// THE LEAK. `quay-send acid-acorn-acre-acts-afar bigfile.zip` puts the
// code in two places nobody thinks about: the shell's history file, where
// it persists indefinitely, and the process table, where `ps` shows it to
// every other user on the machine for as long as the drop runs. The code
// is the *only* secret in the system -- it is the topic, the drop key and
// the proof -- so those two are a full compromise of a drop, available to
// anyone with a shell on either box.
//
// That is a bad property for a tool whose pitch is "no account, no
// server": the threat model people reach for it with is "I do not want a
// third party to have my file", and a shared build box reading ~/.zsh
// _history is exactly that third party.
//
// Argv still works. It is what the test suite and every scratch
// diagnostic use, and breaking it to make a point would cost more than it
// buys. What changes is that it is no longer the only way, and that using
// it says so once on stderr -- visible to a human, harmless to a pipeline.

const fs = require('fs')
const readline = require('readline')

/**
 * Reads a single line from stdin without echoing it.
 *
 * No-echo matters for a shoulder-surfing reason and a screen-sharing one,
 * and it is why this is not just `rl.question`. It falls back to echoing
 * when stdin is not a TTY, where there is nothing to hide the typing from
 * and `setRawMode` does not exist.
 *
 * @param {string} promptText
 * @returns {Promise<string>}
 */
function promptForCode (promptText) {
  const input = process.stdin
  const output = process.stderr

  if (!input.isTTY) {
    // Piped in: one line, no prompt, no echo question.
    return new Promise((resolve, reject) => {
      const rl = readline.createInterface({ input })
      let answered = false
      rl.once('line', (line) => {
        answered = true
        rl.close()
        resolve(line)
      })
      rl.once('close', () => {
        if (!answered) reject(new Error('no code arrived on stdin'))
      })
      rl.once('error', reject)
    })
  }

  return new Promise((resolve, reject) => {
    const rl = readline.createInterface({ input, output, terminal: true })
    output.write(promptText)
    // Suppress the echo by intercepting what readline would draw.
    const mute = { muted: true }
    const realWrite = output.write.bind(output)
    // @ts-ignore -- deliberately replacing the stream's write for the
    // duration of the question, restored in every exit path below.
    rl.output.write = (/** @type {string} */ chunk) => {
      if (!mute.muted) realWrite(chunk)
      return true
    }
    const restore = () => {
      mute.muted = false
      // @ts-ignore
      rl.output.write = realWrite
    }
    rl.question('', (answer) => {
      restore()
      realWrite('\n')
      rl.close()
      resolve(answer)
    })
    rl.once('error', (err) => {
      restore()
      reject(err)
    })
  })
}

/**
 * Resolves where the code should come from.
 *
 * @param {{
 *   argvCode?: string | null,
 *   label: string,
 *   promptText?: string,
 *   warn?: (line: string) => void
 * }} options
 * @returns {Promise<string>}
 */
async function readCode ({ argvCode, label, promptText = 'drop code: ', warn = (line) => process.stderr.write(`${line}\n`) }) {
  // `-` is the long-standing convention for "read it from stdin", and it
  // is the form that composes: `pass show drop | quay-send - file.zip`.
  if (argvCode === '-' || argvCode === '--code-stdin') {
    const line = await promptForCode(promptText)
    return line.trim()
  }

  if (argvCode) {
    warn(
      `[${label}] note: the code was passed as a command-line argument, so it is now in ` +
      'your shell history and visible to `ps`. Pass `-` instead to read it from stdin.'
    )
    return argvCode
  }

  return (await promptForCode(promptText)).trim()
}

/**
 * True when stdin can supply a code at all. A receiver launched by a
 * supervisor with stdin closed should generate a code rather than hang
 * on a prompt nobody can answer.
 */
function stdinCanSupplyCode () {
  try {
    return Boolean(process.stdin) && !fs.fstatSync(0).isDirectory()
  } catch {
    return false
  }
}

module.exports = { readCode, promptForCode, stdinCanSupplyCode }
