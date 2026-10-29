'use strict'

// Every CLI's --help text, and the notices more than one of them prints.
// One file, for the reason env.js and report.js are one file each: four
// copies of a usage string drift, and the one that drifts is the one that
// is wrong about a security property.

// Q-09. Printed by both swarm CLIs when they start, and in their --help.
// ad-hal hides the file, not the people: the peer learns your address when
// it connects, and so do the DHT nodes that store and serve the topic's
// announce records. Saying so up front is cheaper than anyone assuming
// otherwise.
const NOT_ANONYMOUS = 'not anonymous: your IP address is visible to the peer, and to the DHT nodes near this drop\'s topic'

// Q-13. The loopback pair is a harness for tests and demos, and nothing
// about it is meant for a real drop: it listens on 127.0.0.1 only.
const TEST_ONLY = 'TEST-ONLY: the loopback harness, over 127.0.0.1. For a real drop use ad-hal-send / ad-hal-receive.'

const USAGE = {
  'swarm-receive': `Adhal receive: wait for a file from someone who has the drop code.

Usage: ad-hal-receive [--new] [outputDir]      generate a code and show it (the default)
       ad-hal-receive - [outputDir]            read a code from stdin, or type it at the prompt
       ad-hal-receive <code> [outputDir] --code-on-argv
       ad-hal-receive [-] --stdout | tar x     write the file to stdout instead

With one argument and no --new, the argument is the code, not the directory.

Options:
  --yes                   accept the offer without being asked. A risky file
                          name is still warned about.
  --stdout                write the file to stdout, and everything else to
                          stderr. The bytes are verified only if this exits 0:
                          check it (set -o pipefail). No resume.
  --json                  report the drop as JSON lines, on stdout, or on
                          stderr with --stdout. Never asks: without --yes, the
                          offer is declined. See docs/CLI-CONTRACT.md.
  --replace               overwrite an existing file of the same name
  --code-stdin            the same as passing - as the code
  --code-on-argv          allow a code as an argument. It is then in your shell
                          history and visible to \`ps\` for as long as the drop runs.
  --insecure-opaque-code  accept a code that is not drop-code words. This
                          removes the protection the code's secret half gives.
  --verbose               also print the DHT topic
  --help                  show this text

Each offer is shown with its name, size and SHA-256, and you are asked
before anything is written. With no terminal to ask on and no --yes, the
offer is declined.

Note: ${NOT_ANONYMOUS}.`,

  'swarm-send': `Adhal send: send a file to the receiver showing a drop code.

Usage: ad-hal-send - <file>                    read the code from stdin, or type it at the prompt
       ad-hal-send <code> <file> --code-on-argv
       ad-hal-send <code> - [--name=<name>] --code-on-argv
                                               stream stdin as the file. stdin cannot
                                               also carry the code, so it goes on argv.

Options:
  --code-stdin            the same as passing - as the code
  --code-on-argv          allow a code as an argument. It is then in your shell
                          history and visible to \`ps\` for as long as the drop runs.
  --name=<name>           what a stream is offered as (default "stdin")
  --json                  report the drop as JSON lines on stdout, in place of
                          these lines. See docs/CLI-CONTRACT.md.
  --insecure-opaque-code  accept a code that is not drop-code words. This
                          removes the protection the code's secret half gives.
  --verbose               also print the DHT topic
  --help                  show this text

Note: ${NOT_ANONYMOUS}.`,

  receive: `receive.js: ${TEST_ONLY}

Usage: receive.js <port> [outputDir] [--yes]
  port 0 asks the OS for a free port. The bound port and a fresh drop code
  are printed for send.js.

Options:
  --yes   accept the offer without being asked
  --help  show this text`,

  send: `send.js: ${TEST_ONLY}

Usage: send.js <port> - <file|->              read the code from stdin
       send.js <port> <code> <file|-> --code-on-argv
  A file of - streams stdin, offered as "stdin".

Options:
  --code-on-argv  allow a code as an argument (shell history, \`ps\`)
  --help          show this text`
}

/**
 * @param {keyof typeof USAGE} cli
 * @returns {string}
 */
function usage (cli) {
  return USAGE[cli]
}

module.exports = { usage, NOT_ANONYMOUS, TEST_ONLY }
