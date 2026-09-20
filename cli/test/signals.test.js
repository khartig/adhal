'use strict'

// The cancel handler's logic, on every platform, without a child process.
//
// WHY THIS FILE EXISTS. Until now `installCancelHandler` had no unit test
// at all. Its only coverage was the two end-to-end tests in
// cancel.test.js, which spawn a CLI and send it a real signal -- and
// those cannot work on Windows via `child.kill('SIGINT')`, which Node
// documents as unconditional termination rather than a console control
// event. So the one platform with the most signal-handling peculiarities
// had zero coverage of the code that handles them.
//
// The `proc` parameter in the signature is the seam that makes this
// possible; it was there from the start and nobody used it. A fake
// process built on an EventEmitter gives deterministic delivery of
// SIGBREAK on macOS and Linux, where the real signal can never fire.
//
// This runs in the fast tier deliberately: it is the tier people iterate
// against, and signal handling is exactly the kind of code that gets
// edited without running the two-minute suite.

const test = require('node:test')
const assert = require('node:assert/strict')
const os = require('node:os')
const { EventEmitter } = require('node:events')

const { installCancelHandler, EXIT_CODES } = require('../src/signals')

// An EventEmitter is a good enough process for this: `on`,
// `removeListener` and `listenerCount` are the only process APIs the
// handler touches, and exit/exitCode are what we want to observe.
function fakeProc () {
  const emitter = /** @type {any} */ (new EventEmitter())
  emitter.exitCode = undefined
  /** @type {number[]} */
  emitter.exitCalls = []
  emitter.exit = (/** @type {number} */ code) => { emitter.exitCalls.push(code) }
  return /** @type {NodeJS.Process & { exitCalls: number[] }} */ (emitter)
}

const NAMES = /** @type {NodeJS.Signals[]} */ (Object.keys(EXIT_CODES))

// Guards against a signal being dropped from the table by accident: the
// per-signal block below is generated from EXIT_CODES, so a deletion
// there would silently delete its own test.
test('every signal a human can send is in the table', () => {
  assert.deepEqual(NAMES.sort(), ['SIGBREAK', 'SIGINT', 'SIGTERM'])
})

// SIGBREAK is 128 + 21 = 149. That arithmetic is asserted against the OS
// on the only platform that publishes the constant, so the hardcoded
// number is checked rather than merely believed. os.constants.signals
// has no SIGBREAK on darwin or linux, hence the skip.
test('the SIGBREAK exit code matches what the OS says the signal number is', {
  skip: os.constants.signals.SIGBREAK === undefined
    ? `this platform (${process.platform}) has no SIGBREAK constant to check against`
    : false
}, () => {
  assert.equal(EXIT_CODES.SIGBREAK, 128 + os.constants.signals.SIGBREAK)
})

for (const name of NAMES) {
  const code = EXIT_CODES[name]

  test(`${name} once aborts and sets exit code ${code} without exiting`, () => {
    const proc = fakeProc()
    /** @type {string[]} */
    const lines = []
    const cancel = installCancelHandler({ label: 'probe', log: (l) => lines.push(l), proc })

    assert.equal(cancel.signal.aborted, false)
    assert.equal(cancel.cancelled(), false)

    proc.emit(name)

    assert.equal(cancel.signal.aborted, true, 'the first signal must abort')
    assert.equal(cancel.cancelled(), true)
    // The whole point of the file: the exit code is *set*, not taken. The
    // normal catch/finally has to run so the peer gets a CANCEL frame
    // instead of a socket reset.
    assert.equal(proc.exitCode, code)
    assert.deepEqual(proc.exitCalls, [], 'the first signal must not call exit()')
    assert.equal(lines.length, 1)
    assert.match(lines[0], new RegExp(`\\[probe\\] cancelled \\(${name}\\)`))
  })

  test(`${name} twice exits immediately with ${code}`, () => {
    const proc = fakeProc()
    /** @type {string[]} */
    const lines = []
    installCancelHandler({ label: 'probe', log: (l) => lines.push(l), proc })

    proc.emit(name)
    proc.emit(name)

    assert.deepEqual(proc.exitCalls, [code], 'the second signal must exit, with the same code')
    assert.match(lines[1], new RegExp(`\\[probe\\] second ${name}`))
  })
}

// Telling a Ctrl+Break user to "press SIGBREAK again" is the bug this
// pins. Asserted per signal rather than as one string so a future signal
// that needs a keystroke name cannot be added without noticing.
test('the second-press hint names a keystroke, not a signal', () => {
  for (const [name, expected] of [['SIGINT', 'Ctrl-C'], ['SIGBREAK', 'Ctrl-Break'], ['SIGTERM', 'SIGTERM']]) {
    const proc = fakeProc()
    /** @type {string[]} */
    const lines = []
    installCancelHandler({ label: 'probe', log: (l) => lines.push(l), proc })
    proc.emit(/** @type {NodeJS.Signals} */ (name))
    assert.match(lines[0], new RegExp(`press ${expected} again`), `${name} should say "press ${expected} again"`)
  }
})

// A long-lived process installing a handler per transfer accumulates one
// set per transfer if this leaks -- and Node warns at 11, which is a
// confusing thing to see on the twelfth file you send.
test('dispose removes every listener it installed', () => {
  const proc = fakeProc()
  const cancel = installCancelHandler({ label: 'probe', log: () => {}, proc })

  for (const name of NAMES) assert.equal(proc.listenerCount(name), 1, `${name} should be listened on`)

  cancel.dispose()

  for (const name of NAMES) assert.equal(proc.listenerCount(name), 0, `${name} listener should be removed`)
})

// Only its own. Disposing one handler must not deafen another -- receive.js
// installs one per run and a wrapper could hold its own.
test('dispose leaves listeners it did not install alone', () => {
  const proc = fakeProc()
  const theirs = () => {}
  proc.on('SIGINT', theirs)

  const cancel = installCancelHandler({ label: 'probe', log: () => {}, proc })
  assert.equal(proc.listenerCount('SIGINT'), 2)

  cancel.dispose()
  assert.equal(proc.listenerCount('SIGINT'), 1)
  assert.deepEqual(proc.listeners('SIGINT'), [theirs])
})
