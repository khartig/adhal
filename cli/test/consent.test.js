'use strict'

// W15c: what a receiver asks and what it warns about. The accept prompt
// (Q-02), the risky-name warning, and the drop-contention lines (Q-04).
// All of it is driven here with fake streams and fake peers; the
// end-to-end runs are in local-loopback.test.js.

const test = require('node:test')
const assert = require('node:assert/strict')
const { PassThrough } = require('node:stream')

const { ERR_CONFIRMATION } = require('@ad-hal/engine')
const { createConsent, riskWarning, describeOffer } = require('../src/consent')
const { createContentionMonitor, CONFIRMATION_THRESHOLD, SILENT_THRESHOLD } = require('../src/contention')

const offerFor = (overrides = {}) => ({
  name: 'report.pdf',
  declaredName: 'report.pdf',
  size: 2 * 1024 * 1024,
  sha256: 'ab'.repeat(32),
  blockSize: 64 * 1024,
  partial: 0,
  ...overrides
})

// A terminal, as far as readline can tell: `isTTY` is what the CLI checks,
// and readline only needs a stream to read keys from.
function fakeTerminal () {
  const input = /** @type {PassThrough & { isTTY?: boolean }} */ (new PassThrough())
  input.isTTY = true
  const output = new PassThrough()
  let written = ''
  output.on('data', (c) => { written += c.toString('utf8') })
  return { input, output, written: () => written }
}

/** @param {any} promise @param {number} ms */
const settlesWithin = (promise, ms) => Promise.race([
  promise.then(() => true, () => true),
  new Promise((resolve) => setTimeout(() => resolve(false), ms))
])

// --- risky names ----------------------------------------------------------

test('risky names are warned about by what opening them does, and ordinary ones are not', () => {
  for (const name of ['report.pdf', 'source.bin', 'notes', '.bashrc', 'photo.JPG', 'data.csv']) {
    assert.equal(riskWarning(name), null, name)
  }
  assert.match(/** @type {string} */ (riskWarning('setup.exe')), /a program or installer \(\.exe\)/)
  assert.match(/** @type {string} */ (riskWarning('SETUP.EXE')), /a program or installer/, 'case does not hide it')
  assert.match(/** @type {string} */ (riskWarning('install.sh')), /a script \(\.sh\)/)
  assert.match(/** @type {string} */ (riskWarning('Thing.dmg')), /a disk image/)
  assert.match(/** @type {string} */ (riskWarning('budget.xlsm')), /macros/)
  assert.match(/** @type {string} */ (riskWarning('backup.tar.gz')), /an archive \(\.gz\), which can hold programs/)
})

test('a double extension is called a disguise, unless it is an archive of the thing it names', () => {
  assert.match(/** @type {string} */ (riskWarning('invoice.pdf.exe')), /made to look like a \.pdf file.*Do not open it/)
  // Spaces inside a name survive safeWriteName; they must not hide the decoy.
  assert.match(/** @type {string} */ (riskWarning('invoice.pdf      .exe')), /made to look like a \.pdf file/)
  assert.doesNotMatch(/** @type {string} */ (riskWarning('holiday.jpg.zip')), /made to look like/)
})

test('a warning prints the name through displayName, never raw', () => {
  const warning = /** @type {string} */ (riskWarning('a\u001b[2Jb.exe'))
  assert.doesNotMatch(warning, /\u001b/)
})

// --- what the prompt shows ------------------------------------------------

test('the offer is described with its name, size, digest, and any resume', () => {
  const plain = describeOffer(offerFor())
  assert.match(plain[0], /offer: "report\.pdf" \(2\.0 MB, 2097152 bytes\)/)
  assert.match(plain.join('\n'), new RegExp(`sha256: ${'ab'.repeat(32)}`))
  assert.doesNotMatch(plain.join('\n'), /resume/)

  const streamed = describeOffer(offerFor({ size: null, sha256: null }))
  assert.match(streamed[0], /streamed, size unknown/)
  assert.match(streamed.join('\n'), /sha256: sent when the stream ends/)

  const resumed = describeOffer(offerFor({ partial: 1024 * 1024 }))
  assert.match(resumed.join('\n'), /resume: an earlier, interrupted attempt left 1\.0 MB of this file/)

  const renamed = describeOffer(offerFor({ name: '_aux.txt', declaredName: 'aux.txt' }))
  assert.match(renamed[0], /"_aux\.txt"/)
  assert.match(renamed.join('\n'), /the sender asked for "aux\.txt"/)
})

// --- the three answers ----------------------------------------------------

test('--yes accepts without asking, and still warns about a risky name', async () => {
  /** @type {string[]} */
  const lines = []
  const consent = createConsent({ yes: true, label: 'rx', log: (l) => lines.push(l) })
  assert.equal(await consent.onOffer(offerFor()), true)
  assert.deepEqual(lines, [], 'nothing to say about an ordinary file')

  assert.equal(await consent.onOffer(offerFor({ name: 'x.pdf.exe', declaredName: 'x.pdf.exe' })), true)
  assert.equal(lines.length, 1)
  assert.match(lines[0], /^\[rx\] WARNING: "x\.pdf\.exe" is a program/)
})

test('with no terminal and no --yes, the offer is declined with a reason and a way out', async () => {
  /** @type {string[]} */
  const lines = []
  const input = /** @type {any} */ (new PassThrough())
  const consent = createConsent({ yes: false, label: 'rx', log: (l) => lines.push(l), input })
  const verdict = await consent.onOffer(offerFor())
  assert.equal(typeof verdict, 'string', 'a string declines, and is what the sender reads')
  assert.match(/** @type {string} */ (verdict), /not at a terminal.*--yes/)
  assert.match(lines.join('\n'), /offer: "report\.pdf"/, 'the offer is still shown, for the log')
  assert.match(lines.at(-1) ?? '', /no terminal to ask on.*Pass --yes/)
})

test('at a terminal, only a yes accepts; an empty line or anything else declines', async () => {
  const no = 'not accepted at the prompt'
  for (const [typed, expected] of [['y\n', true], ['YES\n', true], [' yes \n', true], ['\n', no], ['n\n', no], ['yep\n', no]]) {
    const term = fakeTerminal()
    const consent = createConsent({ yes: false, label: 'rx', log: () => {}, input: term.input, output: term.output })
    const answered = consent.onOffer(offerFor())
    term.input.write(typed)
    assert.equal(await answered, expected, JSON.stringify(typed))
    assert.match(term.written(), /accept this file\? \[y\/N\]/)
  }
})

test('a question taken down by close() is never answered, and ends its line', async () => {
  // The transfer ended some other way -- the sender canceled -- while the
  // question was up. Answering now would put a DECLINE behind the CANCEL.
  const term = fakeTerminal()
  const consent = createConsent({ yes: false, label: 'rx', log: () => {}, input: term.input, output: term.output })
  const answered = consent.onOffer(offerFor())
  await new Promise((resolve) => setImmediate(resolve))
  consent.close()
  assert.equal(await settlesWithin(answered, 100), false, 'no verdict at all')
  assert.match(term.written(), /\[y\/N\] [^\n]*\n$/, 'the question\'s line is ended')
  assert.equal(term.written().split('\n').length, 2, 'once, not with a blank line after it')
})

test('a cancel while asking takes the question down the same way', async () => {
  const term = fakeTerminal()
  const controller = new AbortController()
  const consent = createConsent({ yes: false, label: 'rx', log: () => {}, input: term.input, output: term.output, signal: controller.signal })
  const answered = consent.onOffer(offerFor())
  await new Promise((resolve) => setImmediate(resolve))
  controller.abort()
  assert.equal(await settlesWithin(answered, 100), false)
  consent.close()
})

test('Ctrl-C at the question is handed to the CLI as an interrupt, not taken as an answer', async () => {
  // In raw mode a terminal delivers Ctrl-C to readline, not as a signal,
  // so without this the cancel handler would never hear it.
  const term = fakeTerminal()
  let interrupted = 0
  const consent = createConsent({ yes: false, label: 'rx', log: () => {}, input: term.input, output: term.output, onInterrupt: () => { interrupted++ } })
  const answered = consent.onOffer(offerFor())
  await new Promise((resolve) => setImmediate(resolve))
  term.input.write('\u0003')
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(interrupted, 1)
  assert.equal(await settlesWithin(answered, 50), false, 'still unanswered: the cancel path decides')
  consent.close()
})

// --- drop contention (Q-04) -----------------------------------------------

const peer = (/** @type {number} */ n) => ({ publicKey: Buffer.alloc(32, n) })

test('failed confirmations from several keys are called a collision or an attack, once they are a pattern', () => {
  /** @type {string[]} */
  const lines = []
  const monitor = createContentionMonitor({ label: 'rx', log: (l) => lines.push(l), maxAttempts: 100 })
  for (let i = 1; i < CONFIRMATION_THRESHOLD; i++) monitor.dropped(peer(i), 'x', ERR_CONFIRMATION)
  assert.deepEqual(lines, [], 'one or two is not yet a pattern')

  monitor.dropped(peer(CONFIRMATION_THRESHOLD), 'x', ERR_CONFIRMATION)
  assert.equal(lines.length, 1)
  assert.match(lines[0], /WARNING: 3 peers, from 3 different keys/)
  assert.match(lines[0], /code collision.*someone is guessing/)
  assert.match(lines[0], /3 of the 100 failures/)

  // Then at each doubling, not on every candidate.
  for (let i = 4; i <= 6; i++) monitor.dropped(peer(i), 'x', ERR_CONFIRMATION)
  assert.equal(lines.length, 2)
  assert.match(lines[1], /6 peers/)
})

test('failed confirmations from one key point at a mistyped code instead', () => {
  /** @type {string[]} */
  const lines = []
  const monitor = createContentionMonitor({ label: 'rx', log: (l) => lines.push(l) })
  for (let i = 0; i < CONFIRMATION_THRESHOLD; i++) monitor.dropped(peer(7), 'x', ERR_CONFIRMATION)
  assert.equal(lines.length, 1)
  assert.match(lines[0], /one peer has failed to prove the code 3 times.*mistyped/)
})

test('silent candidates get a note that says they are not counted, and never the attack warning', () => {
  /** @type {string[]} */
  const lines = []
  const monitor = createContentionMonitor({ label: 'rx', log: (l) => lines.push(l) })
  for (let i = 1; i < SILENT_THRESHOLD; i++) monitor.dropped(peer(i), 'closed before confirming')
  assert.deepEqual(lines, [])
  monitor.dropped(peer(SILENT_THRESHOLD), 'did not complete the handshake within 15000ms')
  assert.equal(lines.length, 1)
  assert.match(lines[0], /5 candidates connected and went silent/)
  assert.match(lines[0], /does not count toward the attempt limit/)
  assert.doesNotMatch(lines[0], /WARNING|guessing/)
})

test('after pairing, the monitor is quiet: "none has succeeded" is no longer true', () => {
  /** @type {string[]} */
  const lines = []
  const monitor = createContentionMonitor({ label: 'rx', log: (l) => lines.push(l) })
  monitor.paired()
  for (let i = 0; i < 20; i++) monitor.dropped(peer(i), 'x', ERR_CONFIRMATION)
  assert.deepEqual(lines, [])
})
