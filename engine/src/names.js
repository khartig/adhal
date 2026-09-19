'use strict'

// Peer-supplied names, in the two places they are dangerous.
//
// A manifest's `name` is a string chosen by the other end. It reaches two
// very different sinks, and until this file existed only one of them was
// defended:
//
//   1. A TERMINAL, when we print "manifest: <name>" or "refusing <name>".
//      A name carrying ESC moves the cursor, clears the screen, or paints
//      a forged line; a name carrying U+202E reverses what follows it, so
//      `inv<U+202E>fdp.exe` reads to a human as `invexe.pdf`. Neither is
//      hypothetical: `JSON.stringify` escapes C0 controls and is therefore
//      often mistaken for enough, but it passes bidi overrides and C1
//      straight through.
//   2. A FILESYSTEM, via safeOutputName in ./transfer.js. That function
//      already refuses traversal and asserts the resolved path stays put.
//      What it did not do is refuse names that are hostile without
//      escaping anywhere: a newline forges a log line, `foo:stream` opens
//      an NTFS alternate data stream, and a trailing dot or space is
//      invisible in every UI ever built, so `a.exe. ` and `a.exe` look
//      identical to the person deciding whether to trust the file.
//
// Both sinks live here so the two policies cannot drift apart, and so
// there is exactly one answer to "what do we do with a hostile name".
//
// THE SPLIT, which is the whole design: display SANITIZES and never
// throws; writing REFUSES OR TRANSFORMS and says which. A display path
// that can throw turns an error report into a second error, and the
// moment we most need to print a name is when we are refusing it.

const { TransferError } = require('./errors')

// C0 (includes NUL and newline), DEL, and C1. C1 matters separately from
// C0 because a UTF-8 terminal decodes U+0080-U+009F to the 8-bit control
// set, where U+009B is a working CSI -- an escape sequence with no ESC
// byte in it, which is exactly the kind of thing a C0-only filter misses.
const CONTROL_CHARS = /[\x00-\x1f\x7f-\x9f]/
const CONTROL_CHARS_G = /[\x00-\x1f\x7f-\x9f]/g

// Explicit bidi overrides and isolates. These reorder the *rendering* of
// the characters after them without changing the bytes, which is what
// makes them a filename spoof rather than a curiosity. Not included: the
// implicit marks (U+200E/U+200F) and RTL script characters, because those
// are how right-to-left languages legitimately write filenames and
// refusing them would make the tool unusable in Hebrew or Arabic.
const BIDI_OVERRIDES = /[\u202a-\u202e\u2066-\u2069]/
const BIDI_OVERRIDES_G = /[\u202a-\u202e\u2066-\u2069]/g

// Illegal in a filename on Windows, and each one is a hazard somewhere
// else too: `:` opens an alternate data stream on NTFS and is rendered as
// `/` by the macOS Finder, and `<>|` are redirection operators in every
// shell that might later touch the file.
//
// APPLIED ON EVERY PLATFORM, unlike the device-name rename below, and the
// asymmetry is deliberate. `_aux.txt` on Linux is pure mangling: nothing
// on Linux cares about the name `aux`. `foo:stream`, by contrast, is
// hostile input wherever it lands -- it is a real attack on one of our
// target platforms, the file we write is routinely copied onward to
// another OS, and a transfer tool whose output filename depends on which
// OS received it is a tool that cannot be scripted. Nothing is hidden
// either way: the caller is handed both the written and the declared
// name, and the CLI prints a `renamed:` line whenever they differ.
const RESERVED_CHARS_G = /[<>:"|?*]/g

// Names Windows treats as devices no matter which directory they are in,
// so `aux.txt` is not an ordinary file there.
//
// THE COMMENT THIS REPLACES SAID "WINDOWS SHIPS FIRST". That is no longer
// true and was load-bearing for the decision: macOS and Linux are the
// primary targets and Windows is third (see docs/IMPLEMENTATION-PLAN.md,
// Stage 3). The rename survives the correction on a different argument --
// a file received on Linux is frequently opened on Windows later, and a
// name that is unopenable there is worth one prefix character to avoid --
// but it is now gated on the platform rather than applied everywhere, so
// the primary platforms stop paying for it.
const WINDOWS_RESERVED_NAMES = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/i

// Long enough that no legitimate name is truncated, short enough that a
// peer cannot push a screenful of text through a log line.
const MAX_DISPLAY_LENGTH = 120

// Most filesystems cap a single path component at 255 bytes.
const MAX_NAME_BYTES = 255

/**
 * Renders a peer-supplied string safely enough to print. Total: never
 * throws, always returns a string, for any input at all.
 *
 * Control and bidi characters are ESCAPED rather than stripped, which is
 * the one judgement call in here. Stripping produces a clean-looking
 * string and destroys the evidence -- `evil\nverified: ok` would print as
 * `evilverified: ok`, which is tidy and tells the reader nothing. The
 * escape shows that something was there and what it was.
 *
 * @param {unknown} value
 * @returns {string}
 */
function displayName (value) {
  if (typeof value !== 'string') return String(value)

  const escape = (/** @type {string} */ ch) => {
    const code = ch.codePointAt(0) || 0
    // The three a reader recognises on sight are worth naming; the rest
    // are unambiguous as hex and would only be noise as mnemonics.
    if (ch === '\n') return '\\n'
    if (ch === '\r') return '\\r'
    if (ch === '\t') return '\\t'
    return `\\u${code.toString(16).padStart(4, '0')}`
  }

  let out = value
    .replace(CONTROL_CHARS_G, escape)
    .replace(BIDI_OVERRIDES_G, escape)

  if (out.length > MAX_DISPLAY_LENGTH) {
    out = `${out.slice(0, MAX_DISPLAY_LENGTH)}... (${out.length} chars)`
  }
  return out
}

/**
 * The write policy: turn a peer's declared name into one we are willing
 * to create, or refuse it.
 *
 * Refusal and transformation are chosen per class, not by taste:
 *
 *   REFUSED      empty, over-long, control characters, bidi overrides,
 *                path separators, `.` and `..`
 *   TRANSFORMED  `<>:"|?*`, trailing dots and spaces, Windows device
 *                names (on Windows)
 *
 * The line between them is whether a correct sender could plausibly have
 * meant it. A file really can be called `report:2026`, and refusing the
 * whole transfer over one punctuation mark would be hostile. No correct
 * sender has ever named a file with a newline in it, and a name that
 * contains one is trying to forge a log line -- so that is refused, and
 * refused loudly, because the interesting thing is not the file but that
 * someone attempted it.
 *
 * @param {string} declaredName
 * @param {{ platform?: NodeJS.Platform | string }} [options]
 *   `platform` defaults to the host's. Injectable so tests can assert both
 *   policies on one machine, and so CI's three-OS matrix asserts the same
 *   thing on all three rather than each OS testing only its own branch.
 * @returns {string} the name to write, which may differ from the input
 * @throws {TransferError} ERR_UNSAFE_NAME
 */
function safeWriteName (declaredName, { platform = process.platform } = {}) {
  const unsafe = (/** @type {string} */ detail) => new TransferError(
    'ERR_UNSAFE_NAME',
    `refusing the peer's filename ${JSON.stringify(displayName(declaredName))}: ${detail}`,
    { declaredName, detail }
  )

  if (typeof declaredName !== 'string') throw unsafe('it is not a string')
  if (declaredName.length === 0) throw unsafe('it is empty')
  if (Buffer.byteLength(declaredName, 'utf8') > MAX_NAME_BYTES) {
    throw unsafe(`it is longer than ${MAX_NAME_BYTES} bytes`)
  }

  // Before anything else: these are the ones where the attempt itself is
  // the finding, so they are named precisely rather than lumped together.
  if (declaredName.includes('\0')) throw unsafe('it contains a NUL byte')
  if (CONTROL_CHARS.test(declaredName)) throw unsafe('it contains control characters')
  if (BIDI_OVERRIDES.test(declaredName)) {
    throw unsafe('it contains a bidirectional override, which disguises a filename by reversing how it is displayed')
  }

  // Checked against both separators regardless of platform:
  // `path.basename('..\\..\\x')` is 'x' on Windows and the entire string
  // on POSIX, so a single basename() call silently means different things
  // depending on where the receiver happens to run.
  if (declaredName.includes('/') || declaredName.includes('\\')) throw unsafe('it contains a path separator')
  if (declaredName === '.' || declaredName === '..') throw unsafe('it is a directory reference')

  // A leading dot is NOT stripped. `.bashrc` as a filename *inside* the
  // output directory is a legitimate thing to send, and mangling it would
  // be the kind of helpfulness that makes a tool untrustworthy. What made
  // `../../.bashrc` dangerous is the traversal, refused above, not the dot.
  let name = declaredName.replace(RESERVED_CHARS_G, '_')

  // Trailing dots and spaces are invisible in every file manager and
  // terminal, so they exist only to make two different names look like
  // one. Windows strips them itself before resolving a path, which makes
  // them an outright evasion there; everywhere else they are merely a
  // disguise, and worth removing on the same grounds.
  name = name.replace(/[. ]+$/, '')

  // Everything above can empty the name -- '...' and '   ' both survive
  // the earlier checks and strip to nothing.
  if (name.length === 0) throw unsafe('it is empty once trailing dots and spaces are removed')

  if (platform === 'win32') {
    const stem = name.split('.')[0]
    if (WINDOWS_RESERVED_NAMES.test(stem)) name = `_${name}`
  }

  return name
}

module.exports = {
  displayName,
  safeWriteName,
  MAX_DISPLAY_LENGTH,
  MAX_NAME_BYTES
}
