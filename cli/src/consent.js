'use strict'

// Asking a person before a file is written (Q-02, decision 5).
//
// THE GAP THIS CLOSES. The engine has had an accept gate since W11: an
// offer is answered ACCEPT or DECLINE before a byte of the file moves. But
// neither receiver passed `onOffer`, so the only party answering was the
// engine's own checks, and anyone holding the code could put any file that
// passed them into the output directory. Holding the code is meant to be
// the right to OFFER a file, not the right to deliver one.
//
// THREE ANSWERS, in the order they are tried:
//   - `--yes`: accept without asking. For scripts, and for a person who
//     has already decided.
//   - a terminal on stdin: show the offer and ask, defaulting to no.
//   - neither: decline, and say how to accept unattended. Hanging on a
//     prompt nobody can see, or silently accepting, are the two failures
//     this replaces.
//
// A risky name is warned about in every case, `--yes` included: the flag
// says "take whatever arrives", not "and don't tell me what it was".

const readline = require('node:readline/promises')
const { displayName } = require('@ad-hal/engine')
const { formatBytes } = require('./progress')

// Extensions that make a file dangerous to open, by what opening them
// does. Lowercase, without the dot. Not exhaustive and cannot be: the
// point is the common cases, where a person double-clicking would run
// something rather than view it.
/** @type {Array<[string, string[]]>} */
const RISKY = [
  ['a program or installer', [
    'exe', 'com', 'scr', 'pif', 'cpl', 'msi', 'msp', 'msix', 'msixbundle', 'appx', 'appxbundle',
    'app', 'apk', 'aab', 'ipa', 'deb', 'rpm', 'pkg', 'mpkg', 'run', 'appimage', 'jar', 'xpi', 'crx',
    'gadget', 'dll', 'sys', 'drv', 'ocx', 'so', 'dylib'
  ]],
  ['a script', [
    'sh', 'bash', 'zsh', 'ksh', 'csh', 'fish', 'command', 'tool', 'bat', 'cmd', 'ps1', 'psm1', 'psd1',
    'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'hta', 'py', 'pyw', 'pl', 'rb', 'php', 'lua', 'scpt',
    'applescript', 'workflow', 'ahk'
  ]],
  ['a shortcut or settings file that can run commands', [
    'lnk', 'url', 'desktop', 'inf', 'reg', 'scf', 'library-ms', 'settingcontent-ms'
  ]],
  // Mounting one is a double-click, and what it holds is not checked by
  // anything that checks a downloaded file.
  ['a disk image', ['dmg', 'iso', 'img', 'vhd', 'vhdx']],
  ['a document that can carry macros', ['docm', 'dotm', 'xlsm', 'xltm', 'xlam', 'pptm', 'potm', 'ppam', 'sldm']],
  ['an archive', ['zip', '7z', 'rar', 'tar', 'gz', 'tgz', 'bz2', 'tbz2', 'xz', 'txz', 'zst', 'lz', 'lzma', 'cab', 'arj', 'z', 'ace']]
]

/** @type {Map<string, string>} */
const RISK_BY_EXTENSION = new Map(RISKY.flatMap(([what, list]) => list.map((ext) => [ext, what])))

// What a disguised program pretends to be. `invoice.pdf.exe` shows as
// `invoice.pdf` wherever known extensions are hidden, which is the Windows
// default.
const DECOYS = new Set([
  'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odp', 'rtf', 'txt', 'csv', 'md',
  'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'heic', 'tif', 'tiff', 'svg',
  'mp3', 'mp4', 'm4a', 'mov', 'avi', 'mkv', 'wav', 'flac', 'html', 'htm'
])

/**
 * The warning a file's name deserves, or null.
 *
 * Judged on the name that will be WRITTEN, not the one the peer asked
 * for: what opening the file does depends on the name on disk. That name
 * has already had its trailing dots and spaces stripped and any bidi
 * override refused (safeWriteName), so neither can hide an extension here.
 *
 * @param {string} name
 * @returns {string | null}
 */
function riskWarning (name) {
  const parts = name.toLowerCase().split('.')
  if (parts.length < 2) return null
  const ext = parts[parts.length - 1]
  const what = RISK_BY_EXTENSION.get(ext)
  if (!what) return null
  const shown = JSON.stringify(displayName(name))

  // An archive of photos may well be `holiday.jpg.zip`; a program called
  // `invoice.pdf.exe` has no innocent reading.
  const before = parts.length > 2 ? parts[parts.length - 2].trim() : ''
  if (DECOYS.has(before) && what !== 'an archive') {
    return `${shown} is ${what} (.${ext}) made to look like a .${before} file, which is how malware is disguised. Do not open it.`
  }
  if (what === 'an archive') {
    return `${shown} is an archive (.${ext}), which can hold programs. Check what is inside before opening anything in it.`
  }
  return `${shown} is ${what} (.${ext}). Opening it can run code on this machine: open it only if you know who sent it and expected it.`
}

/**
 * The offer, as lines a person can decide on.
 *
 * @param {{ name: string, declaredName: string, size: number | null, sha256: string | null, partial?: number }} offer
 * @returns {string[]}
 */
function describeOffer (offer) {
  const size = offer.size === null
    ? 'streamed, size unknown'
    : `${formatBytes(offer.size)}${offer.size >= 1024 ? `, ${offer.size} bytes` : ''}`
  const lines = [`offer: ${JSON.stringify(displayName(offer.name))} (${size})`]
  if (offer.name !== offer.declaredName) {
    lines.push(`  the sender asked for ${JSON.stringify(displayName(offer.declaredName))}; it would be saved under the name above`)
  }
  lines.push(offer.sha256 === null
    ? '  sha256: sent when the stream ends, and checked then'
    : `  sha256: ${offer.sha256} (the sender's claim; the file is checked against it before it is saved)`)
  if (offer.partial && offer.size !== null) {
    lines.push(`  resume: an earlier, interrupted attempt left ${formatBytes(offer.partial)} of this file; if those bytes match the sender's, only the rest is fetched`)
  }
  return lines
}

/**
 * @param {{
 *   yes: boolean,
 *   label: string,
 *   log?: (line: string) => void,
 *   input?: NodeJS.ReadableStream & { isTTY?: boolean },
 *   output?: NodeJS.WritableStream,
 *   signal?: AbortSignal,
 *   onInterrupt?: () => void
 * }} options
 *   `signal` is the CLI's cancel signal: a cancel while the question is on
 *   screen takes the question down. `onInterrupt` is Ctrl-C at the
 *   question, which a terminal in raw mode delivers to readline rather
 *   than as a signal; the CLIs route it back to their cancel handler.
 * @returns {{ onOffer: (offer: any) => Promise<boolean | string>, close: () => void }}
 *   `close` takes down a question still waiting once the transfer has
 *   ended some other way -- the sender canceled or gave up -- so that it
 *   does not hold the process open.
 */
function createConsent ({
  yes,
  label,
  log = console.log,
  input = process.stdin,
  output = process.stderr,
  signal,
  onInterrupt = () => { process.emit('SIGINT', 'SIGINT') }
}) {
  const say = (/** @type {string} */ line) => log(`[${label}] ${line}`)
  let closed = false
  // The question on screen, if any. Taking it down closes the interface
  // and ends its line, synchronously, so whatever the CLI prints next --
  // the cancel handler's line, or the reason the transfer failed -- starts
  // on a line of its own. Not readline's own `signal` option: an aborted
  // question writes its own line ending, after whatever the abort's other
  // listeners have already printed on the question's line.
  /** @type {import('node:readline/promises').Interface | null} */
  let current = null
  const takeDown = () => {
    if (!current) return
    const rl = current
    current = null
    rl.close()
    output.write('\n')
  }
  // A verdict that never comes. The transfer is already ending some other
  // way, and answering now would put a DECLINE on the wire behind a
  // CANCEL, and report "declined" for something that was canceled.
  /** @returns {Promise<never>} */
  const unanswered = () => new Promise(() => {})

  /** @param {any} offer */
  async function onOffer (offer) {
    const risk = riskWarning(offer.name)

    if (yes) {
      if (risk) say(`WARNING: ${risk}`)
      return true
    }

    for (const line of describeOffer(offer)) say(line)
    if (risk) say(`WARNING: ${risk}`)

    if (!input.isTTY) {
      say('no terminal to ask on, so the offer is declined. Pass --yes to accept offers without being asked.')
      // What the sender reads. It says why without saying anything about
      // this machine.
      return 'the receiver is not at a terminal to accept it, and was not started with --yes'
    }

    if (closed || (signal && signal.aborted)) return unanswered()
    const rl = readline.createInterface({ input, output, terminal: true })
    current = rl
    rl.on('SIGINT', () => {
      takeDown()
      onInterrupt()
    })
    if (signal) signal.addEventListener('abort', takeDown, { once: true })
    let answer
    try {
      answer = await rl.question('accept this file? [y/N] ')
    } catch {
      takeDown()
      return unanswered()
    } finally {
      if (signal) signal.removeEventListener('abort', takeDown)
    }
    // Taken down while an answer was on its way in.
    if (current !== rl) return unanswered()
    current = null
    rl.close()
    // Anything but a yes is a no, an empty line included: the default is
    // the answer that writes nothing. A no carries its own reason, because
    // a bare `false` sends the engine's default sentence, and the sender's
    // report then reads "the receiver declined the file: the receiver
    // declined the file".
    return /^\s*y(es)?\s*$/i.test(answer) || 'not accepted at the prompt'
  }

  return {
    onOffer,
    close: () => {
      closed = true
      takeDown()
    }
  }
}

module.exports = { createConsent, riskWarning, describeOffer, RISK_BY_EXTENSION }
