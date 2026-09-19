'use strict'

// Terminal QR rendering for the drop code. This lives in cli/ rather than engine/
// on purpose: engine/ owns the code as a value (engine/src/code.js), and
// every surface draws the symbol its own way -- the Phase B desktop UI will
// hand the same payload to a canvas or an <svg>, not to half-block
// characters. Only the payload string is shared.

const qrcode = require('qrcode-generator')

// Error correction level Q (recovers ~25% damage) rather than the usual M
// (~15%). This is free, and the reason is the uppercasing in
// `encodeQrPayload`: QR's alphanumeric mode is denser than byte mode, and
// measured against the worst-case 41-character payload (six five-letter
// words) the saving is exactly one version's worth of headroom --
//
//   ECC   alphanumeric   byte
//   L     v2 (25x25)     v3 (29x29)
//   M     v3 (29x29)     v3 (29x29)
//   Q     v3 (29x29)     v4 (33x33)
//   H     v4 (33x33)     v5 (37x37)
//
// -- so spending it on error correction keeps the symbol at 29x29 while
// making it more tolerant of the things that actually break a scan off a
// screen: glare, moire against the other display's pixel grid, and a phone
// camera that will not quite focus. Growing it to 33x33 instead would have
// worked against that on the cheap Android cameras of plan section 9
// spike 5.
const ECC_LEVEL = 'Q'

// The QR specification requires a 4-module light border; a symbol printed
// flush against surrounding text is materially harder to acquire.
const QUIET_ZONE = 4

// Black on bright white, set explicitly per line. A QR code is only
// scannable as dark-on-light, and without forcing both halves the symbol
// inherits the user's theme -- inverted on any dark terminal, which is
// most of them, and a coin flip as to whether a given decoder copes.
const DARK_ON_LIGHT = '\x1b[30;107m'
const RESET = '\x1b[0m'

// Two vertical modules per character cell, indexed by (top, bottom). This
// is what keeps the symbol roughly square: a terminal cell is about twice
// as tall as it is wide, so packing two modules into one cell undoes that.
const HALF_BLOCKS = {
  'light,light': ' ',
  'dark,light': '▀', // UPPER HALF BLOCK
  'light,dark': '▄', // LOWER HALF BLOCK
  'dark,dark': '█' // FULL BLOCK
}

/**
 * Renders `payload` as a QR symbol made of text.
 *
 * @param {string} payload the string to encode, e.g. from encodeQrPayload
 * @param {{ wide?: boolean, color?: boolean }} [options]
 *   `wide` uses two full-block characters per module instead of half
 *   blocks -- twice the width and twice the height. However, it needs only
 *   U+2588, which some older Windows console fonts have when they lack the
 *   half blocks. `color` set false omits the ANSI colors (see
 *   DARK_ON_LIGHT for why that is a downgrade, not a neutral choice).
 * @returns {string}
 */
function renderQr (payload, { wide = false, color = true } = {}) {
  // typeNumber 0 lets the library pick the smallest version that fits.
  // 'Alphanumeric' is asserted rather than auto-detected so that a payload
  // which is not uppercase-safe fails loudly here instead of silently
  // costing a version -- encodeQrPayload guarantees the character set.
  const qr = qrcode(0, ECC_LEVEL)
  qr.addData(payload, 'Alphanumeric')
  qr.make()

  const count = qr.getModuleCount()
  const total = count + QUIET_ZONE * 2

  // isDark() throws outside the symbol, so the quiet zone is handled here
  // rather than by asking the library for out-of-range modules.
  const isDark = (row, col) => {
    const r = row - QUIET_ZONE
    const c = col - QUIET_ZONE
    if (r < 0 || c < 0 || r >= count || c >= count) return false
    return qr.isDark(r, c)
  }

  const paint = (line) => (color ? `${DARK_ON_LIGHT}${line}${RESET}` : line)
  const lines = []

  if (wide) {
    for (let row = 0; row < total; row++) {
      let line = ''
      for (let col = 0; col < total; col++) {
        line += isDark(row, col) ? '██' : '  '
      }
      lines.push(paint(line))
    }
  } else {
    // Step two rows at a time. `total` is even whenever the quiet zone is,
    // since every QR version has an odd module count -- but guard anyway,
    // because a bottom row read past the end must come back light, not
    // dark, or the symbol grows a spurious black edge.
    for (let row = 0; row < total; row += 2) {
      let line = ''
      for (let col = 0; col < total; col++) {
        const top = isDark(row, col) ? 'dark' : 'light'
        const bottom = row + 1 < total && isDark(row + 1, col) ? 'dark' : 'light'
        line += HALF_BLOCKS[`${top},${bottom}`]
      }
      lines.push(paint(line))
    }
  }

  return lines.join('\n')
}

/**
 * Prints the symbol to stdout, honoring two environment overrides:
 * QUAY_QR_WIDE=1 for the full-block variant, and NO_COLOR (the usual
 * convention) to drop the ANSI colors.
 *
 * @param {string} payload
 */
function printQr (payload) {
  console.log(renderQr(payload, {
    wide: process.env.QUAY_QR_WIDE === '1',
    color: !process.env.NO_COLOR
  }))
}

module.exports = { renderQr, printQr, ECC_LEVEL, QUIET_ZONE }
