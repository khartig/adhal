'use strict'

// Terminal QR rendering for the drop code. This lives in cli/ rather than engine/
// on purpose: engine/ owns the code as a value (engine/src/code.js), and
// every surface draws the symbol its own way -- a desktop UI (Stage 3) would
// hand the same payload to a canvas or an <svg>, not to half-block
// characters. Only the payload string is shared.

const qrcode = require('qrcode-generator')

// Error correction level H (recovers ~30% damage) rather than the usual M
// (~15%), and the uppercasing in `encodeQrPayload` is what keeps that
// affordable: QR's alphanumeric mode is denser than byte mode, so the same
// payload costs one version less at every level.
//
// Re-measured against the vendored encoder when W15a moved to the EFF
// large wordlist. The worst case is now 56 characters: the 7-character
// ADHAL2: scheme, five 9-letter words, and four separators.
//
//   ECC   worst case alnum (56)   worst case byte (56)
//   L     v3 (29x29)              33x33
//   M     v3 (29x29)              33x33
//   Q     v4 (33x33)              37x37
//   H     v5 (37x37)              41x41
//
// Over 20,000 generated codes at H (mean payload 46 characters): 90.6%
// are 33x33, 9.2% are 37x37, and 0.2% are 29x29.
//
// H IS KEPT, and it now costs something. Under the short wordlist every
// code fit 29x29 at H; the longer words gave that back, and the symbol is
// a version or two larger than it was. H is still the level that matters
// for this deliverable's actual failures -- glare, moire against the other
// display's pixel grid, and a phone camera that will not quite focus off a
// screen -- and a 33x33 or 37x37 symbol drawn in half-blocks still fits a
// standard terminal. Q would hold the worst case at 33x33 for ~25% damage
// tolerance instead of ~30%; that is the lever if the size ever matters
// more than the margin.
//
// The uppercase argument survives unchanged: byte mode costs one more
// version at every level in the table.
const ECC_LEVEL = 'H'

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
 * Prints the symbol, to stdout unless `log` says otherwise, honoring two
 * environment overrides: ADHAL_QR_WIDE=1 for the full-block variant, and
 * NO_COLOR (the usual convention) to drop the ANSI colors.
 *
 * @param {string} payload
 * @param {(text: string) => void} [log] where the lines go; a receiver
 *   writing the file to stdout sends them to stderr
 */
function printQr (payload, log = console.log) {
  log(renderQr(payload, {
    wide: process.env.ADHAL_QR_WIDE === '1',
    color: !process.env.NO_COLOR
  }))
}

module.exports = { renderQr, printQr, ECC_LEVEL, QUIET_ZONE }
