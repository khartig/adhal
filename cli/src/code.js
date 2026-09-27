#!/usr/bin/env node
'use strict'

// The drop code as a thing you can look at: a 5-word code plus a QR
// encoding of the same payload. UX object exists; you can screenshot it.
//
// Usage: code.js              generate a new drop code and show its QR
//        code.js <code>       re-render an existing code (verifies it too)
//        code.js --payload    print only the QR payload string, no symbol
//
// ADHAL_QR_WIDE=1 switches to full-block rendering for console fonts
// lacking the half-block glyphs; NO_COLOR drops the ANSI colors.

const {
  generateCode,
  parseCode,
  splitCode,
  encodeQrPayload,
  resolveCode,
  NAMEPLATE_ENTROPY_BITS,
  SECRET_ENTROPY_BITS,
  NAMEPLATE_WORDS,
  SECRET_WORDS
} = require('@ad-hal/engine')
const { printQr } = require('./qr')

function main () {
  const args = process.argv.slice(2)
  const payloadOnly = args.includes('--payload')
  const positional = args.filter((a) => !a.startsWith('--'))

  if (positional.length > 1) {
    console.error('Usage: code.js [code] [--payload]')
    process.exitCode = 1
    return
  }

  let code
  if (positional.length === 1) {
    // Round-trip an existing code, so this doubles as a "why won't my code
    // work" check: parseCode names the bad word rather than just failing.
    try {
      code = parseCode(positional[0])
    } catch (err) {
      console.error(`[code] not a valid drop code: ${err.message}`)
      process.exitCode = 1
      return
    }
  } else {
    code = generateCode()
  }

  const payload = encodeQrPayload(code)

  if (payloadOnly) {
    console.log(payload)
    return
  }

  console.log()
  printQr(payload)
  console.log()
  const { nameplate, secret } = splitCode(code)
  console.log(`  code:    ${code}`)
  console.log(`  payload: ${payload}`)
  // Shown split, because under v2 the two halves are not the same kind of
  // thing and a reader who treats them alike will draw the wrong
  // conclusion from the topic line below. The nameplate is public the
  // moment the receiver announces; the secret is the only secret.
  console.log(`  parts:   nameplate=${nameplate}  secret=${secret}`)
  // The topic is printed because it is what the DHT actually sees, which
  // makes this the fastest way to get an argument for
  // engine/scratch-lookup.js. Note it is derived from the NAMEPLATE alone
  // -- that is the v2 change, and printing both on adjacent lines is what
  // makes it checkable by eye: the secret must not be recoverable from
  // anything here.
  console.log(`  topic:   ${resolveCode(code).topic.toString('hex')}`)
  // Two figures, not one. A single combined number would let ~51 bits
  // stand in for the strength of a ~31-bit secret, and only the secret's
  // entropy is load-bearing -- a nameplate collision is a rendezvous
  // accident the PAKE then separates, not a compromise.
  console.log(
    `  entropy: nameplate ${NAMEPLATE_ENTROPY_BITS.toFixed(1)} bits (${NAMEPLATE_WORDS} words, public), ` +
    `secret ${SECRET_ENTROPY_BITS.toFixed(1)} bits (${SECRET_WORDS} words)`
  )
  console.log()
}

main()
