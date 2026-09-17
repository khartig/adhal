#!/usr/bin/env node
'use strict'

// Item 3's deliverable as a thing you can look at: "6-word code + QR
// encoding of the same payload. UX object exists; you can screenshot it."
//
// Usage: code.js              generate a new drop code and show its QR
//        code.js <code>       re-render an existing code (verifies it too)
//        code.js --payload    print only the QR payload string, no symbol
//
// QUAY_QR_WIDE=1 switches to full-block rendering for console fonts
// lacking the half-block glyphs; NO_COLOR drops the ANSI colors.

const { generateCode, parseCode, encodeQrPayload, resolveCode, CODE_ENTROPY_BITS, WORD_COUNT } = require('@quay/engine')
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
  console.log(`  code:    ${code}`)
  console.log(`  payload: ${payload}`)
  // The topic is printed because it is what the DHT actually sees, which
  // makes this the fastest way to get an argument for engine/scratch-lookup.js.
  console.log(`  topic:   ${resolveCode(code).topic.toString('hex')}`)
  console.log(`  entropy: ${CODE_ENTROPY_BITS.toFixed(1)} bits (${WORD_COUNT} words)`)
  console.log()
}

main()
