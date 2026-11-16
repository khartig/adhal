'use strict'

// Loaded with `node --require` into a CLI a test spawns: records every relay
// token blind-relay's token() makes in that process, as one JSON line per
// call appended to the file named by ADHAL_TEST_TOKEN_LOG. Each line has
// the process, how many arguments the call was given, and the token.
//
// hyperdht makes a relay token with `relay.token()` (lib/connect.js and
// lib/server.js, 6.36.0), reading the property at call time, so wrapping
// it on the module's exports sees every call. THREAT-MODEL.md section 8,
// gate 3, is the reason: a token the relay pairs on has to be one of these,
// made from nothing passed in.
//
// A preload, not an option in the CLIs, for the reason
// fail-punch-preload.js gives.

const Module = require('node:module')
const fs = require('node:fs')

const log = process.env.ADHAL_TEST_TOKEN_LOG

/** @type {any} */
const loader = Module
const load = loader._load
let wrapped = false

loader._load = function (/** @type {string} */ request, /** @type {any[]} */ ...rest) {
  const exported = load.call(this, request, ...rest)
  if (request !== 'blind-relay' || wrapped || !log) return exported
  wrapped = true
  const token = exported.token
  exported.token = function (/** @type {any[]} */ ...args) {
    const buf = token.apply(this, args)
    fs.appendFileSync(/** @type {string} */ (log), JSON.stringify({ pid: process.pid, args: args.length, token: Buffer.from(buf).toString('hex') }) + '\n')
    return buf
  }
  return exported
}
