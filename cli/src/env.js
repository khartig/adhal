'use strict'

// Environment overrides shared by the swarm CLIs. One file for the reason
// report.js is one file: two copies of a parser drift, and the copy that
// drifts is the one nobody is testing.

// The largest bootstrap list worth accepting. A real one is a handful of
// nodes; anything longer is a mistake or a paste gone wrong.
const MAX_BOOTSTRAP_NODES = 64

/**
 * ADHAL_BOOTSTRAP=<json> overrides the DHT bootstrap nodes: a JSON array
 * of `{ "host": string, "port": 1-65535 }`. Tests point it at an isolated
 * hyperdht testnet; nobody should need it on the public DHT.
 *
 * VALIDATED, NOT PASSED THROUGH (Q-17). This used to be `JSON.parse(raw)`
 * with no try/catch, handed to the DHT as-is: a typo crashed the CLI with
 * a stack trace, and a well-formed but wrong value went into HyperDHT to
 * fail somewhere less legible. Now a bad value is refused before any
 * network work, with a message naming the variable and the expected shape.
 * The value itself is not echoed back, beyond its length.
 *
 * @param {string | undefined} [raw]
 * @returns {Array<{ host: string, port: number }> | undefined}
 */
function parseBootstrap (raw = process.env.ADHAL_BOOTSTRAP) {
  if (raw === undefined || raw === '') return undefined
  const shape = 'a JSON array of {"host": "<name or address>", "port": <1-65535>}'

  let parsed
  try {
    parsed = JSON.parse(raw)
  } catch {
    throw new Error(`ADHAL_BOOTSTRAP is not valid JSON (${raw.length} characters); expected ${shape}`)
  }
  if (!Array.isArray(parsed) || parsed.length === 0 || parsed.length > MAX_BOOTSTRAP_NODES) {
    throw new Error(`ADHAL_BOOTSTRAP must be ${shape}, with 1 to ${MAX_BOOTSTRAP_NODES} entries`)
  }
  return parsed.map((node, i) => {
    const ok = node !== null && typeof node === 'object' &&
      typeof node.host === 'string' && node.host.length > 0 && node.host.length <= 253 &&
      /^[A-Za-z0-9.:\-[\]]+$/.test(node.host) &&
      Number.isInteger(node.port) && node.port >= 1 && node.port <= 65535
    if (!ok) throw new Error(`ADHAL_BOOTSTRAP entry ${i + 1} is not {"host": string, "port": 1-65535}`)
    return { host: node.host, port: node.port }
  })
}

module.exports = { parseBootstrap, MAX_BOOTSTRAP_NODES }
