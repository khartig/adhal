'use strict'

// Diagnostic: how often, and how slowly, acceptOnce/connectOnce pair on a
// local HyperDHT testnet, and whether hyperdht's LAN-shortcut race is the
// reason. See UNANSWERED_CONNECTION_MS in src/swarm.js for the mechanism,
// and IMPLEMENTATION-PLAN.md W15d for the measurements this produced.
//
// Usage: node scratch-pairing-race.js [trials] [--unanswered=<ms>] [--counterfactual] [-v]
//
//   --unanswered=0    turn the engine's dead-connection check off
//   --counterfactual  stop hyperdht's server destroying its raw stream when
//                     it aborts a holepunch -- the race's cause. With it,
//                     every pairing should take the fast path; if one does
//                     not, the stall has another cause too.
//   -v                print every connection event, not only the slow trials
//
// Worth re-running after any hyperdht or hyperswarm upgrade: if the
// counterfactual stops making a difference, the race has been fixed
// upstream and UNANSWERED_CONNECTION_MS is guarding against nothing.
//
// Both peers run in this one process, which is not the same as two
// processes: the race went both ways here, and the same way every time
// between two processes. Measure that with two real CLIs.

const createTestnet = require('hyperdht/testnet')
const { createSwarm, acceptOnce, connectOnce, topicFromNameplate, splitCode, generateCode } = require('./src')

const args = process.argv.slice(2)
const trials = Number(args.find((a) => /^\d+$/.test(a)) || 8)
const unansweredArg = args.find((a) => a.startsWith('--unanswered='))
const extra = unansweredArg ? { unansweredTimeout: Number(unansweredArg.split('=')[1]) } : {}
const counterfactual = args.includes('--counterfactual')
const verbose = args.includes('-v')

// The counterfactual: while a handshake's raw stream is still unclaimed,
// make hyperdht's holepunch abort leave it alone, so the LAN shortcut can
// still arrive on it. Private API, pinned version; diagnostic only.
function suppressAbort (swarm) {
  const server = swarm.server
  const real = server._onpeerholepunch.bind(server)
  server._onpeerholepunch = async (msg, req) => {
    const h = msg.id < server._holepunches.length ? server._holepunches[msg.id] : null
    if (!h || !h.rawStream || h.rawStream.connected) return real(msg, req)
    const abort = server._abort
    server._abort = () => null
    try { return await real(msg, req) } finally { server._abort = abort }
  }
}

function watch (swarm, label, t0, lines) {
  const at = () => ((Date.now() - t0) / 1000).toFixed(2)
  swarm.on('connection', (socket, info) => {
    lines.push(`${at()} ${label} connection (${info.client ? 'we dialed' : 'they dialed'})`)
    socket.on('close', () => {
      const raw = socket.rawStream
      lines.push(`${at()} ${label} close, packets received: ${raw ? raw.packetsReceived : '?'}`)
    })
  })
}

async function trial (testnet) {
  const parts = splitCode(generateCode())
  const topic = topicFromNameplate(parts.nameplate)
  const t0 = Date.now()
  const lines = []
  const rs = createSwarm({ bootstrap: testnet.bootstrap })
  const ss = createSwarm({ bootstrap: testnet.bootstrap })
  if (counterfactual) { suppressAbort(rs); suppressAbort(ss) }
  watch(rs, 'R', t0, lines)
  watch(ss, 'S', t0, lines)
  const onCandidateDropped = (label) => (_info, reason) => lines.push(`${((Date.now() - t0) / 1000).toFixed(2)} ${label} dropped: ${reason}`)
  const [rx, tx] = await Promise.all([
    acceptOnce(rs, topic, { ...parts, ...extra, timeout: 120000, onCandidateDropped: onCandidateDropped('R') }),
    connectOnce(ss, topic, { ...parts, ...extra, timeout: 120000, onCandidateDropped: onCandidateDropped('S') })
  ])
  const ms = Date.now() - t0
  rx.stopAnswering()
  tx.stopAnswering()
  await Promise.all([rs.destroy(), ss.destroy()])
  return { ms, lines }
}

async function main () {
  const testnet = await createTestnet(3)
  const times = []
  try {
    for (let i = 0; i < trials; i++) {
      const { ms, lines } = await trial(testnet)
      times.push(ms)
      // ~4 s is the first REFRESH_INTERVAL re-lookup; the race costs >10 s.
      const slow = ms > 10000
      console.log(`trial ${i + 1}/${trials}: paired in ${(ms / 1000).toFixed(1)}s${slow ? '  SLOW' : ''}`)
      if (verbose || slow) for (const line of lines) console.log(`    ${line}`)
    }
  } finally {
    await testnet.destroy()
  }
  const sorted = [...times].sort((a, b) => a - b)
  console.log(
    `\n${counterfactual ? 'counterfactual, ' : ''}unanswered=${unansweredArg ? extra.unansweredTimeout : 'default'}: ` +
    `${times.filter((t) => t > 10000).length}/${trials} slow, median ${(sorted[Math.floor(sorted.length / 2)] / 1000).toFixed(1)}s, ` +
    `max ${(sorted[sorted.length - 1] / 1000).toFixed(1)}s`
  )
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
