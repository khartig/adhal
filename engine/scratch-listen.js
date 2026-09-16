'use strict'
// Diagnostic: does becoming a *server* work on this network?
//
// hyperswarm's PeerDiscovery._refresh() awaits swarm.listen() before it
// runs any lookup query when isServer is true (the default for
// swarm.join()). If listen() or announce() stalls here, no lookup ever
// happens and the join reports "no peer found" having never actually
// looked. Raw dht.lookup() does neither, which is why it succeeded.

const Hyperswarm = require('hyperswarm')
const os = require('node:os')

const t0 = Date.now()
const log = (...a) => console.log(`+${((Date.now() - t0) / 1000).toFixed(1)}s`, ...a)

function withTimeout (promise, ms, label) {
  return Promise.race([
    promise.then(() => `${label}: OK`),
    new Promise((resolve) => setTimeout(() => resolve(`${label}: STALLED (>${ms}ms)`), ms))
  ])
}

async function main () {
  log(`host machine: ${os.hostname()} (${os.platform()})`)

  const swarm = new Hyperswarm()
  await swarm.dht.ready()
  log(`dht ready: host=${swarm.dht.host}:${swarm.dht.port} firewalled=${swarm.dht.firewalled}`)

  log(await withTimeout(swarm.listen(), 30000, 'swarm.listen()'))
  log(`server relayAddresses: ${JSON.stringify(swarm.server.relayAddresses || [])}`)

  const topic = require('hypercore-crypto').hash(Buffer.from('quay-listen-probe', 'utf8'))
  const announce = swarm.dht.announce(topic, swarm.keyPair, swarm.server.relayAddresses)
  log(await withTimeout(announce.finished(), 30000, 'dht.announce()'))

  await swarm.destroy()
  log('done')
}

main().catch((err) => {
  console.error('failed:', err.message)
  process.exit(1)
})
