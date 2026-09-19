'use strict'
// Diagnostic receiver: announces a topic and accepts connections FOREVER.
//
// swarm-receive.js resolves on its first peer and then exits, so each
// diagnostic dial costs a manual restart on the other machine. This stays
// up, so the far side can probe repeatedly.
//
// It mimics acceptOnce's handshake (see engine/src/swarm.js) so a real
// swarm-send.js can also connect to it -- it just won't read the file. That
// now includes the code proof's code proof: what a genuine sender answers with is
// an HMAC over our challenge, so this reports three outcomes rather than
// two -- a real sender, a peer that answered but could not prove it knows
// the code, and a raw dial that never answered at all.
//
// Usage: node scratch-serve.js <code>
//
// <code> is a six-word drop code in any casing or separator style, or the
// QR payload verbatim, or an opaque secret -- the same inputs swarm-send.js
// accepts, normalized the same way. That matters: this used to hash the
// argument literally, so an uppercased or space-separated code produced a
// valid but different topic and this process would sit announcing on a
// topic no sender was looking at, with nothing on screen to say so.

const Hyperswarm = require('hyperswarm')
const os = require('node:os')
const { resolveCode } = require('./src/resolve-code')
const {
  dropKey,
  makeNonce,
  bindPeers,
  proveRole,
  proofMatches,
  MessageReader,
  PROOF_SIZE,
  NONCE_SIZE
} = require('./src/proof')

const codeArg = process.argv[2]
if (!codeArg) {
  console.error('Usage: scratch-serve.js <code>')
  process.exit(1)
}

let code, topic
try {
  ({ code, topic } = resolveCode(codeArg, { allowOpaque: true }))
} catch (err) {
  console.error(`scratch-serve: ${err.message}`)
  process.exit(1)
}

const READY = Buffer.from([0x01])
const key = dropKey(code)
const t0 = Date.now()
const log = (...a) => console.log(`+${((Date.now() - t0) / 1000).toFixed(1)}s`, ...a)

async function main () {
  log(`host machine: ${os.hostname()} (${os.platform()})`)

  const swarm = new Hyperswarm()

  await swarm.dht.ready()
  log(`dht ready: host=${swarm.dht.host}:${swarm.dht.port} firewalled=${swarm.dht.firewalled}`)
  log(`my public key: ${swarm.keyPair.publicKey.toString('hex')}`)
  // Print the canonical code, not the raw argument, so a normalization
  // difference between the two machines is visible here rather than
  // showing up only as a topic that no sender is looking at.
  log(`code: ${code}`)
  log(`topic: ${topic.toString('hex')}`)

  let n = 0
  swarm.on('connection', (socket, peerInfo) => {
    const id = ++n
    log(`*** CONNECTION #${id} from ${peerInfo.publicKey.toString('hex').slice(0, 12)} ***`)
    socket.on('error', (err) => log(`  #${id} socket error: ${err.message}`))
    socket.on('close', () => log(`  #${id} closed`))
    // Distinguishing a real sender from a raw dial is the whole point of
    // running this: a raw dial (scratch-lookup.js --connect,
    // scratch-hs-dial.js) proves the punch worked, while a valid proof
    // shows the application handshake worked too. Read by byte count, not
    // by chunk, for the reason engine/src/proof.js gives.
    const nonceR = makeNonce()
    const peers = bindPeers(socket, 'receiver')
    const reader = new MessageReader()
    let answered = false
    socket.on('data', (chunk) => {
      if (answered) return
      reader.push(chunk)
      const message = reader.take(PROOF_SIZE + NONCE_SIZE)
      if (!message) return
      answered = true
      const theirProof = message.subarray(0, PROOF_SIZE)
      const nonceS = message.subarray(PROOF_SIZE)
      if (proofMatches(proveRole(key, 'sender', nonceR, peers), theirProof)) {
        log(`  #${id} VALID PROOF -- a real sender completed the handshake`)
        // Answer, so the sender's own connectOnce resolves and it reports
        // success too. Without this the far side would discard us and keep
        // looking, which looks identical to a failure on its screen.
        socket.write(proveRole(key, 'receiver', nonceS, peers))
      } else {
        log(`  #${id} BAD PROOF -- answered the challenge but does not know the code`)
        log('       (or is running a build from before the proof landed)')
      }
    })
    socket.write(Buffer.concat([READY, nonceR]))
    log(`  #${id} wrote READY + challenge, staying open`)
  })

  const discovery = swarm.join(topic)
  discovery.flushed().then(
    () => log('ANNOUNCED -- ready for dials, will stay up until Ctrl-C'),
    (err) => log(`announce failed: ${err.message}`)
  )

  // Re-announce periodically so the record cannot go stale while idle.
  setInterval(() => {
    discovery.refresh({ client: true, server: true }).catch(() => {})
  }, 30000)

  setInterval(() => {
    log(`tick: connections=${swarm.connections.size} peers=${swarm.peers.size}`)
  }, 30000)
}

main().catch((err) => {
  console.error('failed:', err.message)
  process.exit(1)
})
