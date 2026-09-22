'use strict'
// Diagnostic receiver: announces a topic and accepts connections FOREVER.
//
// swarm-receive.js resolves on its first peer and then exits, so each
// diagnostic dial costs a manual restart on the other machine. This stays
// up, so the far side can probe repeatedly.
//
// It mimics acceptOnce's handshake (see engine/src/swarm.js) so a real
// swarm-send.js can also connect to it -- it just won't read the file. That
// includes v2's PAKE: what a genuine sender answers with is a REPLY
// carrying Yb and a confirmation over the whole transcript, so this reports
// three outcomes rather than two -- a real sender, a peer that answered but
// could not confirm the secret, and a raw dial that never answered at all.
//
// Usage: node scratch-serve.js <code>
//
// <code> is a five-word drop code in any casing or separator style, or the
// QR payload verbatim, or an opaque secret -- the same inputs
// swarm-send.js accepts, normalized the same way. That matters: this used
// to hash the argument literally, so an uppercased or space-separated code
// produced a valid but different topic and this process would sit
// announcing on a topic no sender was looking at, with nothing on screen to
// say so.
//
// WHY THIS FILE HAD TO CHANGE FOR v2, correcting a claim in
// docs/ARCHITECTURE.md. That document said this tool needs no change across
// wire breaks "because it never reads a frame". True for the type-tag
// break, and FALSE for v2: this tool does not read frames, but it does
// implement the handshake by hand, and v2 replaced all three of its
// messages. It is now built on the same Initiator class swarm.js uses,
// which is the only way to keep "a real sender can connect to this" true
// without maintaining a second copy of the parameter mapping -- and a
// second copy is exactly how a diagnostic starts lying about what the
// product does.

const Hyperswarm = require('hyperswarm')
const os = require('node:os')
const { resolveCode } = require('./src/resolve-code')
const { MessageReader } = require('./src/reader')
const { Initiator, ERR_CONFIRMATION } = require('./src/handshake')

const codeArg = process.argv[2]
if (!codeArg) {
  console.error('Usage: scratch-serve.js <code>')
  process.exit(1)
}

let code, topic, nameplate, secret
try {
  ({ code, topic, nameplate, secret } = resolveCode(codeArg, { allowOpaque: true }))
} catch (err) {
  console.error(`scratch-serve: ${err.message}`)
  process.exit(1)
}

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
  // Printed split, because under v2 only the first half is in the topic.
  log(`nameplate: ${nameplate} (public)   secret: ${secret.length} chars (not shown)`)
  log(`topic: ${topic.toString('hex')}`)

  let n = 0
  swarm.on('connection', (socket, peerInfo) => {
    const id = ++n
    log(`*** CONNECTION #${id} from ${peerInfo.publicKey.toString('hex').slice(0, 12)} ***`)
    socket.on('error', (err) => log(`  #${id} socket error: ${err.message}`))
    socket.on('close', () => log(`  #${id} closed`))

    // Distinguishing a real sender from a raw dial is the whole point of
    // running this: a raw dial (scratch-lookup.js --connect,
    // scratch-hs-dial.js) proves the punch worked, while a valid
    // confirmation shows the application handshake worked too.
    //
    // Per connection, never hoisted out of this handler -- the same rule
    // swarm.js follows, and for the same reason (PROTOCOL.md section 3.2
    // trap #1). A long-lived diagnostic is the likeliest place to be
    // tempted into caching a scalar, and it is the worst place to do it:
    // this process may see dozens of connections.
    const handshake = new Initiator({ secret, nameplate })
    const reader = new MessageReader()
    let answered = false

    socket.on('data', (chunk) => {
      if (answered) return
      reader.push(chunk)
      let confirmed
      try {
        confirmed = handshake.readReply(reader)
      } catch (err) {
        answered = true
        if (err.code === ERR_CONFIRMATION) {
          log(`  #${id} BAD CONFIRMATION -- answered, but does not know the secret`)
          log('       (or is running a build from before the v2 wire change)')
        } else {
          log(`  #${id} REPLY REJECTED -- ${err.message}`)
        }
        return
      }
      if (!confirmed) return // still arriving; read by byte count, not by chunk

      answered = true
      log(`  #${id} VALID CONFIRMATION -- a real sender completed the handshake`)
      log(`       caps in common: ${confirmed.caps.length ? confirmed.caps.join(',') : '(none)'}`)
      // Answer, so the sender's own connectOnce resolves and it reports
      // success too. Without this the far side would discard us and keep
      // looking, which looks identical to a failure on its screen.
      socket.write(confirmed.confirm)
      // The channel keys are derived and deliberately unused: this tool
      // never reads a frame, and under v2 it could not read a sealed one
      // without becoming a second implementation of the transfer path.
    })

    socket.write(handshake.hello())
    log(`  #${id} wrote HELLO (sid ${handshake.sid.toString('hex').slice(0, 8)}...), staying open`)
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
