'use strict'
// How long a CANCEL actually takes to take effect, and how many bytes move
// in the meantime.
//
// PROTOCOL.md section 8.2 asserts that "CANCEL queues behind
// already-written chunks, so a cancel is delayed by roughly one chunk
// plus the high-water mark", and uses that to pose the Protomux question.
// Nobody had measured it. This script does, because the answer decides
// whether a second control channel would buy anything -- and the repo's
// verification standard is that a finding nobody executed is a
// hypothesis.
//
// TWO DIRECTIONS, AND THEY ARE NOT THE SAME NUMBER. The section conflates
// them:
//
//   sender cancels    -- the CANCEL frame is written into a stream the
//                        sender has already filled with chunk bytes, so
//                        it sits behind all of them. This is genuine
//                        head-of-line blocking, and the only one of the
//                        two a separate control channel could address.
//   receiver cancels  -- the CANCEL travels upstream, where nothing is
//                        queued, and is read promptly. What is delayed is
//                        the *effect*: the sender keeps pushing bytes
//                        until it reads, and everything already in flight
//                        still arrives. That is wasted upload, and no
//                        amount of multiplexing recovers it.
//
// The sweep over chunk size is the actual argument. If latency tracks
// write-ahead depth, the lever is depth -- pause the read stream sooner,
// send smaller chunks -- and not which framing layer carries the control
// message.
//
// LOOPBACK UNDERSTATES THIS. There is no propagation delay and the kernel
// moves bytes between two sockets in one host. A real path adds a round
// trip to every number below, and a slow one adds far more in-flight
// bytes. Read these as a floor.
//
// Usage:
//   node engine/scratch-cancel-latency.js
//   node engine/scratch-cancel-latency.js --size 64 --at 8
//
// Options: --size <MiB> file to transfer (default 32)
//          --at <MiB> offset to cancel at (default 4)
//          --trials <n> repeats per configuration (default 5)

const fs = require('node:fs')
const net = require('node:net')
const os = require('node:os')
const path = require('node:path')
const crypto = require('node:crypto')
const { sendFile, receiveFile, DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE } = require('./src')

function flag (name, fallback) {
  const i = process.argv.indexOf(`--${name}`)
  return i === -1 ? fallback : process.argv[i + 1]
}

const MIB = 1024 * 1024
const fileSize = Number(flag('size', 32)) * MIB
const cancelAt = Number(flag('at', 4)) * MIB
const trials = Number(flag('trials', 5))

// 64 KB is the default both CLIs use and the only size in production
// today; the others are here to show the trend, not because anything
// ships them. The top of the sweep is MAX_CHUNK_SIZE rather than a round
// 1 MiB, because 1 MiB is too many -- the frame cap has to hold the chunk
// plus its type tag and, since v2 sealed every frame, a 16-byte
// authenticator. A run at exactly 1 MiB is refused. That is PROTOCOL.md section 5's worked example,
// still true and now load-bearing for this sweep.
const CHUNK_SIZES = [16 * 1024, DEFAULT_CHUNK_SIZE, 256 * 1024, MAX_CHUNK_SIZE]

/** @param {number[]} xs */
const median = (xs) => {
  const ok = xs.filter((x) => Number.isFinite(x))
  return ok.length === 0 ? NaN : [...ok].sort((a, b) => a - b)[Math.floor(ok.length / 2)]
}
/** @param {number} n */
const kib = (n) => Number.isFinite(n) ? (n / 1024).toFixed(0) + ' KiB' : '    n/a'

/**
 * One transfer, canceled from one side at `cancelAt` bytes.
 *
 * Both ends run in this process so the *other* side's live byte counter
 * can be read at the instant of the abort. That is the only way to get
 * "bytes that moved after the cancel" without inferring it from a rate.
 *
 * @param {{ chunkSize: number, canceller: 'sender'|'receiver', filePath: string, outDir: string }} opts
 */
async function runOnce ({ chunkSize, canceller, filePath, outDir }) {
  const controller = new AbortController()
  let senderBytes = 0
  let receiverBytes = 0
  let abortedAt = 0n
  /** @type {{ sender: number, receiver: number }} */
  let atAbort = { sender: 0, receiver: 0 }

  const fire = () => {
    if (abortedAt) return
    atAbort = { sender: senderBytes, receiver: receiverBytes }
    abortedAt = process.hrtime.bigint()
    controller.abort('measuring cancel latency')
  }

  const server = net.createServer()
  await new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(undefined)))
  const port = /** @type {import('node:net').AddressInfo} */ (server.address()).port

  const accepted = new Promise((resolve) => server.once('connection', resolve))
  const client = net.connect(port, '127.0.0.1')
  await new Promise((resolve) => client.once('connect', () => resolve(undefined)))
  const serverSocket = /** @type {net.Socket} */ (await accepted)
  const highWaterMark = client.writableHighWaterMark

  // The sender writes on `client`; the receiver reads on `serverSocket`.
  // Each side is stamped as IT settles, not after both do. Timing the
  // pair would measure whichever finished last, which for the
  // receiver-cancels case is the wrong side entirely.
  /** @type {{ err: any, at: bigint }} */ let sendResult
  /** @type {{ err: any, at: bigint }} */ let recvResult
  const stamp = (/** @type {any} */ err) => ({ err, at: process.hrtime.bigint() })

  // Random rather than handshake-derived: both ends are in this process,
  // and what is measured here is cancel latency, not authentication. The
  // seal IS on the path, so its cost is in the numbers.
  const k1 = crypto.randomBytes(32)
  const k2 = crypto.randomBytes(32)

  const sending = sendFile(client, filePath, {
    sendKey: k1,
    receiveKey: k2,
    chunkSize,
    signal: canceller === 'sender' ? controller.signal : undefined,
    onProgress: ({ bytes }) => {
      senderBytes = bytes
      if (canceller === 'sender' && bytes >= cancelAt) fire()
    }
  }).then(() => stamp(null), stamp)

  const receiving = receiveFile(serverSocket, outDir, {
    sendKey: k2,
    receiveKey: k1,
    signal: canceller === 'receiver' ? controller.signal : undefined,
    checkSpace: false,
    onProgress: ({ bytes }) => {
      receiverBytes = bytes
      if (canceller === 'receiver' && bytes >= cancelAt) fire()
    }
  }).then(() => stamp(null), stamp)

  ;[sendResult, recvResult] = await Promise.all([sending, receiving])

  client.destroy()
  serverSocket.destroy()
  await new Promise((resolve) => server.close(() => resolve(undefined)))
  for (const name of fs.readdirSync(outDir)) fs.rmSync(path.join(outDir, name), { force: true })

  // The peer -- the side that did NOT abort -- is the one whose settling
  // tells us when the cancel landed.
  const peer = canceller === 'sender' ? recvResult : sendResult
  const own = canceller === 'sender' ? sendResult : recvResult
  if (!abortedAt) {
    // The cancel never fired, so there is no interval to report. Almost
    // always means the transfer failed before reaching the cancel offset;
    // returning NaN keeps it out of the median instead of poisoning it
    // with a since-boot timestamp.
    return { latencyMs: NaN, peerBytesAfter: NaN, peerCode: peer.err && peer.err.code, ownCode: own.err && own.err.code, highWaterMark }
  }
  return {
    latencyMs: Number(peer.at - abortedAt) / 1e6,
    // What the peer kept doing between being told to stop and noticing.
    peerBytesAfter: (canceller === 'sender' ? receiverBytes : senderBytes) -
      (canceller === 'sender' ? atAbort.receiver : atAbort.sender),
    peerCode: peer.err && peer.err.code,
    ownCode: own.err && own.err.code,
    highWaterMark
  }
}

async function main () {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'adhal-cancel-'))
  const filePath = path.join(tmp, 'payload.bin')
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'adhal-cancel-out-'))
  fs.writeFileSync(filePath, crypto.randomBytes(fileSize))

  console.log(`cancel latency over a real loopback TCP socket`)
  console.log(`  ${(fileSize / MIB).toFixed(0)} MiB file, cancelling at ${(cancelAt / MIB).toFixed(0)} MiB, ${trials} trials per cell`)
  console.log('')

  let hwm = 0
  try {
    for (const canceller of /** @type {const} */ (['sender', 'receiver'])) {
      console.log(`  ${canceller} cancels:`)
      for (const chunkSize of CHUNK_SIZES) {
        /** @type {any[]} */ const runs = []
        for (let t = 0; t < trials; t++) {
          runs.push(await runOnce({ chunkSize, canceller, filePath, outDir }))
        }
        // Both codes are printed because a run where the peer reported
        // something other than ERR_CANCELLED_PEER is not a slow cancel,
        // it is a different event, and averaging the two would hide it.
        const codes = new Set(runs.map((r) => `${r.ownCode}/${r.peerCode}`))
        // Bytes in flight is reported as a RANGE, not a median. It is set
        // by kernel socket buffers, which vary run to run by a factor of
        // two or more -- quoting a single number would invite a reader to
        // treat it as a constant of the protocol, which it is not.
        const moved = runs.map((r) => r.peerBytesAfter).filter(Number.isFinite)
        const spread = Math.min(...moved) === Math.max(...moved)
          ? kib(moved[0])
          : `${kib(Math.min(...moved))}-${kib(Math.max(...moved))}`
        console.log(
          `    chunk ${kib(chunkSize).padStart(8)}  ` +
          `latency ${median(runs.map((r) => r.latencyMs)).toFixed(1).padStart(6)} ms  ` +
          `peer moved ${spread.padStart(18)} after being told to stop  ` +
          `[${[...codes].join(' ')}]`
        )
        hwm = runs[0].highWaterMark
      }
      console.log('')
    }
    console.log(`  socket writableHighWaterMark: ${hwm} bytes (the write-ahead depth the framing cannot see past)`)
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
    fs.rmSync(outDir, { recursive: true, force: true })
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
