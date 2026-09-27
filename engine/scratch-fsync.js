'use strict'
// What an fsync actually costs on this filesystem, and therefore how often
// a v2 receiver should checkpoint.
//
// PROTOCOL.md section 8.3 says "needs measurement, not a guess", and it is
// right to: the two failure modes point opposite ways. Checkpoint too
// often and every checkpoint is a full device round trip that the
// transfer waits on. Checkpoint too rarely and a crash throws away
// everything since the last one -- and the whole reason CHECKPOINT exists
// is that resume needs an offset that is genuinely on disk
// (PROTOCOL.md section 4.1).
//
// So the answer is not a latency. It is a ratio: fsync cost as a fraction
// of the transfer time it is amortised over, set against the work a crash
// would discard. This script measures the first and tabulates the second.
//
// WHY IT WRITES REAL BYTES TO A REAL DIRECTORY. fsync latency is a
// property of the filesystem, the device and the OS's write cache, not of
// Node. Measuring it on a tmpfs and applying the number to an APFS volume
// would be measuring the wrong machine. Point --dir at where the receiver
// actually writes; the default is the OS temp directory, which on macOS
// is on the boot volume and is representative, and on many Linux systems
// is tmpfs and is NOT -- the script says which it found.
//
// Usage:
//   node engine/scratch-fsync.js
//   node engine/scratch-fsync.js --dir ~/Downloads --trials 60
//
// Options: --dir <path> where to write (default os.tmpdir())
//          --trials <n> fsyncs per interval size (default 40)
//          --chunk <bytes> the transfer's chunk size (default 65536)

const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const crypto = require('node:crypto')
const { execFileSync } = require('node:child_process')

function flag (name, fallback) {
  const i = process.argv.indexOf(`--${name}`)
  return i === -1 ? fallback : process.argv[i + 1]
}

const dir = path.resolve(String(flag('dir', os.tmpdir())).replace(/^~/, os.homedir()))
const trials = Number(flag('trials', 40))
const chunkSize = Number(flag('chunk', 65536))

// The candidate checkpoint intervals, in bytes. Spread over three orders
// of magnitude on purpose: the point is to find where the curve turns,
// not to confirm a number someone already picked.
const INTERVALS = [
  1 * 1024 * 1024,
  4 * 1024 * 1024,
  16 * 1024 * 1024,
  64 * 1024 * 1024,
  256 * 1024 * 1024
]

/** @param {number[]} xs @param {number} p */
function quantile (xs, p) {
  const sorted = [...xs].sort((a, b) => a - b)
  return sorted[Math.min(sorted.length - 1, Math.floor(p * sorted.length))]
}

/** @param {number} n */
const mib = (n) => (n / 1024 / 1024).toFixed(0) + ' MiB'

// Best effort, and reported as such: knowing the filesystem is the
// difference between "0.02 ms fsync" meaning a fast SSD and meaning tmpfs,
// where the measurement is meaningless for this purpose.
function describeFilesystem () {
  try {
    const out = execFileSync('df', ['-P', dir], { encoding: 'utf8' }).trim().split('\n')
    const device = out[out.length - 1].split(/\s+/)[0]
    if (process.platform === 'darwin') {
      const mount = execFileSync('mount', { encoding: 'utf8' })
        .split('\n').find((l) => l.startsWith(device + ' '))
      return mount ? mount.replace(/\s+/g, ' ') : device
    }
    return device
  } catch {
    return 'unknown (df/mount unavailable)'
  }
}

function main () {
  fs.mkdirSync(dir, { recursive: true })
  const file = path.join(dir, `adhal-fsync-${process.pid}.tmp`)
  const chunk = crypto.randomBytes(chunkSize)

  console.log(`fsync cost on ${dir}`)
  console.log(`  filesystem: ${describeFilesystem()}`)
  console.log(`  ${trials} trials per interval, ${chunkSize} byte writes`)
  console.log('')

  const fd = fs.openSync(file, 'w')
  /** @type {{ interval: number, fsync: number[], write: number[] }[]} */
  const results = []

  try {
    // One untimed pass so the file exists, the extent is allocated and the
    // first-write cost does not land in the first measurement.
    for (let i = 0; i < 16; i++) fs.writeSync(fd, chunk)
    fs.fsyncSync(fd)

    for (const interval of INTERVALS) {
      const chunksPerInterval = Math.max(1, Math.round(interval / chunkSize))
      /** @type {number[]} */ const fsyncMs = []
      /** @type {number[]} */ const writeMs = []

      for (let t = 0; t < trials; t++) {
        const w0 = process.hrtime.bigint()
        for (let i = 0; i < chunksPerInterval; i++) fs.writeSync(fd, chunk)
        const w1 = process.hrtime.bigint()
        fs.fsyncSync(fd)
        const f1 = process.hrtime.bigint()
        writeMs.push(Number(w1 - w0) / 1e6)
        fsyncMs.push(Number(f1 - w1) / 1e6)
      }
      results.push({ interval, fsync: fsyncMs, write: writeMs })
      console.log(
        `  every ${mib(interval).padStart(8)}: ` +
        `fsync p50 ${quantile(fsyncMs, 0.5).toFixed(2).padStart(7)} ms  ` +
        `p90 ${quantile(fsyncMs, 0.9).toFixed(2).padStart(7)} ms  ` +
        `p99 ${quantile(fsyncMs, 0.99).toFixed(2).padStart(7)} ms  ` +
        `max ${Math.max(...fsyncMs).toFixed(2).padStart(7)} ms`
      )
    }
  } finally {
    fs.closeSync(fd)
    fs.rmSync(file, { force: true })
  }

  // The write throughput measured above is local disk, which is faster
  // than any network this will run over. Quoting the overhead against it
  // is therefore the PESSIMISTIC reading -- over a real link the same
  // fsync is amortised over more wall-clock time, so the true fraction is
  // smaller. Both are shown, because a checkpoint policy chosen only
  // against a fast LAN is wrong on a slow one and vice versa.
  const diskMiBps = 1000 / (quantile(results[0].write, 0.5) / (results[0].interval / 1024 / 1024))
  console.log('')
  console.log(`  local write throughput: ~${diskMiBps.toFixed(0)} MiB/s (p50)`)
  console.log('')
  console.log('  fsync cost as a fraction of transfer time, and work lost on a crash:')
  console.log('')

  const LINKS = [
    { name: 'disk-speed', mibps: diskMiBps },
    { name: '100 Mbit/s', mibps: 100 / 8 },
    { name: '10 Mbit/s', mibps: 10 / 8 }
  ]
  const header = '    interval'.padEnd(16) + LINKS.map((l) => l.name.padStart(12)).join('') + '   lost on crash'
  console.log(header)
  for (const { interval, fsync } of results) {
    const cost = quantile(fsync, 0.9)
    const cells = LINKS.map(({ mibps }) => {
      const transferMs = (interval / 1024 / 1024) / mibps * 1000
      return `${(cost / (transferMs + cost) * 100).toFixed(2)}%`.padStart(12)
    })
    console.log(`    ${mib(interval).padEnd(12)}${cells.join('')}   ${mib(interval)}`)
  }
  console.log('')
  console.log('  (p90 fsync, so the column is a bad case rather than a typical one.)')

  // THE FINDING THIS TABLE EXISTS TO MAKE VISIBLE. fsync here costs
  // roughly the same whether it follows 1 MiB or 64 MiB -- it is a device
  // round trip, not a function of the bytes. Transfer time per byte, by
  // contrast, varies by two orders of magnitude across the links this
  // runs on. So a checkpoint interval measured in BYTES cannot have a
  // stable cost: the same rule is free on a slow link and ruinous on a
  // fast one, which is exactly what the table above shows.
  //
  // An interval measured in SECONDS has the opposite property: the cost
  // is the same fraction everywhere, and so is the work a crash discards.
  const perCheckpoint = quantile(results[2].fsync, 0.9)
  console.log('')
  console.log('  the same cost, if the interval is measured in seconds instead:')
  console.log('')
  console.log('    interval'.padEnd(16) + LINKS.map((l) => l.name.padStart(12)).join('') + '   lost on crash')
  for (const seconds of [1, 2, 5, 10]) {
    const cells = LINKS.map(() =>
      `${(perCheckpoint / (seconds * 1000 + perCheckpoint) * 100).toFixed(2)}%`.padStart(12))
    console.log(`    ${(seconds + 's').padEnd(12)}${cells.join('')}   ${seconds}s of transfer`)
  }
  console.log('')
  console.log('  Identical across links, because that is the point.')
}

main()
