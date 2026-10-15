'use strict'
// Writes the ENVIRONMENT.md that goes beside a scratch-trials.js run's logs,
// from the per-trial JSON both machines wrote with --out.
//
// Usage:
//
//   node engine/scratch-trials-environment.js <run-dir>            # print it
//   node engine/scratch-trials-environment.js <run-dir> --write    # write <run-dir>/ENVIRONMENT.md
//
// --write refuses to replace an existing ENVIRONMENT.md unless --force is
// also given, because that file is usually hand-edited after generation.
//
// <run-dir> holds the JSON (and ideally the logs) of one or more runs, as
// docs/TESTING.md lays them out: <date>-trials-<a|b>-<tx|rx>.json. Files are
// grouped into runs by seed, so the names are not load-bearing. Machine 1 is
// the receiver of the first run, which is TESTING.md's convention.
//
// Everything the harness detected is filled in. What it cannot detect -- the
// router's configuration, the link beyond the first hop, the ISP without
// --lookup-isp -- is marked FILL IN, so `grep 'FILL IN'` lists what is left.
// JSON from before 2026-10-14 has no environment block; for that, whatever
// the .log beside it says is used, and the rest is "not recorded".
//
// The "Checks" section lists every disagreement between the two sides that
// would make the run hard to read: different seeds, trial counts, slots or
// start times, different commits, uncommitted changes, a NAT that changed.

const fs = require('node:fs')
const path = require('node:path')

const args = process.argv.slice(2)
const dir = args.find((a) => !a.startsWith('--'))
const write = args.includes('--write')
const force = args.includes('--force')
if (!dir) {
  console.error('Usage: scratch-trials-environment.js <run-dir> [--write [--force]]')
  process.exit(1)
}

const FILL = 'FILL IN'
const NOT_RECORDED = 'not recorded'

// --- Reading the run -------------------------------------------------------

// What a log says that a pre-2026-10-14 JSON does not.
/** @param {string} logPath */
function readLog (logPath) {
  let text
  try { text = fs.readFileSync(logPath, 'utf8') } catch { return null }
  const lines = text.split('\n')
  const rel = (line) => Number((line.match(/^\+(\d+(?:\.\d+)?)s/) || [])[1])
  const host = text.match(/host machine: (\S+) \(([^/]+)\/([^)]+)\) node (\S+)/)
  const slot = text.match(/slot start: (\d+)/)
  const file = text.match(/^\+\S+ file: (.+) \((\d+) bytes\)$/m)
  const build = text.match(/build: commit (\S+)(?: \((clean|UNCOMMITTED CHANGES)\))?/)
  const waitLine = lines.find((l) => /waiting \d+s for the first slot/.test(l))
  const lastLine = [...lines].reverse().find((l) => /^\+\d/.test(l))
  // The log's times are relative to its own start. The slot start is
  // absolute, so the harness started about `waiting` seconds before it.
  let startedAtMs = null
  let endedAtMs = null
  if (slot && waitLine) {
    const waited = Number(waitLine.match(/waiting (\d+)s/)[1])
    startedAtMs = (Number(slot[1]) - waited) * 1000 - rel(waitLine) * 1000
    if (lastLine) endedAtMs = startedAtMs + rel(lastLine) * 1000
  }
  return {
    host: host ? { hostname: host[1], platform: host[2], arch: host[3], node: host[4] } : null,
    startEpoch: slot ? Number(slot[1]) : null,
    file: file ? { path: file[1], size: Number(file[2]) } : null,
    build: build ? { commit: build[1], dirty: build[2] === undefined ? null : build[2] !== 'clean' } : null,
    startedAtMs,
    endedAtMs
  }
}

/** @param {string} jsonPath */
function readSide (jsonPath) {
  let data
  try { data = JSON.parse(fs.readFileSync(jsonPath, 'utf8')) } catch { return null }
  if (!data || !['sender', 'receiver'].includes(data.role) || !data.seed || !Array.isArray(data.results)) return null
  const log = readLog(jsonPath.replace(/\.json$/, '.log'))
  const env = data.environment || null
  return {
    name: path.basename(jsonPath),
    role: data.role,
    seed: data.seed,
    trials: data.trials,
    slotSeconds: data.slotSeconds,
    refreshMs: data.refreshMs,
    startEpoch: data.startEpoch ?? log?.startEpoch ?? null,
    startedAtMs: data.startedAtEpochMs ?? log?.startedAtMs ?? null,
    endedAtMs: data.endedAtEpochMs ?? log?.endedAtMs ?? null,
    timesApproximate: data.startedAtEpochMs === undefined,
    file: data.file ?? log?.file ?? null,
    host: env
      ? { hostname: env.hostname, platform: env.os?.platform, arch: env.os?.arch, node: env.node }
      : log?.host ?? null,
    build: env?.build ?? log?.build ?? null,
    env,
    results: data.results
  }
}

const sides = fs.readdirSync(dir)
  .filter((f) => f.endsWith('.json'))
  .sort()
  .map((f) => readSide(path.join(dir, f)))
  .filter(Boolean)
if (!sides.length) {
  console.error(`scratch-trials-environment: no scratch-trials JSON in ${dir}`)
  process.exit(1)
}

/** @type {string[]} */
const checks = []

/** @type {Map<string, any[]>} */
const bySeed = new Map()
for (const s of sides) bySeed.set(s.seed, [...(bySeed.get(s.seed) || []), s])
const runs = [...bySeed.entries()]
  .map(([seed, list]) => ({
    seed,
    sender: list.find((s) => s.role === 'sender') || null,
    receiver: list.find((s) => s.role === 'receiver') || null,
    list
  }))
  .sort((a, b) => (a.list[0].startEpoch ?? Infinity) - (b.list[0].startEpoch ?? Infinity) || a.seed.localeCompare(b.seed))
runs.forEach((run, i) => { run.letter = String.fromCharCode(65 + i) })

for (const run of runs) {
  const tag = `Run ${run.letter} (seed \`${run.seed}\`)`
  for (const role of ['sender', 'receiver']) {
    const n = run.list.filter((s) => s.role === role).length
    if (n !== 1) checks.push(`${tag} has ${n} ${role} files; expected 1.`)
  }
  if (!run.sender || !run.receiver) continue
  for (const key of ['trials', 'slotSeconds', 'refreshMs', 'startEpoch']) {
    if (run.sender[key] !== run.receiver[key]) {
      checks.push(`${tag}: \`${key}\` differs, sender ${run.sender[key]} and receiver ${run.receiver[key]}.`)
    }
  }
  if (run.sender.host?.hostname && run.sender.host.hostname === run.receiver.host?.hostname) {
    checks.push(`${tag}: both sides ran on ${run.sender.host.hostname}.`)
  }
}

// --- Machines --------------------------------------------------------------

// Keyed by hostname. Without one (very old logs), TESTING.md's convention
// decides: Machine 1 receives in run A, sends in run B, and so on.
/** @type {Map<string, { label: string, sides: any[] }>} */
const machines = new Map()
let assumed = false
const keyFor = (side, runIndex) => {
  if (side.host?.hostname) return side.host.hostname
  assumed = true
  const firstIsReceiver = runIndex % 2 === 0
  return (side.role === 'receiver') === firstIsReceiver ? '#1' : '#2'
}
runs.forEach((run, i) => {
  for (const side of [run.receiver, run.sender, ...run.list].filter(Boolean)) {
    const key = keyFor(side, i)
    if (!machines.has(key)) machines.set(key, { label: `Machine ${machines.size + 1}`, sides: [] })
    const m = machines.get(key)
    if (!m.sides.includes(side)) m.sides.push(side)
    side.machine = m
  }
})
if (assumed) checks.push('A side has no hostname; machines were assigned by TESTING.md\'s convention (Machine 1 receives in run A).')

for (const m of machines.values()) {
  const envs = m.sides.map((s) => s.env).filter(Boolean)
  const differ = (label, f) => {
    // A value one run did not record (no --lookup-isp, say) is not a change.
    const values = new Set(envs.map(f).filter((v) => v !== null && v !== undefined).map((v) => JSON.stringify(v)))
    if (values.size > 1) checks.push(`${m.label}: ${label} changed between its runs.`)
  }
  differ('the commit', (e) => e.build?.commit)
  differ('the OS version', (e) => e.os?.pretty)
  differ('the access interface', (e) => e.access && `${e.access.type} ${e.access.interface}`)
  differ('whether the route went through a VPN', (e) => e.vpn?.onRoute)
  differ('the NAT at start', (e) => e.natAtStart?.kind)
  differ('the ISP', (e) => e.isp?.asn)
  const builds = m.sides.map((s) => s.build).filter(Boolean)
  if (builds.some((b) => b.dirty)) checks.push(`${m.label} ran with UNCOMMITTED CHANGES.`)
  const kinds = new Set(m.sides.flatMap((s) => s.results.map((r) => r.nat?.kind).filter(Boolean)))
  if (kinds.size > 1) checks.push(`${m.label}: its NAT changed during the trials (${[...kinds].join(', ')}).`)
  if (m.sides.some((s) => s.results.some((r) => r.path?.remoteKind === 'private'))) {
    checks.push(`${m.label}: a trial connected from a private address, i.e. the same LAN, not a punch across the internet.`)
  }
}
{
  const ms = [...machines.values()]
  const nat = ms.map((m) => m.sides.find((s) => s.env)?.env.natAtStart?.kind)
  if (ms.length === 2 && nat.every((k) => k === 'randomized')) {
    checks.push('Both machines are behind randomized NATs: the hard pair, which needs a relay.')
  }
  const commits = new Set(ms.map((m) => m.sides.find((s) => s.build)?.build.commit).filter(Boolean))
  if (commits.size > 1) checks.push(`The machines ran different commits: ${[...commits].join(', ')}.`)
}

// --- Formatting ------------------------------------------------------------

/** @param {number} ms @param {'date' | 'time' | 'datetime' | 'hm'} form */
function fmt (ms, form) {
  const parts = Object.fromEntries(new Intl.DateTimeFormat('en-US', {
    year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit',
    hourCycle: 'h23', timeZoneName: 'short'
  }).formatToParts(new Date(ms)).map((p) => [p.type, p.value]))
  const date = `${parts.year}-${parts.month}-${parts.day}`
  if (form === 'date') return date
  if (form === 'hm') return `${parts.hour}:${parts.minute} ${parts.timeZoneName}`
  const time = `${parts.hour}:${parts.minute}:${parts.second} ${parts.timeZoneName}`
  return form === 'time' ? time : `${date} ${time}`
}

/** @param {number} bytes */
function size (bytes) {
  const mib = bytes / 1048576
  return Number.isInteger(mib) ? `${mib} MiB (${bytes} bytes)` : `${bytes} bytes`
}

/** @param {any} host */
function osShort (host) {
  return { darwin: 'macOS', linux: 'Linux', win32: 'Windows' }[host?.platform] || host?.platform || '?'
}

/** @param {any} nat */
function describeNat (nat) {
  if (!nat) return NOT_RECORDED
  if (nat.kind === 'unavailable') return `unavailable (${nat.error})`
  const parts = [nat.kind]
  if (nat.kind === 'consistent') parts.push(nat.portPreserved ? 'port preserved' : 'port translated')
  parts.push(nat.firewalled ? 'firewalled' : 'not firewalled')
  return parts.join(', ')
}

/** @param {any} access */
function describeAccess (access) {
  if (!access) return NOT_RECORDED
  if (!access.interface) return `${FILL} (no route to the internet was found)`
  const what = {
    wifi: 'Wi-Fi',
    ethernet: 'Ethernet',
    cellular: 'cellular',
    tethered: 'tethered to a phone',
    vpn: 'a VPN tunnel',
    virtual: 'a virtual interface (container or VM?)'
  }[access.type] || access.type || 'unknown'
  return `${what} via ${access.interface}${access.detail ? ` (${access.detail})` : ''}; ` +
    `${FILL} what is beyond it (e.g. the router's uplink)`
}

/** @param {any} vpn @param {any} access */
function describeVpnLine (vpn, access) {
  if (!vpn) return NOT_RECORDED
  const parts = []
  parts.push(vpn.onRoute === null ? 'VPN: unknown' : vpn.onRoute ? 'VPN: the route to the internet went through a tunnel' : 'VPN: not on the route')
  if (vpn.tunnelInterfaces?.length) parts.push(`tunnel interfaces up: ${vpn.tunnelInterfaces.join(', ')}`)
  if (vpn.services?.length) parts.push(`configured services: ${vpn.services.map((s) => `${s.name} (${s.status.toLowerCase()})`).join(', ')}`)
  parts.push(access?.hotspot ? `hotspot: likely -- ${access.hotspot}` : 'hotspot: none detected')
  parts.push('relay: none (the harness configures no relay)')
  return parts.join('; ')
}

/** @param {any} fw */
function describeFirewall (fw) {
  if (!fw) return `host firewall ${NOT_RECORDED}`
  if (fw.enabled === null) return 'host firewall unknown'
  if ('stealth' in fw) {
    return `host firewall ${fw.blockAll ? 'enabled, blocking all incoming' : fw.enabled ? 'enabled' : 'disabled'}` +
      `${fw.stealth === null ? '' : `, stealth mode ${fw.stealth ? 'on' : 'off'}`} (macOS application firewall)`
  }
  const on = ['ufw', 'firewalld', 'nftables'].filter((k) => fw[k])
  return on.length ? `host firewall enabled: ${on.join(', ')}` : 'host firewall: none of ufw, firewalld, nftables enabled (iptables not checked)'
}

// --- The document ----------------------------------------------------------

const out = []
const line = (s = '') => out.push(s)
const first = runs[0].list[0]
const dirName = path.basename(path.resolve(dir))
const dateName = path.basename(path.dirname(path.resolve(dir)))
line(`# ${/^\d{8}$/.test(dateName) ? `${dateName} ` : ''}${dirName}`)
line()

{
  const started = Math.min(...sides.map((s) => s.startedAtMs ?? Infinity))
  const ended = Math.max(...sides.map((s) => s.endedAtMs ?? -Infinity))
  const about = sides.some((s) => s.timesApproximate) ? 'about ' : ''
  const parts = []
  if (Number.isFinite(started)) parts.push(`harness started ${about}${fmt(started, 'hm')}`)
  if (first.startEpoch) parts.push(`first slot ${fmt(first.startEpoch * 1000, 'time')}`)
  if (Number.isFinite(ended)) parts.push(`last run ended ${about}${fmt(ended, 'hm')}`)
  const day = Number.isFinite(started) ? started : first.startEpoch ? first.startEpoch * 1000 : null
  line(`Date: ${day ? fmt(day, 'date') : FILL}${parts.length ? `, ${parts.join('; ')}` : ''}`)
}

{
  const perMachine = [...machines.values()].map((m) => ({ m, build: m.sides.find((s) => s.build)?.build || null }))
  const state = (b) => b.dirty === true ? 'UNCOMMITTED CHANGES' : b.dirty === false ? 'clean' : 'clean state unknown'
  if (perMachine.every((p) => !p.build)) {
    line(`Commit: ${NOT_RECORDED}; the logs have no \`build:\` line. ${FILL} the commit and whether each tree was clean`)
  } else if (perMachine.every((p) => p.build && p.build.commit === perMachine[0].build.commit && p.build.dirty === perMachine[0].build.dirty)) {
    line(`Commit: ${perMachine[0].build.commit} on ${perMachine.length === 2 ? 'both machines' : 'every machine'}, ${state(perMachine[0].build)}`)
  } else {
    line(`Commit: ${perMachine.map((p) => `${p.m.label} ${p.build ? `${p.build.commit} (${state(p.build)})` : NOT_RECORDED}`).join('; ')}`)
  }
}

{
  const counts = new Set(sides.map((s) => s.trials))
  line(`Trials: ${counts.size === 1 ? `${[...counts][0]} per direction` : runs.map((r) => `run ${r.letter} ${r.list[0].trials}`).join(', ')}`)
  const files = new Set(runs.map((r) => r.sender?.file ? `${size(r.sender.file.size)} ${r.sender.file.path}` : null))
  line(`File: ${files.size === 1 && !files.has(null) ? [...files][0] : runs.map((r) => `run ${r.letter} ${r.sender?.file ? `${size(r.sender.file.size)} ${r.sender.file.path}` : NOT_RECORDED}`).join('; ')}`)
  const slots = new Set(sides.map((s) => `${s.slotSeconds} seconds, refresh ${s.refreshMs} ms`))
  line(`Slot: ${[...slots].join(' / ')}`)
}

for (const run of runs) {
  const who = [run.receiver, run.sender].filter(Boolean)
    .sort((a, b) => a.machine.label.localeCompare(b.machine.label))
    .map((s) => `${s.machine.label} ${s.role}`)
  const when = run.list[0].startEpoch ? `, slot start ${run.list[0].startEpoch}, ${fmt(run.list[0].startEpoch * 1000, 'time')}` : ''
  line(`Run ${run.letter}: ${who.join(', ')} (seed \`${run.seed}\`${when})`)
}

for (const m of machines.values()) {
  const side = m.sides.find((s) => s.env) || m.sides[0]
  const env = side.env
  const host = side.host
  line()
  line(`## ${m.label}`)
  line()
  line(`Host: ${host ? `${host.hostname} (${host.platform}/${host.arch}), node ${host.node}` : NOT_RECORDED}`)
  line(`OS: ${env ? (env.os?.pretty || `${env.os.platform} ${env.os.release}; ${FILL} the product version`) : `${osShort(host)}; ${FILL} the version (${NOT_RECORDED})`}`)
  line(`Network/carrier/ISP: ${!env ? `${FILL} (${NOT_RECORDED})` : !env.isp ? `${FILL} (run with --lookup-isp to record it)` : env.isp.error ? `${FILL} (the lookup failed: ${env.isp.error})` : `AS${env.isp.asn} ${env.isp.name}`}`)
  line(`Access type: ${env ? describeAccess(env.access) : `${FILL} (${NOT_RECORDED})`}`)
  {
    let nat = `${FILL} (${NOT_RECORDED})`
    if (env) {
      const kinds = new Map()
      for (const s of m.sides) for (const r of s.results) if (r.nat) kinds.set(r.nat.kind, (kinds.get(r.nat.kind) || 0) + 1)
      const perTrial = kinds.size ? `; per trial: ${[...kinds].map(([k, n]) => `${k} ${n}`).join(', ')}` : ''
      const cgnat = env.interfaces?.cgnatIpv4 === undefined
        ? ''
        : env.interfaces.cgnatIpv4 > 0
          ? '; CGNAT: this machine has an address in 100.64/10'
          : `; CGNAT: not visible from this machine, ${FILL} if known`
      nat = `DHT saw ${describeNat(env.natAtStart)} at start${perTrial}${cgnat}`
    }
    line(`NAT: ${nat}`)
  }
  line(`Firewall/router: ${env ? `${describeFirewall(env.hostFirewall)}; DHT ${env.natAtStart?.firewalled ? 'finds it firewalled' : env.natAtStart?.firewalled === false ? 'finds it not firewalled' : 'firewalled unknown'}; router: ${FILL}` : `${FILL} (${NOT_RECORDED})`}`)
  line(`VPN/relay/hotspot: ${env ? describeVpnLine(env.vpn, env.access) : `${FILL} (${NOT_RECORDED})`}`)
  const notes = [...new Set(m.sides.flatMap((s) => s.env?.notes || []))]
  if (notes.length) line(`Notes: ${notes.join('; ')}`)
}

line()
line('## Results')
line()
line('| Run | Direction | Sender | Receiver |')
line('| --- | --- | --- | --- |')
const failures = []
for (const run of runs) {
  const ok = (s) => s ? `${s.results.filter((r) => r.outcome === 'ok').length}/${s.trials}` : 'missing'
  const direction = run.sender && run.receiver
    ? `${run.sender.machine.label} (${osShort(run.sender.host)}) → ${run.receiver.machine.label} (${osShort(run.receiver.host)})`
    : '?'
  line(`| ${run.letter} | ${direction} | ${ok(run.sender)} | ${ok(run.receiver)} |`)
  for (const s of [run.sender, run.receiver].filter(Boolean)) {
    for (const r of s.results) {
      if (r.outcome === 'ok') continue
      const detail = [r.phase && `phase ${r.phase}`, r.cause && `"${r.cause}"`].filter(Boolean).join(', ')
      failures.push(`- Run ${run.letter} ${s.role}, trial ${r.trial + 1}: \`${r.outcome}\`${detail ? ` (${detail})` : ''}`)
    }
  }
}
if (failures.length) {
  line()
  for (const f of failures) line(f)
}

line()
line('## Checks')
line()
if (checks.length) for (const c of checks) line(`- ${c}`)
else line('No mismatches between the sides.')

const text = out.join('\n') + '\n'
if (!write) {
  process.stdout.write(text)
} else {
  const target = path.join(dir, 'ENVIRONMENT.md')
  if (fs.existsSync(target) && !force) {
    console.error(`scratch-trials-environment: ${target} exists; pass --force to replace it, or omit --write to print`)
    process.exit(1)
  }
  fs.writeFileSync(target, text)
  console.error(`wrote ${target}`)
}
