'use strict'
// Repeated-trial measurement harness: runs N real drops back to back and
// reports a success RATE, not an anecdote.
//
// This exists because every wrong conclusion in this project's cross-ISP
// debugging came from reasoning about single runs. One failure looks like a
// bug; one success looks like a fix. On a path that is intermittently
// unable to hole punch, neither is true, and there was no instrument that
// could tell the difference. This is that instrument. Its results are read
// against the reliability bar docs/MEASURING-TRANSFER-RELIABILITY.md states
// (>= 75% success on a path, and 50% as the line below which relay quality
// is the product), and it is what W14's head-to-head runs reuse.
//
// Usage, on the two real machines:
//
//   # Comcast (or wherever the receiver lives)
//   node engine/scratch-trials.js --role receiver --seed run7 --trials 10
//
//   # Starlink
//   node engine/scratch-trials.js --role sender --seed run7 --trials 10 \
//     --file /tmp/test.bin
//
// Both sides must be given the SAME --seed and --trials. Start them within
// a minute of each other, then leave them alone.
//
// Options: --slot <s> per-trial budget (default 135), --start-epoch <s> to
// pin the schedule explicitly, --out <path> to write per-trial JSON,
// --record-addresses to keep IP addresses in the log and JSON (see below),
// --lookup-isp to record the AS this side's public address belongs to (it
// sends that address to a DNS lookup), --note <text> (repeatable) for what
// the machine cannot detect, such as the router's firewall settings.
// engine/scratch-trials-environment.js turns a run's JSON into the
// ENVIRONMENT.md beside its logs.
//
// TWO DESIGN CONSTRAINTS, because the two ends cannot talk to each other:
//
// 1. Codes are derived from (seed, trial index), so both sides agree on
//    every topic without exchanging anything.
//
//    UNDER v2 THEY ARE REAL FIVE-WORD CODES, and that is a correctness fix
//    rather than tidying. They used to be opaque `trial-<hex>` secrets, on
//    the reasoning that "a topic is a 32-byte hash either way". That
//    stopped being true: an opaque code is its own nameplate AND its own
//    secret (see engine/src/resolve-code.js), so every trial would have
//    run down the --insecure-opaque-code path -- publishing its secret in the
//    announced topic and measuring a configuration no user can reach. The
//    instrument would have been measuring something other than the
//    product. Deriving a word code from the same seed keeps the "neither
//    side has to be told the codes" property and measures the real path.
//
// 2. Trials are pinned to absolute wall-clock slots, NOT to each other's
//    progress. If each side simply advanced when its own trial ended, a
//    fast failure on one side and a slow timeout on the other would
//    desynchronize them, and every subsequent trial would fail because the
//    two were on different topics -- turning a working path into a 0%
//    result. Slot alignment makes drift impossible on NTP-synced hosts.

const os = require('node:os')
const fs = require('node:fs')
const path = require('node:path')
const crypto = require('node:crypto')
const { execFileSync } = require('node:child_process')
const { createRequire } = require('node:module')
const {
  createSwarm,
  acceptOnce,
  connectOnce,
  resolveCode,
  sendFile,
  receiveFile,
  closeAfterResult,
  RESULT_DELIVERY_TIMEOUT_MS,
  CLOSE_GRACE_MS,
  WORD_COUNT,
  ERR_CONFIRMATION
} = require('./src')
const { WORDS } = require('./src/wordlist')

function flag (name, fallback = undefined) {
  const i = process.argv.indexOf(`--${name}`)
  return i === -1 ? fallback : process.argv[i + 1]
}

const role = flag('role')
const seed = flag('seed')
const trials = Number(flag('trials', 10))
const slotSeconds = Number(flag('slot', 135))
const filePath = flag('file')
const outPath = flag('out')
// Optional A/B for engine/src/swarm.js REFRESH_INTERVAL. Single runs
// succeeded at both 4000 and 30000, which proves neither is fatal and
// settles nothing about the rate -- exactly the question this harness is
// for. Omitted, the engine default applies.
const refreshMs = flag('refresh') === undefined ? undefined : Number(flag('refresh'))
// What the host cannot detect about its own network -- the router's rules,
// the link beyond the first hop -- in the operator's words. Repeatable.
const notes = process.argv.flatMap((arg, i) => arg === '--note' && process.argv[i + 1] !== undefined ? [process.argv[i + 1]] : [])
const lookupIspFlag = process.argv.includes('--lookup-isp')

if (!['receiver', 'sender'].includes(role) || !seed || !Number.isInteger(trials) || trials < 1) {
  console.error('Usage: scratch-trials.js --role <receiver|sender> --seed <string> --trials <n>')
  console.error('                         [--file <path>] [--slot 135] [--refresh <ms>] [--start-epoch <s>] [--out <path>]')
  console.error('                         [--record-addresses] [--lookup-isp] [--note <text>]...')
  console.error('The sender requires --file. Both sides need the same --seed and --trials.')
  process.exit(1)
}
if (role === 'sender' && !filePath) {
  console.error('scratch-trials: --role sender requires --file <path>')
  process.exit(1)
}

// The sender waits this long into each slot before dialing, so the
// receiver has announced first -- the lookup-before-announce race in
// engine/src/swarm.js is a real effect, and measuring it here would just be
// measuring our own starting order.
const SENDER_LEAD_MS = 10000
// Leave the tail of each slot free so a trial that runs long still tears
// down before the next slot opens.
const TEARDOWN_MS = 5000

// The default --slot of 135 is not arbitrary: the sender's per-trial budget
// works out to SLOT - SENDER_LEAD - TEARDOWN = 120s, which is exactly
// swarm-send.js's default join timeout. The harness therefore measures what
// a real drop would experience. A shorter slot would cut trials off early
// and under-report the success rate relative to the actual CLI.

const SLOT_MS = slotSeconds * 1000
// Align to a 5-minute boundary at least a minute out. Wide enough that two
// hosts started within the same few minutes pick the same schedule; the
// chosen value is printed so a mismatch is obvious rather than silent.
const ALIGN_MS = 300000
const startEpoch = flag('start-epoch')
// Off by default because these logs are committed: docs/trials/ holds two
// home networks' worth of them. Without it, every address is reduced to its
// kind (public, private, CGNAT, ...), which is what the analysis needs.
const recordAddresses = process.argv.includes('--record-addresses')
const startMs = startEpoch
  ? Number(startEpoch) * 1000
  : Math.ceil((Date.now() + 60000) / ALIGN_MS) * ALIGN_MS

const t0 = Date.now()
const log = (...a) => console.log(`+${((Date.now() - t0) / 1000).toFixed(1)}s`, ...a)

// Deterministic per-trial code: a real five-word drop code, derived from
// (seed, trial index) so that both roles compute the same one without
// exchanging anything.
//
// Rejection sampled rather than plain modulo, for the same reason
// generateCode uses crypto.randomInt: 7772 is not a power of two, so
// reducing a 16-bit window modulo 7772 would favor the front of the list.
// It does not matter much for a rendezvous label on a private topic, but a
// harness that quietly draws from a skewed distribution is not the thing to
// leave lying around in a repo whose codes are its security argument.
const SAMPLE_LIMIT = 65536 - (65536 % WORDS.length)

function codeForTrial (i) {
  const words = []
  for (let counter = 0; words.length < WORD_COUNT; counter++) {
    const digest = crypto.createHash('sha256').update(`adhal-trial:${seed}:${i}:${counter}`).digest()
    for (let off = 0; off + 2 <= digest.length && words.length < WORD_COUNT; off += 2) {
      const n = digest.readUInt16BE(off)
      if (n >= SAMPLE_LIMIT) continue
      words.push(WORDS[n % WORDS.length])
    }
  }
  return words.join('-')
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, Math.max(0, ms)))

// --- What the network looked like ------------------------------------------
//
// Added on 2026-10-13, after a run whose rate could not be read without
// knowing what kind of pair it measured. A 95% between two consistent NATs
// says little about the case the project's own risk list names -- two
// randomized ("hard") NATs, which hole punching cannot cross without a
// relay -- and nothing in the records said which this was. Each side can
// only see its own NAT, so read the two machines' logs together.

// Classifies an address without recording it. `null` for no address.
/** @param {string | null | undefined} host */
function addressKind (host) {
  if (!host) return null
  let h = String(host).toLowerCase()
  if (h.startsWith('::ffff:') && h.includes('.')) h = h.slice(7)
  const v4 = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/)
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])]
    if (a === 127) return 'loopback'
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return 'private'
    if (a === 100 && b >= 64 && b <= 127) return 'cgnat'
    if (a === 169 && b === 254) return 'link-local'
    return 'public'
  }
  if (h === '::1') return 'loopback'
  if (/^f[cd]/.test(h)) return 'private'
  if (/^fe[89ab]/.test(h)) return 'link-local'
  return 'public'
}

// This side's NAT as the DHT has sampled it, from the addresses other nodes
// report seeing us at. 'consistent': they agree on a host and port, the
// mapping hole punching relies on. 'randomized': they agree on the host but
// not the port, a new mapping per destination -- the hard case. 'unknown':
// too few samples agree yet. `firewalled` is the DHT's own finding that
// unsolicited packets do not reach us. Reads dht-rpc's NAT sampler for the
// sample count, which is not public API; a scratch tool can afford that.
/** @param {any} dht */
function natSnapshot (dht) {
  try {
    const localPorts = [dht.io && dht.io.serverSocket, dht.io && dht.io.clientSocket]
      .filter(Boolean)
      .map((sock) => { try { return sock.address().port } catch { return null } })
      .filter((port) => typeof port === 'number')
    const kind = dht.host === null ? 'unknown' : dht.randomized ? 'randomized' : 'consistent'
    return {
      kind,
      firewalled: dht.firewalled,
      // A NAT that keeps the local port is the easiest kind to punch.
      portPreserved: kind === 'consistent' ? localPorts.includes(dht.port) : null,
      samples: dht._nat ? dht._nat.size : null,
      ...(recordAddresses ? { publicHost: dht.host, publicPort: dht.port, localPorts } : {})
    }
  } catch (err) {
    return { kind: 'unavailable', error: err.message }
  }
}

// The connection a trial used, from UDX's own counters. Every connection is
// direct: Hyperswarm relays only through a relay it is given, and this
// project configures none. Read at the end of a trial, after the socket may
// have closed, which is safe: the counters live in a buffer UDX allocates
// on the JS side. `onDhtSocket` is whether the punch landed on the DHT's own
// socket rather than one opened for punching, which a randomized NAT forces.
/** @param {any} socket @param {any} dht */
function pathSnapshot (socket, dht) {
  const raw = socket && socket.rawStream
  if (!raw) return null
  try {
    return {
      remoteKind: addressKind(raw.remoteHost),
      remoteFamily: raw.remoteFamily || null,
      onDhtSocket: !!dht && !!dht.io && (raw.socket === dht.io.serverSocket || raw.socket === dht.io.clientSocket),
      rttMs: raw.rtt,
      mtu: raw.mtu,
      retransmits: raw.retransmits,
      rtoCount: raw.rtoCount,
      packetsSent: raw.packetsTransmitted,
      packetsReceived: raw.packetsReceived,
      bytesSent: raw.bytesTransmitted,
      bytesReceived: raw.bytesReceived,
      ...(recordAddresses ? { remoteHost: raw.remoteHost, remotePort: raw.remotePort } : {})
    }
  } catch (err) {
    return { error: err.message }
  }
}

// The build, so a run records what it measured. Two runs have so far been
// written up with "the commit was not recorded".
function buildInfo () {
  const git = (args) => execFileSync('git', args, { cwd: __dirname, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim()
  let commit = null
  let dirty = null
  try {
    commit = git(['rev-parse', '--short=12', 'HEAD'])
    dirty = git(['status', '--porcelain', '--untracked-files=no']) !== ''
  } catch {}
  const versions = {}
  const req = createRequire(__filename)
  for (const name of ['hyperswarm', 'hyperdht']) {
    try { versions[name] = req(`${name}/package.json`).version } catch { versions[name] = null }
  }
  try {
    versions['udx-native'] = createRequire(req.resolve('hyperdht'))('udx-native/package.json').version
  } catch { versions['udx-native'] = null }
  return { commit, dirty, versions }
}

// Interface counts only, never addresses. Global IPv6 matters because the
// DHT and its punching are IPv4. An address in 100.64/10 on this machine
// itself means it sits directly on a carrier-grade NAT (a Starlink dish in
// bypass mode, a phone's tether); behind a home router the CGNAT is
// upstream of it and invisible from here.
function interfaceSummary () {
  let ipv4 = 0
  let cgnatIpv4 = 0
  let globalIpv6 = false
  for (const list of Object.values(os.networkInterfaces())) {
    for (const ni of list || []) {
      if (ni.internal) continue
      if (ni.family === 'IPv4' || ni.family === 4) {
        ipv4++
        if (addressKind(ni.address) === 'cgnat') cgnatIpv4++
      }
      if ((ni.family === 'IPv6' || ni.family === 6) && addressKind(ni.address) === 'public') globalIpv6 = true
    }
  }
  return { ipv4, cgnatIpv4, globalIpv6 }
}

// --- What the machine itself looked like -----------------------------------
//
// Added on 2026-10-14, after writing up the 2026-10-13 run left the OS
// version, access type, VPN, and firewall as "not recorded". Everything here
// is read without root and without sending a packet; anything a command
// cannot tell is recorded as null rather than guessed. The router's own
// configuration is not visible from the host at all: that is what --note
// is for.

// stdout of a command, or null if it is missing, fails, or hangs. `anyExit`
// keeps the output of a command whose exit status is itself an answer, as
// `systemctl is-active` is: it exits 3 when a unit is inactive.
/** @param {string} cmd @param {string[]} args */
function run (cmd, args, { anyExit = false } = {}) {
  try {
    return execFileSync(cmd, args, { encoding: 'utf8', timeout: 3000, stdio: ['ignore', 'pipe', 'ignore'] })
  } catch (err) {
    return anyExit && typeof err.status === 'number' && err.stdout ? String(err.stdout) : null
  }
}

/** @param {string} file */
function readText (file) {
  try { return fs.readFileSync(file, 'utf8') } catch { return null }
}

function osVersion () {
  if (os.platform() === 'darwin') {
    const get = (opt) => (run('sw_vers', [opt]) || '').trim() || null
    const name = get('-productName')
    const version = get('-productVersion')
    const build = get('-buildVersion')
    return { name, version, build, pretty: name && version ? `${name} ${version}${build ? ` (${build})` : ''}` : null }
  }
  if (os.platform() === 'linux') {
    const text = readText('/etc/os-release') || readText('/usr/lib/os-release')
    if (!text) return { name: null, version: null, build: null, pretty: null }
    const field = (key) => {
      const m = text.match(new RegExp(`^${key}=(.*)$`, 'm'))
      return m ? m[1].trim().replace(/^(["'])(.*)\1$/, '$2') : null
    }
    return { name: field('NAME'), version: field('VERSION_ID'), build: null, pretty: field('PRETTY_NAME') }
  }
  return { name: null, version: null, build: null, pretty: typeof os.version === 'function' ? os.version() : null }
}

// Tunnel interface names. A name is only a hint; what counts is whether the
// route to the internet goes through one.
const TUNNEL_NAME = /^(utun|ipsec|tun|tap|wg|tailscale|zt|nordlynx|proton|ppp)/

// iPhone Personal Hotspot always hands out 172.20.10.0/28 with the phone at
// .1, and older Android hotspots used 192.168.43.1. A match is a strong hint,
// not proof, so it is recorded as one.
/** @param {string | null} gateway */
function hotspotHint (gateway) {
  if (gateway === '172.20.10.1') return 'gateway is 172.20.10.1, the address of an iPhone Personal Hotspot'
  if (gateway === '192.168.43.1') return 'gateway is 192.168.43.1, the address older Android hotspots use'
  return null
}

// The interface the route to the internet leaves by, and what kind of link
// it is. Asks for the route to a public address rather than the default
// route, because a full-tunnel VPN often installs 0/1 + 128/1 or a policy
// rule and leaves the default route alone. Neither command sends a packet.
function accessSnapshot () {
  const probe = '1.1.1.1'
  let iface = null
  let gateway = null
  let type = null
  let detail = null
  if (os.platform() === 'darwin') {
    const out = run('route', ['-n', 'get', probe]) || ''
    iface = (out.match(/^\s*interface:\s*(\S+)/m) || [])[1] || null
    gateway = (out.match(/^\s*gateway:\s*(\S+)/m) || [])[1] || null
    if (iface) {
      // "Hardware Port: Wi-Fi\nDevice: en0" blocks.
      const ports = run('networksetup', ['-listallhardwareports']) || ''
      const block = ports.split(/\n\s*\n/).find((b) => new RegExp(`^Device:\\s*${iface}\\s*$`, 'm').test(b))
      const port = block ? (block.match(/^Hardware Port:\s*(.+)$/m) || [])[1] : null
      detail = port || null
      if (TUNNEL_NAME.test(iface)) type = 'vpn'
      else if (!port) type = null
      else if (/wi-?fi|airport/i.test(port)) type = 'wifi'
      else if (/iphone|ipad|android|modem|cellular|bluetooth pan/i.test(port)) type = 'tethered'
      else if (/ethernet|lan|thunderbolt/i.test(port)) type = 'ethernet'
      else type = 'other'
    }
  } else if (os.platform() === 'linux') {
    // "1.1.1.1 via 192.168.1.1 dev wlp2s0 src 192.168.1.50 uid 1000"
    const out = run('ip', ['route', 'get', probe]) || ''
    iface = (out.match(/\bdev\s+(\S+)/) || [])[1] || null
    gateway = (out.match(/\bvia\s+(\S+)/) || [])[1] || null
    if (iface) {
      const sys = `/sys/class/net/${iface}`
      let driver = null
      try { driver = path.basename(fs.readlinkSync(`${sys}/device/driver`)) } catch {}
      detail = driver ? `driver ${driver}` : null
      if (TUNNEL_NAME.test(iface)) type = 'vpn'
      else if (fs.existsSync(`${sys}/wireless`) || fs.existsSync(`${sys}/phy80211`)) type = 'wifi'
      else if (/^(wwan|wwp)/.test(iface) || ['qmi_wwan', 'cdc_mbim'].includes(driver)) type = 'cellular'
      else if (['ipheth', 'rndis_host'].includes(driver)) type = 'tethered'
      // cdc_ether and cdc_ncm are phones and some USB Ethernet adapters alike.
      else if (['cdc_ether', 'cdc_ncm'].includes(driver)) type = 'usb (tethered phone or USB Ethernet adapter)'
      else if (fs.existsSync(`${sys}/device`)) type = 'ethernet'
      else type = 'virtual'
    }
  }
  return {
    interface: iface,
    type,
    detail,
    gatewayKind: addressKind(gateway),
    hotspot: hotspotHint(gateway),
    ...(recordAddresses ? { gateway } : {})
  }
}

// Whether the route out is a tunnel, plus what else could be one. On macOS
// `scutil --nc list` lists the VPN services the system knows, by the name
// the user gave them, with their state.
/** @param {{ type: string | null }} access */
function vpnSnapshot (access) {
  const tunnels = Object.keys(os.networkInterfaces()).filter((name) => TUNNEL_NAME.test(name) && !/^utun\d+$/.test(name))
  /** @type {{ name: string, status: string }[] | null} */
  let services = null
  if (os.platform() === 'darwin') {
    const out = run('scutil', ['--nc', 'list'])
    if (out !== null) {
      services = []
      for (const line of out.split('\n')) {
        const m = line.match(/^\s*\*?\s*\(([^)]+)\).*"([^"]+)"/)
        if (m) services.push({ name: m[2], status: m[1] })
      }
    }
  }
  return {
    onRoute: access.type === null ? null : access.type === 'vpn',
    // macOS always has utun interfaces for its own services, so they are
    // left out; the route and the service list are what say more there.
    tunnelInterfaces: tunnels,
    services
  }
}

// The host's own firewall. Inbound UDP is what matters to hole punching,
// but a host firewall that drops it shows up in the DHT's `firewalled`
// finding anyway; this says whose firewall that was.
function hostFirewallSnapshot () {
  if (os.platform() === 'darwin') {
    const tool = '/usr/libexec/ApplicationFirewall/socketfilterfw'
    const state = run(tool, ['--getglobalstate'])
    const stealth = run(tool, ['--getstealthmode'])
    const n = state && (state.match(/State = (\d)/) || [])[1]
    return {
      tool: 'macOS application firewall; pf not checked, it needs root',
      enabled: n === undefined || n === null ? null : n !== '0',
      blockAll: n === '2',
      stealth: stealth ? /\bon\b|enabled/i.test(stealth) : null
    }
  }
  if (os.platform() === 'linux') {
    const ufwConf = readText('/etc/ufw/ufw.conf')
    const ufw = ufwConf ? /^ENABLED=yes/m.test(ufwConf) : null
    // One line per unit, in order. Unknown units print "inactive" too.
    const active = (run('systemctl', ['is-active', 'firewalld', 'nftables'], { anyExit: true }) || '').split('\n').map((s) => s.trim())
    const firewalld = active[0] ? active[0] === 'active' : null
    const nftables = active[1] ? active[1] === 'active' : null
    const known = [ufw, firewalld, nftables].filter((v) => v !== null)
    return {
      tool: 'ufw (/etc/ufw/ufw.conf), firewalld, nftables.service; iptables not checked, it needs root',
      enabled: known.length ? known.some(Boolean) : null,
      ufw,
      firewalld,
      nftables
    }
  }
  return { tool: null, enabled: null }
}

// Opt-in (--lookup-isp): the network this side's public address belongs to,
// by Team Cymru's IP-to-ASN DNS service. This SENDS the DHT-observed public
// address off the machine, to the DNS resolver and to Cymru, which is why it
// is off by default. Only the AS number, name, and country are recorded.
// The address is the one the DHT saw, so behind CGNAT or a VPN this is the
// carrier's or the VPN provider's network, which is the one that matters.
/** @param {string | null} host */
async function lookupIsp (host) {
  if (!host || !/^\d+\.\d+\.\d+\.\d+$/.test(host)) return { error: 'the DHT reported no public IPv4 address' }
  const dns = require('node:dns').promises
  const txt = async (name) => (await dns.resolveTxt(name)).map((parts) => parts.join(''))[0] || ''
  let timer
  try {
    return await Promise.race([
      (async () => {
        // "14593 | 98.97.0.0/18 | US | arin | 2019-11-18"; a prefix
        // announced by several ASes lists them space-separated.
        const origin = await txt(`${host.split('.').reverse().join('.')}.origin.asn.cymru.com`)
        const asn = origin.split('|')[0].trim().split(/\s+/)[0]
        if (!/^\d+$/.test(asn)) throw new Error('no ASN in the answer')
        // "14593 | US | arin | 2018-09-05 | SPACEX-STARLINK - Space Exploration Technologies Corporation, US"
        const desc = (await txt(`AS${asn}.asn.cymru.com`)).split('|').map((s) => s.trim())
        return { asn: Number(asn), name: desc[4] || null, country: desc[1] || null, source: 'Team Cymru IP-to-ASN (DNS)' }
      })(),
      new Promise((resolve, reject) => { timer = setTimeout(() => reject(new Error('no answer within 5s')), 5000) })
    ])
  } catch (err) {
    return { error: err.message }
  } finally {
    clearTimeout(timer)
  }
}

/** @param {any} isp */
function describeIsp (isp) {
  if (!isp) return 'not looked up (pass --lookup-isp)'
  if (isp.error) return `lookup failed (${isp.error})`
  return `AS${isp.asn} ${isp.name ?? '?'}`
}

/** @param {any} access */
function describeAccess (access) {
  if (!access.interface) return 'unknown (no route to the internet found)'
  const parts = [`${access.type ?? 'unknown'} via ${access.interface}`]
  if (access.detail) parts.push(`(${access.detail})`)
  if (access.hotspot) parts.push(`-- ${access.hotspot}`)
  return parts.join(' ')
}

/** @param {any} vpn */
function describeVpn (vpn) {
  const parts = [vpn.onRoute === null ? 'route unknown' : vpn.onRoute ? 'ROUTE GOES THROUGH A TUNNEL' : 'not on the route']
  if (vpn.tunnelInterfaces.length) parts.push(`tunnel interfaces: ${vpn.tunnelInterfaces.join(', ')}`)
  if (vpn.services) {
    parts.push(vpn.services.length
      ? `services: ${vpn.services.map((s) => `${s.name} ${s.status.toLowerCase()}`).join(', ')}`
      : 'services: none')
  }
  return parts.join('; ')
}

/** @param {any} fw */
function describeFirewall (fw) {
  if (fw.enabled === null) return `unknown${fw.tool ? ` (checked ${fw.tool})` : ''}`
  if ('stealth' in fw) {
    return `${fw.blockAll ? 'enabled, blocking all incoming' : fw.enabled ? 'enabled' : 'disabled'}` +
      `${fw.stealth === null ? '' : `, stealth mode ${fw.stealth ? 'on' : 'off'}`} (${fw.tool})`
  }
  const on = ['ufw', 'firewalld', 'nftables'].filter((k) => fw[k])
  return on.length ? `enabled: ${on.join(', ')} (iptables not checked: it needs root)` : `none enabled (checked ${fw.tool})`
}

// One throwaway swarm before the first slot, so the header says what kind
// of NAT this run starts behind. The per-trial snapshots say whether that
// held: on Starlink in particular, it need not.
// With --lookup-isp it also looks up the network of the public address the
// DHT saw, which is the only time that address leaves the probe.
async function probeNat () {
  const probe = createSwarm()
  try {
    let timer
    await Promise.race([
      probe.dht.ready(),
      new Promise((resolve, reject) => { timer = setTimeout(() => reject(new Error('the DHT did not bootstrap within 20s')), 20000) })
    ]).finally(() => clearTimeout(timer))
    return { nat: natSnapshot(probe.dht), isp: lookupIspFlag ? await lookupIsp(probe.dht.host) : null }
  } catch (err) {
    return { nat: { kind: 'unavailable', error: err.message }, isp: lookupIspFlag ? { error: err.message } : null }
  } finally {
    await probe.destroy().catch(() => {})
  }
}

/** @param {any} nat */
function describeNat (nat) {
  if (!nat) return 'n/a'
  if (nat.kind === 'unavailable') return `unavailable (${nat.error})`
  const parts = [nat.kind]
  if (nat.kind === 'consistent') parts.push(nat.portPreserved ? 'port preserved' : 'port translated')
  parts.push(nat.firewalled ? 'firewalled' : 'not firewalled')
  if (typeof nat.samples === 'number') parts.push(`${nat.samples} samples`)
  if (nat.publicHost) parts.push(`${nat.publicHost}:${nat.publicPort}`)
  return parts.join(', ')
}

// Classifies a failure into something countable.
//
// KEYED ON err.code SINCE ITEM 5, and that is not a cleanup. This harness
// used to classify by regex-matching error *messages*, which coupled the
// project's only measurement instrument to prose: rewording a sentence in
// engine/src/swarm.js silently re-bucketed results, and nothing would have
// said so. engine/src/errors.js exists largely for this.
//
// The failure-reporting work also changed what this function has to catch. The engine now
// verifies the received file against the manifest itself, so a corrupted
// transfer arrives here as a REJECTION rather than as a successful receive
// with a mismatching digest. Without the ERR_HASH_MISMATCH entry below it
// would land in the generic 'transfer-error' bucket, and the loudest
// output this tool has -- ">> N HASH MISMATCH(ES) ... stop feature work"
// -- would never fire again.
const OUTCOME_BY_CODE = {
  ERR_NO_PEER: 'no-peer',
  ERR_NO_HANDSHAKE: 'no-handshake',
  // Should never appear in an unattended run on a private topic. If it
  // does, the run is not measuring the network at all -- somebody reached
  // the nameplate and spent the drop's hundred guesses (section 6).
  ERR_ATTEMPT_CAP: 'attempt-cap',
  ERR_HASH_MISMATCH: 'hash-mismatch',
  ERR_SIZE_MISMATCH: 'size-mismatch',
  ERR_CONNECTION: 'connection-lost',
  ERR_STALLED: 'stalled',
  // Sender only: the receiver had every byte and said, in RESULT, that it
  // could not keep the file. Its own record for the trial says why.
  ERR_RECEIVER_FAILED: 'receiver-failed',
  // The accept gate. This harness's receiver asks no person, so a decline
  // here is the engine's own: a name, a size, the disk. ERR_DECLINED is
  // what the sender sees of any of them, with the receiver's reason.
  ERR_DECLINED: 'declined',
  ERR_NO_SPACE: 'no-space',
  ERR_EXISTS: 'exists',
  // Someone else holding this trial's code paired first. On a derived,
  // private code that should not happen; if it does, a second machine is
  // running the same --seed.
  ERR_DROP_TAKEN: 'drop-taken',
  ERR_UNSAFE_NAME: 'unsafe-name',
  ERR_MANIFEST_INVALID: 'manifest-invalid',
  ERR_PROTOCOL: 'protocol-error',
  ERR_CANCELLED_PEER: 'cancelled-by-peer',
  ABORT_ERR: 'cancelled-locally'
}

function classify (err) {
  if (err && OUTCOME_BY_CODE[err.code]) return OUTCOME_BY_CODE[err.code]

  // FALLBACK ONLY, and documented as such. Anything reaching these
  // patterns is an error that predates the code vocabulary -- a raw
  // socket error, or something thrown by a dependency. If a *ad-hal* error
  // starts landing here, the fix is to give it a code, not to add a
  // pattern.
  //
  // ONE PATTERN WAS REMOVED IN W11, and it is worth saying why rather than
  // just deleting it. It matched /failed the code proof/ to produce a
  // 'bad-proof' bucket -- which is exactly the prose coupling the rest of
  // this comment warns against, and it was already dead: a drop that ends
  // with peers having failed their handshake reports ERR_NO_HANDSHAKE,
  // which the table above catches first. Failed confirmations are
  // per-candidate events, not drop outcomes, so they are now counted
  // where they happen, off the code ERR_PAKE_CONFIRMATION -- see
  // `badConfirmations` below.
  const message = (err && err.message) || String(err)
  if (/timed out/.test(message)) return 'timeout-other'
  return 'transfer-error'
}

// `dialBaselineMs` is the wall-clock moment the sender is scheduled to
// start dialing. Connect and completion times are measured from there, not
// from when this side started waiting, so the two roles report comparable
// numbers. Measuring from the receiver's own start would silently add
// SENDER_LEAD_MS to every figure -- an instrument that inflates the
// connect time by ten seconds would corrupt any read against plan section
// 8's "10 MB median < 30-45s" target.
async function runReceiverTrial (i, budgetMs, dialBaselineMs) {
  const { topic, nameplate, secret } = resolveCode(codeForTrial(i))
  const swarm = createSwarm()
  const outDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'adhal-trial-'))
  const started = Date.now()
  const sinceDial = () => Math.max(0, Date.now() - dialBaselineMs)
  /** @type {any} */
  let manifest = null
  let announcedAt = null
  let candidateAt = null
  let badConfirmations = 0
  // WHERE a failure happened, and how far the bytes got. Added after a run
  // whose trial 4 the sender scored 'ok' and the receiver scored "connection
  // reset by peer": the suspect is the sender's 5s close-wait fallback
  // destroying a socket the receiver was still draining. `failedAtEpochMs`
  // is wall-clock so it can be lined up against the sender's
  // `destroyAtEpochMs` for the same trial -- valid to NTP accuracy, which
  // slot alignment already assumes.
  /** @type {'accept' | 'receive' | 'end'} */
  let phase = 'accept'
  let connectedAt = null
  let bytesReceived = 0
  /** @type {any} */
  let conn = null
  // Taken before the finally below destroys the swarm.
  const withNet = (/** @type {any} */ record) =>
    Object.assign(record, { nat: natSnapshot(swarm.dht), path: pathSnapshot(conn, swarm.dht) })

  try {
    const { socket, pending, sendKey, receiveKey } = await acceptOnce(swarm, topic, {
      nameplate,
      secret,
      timeout: budgetMs,
      refreshInterval: refreshMs,
      onAnnounced: () => { announcedAt = Date.now() - started },
      onCandidate: () => { if (candidateAt === null) candidateAt = sinceDial() },
      // Counted off the CODE, never off the message. On a private topic
      // this should be zero, so a non-zero count means either a
      // build-version skew between the two hosts or someone else on the
      // topic -- both of which would otherwise hide inside the
      // handshake-failure bucket and be read as a NAT problem.
      onCandidateDropped: (info, reason, code) => {
        if (code === ERR_CONFIRMATION) badConfirmations++
      }
    })
    socket.on('error', () => {})
    conn = socket
    connectedAt = sinceDial()

    phase = 'receive'
    const result = await receiveFile(socket, outDir, {
      sendKey,
      receiveKey,
      pending,
      onManifest: (m) => { manifest = m },
      onProgress: (p) => { bytesReceived = p.bytes }
    })
    // RESULT is written but only locally flushed, and the finally below
    // destroys the swarm. So wait for the transport to confirm the sender
    // has it, and for the sender's close in reply, as
    // cli/src/swarm-receive.js does; the file is already verified, so the
    // wait can cost the sender its confirmation but never this trial.
    //
    // Timed separately from the transfer, and its outcome recorded, after
    // 2026-10-12's run A trial 9: this wait was a flat 5s then, and the
    // receiver's record could not say whether it had run out -- which was
    // the whole question once the sender reported a reset for a file the
    // receiver had saved. completedMs used to include it, too.
    //
    // Bounded by what is left of this trial's budget as well, so a drop
    // that finished late cannot wait into the next slot. Cut short that
    // way, the outcome is still an honest 'timeout'.
    phase = 'end'
    const completedMs = sinceDial()
    const left = started + budgetMs - Date.now() - CLOSE_GRACE_MS
    const closeWait = await closeAfterResult(socket, {
      deliveryTimeout: Math.max(1000, Math.min(RESULT_DELIVERY_TIMEOUT_MS, left))
    })

    // A CROSS-CHECK, no longer the integrity check itself.
    //
    // This comparison used to be the only place in the repo that verified
    // a received file against its manifest -- the measurement harness did
    // it and neither CLI did. The failure-reporting work moved it into receiveFile, where it
    // is unconditional, so reaching this line at all means the engine
    // already compared these two digests and was satisfied.
    //
    // It is kept anyway, and labeled differently, because it now tests
    // something else: that the engine's verification agrees with an
    // independent comparison. A disagreement cannot be a corrupt transfer
    // (the engine would have rejected it); it can only be a bug in the
    // verification itself, which is worth hearing about loudly and
    // separately.
    const crossCheckOk = !!manifest && manifest.sha256 === result.sha256
    return withNet({
      trial: i,
      outcome: crossCheckOk ? 'ok' : 'hash-crosscheck-disagreed',
      announcedMs: announcedAt,
      candidateMs: candidateAt,
      connectedMs: connectedAt,
      completedMs,
      badConfirmations,
      bytes: result.size,
      sha256: result.sha256,
      closeWait: closeWait.outcome,
      closeWaitMs: closeWait.ms,
      closeWaitAcked: closeWait.acked,
      closeWaitError: closeWait.error
    })
  } catch (err) {
    return withNet({
      trial: i,
      outcome: classify(err),
      announcedMs: announcedAt,
      candidateMs: candidateAt,
      connectedMs: connectedAt,
      badConfirmations,
      error: err.message,
      phase,
      bytesReceived,
      manifestSize: manifest ? manifest.size : null,
      cause: err && err.cause ? err.cause.message : null,
      failedAtEpochMs: Date.now()
    })
  } finally {
    await swarm.destroy().catch(() => {})
    await fs.promises.rm(outDir, { recursive: true, force: true }).catch(() => {})
  }
}

async function runSenderTrial (i, budgetMs) {
  const { topic, nameplate, secret } = resolveCode(codeForTrial(i))
  const swarm = createSwarm()
  const started = Date.now()
  let candidateAt = null
  let dropped = 0
  let badConfirmations = 0
  // How the post-send wait ended. This used to be the only evidence
  // against a false 'ok': sendFile resolved on hand-off, and all six of the
  // proofv2-3 run's receiver-side resets were among its nine 'timer'
  // trials, none among the 91 that closed. sendFile now resolves only
  // on the receiver's RESULT, so 'ok' here means delivered and verified,
  // and a 'timer' now only means the receiver was slow to close after
  // confirming. Kept because a rise in timers would still be worth seeing.
  /** @type {'closed' | 'timer' | null} */
  let closeWait = null
  let closeWaitMs = null
  let sentAtEpochMs = null
  /** @type {string | null} */
  let socketErrorAfterSend = null
  /** @type {any} */
  let out
  /** @type {any} */
  let conn = null

  try {
    const { socket, pending, sendKey, receiveKey } = await connectOnce(swarm, topic, {
      nameplate,
      secret,
      timeout: budgetMs,
      refreshInterval: refreshMs,
      onCandidate: () => { if (candidateAt === null) candidateAt = Date.now() - started },
      onCandidateDropped: (info, reason, code) => {
        dropped++
        if (code === ERR_CONFIRMATION) badConfirmations++
      }
    })
    socket.on('error', () => {})
    conn = socket
    const connectedAt = Date.now() - started

    // `pending` is anything the receiver coalesced after its proof.
    // Ordinarily empty, but sendFile reads now (for CANCEL), so dropping
    // it would lose a message rather than merely skipping a no-op.
    const result = await sendFile(socket, filePath, { sendKey, receiveKey, pending })
    sentAtEpochMs = Date.now()
    socket.on('error', (err) => { if (!socketErrorAfterSend) socketErrorAfterSend = err.message })
    socket.end()
    // A socket already gone before the wait starts would never emit
    // 'close' to this listener, and would be misreported as 'timer'.
    closeWait = socket.destroyed
      ? 'closed'
      : await Promise.race([
        new Promise((resolve) => socket.once('close', () => resolve('closed'))),
        sleep(5000).then(() => 'timer')
      ])
    closeWaitMs = Date.now() - sentAtEpochMs

    out = {
      trial: i,
      outcome: 'ok',
      candidateMs: candidateAt,
      connectedMs: connectedAt,
      completedMs: Date.now() - started,
      droppedCandidates: dropped,
      badConfirmations,
      bytes: result.size,
      sha256: result.sha256,
      closeWait,
      closeWaitMs,
      sentAtEpochMs,
      socketErrorAfterSend
    }
  } catch (err) {
    out = {
      trial: i,
      outcome: classify(err),
      candidateMs: candidateAt,
      droppedCandidates: dropped,
      badConfirmations,
      error: err.message,
      // 'send' or 'result': whether the receiver was lost while bytes were
      // still going out, or after they all had and before it confirmed.
      // The second is the case the receiver's own record has to settle.
      phase: (err && err.phase) || null,
      bytesSent: err && typeof err.bytes === 'number' ? err.bytes : null,
      manifestSize: err && err.size !== undefined ? err.size : null,
      // The transport's own error behind an ERR_CONNECTION, e.g. "connection
      // reset by peer". Before the engine wrapped socket errors, that was
      // all a record got.
      cause: err && err.cause ? err.cause.message : null,
      failedAtEpochMs: Date.now()
    }
  } finally {
    // Stamped immediately before the destroy, so it can be lined up with
    // the receiver's `failedAtEpochMs`. This destroy was what reset
    // receivers still draining, before sendFile waited for RESULT.
    if (out) {
      Object.assign(out, { nat: natSnapshot(swarm.dht), path: pathSnapshot(conn, swarm.dht) })
      out.destroyAtEpochMs = Date.now()
    }
    await swarm.destroy().catch(() => {})
  }
  return out
}

function percentile (sorted, p) {
  if (sorted.length === 0) return null
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))
  return sorted[idx]
}

function summarise (results, startNat) {
  const ok = results.filter((r) => r.outcome === 'ok')
  const rate = results.length ? (ok.length / results.length) * 100 : 0
  const connects = ok.map((r) => r.connectedMs).filter((v) => typeof v === 'number').sort((a, b) => a - b)

  const counts = new Map()
  for (const r of results) {
    if (r.outcome === 'ok') continue
    counts.set(r.outcome, (counts.get(r.outcome) || 0) + 1)
  }

  log('')
  log('=== SUMMARY ===')
  log(`role: ${role}   seed: ${seed}   trials: ${results.length}   refresh: ${refreshMs ?? 4000}ms`)
  log(`succeeded: ${ok.length}/${results.length}  (${rate.toFixed(0)}%)`)
  if (connects.length) {
    const median = percentile(connects, 50)
    const p90 = percentile(connects, 90)
    log(`connect time: median ${(median / 1000).toFixed(1)}s  p90 ${(p90 / 1000).toFixed(1)}s  ` +
      `min ${(connects[0] / 1000).toFixed(1)}s  max ${(connects[connects.length - 1] / 1000).toFixed(1)}s`)
  }
  if (counts.size) {
    log('failures:')
    for (const [reason, n] of [...counts].sort((a, b) => b[1] - a[1])) {
      log(`  ${reason.padEnd(22)} ${n}`)
    }
  }

  // Reported separately from the failure buckets, because a failed
  // confirmation is not a trial outcome: a trial can succeed having
  // rejected several peers first, which is the behavior section 6 relies
  // on. On a private topic this should be zero, and a non-zero total is
  // worth a line of its own -- it means peers reached the nameplate
  // without the secret, i.e. a version skew between the two hosts or
  // somebody else on the topic.
  // A sender-side 'ok' now means the receiver's RESULT confirmed the same
  // digest, so the two roles' rates should agree. A 'timer' is a receiver
  // that confirmed and was then slow to close: harmless to the file.
  const timerWaits = ok.filter((r) => r.closeWait === 'timer').length
  if (role === 'sender' && ok.length) {
    log(`close wait: ${ok.length - timerWaits} closed by receiver, ${timerWaits} ended by the 5s timer (after RESULT)`)
  }
  // The receiver's side of the same wait (closeAfterResult). 'closed' is
  // the sender ending in reply, which it does only once it has RESULT.
  // 'acked' is harmless: the sender's transport has RESULT. 'lost' and
  // 'timeout' are the ones that matter -- the sender probably never
  // heard, and its record for that trial is likely a failure the file
  // does not deserve.
  if (role === 'receiver' && ok.length) {
    const by = (outcome) => ok.filter((r) => r.closeWait === outcome).length
    log(`close wait: ${by('closed')} ended by sender, ${by('acked')} acked without an end, ` +
      `${by('lost')} connection lost, ${by('timeout')} never acked (after RESULT)`)
    const unconfirmed = ok.filter((r) => r.closeWait === 'lost' || r.closeWait === 'timeout').map((r) => r.trial + 1)
    if (unconfirmed.length) {
      log(`   trial(s) ${unconfirmed.join(', ')}: this side saved the file, but the sender probably`)
      log('   never got RESULT. Expect its record to show phase=result for those.')
    }
  }
  const unconfirmed = results.filter((r) => r.phase === 'result').length
  if (role === 'sender' && unconfirmed) {
    log(`   ${unconfirmed} trial(s) sent every byte and never got RESULT; the receiver's`)
    log('   record for those trials is the only one that knows whether the file landed.')
  }

  // Whether this side's NAT held still. Each line is one side only; the
  // other machine's log has its half.
  const natKinds = new Map()
  for (const r of results) {
    if (!r.nat) continue
    const key = describeNat({ ...r.nat, samples: undefined, publicHost: undefined })
    natKinds.set(key, (natKinds.get(key) || 0) + 1)
  }
  if (natKinds.size) {
    log(`nat (this side): at start ${describeNat({ ...startNat, publicHost: undefined })}`)
    for (const [key, n] of natKinds) log(`   ${String(n).padStart(3)} trial(s): ${key}`)
    if (natKinds.size > 1) log('   CHANGED DURING THE RUN -- read failures against the trials where it did')
  }
  const paths = results.map((r) => r.path).filter((p) => p && !p.error)
  if (paths.length) {
    const kinds = new Map()
    for (const p of paths) kinds.set(p.remoteKind, (kinds.get(p.remoteKind) || 0) + 1)
    log(`peer address: ${[...kinds].map(([k, n]) => `${k} ${n}`).join(', ')}` +
      (kinds.has('private') ? '  (private = same LAN, not a punch across the internet)' : ''))
  }

  const badConfirmations = results.reduce((n, r) => n + (r.badConfirmations || 0), 0)
  if (badConfirmations > 0) {
    log('')
    log(`>> ${badConfirmations} PEER(S) FAILED THE PAKE CONFIRMATION across these trials.`)
    log('   Nobody should be able to reach this topic without the secret. Check')
    log('   both hosts are on the same build before reading anything else here.')
  }

  // Interpretation, so the number is actionable rather than decorative.
  //
  // Both buckets count, and they mean different things. 'hash-mismatch'
  // is the engine having rejected a file whose bytes did not match the
  // manifest. 'hash-crosscheck-disagreed' is worse: the engine accepted a
  // file that an independent comparison says is wrong, i.e. the
  // verification itself is broken.
  const mismatches = results.filter((r) => r.outcome === 'hash-mismatch').length
  const crossCheckFailures = results.filter((r) => r.outcome === 'hash-crosscheck-disagreed').length
  log('')
  if (crossCheckFailures > 0) {
    log(`>> ${crossCheckFailures} TRIAL(S) WHERE THE ENGINE ACCEPTED A FILE THIS HARNESS SAYS IS WRONG.`)
    log('   That is a bug in hash verification itself, not in the transfer.')
    log('   Stop everything and investigate engine/src/transfer.js finalize().')
  } else if (mismatches > 0) {
    log(`>> ${mismatches} HASH MISMATCH(ES). This is a correctness bug, not a network`)
    log('   failure. Stop feature work and investigate framing/chunking.')
  } else if (results.length < 5) {
    log('>> Too few trials to call a rate. Use --trials 10 or more.')
  } else if (rate >= 75) {
    log(`>> ${rate.toFixed(0)}% meets the >=75% reliability bar for this path.`)
    if (counts.get('no-peer')) {
      log(`   ${counts.get('no-peer')} trial(s) never saw a peer -- intermittent discovery or punch`)
      log('   failure, which is what makes a single failing run look like a bug.')
    }
  } else if (rate >= 50) {
    log(`>> ${rate.toFixed(0)}% is below the 75% reliability bar but above the`)
    log('   kill threshold of 50%. This path is flaky, not broken -- expect')
    log('   single runs to fail and do not read a code bug into them.')
  } else {
    log(`>> ${rate.toFixed(0)}% is below the 50% kill threshold. On this path,`)
    log('   relay quality is the product, not an optional extra.')
  }
}

async function main () {
  log(`host machine: ${os.hostname()} (${os.platform()}/${os.arch()}) node ${process.version}`)
  log(`role=${role} seed=${seed} trials=${trials} slot=${slotSeconds}s refresh=${refreshMs ?? 'default(4000)'}`)
  const build = buildInfo()
  const interfaces = interfaceSummary()
  log(`build: commit ${build.commit ?? 'unknown'}${build.dirty ? ' (UNCOMMITTED CHANGES)' : build.dirty === false ? ' (clean)' : ''}  ` +
    Object.entries(build.versions).map(([name, v]) => `${name} ${v ?? '?'}`).join('  ') +
    `  os ${os.platform()} ${os.release()}`)
  log(`interfaces: ${interfaces.ipv4} IPv4${interfaces.cgnatIpv4 ? ` (${interfaces.cgnatIpv4} in the CGNAT range 100.64/10)` : ''}, ` +
    `global IPv6 ${interfaces.globalIpv6 ? 'yes' : 'no'}`)
  const version = osVersion()
  const access = accessSnapshot()
  const vpn = vpnSnapshot(access)
  const hostFirewall = hostFirewallSnapshot()
  log(`os: ${version.pretty ?? 'product version unknown'}`)
  log(`access: ${describeAccess(access)}`)
  log(`vpn: ${describeVpn(vpn)}`)
  log(`host firewall: ${describeFirewall(hostFirewall)}`)
  const { nat: startNat, isp } = await probeNat()
  log(`nat at start: ${describeNat(startNat)}  <-- each side sees only its own; compare both logs`)
  log(`isp: ${describeIsp(isp)}`)
  for (const note of notes) log(`note: ${note}`)
  const environment = {
    hostname: os.hostname(),
    os: { platform: os.platform(), release: os.release(), arch: os.arch(), ...version },
    node: process.version,
    build,
    interfaces,
    access,
    vpn,
    hostFirewall,
    natAtStart: startNat,
    isp,
    notes,
    addressesRecorded: recordAddresses
  }
  let file = null
  if (role === 'sender') {
    const stat = await fs.promises.stat(filePath)
    file = { path: filePath, size: stat.size }
    log(`file: ${filePath} (${stat.size} bytes)`)
  }
  // Printed so that two hosts which picked different schedules are caught
  // immediately, rather than producing a confusing 0% result.
  log(`slot start: ${Math.floor(startMs / 1000)} (${new Date(startMs).toLocaleTimeString()}) ` +
    '<-- MUST MATCH ON BOTH MACHINES')
  log(`waiting ${((startMs - Date.now()) / 1000).toFixed(0)}s for the first slot...`)

  const results = []
  for (let i = 0; i < trials; i++) {
    const slotStart = startMs + i * SLOT_MS
    const myStart = slotStart + (role === 'sender' ? SENDER_LEAD_MS : 0)
    await sleep(myStart - Date.now())

    // Budget ends before the slot does, so a hung trial cannot bleed into
    // the next one and corrupt its result.
    const budget = (slotStart + SLOT_MS - TEARDOWN_MS) - Date.now()
    if (budget < 5000) {
      log(`trial ${i + 1}/${trials}: SKIPPED (slot already over -- clock skew or a slot too short)`)
      results.push({ trial: i, outcome: 'skipped' })
      continue
    }

    const result = role === 'receiver'
      ? await runReceiverTrial(i, budget, slotStart + SENDER_LEAD_MS)
      : await runSenderTrial(i, budget)
    results.push(result)

    const timing = typeof result.completedMs === 'number'
      ? ` connect=${(result.connectedMs / 1000).toFixed(1)}s total=${(result.completedMs / 1000).toFixed(1)}s`
      : ''
    // The lines that line one side's 'ok' up against the other's failure:
    // how each side's close wait ended, and where a failed side stopped.
    const closeInfo = result.closeWait
      ? ` close=${result.closeWait}(${(result.closeWaitMs / 1000).toFixed(1)}s)` +
        (result.destroyAtEpochMs ? ` destroyAt=${result.destroyAtEpochMs}` : '')
      : ''
    const failInfo = result.phase
      ? ` [phase=${result.phase} bytes=${result.bytesReceived ?? result.bytesSent}/${result.manifestSize ?? '?'}` +
        `${result.cause ? ` cause="${result.cause}"` : ''} failedAt=${result.failedAtEpochMs}]`
      : ''
    // This side's NAT for the trial, and how the path behaved. Retransmits
    // and RTO counts are the ones to read beside a slow or failed trial.
    const p = result.path
    const netInfo = (result.nat ? ` nat=${result.nat.kind}` : '') +
      (p && !p.error
        ? ` path=${p.remoteKind ?? '?'} rtt=${p.rttMs}ms retx=${p.retransmits} rto=${p.rtoCount}`
        : '')
    log(`trial ${i + 1}/${trials}: ${result.outcome}${timing}${closeInfo}${netInfo}${result.error ? ` -- ${result.error}` : ''}${failInfo}`)
  }

  summarise(results, startNat)

  if (outPath) {
    await fs.promises.writeFile(outPath, JSON.stringify({
      role,
      seed,
      trials,
      slotSeconds,
      refreshMs: refreshMs ?? 4000,
      startEpoch: Math.floor(startMs / 1000),
      startedAtEpochMs: t0,
      endedAtEpochMs: Date.now(),
      file,
      environment,
      results
    }, null, 2))
    log(`per-trial JSON written to ${outPath}`)
  }
}

main().catch((err) => {
  console.error('scratch-trials failed:', err.message)
  process.exit(1)
})
