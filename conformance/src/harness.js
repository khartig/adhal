'use strict'

// The conformance harness: a reference peer that drives an implementation
// under test (the IUT) through a drop over loopback TCP, and checks what
// the IUT puts on the wire against PROTOCOL.md.
//
// HOW IT SEES THE WIRE WITHOUT INJECTING ANYTHING. The handshake is random,
// and no implementation should accept an injected scalar or sid (section
// 3.2, trap #1), so the harness cannot make the IUT produce fixed bytes.
// It does not need to. It is a party to the handshake: it holds its own
// scalar and the secret, so it derives the same ISK and both channel keys,
// and can open every frame the IUT sends and seal every frame it sends
// back. Each frame from the IUT is checked as it arrives -- its declared
// length against section 5's bounds, its authentication under the right
// direction's key with the next counter and its own header as associated
// data, its type, and its body -- before the scenario looks at what it
// means. A frame that fails any of those fails the scenario, whatever the
// scenario was about.
//
// THE ADAPTER CONTRACT (docs/CONFORMANCE.md has it in full). The harness
// listens on 127.0.0.1 and starts the adapter, which connects:
//
//   <adapter...> receive --connect 127.0.0.1:<port> --dir <dir> [--cancel-after <bytes>]
//   <adapter...> send    --connect 127.0.0.1:<port> --file <path> [--stream] [--cancel-after <bytes>]
//
// with the code in ADHAL_CONFORMANCE_NAMEPLATE and ADHAL_CONFORMANCE_SECRET
// (never on argv, as the CLIs keep it off argv). The adapter runs one
// connection, one attempt, and writes one JSON line to stdout as it exits:
// {"ok":true} or {"ok":false,"code":"<section 10 code>"}. A receiver
// accepts every offer that passes its own checks.

const net = require('node:net')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const crypto = require('node:crypto')
const { spawn } = require('node:child_process')

const wire = require('./wire')

const READ_TIMEOUT_MS = 10000
const EXIT_TIMEOUT_MS = 15000
const CONNECT_TIMEOUT_MS = 15000

/** A conformance failure: what the IUT did, and the section it breaks. */
class Failure extends Error {
  /** @param {string} message @param {string} [ref] */
  constructor (message, ref) {
    super(ref ? `${message} (${ref})` : message)
    this.name = 'Failure'
    this.ref = ref
  }
}

/** @param {string} message @param {string} [ref] @returns {never} */
function fail (message, ref) {
  throw new Failure(message, ref)
}

class ConnClosed extends Error {}
class ConnTimeout extends Error {}

/**
 * A socket as a byte queue the scenario reads exactly-n from. Everything
 * the IUT sends is buffered as it arrives, so the IUT is never blocked by
 * a harness that is busy writing, and a frame the IUT sent just before
 * closing is still read before the close is.
 */
class Conn {
  /** @param {net.Socket} socket */
  constructor (socket) {
    this.socket = socket
    /** @type {Buffer[]} */
    this.chunks = []
    this.length = 0
    this.ended = false
    /** @type {Error | null} */
    this.error = null
    /** @type {(() => void) | null} */
    this.waiter = null
    socket.on('data', (/** @type {Buffer} */ chunk) => {
      this.chunks.push(chunk)
      this.length += chunk.length
      this._wake()
    })
    const end = () => { this.ended = true; this._wake() }
    socket.on('end', end)
    socket.on('close', end)
    socket.on('error', (err) => { this.error = err; end() })
  }

  _wake () {
    const w = this.waiter
    this.waiter = null
    if (w) w()
  }

  /** @param {number} timeout */
  _wait (timeout) {
    return new Promise((resolve) => {
      this.waiter = () => resolve(undefined)
      setTimeout(() => resolve(undefined), timeout).unref()
    })
  }

  /**
   * Exactly n bytes, or ConnClosed / ConnTimeout.
   * @param {number} n
   * @param {number} [timeout]
   */
  async read (n, timeout = READ_TIMEOUT_MS) {
    this.socket.resume()
    const deadline = Date.now() + timeout
    while (this.length < n) {
      if (this.ended) throw new ConnClosed(`closed${this.error ? ` by ${/** @type {any} */ (this.error).code || this.error.message}` : ''} with ${this.length} of ${n} bytes`)
      const left = deadline - Date.now()
      if (left <= 0) throw new ConnTimeout(`${this.length} of ${n} bytes after ${timeout}ms`)
      await this._wait(left)
    }
    const all = Buffer.concat(this.chunks)
    const out = all.subarray(0, n)
    const rest = all.subarray(n)
    this.chunks = rest.length ? [rest] : []
    this.length = rest.length
    return out
  }

  /**
   * Resolves true once the IUT has closed with nothing left unread, false
   * if bytes arrive first or the time runs out.
   * @param {number} [timeout]
   */
  async closes (timeout = READ_TIMEOUT_MS) {
    this.socket.resume()
    const deadline = Date.now() + timeout
    for (;;) {
      if (this.length > 0) return false
      if (this.ended) return true
      const left = deadline - Date.now()
      if (left <= 0) return false
      await this._wait(left)
    }
  }

  /**
   * Waits up to `ms` and reports whether anything arrived. For the checks
   * that something did NOT happen: no file byte before ACCEPT.
   * @param {number} ms
   */
  async quietFor (ms) {
    const deadline = Date.now() + ms
    while (this.length === 0 && !this.ended && Date.now() < deadline) await this._wait(deadline - Date.now())
    return this.length === 0
  }

  /**
   * Writes with backpressure. False when the IUT has already gone, which a
   * scenario that has just been canceled expects and others treat as the
   * IUT hanging up early.
   * @param {Buffer} bytes
   */
  async write (bytes) {
    if (this.ended || this.socket.destroyed) return false
    if (this.socket.write(bytes)) return true
    await new Promise((resolve) => {
      const done = () => {
        this.socket.off('drain', done)
        this.socket.off('close', done)
        resolve(undefined)
      }
      this.socket.on('drain', done)
      this.socket.on('close', done)
    })
    return !this.socket.destroyed
  }

  /**
   * Stops taking bytes off the socket until the next read, so the IUT's
   * writes back up the way they would against a slow receiver. For the
   * scenario that needs a sender held mid-file.
   */
  pause () { this.socket.pause() }

  end () { this.socket.end() }
  destroy () { this.socket.destroy() }
}

/**
 * The bytes of `n`, read for the named purpose, with the IUT's close or
 * silence reported as the failure it is.
 * @param {Conn} conn @param {number} n @param {string} what @param {number} [timeout]
 */
async function readFor (conn, n, what, timeout) {
  try {
    return await conn.read(n, timeout)
  } catch (err) {
    if (err instanceof ConnClosed) fail(`the implementation closed the connection while the harness waited for ${what} (${err.message})`)
    if (err instanceof ConnTimeout) fail(`the implementation sent no ${what} (${err.message})`)
    throw err
  }
}

const utf8 = (/** @type {string} */ s) => Buffer.from(s, 'utf8')

/** @param {Buffer} b */
function flipLastBit (b) {
  const out = Buffer.from(b)
  out[out.length - 1] ^= 0x01
  return out
}

// --- the handshake, harness as sender: the IUT is the receiver ------------

/**
 * Reads and checks the IUT's HELLO.
 * @param {Conn} conn
 */
async function readHello (conn) {
  const prefix = await readFor(conn, 2, 'HELLO')
  const len = prefix.readUInt16BE(0)
  if (len < wire.HELLO_BODY.min || len > wire.HELLO_BODY.max) {
    fail(`HELLO declares a ${len}-byte body; v2 allows ${wire.HELLO_BODY.min}-${wire.HELLO_BODY.max}`, 'section 3.1')
  }
  const body = await readFor(conn, len, 'the rest of HELLO')
  if (body[0] !== wire.VERSION) fail(`HELLO carries version 0x${body[0].toString(16)}, not 0x02`, 'section 3.1')
  const sid = body.subarray(1, 1 + wire.SID_SIZE)
  const Ya = body.subarray(1 + wire.SID_SIZE, wire.HELLO_FIXED)
  const capsR = body.subarray(wire.HELLO_FIXED)
  const tokens = wire.parseCanonicalCaps(capsR)
  if (!tokens) fail(`HELLO's caps_r ${JSON.stringify(capsR.toString('utf8'))} is not the canonical encoding`, 'section 3.2, trap #2')
  return { bytes: Buffer.concat([prefix, body]), sid: Buffer.from(sid), Ya: Buffer.from(Ya), capsR: Buffer.from(capsR), tokens }
}

/**
 * The harness's REPLY to a HELLO. The options are the transformations
 * handshake-negative.json describes; with none, it is an honest REPLY.
 *
 * @param {Awaited<ReturnType<typeof readHello>>} hello
 * @param {{ nameplate: string, secret: string, caps?: string[],
 *   capsRSeenAs?: string, capsSSentAs?: string, capsSRaw?: Buffer, flipConfirmS?: boolean }} o
 *   `capsRSeenAs` MACs caps_r as if HELLO had arrived with that value (caps
 *   stripped from HELLO in transit). `capsSSentAs` sends caps_s as that
 *   value after MACing the real one (stripped from REPLY). `capsSRaw`
 *   sends and MACs bytes verbatim, canonical or not.
 */
function reply (hello, o) {
  const caps = o.caps || wire.KNOWN_CAPS
  const g = wire.calculateGenerator(utf8(o.secret), wire.channelIdentifier(o.nameplate), hello.sid)
  const yb = crypto.randomBytes(32)
  const Yb = wire.scalarMultVfy(yb, g)
  let K
  try {
    K = wire.scalarMultVfy(yb, hello.Ya)
  } catch {
    fail('HELLO\'s Ya yields the neutral element', 'section 3.2')
  }
  const capsS = o.capsSRaw || wire.encodeCaps(caps)
  const capsRMacd = o.capsRSeenAs !== undefined ? utf8(o.capsRSeenAs) : hello.capsR
  const transcript = wire.transcriptIR(hello.Ya, wire.associatedData(capsRMacd), Yb, wire.associatedData(capsS))
  const keys = wire.deriveKeys(hello.sid, K, transcript)
  const confirmS = o.flipConfirmS ? flipLastBit(keys.confirmS) : keys.confirmS
  const sent = o.capsSSentAs !== undefined ? utf8(o.capsSSentAs) : capsS
  return {
    bytes: wire.withLength16(Buffer.concat([Yb, confirmS, sent])),
    keys,
    caps: wire.effectiveCaps(caps, hello.tokens)
  }
}

// --- the handshake, harness as receiver: the IUT is the sender ------------

/**
 * The harness's HELLO.
 * @param {{ nameplate: string, secret: string, caps?: string[], version?: number, capsRaw?: Buffer }} o
 */
function hello (o) {
  const caps = o.caps || wire.KNOWN_CAPS
  const sid = crypto.randomBytes(wire.SID_SIZE)
  const ya = crypto.randomBytes(32)
  const g = wire.calculateGenerator(utf8(o.secret), wire.channelIdentifier(o.nameplate), sid)
  const Ya = wire.scalarMultVfy(ya, g)
  const capsR = o.capsRaw || wire.encodeCaps(caps)
  const version = o.version === undefined ? wire.VERSION : o.version
  return { bytes: wire.withLength16(Buffer.concat([Buffer.from([version]), sid, Ya, capsR])), sid, ya, Ya, capsR, caps }
}

/**
 * Reads and checks the IUT's REPLY to `h`, including that its confirmS
 * verifies: an IUT whose confirmation does not is deriving a different
 * transcript or key, and nothing after it can interoperate.
 * @param {Conn} conn
 * @param {ReturnType<typeof hello>} h
 */
async function readReply (conn, h) {
  const prefix = await readFor(conn, 2, 'REPLY')
  const len = prefix.readUInt16BE(0)
  if (len < wire.REPLY_BODY.min || len > wire.REPLY_BODY.max) {
    fail(`REPLY declares a ${len}-byte body; v2 allows ${wire.REPLY_BODY.min}-${wire.REPLY_BODY.max}`, 'section 3.1')
  }
  const body = await readFor(conn, len, 'the rest of REPLY')
  const Yb = body.subarray(0, 32)
  const confirmS = body.subarray(32, wire.REPLY_FIXED)
  const capsS = body.subarray(wire.REPLY_FIXED)
  const tokens = wire.parseCanonicalCaps(capsS)
  if (!tokens) fail(`REPLY's caps_s ${JSON.stringify(capsS.toString('utf8'))} is not the canonical encoding`, 'section 3.2, trap #2')
  let K
  try {
    K = wire.scalarMultVfy(h.ya, Yb)
  } catch {
    fail('REPLY\'s Yb yields the neutral element', 'section 3.2')
  }
  const transcript = wire.transcriptIR(h.Ya, wire.associatedData(h.capsR), Yb, wire.associatedData(capsS))
  const keys = wire.deriveKeys(h.sid, K, transcript)
  if (!crypto.timingSafeEqual(keys.confirmS, confirmS)) {
    fail('REPLY\'s confirmS does not verify: the implementation derived a different transcript or key', 'section 3.2')
  }
  return { keys, caps: wire.effectiveCaps(h.caps, tokens) }
}

// --- the sealed channel ---------------------------------------------------

/**
 * One side of the sealed channel, after the handshake. Every frame read
 * from the IUT is checked against sections 3.4, 4, and 5 before it is
 * returned.
 */
class SealedPeer {
  /**
   * @param {Conn} conn
   * @param {{ sendKey: Buffer, receiveKey: Buffer, caps: string[], iut: 'sender' | 'receiver' }} o
   */
  constructor (conn, { sendKey, receiveKey, caps, iut }) {
    this.conn = conn
    this.sealer = new wire.Sealer(sendKey)
    this.opener = new wire.Opener(receiveKey)
    this.caps = caps
    this.iutDirection = iut === 'sender' ? 'k_s2r' : 'k_r2s'
    /** @type {string[]} the type of every frame the IUT sent, in order */
    this.received = []
  }

  /**
   * Seals and writes one frame. An object body is sent as JSON.
   * @param {number} type @param {Buffer | object} [body]
   */
  send (type, body = Buffer.alloc(0)) {
    const bytes = Buffer.isBuffer(body) ? body : utf8(JSON.stringify(body))
    return this.conn.write(this.sealer.seal(type, bytes))
  }

  /** @param {Buffer} bytes */
  sendRaw (bytes) {
    return this.conn.write(bytes)
  }

  /**
   * The next frame from the IUT, checked.
   * @param {{ timeout?: number, what?: string }} [o]
   * @returns {Promise<{ type: number, name: string, body: Buffer, json: any }>}
   */
  async next ({ timeout, what = 'a frame' } = {}) {
    const header = await readFor(this.conn, 4, what, timeout)
    const len = header.readUInt32BE(0)
    if (len < wire.MIN_SEALED) fail(`a frame declaring ${len} bytes, too short to be sealed`, 'section 5')
    if (len > wire.MAX_FRAME) fail(`a frame declaring ${len} bytes, over the ${wire.MAX_FRAME}-byte cap`, 'section 5')
    const sealed = await readFor(this.conn, len, 'the rest of a frame', timeout)
    const index = this.received.length
    const plaintext = this.opener.open(header, sealed)
    if (!plaintext) {
      fail(`frame #${index} from the implementation does not authenticate under ${this.iutDirection} with nonce counter ${index} and its length header as associated data`, 'sections 3.4 and 5')
    }
    const type = plaintext[0]
    const name = wire.TYPE_NAME[type]
    if (!name || type === wire.TYPE.RESERVED) fail(`frame #${index} has type 0x${type.toString(16).padStart(2, '0')}, which v2 does not define`, 'section 4')
    this.received.push(name)
    const body = plaintext.subarray(1)
    let json = null
    if (type !== wire.TYPE.CHUNK) {
      try {
        json = JSON.parse(body.toString('utf8'))
      } catch {
        fail(`the implementation's ${name} body is not JSON`, 'section 4')
      }
      if (json === null || typeof json !== 'object' || Array.isArray(json)) fail(`the implementation's ${name} body is not a JSON object`, 'section 4')
    }
    return { type, name, body, json }
  }

  /**
   * The next frame, which must be of type `type` (or one of `allow`,
   * handed to `onAllowed` and skipped).
   * @param {number} type
   * @param {{ allow?: number[], onAllowed?: (f: any) => void, timeout?: number }} [o]
   */
  async expect (type, { allow = [], onAllowed = () => {}, timeout } = {}) {
    for (;;) {
      const f = await this.next({ timeout, what: wire.TYPE_NAME[type] })
      if (f.type === type) return f
      if (allow.includes(f.type)) { onAllowed(f); continue }
      fail(`expected ${wire.TYPE_NAME[type]}, the implementation sent ${f.name}`, 'section 4.4')
    }
  }

  /**
   * Reads, and checks, whatever the IUT sends until it closes. For the end
   * of a scenario in which the IUT has refused something: it may still say
   * why (a CANCEL, a RESULT{error}), and what it says must be well formed.
   *
   * The one thing tolerated is a last frame cut short by the close. A side
   * that refuses mid-transfer tears the connection down, and a CHUNK it
   * was writing at that moment is lost with it; every complete frame
   * before it is still checked.
   * @param {number} [timeout]
   * @returns {Promise<any[] & { truncated?: boolean }>}
   */
  async drain (timeout = READ_TIMEOUT_MS) {
    /** @type {any[] & { truncated?: boolean }} */
    const frames = []
    for (;;) {
      if (await this.conn.closes(timeout)) return frames
      if (this.conn.length === 0) return frames
      const header = this.conn.length >= 4 ? Buffer.concat(this.conn.chunks).subarray(0, 4) : null
      const whole = header && this.conn.length >= 4 + header.readUInt32BE(0)
      if (!whole && this.conn.ended) {
        frames.truncated = true
        return frames
      }
      try {
        frames.push(await this.next({ timeout }))
      } catch (err) {
        if (this.conn.ended && /closed the connection/.test(String(err && err.message))) {
          frames.truncated = true
          return frames
        }
        throw err
      }
    }
  }
}

// --- one session: a listening port, the adapter, one connection ----------

const WORDS = ['acid', 'acorn', 'acre', 'acts', 'afar', 'aloft', 'amber', 'anvil', 'aptly', 'arena', 'badge', 'basil', 'bloom', 'cider', 'cobalt', 'delta']

/** A fresh nameplate and secret: canonical, lowercase, hyphenated (section 2). */
function freshCode () {
  const word = () => WORDS[crypto.randomInt(WORDS.length)]
  return { nameplate: `${word()}-${word()}`, secret: `${word()}-${word()}-${word()}` }
}

/**
 * @param {string[]} adapter the command, e.g. ['node', 'adapters/engine.js']
 * @param {'sender' | 'receiver'} iut
 * @param {string[]} args
 */
async function startSession (adapter, iut, args) {
  const code = freshCode()
  const server = net.createServer()
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => resolve(undefined))
  })
  const { port } = /** @type {net.AddressInfo} */ (server.address())

  const child = spawn(adapter[0], [...adapter.slice(1), iut === 'sender' ? 'send' : 'receive', '--connect', `127.0.0.1:${port}`, ...args], {
    env: { ...process.env, ADHAL_CONFORMANCE_NAMEPLATE: code.nameplate, ADHAL_CONFORMANCE_SECRET: code.secret },
    stdio: ['ignore', 'pipe', 'pipe']
  })
  let stdout = ''
  let stderr = ''
  child.stdout.on('data', (c) => { stdout += c })
  child.stderr.on('data', (c) => { stderr += c })
  /** @type {Promise<{ exitCode: number | null, signal: string | null, stdout: string, stderr: string }>} */
  const exited = new Promise((resolve) => {
    child.on('error', (err) => { stderr += String(err); resolve({ exitCode: null, signal: null, stdout, stderr }) })
    child.on('close', (exitCode, signal) => resolve({ exitCode, signal, stdout, stderr }))
  })

  /** @type {net.Socket | null} */
  const socket = await Promise.race([
    new Promise((resolve) => server.once('connection', resolve)),
    exited.then(() => null),
    new Promise((resolve) => setTimeout(() => resolve(null), CONNECT_TIMEOUT_MS).unref())
  ])
  server.close()
  if (!socket) {
    child.kill('SIGKILL')
    const r = await exited
    fail(`the adapter did not connect within ${CONNECT_TIMEOUT_MS}ms; stderr: ${r.stderr.trim().slice(-400) || '(none)'}`)
  }
  socket.on('error', () => {})
  const conn = new Conn(socket)
  return {
    code,
    conn,
    kill: () => child.kill('SIGKILL'),
    /**
     * The adapter's outcome line, once it exits. A missing or malformed
     * line, or an exit status that disagrees with it, is an adapter fault
     * and fails the scenario as one.
     * @param {number} [timeout]
     */
    async outcome (timeout = EXIT_TIMEOUT_MS) {
      const r = await Promise.race([exited, new Promise((resolve) => setTimeout(() => resolve(null), timeout).unref())])
      if (!r) {
        child.kill('SIGKILL')
        conn.destroy()
        fail(`the implementation did not finish within ${timeout}ms of the harness's last step`)
      }
      conn.destroy()
      const line = r.stdout.trim().split('\n').pop() || ''
      let outcome
      try {
        outcome = JSON.parse(line)
      } catch {
        fail(`the adapter's last stdout line is not its JSON outcome: ${JSON.stringify(line.slice(0, 200))}; stderr: ${r.stderr.trim().slice(-400)}`, 'adapter contract')
      }
      if (typeof outcome.ok !== 'boolean') fail('the adapter\'s outcome has no boolean "ok"', 'adapter contract')
      if ((r.exitCode === 0) !== outcome.ok) fail(`the adapter exited ${r.exitCode} with outcome ${line}`, 'adapter contract')
      return { ...outcome, stderr: r.stderr }
    }
  }
}

/**
 * @param {any} outcome
 * @param {{ ok: true } | { code: string }} expected
 */
function expectOutcome (outcome, expected) {
  if ('ok' in expected) {
    if (!outcome.ok) fail(`expected the drop to succeed; the implementation ended with ${outcome.code}${outcome.stderr ? `: ${outcome.stderr.trim().split('\n').pop()}` : ''}`)
    return
  }
  if (outcome.ok) fail(`expected the implementation to fail with ${expected.code}; it reported success`)
  if (outcome.code !== expected.code) {
    fail(`expected the implementation to fail with ${expected.code}; it reported ${outcome.code}${outcome.stderr ? `: ${outcome.stderr.trim().split('\n').pop()}` : ''}`, 'section 10')
  }
}

// --- the run --------------------------------------------------------------

/**
 * Per-scenario scratch space: output directories for an IUT receiver, and
 * source files for an IUT sender.
 */
async function makeContext () {
  const root = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'adhal-conformance-'))
  let n = 0
  return {
    root,
    /** A new, empty directory. */
    async dir () {
      const d = path.join(root, `out-${n++}`)
      await fs.promises.mkdir(d)
      return d
    },
    /**
     * A source file holding `size` random bytes (or `bytes`), named `name`.
     * @param {{ size?: number, bytes?: Buffer, name?: string }} o
     */
    async file ({ size = 0, bytes, name = 'conformance.bin' }) {
      const d = path.join(root, `src-${n++}`)
      await fs.promises.mkdir(d)
      const data = bytes || crypto.randomBytes(size)
      const p = path.join(d, name)
      await fs.promises.writeFile(p, data)
      return { path: p, name, data, sha256: wire.sha256(data) }
    },
    dispose: () => fs.promises.rm(root, { recursive: true, force: true })
  }
}

/**
 * Runs scenarios against an adapter, one at a time.
 * @param {string[]} adapter
 * @param {Array<{ id: string, title: string, refs: string, run: (t: any) => Promise<void> }>} scenarios
 * @param {{ onResult?: (r: { id: string, title: string, refs: string, ok: boolean, error?: string, ms: number }) => void }} [o]
 */
async function runScenarios (adapter, scenarios, { onResult = () => {} } = {}) {
  const results = []
  for (const s of scenarios) {
    const ctx = await makeContext()
    /** @type {Array<{ kill: () => void, conn: Conn }>} */
    const sessions = []
    const t = {
      ...ctx,
      /** @param {'sender' | 'receiver'} iut @param {string[]} args */
      async start (iut, args) {
        const session = await startSession(adapter, iut, args)
        sessions.push(session)
        return session
      }
    }
    const started = Date.now()
    let result
    try {
      await s.run(t)
      result = { id: s.id, title: s.title, refs: s.refs, ok: true, ms: Date.now() - started }
    } catch (err) {
      const error = err instanceof Failure ? err.message : `harness error: ${err && err.stack ? err.stack : err}`
      result = { id: s.id, title: s.title, refs: s.refs, ok: false, error, ms: Date.now() - started }
    } finally {
      for (const session of sessions) { session.kill(); session.conn.destroy() }
      await ctx.dispose()
    }
    results.push(result)
    onResult(result)
  }
  return results
}

module.exports = {
  Failure,
  fail,
  Conn,
  readHello,
  reply,
  hello,
  readReply,
  readFor,
  SealedPeer,
  startSession,
  expectOutcome,
  runScenarios,
  flipLastBit,
  READ_TIMEOUT_MS
}
