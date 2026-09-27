'use strict'

const crypto = require('node:crypto')
const {
  lvCat,
  calculateGenerator,
  sampleScalar,
  scalarMultVfy,
  transcriptIR,
  isk,
  ELEMENT_SIZE
} = require('./cpace')

// The v2 handshake: CPace over the wire, and the ad-hal-specific parameter
// mapping PROTOCOL.md section 3.2 specifies.
//
// This module owns that mapping and nothing else. Every field and group
// operation comes from ./cpace.js, which is checked against the CFRG
// vectors; the curve arithmetic is @noble/curves, which is audited. What
// is decided here is which ad-hal value goes into which CPace input -- the
// only genuinely novel piece of v2's handshake, and therefore the part
// worth stating in full.
//
//   PRS = the 3-word secret, canonical form, UTF-8    e.g. "acre-acts-afar"
//   CI  = lv_cat("adhal-v2", nameplate)                binds the rendezvous
//   sid = 16 CSPRNG bytes, chosen by the receiver, sent in HELLO
//   ADa = lv_cat(version, caps_r)                     receiver = initiator (A)
//   ADb = lv_cat(version, caps_s)                     sender   = responder (B)
//
// WHAT REPLACED WHAT. v1 proved knowledge of the code with an HMAC over
// nonces, bound to the Noise session's public keys (the deleted
// ./proof.js). That was sound as a proof and useless as a defence, because
// v1's topic was hash(code || salt): the topic is public the moment a
// receiver announces, so an attacker holding it could grind candidate codes
// offline and never touch a peer. And the Noise binding made the engine's
// security depend on which transport carried the bytes, which a relay or a
// browser would have to reinvent (section 3.3). Under v2 the secret is a
// PAKE password that is hashed into nothing an observer can obtain, and the
// binding is to the PAKE transcript.
//
// THE FOUR THINGS SECTION 3.2 SAYS AN IMPLEMENTATION MUST GET RIGHT, and
// where each one is handled:
//
//   1. ya, yb and sid are per CONNECTION, never per drop. Sampled in the
//      Initiator/Responder constructors, so there is nowhere to cache them
//      -- see the note on those classes, which is the trap this engine is
//      most exposed to.
//   2. caps has a byte-exact canonical encoding, fixed here and not left
//      to a serialiser. See encodeCaps.
//   3. Each side binds what it sent and what it received, verbatim. See
//      the note on parseCaps.
//   4. PRS is the secret's canonical form -- not the nameplate, which is
//      in CI, and not the QR payload's uppercase. Enforced by taking the
//      output of splitCode (./code.js) rather than a raw string, and
//      checked below.

// The wire version, carried in HELLO and bound into both ADa and ADb. A
// stripped capability or a forced-older version therefore makes the two
// sides derive different keys and both confirmations fail. Note the honest
// scope of that: detection, not prevention. The handshake aborts; it does
// not silently fall back, which is the correct outcome and the only one
// available to a one-round-trip PAKE.
const VERSION = 0x02

// sid is 16 bytes, the draft's recommended size, sampled per connection.
const SID_SIZE = 16

// HMAC-SHA256 output, and the size of both confirmations.
const CONFIRM_SIZE = 32

// The AEAD channel's key size (./channel.js).
const KEY_SIZE = 32

// The cap on a capability list, in bytes of canonical encoding. It exists
// so both HELLO and REPLY are BOUNDED: without it a peer could declare a
// length prefix of 65535 and make us buffer toward it before a single
// byte of the handshake has been authenticated. 128 bytes is room for
// seven or eight tokens, against the two that exist.
const MAX_CAPS_BYTES = 128

// A capability token: lowercase alphanumeric with internal hyphens, 1 to 16
// characters. Deliberately narrow. The charset excludes ',' so the
// separator cannot appear inside a token, which is what makes the canonical
// encoding parseable without escaping -- and escaping is where a
// "byte-exact" encoding would stop being byte-exact.
const CAPS_TOKEN = /^[a-z0-9]([a-z0-9-]{0,14}[a-z0-9])?$/

// The capabilities this build understands. A token outside this set is not
// an error -- see parseCaps -- it is simply not acted on.
//
// `resume` is ACCEPT{resumeFrom} plus CHECKPOINT (section 7); `stream` is
// size: null plus END{sha256} (section 4.3). Both were declared here in
// W11 ahead of the code, which is the right order: the capability is what
// lets the passes ship separately without a third wire break. `stream` is
// acted on as of W11's second pass -- sendStream will not offer, and
// receiveFile will not accept, a stream unless it is in the negotiated
// set. `resume` is still advertised and not yet acted on.
const KNOWN_CAPS = ['resume', 'stream']

// The domain-separation labels. Every one is distinct and every one is
// prefixed with the wire version, so no hash or KDF input from v2 can be
// replayed into a later version's context.
const CI_LABEL = 'adhal-v2'
const MAC_INFO = 'adhal-v2:mac'
const R2S_INFO = 'adhal-v2:r2s'
const S2R_INFO = 'adhal-v2:s2r'
const CONFIRM_S_LABEL = 'adhal-v2:confirm-s'
const CONFIRM_R_LABEL = 'adhal-v2:confirm-r'

// Message sizes. The length prefix is 2 bytes big-endian and counts the
// body that follows it.
//
// WHY REPLY IS LENGTH-PREFIXED, which section 3.1 as frozen by W10 said it
// would not be. That section fixed REPLY at 64 bytes and gave it no caps_s
// field -- but section 3.2 puts ADb = lv_cat(version, caps_s) inside
// transcript_ir, derives ISK from that transcript, and MACs confirmS under
// a key derived from ISK. The receiver therefore needs caps_s to verify the
// confirmation that arrives IN REPLY, and caps_s was sent nowhere. W11
// found that section 3.2's handshake was not implementable as section 3.1
// framed it; the amendment is recorded in PROTOCOL.md rather than edited
// in silently.
//
// The property section 3.1 actually calls load-bearing is untouched: the
// receiver still writes first and the sender still reads first and writes
// on answering, so Hyperswarm's duplicate tie-break sees the same
// first-read and first-write points. Checked against the source rather
// than the spec's paraphrase -- hyperswarm/index.js:359 computes
// `existingIsOutdated = existing.rawBytesRead > 0 && existing.rawBytesWritten > 0`
// and line 361 falls back to an initiator comparison, so it turns on
// WHETHER bytes moved, never on how many. A longer REPLY cannot affect it.
const LENGTH_PREFIX_SIZE = 2
const HELLO_FIXED = 1 + SID_SIZE + ELEMENT_SIZE // version, sid, Ya
const REPLY_FIXED = ELEMENT_SIZE + CONFIRM_SIZE // Yb, confirmS
const HELLO_MAX_BODY = HELLO_FIXED + MAX_CAPS_BYTES
const REPLY_MAX_BODY = REPLY_FIXED + MAX_CAPS_BYTES

// A per-candidate discard reason, not a drop outcome.
//
// NOT ADDED TO SECTION 10'S TABLE, deliberately. That table is the
// vocabulary for how a *drop* ended, and a single peer failing its
// confirmation does not end a drop: the receiver discards that candidate
// and keeps waiting, exactly as it does for a dead punch. What the drop
// eventually reports is ERR_NO_HANDSHAKE, or ERR_ATTEMPT_CAP once the cap
// exists (W11d, section 6). This code is how ./swarm.js tells a
// confirmation failure apart from a dropped candidate so that it counts
// the first and never the second -- and it is what lets
// ../scratch-trials.js count them without regex-matching prose, which is
// the coupling engine/src/errors.js exists to remove.
const ERR_CONFIRMATION = 'ERR_PAKE_CONFIRMATION'

// The one reason string for "this peer could not confirm the secret".
//
// Note what it cannot mean, which is different from v1 and narrower. Under
// v1 the topic and the key both came from the whole code, so a peer that
// reached us at all had necessarily derived the same key, and a proof
// failure was always either a stranger or a version skew. Under v2 the
// topic commits only to the nameplate, so there is a third case: a peer
// that got the NAMEPLATE right and the SECRET wrong -- which is what a
// half-mistyped code now looks like, and what an actual guessing attempt
// looks like. The two are indistinguishable here on purpose, and telling
// them apart is not possible in principle: that is what a PAKE does.
const CONFIRMATION_FAILED =
  'failed the PAKE confirmation -- either a peer that knows the nameplate ' +
  'but not the secret (a mistyped code, or someone guessing), or a build ' +
  'from before the v2 wire change (it is a wire-format change; both sides ' +
  'must be redeployed)'

/**
 * @param {string} message
 * @param {string} [code]
 * @returns {Error & { code: string }}
 */
function handshakeError (message, code = 'ERR_PROTOCOL') {
  const err = /** @type {Error & { code: string }} */ (new Error(message))
  err.code = code
  return err
}

/**
 * The canonical encoding of a capability set: deduplicated, sorted
 * bytewise ascending, joined with ',', UTF-8. The empty set encodes to
 * zero bytes.
 *
 * SECTION 3.2 TRAP #2. This has to be byte-exact and fixed by the spec
 * rather than left to a serialiser, because two implementations that order
 * the same set differently derive different keys and fail EVERY handshake
 * -- and the failure is indistinguishable from an attack, which is the
 * worst way for an interoperability bug to present. Sorting makes the
 * encoding independent of the order a caller happened to list them in;
 * deduplication makes it independent of repetition.
 *
 * Sorted with Buffer.compare rather than the default string sort. For this
 * charset the two agree, but "bytewise ascending" is what the spec says
 * and JavaScript's default sorts UTF-16 code units -- relying on them
 * coinciding would make the encoding depend on a coincidence.
 *
 * @param {string[]} tokens
 * @returns {Buffer}
 */
function encodeCaps (tokens) {
  if (!Array.isArray(tokens)) throw new TypeError('caps must be an array of strings')
  for (const token of tokens) {
    if (typeof token !== 'string' || !CAPS_TOKEN.test(token)) {
      throw new TypeError(`${JSON.stringify(token)} is not a valid capability token`)
    }
  }

  const unique = [...new Set(tokens)].sort((a, b) =>
    Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'))
  )
  const encoded = Buffer.from(unique.join(','), 'utf8')
  if (encoded.length > MAX_CAPS_BYTES) {
    throw new TypeError(`capabilities encode to ${encoded.length} bytes, over the ${MAX_CAPS_BYTES}-byte cap`)
  }
  return encoded
}

/**
 * Parses a peer's capability bytes, refusing anything non-canonical.
 *
 * SECTION 3.2 TRAP #3, AND THE RULE THAT MAKES IT HOLD: the caller hashes
 * the peer's bytes **verbatim as received**, never a re-serialisation of
 * this function's output. That is what keeps an unknown future token bound
 * into the transcript while being ignored behaviourally -- which is also
 * what lets v2.1 add a capability without breaking a v2 peer. A party that
 * negotiated down from a received value while MACing the original would
 * have reintroduced exactly the downgrade the transcript exists to
 * prevent.
 *
 * Non-canonical input is refused rather than normalised, and that is the
 * point of having a canonical form at all: if unsorted or duplicated bytes
 * were accepted and re-sorted, the transcript would contain bytes no
 * encoder produces and a second implementation could not reproduce it.
 *
 * @param {Buffer} bytes exactly the peer's caps field, verbatim
 * @returns {string[]} the tokens, in canonical order
 */
function parseCaps (bytes) {
  if (bytes.length === 0) return []
  if (bytes.length > MAX_CAPS_BYTES) {
    throw handshakeError(`peer sent ${bytes.length} bytes of capabilities, over the ${MAX_CAPS_BYTES}-byte cap`)
  }

  const tokens = bytes.toString('utf8').split(',')
  for (const token of tokens) {
    if (!CAPS_TOKEN.test(token)) {
      throw handshakeError(`peer sent a malformed capability token ${JSON.stringify(token)}`)
    }
  }

  // Canonical means this exact byte string, so re-encoding what we parsed
  // must reproduce it. Catches unsorted, duplicated, and empty-element
  // input in one comparison instead of three checks that could disagree
  // with encodeCaps.
  if (!encodeCaps(tokens).equals(bytes)) {
    throw handshakeError(
      'peer sent a non-canonical capability encoding (it must be deduplicated, ' +
      'sorted bytewise ascending, and comma-joined) -- see PROTOCOL.md section 3.2'
    )
  }
  return tokens
}

/**
 * The capability set both sides support: a pure function of the two values
 * as they appear in the transcript, per section 3.2's trap #3.
 *
 * @param {string[]} ours
 * @param {string[]} theirs
 * @returns {string[]}
 */
function effectiveCaps (ours, theirs) {
  const mine = new Set(ours)
  return theirs.filter((token) => mine.has(token) && KNOWN_CAPS.includes(token))
}

/**
 * @param {Buffer} expected
 * @param {Buffer} actual
 * @returns {boolean}
 */
function confirmationMatches (expected, actual) {
  // The length check is not itself a leak -- CONFIRM_SIZE is fixed and
  // public -- but it is required, because timingSafeEqual THROWS rather
  // than returning false on a length mismatch. A peer that sends the wrong
  // number of bytes must be rejected, not take the process down.
  if (!Buffer.isBuffer(actual) || actual.length !== expected.length) return false
  return crypto.timingSafeEqual(expected, actual)
}

/**
 * @param {Buffer} isk64
 * @param {Buffer} sid
 * @param {string} info
 * @returns {Buffer}
 */
function derive (isk64, sid, info) {
  // salt = sid, per section 3.2. Note this is HKDF over the ISK, not over
  // the password: the ISK is already a 64-byte uniform secret, so the
  // extract step is domain separation rather than entropy concentration.
  return Buffer.from(crypto.hkdfSync('sha256', isk64, sid, info, KEY_SIZE))
}

/**
 * Everything derived from a completed transcript. Split out because both
 * roles compute all of it -- the initiator to verify confirmS and produce
 * confirmR, the responder the reverse -- and computing it in one place is
 * what guarantees the two agree.
 *
 * @param {Buffer} sid
 * @param {Buffer} K
 * @param {Buffer} transcript
 */
function deriveAll (sid, K, transcript) {
  const iskValue = isk(sid, K, transcript)
  const macKey = derive(iskValue, sid, MAC_INFO)

  // Both confirmations cover the WHOLE transcript under one key, with
  // different role labels. That is a deliberate deviation from draft
  // section 9.4's suggestion that each party MAC only its own message, and
  // it is reflection-safe for the reason section 3.2 gives: the two are
  // computed over the same bytes under the same key but with different
  // prefixes, so neither can stand in for the other. It is the same
  // defence v1's "s"/"r" tags provided.
  const confirmS = hmac(macKey, CONFIRM_S_LABEL, transcript)
  const confirmR = hmac(macKey, CONFIRM_R_LABEL, transcript)

  return {
    isk: iskValue,
    macKey,
    confirmS,
    confirmR,
    kR2S: derive(iskValue, sid, R2S_INFO),
    kS2R: derive(iskValue, sid, S2R_INFO),
    transcript
  }
}

/**
 * @param {Buffer} key
 * @param {string} label
 * @param {Buffer} transcript
 * @returns {Buffer}
 */
function hmac (key, label, transcript) {
  const mac = crypto.createHmac('sha256', key)
  mac.update(Buffer.from(label, 'utf8'))
  mac.update(transcript)
  return mac.digest()
}

/**
 * @param {string} secret
 * @param {string} nameplate
 */
function assertHandshakeInputs (secret, nameplate) {
  // PRS is the secret's canonical form -- section 3.2's trap #4. Rejecting
  // anything with an uppercase letter or whitespace catches the two
  // mistakes that actually happen: passing the QR payload's uppercase, and
  // passing the whole code. Both would derive a different generator and
  // fail every handshake for no visible reason.
  if (typeof secret !== 'string' || secret.length === 0) {
    throw new TypeError('secret must be a non-empty string (the canonical 3-word secret)')
  }
  if (typeof nameplate !== 'string' || nameplate.length === 0) {
    throw new TypeError('nameplate must be a non-empty string')
  }
  if (secret !== secret.toLowerCase() || /\s/.test(secret)) {
    throw new TypeError(
      'secret must be in canonical form -- lowercase and hyphen-separated, as ' +
      'splitCode produces it. The QR payload\'s uppercase would derive a ' +
      'different generator and fail every handshake'
    )
  }
}

/**
 * @param {string} nameplate
 * @returns {Buffer}
 */
function channelIdentifier (nameplate) {
  return lvCat(Buffer.from(CI_LABEL, 'utf8'), Buffer.from(nameplate, 'utf8'))
}

/**
 * @param {Buffer} caps
 * @returns {Buffer}
 */
function associatedData (caps) {
  return lvCat(Buffer.from([VERSION]), caps)
}

// Wraps a body in its 2-byte big-endian length prefix.
/**
 * @param {Buffer} body
 * @returns {Buffer}
 */
function withLength (body) {
  const out = Buffer.allocUnsafe(LENGTH_PREFIX_SIZE + body.length)
  out.writeUInt16BE(body.length, 0)
  body.copy(out, LENGTH_PREFIX_SIZE)
  return out
}

/**
 * Reads one length-prefixed message off a reader, or returns null if it has
 * not all arrived.
 *
 * The prefix is PEEKED, not taken, so that a message which arrives split
 * between its prefix and its body leaves the reader untouched and the next
 * chunk retries cleanly. Consuming the prefix and holding the expected
 * length in a field would work too, and would be one more piece of
 * half-parsed state to get wrong across two roles.
 *
 * @param {InstanceType<(typeof import('./reader'))['MessageReader']>} reader
 * @param {number} min
 * @param {number} max
 * @param {string} what
 * @returns {Buffer | null}
 */
function takeLengthPrefixed (reader, min, max, what) {
  const prefix = reader.peek(LENGTH_PREFIX_SIZE)
  if (!prefix) return null

  const length = prefix.readUInt16BE(0)
  // Bounded before waiting for any of the body, so a peer cannot make us
  // buffer toward a length it has no intention of filling. This is the
  // same rule ./frame.js applies, and it matters more here: nothing in the
  // handshake is authenticated yet, so these are the least trustworthy
  // bytes the engine ever reads.
  if (length < min || length > max) {
    throw handshakeError(`${what} declared a ${length}-byte body, outside the permitted ${min}..${max}`)
  }
  if (reader.buffered < LENGTH_PREFIX_SIZE + length) return null

  reader.take(LENGTH_PREFIX_SIZE)
  return /** @type {Buffer} */ (reader.take(length))
}

// The receiver's side: CPace initiator (A), and the peer that writes first.
//
// SECTION 3.2 TRAP #1, AND THIS ENGINE IS UNUSUALLY EXPOSED TO IT. `ya`
// and `sid` are sampled HERE, in the constructor, so that one instance
// serves exactly one connection. Draft section 9.9 makes scalar reuse a
// MUST NOT, and Hyperswarm hands a receiver several candidate peers per
// drop and *two* connections per peer -- so caching one Ya across them to
// save 2 ms would not be a theoretical slip, it would be the ordinary case.
// ./swarm.js constructs this inside its per-connection handler for exactly
// that reason, and there is deliberately no way to inject a scalar or a
// sid from outside.
class Initiator {
  /**
   * @param {{ secret: string, nameplate: string, caps?: string[] }} options
   */
  constructor ({ secret, nameplate, caps = KNOWN_CAPS }) {
    assertHandshakeInputs(secret, nameplate)
    this._caps = encodeCaps(caps)
    this._capsTokens = parseCaps(this._caps)
    this._sid = crypto.randomBytes(SID_SIZE)
    this._ya = sampleScalar()

    const g = calculateGenerator(
      Buffer.from(secret, 'utf8'),
      channelIdentifier(nameplate),
      this._sid
    )
    // Ya = X25519(ya, g), with the draft's mandatory abort. The generator
    // is derived from the password, so a wrong secret puts this side in a
    // group it cannot relate to the peer's -- which is the whole trick.
    this._Ya = scalarMultVfy(this._ya, g)
    this._adA = associatedData(this._caps)
    this._done = false
  }

  /** @returns {Buffer} the sid, so ./swarm.js can report it (see section 3.2) */
  get sid () {
    return this._sid
  }

  /**
   * HELLO = [len][version][sid][Ya][caps_r]
   * @returns {Buffer}
   */
  hello () {
    return withLength(Buffer.concat([
      Buffer.from([VERSION]),
      this._sid,
      this._Ya,
      this._caps
    ]))
  }

  /**
   * Verifies REPLY and produces CONFIRM.
   *
   * @param {InstanceType<(typeof import('./reader'))['MessageReader']>} reader
   * @returns {{ confirm: Buffer, sendKey: Buffer, receiveKey: Buffer, caps: string[], isk: Buffer } | null}
   *   null if REPLY has not fully arrived yet.
   */
  readReply (reader) {
    if (this._done) throw handshakeError('the handshake has already completed')
    const body = takeLengthPrefixed(reader, REPLY_FIXED, REPLY_MAX_BODY, 'REPLY')
    if (!body) return null

    const Yb = body.subarray(0, ELEMENT_SIZE)
    const theirConfirm = body.subarray(ELEMENT_SIZE, REPLY_FIXED)
    // Verbatim, per trap #3: these exact bytes go into the transcript,
    // whatever parseCaps makes of them.
    const capsS = body.subarray(REPLY_FIXED)

    const theirTokens = parseCaps(capsS)
    // K = scalar_mult_vfy(ya, Yb), aborting on the neutral element. A peer
    // that sends a low-order or twist point learns nothing but would
    // otherwise force both sides onto a key it also knows.
    const K = scalarMultVfy(this._ya, Yb)
    const derived = deriveAll(
      this._sid,
      K,
      transcriptIR(this._Ya, this._adA, Yb, associatedData(capsS))
    )

    if (!confirmationMatches(derived.confirmS, theirConfirm)) {
      throw handshakeError(CONFIRMATION_FAILED, ERR_CONFIRMATION)
    }

    this._done = true
    return {
      confirm: derived.confirmR,
      // The receiver sends under k_r2s and receives under k_s2r.
      sendKey: derived.kR2S,
      receiveKey: derived.kS2R,
      caps: effectiveCaps(this._capsTokens, theirTokens),
      isk: derived.isk
    }
  }
}

// The sender's side: CPace responder (B), and the peer that reads first.
//
// `yb` is sampled per REPLY rather than in the constructor, because the
// generator depends on the sid the receiver chooses and there is nothing to
// compute until HELLO arrives. The per-connection rule is unchanged: one
// Responder serves one connection, and ./swarm.js builds it inside its own
// per-connection handler.
class Responder {
  /**
   * @param {{ secret: string, nameplate: string, caps?: string[] }} options
   */
  constructor ({ secret, nameplate, caps = KNOWN_CAPS }) {
    assertHandshakeInputs(secret, nameplate)
    this._secret = Buffer.from(secret, 'utf8')
    this._ci = channelIdentifier(nameplate)
    this._caps = encodeCaps(caps)
    this._capsTokens = parseCaps(this._caps)
    /** @type {null | { sid: Buffer, derived: any, theirTokens: string[] }} */
    this._pending = null
  }

  /**
   * Verifies HELLO and produces REPLY.
   *
   * @param {InstanceType<(typeof import('./reader'))['MessageReader']>} reader
   * @returns {{ reply: Buffer, sid: Buffer } | null}
   *   null if HELLO has not fully arrived yet.
   */
  readHello (reader) {
    if (this._pending) throw handshakeError('HELLO has already been read on this connection')
    const body = takeLengthPrefixed(reader, HELLO_FIXED, HELLO_MAX_BODY, 'HELLO')
    if (!body) return null

    const version = body[0]
    if (version !== VERSION) {
      // Named rather than left to present as corruption, which is what
      // section 9 asks a v2 implementation to do when it meets a v1 peer.
      // A v1 receiver opens with READY (0x01) followed by a 32-byte nonce,
      // so its first byte lands here as a version of 1.
      throw handshakeError(
        `peer opened with wire version 0x${version.toString(16).padStart(2, '0')}, not ` +
        `0x${VERSION.toString(16).padStart(2, '0')}. This is a version skew, not a corrupt ` +
        'stream: redeploy both sides to the same build'
      )
    }

    const sid = body.subarray(1, 1 + SID_SIZE)
    const Ya = body.subarray(1 + SID_SIZE, HELLO_FIXED)
    const capsR = body.subarray(HELLO_FIXED)
    const theirTokens = parseCaps(capsR)

    const yb = sampleScalar()
    const g = calculateGenerator(this._secret, this._ci, sid)
    const Yb = scalarMultVfy(yb, g)
    const K = scalarMultVfy(yb, Ya)

    const derived = deriveAll(
      sid,
      K,
      transcriptIR(Ya, associatedData(capsR), Yb, associatedData(this._caps))
    )
    this._pending = { sid, derived, theirTokens }

    return {
      // REPLY = [len][Yb][confirmS][caps_s]
      reply: withLength(Buffer.concat([Yb, derived.confirmS, this._caps])),
      sid
    }
  }

  /**
   * Verifies CONFIRM.
   *
   * @param {InstanceType<(typeof import('./reader'))['MessageReader']>} reader
   * @returns {{ sendKey: Buffer, receiveKey: Buffer, caps: string[], isk: Buffer } | null}
   *   null if CONFIRM has not fully arrived yet.
   */
  readConfirm (reader) {
    if (!this._pending) throw handshakeError('CONFIRM arrived before HELLO')
    const theirConfirm = reader.take(CONFIRM_SIZE)
    if (!theirConfirm) return null

    const { derived, theirTokens } = this._pending
    if (!confirmationMatches(derived.confirmR, theirConfirm)) {
      throw handshakeError(CONFIRMATION_FAILED, ERR_CONFIRMATION)
    }

    return {
      // The sender sends under k_s2r and receives under k_r2s -- the
      // mirror of the receiver's view, which is what makes one Channel
      // class serve both roles.
      sendKey: derived.kS2R,
      receiveKey: derived.kR2S,
      caps: effectiveCaps(this._capsTokens, theirTokens),
      isk: derived.isk
    }
  }
}

module.exports = {
  Initiator,
  Responder,
  assertHandshakeInputs,
  encodeCaps,
  parseCaps,
  effectiveCaps,
  confirmationMatches,
  deriveAll,
  channelIdentifier,
  associatedData,
  VERSION,
  SID_SIZE,
  CONFIRM_SIZE,
  MAX_CAPS_BYTES,
  KNOWN_CAPS,
  CAPS_TOKEN,
  LENGTH_PREFIX_SIZE,
  HELLO_FIXED,
  REPLY_FIXED,
  HELLO_MAX_BODY,
  REPLY_MAX_BODY,
  CONFIRMATION_FAILED,
  ERR_CONFIRMATION
}
