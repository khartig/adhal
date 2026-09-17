# Architecture

Condensed from [`Refined-Implementation-Plan.md`](Refined-Implementation-Plan.md)
section 3. Read that document for the full reasoning; this page is a quick
reference kept in sync with it.

## Key hierarchy

```
Device Noise keypair          <- identity, persisted locally
├── Per-peer trust records    <- pk + {stranger | paired | trusted}
├── Per-drop capability       <- 6-word / QR, time-limited topic
├── Transfer encryption key   <- one key per drop (core or stream key)
└── Relay session             <- ciphertext only; no names, no hashes in clear
```

## v1 data path (target, not all implemented yet)

1. Generate code -> topic = hash(code || app-salt) (32 bytes).
2. Both peers `swarm.join(topic)`.
3. Challenge-response: prove you know the code (HMAC over nonce). Don't
   trust a stranger who merely found the topic.
4. Open a Protomux channel; send a manifest (name, size, chunk size,
   content hash).
5. Stream chunks; ack by index; persist offset for resume.
6. Receiver verifies the full-file hash; atomic rename into Downloads.
7. Leave the topic. If "Keep" was off, forget the peer.

Hyperdrive/Autobase/CRDTs are explicitly out of scope for v1 content -- a
framed stream plus a small on-disk manifest is enough, and is easier to
resume and test.

## What's implemented today (items 1-3)

`engine/src/frame.js` and `engine/src/transfer.js` implement steps 4-6 of
the data path above. Item 1 proves this over a plain localhost TCP socket
(zero NAT, zero DHT); item 2 (`engine/src/swarm.js`, `engine/src/topic.js`)
carries the *same* manifest/chunk protocol over an end-to-end
Noise-encrypted Hyperswarm connection instead, proving topic-join +
encrypted transport without changing the framing logic at all.
`cli/src/send.js`/`receive.js` (item 1) and `cli/src/swarm-send.js`/
`swarm-receive.js` (item 2) are the corresponding CLI pairs. Item 3 then
replaces the hand-typed code both of those took with a generated one --
see [The drop code](#the-drop-code-item-3) below.

Item 2 notes, found empirically while building it (see `engine/src/swarm.js`
comments for detail):

- Both peers must `join()` a topic with the (default) `server: true, client: true`.
  Splitting roles asymmetrically (receiver server-only, sender client-only)
  broke the connection -- the server side's `'connection'` event never fired
  even though the client believed it had connected.
- The server side's `'connection'` event fires only once the connection is
  genuinely stable; the client side's fires earlier/optimistically. Writing
  application data immediately after the client-side event can prevent the
  server from ever confirming the connection. Fixed with a one-byte
  readiness handshake: the server writes a marker byte once connected: the
  client waits to receive it before sending anything.
- `socket.write()`'s backpressure return value must be respected (pause the
  read stream, resume on `'drain'`) -- a raw TCP socket (item 1) tolerates
  ignoring this because of deep OS send buffers; the encrypted Hyperswarm
  duplex does not.
- **A topic announce is not instantly visible, and Hyperswarm only retries
  a failed lookup every 10 minutes.** `REFRESH_INTERVAL` in
  `hyperswarm/lib/peer-discovery.js` is 10 min plus up to 2 min of jitter.
  An announce propagates only to the DHT nodes closest to the topic, so a
  lookup finds it only if it happens to query a node that already has the
  record. When both peers joined simultaneously, the loser of that race
  found nothing and then sat idle for ten-plus minutes. Measured on a home
  NAT: transfers either completed in ~5s or never completed at all, 5 of 11
  runs succeeding, and raising the timeout from 30s to 120s rescued **zero**
  stuck runs. Two fixes: the receiver now waits for `discovery.flushed()`
  before reporting itself ready (the point at which a real UI may show the
  drop code), and both sides re-run their own lookup every 4s via
  `discovery.refresh()` rather than trusting Hyperswarm's 10-minute
  schedule. 12 of 12 consecutive public-DHT runs then succeeded.
- **Stale announces starve live peers at Hyperswarm's default
  `maxParallel: 3`.** A DHT announce outlives the process that made it, so
  every abandoned or timed-out drop leaves a dead peer advertised under the
  topic until the record expires. Dialing a dead peer took 10-17s to abort
  when measured, and Hyperswarm only deprioritizes one after `attempts > 3`
  (`hyperswarm/lib/peer-info.js`) -- so three stale records can occupy all
  three connection slots indefinitely. Observed as `swarm-send.js` timing
  out for 120s against a topic carrying three dead announces, on the exact
  network path where a freshly generated topic connected in 9s.
  `createSwarm` now sets `maxParallel: 16`.
- **Cross-ISP transfer verified (item 2's real exit criterion).** A Mac on
  Starlink (CGNAT, DHT-observed `98.97.27.13`, firewalled) sent to a Linux
  box on Comcast (`67.164.91.122`, firewalled) in ~9s. Worth recording
  against plan section 9 spike 1: the Holepunch punch succeeded on a
  genuinely hostile path, so the relay (section 4 item 9) is not on the
  critical path for this network pair. Note that two hosts behind the *same*
  NAT were not proven to work -- that case needs router hairpinning and is
  the stronger argument for item 7 (mDNS/UDP multicast LAN discovery).
- Diagnostics for re-running these measurements live in `engine/scratch-*.js`.
  `scratch-lookup.js <topic-hex> [--connect]` separates "announce not
  visible" from "visible but unpunchable"; `scratch-serve.js <code>` is a
  receiver that accepts connections indefinitely so the far side can probe
  repeatedly. `--connect` is destructive to a live `swarm-receive.js`.
- A peer can connect and then die before confirming, surfacing as
  `connection reset by peer`. The window between the `'connection'` event
  and the server's READY byte had no `'error'` listener, so the
  `NoiseSecretStream` emitted an uncaught error and killed the process.
  A candidate that fails this way is now discarded rather than being
  treated as a fatal drop failure: the sender stays joined and waits for
  the next candidate. The join timeout also stays armed until READY
  actually arrives, so a connection that never confirms can no longer hang
  the drop indefinitely.
- Tearing the swarm down immediately after the sender's own `end()`
  callback fires is not safe -- that only confirms a *local* flush, not
  that the receiver got the last bytes. The receiver now ends its side
  after it finishes reading, and the sender waits for the socket's
  `'close'` event (both sides ended) before destroying its swarm.

## The drop code (item 3)

Step 1 of the data path. `engine/src/code.js` owns the code as a value,
`engine/src/wordlist.js` holds the words, and `cli/src/qr.js` draws the
symbol; `cli/src/resolve-code.js` is the only place in the CLI that turns
user input into a topic.

**Word list: EFF short list #1**, vendored (1295 of its 1296 words, all
3-5 letters, ~62 bits over six words). Resolves plan section 9 spike 4.
Chosen over BIP39 on two grounds. Typing cost: EFF's words are 3-5 letters
against BIP39's up-to-8, and item 3 exists precisely to remove the friction
of typing a code by hand on two machines. Optics: a six-word lowercase
phrase drawn from BIP39 reads as a wallet seed phrase, which cuts against
section 6's deliberate avoidance of crypto framing and would train users
toward typing seed-like phrases into whatever asks for one. The list's one
hyphenated entry, `yo-yo`, is dropped, because a hyphen separates words in
a code and `yo-yo-acid` would otherwise be ambiguous; the count only needs
to be a power of six if you are rolling physical dice, and these come from
`crypto.randomInt` (rejection sampling -- 1295 is not a power of two, so a
plain modulo would skew draws toward the front of the list).

**QR payload: the typed code and nothing else**, as a versioned URI.
Resolves plan section 9 spike 5.

```
QUAY1:ACID-ACORN-ACRE-ACTS-AFAR-AGENT      <- in the QR, at most 41 chars
acid-acorn-acre-acts-afar-agent            <- shown to a human
```

Scanning and typing are therefore provably the same code path rather than
two paths to test. Embedding the sender's public key would let a scanner
`joinPeer()` directly and skip the topic lookup entirely -- attractive
given the announce-propagation race below -- but that is item 4/7 work, and
the `QUAY1` version prefix is what buys the room to add it without a format
break. An unknown scheme (`QUAY2:`) is reported as "newer version" rather
than misread as words.

Two details are load-bearing rather than cosmetic:

- **Uppercase in the QR, lowercase for humans.** QR's alphanumeric encoding
  mode covers only `0-9 A-Z` and `space $%*+-./:` -- both `:` and `-`
  qualify, lowercase does not. Measured against the worst-case
  41-character payload, staying in alphanumeric mode is worth exactly one
  version of headroom (`Q`: 29x29 alphanumeric vs 33x33 byte), and that is
  spent on error correction: **ECC level Q (~25% recovery) at version 3,
  29x29**. A bigger symbol would work against the cheap Android cameras
  that spike 5 was worried about, so the headroom buys robustness against
  glare, moire and poor focus instead of size. `parseCode` is
  case-insensitive, so a scan still round-trips.
- **The code is shown only after `discovery.flushed()`.** Same reasoning as
  the announce-propagation race below: the moment the code is readable is
  the moment the other side may start looking, so showing it before the
  announce has flushed manufactures exactly that race. `swarm-receive.js`
  prints the QR from inside `onAnnounced`.

Input is normalized hard, because a code is read off another device's
screen: case, and any run of `-`, `_`, `.` or whitespace as a separator, all
collapse to one canonical lowercase hyphenated form, which is the only
thing that reaches `topicFromCode`. `topicFromCode` itself hashes exactly
what it is given and normalizes nothing, so that item 2's opaque hex codes
keep working -- which makes feeding it an unnormalized word code a real
footgun, since the result is a valid but wrong topic and presents as a
discovery timeout. `resolveCode` exists to close that hole: an input
*shaped* like a six-word code is held to the strict parse and reports which
word is wrong, rather than being waved through as an opaque secret.

`cli/src/code.js` (`quay-code`) prints a code, its payload, its topic and
the symbol -- item 3's screenshottable artifact, and the quickest way to
get a topic argument for `engine/scratch-lookup.js`.

Verified by `cli/test/code.test.js`, which decodes the printed matrix with
a real QR decoder (`jsqr`, test-only) and confirms the scan lands on the
same topic the receiver joined.

Steps 3 and 7 of the data path above, resume (step 5's offset persistence),
and Protomux-based channel multiplexing all belong to later items in
section 4 and are not yet built.

## Relay threat boundary

Documented here ahead of writing any relay code (plan section 3):

- Sees: two connection times, approximate bytes, IPs.
- Does not see: filenames, plaintext, long-term identity (per-drop tokens only).
- Cannot join a drop without the code.
- Caps: per-token bandwidth and duration.
- Default: a hosted relay; user can paste another URL.

This is also the basis for the project's "we are not a host of user
content" App Review / DSA argument: a relay is a pipe, not storage.
