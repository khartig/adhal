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
   trust a stranger who merely found the topic. (`engine/src/proof.js`,
   exchanged by the readiness handshake in `engine/src/swarm.js` -- see
   [The code proof](#the-code-proof-item-4) below.)
4. Open a Protomux channel; send a manifest (name, size, chunk size,
   content hash).
5. Stream chunks; ack by index; persist offset for resume.
6. Receiver verifies the full-file hash; atomic rename into Downloads.
7. Leave the topic. If "Keep" was off, forget the peer.

Hyperdrive/Autobase/CRDTs are explicitly out of scope for v1 content -- a
framed stream plus a small on-disk manifest is enough, and is easier to
resume and test.

## What's implemented today (items 1-4)

`engine/src/frame.js` and `engine/src/transfer.js` implement steps 4-6 of
the data path above. Item 1 proves this over a plain localhost TCP socket
(zero NAT, zero DHT); item 2 (`engine/src/swarm.js`, `engine/src/topic.js`)
carries the *same* manifest/chunk protocol over an end-to-end
Noise-encrypted Hyperswarm connection instead, proving topic-join +
encrypted transport without changing the framing logic at all.
`cli/src/send.js`/`receive.js` (item 1) and `cli/src/swarm-send.js`/
`swarm-receive.js` (item 2) are the corresponding CLI pairs. Item 3 then
replaces the hand-typed code both of those took with a generated one --
see [The drop code](#the-drop-code-item-3) below. Item 4 makes knowing that
code a requirement rather than a convention -- see
[The code proof](#the-code-proof-item-4).

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
- **An unexplained transient, recorded because it cost a day and was not a
  bug.** After the readiness-handshake fix landed, a Starlink -> Comcast drop failed
  repeatedly with *no candidate logged on either side* -- no connection
  formed at all. During that window `scratch-lookup.js --connect` and
  `scratch-swarm-dial.js` both connected from the same machine to the same
  peer within seconds, so discovery and hole punching were demonstrably
  working while the real pair could not connect. It then began working
  again with no functional change to the swarm path: a 10 MB drop
  succeeded at `refresh=4000` (the exact configuration that had been
  failing) and again at `refresh=30000`.
  Two hypotheses were investigated and **disproven**: that our 4s
  `discovery.refresh()` was destroying in-flight DHT lookups (it coalesces
  when the client/server flags are unchanged, so it does not), and that the
  4s re-announce was churning holepunch relay state (disproven by the
  `refresh=4000` success). No code change is attributable to the recovery.
  The likely explanation is a transient condition on the Starlink path,
  which a LEO satellite link makes plausible, but that is inference and not
  measurement. If it returns, the diagnostics above now separate the
  layers; what is still missing is a repeated-trial success rate, without
  which a flaky path is indistinguishable from a broken one. That gap is
  what `engine/scratch-trials.js` now closes -- see
  [`MEASURING-TRANSFER-RELIABILITY.md`](MEASURING-TRANSFER-RELIABILITY.md).
  **Retroactively settled by measurement: 10 of 10 trials succeeded on that
  same path at `refresh=4000`** (below). There was no code defect; the
  refresh-interval hypothesis is dead on a sample of ten rather than on a
  single run, and the default stays at 4000.
- **Cross-ISP transfer verified (item 2's real exit criterion).** A Mac on
  Starlink (CGNAT, DHT-observed `98.97.27.13`, firewalled) sent to a Linux
  box on Comcast (`67.164.91.122`, firewalled) in ~9s. Re-verified for item
  3 with the two-way handshake: generated six-word code, QR shown on
  announce, 10 MB matching SHA-256 on both sides, at both
  `QUAY_REFRESH_INTERVAL=4000` and `30000`.
- **Measured reliability on that path, 2026-09-17** (`scratch-trials.js`,
  10 trials x 10 MB, `refresh=4000`, public DHT, both hosts firewalled):

  | | |
  | --- | --- |
  | Success | **10/10 (100%)**, hash verified against the manifest each trial |
  | Connect time | median 3.0s, p90 4.3s, range 2.0-4.5s |
  | End-to-end 10 MB | median ~12.9s, range 10.6-15.8s |
  | Throughput | ~0.8-1.2 MB/s (6-10 Mbps) |

  Against plan section 8 this clears the >=75% success gate and sits well
  inside the "10 MB median < 30-45s" target. Throughput is consistent with
  Starlink's upstream rather than with any bottleneck in the chunking or
  backpressure code -- worth revisiting before raising the 50 MB cap
  (section 9 spike 6), not before.

  Stated honestly: 10/10 gives a 95% one-sided lower confidence bound of
  **74.1%**, fractionally short of the 75% gate, so the defensible claim is
  "healthy and comfortably usable", not "proven >=75%". 12 of 12 would put
  that bound at 77.9%. Both roles agreed trial-by-trial to within 0.3s,
  which is the cross-check that the harness itself was measuring correctly.
  A rate is specific to one network pair at one time of day; re-measure
  rather than assuming this holds. Worth recording
  against plan section 9 spike 1: the Holepunch punch succeeded on a
  genuinely hostile path, so the relay (section 4 item 9) is not on the
  critical path for this network pair. Note that two hosts behind the *same*
  NAT were not proven to work -- that case needs router hairpinning and is
  the stronger argument for item 7 (mDNS/UDP multicast LAN discovery).
- Diagnostics for re-running these measurements live in `engine/scratch-*.js`.
  `scratch-lookup.js <topic-hex> [--connect]` separates "announce not
  visible" from "visible but unpunchable"; `scratch-serve.js <code>` is a
  receiver that accepts connections indefinitely so the far side can probe
  repeatedly. `scratch-swarm-dial.js <topic-hex> [--connect-once]` covers
  the layer between them -- Hyperswarm's own discovery and dialing, whose
  failures are otherwise invisible. Verified working across Starlink ->
  Comcast: Hyperswarm dialed with 3 relay addresses and opened in 1.6s,
  READY arrived, and with `--connect-once` the far side confirmed `got
  ACK`. None of these tools are destructive to a live receiver any more.
- A peer can connect and then die before confirming, surfacing as
  `connection reset by peer`. The window between the `'connection'` event
  and the server's READY byte had no `'error'` listener, so the
  `NoiseSecretStream` emitted an uncaught error and killed the process.
  A candidate that fails this way is now discarded rather than being
  treated as a fatal drop failure: **both** sides stay joined and wait for
  the next candidate. The join timeout also stays armed until the handshake
  actually completes, so a connection that never confirms can no longer
  hang the drop indefinitely.
- **Hardening only the sender against that case caused a worse bug, and the
  handshake is now two-way (READY + ACK).** `acceptOnce` used to resolve on
  its *first* `'connection'` event: clear its timeout, remove its listener,
  write READY, hand the socket to `receiveFile`. So the half-failed punch
  the sender had just been hardened against would consume the receiver
  permanently -- the sender correctly discarded the dead candidate and kept
  dialing, while the receiver sat committed to a dead socket, unable to
  answer any of it. Every later dial connected at the DHT/UDX layer and
  then hung. Measured on Starlink -> Comcast: `hyperdht` discovery and a raw
  dial both succeeded (`scratch-lookup.js --connect` reported `CONNECTED`)
  while `swarm-send.js` timed out after 120s having transferred nothing.
  The sender now answers READY with an ACK, so "this candidate confirmed"
  is a state both sides agree on and both can discard a candidate that
  fails. `acceptOnce` pauses the socket and returns any bytes that arrived
  alongside the ACK as `pending`, which `receiveFile` feeds through its
  decoder first -- otherwise a sender that coalesced its manifest into that
  chunk would lose the first frame. That ACK byte is now the code proof of
  item 4, below.
- **A join timeout now says which of the two failures it was.** Previously
  both reported `timed out looking for a peer`, which was actively
  misleading in the case above: the sender had found several. Zero
  candidates means discovery found nobody (wrong code, or the other side
  has not announced); one or more means the DHT and the punch worked and
  the handshake did not. `onCandidate`/`onCandidateDropped` log each
  candidate and each discard, so "peers keep connecting and vanishing" is
  visible rather than inferred. Plan section 8's alpha gate requires being
  able to classify every failure; this is the minimum for that.
- **Hyperswarm discards client dial errors, so a failing sender is
  silent.** In `hyperswarm/index.js` `_connect`, the only `'error'`
  handler on an outbound connection sets `peerInfo.forceRelaying` and
  returns -- the error is never logged, re-emitted or counted. No amount of
  logging in our own code reveals why a dial failed.
  `engine/scratch-swarm-dial.js` wraps `swarm.dht.connect` to print them,
  and reports the counters Hyperswarm does keep
  (`swarm.stats.connects.client.{attempted,opened}`, `swarm.peers`, and
  per-peer `attempts`/`banned`/`proven`). It also runs a raw `hyperdht`
  dial from a second DHT node in the same process, so "raw dial works,
  Hyperswarm dial does not" is one observation on one network path rather
  than two runs minutes apart. `--connect-once` swaps its own bare
  listener for the real `connectOnce`, which distinguishes "Hyperswarm can
  reach the peer" from "our engine completes the handshake".
- **Both peers dial each other, and Hyperswarm's duplicate resolution can
  destroy a connection mid-handshake.** Because both sides join with
  `server: true, client: true`, each pair produces two connections.
  `_handleServerConnection` keeps one and destroys the other with
  `ERR_DUPLICATE`, tie-breaking on
  `existingIsOutdated = rawBytesRead > 0 && rawBytesWritten > 0`. A
  connection in the middle of the handshake has written but not yet read,
  so it does *not* count as established and is eligible to be destroyed.
  This is survivable only because both sides now discard a failed candidate
  and wait for the next one; with the old one-shot `acceptOnce` it was
  another way to wedge the receiver permanently.
- **Item 4's three-message handshake does not widen that window**, which is
  worth stating because the warning that used to sit here was "worth
  remembering before any change that makes the handshake longer than one
  round trip", and item 4 is exactly such a change. The tie-break turns on
  each side's *first* read and *first* write, and the code proof moves
  neither: the receiver still writes first (`READY`, now carrying a nonce)
  and reads on the sender's answer, and the sender still reads first and
  writes on answering. Both sides therefore reach `rawBytesRead > 0 &&
  rawBytesWritten > 0` at the same points in the exchange as they did with
  the constant ACK. The third message is sent only after both are already
  established. Only the message *sizes* changed -- which is its own hazard,
  handled by reading a fixed byte count rather than assuming one chunk is
  one message (`MessageReader` in `engine/src/proof.js`).
- **`scratch-lookup.js --connect` and `scratch-hs-dial.js` are no longer
  destructive.** They never answer the receiver's challenge, so a live
  receiver logs them as a dropped candidate and keeps waiting. A
  `CONNECTED` result from them therefore no longer implies a drop would
  succeed – it isolates discovery and hole punching from the application
  handshake, which is exactly the distinction that was missing above.
  Since item 4 they could not complete a drop even if they tried: both are
  given a topic and no code.
- Tearing the swarm down immediately after the sender's own `end()`
  callback fires is not safe – that only confirms a *local* flush, not
  that the receiver got the last bytes. The receiver now ends its side
  after it finishes reading, and the sender waits for the socket's
  `'close'` event (both sides ended) before destroying its swarm.

## The drop code (item 3)

Step 1 of the data path. `engine/src/code.js` owns the code as a value,
`engine/src/wordlist.js` holds the words, and `cli/src/qr.js` draws the
symbol; `engine/src/resolve-code.js` is the only place that turns
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
given the announce-propagation race below -- but that is item 7 work, and
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

Step 7 of the data path above, resume (step 5's offset persistence), and
Protomux-based channel multiplexing all belong to later items in section 4
and are not yet built.

## The code proof (item 4)

Data path step 3. `engine/src/proof.js` holds the construction and the
reasoning; this is the summary.

**The hole it closes.** A topic is `hash(code || app-salt)`, and a receiver
must *announce* that topic to be findable at all -- so the topic is public
from the moment a drop starts, readable by anyone walking the DHT.
`engine/scratch-lookup.js` is that walk, written as a diagnostic. The code
is not public. Until item 4 the answer to `READY` was the constant byte
`0x02`, which proves nothing, so a stranger who scraped a topic could
complete the handshake and be treated as the intended peer.

It is mutual because both directions are exposed: a sender must not
transmit a file to someone who merely found the topic, and a receiver must
not accept one -- into `~/Downloads` -- from them either.

**The exchange**, replacing the constant ACK and keeping its round trips:

```
K = HKDF(code, "quay-drop-v1")                  derived both sides, never sent
receiver -> sender:   READY || nonceR                    (1 + 32 bytes)
sender   -> receiver: HMAC(K, "s" || nonceR || bind) || nonceS  (32 + 32)
receiver -> sender:   HMAC(K, "r" || nonceS || bind)     (32 bytes)
```

Four properties, each closing an attack that the others do not:

| Element | Stops |
| --- | --- |
| `K` from the code | A peer that has only the topic |
| Fresh `nonceR`/`nonceS` per attempt | Replaying a proof captured earlier |
| `"s"` / `"r"` domain tags | Reflecting one direction's proof into the other |
| `bind` = both Noise public keys, ordered by role | Relaying: getting an honest peer to answer a challenge on your behalf |

That last one is worth spelling out, because nonces and tags look
sufficient and are not. An attacker can announce on the topic, take the
receiver's challenge, pose as a receiver to the honest *sender* (which
dials every candidate it discovers), have the sender answer that very
challenge, and forward the result. Every nonce is fresh and every tag
correct. What breaks it is binding the proof to the session it was made on:
the attacker cannot borrow the sender's public key, having no private half,
so the proof it obtains is bound to the wrong pair of peers.

Comparisons use `crypto.timingSafeEqual`, behind an explicit length check
-- that function throws rather than returning false on a length mismatch,
so without one a peer could stop the process by answering with the wrong
number of bytes.

**A peer that fails the proof is discarded like any other bad candidate**
and both sides keep waiting, reusing the resilience item 2 already had. An
attacker must not be able to end a drop just by connecting to it and
failing. It is reported with its own reason string, though, because it is
the one discard that is not a network problem: `cli/test/code-proof.test.js`
covers wrong-code, reflected, replayed and relayed proofs, and asserts that
a genuine drop still completes after three rejected peers.

Two consequences to know:

- **It cannot mean a mistyped code.** Topic and key both derive from the
  code, so a peer that reached you on this topic at all derived the same
  key. Get a word wrong and the two sides land on unrelated topics and
  never meet, which surfaces as the zero-candidate timeout instead. A proof
  failure is a stranger, or a version skew.
- **It is a wire-format change, so both machines must be redeployed
  together.** Old and new do not interoperate: a pre-item-4 peer answers
  with `0x02` and is discarded. The reason string says so, since during a
  staged rollout that is the likeliest cause.

**What it does not do: it does not make a weak code strong.** Six words is
~62 bits and the announced topic already commits to them, so an attacker
holding a topic can grind candidate codes offline against
`hash(code || salt)` whether or not this handshake exists. Deriving `K`
from the code adds no exposure the topic had not already created, and
cannot remove it. Short-lived topics are the answer to grinding, and that
is item 7.

## Relay threat boundary

Documented here ahead of writing any relay code (plan section 3):

- Sees: two connection times, approximate bytes, IPs.
- Does not see: filenames, plaintext, long-term identity (per-drop tokens only).
- Cannot join a drop without the code.
- Caps: per-token bandwidth and duration.
- Default: a hosted relay; user can paste another URL.

This is also the basis for the project's "we are not a host of user
content" App Review / DSA argument: a relay is a pipe, not storage.
