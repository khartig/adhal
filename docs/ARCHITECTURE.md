# Architecture

How the thing is built, and what was learned building it. The plan lives
in [`IMPLEMENTATION-PLAN.md`](IMPLEMENTATION-PLAN.md), the exposure
analysis in [`THREAT-MODEL.md`](THREAT-MODEL.md), and the wire format in
[`PROTOCOL.md`](PROTOCOL.md).

**Numbering.** `D1`-`D7` are the data-path steps below. `W1`-`Wn` are work
items in the plan. The older docs used "item N" for both, and the
collision produced at least one documented error, so it is gone.

## Key hierarchy

```
Per-drop ephemeral transport keypair   <- ROOT. Never persisted, never reused.
`-- Drop secret  (nameplate | PAKE secret)
    `-- PAKE session key (ISK)
        `-- AEAD channel keys (directional send/recv)

Long-term identity (optional, "Keep this device")
        ^ presented ONLY inside the authenticated channel.
          Never the drop swarm keypair. Never visible to the DHT.
```

**This is inverted from what used to be written here.** The old hierarchy
rooted everything in a *persisted device Noise keypair* with per-peer
trust records hanging off it. That is structurally incompatible with
ephemeral-by-construction privacy, which is one of the few properties a
trusted-device competitor cannot copy without abandoning their own design.

The invariant now: **the keypair a drop announces to the DHT is generated
for that drop and discarded with it.** Today that is true by accident —
`createSwarm` passes no `keyPair`, so Hyperswarm makes a fresh one per
process. Promoting the accident to a stated invariant matters because the
obvious way to build "Keep this device" is to persist that keypair, which
would silently make every drop by one user linkable by the DHT nodes that
observe them. A long-term identity, if it is ever added, is presented
*inside* the authenticated channel — never as the swarm keypair.

See [`THREAT-MODEL.md`](THREAT-MODEL.md) §4.

## Data path

1. **D1** Generate code. v1: `topic = hash(code || app-salt)`. v2: the
   code splits into nameplate + secret and the topic commits only to the
   nameplate — see [`PROTOCOL.md`](PROTOCOL.md) §2.
2. **D2** Both peers `swarm.join(topic)`.
3. **D3** Prove knowledge of the code before treating the peer as real.
   v1 is an HMAC challenge-response (`engine/src/proof.js`, exchanged by
   the readiness handshake in `engine/src/swarm.js` — see
   [The code proof](#the-code-proof-d3) below); v2 replaces it with a
   PAKE in the same three-message slot.
4. **D4** Send a manifest (name, size, chunk size, content hash).
5. **D5** Stream chunks. **Resume is a durable offset, not a per-chunk
   ack** — this step used to read "ack by index", which is the wrong
   primitive: UDX under Noise is already reliable and ordered, so
   per-chunk acknowledgement re-implements a guarantee the transport
   gives for free and costs a round trip to do it. v2 uses a periodic
   post-fsync `CHECKPOINT{offset}`. Neither exists yet (W11).
6. **D6** Receiver verifies the full-file hash and only then publishes the
   file under its real name. Implemented. Since Stage 0 it also refuses
   to replace a file it did not create — see
   [What the receiver now refuses](#what-the-receiver-now-refuses).
7. **D7** Leave the topic. If "Keep" was off, forget the peer.

Hyperdrive/Autobase/CRDTs are explicitly out of scope for v1 content -- a
framed stream plus a small on-disk manifest is enough, and is easier to
resume and test.

## What's implemented today

`engine/src/frame.js` and `engine/src/transfer.js` implement D4-D6 of the
data path above. The first milestone proved this over a plain localhost
TCP socket (zero NAT, zero DHT); the Hyperswarm milestone
(`engine/src/swarm.js`, `engine/src/topic.js`) carries the *same*
manifest/chunk protocol over an end-to-end
Noise-encrypted Hyperswarm connection instead, proving topic-join +
encrypted transport without changing the framing logic at all.
`cli/src/send.js`/`receive.js` (loopback) and `cli/src/swarm-send.js`/
`swarm-receive.js` (Hyperswarm) are the corresponding CLI pairs. The drop
code then replaces the hand-typed code both of those took with a
generated one --
see [The drop code](#the-drop-code-d1) below. The code proof makes knowing
that code a requirement rather than a convention -- see
[The code proof](#the-code-proof-d3). The manifest/progress/cancel work
makes every failure path say what it was, and adds the two things a human
needs while a transfer is running -- see
[Manifest, progress and cancel](#manifest-progress-and-cancel). Stage 0
then hardened all of it against a peer that knows the code and is hostile
anyway -- see [Stage 0 hardening](#stage-0-hardening).

Hyperswarm notes, found empirically while building it (see `engine/src/swarm.js`
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
  read stream, resume on `'drain'`) -- a raw TCP socket (the loopback path) tolerates
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
- **Cross-ISP transfer verified (the Hyperswarm milestone's real exit
  criterion).** A Mac on
  Starlink (CGNAT, DHT-observed <host A>, firewalled) sent to a Linux
  box on Comcast (<host B> firewalled) in ~9s. Re-verified for the
  drop code with the two-way handshake: generated six-word code, QR shown on
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

  This clears the >=75% success gate and sits well
  inside the "10 MB median < 30-45s" target. Throughput is consistent with
  Starlink's upstream rather than with any bottleneck in the chunking or
  backpressure code -- worth revisiting before raising the 50 MB cap
  (a later spike), not before.

  Stated honestly: 10/10 gives a 95% one-sided lower confidence bound of
  **74.1%**, fractionally short of the 75% gate, so the defensible claim is
  "healthy and comfortably usable", not "proven >=75%". 12 of 12 would put
  that bound at 77.9%. Both roles agreed trial-by-trial to within 0.3s,
  which is the cross-check that the harness itself was measuring correctly.
  A rate is specific to one network pair at one time of day; re-measure
  rather than assuming this holds. Worth recording
  for the relay question: the Holepunch punch succeeded on a
  genuinely hostile path, so the relay is not on the
  critical path for this network pair. Note that two hosts behind the *same*
  NAT were not proven to work -- that case needs router hairpinning and is
  the stronger argument for LAN discovery (mDNS/UDP multicast, Stage 3).
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
  the code proof, below.
- **A join timeout now says which of the two failures it was.** Previously
  both reported `timed out looking for a peer`, which was actively
  misleading in the case above: the sender had found several. Zero
  candidates means discovery found nobody (wrong code, or the other side
  has not announced); one or more means the DHT and the punch worked and
  the handshake did not. `onCandidate`/`onCandidateDropped` log each
  candidate and each discard, so "peers keep connecting and vanishing" is
  visible rather than inferred. The alpha gate requires being
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
- **The code proof's three-message handshake does not widen that window**, which is
  worth stating because the warning that used to sit here was "worth
  remembering before any change that makes the handshake longer than one
  round trip", and the code proof is exactly such a change. The tie-break turns on
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
  Since the code proof they could not complete a drop even if they tried: both are
  given a topic and no code.
- Tearing the swarm down immediately after the sender's own `end()`
  callback fires is not safe – that only confirms a *local* flush, not
  that the receiver got the last bytes. The receiver now ends its side
  after it finishes reading, and the sender waits for the socket's
  `'close'` event (both sides ended) before destroying its swarm.

## Manifest, progress and cancel

The earlier milestones got a drop working. This work is about what happens
when it does not: before it, every failure path was silent, and four of
them were live bugs.

### The wire format, and the second break

```
frame   = [4-byte BE length][payload]      <- engine/src/frame.js
payload = [1-byte type][body]              <- engine/src/message.js

0x00  reserved, always invalid  (what a desynced/truncated stream looks like)
0x01  MANIFEST  body = JSON {v, type, name, size, chunkSize, sha256}
0x02  CHUNK     body = raw file bytes
0x03  CANCEL    body = JSON {reason}
0x04+ reserved -- v2 assigns them; see PROTOCOL.md
```

**This was the second wire-format change after the code proof, and both
machines must be redeployed together.** It was taken then because it was
the last cheap moment: before the tag, a frame was "the manifest if it is the first
one, file bytes otherwise", so there was no way to say anything at all
during a transfer -- and resume needs more messages still. A type space that
does not exist by then costs two breaks instead of one.

`0x00` is reserved and always invalid so that a stream read out of phase
fails loudly on the first frame rather than parsing as garbage and
surfacing later as a hash mismatch. A pre-item-5 sender's untagged
manifest begins `0x7b` (`{`), which is detected by name: the error says to
redeploy both sides rather than sending someone hunting a corruption bug.

The tag deliberately did *not* go into `frame.js`, which stays a pure
length-prefixer with no opinion about its contents -- `transfer.js` simply
never calls `encodeFrame` directly. `frame.js` did gain a `maxFrameSize`
bound (default 1 MiB), because a declared length is four untrusted bytes
and a peer announcing `0xFFFFFFFF` previously made the decoder buffer
toward 4 GB.

`engine/scratch-serve.js` needs no change and still works against a
redeployed peer: it only speaks the handshake and never reads a frame.
That makes it the right tool to reach for during a skewed rollout.

> **Corrected in W11.** That was true for the type-tag break and is
> **false for v2.** The claim conflates two things: `scratch-serve.js`
> indeed never reads a frame, but it *hand-implements the handshake*, and
> v2 replaced all three of its messages. It had to be rewritten.
>
> It is now built on the same `Initiator` class `swarm.js` uses, rather
> than on its own copy of the parameter mapping — which is the only way
> "a real `swarm-send.js` can connect to this" stays true across the next
> break as well. A second copy of a handshake is how a diagnostic starts
> quietly lying about what the product does.
>
> The generalisation worth keeping: a tool is insulated from a wire break
> by not implementing the wire, not by not reading frames.

### Error codes

`engine/src/errors.js` defines one `TransferError` with a machine-readable
`.code`. This is not tidiness. `engine/scratch-trials.js` -- the harness
behind every reliability number in this repo -- classified failures by
regex-matching error *messages*, so the project's own measurement
instrument was coupled to prose.

| `.code` | Meaning |
| --- | --- |
| `ABORT_ERR` (`name: 'AbortError'`) | we cancelled, locally |
| `ERR_CANCELLED_PEER` | the peer cancelled, with its reason |
| `ERR_HASH_MISMATCH` | the digest does not match the manifest's |
| `ERR_SIZE_MISMATCH` | over-read, or a file that shrank mid-send |
| `ERR_UNSAFE_NAME` | the manifest's name escapes the output directory |
| `ERR_MANIFEST_INVALID` | a manifest field failed validation |
| `ERR_PROTOCOL` | unknown tag, oversize frame, out-of-order frame |
| `ERR_CONNECTION` | the socket closed before completion |
| `ERR_NO_PEER` / `ERR_NO_HANDSHAKE` | the two join timeouts, above |

Local cancellation uses Node's own `AbortError`/`ABORT_ERR` so
`signal.reason` and generic abort handling work unchanged.

### What the receiver now refuses

- **A corrupted file.** `receiveFile` computed a SHA-256 and compared it
  to nothing; only `scratch-trials.js` ever did the comparison, so the
  measurement harness verified integrity and neither CLI did. It is now
  compared against the manifest unconditionally, and the file streams into
  `<name>.part` and is renamed into place only after it passes. The `.part`
  name is predictable because resume (W11) must find it again.
- **A filename that is not a filename.** `path.join(outputDir,
  manifest.name)` was unvalidated, so a manifest naming `../../.bashrc`
  wrote there. The code proof stopped a *stranger* reaching the receiver; it never
  stopped a peer who knows the code from aiming at any path. Names are now
  refused by shape (empty, >255 bytes, NUL, `/` or `\`, `.`, `..` --
  checked against both separators, since `path.basename` means different
  things on different platforms) and then backstopped by asserting the
  resolved path stays under the output directory. Windows device names
  (`CON`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`, including trailing-dot
  evasions) are prefixed `_` rather than refused, **on Windows only**. The
  justification used to be "Windows ships first", which was never true of
  where the work happens and is now explicitly not the plan: macOS and
  Linux are the primary targets and Windows is third. `_aux.txt` on Linux
  is pure mangling of a name nothing on Linux objects to. The rename
  survives on a different argument -- a file received on Linux is often
  opened on Windows later, and a name unopenable there is worth one prefix
  character -- but it is gated on the platform, and the platform is
  injectable so all three legs of CI assert both policies. A leading dot
  is *not* stripped: `.bashrc` is a legitimate filename. `result.name`
  reports what was written and `result.declaredName` what was asked for.
- **More bytes than declared.** Refused rather than truncated: a correct
  sender cannot over-read its own manifest, so trimming would hide a bug
  and accept unbounded bytes from a peer that proved the code but is not
  thereby well-behaved.
- **A sender that vanishes.** `receiveFile` listened for `'data'` and
  `'error'` but not `'end'`/`'close'`, so a truncated transfer never
  settled -- no error, no timeout, no exit, forever. This was the routine
  outcome of a half-failed punch.

**Filename collisions used to be deliberately not handled, and that was a
security bug wearing a design decision's clothes.** What stood here was:
"`fs.rename` overwrites an existing destination, exactly as
`createWriteStream` did. Overwrite / suffix / prompt is an accept-screen
decision, and deciding it here would mean deciding it twice."

The reasoning is wrong in a way worth keeping on the page, because it is a
tempting shape of argument. It treats the choice as *cosmetic* — which of
several acceptable outcomes should the UI present — when the status quo
while waiting for that UI was **destroying an existing file**. And the
output directory defaults to `process.cwd()`, so "inside the output
directory" was never a synonym for safe: any peer holding the drop code
could name its file `.zshrc`, `package.json` or `id_rsa` and replace
whatever sat in the directory the receiver happened to be launched from.
A future accept screen could not have fixed that for headless or scripted
callers, who have no screen.

Stage 0 moved the default into the engine: the file is published with
`link()` + `unlink()` rather than `rename()`, because `link` fails with
`EEXIST` instead of clobbering, atomically. A taken name lands as
`report (1).pdf`. `replace: true` opts back in, and an accept screen can
still offer it.

See [Stage 0 hardening](#stage-0-hardening).

The sender was hardened for the same reason: `stat`, `hashFile` and
`createReadStream` are three separate reads of a file that can change
underneath them. The read is capped at `{ end: size - 1 }` and bytes sent
are asserted to equal the declared size -- before this, a file that shrank
mid-send resolved *successfully* having sent short.

### Progress

`onProgress({ bytes, total })`, one event per chunk, unthrottled, with a
guaranteed first call at `bytes: 0` and a final call at `bytes === total`.
No rate, ETA or percentage: those are derivable, and the engine cannot know
whether its consumer is a 10 Hz bar, a test or a log. Presentation lives in
`cli/src/progress.js` -- an in-place bar on a TTY, whole lines at fixed 25%
milestones otherwise (milestones rather than a timer, so the line count is
not load-sensitive and tests asserting on it are not flaky).
`QUAY_NO_PROGRESS=1` silences it.

**The sender's number is what it handed to the transport, not what the
receiver stored.** A sender's bar can legitimately read 100% while the
receiver is at 90%. Closing that gap is the v2 `RESULT` message (W11); the
receiver's `verified:` line is the authoritative one.

### Cancel

An `AbortSignal`, so one controller covers both the join and the transfer.
The sequence is symmetric: write CANCEL, wait briefly for it to flush, then
reject locally with an `AbortError`. The peer's decoder sees the tag and
rejects `ERR_CANCELLED_PEER` carrying the reason.

The flush window is the point. Destroying immediately loses the message --
the same lesson `swarm-send.js` already records about `end()` versus
waiting for `'close'` -- and a lost CANCEL means the peer sees `connection
reset by peer`, which is byte-for-byte what a dead punch looks like.
Shipping a deliberate user action that is indistinguishable from this
project's hardest-to-diagnose failure would have been a regression.
Latency is bounded by roughly one chunk plus the high-water mark, not
instantaneous.

First settle wins on each side, so on a simultaneous cancel each end
reports its own and the two logs cannot disagree about who cancelled. The
peer's `reason` is untrusted -- it goes straight into a terminal -- so it
is capped at 256 bytes with control characters stripped.

Consequence worth noting: **`sendFile` now reads**, for inbound CANCEL. So
`connectOnce` returns `pending` exactly as `acceptOnce` does, and the old
comment claiming leftover bytes there could only mean a peer talking out of
turn is no longer true.

`cli/src/signals.js` turns SIGINT/SIGTERM/SIGBREAK into that signal: the
first aborts and lets the normal catch/finally run (CANCEL written, socket
ended, swarm destroyed) before exiting 130/143/149; the second exits
immediately, because `swarm.destroy()` can take seconds and a Ctrl-C that
appears to do nothing is one people follow with `kill -9`.

On Windows the table reads differently than it looks. **Ctrl-C works**:
Node delivers the console Ctrl+C event as SIGINT there, so the clean path
above is what a human already gets. **Ctrl+Break now works too** -- SIGBREAK
was unhandled, so Ctrl+Break tore the process down and the peer saw the
socket reset this whole design exists to avoid. **SIGTERM can never fire
there** (Node: "`SIGTERM` is not supported on Windows, it can be listened
on"); it stays in the table as harmless dead weight rather than a platform
branch. What does *not* work on Windows is `child.kill('SIGINT')`: libuv implements
it as `TerminateProcess`, so the child dies before a handler runs. That is a
testing problem, not a product one. `cli/test-helpers/interrupt.js` raises a
real `CTRL_C_EVENT` in the child's console instead, which arrives as SIGINT
just as a keypress would -- and because a control event reaches every process
sharing that console, it first checks the child is alone in one and skips
rather than signal the test runner along with it. `acceptOnce`/`connectOnce`
take the same signal, so Ctrl-C works *while waiting for a peer* -- the
likeliest moment a human cancels, and previously the one state with no way
out but killing the process. Aborting removes only our own listener and
timer; the swarm belongs to the caller.

**That sentence was half false until Stage 0, and this page was one of the
places asserting it.** `connectOnce` accepted a `signal`, documented it,
and defined an `onAbort` that `finish()` removed -- but never registered
the listener, so on the *sender* the signal was inert. Measured with a
500ms abort against a 5000ms budget: `acceptOnce` rejected at 502ms,
`connectOnce` ran the full 5001ms and then reported `ERR_NO_PEER`. On a
real sender that is up to two minutes of Ctrl-C doing nothing.

It survived four milestones because the receiver's half worked, so the
feature looked shipped from every angle anyone checked -- and because
there was **no sender-side cancel test at all**. The asymmetry in the
tests was the same shape as the asymmetry in the bug. Both halves are now
registered and both are tested (`cli/test/cancel.test.js`).

## Stage 0 hardening

The code proof answers exactly one question: *is this the peer the human
meant?* Everything here is about a peer for which the answer is **yes**
and which is hostile anyway — a code can be shoulder-surfed,
screenshotted, forwarded to the wrong chat, or given to someone for a
different file than the one they send. "They know the code" is the
beginning of the threat model, not the end.

Each row was reachable by a proven peer before Stage 0, and each is
covered by `cli/test/hardening.test.js`.

| Attack | Now |
| --- | --- |
| Replace `~/.zshrc`, `package.json`, `id_rsa` in the launch directory | Publish via `link()`+`unlink()`, which fails `EEXIST` rather than clobbering; lands `name (1)`. `replace: true` opts back in |
| Redirect the write with a planted `<name>.part` symlink | Partial opened `O_CREAT\|O_EXCL`, which refuses to follow a symlink |
| Forge a log line, clear the terminal, spoof a name with RLO | Control and bidi characters refused; everything printed through `displayName()` |
| NTFS alternate data stream (`foo:stream`) | `<>:"\|?*` transformed on every platform |
| Invisible trailing dot or space (`a.exe. `) | Stripped |
| Declare 9 PB | 8 GiB default cap (`null` to opt out) plus a free-space check before anything opens |
| Outrun the disk and grow memory without bound | `writeStream.write()`'s return value honoured; the socket pauses |
| Prove, then send nothing, forever | `ERR_STALLED` on a manifest deadline and a no-progress deadline |
| Hold a connection slot without handshaking | 15s per-candidate handshake deadline |

Two pieces of the split are worth naming, because they are the design
rather than the list:

- **`engine/src/names.js` owns both sinks.** A peer-supplied name reaches
  a terminal and a filesystem, and those had separate, unequal defences
  until the moment a name was *refused* — at which point the refusal
  message printed the hostile name raw. Display sanitises and never
  throws; writing refuses or transforms and says which. A display path
  that can throw turns one error into two, and the moment we most need to
  print a name is when we are rejecting it.
- **Escaping, not stripping.** `displayName` renders control and bidi
  characters as `\uXXXX` rather than removing them. Stripping produces a
  clean-looking string and destroys the evidence: `evil\nverified: ok`
  would print as `evilverified: ok`, which looks fine and tells the reader
  nothing.

Still true and not fixable here: **a peer who knows the code can send you
any file.** The displayed SHA-256 proves the bytes arrived intact; it
proves nothing about the sender's honesty. Integrity is not authenticity
of intent.

### A defect class worth remembering: unreadable source

Three files in this repo contained **literal NUL and ESC bytes** in string
literals and character classes. `file(1)` reported them as `data`, and
`grep` treats a binary file as unmatchable:

```
$ grep -n 'safeOutputName' engine/src/transfer.js
$ echo $?
1                      # ... for a string that occurs three times
```

So a repo-wide `grep` for `ERR_HASH_MISMATCH` silently omitted the file
that throws it, and the two largest security-critical modules returned
false negatives to any auditor's search. That is a correctness hazard, not
a style preference. All three now use `\x00` / `\x1b` escapes, and the
check is one command:

```
find . -name '*.js' -not -path './node_modules/*' -exec file {} + | grep -v text
```

The third file was found only by running that over the whole repo — it was
not in the list of known cases.

## The drop code (D1)

Step D1 of the data path. `engine/src/code.js` owns the code as a value,
`engine/src/wordlist.js` holds the words, and `cli/src/qr.js` draws the
symbol; `engine/src/resolve-code.js` is the only place that turns
user input into a topic.

**Word list: EFF short list #1**, vendored (1295 of its 1296 words, all
3-5 letters, ~62 bits over six words).
Chosen over BIP39 on two grounds. Typing cost: EFF's words are 3-5 letters
against BIP39's up-to-8, and a generated code exists precisely to remove the friction
of typing a code by hand on two machines. Optics: a six-word lowercase
phrase drawn from BIP39 reads as a wallet seed phrase, which cuts against
the deliberate avoidance of crypto framing and would train users
toward typing seed-like phrases into whatever asks for one. The list's one
hyphenated entry, `yo-yo`, is dropped, because a hyphen separates words in
a code and `yo-yo-acid` would otherwise be ambiguous; the count only needs
to be a power of six if you are rolling physical dice, and these come from
`crypto.randomInt` (rejection sampling -- 1295 is not a power of two, so a
plain modulo would skew draws toward the front of the list).

**QR payload: the typed code and nothing else**, as a versioned URI.

```
QUAY1:ACID-ACORN-ACRE-ACTS-AFAR-AGENT      <- in the QR, at most 41 chars
acid-acorn-acre-acts-afar-agent            <- shown to a human
```

Scanning and typing are therefore provably the same code path rather than
two paths to test. Embedding the sender's public key would let a scanner
`joinPeer()` directly and skip the topic lookup entirely -- attractive
given the announce-propagation race below -- but that is LAN-discovery work (Stage 3), and
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
what it is given and normalizes nothing, so that opaque hex codes
keep working -- which makes feeding it an unnormalized word code a real
footgun, since the result is a valid but wrong topic and presents as a
discovery timeout. `resolveCode` exists to close that hole: an input
*shaped* like a six-word code is held to the strict parse and reports which
word is wrong, rather than being waved through as an opaque secret.

`cli/src/code.js` (`quay-code`) prints a code, its payload, its topic and
the symbol -- the drop code's screenshottable artifact, and the quickest way to
get a topic argument for `engine/scratch-lookup.js`.

Verified by `cli/test/code.test.js`, which decodes the printed matrix with
a real QR decoder (`jsqr`, test-only) and confirms the scan lands on the
same topic the receiver joined.

Step D7 of the data path above and resume (D5's offset persistence)
belong to later stages and are not yet built. Protomux-based channel
multiplexing was on that list and has since been ruled out rather than
deferred -- see [`PROTOCOL.md`](PROTOCOL.md) §8.2.

## The code proof (D3)

Data path step D3. `engine/src/proof.js` holds the construction and the
reasoning; this is the summary.

**The hole it closes.** A topic is `hash(code || app-salt)`, and a receiver
must *announce* that topic to be findable at all -- so the topic is public
from the moment a drop starts, readable by anyone walking the DHT.
`engine/scratch-lookup.js` is that walk, written as a diagnostic. The code
is not public. Until the code proof landed, the answer to `READY` was the constant byte
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
and both sides keep waiting, reusing the resilience the Hyperswarm
milestone already had. An
attacker must not be able to end a drop just by connecting to it and
failing.

> **Superseded in v2.** That last rule is a v1 rule and v2 reverses it
> deliberately. Under v2 a nameplate-holder *can* end a drop, after 100
> failed PAKE confirmations — see [`PROTOCOL.md`](PROTOCOL.md) §6 and
> [`THREAT-MODEL.md`](THREAT-MODEL.md) §5.3. The trade is explicit:
> unlimited guessing against ~31 bits is worse than a denial of service,
> because a denial of service is visible and a silent compromise is not.
> The v1 rule stands for the v1 handshake this section describes, which
> is what still ships.
 It is reported with its own reason string, though, because it is
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
cannot remove it.

**The answer to grinding is the v2 code split**, not a shorter topic
lifetime: the topic comes to commit only to a public *nameplate*, and the
secret is fed to a PAKE and never hashed into anything an observer can
obtain. That removes the offline target entirely rather than shrinking the
window on it. See [`PROTOCOL.md`](PROTOCOL.md) §2.

## Relay threat boundary

Moved to [`THREAT-MODEL.md`](THREAT-MODEL.md) §8, which is the document
that has to stay correct about it.

One constraint changed in the move and is worth naming here, because it
contradicts what this section used to say. It read **"Default: a hosted
relay; user can paste another URL."** That erodes the one structural
difference this project has from an Iroh-based competitor — serverless by
default — and turns it into the same product with a smaller relay fleet.
The relay is now **optional, self-hostable, and never in the default path
when a direct connection works**.
