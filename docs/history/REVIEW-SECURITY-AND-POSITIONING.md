# Quay: security, positioning, and plan review

> **Historical.** This review describes the code as it was on 2026-09-18,
> before the v2 protocol, under the product's old name, Quay. Nothing in
> it describes the current code. It is kept because the plan's Stage 0
> work answered it point by point. For the current security position, see
> [`../PROTOCOL.md`](../PROTOCOL.md) §12, [`../THREAT-MODEL.md`](../THREAT-MODEL.md),
> and [`../SECURITY-REVIEW.md`](../SECURITY-REVIEW.md).

Reviewed 2026-09-18 at the state "section 4 items 1-5 done". Working tree
included uncommitted item-5 work. Read: the plan, `ARCHITECTURE.md`, and all of
`engine/src/*` plus the send/receive CLIs. Ran: the full test suite (73/73
pass, ~150 s) and a probe of `safeOutputName`/`validateManifest` (results
below). Fetched the READMEs of MeshDrop and DashBeam.

**What I did not do:** read MeshDrop's or DashBeam's source, run a network
capture, or read `hyperswarm`/`hyperdht` internals beyond what the repo's own
docs say. Competitor facts below come from a summarized README fetch, and
claims about DHT-node visibility are from protocol knowledge, marked
*(verify)*.

---

## 0. Executive summary

1. **The crypto core is better than the plan gives it credit for.** The
   channel-bound mutual HMAC proof (`proof.js`) is carefully reasoned, and the
   docs are honest about limits. The problems are around it, not in it.
2. **The biggest structural weakness is that the code is both the rendezvous
   secret and the authentication secret**, so a public DHT value (the topic)
   is an offline-grinding oracle for the whole 62-bit secret. Fix: split the
   code into a public *nameplate* and a PAKE-protected *secret*
   (magic-wormhole's design). This also makes wrong-code failures detectable
   and lets the code get *shorter*. Section 1.1.
3. **The receiver as shipped will overwrite any file in its working directory
   and print attacker-controlled bytes to your terminal**, for any peer who
   holds the code. Verified by probe. Section 1.2.
4. **The wire protocol has no accept step and no receiver→sender result
   message.** Item 6 (resume), item 10 (accept screen), and "hash shown before
   success" all need the same missing messages. Design them once, now, or
   you take a third wire break. Section 3.1.
5. **Security is currently welded to Hyperswarm's transport.** When the
   relay arrives, either the relay is a trusted MITM or you build a second
   security architecture. Build one transport-independent E2E channel first.
   Section 3.2.
6. **MeshDrop is not "tiny and fragile" by its own README; it is ahead of
   Quay on nearly every feature and shares its architecture.** Treat it as
   prior art and a benchmark, not a market. Section 2.1.
7. **Recommended positioning:** magic-wormhole for the serverless age.
   Protocol-first, CLI/stream-first, ephemeral-by-construction, with
   *published, reproducible* reliability numbers. Do not fight DashBeam on
   GUI, browser receive, or trusted devices. Section 2.3.

---

## 1. Security findings

Severity is for the code as it stands, assuming an adversary who is (a) a
network/DHT observer, (b) someone who has seen the code, or (c) a legitimate
peer who is malicious. "Verified" means I ran it; "read" means from source.

| # | Finding | Severity | Status |
|---|---|---|---|
| 1.1 | Topic is an offline oracle for the code; HMAC transcript is a second one | High (design) | read |
| 1.2a | Peer can overwrite any file in the receive dir (default: cwd) | High | read (rename semantics) |
| 1.2b | Filenames allow control chars, newlines, bidi, `:`, trailing dot/space | Medium | **verified** |
| 1.3 | No default size cap, no disk check; receiver ignores write backpressure | Medium | **verified** (cap), read (backpressure) |
| 1.4 | No idle/stall timeout after the proof passes | Medium | read |
| 1.5 | No accept step: bytes flow before the receiver decides | Medium | read |
| 1.6 | Opaque/"any string" codes are accepted and can be weak | Medium | read |
| 1.7 | Sender reports success without receiver confirmation | Low-Med | read |
| 1.8 | Real public IPs committed in `docs/ARCHITECTURE.md` | Low-Med | **verified** |
| 1.9 | Metadata exposure of DHT/announce not in a threat model | Medium (doc) | protocol knowledge |
| 1.10 | Code passed as a CLI argument | Low | read |
| 1.11 | No CI, no Windows testing, Windows is the "first" target | Process | verified (no `.github`) |

### 1.1 The code is a grindable rendezvous secret (design)

`topic = BLAKE2b("quay-v1:" + code)` is published to DHT nodes by the
receiver. `K = HKDF(code)` authenticates. Both derive from the same 62 bits,
so anyone who learns the topic can test candidate codes at hash speed. The
docs admit this (ARCHITECTURE "What it does not do") and defer it to "short-
lived topics".

Two additional points the docs do not make:

- **The handshake is a second oracle.** The sender dials *every* candidate on
  the topic and answers a challenge with `HMAC(K, "s"‖nonceR‖pkR‖pkS)`. An
  attacker who announces on the topic gets that MAC for free, so grinding does
  not even need the topic hash, and works with an attacker-chosen nonce. The
  channel binding stops relaying; it does not stop this. Same keyspace, so no
  *new* exposure, but it means nothing you do to the topic alone fixes it.
- **Who can see a topic.** Topics cannot be enumerated from the DHT, but the
  nodes closest to a topic store its announces and see announcer source IPs
  *(verify)*. A Sybil operator with many nodes sees a slice of all Quay topics
  and who announces them. The plan's phrase "readable by anyone walking the
  DHT" is stronger than the reality; "readable by nodes near it" is the
  honest form and still enough.

Cost of the attack, for calibration: 2^62 BLAKE2b evaluations. At roughly
10^9 H/s per GPU that is ~146 GPU-years, so about 5 days on 10,000 GPUs. That
is nation-state/cloud-budget territory against a topic that lives for
minutes: **not a practical break of an ephemeral drop today**. It becomes
real the moment topics live longer ("Keep this device", home-base pinning,
Phase F) or the code is user-chosen (1.6). And 62 bits is being used to pay
for a property (offline resistance) that a PAKE gives for free.

**Recommendation (highest-value security change available):**

```
code      = nameplate (2 words, ~20.7 bits) + secret (3 words, ~31 bits)  -> 5 words
topic     = H("quay-v2:topic" ‖ nameplate)          public, findable
session   = PAKE(secret)  (CPace or SPAKE2 over ristretto255)
            -> key material fed into a Noise NNpsk0-style channel (3.2)
```

What this buys:

- The topic reveals only the nameplate. **No offline attack exists**: every
  guess of the secret costs one live protocol run.
- **Attempt cap.** The receiver burns the drop after N failed PAKE runs
  (N≈50-100). With a 31-bit secret and N=100 the success chance for an
  attacker who found the nameplate is ~5×10^-8 per drop. Note this reverses
  a current design rule ("an attacker must not be able to end a drop just by
  connecting and failing"). The trade is real: an attacker who knows the
  nameplate can now DoS the drop, but only after 100 attempts, and the
  alternative is unlimited guessing. Choose N deliberately and document it.
- **Wrong-code becomes detectable.** Today a mistyped code lands on an
  unrelated topic and the user sees a 30 s "no peer" timeout, which is
  exactly the failure class the plan wants users to understand. With a
  nameplate, a typo in the *secret* words connects and fails the PAKE, so
  you can say "wrong code" (a typo in the nameplate still looks like no peer;
  put a check-word or prefix-unique wordlist on it).
- **Shorter code** (5 words vs 6) at higher security, because entropy no
  longer has to defend a public hash.
- Nameplate collisions: 2^20 space. With ~1,000 concurrent global drops a
  given drop collides with probability ~0.1%; the failure is a PAKE
  mismatch, which the discard-and-keep-waiting path already handles.

Do not hand-roll the PAKE. Use a reviewed implementation and get it looked
at by someone who does this for a living; libsodium's ristretto primitives
are already in your dependency tree via `sodium-native`.

If you do not do this: at minimum (a) put a memory-hard KDF (scrypt/argon2id)
in front of topic and key derivation so grinding costs 10^5-10^6× more, and
(b) give topics an epoch so they expire. Both are patches, not fixes.

### 1.2 Receiver filesystem behavior

**(a) Overwrite.** `receiveFile` writes `<name>.part` then
`fs.promises.rename` onto the destination, which replaces an existing file
silently. The doc records this as a deliberate deferral to the accept screen.
Combined with the default output directory being `process.cwd()`
(`cli/src/swarm-receive.js:115`) and no accept step, **any code-holder can
replace `.bashrc`, `.zshrc`, `.npmrc`, `package.json`, or a script** in
wherever the receiver was launched. That is arbitrary code execution on next
shell start if the user runs it from `$HOME`. The path check is sound; the
problem is that "the name is inside the directory" is different from "safe to
overwrite". Fix in the engine, not the UI: refuse or auto-suffix
(`name (1)`) by default, create with `O_EXCL`, and let the UI opt in to
replace. Also open the `.part` with `O_NOFOLLOW`-equivalent care (a
pre-existing symlink at `<name>.part` is followed by `createWriteStream`;
local-attacker only, low).

**(b) Names.** I ran `safeOutputName` against hostile names. All of these are
**accepted unchanged**:

```
".bashrc"                  (intended, but see 1.2a)
"evil\nverified: ok"       newline: forges a log line
"a\x1b[2Jb"                ESC: terminal control sequence
"inv‮fdp.exe"         RLO bidi override: displays as "invoiceexe.pdf"-style
"foo:stream"               NTFS alternate data stream on Windows
"a.exe. "                  Windows strips trailing dot/space: becomes a.exe
```

The CLI prints `manifest.name` and `result.name` raw
(`swarm-receive.js:194,199`). The cancel-reason path is sanitized
(`sanitizeReason`); the filename, which is the *more* obviously hostile
field, is not. It matters doubly because plan item 10 (executable warning)
will key off the extension, and bidi/trailing-dot tricks defeat exactly that.
Recommendation: one `displayName()` used everywhere a name is shown (strips
controls and bidi, escapes the rest), and on Windows reject or transform
`<>:"|?*`, control chars, and trailing dot/space. Windows ships first, and the
current tests run only on macOS/Linux.

Minor: `transfer.js:360` contains a *literal NUL byte* inside the source
string. It works (I checked the bytes), but it is one careless editor or
formatter away from silently becoming a different check. Write `'\0'`.
Same for the control-character regex in `message.js`.

### 1.3 Unbounded resource use

- `validateManifest` accepts `size: 10^13` (verified). `maxSize` is optional
  and neither CLI passes it. A peer declares 10 TB and the receiver writes
  until the disk is full. The plan's 50 MB cap is "product policy at the
  accept screen", but that screen does not exist, so today there is no cap
  anywhere. Give the engine a conservative default and require an explicit
  opt-out, and check free space against `size` before opening the `.part`.
- **The receiver ignores write backpressure.** `writeStream.write(body)` in
  `receiveFile`'s decoder callback discards the return value and never
  pauses the socket. If the disk is slower than the link (fast LAN into a USB
  drive), memory grows without bound. The sender side got this treatment
  (its comment explains why); the receiver did not. This is a correctness bug
  for large files as well as a DoS lever.

### 1.4 No stall timeout after the proof

`acceptOnce` has a 30 s budget; once the proof passes, `receiveFile` has none.
A code-holder can connect, prove, and then send nothing (or one byte a
minute). The receiver waits forever. In a shared-code scenario (code pasted
in a group chat) the first prover wins the single slot and can squat it.
Add a manifest deadline and a no-progress timeout, both cancellable with
`ERR_STALLED`.

### 1.5 No accept step in the protocol

The receiver writes nothing after the proof. The sender streams manifest and
chunks immediately, and `onManifest` is a notification that fires *after* the
`.part` is created and cannot refuse. Bytes are in flight before any human or
policy decides. See 3.1: this needs a protocol message, not a callback.

### 1.6 Weak codes are accepted

`resolveCode` treats anything that is not shaped like six words as an
"opaque secret" and hashes it. `swarm-send.js hunter2 file` works, and yields
a topic anyone can dictionary-attack in seconds. It exists for scratch
tooling and tests. Keep it, but gate it behind an explicit `--unsafe-opaque`
(or an env var) so no product surface ever produces a weak drop.

### 1.7 Sender-side false success

The sender prints `done:` after handing bytes to the transport and closing.
If the receiver then rejects the file (hash mismatch, unsafe name, disk
error), the sender's exit code and output still say success. The code
comments say so honestly, but the plan's Phase-1 bar ("both UIs show the same
SHA-256 before Done") is unmeetable without a receiver→sender `RESULT`
message. Section 3.1.

### 1.8 Real IPs in the repo

`docs/ARCHITECTURE.md` recorded two residential IP addresses (a Starlink
host and a Comcast host) as the test hosts. For a privacy-positioned project
these are the author's home IPs, and they will sit in git history. Replace with
`<host-A>`/`<host-B>` and consider whether the history needs rewriting before
the repo goes public. Also strip topics/public keys from anything an opt-in
crash reporter will send (the CLIs currently print the full topic hex).
`trials/` is correctly gitignored; check it is never zipped into a bug report.

### 1.9 Metadata: write the threat model now

The plan schedules the threat model for Phase D. It should exist before the
protocol is frozen, because it drives 1.1 and 3.2. Items it must state
plainly (each *verify* against hyperdht source):

- DHT nodes near the topic see: topic, announcer pubkey, announcer source IP,
  timing. Both peers announce (`server:true, client:true`), so **the sender is
  exposed too**, not just the receiver.
- The two peers learn each other's public IPs on a direct connection. That is
  inherent to P2P and is exactly what a relay-only mode would hide.
- Ephemeral Noise keys per process (Hyperswarm's default; `createSwarm` does
  not set a `keyPair`) are a *privacy feature*. **When "Keep this device"
  arrives, do not reuse the persistent identity for the drop swarm.** Keep
  drop keys ephemeral and present the long-term identity only *inside* the
  authenticated channel. Otherwise every drop becomes linkable and DHT nodes
  can build a social graph. DashBeam's persistent-ID trusted-device model is
  structurally the opposite; this is a real differentiator if you protect it.
- The refresh loop re-announces every 4 s for up to 30-120 s. Fine for a
  drop. Multiply by a "Keep" mode or a busy relay fleet and you are a noisy
  neighbor on a shared public DHT; budget for it.

### 1.10 Minor

- The code is an argv (`swarm-send.js <code> <file>`), so it sits in shell
  history and `ps`. Offer stdin/prompt entry.
- Anyone who has seen the code (screen, chat) can race the real sender and
  deliver a file first; first valid proof wins the single slot. That is
  inherent to capability codes. Mitigations belong in the UX: single use,
  short TTL, show sender/manifest at accept, and on the sender side a clear
  "receiver already paired with someone else" state rather than a timeout.
- Every candidate socket stays open until the swarm is destroyed; there is no
  per-candidate handshake deadline. Harmless in a CLI, worth fixing before an
  always-on app.
- `QUAY_BOOTSTRAP` is parsed from the environment; fine for tests, but the
  production build should not read it.

### What is good (keep it)

Constant-time compare behind a length check; per-attempt nonces; role tags;
channel binding to both Noise keys with role-ordered concatenation; length-
bounded frames; reserved `0x00` type; strict `resolveCode` shape check; atomic
`.part`→rename after hash verify; an honest doc trail including disproven
hypotheses. The proof itself does not need a rewrite. It needs a different
secret feeding it (1.1) and a transport-independent home (3.2).

---

## 2. Positioning against MeshDrop and DashBeam

### 2.1 What the competitors actually are (from their READMEs, today)

| | MeshDrop | DashBeam | Quay today |
|---|---|---|---|
| Stack | Hyperswarm + Hyperbee, Noise | Iroh (QUIC/TLS 1.3, BLAKE3 blobs) | Hyperswarm, Noise |
| Codes | `MD-` pair codes, single-use `DROP-` codes, HMAC challenge-response | tickets, links, QR, pairing codes, verification codes | 6-word code + QR, HMAC proof |
| Discovery | mDNS + DHT + **TCP relay** | mDNS, n0 relays (self-hostable) | DHT only |
| Resume | yes | yes (BLAKE3) | no (item 6) |
| Approval gate | yes | yes, plus trusted auto-accept | no |
| Platforms | Win / macOS / Linux / Android | Win / macOS / Linux / Android / CLI / web | CLI |
| Version / traction | v1.0.14, 133 commits, ~1 star, MIT | v0.7.1, ~9.6k stars, AGPL-3.0 | 0.1.0 |

Consequences:

- **The plan's competitor table is out of date or wrong about MeshDrop**
  ("Android only", "store-ready: weak", "Yes, fragile"). Per its README it
  ships on four platforms with a relay, resume, and an approval gate, and its
  drop-code design is almost the plan's data path. "Tiny same-stack
  competitor, not the market" is true for *traction*, false for *feature
  parity*. Quay is currently behind it. I have not run it, so "fragile" may
  still be right, but that is a claim to measure, not assume.
- Cheapest high-value action: **read MeshDrop's core and its handshake.**
  Same stack, same idea; you will find either bugs to avoid or a design worth
  adopting. Then run your `scratch-trials` harness against it on the same
  two networks. That single experiment tests your central thesis.
- DashBeam is a different beast: real traction, Iroh's mature relay and
  path-migration story, a browser client. Do not compete on those.
- License hygiene: DashBeam is AGPL-3.0. Do not copy from it; treat it as a
  black box. MeshDrop is MIT (its name and logo are separately protected).

### 2.2 Name

"Quay" is well known as **quay.io**, Red Hat's container registry (Project
Quay). Search and SEO will be hostile, and there is a trademark-adjacent
risk in software. The plan tells you to avoid "Mesh/Beam/Drop" collisions;
apply the same rule here before you have a website. Cheap to fix now,
expensive after users exist.

### 2.3 What you can genuinely own

Ranked by how defensible each is. "Defensible" means a competitor cannot
match it without abandoning a design decision.

1. **Serverless-by-default rendezvous, with relay as a plug-in.** The DHT
   means no operator-controlled infrastructure is needed to *find* a peer.
   Iroh, by design, routes discovery and first-hop through relay servers
   (default: n0's). This is your one structural difference. **Plan phase C
   erodes it**: "your relay, default hosted" makes Quay an Iroh-shaped product
   with a smaller relay fleet. Keep the claim true by making the relay
   optional, self-hostable, protocol-documented, and not in the default path
   when direct works. Investigate whether Holepunch's own blind-relay
   component can serve as the fallback so you run nothing *(verify; your
   spike 2/7)*.
2. **Protocol-first, with a spec and a conformance suite.** Both competitors
   are apps that happen to have an engine. Publish a versioned wire spec
   (handshake, PAKE, accept/resume messages), test vectors, and the
   `scratch-trials`-style harness as a reusable tool. Your docs already have
   this discipline; almost nobody in this space does. It makes Quay the thing
   *other* clients (Rust, Go, Swift, a browser) implement, which is the only
   way a solo project outlives its author. The natural comparator is
   **magic-wormhole** (PAKE code, mature CLI, but needs a mailbox/relay
   server). "Wormhole without the server" is a sentence people understand.
3. **Ephemeral-by-construction privacy.** No persistent device identity, no
   accounts, per-drop keys, nothing to link two drops. Cheap now, hard to
   retrofit, and structurally unavailable to a product built around trusted
   paired devices. Combine with an opt-in **relay-only mode that hides IPs
   from the peer** (neither competitor headlines this). The plan says defer
   anti-surveillance marketing; I agree on *claims*, but the *architecture*
   choices (1.9) must be made now or you cannot make the claim later.
   Be honest that DHT nodes still see topic and IP.
4. **Streaming and scripting.** Blob-based designs (Iroh) want to hash a file
   before they can address it. A framed stream can send stdin, a tarball, or a
   build artifact of unknown size with a trailing hash:
   `tar c dir | quay send -`, `quay recv | tar x`. That serves developers,
   CI, headless servers, and SSH-less boxes, which GUI-first tools ignore.
   DashBeam has a CLI; the pipe/stream contract and a stable machine-readable
   output mode (`--json` events built on your error codes) are the gap.
5. **Published reliability numbers.** "Lead with reliability" is only a
   position if it is *evidence*. Turn spike 1 into a public, reproducible
   scoreboard: same file, same NAT pairs (home, CGNAT, symmetric, hotspot,
   corporate), Quay vs MeshDrop vs DashBeam vs LocalSend, with Wilson
   intervals (you already computed one honestly for 10/10 → 74.1%). If Quay
   loses, that is the most valuable finding you can get early. If it wins,
   it is your marketing.

**Do not fight on:** a polished GUI race, browser receive (it needs a hosted
bridge, which contradicts "no intermediary" and is DashBeam's growth engine),
trusted-device auto-accept, or content-addressed multi-file sharing.

**Open question to test, not assume: iOS.** Both competitors lack it (per the
plan). Holepunch's Bare runtime is designed for embedding and Keet ships on
iOS *(verify)*, so the runtime path may exist. The plan puts iOS last; if the
spike says it is feasible, cross-OS-including-iOS with no server is the
largest open gap. Local-network permission and background rules make it hard;
PairDrop-style browser tools already serve casual iOS use, so size the prize
before reordering.

---

## 3. Plan and architecture: gaps to close early

### 3.1 One protocol message set, designed once

Today: sender→receiver `MANIFEST, CHUNK, CANCEL`; receiver→sender `CANCEL`
only. Pending needs, all of which are the *same missing messages*:

| Need | Where it lives in the plan | Needs |
|---|---|---|
| Accept/decline before bytes flow | item 10, section 6 | receiver→sender `ACCEPT` / `DECLINE` |
| Resume from offset | item 6 | `ACCEPT` carries `resumeFrom` |
| "Both UIs show the same hash before Done" | Phase-1 bar 3 | receiver→sender `RESULT{ok, sha256 \| error}` |
| Honest sender progress | item 5 known limit | periodic `CHECKPOINT{offset}` |
| Version/feature negotiation | none | capabilities in HELLO |

Proposal:

```
S→R  MANIFEST{name,size,sha256,...}
R→S  ACCEPT{resumeFrom} | DECLINE{reason}      <- one message covers items 6 and 10
S→R  CHUNK...   (from resumeFrom)
R→S  CHECKPOINT{offset}  every N MiB after fdatasync   (not per-chunk acks)
R→S  RESULT{ok, sha256} | {error}
```

Per-chunk "ack by index" (as item 6 is worded) is the wrong primitive: UDX
under Noise is already reliable and ordered, so acks add round-trip cost for
nothing. What resume needs is a *durable offset*, which a periodic
post-fsync checkpoint gives. Put a **protocol version and capability bitmap in
the authenticated handshake** (inside the MAC transcript, so it cannot be
downgraded). You have taken two "redeploy both sides" breaks already; that
is fine at 0.1.0 and fatal after the first outside user.

Resume has traps the plan does not list:

- **Resume needs the secret to outlive the process.** If the receiver is
  killed, its code and topic are gone. Either persist the code (a capability
  at rest, needs a 0600 file and a TTL) or re-pair with a new code and match
  the partial by `sha256`/name/size. The second is safer and is what the
  sidecar should be keyed on.
- **A `.part` prefix cannot be trusted** after a restart (local tampering,
  crash mid-write). Either re-hash the prefix (cost = a full read) or carry a
  chunk/Merkle hash list in the manifest. This is the real content of spike 6
  (SHA-256 vs BLAKE3/bao vs Hypercore) and it must be decided *before* the
  manifest format is frozen, not before raising the size cap.
- Resuming against a *different* sender is fine if the final hash is over the
  same manifest hash, but the manifest hash is sender-supplied. It is
  transport-integrity, not authenticity. Do not describe the displayed hash
  as protection from a malicious sender.
- The sender hashes the whole file *after* connecting
  (`sendFile` → `hashFile`). For GB files the receiver stares at nothing
  while the sender reads the disk. Hash before joining, or stream with a
  trailing hash.

### 3.2 A transport-independent secure channel

Currently confidentiality/integrity come from Hyperswarm's Noise stream, and
the proof binds to *its* public keys (`bindPeers`). That is elegant and
Hyperswarm-specific. Plan phase C adds a relay that "stitches two sockets" and
sees only ciphertext. What ciphertext? Over a TCP splice there is no Hyperswarm
Noise session between the peers, so either:

- the relay is a trusted MITM (contradicts the threat-boundary text), or
- you write a second E2E handshake for the relay path, then maintain two.

Do it once, now: after the PAKE (1.1), run a Noise channel (e.g. `NNpsk0`
keyed by the PAKE output) *inside* whatever byte pipe exists (Hyperswarm
stream, TCP relay, WebSocket, later a browser). Channel binding then binds to
that inner handshake hash, not to the outer transport's public keys. Payoffs:
relay-safe, browser-receive-possible if you ever want it, and the engine's
security stops depending on which transport carried the bytes. It also
retires the "derive relay token from the code" hazard: **relay tokens must
come from the nameplate, never from anything grindable to the secret**, or the
relay operator becomes a grinder.

Related decision: the plan's data path says Protomux channel; the code uses a
raw stream and hand-rolled frames. That is a defensible simplification, but
Protomux wants to own the stream from the first byte. Adopting it later means
another break. Decide now whether control (CANCEL, CHECKPOINT) and data
share one stream (today: CANCEL waits behind queued chunks) or two.

### 3.3 Items and numbering

- The docs use "item N" for section-4 rows *and* "step N" for the section-3
  data path, and this has already caused an error. ARCHITECTURE says
  "short-lived topics are the answer to grinding, and that is **item 7**".
  Item 7 in the plan is mDNS/multicast. The data path's step 7 is "leave the
  topic". **No plan item owns topic lifetime.** Rename one numbering scheme
  and add the missing item (it dissolves into 1.1 if you adopt the PAKE).
- The plan's Phase-1 bar #1 requires "laptop ↔ phone across home NAT,
  cellular, public Wi-Fi". There is no phone build until Phase E. Substitute
  a tethered laptop for now, and say so.
- §3 says "do not use Hypercore"; §5 lists `protomux` and `compact-encoding`
  as Phase A packages, neither of which the engine uses. Either use them
  (compact-encoding for the manifest makes cross-language implementations
  easier than JSON) or drop them from the plan.
- The plan says decide names "brand-neutral"; see 2.2.

### 3.4 Reliability measurement, extended

The measured 10/10 is one path (CGNAT ↔ home NAT) on one afternoon. The plan's
own risk is dual hard NAT. Before believing "the relay is not on the critical
path":

- Measure **CGNAT ↔ CGNAT** (two phones/hotspots on different carriers) and
  a symmetric/port-randomizing NAT; these are where punching fails.
- Sample across time of day and across DHT churn; the transient the docs
  call "unexplained" deserves a per-hour series, not a lucky rerun.
- Test **same-NAT / hairpin** (already noted) and **VLAN-isolated** networks.
- With `maxParallel: 16` and a 4 s re-announce, measure what a *hostile*
  topic does (many bogus announces): that is both a reliability and a DoS
  test, and you have the harness for it.
- Add a hostile-peer test suite: oversize manifest, huge `size`, slow
  loris after the proof, filenames from 1.2, disk-full, receiver slower than
  sender. Your current tests cover proof attacks well and post-proof
  misbehavior thinly.

### 3.5 Relay design (before writing it)

- Open token allocation with no accounts is a free proxy and a resource
  exhaustion target. Decide rate limits, proof-of-work per allocation, or
  per-IP quotas up front; "cap bandwidth and TTL" alone does not cover it.
- "One connection per token" plus first-come pairing lets whoever races to
  the token take the slot. The relay cannot authenticate, so the E2E channel
  (3.2) must, and the losing peer needs a clear "wrong peer" outcome.
- 443/WebSocket first (your spike 2 is right). Budget: a $6 VPS is fine for a
  50 MB cap, not for abuse; publish the relay's own privacy statement.
- The "we are a pipe" legal argument (plan §3) is only as good as the relay
  never holding plaintext or filenames. That is another reason to settle 3.2
  first.

### 3.6 Process

- **No CI, and Windows is the stated first platform.** Add a GitHub Actions
  matrix (ubuntu, macos, windows-latest) running the existing suite. Expect
  real failures: `fs.rename` over an existing/open file on Windows, SIGTERM
  semantics in `signals.js`, `:` in names, path length, and native prebuilds
  for `sodium-native`/`udx-native` when packaging with Electron or Tauri.
- Pinned versions are good. Add `pnpm audit`/lockfile review to CI; the
  dependency tree (native modules from one org) is your supply-chain surface.
- The 150 s test suite is dominated by real-network/testnet cases; split a
  sub-10 s fast tier so it runs on every save.
- Commit the uncommitted item-5 work; a large uncommitted diff in a security
  -sensitive layer is its own risk.

---

## 4. Suggested order of work (no code written here; this is sequencing)

1. Threat model page (short, 1.9), and scrub the IPs (1.8). Hours.
2. Engine hardening that is independent of protocol changes: safe display
   names, Windows name rules, overwrite protection, default size cap and disk
   check, receiver backpressure, stall timeouts. Days.
3. **Decide 3.1 + 3.2 + 1.1 together** as one "v2 handshake and message set"
   design note *before* item 6. Then item 6 is implemented against a stable
   protocol instead of forcing another break. Include the wordlist split and
   attempt cap.
4. Run the head-to-head reliability experiment against MeshDrop and DashBeam
   (2.3 #5), including CGNAT↔CGNAT. It decides how much the relay matters
   and whether the "reliability" thesis is true.
5. CI matrix including Windows, in parallel with all of the above.
6. Then plan items 6, 7, 8 as written. Choose the name before the site.

## 5. Confidence and gaps

- High confidence (read the code, ran probes): 1.2b, 1.3 (size), 1.8, the
  test-suite result, the numbering inconsistency in 3.3.
- Medium (read the code, did not execute the scenario): 1.2a overwrite,
  1.3 backpressure, 1.4, 1.7.
- Design judgment, not defects: 1.1, 3.1, 3.2. The grinding cost estimate
  is order-of-magnitude with an assumed 10^9 H/s per GPU.
- Unverified: DHT-node visibility details, Holepunch blind-relay and Bare/iOS
  capability, and all competitor claims beyond their READMEs (I could not
  confirm MeshDrop's reliability either way).
