# Implementation plan

Replaces `Refined-Implementation-Plan.md`, which was deleted rather than
amended. Its useful reasoning moved here and into
[`PROTOCOL.md`](PROTOCOL.md); the rest — an out-of-date competitor table,
a platform order that did not match where development happens, and a relay
plan that eroded the project's one structural advantage — was wrong in
ways that editing around would have preserved.

**Numbering, permanently.** `D1`-`D7` are data-path steps. `W1`-`Wn` are
work items. No bare "item N" anywhere: the old docs used it for both, and
that collision produced at least one documented error.

---

## 1. What this project is for

Two people move a file directly between their machines. No account, no
server holding the bytes, no install on a third party's terms.

That sentence is not a differentiator on its own — several tools claim it.
What follows is an attempt to be honest about which parts of it a
competitor would have to abandon their own design to copy.

---

## 2. Differentiators, ranked by defensibility

"Defensible" means: a competitor cannot match this without giving up a
decision they have already built on.

**1. Serverless-by-default rendezvous.** Discovery is the DHT. A relay is
an opt-in plug-in, never the default path when direct works. Iroh-based
designs route discovery and first hop through relay servers by design —
matching this would mean unbuilding that. This is the one structural
difference, which is why §6 freezes constraints on the relay before any
relay code exists.

**2. Protocol-first.** A published, versioned spec with test vectors and a
conformance suite ([`PROTOCOL.md`](PROTOCOL.md), W12). Both competitors
are applications that happen to contain an engine. This is the property
that lets a second implementation exist, and therefore the one that lets a
solo project outlive its author.

**3. Ephemeral-by-construction privacy.** No accounts, no persistent
identity, per-drop keys, nothing linking two drops
([`THREAT-MODEL.md`](THREAT-MODEL.md) §4). Structurally unavailable to a
trusted-device product, because their feature *is* the persistent
identity. Cheap now — it is already true by accident — and impossible to
retrofit once linkage exists in records other people hold.

**4. Streaming and scripting.** `tar c dir | quay send -`,
`quay recv | tar x`, stable `--json` events. Blob-addressed designs must
hash before they can address, so they cannot stream an unknown length.
Serves developers, CI and headless boxes — and aligns exactly with
macOS/Linux-first (§7).

**5. Published, reproducible reliability numbers.** Evidence, not a
slogan. `scratch-trials.js` already exists, classifies by `err.code` and
reports Wilson-honest rates.

### Deliberately not building

- **A polished GUI race.** Cannot be won solo against a funded competitor.
- **Browser receive.** Needs a hosted bridge, which contradicts #1. It is
  a competitor's growth engine and would be our contradiction.
- **Trusted-device auto-accept.** Directly contradicts #3.
- **Content-addressed multi-file sharing.** That is the other design.

---

## 3. Competitors

**Provenance, stated because it changes how much weight this deserves:**
the table below is derived from the competitors' own READMEs as summarised
during the September 2026 review. Nobody here has run either tool, read
their source, or measured them. Treat every row as a claim to verify, not
a fact.

| | MeshDrop | DashBeam | Quay today |
|---|---|---|---|
| Stack | Hyperswarm + Hyperbee, Noise | Iroh (QUIC/TLS 1.3, BLAKE3 blobs) | Hyperswarm, Noise |
| Codes | `MD-` pair codes, single-use `DROP-` codes, HMAC challenge-response | tickets, links, QR, pairing + verification codes | 6-word code + QR, HMAC proof |
| Discovery | mDNS + DHT + TCP relay | mDNS, relays (self-hostable) | DHT only |
| Resume | yes | yes (BLAKE3) | no (W11) |
| Approval gate | yes | yes, plus trusted auto-accept | no |
| Platforms | Win / macOS / Linux / Android | Win / macOS / Linux / Android / CLI / web | CLI |
| Traction | v1.0.14, ~1 star, MIT | v0.7.1, ~9.6k stars, AGPL-3.0 | 0.1.0 |

**The correction that matters.** The old plan called MeshDrop "Android
only", "fragile", "a tiny same-stack competitor, not the market". Per its
own README it ships on four platforms with a relay, resume and an approval
gate, and its drop-code design is close to our data path. "Not the market"
is true of *traction* and false of *feature parity*: **on features, Quay
is currently behind it.** "Fragile" may still be true — that is what W14
measures.

**Licence hygiene.** DashBeam is AGPL-3.0: treat it as a black box, do not
read its source with an eye to copying. MeshDrop is MIT, so reading its
core is both legal and the cheapest high-value research available — same
stack, same idea, so it contains either bugs to avoid or a design worth
adopting.

**Standing instruction: re-verify before relying on any row above.**
A dated table is a snapshot, and this one is second-hand.

---

## 4. Corrected key hierarchy

The old architecture rooted everything in a *persisted device keypair*.
That is structurally incompatible with differentiator #3.

```
Per-drop ephemeral transport keypair   <- ROOT. Never persisted, never reused.
`-- Drop secret  (nameplate | PAKE secret)
    `-- PAKE session key (ISK)
        `-- AEAD channel keys (directional send/recv)

Long-term identity (optional, "Keep this device")
        ^ presented ONLY inside the authenticated channel.
          Never the drop swarm keypair. Never visible to the DHT.
```

Full reasoning in [`THREAT-MODEL.md`](THREAT-MODEL.md) §4. The short
version: Hyperswarm already generates a fresh keypair per process because
`createSwarm` sets no `keyPair`. That accident is a privacy feature, and
it has to become a stated invariant *before* "Keep this device" is
designed — otherwise every drop by one user becomes linkable.

---

## 5. Protocol v2 — one break

Specified in [`PROTOCOL.md`](PROTOCOL.md). Summary of what changes and
why it is a single break rather than three:

- Code splits into **nameplate + secret**; the topic commits only to the
  nameplate, so there is no offline grinding target.
- **CPace** replaces the HMAC proof, in the same three-message slot, so
  neither side's first read or first write moves and Hyperswarm's
  duplicate-connection tie-break is not disturbed.
- **AEAD channel keyed by the PAKE transcript**, so security stops
  depending on which transport carried the bytes.
- Message set gains `ACCEPT`, `DECLINE`, `CHECKPOINT`, `RESULT`, `END`.
- **`size: null` + `END{sha256}`** for streaming. Not optional: without
  it, differentiator #4 costs a third wire break.

The window for a cheap break closes at first release.

---

## 6. Relay constraints (frozen before any relay exists)

The old plan's "your relay, default hosted" erodes differentiator #1 — it
makes this an Iroh-shaped product with a smaller relay fleet.

- **Optional**, and never in the default path when direct works.
- **Self-hostable**, protocol documented.
- Relay tokens derive from the **nameplate only**, never from anything
  grindable back to the secret.
- Investigate Holepunch's own blind-relay first: the best relay to operate
  is none.

Full boundary in [`THREAT-MODEL.md`](THREAT-MODEL.md) §8.

---

## 7. Platform order

**macOS + Linux → Windows → Android → iOS.**

This is a correction. The old plan led with Windows, and the code still
carries comments justifying decisions with "Windows ships first" — which
was never true of where the work happens. macOS and Linux are where
development, testing and every measurement to date have run, and they are
where differentiator #4 (pipes, scripting, CI, headless) lands naturally.

**iOS is a potential differentiator, not an afterthought.** Both
competitors lack it. Holepunch's Bare runtime *may* make it reachable —
**unverified**, and worth a spike early to size the prize, because
"cross-OS including iOS, with no server" is the strongest version of this
project's story.

---

## Stage 0 — security, no protocol change (done)

Every item here is wire-compatible with v1, so none of it waited on the v2
design. Baseline before: **73 tests, ~100 s**. After: **89 tests**, plus a
**4 s fast tier**.

| | Item | Outcome |
|---|---|---|
| **W1** | Purge leaked IPs from git history | Two home IPs were in 9 of 19 commits |
| **W2** | [`THREAT-MODEL.md`](THREAT-MODEL.md) | Written before the protocol froze, because it drives the design |
| **W3** | Engine hardening | New `engine/src/names.js`; overwrite protection; `O_EXCL`; size cap + free-space; receiver backpressure; stall timeouts; per-candidate handshake deadline |
| **W4** | `resolveCode` gate | Opaque codes now require `--unsafe-opaque` |
| **W5** | CLI hygiene | Code readable from stdin; names printed via `displayName()`; `maxSize` passed |
| **W6** | Tests | 16 new, including the first **sender-side** cancel tests |
| **W7** | CI | macOS + Linux required, Windows advisory; fast tier |
| **W8** | Commit in reviewable chunks | |

### The three bugs found by probing rather than reading

Each was verified by execution before being believed, and each is now
covered by a test.

1. **`connectOnce` silently ignored its `AbortSignal`.** It accepted
   `signal`, defined `onAbort`, and removed it in `finish()` — but never
   registered it. Measured: aborting at 500 ms against a 5000 ms budget,
   `acceptOnce` rejected at 502 ms and `connectOnce` ran the full 5001 ms.
   On the real sender that is up to two minutes of Ctrl-C doing nothing,
   while `README.md`, `ARCHITECTURE.md` and `swarm-send.js` all documented
   the opposite as shipped. It survived because **there was no sender-side
   cancel test at all** — the asymmetry in the tests mirrored the
   asymmetry in the bug.

2. **`chunkSize` / frame-size off-by-one.** `MAX_CHUNK_SIZE` and the frame
   cap were both `1024 * 1024`, but `encodeMessage` adds a one-byte tag —
   so a sender using the largest *permitted* chunk size emitted a
   1048577-byte frame its peer refused with `ERR_PROTOCOL`. The manifest
   validated; the first chunk died. Latent only because both CLIs use the
   64 KB default. Now derived as `maxFrame - tagSize`, so the two cannot
   drift apart again.

3. **Literal NUL bytes made source files invisible to `grep`.**
   `transfer.js` and `message.js` contained raw `0x00`, so `file(1)`
   reported both as `data` and
   `grep -n 'safeOutputName' engine/src/transfer.js` **exited 1 for a
   string that occurs three times**. A repo-wide grep for
   `ERR_HASH_MISMATCH` silently omitted the file that throws it. This is a
   correctness hazard, not a style nit: the two largest security-critical
   modules returned false negatives to any auditor's search. A third file,
   `cli/test/cancel.test.js`, turned out to have the same defect and was
   found only by auditing every file in the repo with `file(1)`.

### One correction to the review that prompted this work

Its PAKE recommendation rested on "libsodium's ristretto primitives are
already in your dependency tree via `sodium-native`". **Verified false:**
`sodium-native@5.1.0` exposes no `crypto_core_ristretto255_*`, and it is
only a transitive dependency, never declared. It does expose ed25519 group
arithmetic and argon2id. W10 decides on that real footing.

---

## Stage 1 — freeze the protocol

- **W9 — [`PROTOCOL.md`](PROTOCOL.md). Done.** Includes the three
  resume traps the old plan omitted: the secret must outlive the process
  (prefer re-pairing over persisting a capability at rest); a `.part`
  prefix cannot be trusted after a restart; and the displayed hash is
  transport integrity, not protection from a malicious sender.

- **W10 — PAKE selection spike. Done, and the spec is frozen.** Every
  §8 decision is settled and carries the running code that settled it:

  | Decision | Outcome | Evidence |
  | --- | --- | --- |
  | §8.1 which PAKE | CPACE-X25519-SHA512 over `@noble/curves@2.4.0` | all 9 CFRG vectors + all 12 low-order vectors reproduce; 2.08 ms/side |
  | §8.2 Protomux | No — keep the hand-rolled framing; dependency removed | protomux 3.12.0 has no priority path; cancel latency measured |
  | §8.3 checkpoint | Every **5 seconds**, not every N bytes | fsync is a fixed ~17 ms cost, so a byte interval has no stable price |
  | §7.2 resume | Re-hash the `.part` prefix; manifest stays fixed-shape | — |

  The premise the spike started from was false and checking it was the
  point: `sodium-native@5.1.0` exports 313 symbols and **zero**
  ristretto255 ones, and is not resolvable from `engine/` at all.

  Two things landed that were not asked for and are worth knowing.
  **`engines.node` moved `>=18` → `>=20.19`** across all three
  `package.json` files, because `@noble/curves@2.4.0` is ESM-only and
  the CJS-compatible 1.9.7 does not export the Elligator2 map. And
  `cli/test/cpace-vectors.test.js` is the repo's **first conformance
  test** — every other expected value in `cli/test/` is recomputed at
  runtime by the primitive under test, which proves self-consistency and
  not correctness. It is the seed of W12.

  §8.2's own estimate turned out to be wrong, which is the sort of thing
  this standard exists to catch: "one chunk plus the high-water mark"
  understates sender-side cancel latency by 4.5×, because
  `writableHighWaterMark` is not the write-ahead depth.

- **W11 — Implement v2**, against the frozen spec. Handshake
  ([`PROTOCOL.md`](PROTOCOL.md) §3.2 has the full parameter mapping and
  the four ways to get it wrong), AEAD channel, message set, then resume
  (`ACCEPT{resumeFrom}` + `CHECKPOINT`). `engine/src/cpace.js` exists and
  is tested; nothing consumes it yet. Also lands `ERR_ATTEMPT_CAP`, which
  §10 specifies and nothing yet throws.

---

## Stage 2 — prove and publish the thesis

- **W12 — Publish spec, test vectors, conformance harness**
  (differentiator #2). Nearly free once W9 exists, and it is the artifact
  that makes other clients possible.
- **W13 — Streaming/pipe contract + `--json` events** (differentiator #4),
  built on the existing error codes.
- **W14 — Head-to-head reliability** against MeshDrop, DashBeam and
  LocalSend on identical network pairs, including **CGNAT↔CGNAT** and
  symmetric NAT. Reuse `scratch-trials.js`. **This single experiment tests
  the central thesis and decides how much the relay matters.** Read
  MeshDrop's core first (MIT, same stack); treat DashBeam as a black box
  (AGPL).

---

## Stage 3 — reach, in corrected order

macOS + Linux CLI → LAN discovery (mDNS/multicast) → macOS + Linux desktop
app → optional relay (under §6) → **Windows** → **Android** → **iOS spike,
then build**.

Size the iOS prize early (§7).

---

## Verification standard

Applies to this plan and to anything built from it.

1. `pnpm test` green. `pnpm test:fast` for iteration.
2. `pnpm typecheck` (`tsc --noEmit`) — the repo is JSDoc-typechecked.
3. **Probe, do not infer.** Every security claim in Stage 0 was checked by
   running code against the shipping path. Three defects were found that
   reading had missed, and one claim in the review that prompted the work
   turned out to be false. A finding nobody executed is a hypothesis.
4. `file <src>` must report text for every source file, and `grep` must
   find what is in them.
5. Real two-machine drop on the public DHT (macOS ↔ Linux) before calling
   a transport change safe.
