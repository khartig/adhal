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
that lets a second implementation exist and therefore the one that lets a
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
Serves developers, CI, and headless boxes — and aligns exactly with
macOS/Linux-first (§7).

**5. Published, reproducible reliability numbers.** Evidence, not a
slogan. `scratch-trials.js` already exists, classifies by, and
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
the table below is derived from the competitors' own READMEs as summarized
during the September 2026 review. Nobody here has run either tool, read
their source, or measured them. Treat every row as a claim to verify, not
a fact.

| | MeshDrop | DashBeam | Quay today |
|---|---|---|---|
| Stack | Hyperswarm + Hyperbee, Noise | Iroh (QUIC/TLS 1.3, BLAKE3 blobs) | Hyperswarm, Noise |
| Codes | `MD-` pair codes, single-use `DROP-` codes, HMAC challenge-response | tickets, links, QR, pairing + verification codes | 5-word code (public nameplate + secret) + QR, CPace PAKE, attempt cap |
| Discovery | mDNS + DHT + TCP relay | mDNS, relays (self-hostable) | DHT only |
| Resume | yes | yes (BLAKE3) | no (W11) |
| Approval gate | yes | yes, plus trusted auto-accept | no |
| Platforms | Win / macOS / Linux / Android | Win / macOS / Linux / Android / CLI / web | CLI |
| Traction | v1.0.14, ~1 star, MIT | v0.7.1, ~9.6k stars, AGPL-3.0 | 0.1.0 |

**The correction that matters.** The old plan called MeshDrop "Android
only", "fragile", "a tiny same-stack competitor, not the market". Per its
own README it ships on four platforms with a relay, resume, and an approval
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

The window for an inexpensive break closes at the first release.

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
development, testing, and every measurement to date have run, and they are
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
   `acceptOnce` rejected at 502 ms, and `connectOnce` ran the full 5001 ms.
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

### Security review disposition, then the freeze

**Source, stated because it sets how much weight it deserves.** An
AI-assisted security review of `w11-protocol-v2` at commit `6760cae`:
seven model-generated reviews, one discarded for describing a codebase
that is not this one, merged into 21 findings `Q-01`-`Q-21`. It is not
an independent audit. That is Q-05, and it comes after W17, against a
frozen spec.

Every finding was re-checked against `3042057`, five commits later.
Those commits closed three of them in the engine:

| | Finding | State at `3042057` |
|---|---|---|
| Q-01 | AEAD channel not on the transfer path | **Closed.** Every post-handshake frame goes through `openChannel`, which refuses to run without keys; there is no unsealed mode. Tamper test in `sealed-transfer.test.js`. The length prefix is still outside the tag (W15a). |
| Q-02 | Code possession is the only authorisation | **Engine half closed:** ACCEPT/DECLINE, RESULT, DECLINE codes. **CLI half open:** neither receiver passes `onOffer`, so both accept any valid offer without asking (W15c). |
| Q-03 | Capabilities advertised without handlers | **Closed.** `resume` and `stream` both have handlers. Pinned by a test in W15d. |

Every other finding is disposed of below, either in W15 or deferred with
a reason.

**Decisions, 2026-09-26.** Settled before any W15 code, because five of
them change the wire and the freeze is defined by them.

| # | Question | Decision |
|---|---|---|
| 1 | Bind the frame length into the AEAD tag? (Q-01) | **Yes.** The 4-byte length prefix becomes associated data. |
| 2 | Topic encoding (Q-21) | **`lvCat`**, the length-prefixed encoding CPace already uses. |
| 3 | Secret entropy (Q-14) | **Switch to the EFF large wordlist.** Still 2 + 3 words. |
| 4 | Tell a peer that arrives after pairing? (Q-02) | **Yes, with a DECLINE code, `ERR_DROP_TAKEN`.** |
| 5 | Consent and argv defaults (Q-02, Q-17) | **The receiver prompts by default; `--yes` skips it.** A code on argv requires an explicit flag. |
| 6 | How much robustness testing before the freeze (Q-06) | **State-machine spec, negative vectors, a basic fuzz harness.** Property-based and mutation testing go to W12. |
| 7 | The source reviews | **Called AI-assisted reviews.** The raw transcripts are not tracked; only the findings and their status are published. |
| 8 | The product name | **The product becomes ad-ḫal**, written with ḫ (U+1E2B, h with breve below) for the hard *ch* of *loch*. Code, flags, environment variables, comments and protocol labels all use ASCII forms of the name. The protocol identifier is `adhal` (W15a item 5). |

---

- **W15 — Security review disposition.** Four parts, in this order.

  **W15a — Wire changes.** All five land before the freeze. Each one
  updates [`PROTOCOL.md`](PROTOCOL.md) and regenerates the vectors it
  touches, in the same commit.

  1. *Length as associated data (decision 1).* The seal becomes
     `AEAD(k_dir, nonce, [type][body], aad = [len 4])`. Changes
     `channel.js` (`setAAD` on both sides), PROTOCOL §3.4 and §5, and the
     "there is NO AAD" rationale in `channel.js`, which becomes the
     opposite rationale. The existing tampered-length test changes its
     expectation: a rewritten length now fails the tag rather than
     misframing.
  2. *Topic via `lvCat` (decision 2).* The topic becomes
     `BLAKE2b-256(lvCat("quay-v2:topic", nameplate))`. This changes every
     topic, which is the point of doing it now. Changes `topic.js`,
     PROTOCOL §2, and the expected values in `code-vectors.test.js`.
  3. *EFF large wordlist (decision 3).* Replaces short list #1 in
     `wordlist.js`, vendored with the SHA-256 of the EFF source file
     recorded beside it. Hyphenated entries are dropped as today; the
     exact count is confirmed when the list is vendored, not assumed.
     At 7,776 words, each word carries log2(7776) ≈ 12.92 bits:
     - **Secret, 3 words:** about 38.8 bits, up from about 31. Against the
       100-attempt cap that is about 2 × 10⁻¹⁰ per drop, not 4.7 × 10⁻⁸.
     - **Nameplate, 2 words:** about 25.8 bits, up from about 20.7. A 50%
       collision chance moves from about 1,300 to about 9,100 concurrent
       drops.

     Three consequences to handle, not discover:
     - The codes get longer. Large-list words run up to 9 letters, where
       the short list's ran to 5. The worst-case QR payload grows from 35
       characters to about 56 (`ADHAL2:`, plus five 9-letter words, plus
       four separators). At error-correction level H, the standard
       alphanumeric capacities (35 for version 3, 64 for version 5) say
       that moves from a 29×29 code to a 37×37 one. Confirm this against
       `qr.js` once the list is vendored, and update the README examples.
     - `resolve-code.js`'s v1 six-word detection is keyed on the short
       list. **It is deleted.** No v1 code ever existed outside
       development machines, and keeping it would mean vendoring a second
       wordlist just for that check.
     - The entropy constants in `code.js`, the numbers in THREAT-MODEL
       §5.2, and `code.test.js` all change.
  4. *`ERR_DROP_TAKEN` (decision 4).* Today, once `acceptOnce` pairs it
     removes its connection listener, and a later candidate simply goes
     unanswered. Proposed behaviour:
     - While the transfer runs, the paired side keeps answering late
       candidates.
     - A candidate that completes the handshake is told
       `DECLINE{code: ERR_DROP_TAKEN}` as its first sealed frame, then
       closed. Only a peer holding the secret, which means the other human
       in a race, learns the drop was taken.
     - A candidate that fails confirmation still counts toward the attempt
       cap. Burning the cap mid-transfer stops the answering; it does not
       abort the transfer already under way.
     - The losing side reports "this drop was already taken by another
       peer" and exits nonzero.

     **Both directions.** DECLINE was receiver → sender only. The mirror
     case, a second *receiver* arriving at a sender that has already
     paired, needs the sender to say it. So `DECLINE{ERR_DROP_TAKEN}` is
     legal from either side, but only as the first sealed frame after
     CONFIRM. The state machine (W15d) gains one well-defined state rather
     than a special case.
  5. *Rename to ad-ḫal (decision 8).* The old name is on the wire in two
     places, so this has to land before the freeze. After it, a rename
     would be a v3 break.

     **Wire, protocol identifier `adhal`.** Every handshake and code
     vector is regenerated.

     | | Before | After |
     |---|---|---|
     | CPace label (`handshake.js`) | `quay-v2` | `adhal-v2` |
     | HKDF and MAC labels (`handshake.js`) | `quay-v2:mac`, `:r2s`, `:s2r`, `:confirm-s`, `:confirm-r` | `adhal-v2:mac`, `:r2s`, `:s2r`, `:confirm-s`, `:confirm-r` |
     | Topic label (`topic.js`) | `quay-v2:topic` | `adhal-v2:topic` |
     | QR scheme (`code.js`) | `QUAY2:` | `ADHAL2:` |

     `v2` stays, because it matches the version byte HELLO already
     carries. The retired `QUAY1:` scheme leaves `SCHEMES_BY_AGE` along
     with the v1 code detection (item 3).

     **Rule: anything hashed or encoded on the wire is ASCII.** The ḫ
     never enters a label. It has a precomposed form (U+1E2B) and a
     decomposed one (h + U+032E), and a label that depended on Unicode
     normalisation would be a latent interoperability bug in every second
     implementation.

     **Product-facing names.** At `3042057` these are about 200
     occurrences in about 50 files.

     | | Before | After |
     |---|---|---|
     | Packages | `quay`, `@quay/engine`, `@quay/cli` | `ad-hal`, `@ad-hal/engine`, `@ad-hal/cli` |
     | Bins | `quay-send`, `quay-receive`, `quay-code` | `ad-hal-send`, `ad-hal-receive`, `ad-hal-code` |
     | Environment variables | `QUAY_*` (8 of them) | `ADHAL_*`, since a hyphen is not legal in a variable name |
     | Log prefixes, error strings, comments | `Quay`, `quay` | `ad-hal` |

     The display form **ad-ḫal**, with the diacritic, appears only in
     prose: the README title, the docs, `--help` text. Every identifier a
     person types stays ASCII. Renaming the GitHub repository and the
     local checkout is outside this plan.

  **W15b — Engine and CLI hardening.** No wire change.

  | | Change |
  |---|---|
  | Q-11 | Stop echoing peer bytes to the terminal. Sanitise at the throw sites: the `JSON.parse` branches in `message.js` and `transfer.js` stop echoing V8's snippet of peer input, and echoed field values go through `displayName()`. `report.js` also passes every `err.message` through `displayName()`, as defence in depth. |
  | Q-12 | Generate the drop's announce keypair explicitly in Quay and pass it to `createSwarm`, instead of relying on Hyperswarm's default. Record the rule in THREAT-MODEL §4: any persistent identity is presented only inside the channel, never to the DHT. |
  | Q-15 | Rename `--unsafe-opaque` to `--insecure-opaque-code`, and `QUAY_UNSAFE_OPAQUE` to `ADHAL_INSECURE_OPAQUE_CODE`. |
  | Q-16 | The sender opens the file once, and hashes, computes prefixes and sends through one descriptor, with `fstat` supplying the size. |
  | Q-17 | Validate `QUAY_BOOTSTRAP` inside `try/catch` as an array of `{host: string, port: 1-65535}`, with a clean error. Redact topic hex and peer addresses from default output, behind a `--verbose` flag. The argv half is W15c. |
  | Q-19 | When `publish()` falls back to the check-then-rename path, print a warning saying so. `replace: false` stays the default. |
  | Q-18 | Best effort: `fill(0)` the ISK, channel keys and secret Buffers once they are no longer needed. The limitation is documented in THREAT-MODEL, not solved. |

  **W15c — Consent and what the user is told.**
  - *Accept prompt (Q-02, decision 5).* Both receiver CLIs pass
    `onOffer`. The prompt shows the displayed name, size (or "streamed,
    size unknown"), declared SHA-256, and a resume note if one applies.
    `--yes` skips it.
    - With no TTY and no `--yes`, the receiver declines with a clear
      message rather than hanging or silently accepting. This is a
      deliberate behaviour change. Every caller in this repo that drives
      a receiver unattended (the CLI tests, `scratch-trials.js`, the
      demos) gains `--yes` in the same commit. There are no outside users
      at 0.1.0, so no outside script is broken.
    - A risky extension (executables, scripts, installers, archives, and
      double extensions such as `.pdf.exe`) gets an explicit warning
      line, even with `--yes`.
  - *Argv codes (Q-17, decision 5).* A code on argv is refused unless an
    explicit flag is passed: `--code-on-argv`. The interactive
    prompt and stdin (`-`) stay the normal paths. Tests and scripts move
    to stdin.
  - *Drop contention (Q-04).* The receiver prints a prominent line when
    candidates repeatedly fail confirmation or connect silently. Failed
    confirmations from many distinct keys with no success mean a code
    collision or an attack, and the message says so.
    - Silent timeouts are **not** counted toward the burn cap. Counting
      them would let the DHT's own stale announces burn a legitimate drop,
      which is the rule §6 of PROTOCOL.md exists to keep.
  - *Metadata (Q-09).* A one-line notice in both swarm CLIs and in
    `--help`: both IP addresses are visible to the peer and to DHT nodes
    near the topic. Quay is not anonymous.
  - *Loopback (Q-13).* `send.js` and `receive.js` are labelled test-only
    in help and docs. **The published `quay-send` / `quay-receive` bins
    currently point at the loopback tools, not the swarm ones.** Remap
    them, or drop the loopback tools from `bin`.

  **W15d — Tests that pin the argument, and the Q-06 pre-freeze scope.**
  - *Security-property tests:*
    - every advertised capability has a handler (Q-03);
    - channel nonces never repeat in either direction (Q-01);
    - two drops from one process announce different public keys (Q-12);
    - attempt-cap counting: confirmation failures count, silent and
      dropped candidates do not, and backoff is applied (Q-14);
    - opaque codes are never enabled by default (Q-15);
    - a manifest body of `\x1b[2J` and a field carrying U+202E reach the
      terminal escaped (Q-11).
  - *State machine (decision 6).* A new PROTOCOL.md section gives the
    formal state machine for both roles: discovery → candidate →
    handshake → confirm → [drop-taken] → offer → prefix check → transfer
    → result → teardown. Each state lists the messages it accepts.
    `accept-gate.test.js` and `resume.test.js` already cover much of
    this. Add a table-driven test that sends every message type in every
    state and expects the specified refusal, so a gap is a missing row
    rather than a missing thought.
  - *Negative vectors (decision 6).* Published alongside the existing
    Quay vectors:
    - reflected confirmation, replayed HELLO, reused `sid`;
    - downgraded caps, non-canonical caps;
    - CHUNK before MANIFEST, a `0x00` tag, an oversize frame;
    - a truncated length prefix, a rewritten length (now caught by the
      tag, per W15a);
    - PREFIX when none was asked for.
  - *Fuzz harness (decision 6).* A seeded random-mutation harness over
    `frame.js`, `message.js` (every `decode*`), `reader.js`, manifest
    validation and the handshake readers. It checks one property: the
    input is either accepted or refused with a `TransferError`, and
    never throws anything else, hangs, or buffers past its cap. Built on
    `node:test` with **no new dependency**, since adding one needs a
    package manager this environment does not have. Runs a short seed
    budget in the fast tier and a long one on demand.
  - *Security claims (Q-05).* A PROTOCOL.md section stating what v2
    claims and does not claim, so the Q-05 reviewer tests against a
    stated target. For example, it does not claim UC security, because
    of the receiver-chosen `sid`. It also names the `@noble` experimental
    Elligator2 export as a pinned, vector-guarded dependency.

  **Deferred, each with its reason:**

  | | Deferred to | Why not now |
  |---|---|---|
  | Q-04 layered throttling (per-source, per-key budgets) | After W14 | A Sybil attacker rotates both identifiers. W15c makes the attack visible, and W14's data shows whether it happens. |
  | Q-05 independent cryptographic review | After W17 | Reviewing a moving spec wastes the review. |
  | Q-06 property-based and mutation testing | W12 | Decision 6. |
  | Q-07 Windows as a required CI leg | Stage 3 | Documented as unsupported for security purposes until then (W16). |
  | Q-08 gating advisories, SBOM, signed releases | First release | Nothing ships yet. The unused `compact-encoding` is removed in W15b: `engine/package.json` is edited, and `pnpm install` regenerates the lockfile. |
  | Q-09 length padding, re-announce back-off | Post-freeze | Neither changes the wire. Padding only if file-size confidentiality ever becomes a stated goal. |
  | Q-10 relay invariants | Before any relay code | Written into THREAT-MODEL §8 as merge gates now (W16); enforced when a relay exists. Resume's half is already met: nothing is persisted, and PREFIX re-hashes the prefix. |

- **W16 — Release documentation pass.** Last, so the docs describe the
  final code. The rule from here on: **every security claim in a doc
  names the work item that makes it true** (Q-20), which is how the
  Q-01 overclaim would have been caught.

  | Doc | Change |
  |---|---|
  | `README.md` | Rewrite Status and Quickstart to match the code: accept gate, streaming, resume, and the prompt. Say that the code is a bearer capability, that Quay is not anonymous, and that Windows is not supported for security purposes. Fix the Node floor (≥ 24, not ≥ 18). Drop the development narrative. |
  | `PROTOCOL.md` | Spec only. Move the W10/W11 amendment history into a changelog section at the end. Fix the §7.3/§7.4 order. Mark §9 (v1) as historical. Replace the `quay send -` examples with real commands. Remove competitor remarks. |
  | `THREAT-MODEL.md` | Rewrite §9 to present reality. Add the consent prompt, resume `.part` handling (`O_NOFOLLOW`, link-count check, PREFIX's one-bit oracle), the large-list entropy numbers, the DoS posture, secret memory handling, and the relay merge gates. |
  | `ARCHITECTURE.md` | Split into a current design doc and an engineering log under `docs/history/`. Fix the error-code table and the stale "code proof" and cancel-latency passages. Document `stream-handshake.js`. |
  | `IMPLEMENTATION-PLAN.md` | Fix the stale W11 and competitor-table status. Before publication, decide whether it stays public; if so, it becomes a roadmap without the competitor analysis. |
  | `REVIEW-SECURITY-AND-POSITIONING.md` | Move to `docs/history/`. It describes a code state that no longer exists. |
  | `SETUP.md`, `MEASURING-TRANSFER-RELIABILITY.md` | Fix the Node floor, the references to the deleted plan ("Phase A", "Section 8"; the same references are in `scratch-trials.js`), and the missing outcome rows. |
  | New `SECURITY.md` | Disclosure contact and response targets (Q-20). |
  | New `docs/SECURITY-REVIEW.md` | The 21 findings with their final status, framed as an AI-assisted review. The raw transcripts in `docs/audit/` stay untracked (decision 7). |
  | The name, everywhere in prose | Quay becomes ad-ḫal in every doc, written in NFC (precomposed U+1E2B) so that a search for the name finds every occurrence. Commands and identifiers in the docs use the ASCII forms from W15a item 5. |
  | Source comments and strings | Remove the remaining "item N" references, including the user-facing "pre-item-5 build" error string in `message.js`. Keep `scratch-*` out of any published package (Q-20). |

- **W17 — Freeze gate.** PROTOCOL.md is tagged v2-final only when every
  line below is true and was checked by running something, not by
  reading:

  1. W15a's five wire changes are in the spec, the code and the vectors.
     Every protocol label and the QR scheme use the ASCII identifier
     `adhal`. `grep -ri quay` over the code finds nothing.
  2. Every post-CONFIRM frame is sealed with its length bound. No
     plaintext frame is written after CONFIRM, checked by a test.
  3. The consent prompt is the default on both receivers. A late peer
     gets `ERR_DROP_TAKEN` end to end.
  4. Only implemented capabilities are advertised, checked by a test.
  5. The state-machine section exists and its table-driven test passes.
  6. The negative vectors are published and pass. The fuzz harness runs
     in the fast tier and is green.
  7. The security claims section exists.
  8. `pnpm test` and `pnpm typecheck` are green on macOS and Linux. A real
     two-machine drop (macOS ↔ Linux) on the public DHT succeeds on the
     frozen wire.
  9. W16 is done, and `docs/SECURITY-REVIEW.md` shows no finding without
     a status.

  After W17, a change to the wire is a v3 break, and Q-05 can begin.

---

## Stage 2 — prove and publish the thesis

- **W12 — Publish spec, test vectors, conformance harness**
  (differentiator #2). Nearly free once W9 exists, and it is the artifact
  that makes other clients possible.
- **W13 — Streaming/pipe contract + `--json` events** (differentiator #4),
  built on the existing error codes.
- **W14 — Head-to-head reliability** against MeshDrop, DashBeam, and
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
