# Quay wire protocol

**v1 — shipped, described in §9 for interoperability.**
**v2 — specified here and frozen by W10. Implemented in W11. Not yet on
the wire.**

§8's decisions are settled, not open: the PAKE suite, the framing, the
resume strategy and the checkpoint interval each carry the measurement
or the test vector that closed them. What W11 builds against will not
move underneath it.

This is the versioned specification. It is a deliverable, not a note: a
published spec with test vectors and a conformance suite is what lets a
second implementation exist, and that is
[differentiator #2](IMPLEMENTATION-PLAN.md#differentiators). Both
competitors are applications that happen to contain an engine. This is an
engine with a specification, and that is what lets a solo project outlive
its author.

Numbering: **D1-D7** are data-path steps, **W1-Wn** are work items. No
bare "item N" — that collision has already produced one documented error.

---

## 1. Why v2 breaks the wire, once

v2 changes the code format, the handshake, the framing and the message
set, all together. Three separate breaks would be three "redeploy both
machines" events; this is one.

**The window for doing it is now and it closes on first release.** At
0.1.0, with no outside users, a wire break costs a `git pull` on two
machines. After the first outside user it costs compatibility code
forever. v1 already took two breaks (the code proof, then the type tag),
and each was justified the same way: take it while it is cheap.

What forces the break:

| Change | Why it cannot wait |
| --- | --- |
| Split code into nameplate + secret | The topic currently commits to the whole code, so codes are grindable offline. Fixing it changes what a code *is*. |
| PAKE replaces the HMAC proof | Different messages, different sizes. |
| AEAD channel keyed by the PAKE transcript | Security stops depending on which transport carried the bytes — the precondition for a relay and for browsers. |
| `size: null` + `END{sha256}` | Streaming (`tar c dir \| quay send -`) cannot be expressed in a manifest that requires a length. Omitting it costs a *third* break. |
| `ACCEPT{resumeFrom}` / `CHECKPOINT` | Resume needs a durable offset. |

---

## 2. The code

```
code   = nameplate(2 words) + secret(3 words)        5 words total
         ~20.7 bits           ~31.0 bits
topic  = BLAKE2b-256("quay-v2:topic" || nameplate)   public, findable
secret -> PAKE                                       never hashed into anything public
```

Words come from the vendored EFF short list #1 (1295 words, 3-5 letters);
see [`ARCHITECTURE.md`](ARCHITECTURE.md) for why that list and not BIP39.

The nameplate is a **rendezvous label**, not a secret. It is public the
moment the receiver announces. The secret is the only secret, and it never
appears in any value an observer can obtain — so there is no offline
grinding target. Guessing the secret requires a live protocol run against
a peer that is counting (§6).

**The code is shorter than v1's six words and stronger**, because its
entropy no longer has to defend a public hash.

Canonical form is lowercase, hyphen-separated, nameplate first:

```
QUAY2:ACID-ACORN-ACRE-ACTS-AFAR      <- QR payload, uppercase (alphanumeric mode)
acid-acorn-acre-acts-afar            <- shown to a human
^^^^^^^^^^ nameplate   ^^^^^^^^^^^^^ secret
```

Input normalisation is unchanged from v1: case, and any run of `-`, `_`,
`.` or whitespace, collapse to one canonical form before anything derives
from it.

---

## 3. The handshake

### 3.1 It fits the existing three-message slot, and that is load-bearing

Hyperswarm produces **two** connections per pair (both sides join with
`server: true, client: true`) and destroys one with `ERR_DUPLICATE`. The
tie-break is `existingIsOutdated = rawBytesRead > 0 && rawBytesWritten > 0`
— so a connection that has written but not yet read does not count as
established and is eligible to be destroyed mid-handshake.

v1's code proof was designed carefully not to move either side's first
read or first write. **v2 must not move them either.** CPace is a
one-round-trip simultaneous PAKE, so it drops into the same shape:

```
R -> S   HELLO   { version, caps, sid, Ya }   receiver still writes first
S -> R   REPLY   { Yb, confirmS }             sender still reads first, writes on answering
R -> S   CONFIRM { confirmR }
```

Same three messages, same first-read and first-write points, so **no new
duplicate-resolution risk**. The third message is sent only after both
sides are already established.

**One framing consequence, stated here because W11 will otherwise trip
over it.** v1's three messages are all fixed sizes — 33, 64, 32 — which
is why `engine/src/swarm.js:66-67` can hold them as compile-time
constants and call `MessageReader.take(n)` with a literal. `CONFIRM` (32)
stays fixed under v2. `HELLO` and `REPLY` do not: `caps` is
variable-length, so **both carry their own length prefix** and the reader
takes the prefix first. `MessageReader` already reads by byte count and
needs no change; the constants do.

> **Amended in W11, and the reason is a defect in this section.** As
> frozen by W10, §3.1 fixed `REPLY` at 64 bytes — `{Yb 32, confirmS 32}`,
> with no `caps_s` field. But §3.2 puts `ADb = lv_cat(version, caps_s)`
> inside `transcript_ir`, derives `ISK` from that transcript, and MACs
> `confirmS` under a key derived from `ISK`. So the receiver needs
> `caps_s` in order to verify the confirmation that arrives *in* `REPLY`
> — and `caps_s` was transmitted nowhere in the three-message handshake.
> **§3.2's handshake was not implementable as §3.1 framed it.**
>
> The fix is to length-prefix `REPLY` as well, so it carries `caps_s`:
>
> ```
> HELLO   = [2-byte BE len][version 1][sid 16][Ya 32][caps_r ...]   R -> S
> REPLY   = [2-byte BE len][Yb 32][confirmS 32][caps_s ...]         S -> R
> CONFIRM = [confirmR 32]                                           R -> S
> ```
>
> `version = 0x02`; `caps` is capped at 128 bytes, so both bodies are
> bounded and a peer cannot make us buffer.
>
> This preserves the property §3.1 actually calls load-bearing: the
> receiver still writes first, the sender still reads first and writes on
> answering. Checked against Hyperswarm's source rather than this
> section's paraphrase of it — `hyperswarm/index.js:359` computes
> `existingIsOutdated = existing.rawBytesRead > 0 && existing.rawBytesWritten > 0`
> and line 361 falls back to an initiator comparison, so the tie-break
> turns on *whether* bytes have moved, never on how many. A longer
> `REPLY` cannot affect it.
>
> So "REPLY stays fixed" was a note about holding sizes as compile-time
> constants (`swarm.js:66-67`), not a security claim. Recorded here
> rather than edited away, for the same reason §8.2's wrong latency
> estimate and the Node-version floor are: a spec that quietly rewrites
> its own mistakes teaches a second implementer nothing.

### 3.2 Parameter mapping, transcript, and downgrade resistance

The suite is **CPACE-X25519-SHA512** (`CPace255`), per §8.1. The
composition lives in `engine/src/cpace.js` and is checked against the
CFRG vectors by `cli/test/cpace-vectors.test.js`. What follows is the
part that is *not* in the draft: which Quay value goes into which CPace
input. It is the only genuinely novel piece of v2's handshake, so it is
specified here in full and its weak points are named rather than left
for a reader to find.

```
PRS = the 3-word secret, canonical form, UTF-8       e.g. "acre-acts-afar"
CI  = lv_cat("quay-v2", nameplate)                   binds the nameplate into the generator
sid = 16 CSPRNG bytes, chosen by the receiver, sent in HELLO
ADa = lv_cat(version, caps_r)                        receiver = CPace initiator (A)
ADb = lv_cat(version, caps_s)                        sender   = CPace responder (B)

g            = calculate_generator(PRS, CI, sid)
Ya           = X25519(ya, g)       ya fresh per connection, never reused
Yb           = X25519(yb, g)       yb likewise
K            = scalar_mult_vfy(...)                  aborts on the neutral element
transcript   = transcript_ir(Ya, ADa, Yb, ADb)
ISK          = SHA-512( lv_cat("CPace255_ISK", sid, K) || transcript )

mac_key  = HKDF-SHA256(ISK, salt=sid, info="quay-v2:mac", 32)
confirmS = HMAC-SHA256(mac_key, "quay-v2:confirm-s" || transcript)
confirmR = HMAC-SHA256(mac_key, "quay-v2:confirm-r" || transcript)
k_r2s    = HKDF-SHA256(ISK, salt=sid, info="quay-v2:r2s", 32)
k_s2r    = HKDF-SHA256(ISK, salt=sid, info="quay-v2:s2r", 32)
```

`lv_cat` is the draft's LEB128 length-prefixed concatenation. Every
composite input uses it, so no two distinct parameter sets can produce
the same hash input by shifting bytes across a field boundary.

**`transcript_ir`, not `transcript_oc`**, because message ordering here
**is** enforced: the receiver always writes first, and §3.1 explains why
that cannot change. The draft permits `_ir` exactly under that condition.
If the write order ever became negotiable, this would have to become
`_oc` in the same change.

#### What this mapping gets right

`version` and `caps` sit in `ADa`/`ADb`, which are inside
`transcript_ir`, which is hashed into `ISK`, which keys both
confirmations. An attacker who strips a capability or forces an older
version makes the two sides derive different keys, and both confirmations
fail. Note the honest scope of that: it is **detection, not prevention**.
The handshake aborts; it does not silently fall back. That is the correct
outcome, and it is the only one available to a one-round-trip PAKE.

Domain tags `-s`/`-r` stop one direction's confirmation being replayed as
the other's. This is the same defence v1 used
(`ROLE_TAGS` in `engine/src/proof.js`) and it is why MACing the *whole*
transcript from both sides — rather than the draft §9.4 suggestion that
each party MAC only its own message — does not open a reflection hole:
the two confirmations are computed over the same bytes under the same
key, but with different prefixes, so neither can stand in for the other.

#### Four things an implementation must get right, or it is wrong

1. **`ya` and `yb` are per *connection*, never per drop.** Draft §9.9
   makes scalar reuse a MUST NOT, and this engine is unusually exposed to
   it: Hyperswarm hands a receiver several candidate peers per drop and
   *two* connections per peer (§3.1). Caching one `Ya` across them to
   save 2 ms would be exactly the reuse the draft forbids. The same
   applies to `sid`.

2. **`caps` needs a byte-exact canonical encoding**, fixed by this spec
   and not left to a serialiser. Two implementations that order the same
   capability set differently will derive different keys and fail every
   handshake — and the failure is indistinguishable from an attack, which
   is the worst way for an interoperability bug to present.

3. **Each side binds what it sent and what it received.** Whatever
   capability set a party acts on must be a pure function of `caps_r` and
   `caps_s` as they appear in the transcript. A party that negotiates
   down based on a received value while MACing the original has
   reintroduced the downgrade the transcript exists to prevent.

4. **`PRS` is the secret's canonical form**, lowercase and
   hyphen-separated exactly as §2 defines it and as `engine/src/code.js`
   already produces — `"acre-acts-afar"`, not `"acreactsafar"` and not
   the QR payload's uppercase. The nameplate is *not* in `PRS`; it is in
   `CI`.

#### The weak point: `sid` is chosen by one party

This is the part of the mapping that departs from the draft's advice, so
it is stated plainly rather than buried.

Draft §9.9 recommends that `sid` be "concatenation of ephemeral random
strings contributed by both parties", and §9.11's quantum-resistance
argument is specifically about a **pre-established** `sid`. A
receiver-chosen `sid` is neither.

**Why it is chosen anyway:** `g` depends on `sid`, and the receiver must
compute `g` before it can send `Ya`. A jointly contributed `sid`
therefore costs an extra round trip — the receiver could not write first,
which §3.1 shows is load-bearing for Hyperswarm's duplicate tie-break.
The choice is between a two-party `sid` and the message shape, and the
message shape wins.

**What it does and does not cost.** An attacker posing as the receiver
still verifies exactly **one** password candidate per run: to test a
guess it needs `CDH(g_guess, Yb)`, and choosing `sid` does not give it
that. So the quantity the attempt cap (§6) defends — guesses per run — is
unchanged. What a chosen, reusable `sid` does buy is (a) escaping the UC
proof's premise that session ids are unique, and (b) amortising the
generator derivation across many attack sessions, which is a constant
factor on work that was never the bottleneck.

**Two mitigations, both cheap, both required:**

- The **sender** remembers the `sid` values it has seen for a nameplate
  and treats a repeat as a failed attempt — countable under §6 rather
  than merely odd. This turns `sid` reuse from invisible into expensive.
- The **receiver** samples `sid` from a CSPRNG per connection, as above.

#### Deviations from the draft, named

So that a second implementation does not assume the draft's text where
this spec differs:

- `mac_key` is `HKDF-SHA256(ISK, salt=sid, info="quay-v2:mac", 32)`, not
  the draft §9.4 suggestion `H.hash("CPaceMac" || sid || ISK)`. Draft
  §9.4 offers its formula as "one suitable option"; HKDF is used here
  because the same construction already produces `k_r2s`/`k_s2r` and one
  KDF is one thing to get right.
- Both confirmations cover the full transcript with role tags, rather
  than each party covering its own message (draft §9.4). See above for
  why this is reflection-safe.

### 3.3 Channel binding moves to the PAKE transcript

v1 bound its proof to the Noise session's public keys
(`bind = both peers' Noise public keys, ordered by role`). That was correct
for v1 and is wrong for v2, for one reason: it makes the engine's security
depend on which transport carried the bytes. A relayed connection, or a
browser one, would have different or absent Noise keys and the binding
would have to be reinvented per transport.

Binding to the PAKE transcript instead means:

- relay-safe — the relay is a pipe and cannot be a party
- browser-possible, later, without redesigning authentication
- one property to reason about, not one per transport

Noise remains, underneath, and is still valuable. It just stops being
load-bearing for authentication.

### 3.4 The AEAD channel

The ISK derives directional keys:

```
k_r2s = HKDF-SHA256(ISK, salt=sid, info="quay-v2:r2s", 32)
k_s2r = HKDF-SHA256(ISK, salt=sid, info="quay-v2:s2r", 32)
```

The full derivation, including `mac_key`, is in §3.2; it is repeated here
only for the reader who arrives at the channel first.

Separate keys per direction, nonces counting from zero and never reused
within a drop. Every frame after the handshake is sealed. This replaces
today's raw framing; the length prefix stays outside the ciphertext so the
decoder can still bound a frame before buffering it (§5).

---

## 4. Message set

Inside the AEAD channel:

```
0x00 reserved (desync sentinel, kept from v1)
0x01 MANIFEST   {v, name, size|null, sha256|null, mode, blockSize, caps}
0x02 CHUNK      raw bytes
0x03 CANCEL     {reason}
0x04 ACCEPT     {resumeFrom}         accept step AND resume, one message
0x05 DECLINE    {reason}
0x06 CHECKPOINT {offset}             R->S, periodic, post-fsync
0x07 RESULT     {ok, sha256} | {error}
0x08 END        {sha256}             streaming trailer, when size was null
```

`0x00` stays reserved and always invalid: a stream read out of phase most
often presents as a length header taken from the middle of a payload, and
zero bytes are what padding and lengths are full of. Reserving it makes
desync fail loudly on the first frame rather than surface later as a hash
mismatch.

### 4.1 Why there is no per-chunk ACK

An earlier plan described resume as "ack by index". That is the wrong
primitive. UDX under Noise is **already reliable and ordered** — a
per-chunk acknowledgement re-implements a guarantee the transport gives
for free, and costs a round trip per chunk to do it.

What resume actually needs is a **durable offset**: how much is safely on
disk. That is `CHECKPOINT{offset}`, sent periodically by the receiver
*after* the bytes are fsynced, not per chunk. Periodic because the cost is
an fsync, and the right frequency is a tuning decision, not a protocol one.

### 4.2 RESULT, and making the hash claim true

`RESULT` carries the receiver's computed digest back to the sender. Until
now the sender printed its own hash and the receiver printed its own, and
"both sides show the same hash" was something a human checked by eye
across two terminals. `RESULT` makes it an assertion the protocol makes.

### 4.3 `size: null` and END — not optional

Streaming is [differentiator #4](IMPLEMENTATION-PLAN.md#differentiators):

```
tar c dir | quay send -
quay recv | tar x
```

A manifest that requires a length cannot express it. So `size` may be
`null`, `sha256` may be `null`, and the sender closes with
`END{sha256}` carrying the digest it computed as it streamed.

The receiver's verification changes shape accordingly: with a declared
size and hash it checks both; with neither it checks the `END` digest
against what it computed. A receiver must not treat a missing `sha256` as
"no verification" — it means "the digest arrives at the end".

Blob-addressed designs (Iroh) cannot do this without hashing first,
because they must know the hash to address the content. That is a
structural advantage, and it is worth one message.

---

## 5. Framing

```
frame = [4-byte BE length][sealed payload]
sealed payload = AEAD(k_dir, nonce, [1-byte type][body])
```

The length prefix is outside the seal so the decoder can reject an absurd
declared length before buffering toward it. A declared length is four
untrusted bytes; without a bound, a peer announcing `0xFFFFFFFF` makes the
decoder buffer toward 4 GB.

**The frame budget must account for every term.** v1 got this wrong in a
way worth recording: `MAX_CHUNK_SIZE` and the frame cap were both stated
as `1024 * 1024`, but `encodeMessage` prefixes a one-byte type tag, so a
chunk of exactly the maximum *permitted* size produced a 1048577-byte
payload that the peer refused with `ERR_PROTOCOL`. The manifest validated;
the first chunk died. Latent only because both CLIs use the 64 KB default.

v2 keeps the rule as an equation rather than two constants, and names
every term so that the two different things called "tag" cannot be
confused for each other again:

```
sealed  = AEAD(k_dir, nonce, [1-byte type][body])
frame   = [4-byte BE length][sealed]

typeTagSize = 1        the message type byte, inside the seal
aeadTagSize = 16       ChaCha20-Poly1305's Poly1305 authenticator
nonce                  implicit, a per-direction counter; not on the wire

maxChunk = maxFrame - typeTagSize - aeadTagSize
         = maxFrame - 17
```

With `maxFrame = 1 MiB` that is **1048559** bytes. ChaCha20-Poly1305 is
a stream cipher, so the ciphertext is the same length as the plaintext
and the 16 bytes are the authenticator alone — there is no block
padding term.

No new dependency is needed for this: Node ships `chacha20-poly1305` in
`crypto.getCiphers()` with a 16-byte `authTagLength`, verified on the
Node 24 this was written against.

v1's equivalent is already correct and worth keeping as the pattern:
`MAX_CHUNK_SIZE = DEFAULT_MAX_FRAME_SIZE - TAG_SIZE`
(`engine/src/transfer.js:39`) — derived, never a second literal. A
chunk of exactly 1 MiB is still refused, which
`engine/scratch-cancel-latency.js` rediscovered by trying it.

---

## 6. Attempt cap

Count **PAKE confirmation failures only**. N = 100, exponential backoff.
On exhaustion, burn the drop, fail with `ERR_ATTEMPT_CAP` (§10) and tell
the human that someone was guessing.

A repeated `sid` from a peer counts as a failed attempt too — see §3.2,
where that mitigation is why a receiver-chosen `sid` is acceptable.

**Never count dropped candidates.** Stale DHT announces routinely produce
dead candidates — measured in this repo, three were once enough to starve
every connection slot — and counting them would let the DHT's own garbage
burn a legitimate drop.

This reverses v1's rule that an attacker must not be able to end a drop by
connecting and failing. Under v2 a nameplate-holder can, after 100 failed
guesses. Accepted deliberately: the alternative is unlimited guessing
against ~31 bits, and a denial of service is a better failure than a silent
compromise. See [`THREAT-MODEL.md`](THREAT-MODEL.md) §5.3.

[`ARCHITECTURE.md`](ARCHITECTURE.md) still states the v1 rule, correctly,
in its description of the v1 code proof; it is annotated there as
superseded by this section rather than rewritten, because the v1
handshake it describes is what still ships.

---

## 7. Resume, and the traps in it

Resume is the feature most likely to be implemented wrongly, because the
obvious design is wrong in three separate ways. All three had to be
settled **before** the manifest format froze, since two of them change
it. All three now are: §7.1 prefers re-pairing, §7.2 re-hashes the
prefix (W10), and §7.3 is a statement about what the hash means.

### 7.1 The secret must outlive the process

Resuming means re-authenticating, which means having the secret again. Two
options:

- **Persist a capability at rest.** Now there is a long-lived secret on
  disk, which contradicts the ephemeral-by-construction invariant
  ([`THREAT-MODEL.md`](THREAT-MODEL.md) §4) and creates something worth
  stealing.
- **Re-pair.** The human supplies the code again; the receiver matches the
  new drop to an existing partial by `sha256`/name/size.

**Prefer re-pairing.** It keeps the invariant, and the cost — retyping a
five-word code after a crash — is small and comprehensible.

### 7.2 A `.part` prefix cannot be trusted after a restart

The `.part` name is predictable by design, so anything that can write to
the output directory can plant or corrupt one. Nothing about a file on
disk proves it is the prefix of the file now being offered.

So a resumed transfer must either **re-hash the prefix** before trusting
it, or the manifest must carry **per-block hashes** so only the blocks
actually being skipped need checking. Re-hashing is simpler and costs one
read; block hashes are faster for very large files and change the manifest.

**Decided (W10): re-hash the `.part` prefix.** No per-block hashes.

The manifest therefore stays fixed-shape — no block-hash field, and
`blockSize` keeps its existing meaning of "how the sender chunks", not
"the unit of a hash tree". That is the consequence that mattered for the
freeze, and it is now settled.

Why re-hashing wins here:

- The cost is one sequential read of the prefix, against a transfer that
  is about to re-fetch the *remainder* over a network. For any resume
  worth doing, the local read is the cheaper half.
- Block hashes are a manifest field, and a manifest field is forever.
  Adding one to make resume faster would be paying a permanent format
  cost for an optimisation nobody has measured a need for.
- A hash tree is also a second thing that can be wrong. The re-hash
  compares against the `sha256` the manifest already carries, so resume
  reuses the integrity check the protocol already has rather than
  introducing a parallel one.

The receiver re-hashes the prefix, compares against the offered
manifest's `sha256` prefix-wise — that is, it hashes what it has and
carries the hash state forward rather than recomputing at the end — and
sends `ACCEPT{resumeFrom}` only for a prefix it has verified itself.
A prefix that does not match is discarded and the transfer starts at
zero; it is not an error to report to the human, because a planted
`.part` is exactly the case this defends against and it is not the
human's doing.

Note what this does **not** cover: `size: null` streaming transfers have
no declared `sha256` (§4.3), so there is nothing to re-hash a prefix
against. **Streaming transfers are not resumable**, and that falls out
of this decision rather than being a separate one.

### 7.3 The displayed hash is integrity, not authenticity

Worth stating in the spec because resume makes it more tempting to
misread: a matching SHA-256 proves the bytes arrived as the sender
described them. It proves nothing about whether the sender was honest
about what it was sending.

---

## 8. Decisions settled in W10

These were open when this document was first written (W9). W10 closed
them, and each one below carries the evidence that closed it rather than
the reasoning that motivated it. Nothing here went on the wire — W11 is
the implementation, and it builds against a spec that will not move.

### 8.1 Which PAKE, and on what — **CPACE-X25519-SHA512 over `@noble/curves`**

**First, the correction that started this.** It was asserted that
"libsodium's ristretto primitives are already in your dependency tree via
`sodium-native`". That is **false**, and it is false in two ways:

- `sodium-native@5.1.0` exports **313 symbols and zero**
  `crypto_core_ristretto255_*` ones.
- It is not resolvable from `engine/` at all. It is a transitive
  dependency of `hypercore-crypto`, declared in no `package.json` here.

What it does expose, and what a decision could have rested on, is
ed25519 group arithmetic (`crypto_core_ed25519_from_uniform`,
`crypto_scalarmult_ed25519_noclamp`) and argon2id.

**The decision, and what settled it.** `@noble/curves@2.4.0` with
`@noble/hashes@2.4.0`:

| Evidence | Result |
| --- | --- |
| The 9 CFRG `CPACE-X25519-SHA512` vectors | all reproduce byte-for-byte |
| The 12 low-order / twist vectors | all reproduce; 7 abort, 5 return the stated values |
| `ua`, `ub` — bit #255 set | correct, so `decodeUCoordinate` is handled |
| Cost, p50, this machine | **2.08 ms per side** (generator + 2 scalar mults + SHA-512) |
| Generator derivation alone | 0.11 ms p50 |

`ua` and `ub` deserve the separate row. They are the *same field
elements* as `u3` and `u4` (because `2^255 ≡ 19 mod p`), yet `u3` and
`u4` must abort and `ua` and `ub` must not. That is only consistent if
an implementation masks bit #255 without reducing mod p — RFC 7748 to
the letter. Both natural mistakes, reducing and not masking, fail on
exactly these two inputs and nowhere else, which is why the draft ships
them and why `cli/test/cpace-vectors.test.js` asserts the relationship
and not just the two outputs.

The vectors are the deliverable, not this table. The rule "do not
hand-roll without external review" is met by composition: every field
and group operation comes from the audited library, and the only thing
`engine/src/cpace.js` does itself is put the draft's byte strings
together in the draft's order — which is precisely what a fixed
input/output vector can check.

**The one user-visible cost.** `@noble/curves@2.4.0` is ESM-only
(`"type": "module"`, `engines: >= 20.19.0`). It loads from CommonJS via
`require(esm)` on Node 20.19+ / 22.12+ but not on Node 18. The
CJS-compatible `1.9.7` was checked as a fallback and **does not export
the Elligator2 map at all**, so staying on v1 would mean reaching into
internals or hand-rolling the map — the thing this decision exists to
avoid. So `engines.node` moves from `>=18` to `>=20.19` in all three
`package.json` files. Node 18 went end-of-life in April 2025 and CI
already runs Node 22 on all three legs, so the declared `>=18` was
untested anyway.

> **Superseded.** The floor is now `>=24` and CI runs Node 24
> (`.github/workflows/ci.yml:58,95,131`). Not for `require(esm)` —
> 20.19/22.12 are enough for that — but because on 22.x the six
> stall-timer and size-cap tests in `cli/test/hardening.test.js` are
> reported cancelled rather than run, reproducibly on 22.23.2 and clean
> on 24.21.0.

Also confirmed, so that neither forces a further dependency:

- Node ships `chacha20-poly1305` with a 16-byte tag — the v2 AEAD (§5)
  needs nothing new.
- `hypercore-crypto.hash` **is** BLAKE2b-256, checked against the known
  digest of `abc` — §2's topic derivation needs nothing new either.

`_map_to_curve_elligator2_curve25519` is marked experimental by noble
and may be renamed. Both dependencies are pinned to exact versions, and
the vector test is what catches a behaviour change.

### 8.2 Protomux or raw stream — **keep the hand-rolled framing**

`protomux@3.12.0` **has no priority, preempt or urgent path.** It
cork/uncork-batches and writes in order to a single stream. So a
`CANCEL` on a separate channel would queue behind already-written chunk
bytes *exactly* as it does today. It does not solve the problem this
section posed. Two further reasons, either of which would be sufficient:
under v2's AEAD channel it would double-frame, and it binds to a
`NoiseSecretStream`-shaped duplex — the transport dependency §3.3 exists
to remove.

The dependency has been removed from `engine/package.json`; it was never
imported by any source file.

**And the estimate this section was built on was wrong.** §8.2 used to
say a cancel is "delayed by roughly one chunk plus the high-water mark".
`engine/scratch-cancel-latency.js` measures it over a real loopback TCP
socket, at the 64 KB default and either side cancelling:

Median latency, and bytes the peer moved *after* being told to stop
shown as a range over 15 trials — that quantity is set by kernel socket
buffers and varies run to run, which is itself part of the finding:

| chunk | sender cancels | receiver cancels |
| --- | --- | --- |
| 16 KiB | 1.7 ms, 16–32 KiB in flight | 0.3 ms, 16 KiB |
| **64 KiB** | **3.4 ms, 256–832 KiB** | **0.4 ms, 64 KiB** |
| 256 KiB | 5.1 ms, 768–2048 KiB | 0.8 ms, 256–512 KiB |
| 1048575 B | 8.4 ms, 2048–3072 KiB | 1.4 ms, 1024–3072 KiB |

"One chunk plus the high-water mark" would be 128 KiB at the default.
The receiver-cancels column beats that and is dead stable at **exactly
one chunk**. The sender-cancels column is **2–6.5× worse** than the
estimate, because `writableHighWaterMark` is 65536 and is *not* the
write-ahead depth: the kernel's send and receive buffers are, they are
an order of magnitude larger, and the framing layer cannot see them.
Estimating from the number Node happens to expose was the error, and no
framing change would have fixed it.

The two directions are also not the same thing, which the old wording
conflated. A sender's `CANCEL` is written into a stream it has already
filled, so it sits behind those bytes — genuine head-of-line blocking,
and the only one of the two a control channel could address. A
receiver's `CANCEL` travels upstream where nothing is queued and is read
promptly; what is delayed is the *effect*, and the bytes already in
flight arrive regardless. No multiplexer recovers those.

**The lever is write-ahead depth, and the measurement shows it.**
Quartering the chunk size from 64 KiB to 16 KiB cut sender-side
in-flight bytes by a factor of 16–26 and halved the latency. Changing
which framing layer carries the control message would have moved none of
these numbers, because every one of them is set below the framing layer.

Loopback has no propagation delay, so read every figure as a floor.

### 8.3 Checkpoint frequency — **every 5 seconds, not every N bytes**

`engine/scratch-fsync.js` measures `fsync` on the target filesystem
(APFS, `/System/Volumes/Data`), and the measurement **refutes the way
this section asked the question.**

fsync cost here is a device round trip, near-independent of how much was
written since the last one:

| bytes since last fsync | p50 | p90 | p99 |
| --- | --- | --- | --- |
| 1 MiB | 6.94 ms | 7.72 ms | 9.11 ms |
| 16 MiB | 14.34 ms | 17.34 ms | 18.00 ms |
| 64 MiB | 15.13 ms | 17.52 ms | 19.36 ms |
| 256 MiB | 19.36 ms | 61.62 ms | 82.05 ms |

64× the data costs about 2× the fsync. Transfer *time* per byte, by
contrast, varies by two orders of magnitude across the links this runs
over. So an interval measured in **bytes cannot have a stable cost** —
the same rule is nearly free on a slow link and ruinous on a fast one:

| interval | at disk speed | at 100 Mbit/s | at 10 Mbit/s |
| --- | --- | --- | --- |
| 1 MiB | 91.8% | 9.6% | 1.1% |
| 16 MiB | 50.9% | 0.97% | 0.10% |
| 64 MiB | 25.0% | 0.31% | 0.03% |

An interval measured in **seconds** has the opposite property, which is
the whole reason to prefer it:

| interval | at any link speed | work lost on a crash |
| --- | --- | --- |
| 1 s | 1.24% | 1 s of transfer |
| 2 s | 0.62% | 2 s |
| **5 s** | **0.25%** | **5 s** |
| 10 s | 0.13% | 10 s |

**The decision: `CHECKPOINT` every 5 seconds of elapsed transfer**, with
one guard — skip a checkpoint if nothing has been written since the last
one, so an idle or stalled transfer does not fsync on a timer. 0.25%
overhead and at most five seconds of lost work, and both of those hold
on a LAN and on a 10 Mbit/s uplink alike, which is the property a byte
interval cannot offer.

This is a receiver-local tuning decision, not a wire format one: the
interval can change without a protocol break. It is recorded here
because §4.1 promised a number and because the *unit* — seconds, not
bytes — is the part a second implementation should copy.

---

## 9. v1, for reference

Shipped today. Documented so a v2 implementation can recognise a v1 peer
and say so rather than reporting corruption.

```
code  = 6 words
topic = hash(code || app-salt)
key   = HKDF(code, "quay-drop-v1")

R -> S   READY || nonceR                              (1 + 32 bytes)
S -> R   HMAC(K, "s" || nonceR || bind) || nonceS     (32 + 32)
R -> S   HMAC(K, "r" || nonceS || bind)               (32)

bind = both Noise public keys, ordered by role

frame   = [4-byte BE length][payload]      max payload 1 MiB
payload = [1-byte type][body]              cleartext (Noise underneath)

0x00 reserved   0x01 MANIFEST   0x02 CHUNK   0x03 CANCEL
```

Manifest v1: `{v: 1, type: "manifest", name, size, chunkSize, sha256}`.

**Version-skew detection already exists and should be kept.** A v1 sender's
first frame begins `0x7b` (`{`) if it predates the type tag, which is
reported by name — "redeploy both sides", not "unknown type 0x7b". A v2
implementation meeting a v1 peer should do the same: name the skew rather
than let it present as corruption.

---

## 10. Error codes

Machine-readable, and the thing anything automated should switch on. The
messages are free to be reworded; **nothing may match on them.** This is
not tidiness: the harness behind every reliability number in this repo once
classified failures by regex-matching error prose, which coupled the
project's own measurement instrument to its wording.

| Code | Meaning |
| --- | --- |
| `ABORT_ERR` (`name: AbortError`) | we cancelled, locally |
| `ERR_CANCELLED_PEER` | they cancelled, with their reason |
| `ERR_HASH_MISMATCH` | the bytes are wrong |
| `ERR_SIZE_MISMATCH` | more or fewer bytes than declared |
| `ERR_UNSAFE_NAME` | the name is not one we will write; `.detail` says why |
| `ERR_MANIFEST_INVALID` | a manifest field failed validation |
| `ERR_PROTOCOL` | unknown tag, oversize frame, out-of-order frame |
| `ERR_CONNECTION` | the socket closed before completion |
| `ERR_STALLED` | the peer proved the code and then stopped sending |
| `ERR_NO_SPACE` | the declared size does not fit |
| `ERR_EXISTS` | could not land the file without destroying another |
| `ERR_NO_PEER` | join timed out having seen nobody |
| `ERR_NO_HANDSHAKE` | join timed out having seen peers that never confirmed |
| `ERR_ATTEMPT_CAP` | the drop was burned after N failed PAKE confirmations (§6) |

`ERR_ATTEMPT_CAP` is **specified here and thrown in W11.** It is not in
`engine/src/errors.js` yet, deliberately: there is nothing to count until
there is a PAKE confirmation to fail, and a code that nothing throws is a
code nothing tests. The name matches §6's own term ("attempt cap") and
the `ERR_NO_PEER` / `ERR_NO_HANDSHAKE` shape already in
`engine/src/errors.js:14-43`.

It is the one error in this table that means *someone was guessing*, and
the only one whose human-facing message should say so. Everything else
here is a fault; this one is a report.

---

## 11. Conformance (W12)

The spec is only worth what its test vectors are. Required for v2 to be
considered published:

- **Test vectors** for the code format, `topic` derivation, the CPace
  transcript, ISK derivation, and both confirmations — as fixed
  input/output pairs, independent of this implementation.
  `cli/test/cpace-vectors.test.js` is the first of these and covers the
  suite itself (the CFRG vectors, transcribed rather than computed). The
  Quay-specific ones — a code to a topic, a secret and nameplate to an
  ISK, an ISK to both confirmations — need W11's implementation to exist
  before they can be generated.
- **A conformance harness** that drives any implementation through the
  handshake, a normal transfer, a cancel, a resume and a streaming
  transfer, and checks the wire bytes.
- **Negative vectors**: reflected confirmation, replayed transcript,
  downgraded `caps`, oversize frame, chunk before manifest, `0x00` tag.
  A specification that only says what valid looks like has not said much.
