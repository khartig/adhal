# Quay wire protocol

**v1 — shipped, described in §9 for interoperability.**
**v2 — designed here, implemented in W11. Not yet on the wire.**

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
R -> S   HELLO   { version, caps, Ya }        receiver still writes first
S -> R   REPLY   { Yb, confirmS }             sender still reads first, writes on answering
R -> S   CONFIRM { confirmR }
```

Same three messages, same first-read and first-write points, so **no new
duplicate-resolution risk**. The third message is sent only after both
sides are already established.

### 3.2 Transcript and downgrade resistance

```
transcript = version || caps || nameplate || Ya || Yb
ISK        = CPace(secret, transcript)
confirmS   = MAC(ISK, "quay-v2:confirm-s" || transcript)
confirmR   = MAC(ISK, "quay-v2:confirm-r" || transcript)
```

`version` and `caps` are **inside the transcript**, so both are
authenticated by both confirmations. An attacker cannot strip a capability
or force an older version without both confirmations failing. Domain tags
`-s`/`-r` stop one direction's confirmation being reflected into the other.

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
k_r2s = HKDF(ISK, "quay-v2:r2s")
k_s2r = HKDF(ISK, "quay-v2:s2r")
```

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

v2 keeps the rule as an equation rather than two constants:

```
maxChunk = maxFrame - tagSize - aeadOverhead
```

---

## 6. Attempt cap

Count **PAKE confirmation failures only**. N = 100, exponential backoff.
On exhaustion, burn the drop and tell the human that someone was guessing.

**Never count dropped candidates.** Stale DHT announces routinely produce
dead candidates — measured in this repo, three were once enough to starve
every connection slot — and counting them would let the DHT's own garbage
burn a legitimate drop.

This reverses v1's rule that an attacker must not be able to end a drop by
connecting and failing. Under v2 a nameplate-holder can, after 100 failed
guesses. Accepted deliberately: the alternative is unlimited guessing
against ~31 bits, and a denial of service is a better failure than a silent
compromise. See [`THREAT-MODEL.md`](THREAT-MODEL.md) §5.3.

---

## 7. Resume, and the traps in it

Resume is the feature most likely to be implemented wrongly, because the
obvious design is wrong in three separate ways. All three must be settled
**before** the manifest format freezes, since two of them change it.

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

**This is the decision that must be made before the freeze**, because
`blockSize` and any block-hash field are manifest fields.

### 7.3 The displayed hash is integrity, not authenticity

Worth stating in the spec because resume makes it more tempting to
misread: a matching SHA-256 proves the bytes arrived as the sender
described them. It proves nothing about whether the sender was honest
about what it was sending.

---

## 8. Open decisions (W10)

These are costed in W10 and settled before W11 begins.

### 8.1 Which PAKE, and on what

**A correction to the premise this started from.** It was asserted that
"libsodium's ristretto primitives are already in your dependency tree via
`sodium-native`". That is **false**, verified by inspection:
`sodium-native@5.1.0` exposes **no** `crypto_core_ristretto255_*`
functions, and it is only a *transitive* dependency (via
`hypercore-crypto`) — never declared in any `package.json` here.

What `sodium-native` does expose, and what the decision must actually rest
on:

- ed25519 group arithmetic: `crypto_core_ed25519_from_uniform`,
  `crypto_scalarmult_ed25519_noclamp`, and the full scalar operations
- argon2id via `crypto_pwhash`

Candidates to cost:

1. A reviewed npm PAKE implementation.
2. libsodium **WASM**, which does expose ristretto255 — at the cost of a
   WASM blob and its load time.
3. **CPace over ed25519** using `sodium-native` promoted to a *direct*
   dependency, implemented against the published CFRG test vectors.

**Do not hand-roll without external review.** A PAKE implemented from the
paper and validated only against itself is worse than the HMAC proof it
replaces, because it looks stronger.

### 8.2 Protomux or raw stream

Adopting Protomux later is another wire break, so decide now. The question
is whether control and data share one stream: today `CANCEL` queues behind
already-written chunks, so a cancel is delayed by roughly one chunk plus
the high-water mark. A separate control channel fixes that.

### 8.3 Checkpoint frequency

An fsync per checkpoint is the cost. Too frequent wastes IO; too sparse
loses work on a crash. Needs measurement, not a guess.

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

v2 adds, at minimum, a code for attempt-cap exhaustion.

---

## 11. Conformance (W12)

The spec is only worth what its test vectors are. Required for v2 to be
considered published:

- **Test vectors** for the code format, `topic` derivation, the CPace
  transcript, ISK derivation, and both confirmations — as fixed
  input/output pairs, independent of this implementation.
- **A conformance harness** that drives any implementation through the
  handshake, a normal transfer, a cancel, a resume and a streaming
  transfer, and checks the wire bytes.
- **Negative vectors**: reflected confirmation, replayed transcript,
  downgraded `caps`, oversize frame, chunk before manifest, `0x00` tag.
  A specification that only says what valid looks like has not said much.
