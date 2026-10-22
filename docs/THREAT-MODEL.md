# Threat model

What this tool protects, what it leaks, and what it does not try to do.

This document exists *before* the v2 protocol freezes, because it is what
the protocol has to be designed against. Writing it afterwards would mean
justifying whatever was built.

Terms used throughout: **D1-D7** are the steps of the data path, **W1-Wn**
are the work items in [`IMPLEMENTATION-PLAN.md`](IMPLEMENTATION-PLAN.md).
There is no "item N" anywhere — that numbering collided with the data-path
steps and has already produced one documented error.

---

## 1. What the tool is for

Two people who can talk to each other by some other channel — in person, a
phone call, a chat window — want to move a file directly between their
machines, without an account and without the bytes resting on anyone's
server.

The **drop code** is the entire secret. It is generated, shown to one
human, carried to the other by that out-of-band channel, and typed or
scanned. Everything else is derived from it.

---

## 2. Who is in the model

| Adversary | Capability assumed |
| --- | --- |
| **Passive network observer** | Sees packets between the two peers, and to/from the DHT. |
| **DHT node near the topic** | Answers lookups for that topic; sees who announces and who asks. |
| **Active network attacker** | Can inject, drop, and replay; can announce on any topic. |
| **Code guesser** | Has the topic (it is public) and wants the code. |
| **A peer who has the code** | Proved the handshake, and is hostile anyway. |
| **Relay operator** (when a relay is used at all) | Sees and can withhold whatever passes through it. |

The fifth row is the one most often skipped, and it is the one Stage 0 is
mostly about. See §6.

---

## 3. What is exposed, precisely

### 3.1 To DHT nodes near the topic

A receiver has to **announce** its topic to be findable. That announcement
is a record on the DHT nodes closest to the topic, and it carries:

- the **topic** (32 bytes)
- the announcing node's **public key** — today an ephemeral per-process
  key (§4)
- the announcing node's **source IP and port**, because a DHT record that
  did not say how to reach you would be useless
- **timing**: when the drop started, how long it stayed up, how often it
  re-announced

**Both peers announce, so the sender is exposed too.** Both sides join with
`server: true, client: true` — that is not an accident, it is load-bearing
(splitting the roles broke connection establishment outright; see
[`history/ENGINEERING-LOG.md`](history/ENGINEERING-LOG.md)). The practical consequence is that
"the receiver is visible and the sender is anonymous" is false, and any
description of the tool that implies it is wrong.

**The honest scope of this.** A topic is readable by *nodes near that
topic* — not by "anyone walking the DHT". Kademlia routing means a lookup
for an unrelated topic never touches these records. To observe a specific
drop you must either be near its topic already, or have the code (and thus
the topic) in advance. To observe drops *in general* you must operate many
nodes spread across the keyspace, which is the Sybil case in §7.

That is a materially weaker exposure than "public", and it is still enough
to justify everything below. Overstating it would make the rest of this
document less believable, not more.

### 3.2 To the peer, once connected

Each peer learns the other's **IP address**. Hole punching is the
mechanism: the whole point is getting two machines to send packets
directly to each other.

There is no version of direct peer-to-peer transfer where this is not
true. A user who must not reveal their IP to the person they are sending
to needs a relay (§8) or a different tool.

### 3.3 To a passive observer on the path

Packet sizes and timing. The transport is Noise-encrypted end to end,
and since W11 every frame is independently sealed again under keys from
the PAKE ([`PROTOCOL.md`](PROTOCOL.md) §3.4), so filenames, contents, and
hashes are not visible. **Length is not
hidden**: a 4.2 MB transfer looks like 4.2 MB on the wire. No padding, no
cover traffic. See §7.

### 3.4 Re-announce traffic

Both sides re-run their own DHT announce/lookup every 4 s by default
(`ADHAL_REFRESH_INTERVAL`), because Hyperswarm's own 10-minute refresh loses
a race that measurably killed transfers. The cost is that an idle receiver
showing a QR code emits a DHT record roughly every 4 seconds for as long
as it waits — a louder, longer-lived signature than one announce, and more
opportunities for a node near the topic to observe it. A receiver left open
for an hour has announced ~900 times.

Worth revisiting when the drop code becomes short-lived; not worth changing
on speculation, because the 4 s value was arrived at by measurement.

---

## 4. The key hierarchy, and the invariant it depends on

```
Per-drop ephemeral transport keypair   <- ROOT. Never persisted, never reused.
`-- Drop secret  (nameplate | PAKE secret)
    `-- PAKE session key (ISK)
        `-- AEAD channel keys (directional send/recv)

Long-term identity (optional, "Keep this device")
        ^ presented ONLY inside the authenticated channel.
          Never the drop swarm keypair. Never visible to the DHT.
```

**The invariant: the keypair a drop announces to the DHT is generated for
that drop and discarded with it.**

Until W15b this was true *by accident*: `createSwarm` passed no `keyPair`,
so Hyperswarm generated a fresh one per swarm, and nothing declared or
tested that. Any change that added a persistent device identity — which is
exactly what a "Keep this device" feature wants — would have silently made
every drop by one user linkable by the DHT nodes that see them, and let a
well-placed observer build a social graph of who transfers with whom. That
is a privacy property that cannot be retrofitted once it is lost, because
the linkage is in records other people already hold.

It is now enforced in code (W15b, Q-12). `createSwarm` generates the
announce keypair itself, for every swarm, and throws if a caller passes
one. `cli/test/announce-key.test.js` checks that two drops from one
process are seen by their peer under different keys, on a real DHT.

The rule that follows: if a long-term identity is ever added, it is
presented *inside* the authenticated channel, to the peer, after the PAKE
— never as the swarm keypair, and never to the DHT.

This is also the single privacy property a trusted-device product cannot
copy without abandoning its own design.

---

## 5. What the drop code protects, and what it cannot

### 5.1 v1, as shipped until W11

```
topic = hash(code || app-salt)      announced publicly
key   = HKDF(code, ...)             proves the peer knows the code
```

Both derived from the *whole* code, and the topic is public. So an attacker
who scraped a topic could **grind candidate codes offline**: hash each
guess, compare to the topic, no network round trip and no rate limit. ~62
bits of code was what stood between them and the drop key.

62 bits is a lot. But the structure was wrong: it spent the code's entropy
on defending a public value, and it got weaker the moment anyone wanted a
shorter code.

### 5.2 v2, implemented in W11

```
code   = nameplate(2 words) + secret(3 words)
topic  = BLAKE2b(lv_cat("adhal-v2:topic", nameplate))   public, findable
secret -> PAKE                                         never hashed into anything public
```

The topic commits only to the nameplate. The secret is never hashed into
any public value, so there is nothing to grind offline: **every guess of
the secret costs one live protocol run** against a peer that is counting.

The code is *shorter* — five words instead of six — while being stronger,
because entropy no longer has to defend a public hash.

**What each half is worth (W15a, Q-14).** The words come from the EFF
large wordlist, vendored with its source's SHA-256 in
`engine/src/wordlist.js`: 7,772 words, the list's 7,776 less its four
hyphenated entries, so each word carries about 12.92 bits.

- **The secret, three words: ~38.8 bits.** Against the 100-attempt cap of
  §5.3, a guesser's chance of taking one drop is at most
  100 / 7772³ ≈ 2.1 × 10⁻¹⁰.
- **The nameplate, two words: ~25.8 bits.** It is not secret, and its size
  sets only how often two live drops share a topic: a 50% chance of a
  collision somewhere at about 9,150 concurrent drops. A collision leaks
  nothing. Each side's peers fail the other's confirmation, and those
  failures count toward each drop's cap.

An opaque code, one that is not in the five-word format, has no nameplate
to separate from its secret, so its topic is grindable offline. It is off
unless `--insecure-opaque-code` or `ADHAL_INSECURE_OPAQUE_CODE=1` names it
(W15b, Q-15).

Shipped in W11: `engine/src/topic.js` derives the topic from the nameplate
alone, `engine/src/handshake.js` feeds the secret to CPace, and
`engine/src/proof.js` — v1's HMAC proof — is deleted. §5.1 is kept because
a v2 build still has to recognize a v1 peer and say so
([`PROTOCOL.md`](PROTOCOL.md) §9), and because the reasoning is what
justifies the break.

### 5.3 The attempt cap, and the trade it makes

Online guessing is answered by counting failures: N=100 PAKE confirmation
failures with exponential backoff, then the drop is burned and the human is
told someone was guessing. Implemented in W11
(`engine/src/attempts.js`, `ERR_ATTEMPT_CAP`).

The backoff is applied as a **delay before answering**, not as a refusal to
talk. That distinction matters: declining new candidates during a backoff
window would discard the legitimate peer along with the guesser, and the
legitimate peer is the one that cannot retry a thousand times. A guess
needs our next message, so delaying it is what makes guessing cost
wall-clock time.

**Only PAKE confirmation failures are counted — never dropped candidates.**
This repo has measured evidence that stale DHT announces routinely produce
dead candidates; three were once enough to starve every connection slot.
Counting those would let the DHT's own garbage burn a legitimate drop.

**This reverses an earlier rule, deliberately.** The v1 code said an
attacker "must not be able to end a drop just by connecting to it and
failing". Under v2 a nameplate-holder *can* end a drop, after 100 failed
guesses. That is accepted because the alternative is unlimited guessing
against ~38.8 bits of secret, and a denial of service is a far better outcome
than a silent compromise. It is a chosen trade, not an oversight.

### 5.4 Denial of service: what is bounded, and what is accepted

A drop is not built to survive someone determined to stop it. What it is
built for is that stopping it costs that someone something, and that the
human is told.

| Who | What they can do | What bounds it |
| --- | --- | --- |
| Anyone with the nameplate | Burn the drop with 100 wrong guesses | Exponential backoff makes it take wall-clock time, and the human is told someone was guessing (§5.3). Accepted. |
| Anyone with the nameplate | Hold connection slots without handshaking | A 15 s per-candidate deadline, and 5 s for a connection that never receives a packet (W15d), with 16 parallel dials rather than Hyperswarm's 3. Silent candidates are not counted. The receiver warns when they recur (W15c). |
| A peer with the code | Prove the code, then stall | `ERR_STALLED`: 30 s for the offer, 60 s without progress, and 5 min for a receiver's answer (PROTOCOL §4.4) |
| A peer with the code | Exhaust memory or disk | Frames capped at 1 MiB before buffering, 8 GiB per file by default, a free-space check before anything is opened, and backpressure in both directions (§6) |
| A Sybil DHT operator | Rotate identities to dodge per-source limits | Nothing yet: per-source and per-key budgets are deferred until W14's data shows the attack happens (Q-04). The warnings make it visible. |
| The network | Block the DHT | Nothing (§7) |

---

## 6. A peer that knows the code is not a peer you can trust

The handshake answers exactly one question: *is this the peer the human
meant?* It says nothing about whether that peer is well-behaved. A code can
be shoulder-surfed, screenshotted, forwarded to the wrong chat, or given to
someone for a different file than the one they send.

Everything in this section was reachable by a proven peer before Stage 0,
and is covered by tests in `cli/test/hardening.test.js`.

| Attack | Before | Now |
| --- | --- | --- |
| Overwrite `~/.zshrc`, `package.json`, `id_rsa` | `fs.rename` overwrote; output dir defaults to `process.cwd()` | Never replaces a file it did not create; lands `name (1)` instead. `--replace` opts back in |
| Redirect the write via a planted `<name>.part` symlink | `createWriteStream` followed it | Partial opened `O_CREAT\|O_EXCL`, which refuses symlinks |
| Forge a log line, clear the terminal, spoof a filename with RLO | Names printed and written raw | Control and bidi characters refused; everything printed through `displayName()` |
| NTFS alternate data stream (`foo:stream`) | Written as given | `<>:"\|?*` transformed, on every platform |
| Invisible trailing dot/space (`a.exe. ` vs `a.exe`) | Written as given | Stripped |
| Declare 9 PB and exhaust the disk | No cap by default; both CLIs passed none | 8 GiB default cap, explicit `null` to opt out, plus a free-space check before anything opens |
| Outrun the disk and grow memory without bound | `writeStream.write()`'s return value discarded | Honored; the socket pauses |
| Prove, then send nothing, forever | No timer once the socket was handed over | `ERR_STALLED` on a manifest deadline and a no-progress deadline |
| Hold a connection slot without handshaking | Candidate sockets lived until the swarm died | 15 s per-candidate handshake deadline |
| Deliver a file the receiver never agreed to | Both CLIs accepted any valid offer | Both receiver CLIs show the name, size, digest, and any resume, and ask (W15c, Q-02). `--yes` skips the question; with no terminal and no `--yes` the offer is declined. A name that would run when opened — an executable, a script, an installer, an archive, a double extension such as `.pdf.exe` — is warned about even with `--yes` |
| Lift the code from shell history or `ps` | Codes were taken on the command line | A code on argv is refused unless `--code-on-argv` says so; the prompt and stdin are the normal paths (W15c, Q-17) |
| Race the intended peer with a forwarded or overheard code | First handshake won silently; the loser timed out with no reason and the winner's human never knew | Still first-handshake-wins, but a late peer that proves the code is told `ERR_DROP_TAKEN`, and the side that paired reports that someone else holds the code (PROTOCOL.md §4.0, W15a). Guesses during the transfer still count toward the attempt cap |

**Resume, and the `.part` it reopens (W11).** An interrupted transfer
leaves `<name>.part`, and a later offer of the same name may continue from
it ([`PROTOCOL.md`](PROTOCOL.md) §7). The partial is a predictable name in
a directory other things can write to, so it is not trusted:

- It is reopened with `O_NOFOLLOW`, so a planted symlink fails to open
  rather than redirecting the write (`O_EXCL` gives a fresh partial the
  same protection).
- It must have exactly one link, because a planted hard link to a file
  elsewhere on the volume is a regular file and only its link count gives
  it away.
- It must be no longer than the offer, and it is re-hashed before
  anything is proposed.
- The sender proves the prefix before any byte is sent. It sends PREFIX,
  the SHA-256 of its own first *n* bytes, and the receiver compares that
  against what it holds. A mismatch truncates the partial to nothing, and
  the transfer starts over. Nothing derived from the receiver's partial is
  ever sent.

Two things remain, and both are stated in PROTOCOL §7.5. First, whether
the receiver resumed or restarted tells the sender **one bit** per
session: whether the partial matched the sender's bytes. That costs a full
PAKE per guess and a partial under the same name, and it was already
observable at a higher price. Second, a peer with the code can make the
receiver discard a same-named partial. A partial is only ever discarded,
never published.

**Still true, and not fixable here:** a peer who knows the code can send you
*any file*. The displayed SHA-256 proves the bytes arrived intact; it
proves nothing about whether the sender was honest. Integrity is not
authenticity of intent.

---

## 7. Explicit non-goals

Stating these plainly is more useful than a hedge, because each one is
something a reasonable person might assume.

- **Not anonymity.** Peers learn each other's IPs. DHT nodes near a topic
  learn the announcer's IP. This is not Tor and must never be described as
  private in that sense.
- **No traffic-analysis resistance.** Transfer size and timing are
  visible to anyone on the path. No padding, no cover traffic, no constant
  rate.
- **No defense against a Sybil DHT operator.** Someone running many nodes
  across the keyspace sees a large share of announces: topics, IPs, timing.
  They still cannot read content or join a drop without the code, but they
  can observe that a drop happened, between which addresses, and when.
- **No protection against a compromised endpoint.** Malware on either
  machine reads the file and the code.
- **No guarantee that secrets leave memory.** The code, the PAKE's
  intermediates, and the channel keys live in a Node.js process, which
  cannot reliably erase memory. As a best effort (W15b, Q-18), the
  handshake zeroes its private scalar, K, the ISK, the MAC key, and the
  password bytes as soon as it is done with them, and each transfer zeroes
  its channel keys when it ends. The code itself is a JavaScript string and
  cannot be wiped, and copies made inside the crypto libraries are out of
  reach. So a core dump or swapped page taken during or shortly after a
  drop may contain them. On a machine where that matters, disable core
  dumps (`ulimit -c 0`) and use encrypted swap. Once the drop has closed,
  the code is spent in any case.
- **No protection against the human you sent the code to.** They are the
  intended recipient. If they are not, that is a code-handling failure,
  and it is why the code should be carried over a channel appropriate to
  what is being sent.
- **No forward secrecy for the code itself.** A code that leaks *while the
  drop is open* compromises that drop. Codes are single-use and the drop
  closes; there is no long-term key whose compromise reaches backwards.
- **Not censorship-resistant.** A network that blocks the DHT bootstrap
  nodes blocks discovery.

---

## 8. The relay boundary

There is no relay today. These are the constraints any relay must satisfy,
recorded before one is written, because a relay is the easiest way to
destroy the one structural advantage this design has over its competitors.

**Frozen constraints:**

- **Optional.** Never in the default path when a direct connection works.
- **Self-hostable**, with a documented protocol, so "use someone else's
  relay" is always available.
- Sees: two connection times, approximate byte counts, two IPs.
- Does **not** see: filenames, plaintext, hashes, or any long-term
  identity. Traffic through it is already sealed under keys from the
  PAKE, which is why v2 binds the channel to the PAKE transcript rather
  than to the transport's Noise keys (W11, [`PROTOCOL.md`](PROTOCOL.md)
  §3.3). A relayed connection has to be exactly as safe as a direct one,
  and that cannot be true if security depends on which transport carried
  the bytes.
- **Cannot join a drop without the code.**
- Relay tokens derive from the **nameplate only** — never from anything
  grindable back to the secret. Otherwise the relay operator becomes the
  best-positioned code guesser in the system.
- Per-token bandwidth and duration caps.

**Merge gates (Q-10).** The constraints above are only worth something if
they are enforced, so relay code merges only when each of these holds and
a test shows it:

1. A drop carried through the relay, with no Noise session underneath,
   completes, and a byte the relay alters fails authentication at that
   frame. That is `sealed-transfer.test.js`'s plain-TCP case, with the relay
   in the middle.
2. A relay holding the nameplate and a valid token, but not the secret,
   cannot complete a handshake. Its attempt counts toward the cap like any
   other failed confirmation.
3. The relay token is derived from the nameplate alone. A test shows the
   derivation's inputs, so that nothing from the secret can enter them.
4. The relay persists nothing about a drop beyond its per-token counters.
   Resume through a relay re-pairs and re-hashes, exactly as it does
   directly; that half is already met (§6, PROTOCOL §7).
5. The per-token bandwidth and duration caps are enforced.
6. A drop that can connect directly does so, and the relay is not used.

Holepunch's own blind-relay is worth investigating first, on the grounds
that the best relay to operate is none.

This is also the basis for the "we are not a host of user content"
argument: a relay is a pipe, not storage.

---

## 9. Known gaps

As of W16. Each one names the work item that would close it, or says why
it stays open.

- **Windows is not supported for security purposes** (Q-07, until Stage
  3). It has no `O_NOFOLLOW`, so reopening a partial falls back to an
  `lstat`, which races. Its `link`-based publish and its signal handling
  have not been exercised on a real Windows machine, and CI runs it
  advisory-only.
- **No independent review** of the cryptographic composition (Q-05). It
  comes after the wire format is frozen (W17), against the claims in
  [`PROTOCOL.md`](PROTOCOL.md) §12. The review that produced W15 was
  AI-assisted ([`SECURITY-REVIEW.md`](SECURITY-REVIEW.md)).
- **No traffic-analysis resistance** (Q-09). There is no padding (§3.3,
  §7). That is post-freeze, and only if file-size confidentiality ever
  becomes a stated goal.
- **No per-source or per-key throttling** (Q-04). A Sybil attacker rotating
  identities meets only the drop-wide cap (§5.4). Deferred until W14 shows
  whether the attack happens.
- **Releases are not signed** (Q-08). Every dependency is pinned exactly,
  advisories fail CI ([`DEPENDENCY-POLICY.md`](DEPENDENCY-POLICY.md)), and
  each GitHub Release carries a CycloneDX SBOM. But neither npm package
  has a provenance attestation, and there are no signed checksums. Due
  with the next npm publish.
- **Publishing without hard links races** (Q-19). On a filesystem with no
  `link()`, publishing falls back to check-then-rename, and a local process
  that creates the destination in that gap has it replaced. The receiver
  says when it used the fallback.
- **Memory is cleared on a best-effort basis only** (Q-18; §7).
- **A file edited in place while it is sent** is caught only by the
  receiver's digest check (Q-16). It fails closed, and nothing short of a
  private copy would prevent it.
- **A code has to come from somewhere.** With `--code-on-argv` it is in
  shell history. A code piped on stdin needs `--yes` as well, because the
  prompt needs a terminal and stdin is not one (W15c).
- **Two peers behind one address pair slowly at times.** hyperdht can
  report a connection open whose far end it has discarded. The engine
  drops such a connection after 5 s, but a pairing can still take tens of
  seconds (W15d; `UNANSWERED_CONNECTION_MS` in `engine/src/swarm.js`).
  This is availability, not security, and the fix belongs upstream.
- **An idle receiver re-announces every 4 s** (§3.4).
