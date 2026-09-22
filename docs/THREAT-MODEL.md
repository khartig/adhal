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
| **Active network attacker** | Can inject, drop and replay; can announce on any topic. |
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
[`ARCHITECTURE.md`](ARCHITECTURE.md)). The practical consequence is that
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

Packet sizes and timing. The transport is Noise-encrypted end to end
(and after W11, independently encrypted again under the PAKE session key),
so filenames, contents and hashes are not visible. **Length is not
hidden**: a 4.2 MB transfer looks like 4.2 MB on the wire. No padding, no
cover traffic. See §7.

### 3.4 Re-announce traffic

Both sides re-run their own DHT announce/lookup every 4 s by default
(`QUAY_REFRESH_INTERVAL`), because Hyperswarm's own 10-minute refresh loses
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

Today this is true *by accident*. `createSwarm` passes no `keyPair`, so
Hyperswarm generates a fresh one per process. Nothing declares that as a
requirement and nothing tests it, so any future change that adds a
persistent device identity — which is exactly what a "Keep this device"
feature wants — would silently make every drop by one user linkable by the
DHT nodes that see them, and would let a well-placed observer build a
social graph of who transfers with whom. That is a privacy property that
cannot be retrofitted once it is lost, because the linkage is in records
other people already hold.

So the accident is promoted to a stated invariant here, before the feature
that would break it is designed. If a long-term identity is ever added, it
is presented *inside* the authenticated channel, to the peer, after the
PAKE — never as the swarm keypair, and never to the DHT.

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
topic  = BLAKE2b("quay-v2:topic" || nameplate)     public, findable
secret -> PAKE                                     never hashed into anything public
```

The topic commits only to the nameplate. The secret is never hashed into
any public value, so there is nothing to grind offline: **every guess of
the secret costs one live protocol run** against a peer that is counting.

The code is *shorter* — five words instead of six — while being stronger,
because entropy no longer has to defend a public hash.

Shipped in W11: `engine/src/topic.js` derives the topic from the nameplate
alone, `engine/src/handshake.js` feeds the secret to CPace, and
`engine/src/proof.js` — v1's HMAC proof — is deleted. §5.1 is kept because
a v2 build still has to recognise a v1 peer and say so
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
against ~31 bits of secret, and a denial of service is a far better outcome
than a silent compromise. It is a chosen trade, not an oversight.

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
| Outrun the disk and grow memory without bound | `writeStream.write()`'s return value discarded | Honoured; the socket pauses |
| Prove, then send nothing, forever | No timer once the socket was handed over | `ERR_STALLED` on a manifest deadline and a no-progress deadline |
| Hold a connection slot without handshaking | Candidate sockets lived until the swarm died | 15 s per-candidate handshake deadline |

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
- **No defence against a Sybil DHT operator.** Someone running many nodes
  across the keyspace sees a large share of announces: topics, IPs, timing.
  They still cannot read content or join a drop without the code, but they
  can observe that a drop happened, between which addresses, and when.
- **No protection against a compromised endpoint.** Malware on either
  machine reads the file and the code.
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
  identity. Traffic through it is already encrypted under the PAKE
  session key, which is why W9 moves channel binding off the transport's
  Noise keys — a relayed connection has to be exactly as safe as a direct
  one, and that cannot be true if security depends on which transport
  carried the bytes.
- **Cannot join a drop without the code.**
- Relay tokens derive from the **nameplate only** — never from anything
  grindable back to the secret. Otherwise the relay operator becomes the
  best-positioned code guesser in the system.
- Per-token bandwidth and duration caps.

Holepunch's own blind-relay is worth investigating first, on the grounds
that the best relay to operate is none.

This is also the basis for the "we are not a host of user content"
argument: a relay is a pipe, not storage.

---

## 9. Known gaps

Recorded rather than quietly carried.

- **The v2 protocol is designed, not built.** Until W11 lands, §5.1 is the
  live situation: the topic commits to the whole code and is grindable
  offline.
- **No rate limiting on proof failures today.** The v1 rule is that a
  failed candidate is discarded and the drop continues, which is correct
  for v1 (where the code cannot be usefully guessed online) and is
  replaced by the §5.3 cap in v2.
- **The ephemeral-key invariant is documented but not tested.** It holds
  because Hyperswarm's default does the right thing. A test should assert
  that two drops from one process announce different public keys.
- **`hashFile` reads the file a second time.** `stat`, hash and read are
  three separate reads of a file nothing stops changing underneath them.
  The send path caps and asserts the length, so a changed file fails
  loudly rather than silently — but the hash describes the file as of the
  hashing pass, not as of the send.
- **Windows is unverified.** CI runs it advisory-only. Several Stage 0
  mechanisms (`link`-based publish, `O_EXCL`, SIGTERM handling) have
  platform-specific behaviour that has not been exercised on a real
  Windows machine.
