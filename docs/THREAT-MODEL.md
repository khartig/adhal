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
to needs a different tool. Adhal's relay (§8) is not built to hide it:
it is used only after a punch fails, and hyperdht's handshake, which
carries address fields to the peer, comes before any relay.

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
a race that measurably killed transfers. The cost is that a waiting
receiver emits a DHT record roughly every 4 seconds for as long as it
waits — a louder signature than one announce, and more opportunities for
a node near the topic to observe it.

How long that is, is bounded by the join timeout. By default a receiver
gives up after 30 s with no peer, about 8 announces, and a sender after
120 s, about 30 (`ADHAL_JOIN_TIMEOUT`; `joinTimeout()` in each swarm CLI).
Only a wait the user lengthens is long: with `ADHAL_JOIN_TIMEOUT=0`, which
waits indefinitely, a receiver left open for an hour announces about 900
times.

A back-off for such long waits would change nothing on the wire. It is
not worth doing on speculation, because the 4 s value was arrived at by
measurement: any back-off has to be measured as not costing reliability,
which is W14's kind of run.

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
| Anyone with the nameplate | Make hyperdht refuse to hole-punch, by reporting a randomized NAT to a side that has one too | Nothing to bound: a refusal does not end the drop. The CLI warns once (`double-randomized-nat`) and keeps waiting for a peer that can connect, until its join timeout (below). |
| Anyone with the nameplate | Hold connection slots without handshaking | A 15 s per-candidate deadline, and 5 s for a connection that never receives a packet (W15d), with 16 parallel dials rather than Hyperswarm's 3. Silent candidates are not counted. The receiver warns when they recur (W15c). |
| A peer with the code | Prove the code, then stall | `ERR_STALLED`: 30 s for the offer, 60 s without progress, and 5 min for a receiver's answer (PROTOCOL §4.4) |
| A peer with the code | Exhaust memory or disk | Frames capped at 1 MiB before buffering, 8 GiB per file by default, a free-space check before anything is opened, and backpressure in both directions (§6) |
| A Sybil DHT operator | Rotate identities to dodge per-source limits | Nothing yet: per-source and per-key budgets are deferred until W14's data shows the attack happens (Q-04). The warnings make it visible. |
| The network | Block the DHT | Nothing (§7) |

**A refused hole punch does not end a drop, by choice.** When both sides'
NATs are randomized, hyperdht refuses to punch
(`HOLEPUNCH_DOUBLE_RANDOMIZED_NATS`), and with no relay that pair cannot
connect. This is what happens with a VPN at both ends (0 of 80 trials,
2026-11-04). hyperdht already ends the refused attempt itself, so there
is nothing left to clean up. The question is whether the whole drop
should stop at the first refusal, and it does not:

- **The refused peer is unknown.** The refusal comes before any
  handshake, so before the code is proven, and the topic is visible to
  anyone watching the DHT once the receiver announces.
- **The NAT type is the peer's own claim.** hyperdht reads it from the
  peer's hole-punch payload, so a stranger needs no real VPN to cause a
  refusal, only a claim to have one.
- **So stopping would make a drop cheap to end.** Against anyone on a
  randomizing NAT, one dial with a false claim would end a drop that would
  otherwise connect to the real peer: one randomized NAT, against a
  consistent one, connected in 40 of 40 (2026-11-03). Today, ending a drop
  takes 100 failed guesses (§5.3).

The cost is accepted. A drop between two genuinely randomized NATs waits
out its join timeout, 30 s for the receiver and 120 s for the sender by
default. The warning appears at the first refusal, so the person can stop
sooner, and the timeout's `ERR_NO_PEER` says why, with the count as
`holepunchRefused` (`engine/src/swarm.js`, `onHolepunchRefused`). Ending
the drop early, or after a short grace period, was considered and
declined on 2026-11-05.

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

The relay is **experimental** (2026-11-12). `--relay=<key>` pairs through
a blind-relay the user names, only after a hole punch to the peer fails
(`relayOnlyAfterFailedPunch` in `engine/src/swarm.js`). These are the
constraints any relay must satisfy. They were recorded before one was
written, because a relay is the easiest way to destroy the one structural
advantage this design has over its competitors.

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
- Relay tokens carry **nothing from the drop code**, neither the
  nameplate nor the secret. Anything grindable back to the secret would
  make the relay operator the best-positioned code guesser in the system.
  This was written as "derived from the nameplate only"; hyperdht's relay
  path does better, with a fresh random 32-byte token per connection
  (`blind-relay` `token()`), so the constraint now says so.
- **Bounded use, by Adhal.** Adhal bounds its own use of a relay (gate
  5). Bandwidth and duration caps on the relay itself are the relay
  host's to set, not Adhal's. blind-relay 1.6.1 and Pear 3.6.0's
  `pear blind-relay` have none, and caps per token cannot work on their
  own, because every connection brings a fresh token (gate 3) and an
  abuser simply pairs again. Meaningful caps count per IP address or per
  credential, which lets the operator link a user's connections, so that
  trade is the operator's to make. [sluice](https://github.com/khartig/sluice) is a separate project, a
  relay host built on blind-relay for groups that want caps and run
  their own relay. Adhal stays relay-agnostic: it takes a relay's key,
  and works with any server that speaks blind-relay over hyperdht,
  Pear's own included. This constraint read "per-token bandwidth and
  duration caps" until 2026-11-18, when the caps moved to the relay host.

**Merge gates (Q-10).** The constraints above are only worth something if
they are enforced. The relay stays experimental, and outside what a
release claims, until each of these holds and a test shows it. Each
gate's status is as of 2026-11-12, except gates 1 to 3, which are as
of 2026-11-15, and gates 4 and 5, reworded on 2026-11-18:

1. A drop carried through the relay, with no Noise session underneath,
   completes, and a byte the relay alters fails authentication at that
   frame. That is `sealed-transfer.test.js`'s plain-TCP case, with the relay
   in the middle. **Met** (2026-11-15, the two `gate 1` tests in
   `cli/test/relay.test.js`). Two raw streams are paired through
   blind-relay's own server with blind-relay's pairing protocol, as
   hyperdht pairs them, but with no Noise secret stream started on them.
   The PAKE and a whole drop run over them and complete, and the relay,
   reading the frames as it forwards them, finds no file content, name,
   or digest. Then the relay alters one byte of the first CHUNK. The
   receive fails `ERR_PROTOCOL` (`failed to authenticate`) at frame 2, the
   altered one, after accepting the untouched MANIFEST before it. Nothing
   is written, and the sender hears the hang-up through the relay.
   blind-relay forwards inside udx-native, where JavaScript cannot touch
   a byte, so the test's relay replaces that forwarding with its own, as
   a relay operator who modified the server could
   (`cli/test-helpers/relay.js`). The CLIs' relayed drops still run under
   hyperdht's Noise, where an altered byte fails first. These tests show
   the channel alone would stop it.
2. A relay holding the nameplate and a valid token, but not the secret,
   cannot complete a handshake. Its attempt counts toward the cap like any
   other failed confirmation. **Met** (2026-11-15, the two `gate 2` tests
   in `cli/test/relay.test.js`). With no Noise underneath, the relay
   takes over both raw legs of a pair it matched on its own token, and
   runs the handshake itself with the nameplate and a guessed secret: as
   the sender toward the receiver, and as the receiver toward the sender.
   It completes neither. The receiver refuses its REPLY with
   `ERR_PAKE_CONFIRMATION`. The sender's REPLY gives the relay one offline
   test of its guess, which fails, so it has no valid CONFIRM to send and
   hangs up, which the swarm counts on the sender as
   `ERR_REPLY_UNANSWERED` (tested on its own in
   `security-properties.test.js`, Q-14). Under hyperdht, a relayed connection is a Noise
   session between its two peers, so a relay operator can try the
   handshake only as one of those peers. The second test is that peer: a
   guesser pairing through the relay with the receiver CLI, whose punch
   fails. The receiver reports one `candidate-dropped`, with
   `ERR_PAKE_CONFIRMATION` and `counted: true`, the same as any guess, and
   the real sender then completes the drop through the relay. A planted
   bug that stops the receiver counting a failed confirmation fails that
   test.
3. The relay token is independent of the drop code. A test shows that it
   is freshly random per connection, and that two connections for the
   same code get unrelated tokens, so nothing from the secret or the
   nameplate can enter it. **Met** (2026-11-15, the `gate 3` test in
   `cli/test/relay.test.js`). Two relayed drops run through the CLIs with
   one code. The relay records the token of every pairing, and a preload
   in each CLI (`cli/test-helpers/token-spy-preload.js`) records every
   call to `blind-relay`'s `token()`. Every pairing has its own token,
   each of the first drop's is more than 64 of 256 bits from each of the
   second's, and none contains the nameplate, the secret, or the code, or
   equals the topic. Every token the relay paired on was made by a
   `token()` call given no argument, so its bytes came from
   `randombytes_buf` alone (hyperdht 6.36.0 calls it in `lib/connect.js`
   and `lib/server.js`; blind-relay 1.6.1). A planted `token()` that
   returns one token for every connection fails the test. What the test
   cannot show is that a different hyperdht keeps doing this, so it pins
   the behavior for the versions in the lockfile.
4. Adhal gives a relay nothing worth keeping, and depends on nothing a
   relay keeps. What a relay stores is up to whoever runs it, so this
   gate is what Adhal can show. Everything it relays is sealed, with no
   file content, name, or digest legible to the relay (gate 1), and the
   token it pairs on carries nothing from the code (gate 3). A drop cut
   off at the relay resumes by re-pairing and re-hashing, as it does
   directly (§6, PROTOCOL §7), so nothing on the relay is ever needed or
   trusted. **Partly met:** gates 1 and 3 test the first half, and resume
   re-pairs and re-hashes on a direct path (`cli/test/resume.test.js`),
   but no test resumes a drop through a relay. A relay host that claims
   to keep nothing has to show it itself; keeping its counters in memory
   only is a design goal of [sluice](https://github.com/khartig/sluice). This gate read "the relay persists
   nothing about a drop beyond its per-token counters" until 2026-11-18.
5. Adhal bounds its own use of a relay. A relayed drop never carries
   more than its declared size: a sender that sends more is refused
   (`cli/test/verify.test.js`). A peer that stops mid-file is timed out
   (`cli/test/hardening.test.js`). The relay is used only after a failed
   punch (gate 6). The relay attempts per drop are capped. A relayed drop
   that loses its connection says so, and how to resume. **Open:** there
   is no cap on relay attempts per drop yet (one failed trial on
   2026-11-13 made 22), and no test of what a relayed drop cut off
   mid-transfer reports. Caps on the relay itself belong to the relay
   host (the constraint above). This gate read "the per-token bandwidth
   and duration caps are enforced" until 2026-11-18.
6. A drop that can connect directly does so, and the relay is not used.
   **Met:** with a relay at both ends and a punch that works, no session
   is opened with the relay (`cli/test/relay.test.js`). Hyperswarm's
   default would relay whenever this side's NAT is randomized, before any
   punch, so the engine passes it a function that offers the relay only
   on a retry after a punch-class failure.

**A peer can choose the relay, and that is accepted (2026-11-08).**
"Optional" holds for each side's own choice only. hyperdht pairs a
connection through a relay named in the peer's handshake payload, whether
or not this side turned relaying on, and it offers no hook to decline. The
peer is unauthenticated at that point, so anyone who finds the topic can
make a waiting peer connect to their relay. That relay's operator learns
the peer's IP address and connection times, which the stranger learns
anyway by dialing, and sees only end-to-end encrypted traffic. Someone
who would rather not can pass `--refuse-peer-relay`: the relay the peer
named is cleared from its handshake before hyperdht reads it, so this side
never contacts that relay (`refusePeerRelays` in `engine/src/swarm.js`,
tested in `cli/test/peer-relay.test.js`). It works around hyperdht, through
two internals that are not public API. The upstream change that would
replace it is in [`UPSTREAM-HYPERDHT.md`](UPSTREAM-HYPERDHT.md) §1.

The relay is Holepunch's own blind-relay, which hyperdht already speaks,
so the project writes and runs no relay server, on the grounds that the
best relay to operate is none. Anyone can run one, which is what keeps
it self-hostable.

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
  §7), and only if file-size confidentiality ever becomes a stated goal.
  It would be a protocol change: v2 has nowhere to carry padding, since
  every CHUNK byte counts toward the size and the digest, the manifest's
  fields are closed, and an unknown frame type is refused in every state
  ([`PROTOCOL.md`](PROTOCOL.md) §4.4). It would need a negotiated
  capability and a new message type.
- **No per-source or per-key throttling** (Q-04). A Sybil attacker rotating
  identities meets only the drop-wide cap (§5.4). Deferred until W14 shows
  whether the attack happens.
- **Dependency assurance has two gaps** (Q-08, closed). Dependencies are
  pinned exactly, advisories fail CI, and releases from 0.1.1 carry npm
  provenance, signed checksums, and an SBOM
  ([`DEPENDENCY-POLICY.md`](DEPENDENCY-POLICY.md)). But the scans run
  only when the code changes, so an advisory against an unchanged
  lockfile waits for the next push. And the prebuilt binaries in
  `sodium-native` and `udx-native` are trusted as npm serves them:
  nothing here checks how they were built. 0.1.0 has no provenance.
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
- **A waiting peer re-announces every 4 s**, for at most 30 s on the
  receiver and 120 s on the sender by default (§3.4).
