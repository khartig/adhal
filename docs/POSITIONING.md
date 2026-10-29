# Positioning

Where Adhal stands against other tools that move files between two
machines, what it can own that they cannot easily copy, and how that will
be tested rather than asserted. The roadmap
([`IMPLEMENTATION-PLAN.md`](IMPLEMENTATION-PLAN.md)) says what is being
built; this says why those choices matter against the alternatives.

**Provenance, stated first because it sets how much weight this
deserves.** Everything here about other tools comes from their own READMEs,
as summarized in September 2026: in the review of 2026-09-18
([`history/REVIEW-SECURITY-AND-POSITIONING.md`](history/REVIEW-SECURITY-AND-POSITIONING.md))
and in the plan's competitor section, which corrected it a week later.
The Hushdrop profile is from its sites and READMEs, read on 2026-10-10.
The magic-wormhole and croc profiles and §2a are weaker still: general
knowledge, not even a README read. Nobody here has run any of these tools, read their source, or measured
them. **Treat every claim about another tool as a claim to verify, not a
fact.** §4 is how they will be verified.

---

## 1. What Adhal can own

"Defensible" means another tool cannot match it without giving up a
design decision it has already built on. Ranked by how defensible each
one is.

**1. Serverless-by-default rendezvous.** Discovery is the DHT, so no
operator-run infrastructure is needed to find a peer. A relay is an
opt-in plug-in, never in the default path when a direct connection works.
Iroh-based designs route discovery and the first hop through relay servers
by design (n0's by default), so matching this would mean unbuilding that.
It is the one structural difference, and the easiest to lose: a relay that
is hosted and on by default would make Adhal an Iroh-shaped product with a
smaller relay fleet. That is why the relay's constraints and merge gates
are fixed before any relay code exists
([`THREAT-MODEL.md`](THREAT-MODEL.md) §8). Holepunch's own blind-relay is
worth investigating first, so that the project runs nothing.

**2. Protocol-first.** A published, versioned specification with test
vectors and a conformance suite ([`PROTOCOL.md`](PROTOCOL.md),
[`CONFORMANCE.md`](CONFORMANCE.md)). The tools compared below are
applications that happen to contain an engine. A specification is what lets other clients exist (Rust, Go,
Swift, a browser), and so what lets a one-person project outlive its
author. The natural comparator is **magic-wormhole** (§2): a
PAKE-protected code, a mature CLI, a published protocol with several
implementations, and a mailbox server it needs. "Wormhole without the
server" is a sentence people already understand.

**3. Ephemeral-by-construction privacy.** No accounts, no persistent
identity, per-drop keys, nothing linking two drops
([`THREAT-MODEL.md`](THREAT-MODEL.md) §4; enforced since W15b). A product
built around trusted, paired devices cannot offer this, because its feature
*is* the persistent identity. It cannot be retrofitted once linkage exists
in records other people hold. Be honest about its limits: DHT nodes still
see the topic and IP addresses, and Adhal is not anonymous. An opt-in
relay-only mode that hides each side's IP from the other would extend it,
and none of the tools below headlines that.

**4. Streaming and scripting.** A blob-addressed design has to hash a file
before it can address it, so it cannot send a stream of unknown length.
A framed stream with a trailing digest can:
`tar c dir | ad-hal-send <code> -` works, and so does
`ad-hal-receive --stdout | tar x`, with stable `--json` events built on
the error codes ([`CLI-CONTRACT.md`](CLI-CONTRACT.md); W13). That
serves developers, CI, headless servers, and machines without SSH, which
GUI-first tools ignore, and it lands naturally on macOS and Linux first.

**5. Published, reproducible reliability numbers.** "Lead with
reliability" is a position only if it is evidence, so every rate is
stated with an honest bound. The first measurement, 10 of 10 on one path
(Starlink CGNAT to Comcast), gives a 95% one-sided lower bound of 74.1%,
not "100%". Two runs of 40 trials with `scratch-trials.js` followed on the
same pair of networks, 20 in each direction ([`trials/`](trials/), one
`ENVIRONMENT.md` per run). On 2026-10-13 the senders completed 38 of 40
and the receivers 39 of 40: one direction was 20/20 on both sides, and
both failures were in the other. On 2026-10-15, at `8bc808a`, in the run
that gated the wire freeze (W17), both directions were 20/20 on both
sides: 40 of 40, which gives a lower bound of 92.8%. That is still one
pair of networks. §4 turns it into a public scoreboard. If Adhal loses,
that is the most valuable early finding available. If it wins, it is the
case for using it.

### Do not fight on

- **A polished GUI race.** It cannot be won by one person against a
  funded team.
- **Browser receive.** It needs a hosted bridge, which contradicts #1, and
  it is DashBeam's growth engine.
- **Trusted-device auto-accept.** It contradicts #3.
- **Content-addressed multi-file sharing.** That is the other design.
- **Two devices in the same room.** The built-in share sheets (§2a) are
  preinstalled, need no code, and work with no internet connection. Adhal
  has no LAN discovery yet, and even with it, "install this on both
  phones first" loses to a button that is already there.
- **Public, one-to-many distribution.** BitTorrent and IPFS (§2a) serve a
  file to anyone who asks, for as long as someone seeds it. A one-time,
  one-recipient drop is the opposite promise.

---

## 2. The tools compared

| | magic-wormhole | MeshDrop | DashBeam | Adhal today |
|---|---|---|---|---|
| Stack | Python (Twisted); SPAKE2 PAKE, NaCl SecretBox | Hyperswarm + Hyperbee, Noise | Iroh (QUIC/TLS 1.3, BLAKE3 blobs) | Hyperswarm, Noise underneath; its own sealed channel keyed by a PAKE (v2) |
| Codes | A number nameplate + two words (`7-guitarist-revenge`); SPAKE2; a wrong guess ends the exchange | `MD-` pair codes, single-use `DROP-` codes, HMAC challenge-response | Tickets, links, QR, pairing and verification codes | Five words (public nameplate + secret) and QR; CPace PAKE; an attempt cap; a late peer is told the drop is taken |
| Discovery | A mailbox (rendezvous) server, the project's by default; a direct path is tried, with a transit relay as the fallback | mDNS + DHT + TCP relay | mDNS, relays (self-hostable) | DHT only. LAN discovery and an optional relay are planned (Stage 3) |
| Resume | Not known to | Yes | Yes (BLAKE3) | Yes: the prefix is proven by the sender before it is resumed (W11) |
| Approval gate | Yes: the receiver confirms before a file is written | Yes | Yes, plus trusted auto-accept | Yes: in the engine (W11), and a prompt in the CLI (W15c) |
| Platforms | CLI wherever Python runs; Go and Rust implementations, and apps built on them | Windows / macOS / Linux / Android | Windows / macOS / Linux / Android / CLI / web | CLI on macOS and Linux; Windows not supported for security purposes yet |
| Version / traction | MIT, long established and widely used; version and stars not checked | v1.0.14, ~1 star, MIT | v0.7.1, ~9.6k stars, AGPL-3.0 | 0.1.0, unreleased |

The magic-wormhole column is general knowledge, like its profile below,
not a README read.

**magic-wormhole** is the main competitor for the position in §1: the
tool people already reach for when they want a short spoken code instead
of an account or a cloud link, and the one most likely to be named in the
first reply to any announcement of Adhal. As understood: two sides that
share a code such as `7-guitarist-revenge` meet at a mailbox server, run
SPAKE2 over it to agree a key, and then try a direct connection, falling
back to a transit relay. The number is a public channel on the mailbox,
and the words are the secret. A wrong guess ends the exchange, so an
attacker gets one guess per code. The receiver confirms before a file is
written, and directories are sent as an archive. The protocol is
documented and has independent implementations (wormhole-william in Go,
magic-wormhole.rs in Rust), which is the protocol-first position of §1 #2
already taken, by a mature project. What Adhal can claim against it is
§1 #1: the mailbox server is required for every transfer, even when the
direct path works, and whoever runs it sees who met whom and when. Adhal's
DHT nodes see a topic and IP addresses too (§1, #3), so the difference is
an operator, not anonymity. It is a W14 comparison target. To verify: the
code format and its entropy, the one-guess rule, whether resume or a piped
input is supported, what the mailbox and transit relay log, how often the
default servers have been unavailable, and the current release and
platforms.

**MeshDrop, corrected.** An earlier plan called it "Android only",
"fragile", and "a tiny same-stack competitor, not the market". Per its own
README it ships on four platforms with a relay, resume, and an approval
gate, and its drop-code design is close to Adhal's data path. "Not the
market" is true of *traction* and false of *feature parity*. On features
it was ahead of Adhal when this was written, and on platforms and
discovery it still is. Whether it is fragile is unknown, and is what §4
measures.

**DashBeam** is a different kind of tool: real traction, Iroh's mature
relay and path-migration story, and a browser client. Not something to
compete with on those.

**croc** is probably the closest comparator for the developer and
scripting position (§1, #4), and was missing from the earlier review. This
profile is from general knowledge, not even a README read, so it is
weaker than the two above. As understood: a Go CLI, MIT-licensed and
widely used, that pairs two sides with a PAKE-protected code, resumes
interrupted transfers, accepts piped input, and runs on every desktop OS.
Both sides meet at a relay, a public one run by its author by default or a
self-hosted one, and the data appears to travel through that relay rather
than over a punched direct path. If that holds, croc is the cleanest
statement of the contrast in §1 #1: the same user experience, with a
server in the middle of every transfer. It is also the tool most likely to
make a CLI user ask why Adhal needs to exist, so it is a strong candidate
for the W14 comparison. To verify: the code format, whether a direct path
is ever attempted, what the relay can observe, and whether the default
relay's availability has been a problem in practice. Its contrast with
magic-wormhole matters too: if croc's data always crosses the relay and
magic-wormhole's usually does not, they are two different points on the
same line, and Adhal is the end of it.

**Hushdrop** is two unrelated projects that share a name, both read from
their sites and READMEs on 2026-10-10 and neither run. Neither is
peer-to-peer. Both encrypt in the browser and leave the ciphertext on a
server for the recipient to fetch. That makes them the "upload it
somewhere encrypted" alternative, the default many people reach for when
the recipient is not nearby.

- **hushdrop.dev** ([maxtechera/hushdrop](https://github.com/maxtechera/hushdrop),
  MIT, about 8 stars) is a link-sharing tool for output from AI agents:
  HTML, Markdown, PDFs, and static sites, published from a CLI
  (`npx hushdrop`), an MCP server, or a Claude Code plugin. A locked drop is
  encrypted in the browser with StatiCrypt (AES-256; no mode or KDF is
  stated) behind a password, and the ciphertext is stored in Vercel Blob.
  Its tiers are anonymous (24-hour links, 512 KB), a free account, and
  self-hosting. It offers burn-after-read and expiry. A raw file uploaded
  without a password page is protected only by an unguessable URL. Its own
  security page says locked ciphertext "is downloadable, so use long
  passwords" and calls it "strong against casual access, not a vault".
- **hushdrop.vercel.app** ([zaidmukaddam/hushdrop](https://github.com/zaidmukaddam/hushdrop),
  no license shown, one commit) is a burn-after-reading secret sharer: a
  Next.js app that encrypts text with a password in the browser, stores
  the ciphertext in Redis, and deletes it after the first decryption or
  when its chosen lifetime expires. A captcha guards uploads, and the
  encryption's work factor can be set. No cipher or KDF is stated.

**Why this matters to Adhal.** It is the clearest case for §1 #1: a
server holds the file, even if it is encrypted, for as long as the drop
lasts, and whoever runs that server sees who uploaded and who fetched it.
The sharper difference is the code. Hushdrop's ciphertext is guarded by a
password, and a copy of the ciphertext can be guessed against offline at
any speed, which is why its own page asks for long passwords. The secret
half of Adhal's five-word code feeds a PAKE and is never hashed into
anything public, so there is nothing to grind offline. Every guess costs a
live protocol run, and the drop is burned after 100 failures
([`THREAT-MODEL.md`](THREAT-MODEL.md) §5.2–5.3). That is why three short
secret words are enough. The opt-in opaque code gives up this property. Hushdrop's real advantages are worth stating too: the
recipient needs only a browser, and the sender and recipient do not have
to be online at the same time. Adhal requires both, by design. Neither
project has traction yet, so this is a comparison of designs, not of
markets. To verify: StatiCrypt's KDF and cost, and what the managed tier
logs.

**Others named but not profiled here:** LocalSend (a W14 comparison
target), and PairDrop-style browser tools, which already serve casual use
from iOS. Each needs the same treatment as the tools above before anything
is said about it.

**License hygiene.** DashBeam is AGPL-3.0: treat it as a black box, and do
not read its source with an eye to copying. magic-wormhole is MIT, and its
protocol documentation is the first thing to read before W14. MeshDrop is
MIT (its name and logo are separately protected), so reading its core is both legal and the
cheapest high-value research available. It uses the same stack for the same
idea, so it holds either bugs to avoid or a design worth adopting.

**Re-verify before relying on any row.** A dated table is a snapshot, and
this one is second-hand.

---

## 2a. Incumbents and why Adhal is not competing with them

The tools in §2 share Adhal's niche. The tools here are what most people
actually use to move a file, and "why not just use that?" is the first
question anyone will ask. The honest answer is that for most transfers
they are the better choice, and Adhal should say so and name the cases
they leave uncovered.

**Provenance is weaker here than in §2.** Nothing below comes from a
README read for this document. It is general knowledge, written down so
that it can be checked. Every claim is to be verified before it is
repeated anywhere public, and anything about another product's security
needs a cited source.

**The barrier is installation, not features.** These tools are already on
the device, or come with the ecosystem the user has chosen. Adhal must be
installed on *both* ends before the first transfer. No feature on Adhal's
list removes that cost, so its case has to rest on transfers the
incumbents cannot do at all, not on doing the same transfer slightly
better.

### Built-in proximity sharing

Quick Share (Google and Samsung, also on Windows), AirDrop, Huawei Share,
and Xiaomi's share feature (with the Xiaomi, OPPO, and vivo interoperability
alliance). As understood: devices find each other over Bluetooth LE and
move data over Wi-Fi Direct or the local network, with no internet
connection needed. Each works best, or only, within its vendor's
ecosystem, and some tie visibility to an account or contact list. Reports
of interoperability between some of these (for example Quick Share with
AirDrop on some Pixel devices) should be checked, because they change who
is locked out.

**Where Adhal is not competing:** two devices in the same room, same
ecosystem. Proximity tools are faster to start, need no internet, and are
already installed. This will be include in the next version.

**What they leave uncovered:**

- **Distance.** These are proximity tools. When the recipient is in
  another building or another country, they do not apply, and the usual
  fallback is a cloud upload or a chat app, which is a server holding the
  file. That is the case §1 #1 is about.
- **Mixed devices.** A Linux server, a CI runner, a machine with no
  Bluetooth, or a phone from a different vendor.
- **No account and no persistent identity** (§1, #3). Contact-based
  visibility is the opposite design.
- **Scripting** (§1, #4). A share sheet is not a pipe.

**Not in the W14 trials.** They do not cross NAT, so they cannot be run on
the network pairs in §4. Say so where the results are published, so that
their absence is not read as avoiding them.

### Third-party sharing apps

SHAREit and similar apps are widely installed, particularly where
built-in sharing is missing between vendors. Their reputation includes
heavy advertising, bundled extras, and published security findings. The
contrast with §1 #3 is real, but any specific security claim must cite
its source and its date, and must say whether the problem was fixed. An
unsourced swipe at a competitor would cost more credibility than it
gains.

**LG SmartShare** was named as a candidate, but appears to have been
mainly DLNA media streaming to LG TVs rather than sending files between
people, and may be discontinued. Verify both before deciding whether it
belongs here at all.

### BitTorrent and IPFS

The other design (§1, "Do not fight on"). Content is addressed by its hash
(an infohash or a CID), served to anyone who has that address, and kept
available by whoever holds a copy. That is the right design for
one-to-many distribution and for content meant to stay available, and
Adhal does not compete there.

**Why a magnet link is not a private drop**, as understood and to be
verified per protocol:

- The address is the capability. Anyone who learns the infohash or CID
  can fetch the content, and nothing like a PAKE stops a guesser or an
  eavesdropper who saw the link.
- Who is serving it is visible. DHT peers can see which addresses are
  announced and from which IP addresses; Adhal's DHT nodes see a topic and
  IP addresses too (§1, #3), but not a durable, content-derived address.
- Availability is meant to last. A drop that ends after one recipient is
  not the model.
- A hash is needed first, so a stream of unknown length cannot be sent
  (§1, #4).

Iroh, under DashBeam, comes from this content-addressed family, which is
part of why §2 treats DashBeam as a different kind of tool.

### Paired-network tools

Taildrop (Tailscale) and Syncthing both cross networks with no cloud copy
of the file, which is Adhal's ground. Both need the devices to be enrolled
and trusted in advance: a tailnet, or a shared device ID. That suits a
person moving files between their own machines, and it is the
persistent-identity design that §1 #3 rules out. Adhal's case against
them is a transfer between two people who share nothing beforehand.

---

## 3. Open questions

- **iOS.** Per the plan, neither profiled tool has it. Holepunch's Bare
  runtime is designed for embedding, and Keet ships on iOS (unverified), so
  a path may exist. Local-network permission and background-execution rules
  make it hard. Cross-OS including iOS, with no server, would be the
  largest open gap in this space, so it is worth a spike early, to size the
  prize before reordering the platforms.
- **Is MeshDrop fragile?** A claim from an earlier plan, never measured.
- **Does the relay matter?** One pair of networks has been measured
  (Starlink CGNAT to Comcast): 10 of 10 punched at first, then two runs
  of 40 trials with no relay configured, and every one of the 80
  connected directly. The two failures, on 2026-10-13, lost the
  connection after it was made. Dual hard NAT, the plan's own named risk,
  has not been measured, so "the relay is not on the critical path" is
  not yet established.

---

## 4. Comparison testing (W14, planned)

Not done yet. This is the method, so that when it is run the result can
be trusted, and it is where the results will go.

**The experiment.** The same file, sent by each tool on identical network
pairs, many times, with a success rate and a timing distribution for each
pair. `scratch-trials.js` is the harness for Adhal
([`MEASURING-TRANSFER-RELIABILITY.md`](MEASURING-TRANSFER-RELIABILITY.md));
the other tools need an equivalent driver. **This single experiment tests
the central thesis**, serverless-by-default rendezvous, and decides how
much the relay matters.

**The network pairs**, chosen for where hole punching fails:

- home NAT ↔ home NAT, and CGNAT ↔ home NAT (the one path measured so far);
- **CGNAT ↔ CGNAT**, for example two phones on hotspots from different
  carriers;
- a symmetric or port-randomizing NAT;
- same NAT (hairpinning) and VLAN-isolated networks. Two peers on one
  machine or one LAN connect by hyperdht's LAN shortcut, without
  touching the router, so hairpinning is tested only by two devices
  behind one NAT that cannot reach each other locally, such as main and
  guest Wi-Fi. Adhal's same-machine baseline is 20 of 20 (2026-10-18,
  [`ARCHITECTURE.md`](ARCHITECTURE.md)). The isolated case, guest and
  main Wi-Fi behind one eero Pro 6E, is 0 of 20 in both directions
  (2026-10-19): the router did not hairpin, so only a relay connects
  that pair. The other tools have not been run on it;
- a mobile hotspot and a corporate network.

**How it is read.**

- Rates with Wilson intervals, never a bare "10/10". At ten trials the
  bound is too wide to separate two good tools, so the trial count is set
  by the difference worth detecting.
- Sampled across the time of day and across DHT churn: a transient that
  shows up once deserves a series, not a lucky rerun.
- A hostile topic (many bogus announces) is both a reliability and a
  denial-of-service test, and worth running against every tool that uses a
  DHT.
- Every tool runs its own default configuration, and the configuration is
  published with the result.

**Before running it.** Read magic-wormhole's protocol documentation (MIT),
and MeshDrop's core and its handshake (MIT, same stack). Treat DashBeam as
a black box (AGPL).

**Results.** None yet. Adhal's own runs on the CGNAT ↔ home NAT pair
(§1, #5) are in [`ARCHITECTURE.md`](ARCHITECTURE.md), but they are not a
comparison until the other tools have been run on the same pair.

| Pair | Adhal | magic-wormhole | MeshDrop | DashBeam | LocalSend |
|---|---|---|---|---|---|
| | | | | | |
