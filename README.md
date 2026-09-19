# Quay

<img src="assets/AppIcon-preview-rounded.png" width="120" alt="Project logo" />

Quay is a one-shot, no-account file drop between two devices: QR or 6-word
code, LAN first, DHT second, relay if a direct connection can't be
established. No intermediary server sees your file unless a relay carries
ciphertext on your behalf.

- [`docs/IMPLEMENTATION-PLAN.md`](docs/IMPLEMENTATION-PLAN.md) -- what is
  being built, in what order, and which parts a competitor cannot copy
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) -- how it works, and what
  was learned building it
- [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) -- what leaks, what does
  not, and the explicit non-goals
- [`docs/PROTOCOL.md`](docs/PROTOCOL.md) -- the versioned wire spec

Built on [Holepunch](https://holepunch.to) (Hyperswarm / Hyperdht / Noise)
rather than a custom NAT-traversal stack.

## Status

**A drop works end to end, over the public DHT, across ISPs, and the
security work that had been deferred is done (Stage 0).**

- **Loopback:** two CLI processes on one machine exchange a 10 MB file over a
  localhost TCP pipe and independently print matching SHA-256 hashes --
  zero NAT, zero Hyperswarm, just the chunking/framing/hashing pipeline.
- **Hyperswarm:** the same manifest/chunk protocol, now carried over an
  end-to-end Noise-encrypted Hyperswarm connection instead of a bare TCP
  socket. `pnpm test` proves this against an isolated local DHT testnet
  (no internet required, so it's fast and CI-safe); `pnpm run demo:swarm`
  proves it against the real public DHT, which needs outbound UDP
  reachability to Hyperswarm's bootstrap nodes -- this can time out in
  sandboxed environments that only permit TCP/HTTPS egress.
  `QUAY_JOIN_TIMEOUT=<ms>` overrides the 30s peer-discovery timeout (0
  disables it) if you need a longer budget while diagnosing a slow
  network. Note that a longer budget does not help the announce-propagation
  race described in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) -- that
  one is fixed, not waited out. Cross-ISP transfer (Starlink CGNAT to
  Comcast, both behind NAT) is verified with matching hashes on both sides.
- **Drop codes** are generated rather than typed. Six words from the
  vendored EFF short list (`acid-acorn-acre-acts-afar-agent`, ~62 bits) and
  a QR carrying the same payload uppercased (`QUAY1:ACID-ACORN-...`), which
  keeps it a 29x29 version-3 symbol at ECC level Q. `pnpm run code`
  prints one; `quay-receive`/`swarm-receive.js` now generates its own when
  given no code, and shows the QR at the moment it becomes discoverable.
  Word list and QR payload contents are both settled --
  see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#the-drop-code-d1).
- **The code proof:** knowing the code is a requirement, not a convention.
  A receiver has to announce its topic to be findable, so the topic is
  public from the moment a drop starts -- readable by the DHT nodes near
  that topic, which is what `engine/scratch-lookup.js` walks. The code is not
  public, so the handshake ends with each side proving to the other, over
  fresh nonces, that it has one. A stranger who scraped the topic can no
  longer be handed a file, nor hand one over into your `~/Downloads`. It is
  mutual because both of those are real. See
  [The code proof](docs/ARCHITECTURE.md#the-code-proof-d3) -- including
  what it deliberately does not defend against, and note that it is a
  wire-format change, so both machines must be redeployed together.
- **Failure reporting:** failures are something a human can name and act on. The
  receiver verifies the file against the sender's manifest digest and
  publishes it under its real name only if it passes (D6, which had been
  written down from the start and implemented nowhere that shipped); a manifest can no longer choose a path outside the output
  directory; a sender that vanishes mid-transfer fails the receive instead
  of hanging it forever; and a declared frame length is bounded rather
  than buffered toward 4 GB. Progress is reported on both sides, and
  Ctrl-C sends a real CANCEL so the peer reports a deliberate cancellation
  rather than `connection reset by peer` -- which is exactly what a dead
  hole punch looks like, and the confusion the Hyperswarm work spent a
  week learning to separate. Every failure now carries a machine-readable `.code`. **This
  is a second wire-format change** (a one-byte type tag on every frame),
  so again both machines must be redeployed together; a peer on an older
  build is detected and told to redeploy rather than reported as
  corruption. See
  [Manifest, progress and cancel](docs/ARCHITECTURE.md#manifest-progress-and-cancel).
- **Stage 0 hardening:** the code proof proves a peer is the one the human
  meant, and nothing more. A peer that has the code could still overwrite
  `~/.zshrc`, redirect a write through a planted symlink, forge a log line
  or clear your terminal with a crafted filename, declare a 9 PB transfer,
  outrun your disk until the process grew without bound, or prove the code
  and then hold the connection open forever. None of those are reachable
  now, and each has a test. Three latent bugs were found by probing the
  shipping code rather than reading it -- including a sender whose Ctrl-C
  had never worked. See
  [Stage 0 hardening](docs/ARCHITECTURE.md#stage-0-hardening) and
  [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

The readiness handshake between the two peers became two-way as of the
first cross-ISP attempt at a real drop, which exposed a receiver
that could be permanently consumed by a peer that connected and then
vanished -- routine on a firewalled CGNAT path. Both sides now discard a
candidate that fails to confirm and keep waiting, a join timeout says
whether it found nobody or found peers that never completed the handshake,
and each candidate is logged as it arrives or is dropped. Details and the
measurement in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

Reliability on that path is measured, not assumed: `engine/scratch-trials.js`
runs N real drops back to back and reports a success rate, a connect-time
distribution and a classified reason for every failure. On Starlink CGNAT to
Comcast (2026-09-17, 10 trials x 10 MB) it recorded **10/10 with a ~12.9s
median end-to-end and a 3.0s median connect**, clearing the alpha gates.
Stated honestly, 10/10 gives a 95% one-sided lower bound of 74.1%, so the
defensible claim is "healthy and comfortably usable", not "proven >=75%". See [`docs/MEASURING-TRANSFER-RELIABILITY.md`](docs/MEASURING-TRANSFER-RELIABILITY.md)
-- single runs cannot distinguish a flaky path from a broken one, and
assuming they can cost this project a day.

Not yet implemented: resume, LAN discovery, relay, and the v2 protocol
(PAKE-based codes, AEAD channel, streaming). See
[`docs/IMPLEMENTATION-PLAN.md`](docs/IMPLEMENTATION-PLAN.md).

## Project layout

```
quay/
├── engine/   @quay/engine -- transport-agnostic framing, manifest, chunking, hashing
├── cli/      @quay/cli    -- send/receive command-line proof of concept
└── docs/     plan, architecture, threat model, protocol spec, setup
```

`engine` stays pure JS with no UI/runtime framework attached, per the plan's
Phase A instruction. Holepunch packages (hyperswarm, hyperdht,
hypercore-crypto, protomux, compact-encoding, b4a) are already installed in
`engine/` from the Hyperswarm work onward, even though the loopback transport is plain
Node `net`/`fs`/`crypto`. The word list is vendored into
`engine/src/wordlist.js` so a drop code never depends on a network fetch;
`cli/` adds the zero-dependency `qrcode-generator` to draw the symbol, and
`jsqr` as a test-only decoder that proves the printed symbol really scans.

## Quickstart

Prerequisites: Node.js >= 18 (developed against v22.11.0), [pnpm](https://pnpm.io) (developed against 12.4.1).

```bash
pnpm install
pnpm test               # everything: 89 tests, ~2 min (spins up DHT testnets)
pnpm test:fast          # the same minus network/subprocess tests: ~4s
pnpm typecheck          # tsc --noEmit; the repo is JSDoc-typechecked
pnpm run demo:loopback  # loopback TCP, printing both sides' output live
pnpm run demo:swarm     # Hyperswarm, against the real public DHT
pnpm run code           # a drop code + its QR, ready to screenshot
```

To do a real two-machine drop, let the receiver generate the code and read
it off its screen -- by camera or by eye:

```bash
# on the receiving machine
node cli/src/swarm-receive.js --new ~/Downloads

# on the sending machine, using the words it printed
node cli/src/swarm-send.js acid-acorn-acre-acts-afar-agent ./some-file.bin
```

Both sides show a progress bar while the transfer runs (`QUAY_NO_PROGRESS=1`
turns it off), and Ctrl-C on either side cancels the drop deliberately: the
other end reports a cancellation with your reason, rather than a dropped
connection. That is true on both sides as of Stage 0 -- it had been
documented here for four milestones while the *sender* silently ignored
its abort signal. The receiver prints a `verified:` line only when the
file it wrote matches the digest the sender declared -- if it does not
match, nothing is saved.

The code can be kept out of your shell history and out of `ps` by passing
`-` instead and typing it at the prompt:

```bash
node cli/src/swarm-send.js - ./some-file.bin
```

An existing file is never overwritten: a drop that collides with one lands
as `name (1)` unless you pass `--replace`.

The sender accepts the code in any casing or separator style, and accepts a
scanned QR payload (`QUAY1:ACID-...`) verbatim; all of them normalize to
the same topic. If a word is mistyped, it says which one, before it spends
any time on the network. `QUAY_QR_WIDE=1` switches to a double-width
symbol for console fonts lacking the half-block glyphs, and `NO_COLOR`
drops the ANSI colors (at the cost of relying on a light terminal
background -- a QR only scans dark-on-light).

See [`docs/SETUP.md`](docs/SETUP.md) for setup and more detail on running/extending the CLI.

## License

MIT -- see [`LICENSE`](LICENSE). The engine and CLI are licensed
permissively to maximize forkability; a future GUI app's license is a
separate, not-yet-decided question.
