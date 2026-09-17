# Quay

<img src="assets/AppIcon-preview-rounded.png" width="120" alt="Project logo" />

Quay is a one-shot, no-account file drop between two devices: QR or 6-word
code, LAN first, DHT second, relay if a direct connection can't be
established. No intermediary server sees your file unless a relay carries
ciphertext on your behalf. See [`docs/Refined-Implementation-Plan.md`](docs/Refined-Implementation-Plan.md)
for the full product and phasing strategy, and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
for the condensed technical design.

Built on [Holepunch](https://holepunch.to) (Hyperswarm / Hyperdht / Noise)
rather than a custom NAT-traversal stack.

## Status

**Phase A, items 1-3 (of the plan's section 4 ordered list):** proven.

- Item 1: two CLI processes on one machine exchange a 10 MB file over a
  localhost TCP pipe and independently print matching SHA-256 hashes --
  zero NAT, zero Hyperswarm, just the chunking/framing/hashing pipeline.
- Item 2: the same manifest/chunk protocol, now carried over an
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
- Item 3: drop codes are generated rather than typed. Six words from the
  vendored EFF short list (`acid-acorn-acre-acts-afar-agent`, ~62 bits) and
  a QR carrying the same payload uppercased (`QUAY1:ACID-ACORN-...`), which
  keeps it a 29x29 version-3 symbol at ECC level Q. `pnpm run code`
  prints one; `quay-receive`/`swarm-receive.js` now generates its own when
  given no code, and shows the QR at the moment it becomes discoverable.
  Both §9 open decisions (word list, QR payload contents) are resolved --
  see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#the-drop-code-item-3).

The readiness handshake between the two peers is two-way (READY + ACK) as
of the first cross-ISP attempt at an item-3 drop, which exposed a receiver
that could be permanently consumed by a peer that connected and then
vanished -- routine on a firewalled CGNAT path. Both sides now discard a
candidate that fails to confirm and keep waiting, a join timeout says
whether it found nobody or found peers that never completed the handshake,
and each candidate is logged as it arrives or is dropped. Details and the
measurement in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

See [`docs/Refined-Implementation-Plan.md` section 4](docs/Refined-Implementation-Plan.md#4-implement-first-easiest-highest-chance-of-success)
for the full ordered list; items 4+ (challenge-response, progress/cancel,
resume, relay, ...) are not yet implemented.

## Project layout

```
quay/
├── engine/   @quay/engine -- transport-agnostic framing, manifest, chunking, hashing
├── cli/      @quay/cli    -- send/receive command-line proof of concept
└── docs/     product plan, architecture notes, setup guide
```

`engine` stays pure JS with no UI/runtime framework attached, per the plan's
Phase A instruction. Holepunch packages (hyperswarm, hyperdht,
hypercore-crypto, protomux, compact-encoding, b4a) are already installed in
`engine/` for item 2 onward, even though item 1's own transport is plain
Node `net`/`fs`/`crypto`. The word list is vendored into
`engine/src/wordlist.js` so a drop code never depends on a network fetch;
`cli/` adds the zero-dependency `qrcode-generator` to draw the symbol, and
`jsqr` as a test-only decoder that proves the printed symbol really scans.

## Quickstart

Prerequisites: Node.js >= 18 (developed against v22.11.0), [pnpm](https://pnpm.io) (developed against 12.4.1).

```bash
pnpm install
pnpm test               # runs the item-1, -2 and -3 proofs automatically
pnpm run demo:loopback  # item 1, manually, printing both sides' output live
pnpm run demo:swarm     # item 2, manually, against the real public DHT
pnpm run code           # item 3, a drop code + its QR, ready to screenshot
```

To do a real two-machine drop, let the receiver generate the code and read
it off its screen -- by camera or by eye:

```bash
# on the receiving machine
node cli/src/swarm-receive.js --new ~/Downloads

# on the sending machine, using the words it printed
node cli/src/swarm-send.js acid-acorn-acre-acts-afar-agent ./some-file.bin
```

The sender accepts the code in any casing or separator style, and accepts a
scanned QR payload (`QUAY1:ACID-...`) verbatim; all of them normalize to
the same topic. If a word is mistyped, it says which one, before it spends
any time on the network. `QUAY_QR_WIDE=1` switches to a double-width
symbol for console fonts lacking the half-block glyphs, and `NO_COLOR`
drops the ANSI colors (at the cost of relying on a light terminal
background -- a QR only scans dark-on-light).

See [`docs/SETUP.md`](docs/SETUP.md) for IntelliJ IDEA setup and more detail
on running/extending the CLI.

## License

MIT -- see [`LICENSE`](LICENSE). The engine and CLI are licensed permissively
to maximize forkability, per the plan's licensing guidance (section 7); a
future GUI app's license is a separate, not-yet-decided question.
