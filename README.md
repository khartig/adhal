# Quay

<img src="assets/quay.jpg" alt="Quay icon" width="96" />

Quay is a one-shot, no-account file drop between two devices: QR or 6-word
code, LAN first, DHT second, relay if a direct connection can't be
established. No intermediary server sees your file unless a relay carries
ciphertext on your behalf. See [`docs/Refined-Implementation-Plan.md`](docs/Refined-Implementation-Plan.md)
for the full product and phasing strategy, and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
for the condensed technical design.

Built on [Holepunch](https://holepunch.to) (Hyperswarm / Hyperdht / Noise)
rather than a custom NAT-traversal stack.

## Status

**Phase A, item 1 (of the plan's section 4 ordered list):** proven. Two CLI
processes on one machine exchange a 10 MB file over a localhost TCP pipe and
independently print matching SHA-256 hashes -- zero NAT, zero Hyperswarm,
just the chunking/framing/hashing pipeline. See
[`docs/Refined-Implementation-Plan.md` section 4](docs/Refined-Implementation-Plan.md#4-implement-first-easiest-highest-chance-of-success)
for the full ordered list; items 2+ (LAN via Hyperswarm, code/QR, challenge-response,
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
Node `net`/`fs`/`crypto`.

## Quickstart

Prerequisites: Node.js >= 18 (developed against v22.11.0), [pnpm](https://pnpm.io) (developed against 12.4.1).

```bash
pnpm install
pnpm test               # runs the item-1 loopback proof automatically
pnpm run demo:loopback  # runs it manually and prints both sides' output live
```

See [`docs/SETUP.md`](docs/SETUP.md) for IntelliJ IDEA setup and more detail
on running/extending the CLI.

## License

MIT -- see [`LICENSE`](LICENSE). The engine and CLI are licensed permissively
to maximize forkability, per the plan's licensing guidance (section 7); a
future GUI app's license is a separate, not-yet-decided question.
