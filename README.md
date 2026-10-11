# Adhal

<img src="assets/app-icon.jpg" width="120" alt="Project logo" />

Adhal is a one-shot, no-account file drop between two devices. The
receiver shows a QR code or a five-word code, the sender types or scans
it, and the file goes directly between the two machines over the
Holepunch DHT, encrypted end to end. No server stores it, and no account
is involved.

The name comes from the Sumerian *ad-ḫal* (Ad-ḫal, written 𒀜𒄬), an ancient
word meaning “secret”: something kept hidden, knowledge sealed between
those who share it and no one else.

- [`docs/IMPLEMENTATION-PLAN.md`](docs/IMPLEMENTATION-PLAN.md): the
  roadmap, what is done, and what Adhal is built around
- [`docs/POSITIONING.md`](docs/POSITIONING.md): how it compares with other
  tools, and how that will be tested
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): how it is built
- [`docs/PROTOCOL.md`](docs/PROTOCOL.md): the versioned wire
  specification, including what v2 claims and does not (§12)
- [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md): what leaks, what does
  not, and the explicit non-goals
- [`SECURITY.md`](SECURITY.md): how to report a vulnerability, and
  [`docs/SECURITY-REVIEW.md`](docs/SECURITY-REVIEW.md), the status of
  every finding so far
- [`docs/history/`](docs/history/): how it got here

Built on [Holepunch](https://holepunch.to) (Hyperswarm, HyperDHT, Noise)
rather than a custom NAT-traversal stack.

## Status

**A drop works end to end, over the public DHT and across ISPs. Protocol
v2 is implemented, and a security review of it has been worked through
(W15). The wire format is not yet frozen (W17), and there are no releases
yet.**

What a drop does today:

- **The code is split.** Five words from the EFF large wordlist: a
  two-word *nameplate* that names the DHT topic and is public, and a
  three-word *secret* (~38.8 bits) that is never hashed into anything an
  observer can see. The secret is the password to a CPace PAKE, so a
  guess costs a live run against a peer that is counting, and 100 failed
  guesses burn the drop (W11; [`PROTOCOL.md`](docs/PROTOCOL.md) §2, §6).
- **Every byte after the handshake is sealed**, with ChaCha20-Poly1305
  under keys from the PAKE and the frame length authenticated, so security
  does not depend on the transport that carried the bytes (W11, W15a).
- **The receiver is asked.** Each offer is shown with its name, size and
  SHA-256 before anything is written, and a name that would run when
  opened is warned about (W15c).
- **The file is verified, and nothing is overwritten.** The receiver
  publishes it under its name only once its digest matches, never in
  place of an existing file, and only then tells the sender it arrived
  (Stage 0, W11).
- **Streaming and resume.** `tar c dir | ad-hal-send <code> -` sends a
  stream of unknown length. An interrupted transfer resumes from what the
  receiver already holds, once the sender has proved that prefix is
  really its own (W11).

What to know before using it:

- **The code is a bearer capability.** Whoever holds it can complete the
  drop, so hand it over by a route only the intended person sees. If
  someone else with the code reaches the receiver first, you are told the
  drop was already taken, and the side that paired says someone else has
  the code (W15a).
- **Adhal is not anonymous.** Each side's IP address is visible to the
  other, and to the DHT nodes near the drop's topic. Both CLIs say so
  when they start.
- **Windows is not supported for security purposes** until it is a
  required CI leg. Some of the filesystem defences fall back to weaker,
  racy checks there (Q-07).

Not built yet: LAN discovery, the optional relay, and a receive that
writes to stdout with stable `--json` events (W13). See the
[roadmap](docs/IMPLEMENTATION-PLAN.md).

Reliability is measured, not assumed. `engine/scratch-trials.js` runs
repeated real drops and classifies every failure. On Starlink CGNAT to
Comcast (2026-09-17, 10 trials of 10 MB) it recorded **10 of 10, with a
~12.9 s median end to end**. Stated honestly, 10 of 10 gives a 95%
one-sided lower bound of 74.1%, so the defensible claim is "healthy and
comfortably usable", not "proven ≥ 75%"
([`MEASURING-TRANSFER-RELIABILITY.md`](docs/MEASURING-TRANSFER-RELIABILITY.md)).

## Quickstart

Prerequisites: Node.js ≥ 24, and [pnpm](https://pnpm.io) 12.4.1
(`corepack enable` provides it from `packageManager`).

```bash
pnpm install
pnpm test               # everything: ~500 tests, about two minutes (DHT testnets)
pnpm test:fast          # the same without network and subprocess tests: ~15 s
pnpm typecheck          # tsc --noEmit; the repo is JSDoc-typechecked
pnpm fuzz               # the fuzz harness at 100,000 iterations per target
pnpm run code           # a drop code and its QR symbol
pnpm run demo:swarm     # a drop between two local processes, over the public DHT
```

A real two-machine drop. The receiver generates the code and shows it, as
words and as a QR symbol, once it can be found:

```bash
# on the receiving machine
node cli/src/swarm-receive.js --new ~/Downloads

# on the sending machine: type the words at the prompt
node cli/src/swarm-send.js - ./report.pdf
```

These are the `ad-hal-receive` and `ad-hal-send` bins. The receiver shows
the offer and asks before writing anything; `--yes` accepts without
asking, and with no terminal and no `--yes` the offer is declined, and the
sender is told why. Both sides show progress (`ADHAL_NO_PROGRESS=1` turns
it off). Ctrl-C on either side cancels the drop, and the other side
reports a cancellation with your reason rather than a dropped connection.

- **The code** is read from the prompt or stdin (`-`), so it stays out of
  your shell history and `ps`. A code on the command line is refused
  unless you add `--code-on-argv`, which you need only when stdin carries
  the file: `tar c dir | node cli/src/swarm-send.js <code> - --name=dir.tar --code-on-argv`.
  Any casing or separator is accepted, as is a scanned QR payload, and a
  mistyped word is named before anything touches the network.
- **An existing file is never overwritten.** A name that is taken lands
  as `name (1)`, unless you pass `--replace`.
- **`--verbose`** prints the DHT topic, which is otherwise kept out of
  the logs. **`--insecure-opaque-code`** accepts an arbitrary string
  instead of a generated code. It is for diagnostics only, because such a
  string can be guessed offline by anyone watching the DHT.
- **`ADHAL_QR_WIDE=1`** draws a double-width symbol for console fonts
  that lack the half-block glyphs. **`NO_COLOR`** drops the colours, at
  the cost of relying on a light terminal background, since a QR only
  scans dark-on-light.

`--help` on either CLI lists every flag. `cli/src/send.js` and
`receive.js` are a loopback pair over `127.0.0.1` for tests, not for real
drops. See [`docs/SETUP.md`](docs/SETUP.md) for setting up a development
environment.

## Project layout

```
engine/   @ad-hal/engine -- the protocol, the transport and the transfer
cli/      @ad-hal/cli    -- the command-line tools, their tests and test helpers
docs/     the roadmap, architecture, protocol, threat model and history
```

`engine/` is plain JavaScript with no UI framework, so any front end can
sit on it, and `cli/` imports only from it. Every dependency is pinned to
an exact version. Holepunch's packages carry the transport, and
`@noble/curves` and `@noble/hashes` carry the PAKE. The wordlist is
vendored, so a drop code never depends on a network fetch. `cli/` adds
`qrcode-generator` to draw the symbol, and `jsqr`, test-only, to prove
the printed symbol really scans.

## License

MIT; see [`LICENSE`](LICENSE). The engine and CLI are licensed
permissively to maximise forkability. A future GUI app's licence is a
separate question, not yet decided.
