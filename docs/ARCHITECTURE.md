# Architecture

Condensed from [`Refined-Implementation-Plan.md`](Refined-Implementation-Plan.md)
section 3. Read that document for the full reasoning; this page is a quick
reference kept in sync with it.

## Key hierarchy

```
Device Noise keypair          <- identity, persisted locally
├── Per-peer trust records    <- pk + {stranger | paired | trusted}
├── Per-drop capability       <- 6-word / QR, time-limited topic
├── Transfer encryption key   <- one key per drop (core or stream key)
└── Relay session             <- ciphertext only; no names, no hashes in clear
```

## v1 data path (target, not all implemented yet)

1. Generate code -> topic = hash(code || app-salt) (32 bytes).
2. Both peers `swarm.join(topic)`.
3. Challenge-response: prove you know the code (HMAC over nonce). Don't
   trust a stranger who merely found the topic.
4. Open a Protomux channel; send a manifest (name, size, chunk size,
   content hash).
5. Stream chunks; ack by index; persist offset for resume.
6. Receiver verifies the full-file hash; atomic rename into Downloads.
7. Leave the topic. If "Keep" was off, forget the peer.

Hyperdrive/Autobase/CRDTs are explicitly out of scope for v1 content -- a
framed stream plus a small on-disk manifest is enough, and is easier to
resume and test.

## What's implemented today (item 1 only)

`engine/src/frame.js` and `engine/src/transfer.js` implement steps 4-6 of
the data path above, minus the Hyperswarm/Protomux transport -- item 1
proves the framing/manifest/chunking/hashing logic over a plain localhost
TCP socket, with zero NAT and zero DHT involved. `cli/src/send.js` and
`cli/src/receive.js` are the two CLI processes described in section 4, item
1 of the plan. Steps 1-3, 7, resume (step 5's offset persistence), and the
Hyperswarm-based transport all belong to later items in section 4 and are
not yet built.

## Relay threat boundary

Documented here ahead of writing any relay code (plan section 3):

- Sees: two connection times, approximate bytes, IPs.
- Does not see: filenames, plaintext, long-term identity (per-drop tokens only).
- Cannot join a drop without the code.
- Caps: per-token bandwidth and duration.
- Default: a hosted relay; user can paste another URL.

This is also the basis for the project's "we are not a host of user
content" App Review / DSA argument: a relay is a pipe, not storage.
