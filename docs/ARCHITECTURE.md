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

## What's implemented today (items 1-2)

`engine/src/frame.js` and `engine/src/transfer.js` implement steps 4-6 of
the data path above. Item 1 proves this over a plain localhost TCP socket
(zero NAT, zero DHT); item 2 (`engine/src/swarm.js`, `engine/src/topic.js`)
carries the *same* manifest/chunk protocol over an end-to-end
Noise-encrypted Hyperswarm connection instead, proving topic-join +
encrypted transport without changing the framing logic at all.
`cli/src/send.js`/`receive.js` (item 1) and `cli/src/swarm-send.js`/
`swarm-receive.js` (item 2) are the corresponding CLI pairs.

Item 2 notes, found empirically while building it (see `engine/src/swarm.js`
comments for detail):

- Both peers must `join()` a topic with the (default) `server: true, client: true`.
  Splitting roles asymmetrically (receiver server-only, sender client-only)
  broke the connection -- the server side's `'connection'` event never fired
  even though the client believed it had connected.
- The server side's `'connection'` event fires only once the connection is
  genuinely stable; the client side's fires earlier/optimistically. Writing
  application data immediately after the client-side event can prevent the
  server from ever confirming the connection. Fixed with a one-byte
  readiness handshake: the server writes a marker byte once connected: the
  client waits to receive it before sending anything.
- `socket.write()`'s backpressure return value must be respected (pause the
  read stream, resume on `'drain'`) -- a raw TCP socket (item 1) tolerates
  ignoring this because of deep OS send buffers; the encrypted Hyperswarm
  duplex does not.
- Tearing the swarm down immediately after the sender's own `end()`
  callback fires is not safe -- that only confirms a *local* flush, not
  that the receiver got the last bytes. The receiver now ends its side
  after it finishes reading, and the sender waits for the socket's
  `'close'` event (both sides ended) before destroying its swarm.

Steps 1-3 and 7 of the data path above, resume (step 5's offset
persistence), and Protomux-based channel multiplexing all belong to later
items in section 4 and are not yet built.

## Relay threat boundary

Documented here ahead of writing any relay code (plan section 3):

- Sees: two connection times, approximate bytes, IPs.
- Does not see: filenames, plaintext, long-term identity (per-drop tokens only).
- Cannot join a drop without the code.
- Caps: per-token bandwidth and duration.
- Default: a hosted relay; user can paste another URL.

This is also the basis for the project's "we are not a host of user
content" App Review / DSA argument: a relay is a pipe, not storage.
