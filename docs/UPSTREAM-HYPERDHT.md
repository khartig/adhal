# Upstream notes: hyperdht

Behavior in Holepunch's libraries that Adhal works around or accepts, written
so that each note can be handed to the library's developers as it stands.
Versions as pinned in `engine/package.json`: hyperdht 6.36.0, Hyperswarm
4.17.1, and blind-relay 1.6.1, which hyperdht depends on. Line numbers are
from hyperdht 6.36.0 unless a note says otherwise.

---

## 1. A peer can choose the relay your connection goes through

### What happens

A relay in hyperdht is opt-in per side: `relayThrough` on `dht.connect()` or
`dht.createServer()`, or on Hyperswarm. But each side also follows a relay
the *other* side names in its handshake payload, whatever its own setting:

- **The side being dialed** pairs through the relay the dialer names.
  `lib/server.js:429`: `if (relayThrough || remotePayload.relayThrough)
  this._relayConnection(...)`.
- **The dialing side** pairs through the relay the dialed side names, in
  preference to its own. `lib/connect.js:534` calls `relayConnection`, which
  takes `payload.relayThrough` first (`lib/connect.js:798`).

Neither path has a hook to decline. Hyperswarm adds none either: it builds
the server and each `dht.connect()` itself, and passes only `relayThrough`
(`index.js:50`, `index.js:210`).

### Why it matters to an application like Adhal

Adhal treats a relay as something the user turns on (`--relay <key>`), and
the peer is unauthenticated when the relay decision is made: the handshake
that names the relay comes before Adhal's PAKE proves the drop code. So
anyone who finds the drop's topic on the DHT can make a waiting peer connect
to a relay of their choosing. That relay's operator learns the peer's IP
address and connection times.

Adhal accepts this (2026-11-08, [`THREAT-MODEL.md`](THREAT-MODEL.md) §8): a
stranger who dials the peer learns its address anyway, and traffic through
the relay stays end-to-end encrypted. An application with a stricter policy
cannot enforce one today without the workaround below.

### The change we would propose upstream

An `acceptRelay` option, on both sides, consulted before pairing through a
relay the peer named:

```js
dht.createServer({ acceptRelay: (relayPublicKey, remotePublicKey) => boolean })
dht.connect(publicKey, { acceptRelay: (relayPublicKey, remotePublicKey) => boolean })
```

- Called only for a relay named by the peer, never for the side's own
  `relayThrough`.
- Returning `false` treats the payload as if it named no relay. Punching
  goes on as it would have.
- When it is absent, behavior is unchanged.
- Hyperswarm would pass it through to both its server and its dials.

One more thing would help: telling the peer it was refused. A refused peer
currently learns nothing, and waits out its own 15 s relay timeout
(`RELAY_ABORTED`, `lib/connect.js` `relayConnection`). That needs a signal
in the protocol, so it is a larger change than the option above.

### The workaround, until then

Adhal ships this as `--refuse-peer-relay` (`refusePeerRelays` in
`engine/src/swarm.js`). Both sides already accept a `createHandshake` factory. A wrapper around
hyperdht's own `NoiseWrap` can clear `relayThrough` from the peer's decoded
payload before hyperdht acts on it:

```js
const NoiseWrap = require('hyperdht/lib/noise-wrap.js')

function refusingPeerRelays (keyPair, remotePublicKey) {
  const handshake = new NoiseWrap(keyPair, remotePublicKey)
  const recv = handshake.recv.bind(handshake)
  handshake.recv = (buf) => {
    const payload = recv(buf)
    if (payload) payload.relayThrough = null
    return payload
  }
  return handshake
}

swarm.server.createHandshake = refusingPeerRelays          // the dialed side
// the dialing side: wrap swarm.dht.connect to add { createHandshake: refusingPeerRelays }
```

What it was first tested against: `engine/scratch-relay-spike.js` on a
hyperdht 6.34.0 testnet, with the punch forced to fail and the dialer naming
a relay. `cli/test/peer-relay.test.js` now checks it on each run, against
the pinned version, each case with a control showing that the setup
detects a relay when one is used.

| Scenario | Result |
|---|---|
| Receiver refuses, sender names a relay | The receiver cleared the relay in 4 of 4 handshakes, and the relay matched no pair. The sender's relay attempts ended `RELAY_ABORTED`, and the drop ended `ERR_NO_PEER`, as with no relay at all. |
| The wrapper on, no relay anywhere | A direct 8 MiB drop completed, with the digest verified |

Its limits:

- It depends on `hyperdht/lib/noise-wrap.js`, an internal module, and on
  `server.createHandshake` being a plain property that is read on each
  handshake. Neither is public API, so either can change in an upgrade.
- Only the dialed side's half was exercised. Adhal's own dialed side
  never names a relay, so the dialing side's half would only matter
  against another implementation, or a stranger.
- The refused peer waits out its 15 s relay timeout, and its unmatched
  pairing request stays pending on the relay until the relay drops the
  session (one was still pending when the run ended).
