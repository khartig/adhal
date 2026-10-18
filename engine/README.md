# @ad-hal/engine

The transfer engine behind [Adhal](https://github.com/khartig/adhal): drop
codes, the CPace-X25519-SHA512 handshake, the ChaCha20-Poly1305 channel,
and the manifest, consent, and chunk transfer, over Hyperswarm.

Most people want the command-line tools,
[`@ad-hal/cli`](https://www.npmjs.com/package/@ad-hal/cli). The only
official npm packages are those two. The source is
[github.com/khartig/adhal](https://github.com/khartig/adhal).

## Status

**The JavaScript API is not stable before 1.0.** The wire protocol is:
it is frozen as v2 and specified in
[`PROTOCOL.md`](https://github.com/khartig/adhal/blob/main/docs/PROTOCOL.md).

The package exports more than an application needs, because the tests and
the protocol's vectors use the internals. The entry points an application
uses are:

- `generateCode`, `resolveCode`, and `encodeQrPayload`, for the drop code;
- `createSwarm`, then `acceptOnce` on the receiving side and `connectOnce`
  on the sending side, for pairing and the handshake;
- `sendFile` or `sendStream`, and `receiveFile` followed by
  `closeAfterResult`, for the transfer;
- `displayName`, for showing a peer's file name safely.

The reference callers are the CLI's
[`swarm-send.js`](https://github.com/khartig/adhal/blob/main/cli/src/swarm-send.js)
and
[`swarm-receive.js`](https://github.com/khartig/adhal/blob/main/cli/src/swarm-receive.js).

Node.js ≥ 24. Adhal is not anonymous, and Windows is not supported for
security purposes yet; the
[threat model](https://github.com/khartig/adhal/blob/main/docs/THREAT-MODEL.md)
says what is and is not claimed.

## License

MIT
