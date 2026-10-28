# W12 mutation triage: every survivor of the first full run

The detail behind [WORK-RECORD.md](WORK-RECORD.md#stage-2--w12-the-rest-the-first-full-mutation-run):
the 174 mutants that survived the first full run of `tools/mutate.js`
(2026-10-26, 751 mutants, `--workers 2 --conformance`), each with its
verdict and the reason for it. Read it as history: line numbers are as of
that run, and move with any later edit to the engine.

**The verdicts.**
- **Gap:** an input reachable through a real caller behaves differently
  under the mutant, and no test noticed.
- **Equivalent:** no input can observe the change.
- **Constant:** an integer constant moved by one, observable only by a
  test that pins the exact value, and not a security limit.
- **Unreachable:** defensive code no real caller can reach.

"Remote" marks what a peer can trigger; "local" what only a local caller,
the file system, or the environment can.

**How the verdicts were reached.** Each module group was read against
its callers and tests, and every claimed behavior change was confirmed by
planting the mutant in a throwaway copy (`tools/sandbox.js`) and comparing
its behavior with the unmutated engine's. Every gap verdict was then
proven: a new test that passes on the engine and fails with its mutant
planted, and a rerun of all 174 (`node tools/mutate.js --survivors`) in
which each gap was killed. The 56 that survived it are the rows marked
equivalent, constant, or unreachable, less the six unreachable checks
that were given direct tests anyway (`names.js:183`, `handshake.js:293`
twice, `transfer.js:238` twice, and `transfer.js:1265`). Rows marked ×2
or more are mutants on one line that share a verdict.

## Group A verdicts (names.js, message.js, reader.js, frame.js): 29 rows

Each behavior change was confirmed by planting the mutant and diffing a probe's output against the unmutated engine.

| survivor | verdict | why |
|---|---|---|
| frame.js:78 > to >= | equivalent | an empty buffer is concatenated (a copy) instead of aliased; the only caller (channel.js:307) pushes socket Buffers that are never reused |
| message.js:169 < to <= | equivalent | `bytes[bytes.length]` is undefined, and `undefined & 0xc0` is 0 |
| message.js:169 > to >= | equivalent | Buffer.from(string) is well-formed UTF-8, with at most 3 continuation bytes, so `end` never nears 0 |
| message.js:169 integer + 1 | equivalent | same |
| message.js:252 true to false | gap, local | decodeResult returns ok:false for a success; the engine reads `'error' in result`, never `.ok`, but decodeResult is public |
| message.js:254 && to \|\| | gap, remote | RESULT `{}` gives ERR_RECEIVER_FAILED, not ERR_PROTOCOL; `null` gives a TypeError; never counted as a success |
| message.js:254 true to false | gap, remote | `{"ok":false,"error":"x"}` becomes ERR_PROTOCOL; `{"ok":true,"error":"x"}` a receiver failure |
| message.js:255 false to true | gap, local | errors decode as ok:true |
| message.js:373 throw removed | gap, message only | CHECKPOINT that isn't JSON: same code, but the message no longer says it isn't JSON |
| message.js:403 throw removed | gap, message only | same, for END |
| message.js:405 \|\| to && | gap, remote | END `{"sha256":[hex]}` accepted as an array (gives ERR_HASH_MISMATCH, not ERR_PROTOCOL); `null` gives a TypeError |
| message.js:447 throw removed | gap, message only | same as 403, for PREFIX |
| message.js:449 \|\| to && | gap, remote | PREFIX `{"sha256":[hex]}` makes the receiver fail with a RangeError from timingSafeEqual, outside the error vocabulary; the prefix is never adopted |
| names.js:81 integer + 1 | constant | display cut, not a safety limit |
| names.js:87 integer + 1 | constant | same, displayText |
| names.js:130 integer + 1 | gap, remote | displayName shows a NUL as \u0001, so the refusal names the wrong byte |
| names.js:143 > to >= | gap, cosmetic | exactly 120 (or 4096) characters gets a spurious "... (120 chars)" |
| names.js:183 throw removed | unreachable from the wire | validateManifest (transfer.js:1193) refuses a non-string name first; a direct caller of the public safeWriteName gets a TypeError instead of ERR_UNSAFE_NAME |
| names.js:184 integer + 1 | gap, remote | every 1-character name is refused (fails closed; availability) |
| names.js:184 throw removed | gap, message only | '' is caught by 219 instead, with the wrong detail |
| names.js:185 > to >= | gap, remote | a 255-byte name is refused; only 256 is tested |
| names.js:191 throw removed | gap, message only | NUL is caught by CONTROL_CHARS (192) instead, with the wrong detail |
| names.js:202 \|\| to && | gap, message only | `.`/`..` strip to '' and are caught by 219, with the wrong detail |
| names.js:202 throw removed | gap, message only | same |
| names.js:219 integer + 1 | gap, remote | 1-character stripped names ('a.') refused; '...' returns '' and only transfer.js:1265 stops it |
| names.js:219 throw removed | gap, remote, backstopped | safeWriteName('...') returns ''; on the wire only the containment check (transfer.js:1265) still refuses it |
| reader.js:31 > to >= | equivalent | copy instead of alias, as frame.js:78 |
| reader.js:79 > to >= | gap, local | rest() returns Buffer(0) instead of the documented null; every engine caller checks length |
| reader.js:79 integer + 1 | gap, remote | exactly 1 leftover byte after the handshake is dropped, and the transfer desyncs (fails closed) |

Layers for a peer's name: validateManifest (transfer.js:1193) → safeWriteName (names.js:183-219) → containment (transfer.js:1261-1266). Every name test asserted only the code, never `detail`, so no layer was tested on its own.

## Group B verdicts (handshake.js, channel.js, cpace.js, attempts.js): 27 rows

Each behavior change was confirmed by planting the mutant in a sandbox and probing it against the unmutated engine.

Who calls the state guards: Initiator (swarm.js:655, stream-handshake.js:142) and Responder (swarm.js:988/1034, stream-handshake.js:165/174). After a success or a throw, the connection code removes its data listener (swarm.js:577-584 detach; stream-handshake.js:64-77 fail/detach), and each connection builds its own handshake object. So no remote peer can drive the guards at 520, 551, 594, or 651; only a local caller of the exported classes can.

| survivor | verdict | why |
|---|---|---|
| attempts.js:78 integer + 1 | constant | backoff base; PROTOCOL.md gives no number |
| attempts.js:79 integer + 1 | constant | the tests check the relations deliberately (attempts.js:68-72) |
| attempts.js:94 integer + 1 | constant | the sid memory, 1024 vs 1025; not a security boundary (both are far above the 100-attempt cap) |
| attempts.js:136 !== to === | gap, diagnostic | replyUnansweredError drops `.cause`; seen only by a direct caller |
| channel.js:140 > to >= | unreachable | needs 2^64 frames; deliberate defense in depth (channel.js:136-139) |
| channel.js:141 throw removed | unreachable | same; even under the mutant writeBigUInt64BE throws before the counter can wrap |
| channel.js:223 throw removed | gap, local | Channel built without onMessage fails late, at the first frame |
| channel.js:258 throw removed | gap, local, message only | seal of a non-Buffer still throws a TypeError, without the message; no nonce is spent |
| cpace.js:89 < to <= | equivalent | at 128 both branches give 0x80; byte-identical for lengths 0..69999 and edge powers |
| cpace.js:89 integer + 1 | equivalent | same |
| cpace.js:89 + to - | equivalent | `Buffer.from` stores `v & 0xff`, the same byte |
| cpace.js:126 integer + 1 | gap, interop | a PRS of 117 bytes or more gets a 1-byte zpad, so the generator differs from conformance/src/wire.js; engine-to-engine still pairs |
| cpace.js:199 throw removed | unreachable | noble throws on an all-zero result first; documented backup (cpace.js:195-198); the stub to test it can't be built, since noble's export is frozen |
| cpace.js:212 !== to === | gap, diagnostic | the neutral-element error loses noble's `.cause`; a remote low-order point triggers it |
| cpace.js:221 integer + 1 | unreachable | disables the :199 backup only |
| cpace.js:223 integer + 1 | equivalent in practice | rejects results whose bytes are all 0 or 1; no peer can steer K without the scalar |
| cpace.js:282 < to <= | equivalent | writing out[32] on a 32-byte Buffer is a no-op |
| handshake.js:207 throw removed | gap, local | encodeCaps('resume') returns e,m,r,s,u instead of throwing |
| handshake.js:218 > to >= | gap, remote | a canonical caps set of exactly 128 bytes (the PROTOCOL.md cap) is refused, ours or a peer's |
| handshake.js:246 > to >= | gap, remote | a peer's 128-byte caps refused |
| handshake.js:293 \|\| to && | unreachable from the wire | both callers pass exactly CONFIRM_SIZE bytes; exported, so worth a unit test |
| handshake.js:293 false to true | unreachable from the wire | under the mutant any wrong-length confirmation MATCHES; the most dangerous latent form, worth a unit test |
| handshake.js:437 > to >= | gap, remote | a HELLO of exactly 177 or a REPLY of 192 bytes (the PROTOCOL.md maxima) is refused |
| handshake.js:520 throw removed | gap, local | a second readReply after success accepts a REPLY forged without the secret (demonstrated) |
| handshake.js:551 true to false | gap, local | same, through the latch never being set |
| handshake.js:594 throw removed | gap, local | a second readHello: a party without the secret completes the handshake and gets the receiver's keys (demonstrated) |
| handshake.js:651 throw removed | gap, local, low | readConfirm before HELLO returns null or a TypeError, not ERR_PROTOCOL |

### A finding in the engine itself, not a mutant (verified on the unmutated engine)

The Initiator sets `_done` only on success (handshake.js:551), but wipes `_ya` on every path (:560). After a readReply that fails ERR_PAKE_CONFIRMATION, a second readReply runs with a zeroed scalar and accepts a REPLY forged without the secret ("FORGED accepted"). The Responder, after a failed readConfirm, has `confirmR` zeroed, so a second readConfirm with 32 zero bytes returns all-zero keys (Channel then refuses them). Not reachable by a remote peer: both connection paths stop calling the object after a throw (swarm.js onFailed → detach; stream-handshake.js fail → settled). But Initiator and Responder are exported. The fix would be to latch on failure as well as success.

## Group C verdicts (transfer.js before line 1170): 53 rows

Each GAP and most EQUIVALENT rows were confirmed by planting the mutant in a sandbox and comparing against the unmutated engine.

| survivor | verdict | why |
|---|---|---|
| transfer.js:87 integer + 1 (×4) | gap, remote | DEFAULT_MAX_SIZE, the documented 8 GiB cap (PROTOCOL.md:947); tests compare against the exported constant, so moving it moves the test |
| transfer.js:99, 100, 111, 132, 143 (×3), 151, 315 integer + 1 | constant (9) | timeouts and intervals moved by a millisecond or a small step; liveness bounds, not security limits |
| transfer.js:196 && to \|\| | gap, local hook | an onOffer error's code reaches the peer even when it is not a decline code; `throw null` sends no DECLINE, and the sender waits out its accept timeout |
| transfer.js:234 - to + | gap, local fs | a file that grows during hashing is hashed past `size`, so the receiver fails ERR_HASH_MISMATCH (the Q-16 guarantee) |
| transfer.js:238 - to + (×2) | unreachable | the hash stream reads 64 KiB chunks from 0, which divide PREFIX_BOUNDARY; only short reads (network, FUSE) would reach it |
| transfer.js:268, 355, 362 true to false | equivalent | idempotent finish steps; streams mark ended before emitting 'end' |
| transfer.js:276, 772 === to !== | equivalent | `unref` only affects process exit |
| transfer.js:364 && to \|\| | gap, low | a socket error with an empty message is reported as "" |
| transfer.js:369 \|\| to && | gap, low | streamx 'ending' without 'end' before 'close' is reported acked, not closed |
| transfer.js:385 false to true | gap, low | a rejected flush then close is reported acked |
| transfer.js:391 \|\| to && | gap, low | a flush that resolves false then close is reported acked |
| transfer.js:408 ! removed (×2), \|\| to && | gap, low | peerEnded false for an ended, unread, destroyed socket: 'lost' instead of 'closed' |
| transfer.js:408 true to false | gap | on streamx (Hyperswarm), a lost connection is reported as 'closed', the 2026-10-13 misreport |
| transfer.js:439 \|\| to && | gap, cosmetic | one key missing still refused, with a different message |
| transfer.js:469 integer + 1 | equivalent | emit(0) runs at construction |
| transfer.js:586 - to + | gap, local fs | a file that grows after the offer sends extra bytes; ERR_SIZE_MISMATCH |
| transfer.js:586 false to true | equivalent | the stream is opened once; the second close is caught |
| transfer.js:636 throw removed | gap, low | sendStream without a name writes a nameless MANIFEST instead of a TypeError |
| transfer.js:684 \|\| to && | gap | chunkSize 1.5, NaN, or 0 accepted; 0 makes sendStream loop forever |
| transfer.js:684 <= to < | gap | chunkSize 0 accepted |
| transfer.js:684 integer + 1 | gap | chunkSize 1 refused |
| transfer.js:690 throw removed | gap, low | a pre-aborted signal opens and hashes the file first (ENOENT instead of AbortError) |
| transfer.js:690 integer + 1 | gap, low | bytes 1 instead of 0 |
| transfer.js:732 throw removed | gap, important | an abort during hashing is lost: the MANIFEST goes out and the file is sent if accepted |
| transfer.js:732 integer + 1 | gap, low | bytes 1 instead of 0 |
| transfer.js:735 integer + 1 | gap, diagnostic | offer-phase errors report bytes 1 |
| transfer.js:742, 743 integer + 1 | equivalent | assigned before any read |
| transfer.js:790 true to false | equivalent | every source of a second fail is removed synchronously |
| transfer.js:796 true to false | gap, remote, harmless | a CHECKPOINT coalesced after RESULT calls onCheckpoint on a finished transfer |
| transfer.js:885 integer + 1 | gap, diagnostic | a stalled prefix phase reports bytes 1 |
| transfer.js:942 && to \|\| | gap, low | abort with no reason: the peer's CANCEL reason is "" instead of "cancelled by sender" |
| transfer.js:943 && to \|\| | gap, low | the AbortError's cause is the signal, not its reason |
| transfer.js:1130 true to false | equivalent | an AbortSignal fires once |
| transfer.js:1141 > to >= | equivalent | pushing 0 bytes does nothing |
| transfer.js:1141 integer + 1 | gap, remote, fails closed | a 1-byte `pending` after the handshake is dropped, and the transfer stalls |

Totals: 30 gap, 9 constant, 12 equivalent, 2 unreachable.

## Group D verdicts (transfer.js from line 1170): 65 rows

Each claim was confirmed by planting the mutant in a sandbox and probing both trees.

| survivor | verdict | why |
|---|---|---|
| transfer.js:1180 \|\| to && (×2), throw removed | gap, remote, low (3) | a MANIFEST of `null` gives a TypeError (DECLINE as ERR_RECEIVER_FAILED) instead of ERR_MANIFEST_INVALID `(root)`; arrays and primitives are blamed on field `v` |
| transfer.js:1210 integer + 1 | gap (first triaged as a constant) | refuses blockSize 1, which PROTOCOL.md allows; the new one-byte chunk-size test (sealed-transfer.test.js) fails on it |
| transfer.js:1223 > to >= | gap, remote | a size equal to the cap is declined (stricter, not a bypass) |
| transfer.js:1265 throw removed | unreachable | safeWriteName (names.js:183-219) refuses or rewrites every name that could leave the directory; deliberate backstop (transfer.js:1229-1237) |
| transfer.js:1334 false to true | equivalent | the only caller always passes `replace` |
| transfer.js:1341 <= to < | gap, local | with `a (1)`..`a (999)` present, the 1000th suffix is refused |
| transfer.js:1351 !== to === (ENOSYS, EXDEV, ENOTSUP) | gap, environment (3) | link-less filesystems are refused instead of falling back to check-then-rename |
| transfer.js:1351 throw removed | gap, environment | link() failing with EIO publishes anyway |
| transfer.js:1354 false to true | equivalent | only the number of link() calls changes |
| transfer.js:1367 throw removed | gap, local | with every suffix taken: an unhandled rejection, a receive that never settles, a .part left |
| transfer.js:1392 <= to < | gap, local | `.part.1000` refused |
| transfer.js:1460 \|\| to && | gap, security, local race | O_NOFOLLOW off: when the lstat/open race is lost, the payload is written through a symlinked .part (an authorized_keys file overwritten in the probe) |
| transfer.js:1463 ! removed, && to \|\| | equivalent on darwin/linux (2) | O_NOFOLLOW is nonzero there; win32 differs, and the symlink test is skipped on win32 |
| transfer.js:1479 - to + | equivalent | EOF clips the read |
| transfer.js:1482 integer + 1 | gap, local | a whole-file .part of size ≡ 1 mod 1 MiB is refused and the file re-sent |
| transfer.js:1511 \|\| to &&, > to >= | gap, hint only (2) | partialHint misreports a hard-linked, over-long, or exact-size .part; reopenPartial (1470) still refuses, but consent shows a misleading "resume:" line |
| transfer.js:1514 integer + 1 | gap, hint only | every resume offer without a .part reports partial 1 |
| transfer.js:1540 \|\| to &&, <= to < | gap, environment (2) | statfs reporting 0 free: declined instead of skipping the advisory check |
| transfer.js:1540 integer + 1 | constant | only free == 1 differs |
| transfer.js:1541 > to >= | gap | size == free is declined |
| transfer.js:1675 integer + 1 | gap, diagnostic | errors before ACCEPT report bytes 1 |
| transfer.js:1705, 1710 | equivalent (2) | assigned before any read |
| transfer.js:1718 integer + 1 | gap, diagnostic | a pre-aborted receive reports bytes 1 |
| transfer.js:1740 === to !== | gap, low | the stall timer is not unref'd, so a pending receive keeps the process alive |
| transfer.js:1786 && to \|\|, ! removed; 1791 ! removed | gap, remote (3) | a CANCEL or close in the PREFIX window leaks one file descriptor per offer |
| transfer.js:1791 && to \|\| | equivalent | fileHandle is always set there; a second close is caught |
| transfer.js:1801 && to \|\|, ! removed | gap, local (2) | when publish fails, the receive waits forever for a 'close' that already fired |
| transfer.js:1807 true to false | equivalent | every rm error is caught anyway |
| transfer.js:1822 > to >= | gap, remote | a connection dropped before any CHUNK keeps an empty .part |
| transfer.js:1822 integer + 1 | constant | resume policy for a 1-byte partial |
| transfer.js:1828 && to \|\| | equivalent | accepted implies writeStream |
| transfer.js:1828 ! removed | gap, remote | an interrupted resumable transfer leaks a descriptor and reports the partial before flushing |
| transfer.js:1884 true to false | gap, remote | a reset mid-file with resume discards the partial |
| transfer.js:1911, 1912 && to \|\| | gap, low (2) | abort without a reason: CANCEL reason "" and the cause is the signal |
| transfer.js:1992 && to \|\| | gap | checkSpace:false ignored when a size is declared |
| transfer.js:1994 - to + | gap, local | a resumed file asks for size+prior free space instead of size−prior |
| transfer.js:2066 === to !== | gap, low | the checkpoint interval is not unref'd |
| transfer.js:2082 false to true | gap, remote | a duplicate PREFIX is adopted twice (a stream leaked, three ACCEPTs) instead of ERR_PROTOCOL |
| transfer.js:2084 integer + 1 | gap, timing | a 1 ms stall timer during adopt fails a slow truncate |
| transfer.js:2095 \|\| to && (settled/checkpointing) | gap, slow disk | concurrent fsyncs and CHECKPOINTs that go backwards |
| transfer.js:2095 \|\| to && (writeStream/fileHandle) | equivalent | the timer exists only after both are set |
| transfer.js:2107 false to true | gap | one failed fsync stops checkpoints for good |
| transfer.js:2224 + to - | gap, security, remote | a stream can overshoot maxSize by about 2 × blockSize and is published |
| transfer.js:2224 > to >= | gap, remote | a stream of exactly the cap is refused |
| transfer.js:2228 + to - | gap, low | err.bytes wrong in the cap error |
| transfer.js:2254 true to false | gap, security, remote | frames after the final CHUNK in one segment are still processed; a bad digest plus a trailing CANCEL crashes the receiver process |
| transfer.js:2261 === to !== | gap, low | the socket stays paused after finalize |
| transfer.js:2282 > to >= | gap, trivial | a fresh transfer's mismatch message claims "resumed from byte 0" |
| transfer.js:2282 integer + 1 | constant | message only |
| transfer.js:2298 true to false | equivalent | resultBody ignores `ok` |
| transfer.js:2337 true to false | equivalent | 'abort' fires once |
| transfer.js:2343 > to >= | equivalent | pushing 0 bytes does nothing. Killed once in the rerun by a phase-1 failure that did not reproduce (0 of 6 replants; the unmutated tests passed 20 of 20, 8 of them under the runner's load) |
| transfer.js:2343 integer + 1 | gap (first triaged as a constant) | a 1-byte `pending` is dropped and the receive never completes, the receive-side twin of 1141 |

Totals, with the two corrections: 47 gap, 14 equivalent, 3 constant, 1 unreachable.
