# The CLI's output contract (W13)

**Implemented after 0.1.2, and not yet in a release.** The four decisions the draft left
open are recorded in §8.

What `ad-hal-send` and `ad-hal-receive` promise to a script: a receive
that writes the file to stdout, for `ad-hal-receive --stdout | tar x`,
and a `--json` mode that reports a drop as one JSON object per line. Both
are built on the error codes in [`PROTOCOL.md`](PROTOCOL.md) §10, which
are already the contract for anything automated, and both are CLI
behavior only: **nothing here changes the wire**, so `v2-final` stands.

The human-readable output stays what it was before W13, and stays free to
be reworded. Anything a script needs is in the exit status or the event
stream, never in the prose.

---

## 1. Exit status

Unchanged by W13, and now written down.

| Status | Meaning |
| --- | --- |
| `0` | The drop finished and was verified: on the receiver, the file matched the sender's digest; on the sender, the receiver confirmed it with RESULT carrying the same digest. |
| `1` | Anything else that ended the drop: a §10 failure, the peer's cancel (`ERR_CANCELLED_PEER`), a decline, a usage error, or an unreadable code. |
| `130`, `143`, `149` | Canceled locally by SIGINT, SIGTERM, or SIGBREAK (128 + the signal number; `cli/src/signals.js`). The peer was sent CANCEL. |

A script that needs to know *why* reads the event stream (§3), not the
status: the status says whether to trust the result, and the code says
what to do next. They are kept coarse on purpose, since an exit status
per §10 code would be a second list to keep in step with the first.

---

## 2. Receiving to stdout: `--stdout`

```
ad-hal-receive --stdout | tar x
ad-hal-receive --stdout --yes --code-stdin < code.txt > backup.tar
```

**A flag, not `-` as the output directory.** In `ad-hal-receive`'s
first position, `-` already means "read the code from stdin", so
`ad-hal-receive - -` would be legal and unreadable. `--stdout` cannot be
confused with either positional. It takes the place of `outputDir` and
cannot be combined with it, or with `--replace`.

### 2.1 What a consumer sees before the digest

**The bytes on stdout are not verified until the process exits 0.** On
disk, the receiver writes a `.part` and publishes it only after the
digest matches (PROTOCOL §4.3). A pipe cannot keep that property: `tar`
reads each byte as it arrives, and nothing can take a byte back once it
has been read.

How much that costs is narrower than it sounds. Every frame is opened by
the AEAD channel before a byte of it reaches stdout (PROTOCOL §3.4), so
what a consumer reads came from the peer that proved the code, in order,
unaltered in transit. What the final digest adds is the check that the
sender sent the file it declared, and that nothing was lost at the end.
So the failure a pipe can see in practice is **truncation**, from a
connection that dies mid-file, not tampering.

The contract, then:

- **Exit `0` is the only success.** A script must check it, with
  `set -o pipefail` in a shell pipeline, since a pipeline's status is
  otherwise its last command's.
- On a failure after the first byte, stdout is closed where it stopped,
  the exit status is nonzero, and the `failed` event (§3) says how many
  bytes were written (`bytes`).
- A digest mismatch is reported to the sender in `RESULT{error}`, as
  today, so the sender exits nonzero too (`ERR_RECEIVER_FAILED`).

Spooling to a temporary file and copying it out after the digest matches
would keep the on-disk property, at the cost of disk space, a second
pass, and the stream itself. Decision 1 in §8 chose streaming.

### 2.2 What `--stdout` changes about the drop

- **stdout carries the file's bytes and nothing else.** Every line the
  receiver prints otherwise, including the QR symbol, the generated code,
  the consent question, and progress, goes to stderr instead.
- **No resume.** There is no `.part` to resume from. The receiver leaves
  `resume` out of the capabilities it advertises. v2 already allows
  that: each side advertises a set, and what both act on is the
  intersection (`effectiveCaps` in `engine/src/handshake.js`), a function
  of the transcript as PROTOCOL §3.2 requires. So there is no
  `CHECKPOINT` and no `PREFIX`, and a
  sender holding an earlier partial for this name sends from byte 0.
- **The size limit applies, and the free-space check does not.**
  `ADHAL_MAX_SIZE` caps the output as it does a file, and a stream past
  it is stopped with `CANCEL{reason}` (PROTOCOL §4.3). There is no disk
  to check.
- **The name is reported, not used.** The offer's name is shown in the
  consent question and in the `offer` event, and still refused if it is
  unsafe (`ERR_UNSAFE_NAME`), so a wrapper that does use it gets the same
  guarantees as the engine.
- **Refused when stdout is a terminal**, the mirror of `ad-hal-send`
  refusing to stream from one: binary on a terminal is never what was
  meant.
- **Backpressure is honored.** A slow consumer slows the sender, as a
  slow disk does today.
- **A consumer that stops reading**, like `| head -c 100`, closes the
  pipe. The receiver sends `CANCEL{"the receiver's output was closed"}`
  and exits `1` with a CLI-level code, `ERR_OUTPUT_CLOSED` (§4).

Consent works as it does without `--stdout`: on a terminal it asks, on
stderr. With `-` or `--code-stdin`, stdin is the code, not a terminal, so
`--yes` is needed.

---

## 3. The event stream: `--json`

```
ad-hal-receive --json --yes
ad-hal-send --json - big.iso < code.txt
```

With `--json`, the human-readable lines are replaced, not supplemented,
by one JSON object per line (NDJSON), UTF-8, each ending `\n`.

**Where the events go.** To stdout, or to stderr when `--stdout` puts
the file on stdout (decision 2 in §8). Whichever stream they are on
carries no human-readable lines. Two other things can still land there:
a warning from Node itself, and the `drop code:` prompt when the code is
read from a terminal, which is on stderr. So **a line that does not
parse as a JSON object is not an event and must be ignored**.

**`--json` never asks whether to accept an offer.** An offer without
`--yes` is declined, with the reason the non-terminal case already
sends, and the `offer` event reports what was declined (decision 3).

### 3.1 Every event

```json
{"v":1,"event":"paired","ms":5212,"role":"receive","peer":"3fa29c0e81b2"}
```

| Field | Type | |
| --- | --- | --- |
| `v` | number | The schema version, `1`. On every line, so a line copied out of a log still says what it is. |
| `event` | string | One of §3.2. |
| `ms` | number | Milliseconds since the process started, from a monotonic clock. For durations, which is what W14 measures; wall-clock time is in `start` only. |
| `role` | string | `"send"` or `"receive"`. |

A **peer** is the first 12 hex characters of the candidate's ephemeral
public key, as the human lines print it today. It identifies a candidate
within one drop and nothing beyond it.

### 3.2 The events, in the order they can occur

| Event | Side | Fields | When |
| --- | --- | --- | --- |
| `start` | both | `version` (the CLI's), `time` (ISO 8601, UTC), `joinTimeout`, `refreshInterval` (ms), `stdout` (receive), `stream` (send) | First, once the arguments, the environment, and the code are accepted. A `failed` for one of those comes alone. |
| `code` | receive | `code`, `payload` (the QR payload) | Generated codes only, after `announced`. See the note below. |
| `announced` | receive | | The topic is announced and the code may be shown. |
| `candidate` | both | `peer` | A connection began the handshake. |
| `candidate-dropped` | both | `peer`, `code` (or null), `counted` (boolean), `paired` (boolean) | A candidate failed. `code` is a per-candidate code (`ERR_PAKE_CONFIRMATION`, `ERR_SID_REUSED`, `ERR_REPLY_UNANSWERED`, or a handshake failure), or null for a connection that closed with no error; `counted` is whether it counts toward the attempt cap, as the engine decided it. After `paired`, only counted failures are reported. |
| `drop-taken` | both | `peer` | A second peer proved the code after this side paired, and was told the drop is taken. |
| `warning` | both | `kind`, `message` | See §3.3. |
| `paired` | both | `peer` | The handshake completed with this peer. |
| `offer` | receive | `name`, `declaredName`, `size` (number or null), `sha256` (or null), `partial`, `risk` (string or null) | An offer passed the engine's checks and is about to be answered. |
| `accepted` | both | `resumeFrom` | The offer was accepted, and the file starts moving. |
| `progress` | both | `bytes`, `total` (number or null) | At most every 250 ms, plus one at the end. The count varies run to run: do not count them. |
| `done` | both | `name`, `declaredName`, `size`, `sha256`, `resumedFrom`, and on the receiver `path` and `published` (both null with `--stdout`) and `acknowledged` | The drop finished and was verified. Last line. |
| `failed` | both | `code` (or null), `message`, `bytes` (or null), and the error's own fields where set: `phase`, `reportedBy`, `peerReason`, `declineCode`, `detail`, `field`, `attempts`, `max`, `limit`, `size`, `expected`, `actual`, `partial`, and `socketError`, the transport's own message when it also reported one | The drop ended any other way. Last line. |

**Exactly one of `done` or `failed`, and it is the last line.** A stream
that ends without one means the process died, killed or crashed, and
the outcome is unknown. A second Ctrl-C is the one deliberate case: it
exits at once, without waiting for teardown, and so without a final
event. Exit `0` comes with `done`, and every nonzero status with
`failed`. `message` is the sentence the human output would have
printed, already escaped for a terminal.

The receiver's `done` comes after it waits for the sender to acknowledge
RESULT, so it can carry `acknowledged`: `false` when the sender never
confirmed it, which today is a `note:` line. The file is already
verified and saved by then, so the wait delays the event, not the data.

**The `code` event carries the secret**, since the code is the secret.
It is the receiver's own generated code, which the human output already
prints to stdout for a person to read out, so this is the same exposure
in a different shape. But a log that keeps the event stream keeps the
code: a wrapper should show it and not store it.

### 3.3 `warning` kinds

| `kind` | Today's line |
| --- | --- |
| `not-anonymous` | `note: not anonymous: ...` (Q-09), always, at start |
| `risky-name` | `WARNING: "x.pdf.exe" is a program ...` (`cli/src/consent.js`) |
| `contention` | The pattern lines in `cli/src/contention.js` (Q-04), with `failed`, `silent`, and `keys` as numbers |
| `check-then-rename` | The no-hard-links note (Q-19) |
| `code-on-argv` | The note that a code passed with `--code-on-argv` is in the shell history and visible to `ps` |

New kinds may be added (§5). A consumer that does not know a kind should
show its `message`.

### 3.4 Strings the peer chose

`declaredName`, `peerReason`, `detail` on `ERR_UNSAFE_NAME`, and the
`message` of an error that quotes the peer carry text the other end
chose. The engine has already capped and sanitized the reasons, but a
declared name is reported as the peer sent it, because a wrapper may
need the real value. JSON escapes C0 control characters, not bidi
overrides or C1 controls. **A consumer that displays one of these must
escape it first**, as the human output does with `displayName`
(Q-11).

---

## 4. Codes

`failed.code` is one of:

- A PROTOCOL §10 code. The list there is authoritative.
- A Node system error's own code, such as `ENOSPC` or `EACCES`, for a
  failure the engine did not raise itself: a disk that filled, say. It
  is null when the error had no code at all.
- One of three CLI-level codes, which say how the process ended, not how
  the drop did, and are not in §10 for that reason:

| Code | Meaning |
| --- | --- |
| `ERR_USAGE` | A flag, an argument, or an environment variable was wrong. Nothing touched the network. |
| `ERR_CODE_INVALID` | The code could not be read or resolved: a mistyped word, the wrong count, or an opaque code without `--insecure-opaque-code`. Nothing touched the network. |
| `ERR_OUTPUT_CLOSED` | With `--stdout`, the consumer closed the pipe. The peer was sent CANCEL. |

A usage error and an unreadable code are a plain `Error` in the code,
and in the human output its message is the only report. They get codes
here because a script switching on `failed.code` needs one. With
`--stdout`, `ERR_OUTPUT_CLOSED` is what `EPIPE` on stdout is reported as.

---

## 5. What is stable

Under `"v": 1`:

- **Added, without a version change:** an event, a field on an event, a
  `warning` kind, a §10 code, and a CLI-level code. A consumer must
  ignore events and fields it does not know, and treat an unknown code
  as a failure it cannot classify.
- **A breaking change, which bumps `v` and the CLI's major version:**
  removing or renaming an event or field, changing a field's type or
  meaning, or changing what an exit status means.
- **Never stable:** `message`, and every human-readable line. That is
  §10's rule, kept: nothing may match on prose.

---

## 6. What it took from the engine

Four API additions, none of them on the wire:

- **`receiveFile` takes a writable sink** in place of an output
  directory, writing through it with backpressure and skipping the
  `.part`, the free-space check, and publishing. The digest is still
  computed, checked against the manifest or END, and reported in RESULT.
- **`acceptOnce` takes `caps`**, so a stdout receiver can advertise
  `["stream"]` without `resume`. The handshake classes already accept
  `caps`; `acceptOnce` does not pass it through yet.
- **`sendFile` and `sendStream` take `onAccepted`**, so the sender can
  report `accepted` and its `resumeFrom` when ACCEPT arrives, not only at
  the end.
- **`onCandidateDropped` gets a fourth argument, `counted`**, the
  engine's own decision. The CLI could have re-derived it from the code,
  but that would be the second copy of a rule `engine/src/swarm.js` keeps
  in two places already.

A sink's write error is told to the sender as `CANCEL{reason}`, so the
sender reports `ERR_CANCELLED_PEER` with `"the receiver's output was
closed"` rather than a dropped connection.

---

## 7. How it is tested

- **`cli/test/json-events.test.js`** carries §3.2's table as code,
  `checkEvent`, and every line every test there reads goes through it, so
  a field that drifts fails a test rather than a consumer. Its fast half
  checks the stream itself: one valid line per event, including for a
  name carrying controls, a bidi override, and a lone surrogate;
  progress throttled without losing the last count; `failed.code` taken
  from `err.code` and never from the message; and consent under `--json`
  declining without writing to the terminal.
- Its slow half runs both CLIs on a local testnet: `--stdout --json`,
  where stdout is the file byte for byte and the event stream is the
  only thing on stderr; `--json` without `--yes`, where both sides end
  in `ERR_DECLINED` and nothing is written; a generated code's `code`
  event, and a Ctrl-C ending in `ABORT_ERR`; usage and code errors; a
  reader that closes stdout after the first bytes, ending in
  `ERR_OUTPUT_CLOSED` on the receiver and `ERR_CANCELLED_PEER` with the
  reason on the sender; and `--stdout` without `--json`, where the human
  lines are on stderr.
- **`cli/test/sink.test.js`** tests the engine's half over a duplex
  pair: a file and a stream into a sink, against a slow reader; a digest
  mismatch, reported to the sender after the sink has the bytes; an
  unsafe name, refused before any byte; a sink error, reaching the
  sender as CANCEL; `onAccepted`, once and before any byte; and a
  receiver that leaves `resume` out of its caps, paired without it.
  Three of those were checked by planting the bug each one is for.
- `engine/scratch-trials.js` is unaffected: it drives the engine
  directly, not the CLIs. W14's harness for the other tools is what
  consumes `--json`.

---

## 8. Decisions

Settled on 2026-10-28, before the code was written.

1. **Stream through, not spool first.** Bytes reach stdout as they
   arrive, and only exit `0` means verified (§2.1). Spooling to a
   temporary file would keep the on-disk guarantee, but it gives up the
   stream, needs the disk space, and doubles the I/O, and a pipe that
   waits for the whole file is not what `| tar x` is for. The AEAD
   channel already rules out tampering in transit. A `--verify-first`
   spool could still be added without a version change.
2. **Events on stdout, and on stderr only when `--stdout` takes
   stdout** (§3). Stderr always would be one rule instead of two, but it
   is also where Node writes its own warnings, and stdout is where
   `--json` goes in most tools, including this repository's conformance
   adapters ([`CONFORMANCE.md`](CONFORMANCE.md)).
3. **`--json` never asks.** An offer without `--yes` is declined. A
   control channel on stdin, for a wrapper that decides per offer, is
   left to the desktop app in Stage 3, where it has a user.
4. **`ERR_OUTPUT_CLOSED` exits `1`**, not `141`. A shell killed by
   SIGPIPE reports `141`, but this process is not killed: Node ignores
   SIGPIPE, sees `EPIPE`, and the event says what happened.
