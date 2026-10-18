# Measuring transfer reliability (`scratch-trials.js`)

How to run `engine/scratch-trials.js`, what its numbers mean, and what to do
with each result.

## Why this tool exists

Every wrong conclusion in this project's cross-ISP debugging came from
reasoning about **single runs**.

One failure looks like a bug. One success looks like a fix. On a path that
is only intermittently able to hole punch, neither is true. A concrete
example from this repo's history: a Starlink → Comcast drop failed
repeatedly with no connection on either side; two code hypotheses were
formed, investigated, and both disproven; the same code then worked with no
functional change. Roughly a day went into looking for a defect that the
evidence never supported. A 70%-reliable path and a broken one are
indistinguishable from one run, and nothing in the repo could tell them
apart.

This tool is that missing instrument. It runs N real drops back to back and
reports a **rate**, a **timing distribution**, and a **classified reason for
every failure**.

**The reliability bar** it measures against, stated here because this is
where it is used. An earlier plan set these figures, and that plan's
section on them no longer exists:

- *Transfer success (direct or relay) ≥ 75%* on a path. Below 50%, relay
  quality is the product rather than an optional extra, and work on the
  path pauses until that is decided.
- *A 10 MB drop on a good path: median under 30–45 s.*

It is also what W14 (`IMPLEMENTATION-PLAN.md`) reuses to measure the punch
rate head to head, on genuinely hostile network pairs.

## What it does per trial

1. Derives a fresh drop code from `sha256("adhal-trial:<seed>:<index>")`.
2. Creates a **new** Hyperswarm and joins the topic for that code.
3. Receiver: `acceptOnce` → `receiveFile` into a temp dir, then compares the
   hash it computed off the wire against the hash in the sender's manifest.
4. Sender: `connectOnce` → `sendFile`.
5. Tears the swarm down, deletes the received file, records the outcome and
   timings, and waits for the next slot.

Each trial gets a fresh swarm and a fresh topic, so no stale announce from
trial *n* can affect trial *n+1* — a documented failure mode in
[`history/ENGINEERING-LOG.md`](history/ENGINEERING-LOG.md) and one that would otherwise make later
trials look worse than earlier ones.

## Running it

Both machines need the repo at the same commit, `pnpm install` run, and
outbound UDP to Hyperswarm's bootstrap nodes. The harness always uses the
**public DHT** — there is no bootstrap override, because the point is to
measure the real network.

**On the receiving machine:**

```bash
cd ~/adhal && git pull
node engine/scratch-trials.js --role receiver --seed run1 --trials 10 \
  --out ~/rx-trials.json 2>&1 | tee ~/rx-trials.log
```

**On the sending machine**, started within about a minute:

```bash
cd ~/adhal && git pull
head -c 10485760 /dev/urandom > /tmp/test.bin
node engine/scratch-trials.js --role sender --seed run1 --trials 10 \
  --file /tmp/test.bin --out ~/tx-trials.json 2>&1 | tee ~/tx-trials.log
```

10 trials at the default 135s slot takes about **23 minutes**, unattended.

### Check this before walking away

Both sides print a line like:

```
+0.0s slot start: 1789657432 (8:03:52 AM) <-- MUST MATCH ON BOTH MACHINES
```

**If the two numbers differ, kill both and restart with an explicit
schedule.** A mismatch means the two sides run different trials at the same
time, and the run reports 0% while the path is perfectly fine:

```bash
# pick a time ~2 minutes out and pass the SAME value to both
node engine/scratch-trials.js --start-epoch 1789657700 ...
```

Clocks should be NTP-synced. They almost certainly are; if one host is
minutes off, use `--start-epoch` computed on that host.

## Options

| Flag | Default | Meaning |
| --- | --- | --- |
| `--role` | *required* | `receiver` or `sender` |
| `--seed` | *required* | Any string. **Must match on both sides.** Determines all trial codes. Use a new seed per run. |
| `--trials` | `10` | Number of drops. **Must match on both sides.** |
| `--file` | *required for sender* | The file to send each trial. Created once, reused. |
| `--slot` | `135` | Seconds per trial. See below before changing. |
| `--refresh` | engine default (4000) | Overrides `REFRESH_INTERVAL` in `engine/src/swarm.js` for the run. |
| `--start-epoch` | next 5-min boundary ≥1 min out | Unix seconds. Pin the schedule explicitly. |
| `--out` | — | Write per-trial JSON here. |
| `--record-addresses` | off | Keep IP addresses (public host and port, the peer's address) in the log and JSON. Off because these files get committed; without it, each address is recorded only as its kind. |
| `--lookup-isp` | off | Record the AS (number, name, country) that this side's DHT-observed public address belongs to. **Sends that address off the machine**, as a DNS query to Team Cymru's IP-to-ASN service, which is why it is off. The address itself is not recorded. |
| `--note <text>` | — | Free text for the log and JSON, for what the machine cannot detect: the router's firewall settings, the uplink beyond the first hop. Repeatable. |

### Why `--slot` defaults to 135

The sender's per-trial budget is `slot − 10s sender lead − 5s teardown`. At
135 that is **exactly 120s, matching `swarm-send.js`'s default join
timeout** — so the harness measures what a real drop would experience.

Lowering it makes runs faster but **cuts trials off earlier than the real
CLI would give up**, under-reporting the success rate. If you want a quick
smoke run, `--slot 60` is fine, but do not quote its rate as the path's
reliability. Raise it above 135 for large files or a very slow path.

### Two design constraints worth knowing

The two ends are on different machines with **no channel between them**.

1. **Codes are derived, not exchanged.** Both sides compute the same code
   from `(seed, index)`, so neither has to be told anything.

   **They are real five-word codes as of W11, and that is a correctness
   fix rather than tidying.** They used to be opaque `trial-<hex>`
   secrets, on the reasoning that "a topic is a 32-byte hash either way".
   That stopped being true under v2: an opaque code becomes its own
   nameplate *and* its own secret, so every trial would have run down the
   `--insecure-opaque-code` path — publishing each trial's secret in its own
   announced topic and measuring a configuration no user can reach. The
   instrument would have been measuring something other than the product.
   The derivation from `(seed, index)` is unchanged in spirit and
   rejection-sampled over the word list, so the "neither side has to be
   told the codes" property survives.
2. **Trials are pinned to wall-clock slots, not to each other's progress.**
   If each side advanced when *its own* trial finished, a fast failure on
   one side against a slow timeout on the other would desynchronize them,
   and every later trial would fail on mismatched topics — reporting 0% for
   a working path. Slot alignment makes that drift impossible.

## Reading the output

Per trial:

```
+27.1s trial 1/10: ok connect=2.3s total=2.4s
+162.3s trial 2/10: no-peer -- timed out after 120000ms looking for a peer: no peer ever connected (...)
```

Then a summary:

```
=== SUMMARY ===
role: sender   seed: run1   trials: 10   refresh: 4000ms
succeeded: 8/10  (80%)
connect time: median 7.4s  p90 19.1s  min 5.2s  max 22.0s
failures:
  no-peer                 2

>> 80% meets the >=75% reliability bar for this path.
   2 trial(s) never saw a peer -- intermittent discovery or punch
   failure, which is what makes a single failing run look like a bug.
```

Both roles measure connect time from the same instant (the moment the
sender is scheduled to dial), so their numbers are directly comparable. If
they disagree by much, something is wrong with the run itself.

Each `ok` line also says how that side's wait after the transfer ended,
as `close=<outcome>(<seconds>)`, and the summary counts them. `total` stops
before this wait on both sides.

- **Sender:** `closed` or `timer`. A `timer` is a receiver that confirmed
  the file and then took more than 5s to close: harmless.
- **Receiver** (`closeAfterResult` in `engine/src/transfer.js`): one of
  four outcomes.
  - `closed`: the sender ended its side. It does that only once it has
    read RESULT, so this is the one outcome that means the sender has its
    confirmation.
  - `acked`: the sender's transport acknowledged RESULT, but the sender
    did not end. Harmless.
  - **`lost`**: the connection closed with neither an end nor an
    acknowledgment. The sender probably never got RESULT.
  - **`timeout`**: nothing happened within 60 s. Same meaning as `lost`.

  After `lost` or `timeout`, the sender's record for that trial is
  probably a `phase: result` failure for a file this side saved, and the
  summary lists those trials. The JSON adds `closeWaitAcked` and
  `closeWaitError`, the socket's own error (e.g. "connection timed out").

  `lost` is new since 2026-10-13. Before it, any close counted as
  `closed`, and in run A trial 10 that day a connection that died 2.2 s
  after RESULT was reported as the sender's reply.

### What each side's network looked like

Added after the 2026-10-13 run, whose rate could not be read without knowing
what kind of pair it measured. **Each machine sees only its own NAT, so read
both logs.** The header says:

```
build: commit 643ffeb90d72 (clean)  hyperswarm 4.17.1  hyperdht 6.34.0  udx-native 1.21.1  os darwin 25.5.0
interfaces: 1 IPv4, global IPv6 no
os: macOS 26.5.2 (25F84)
access: wifi via en0 (Wi-Fi)
vpn: not on the route; services: ProtonVPN disconnected
host firewall: disabled, stealth mode off (macOS application firewall; pf not checked, it needs root)
nat at start: consistent, port preserved, firewalled, 16 samples
isp: AS7922 COMCAST-7922 - Comcast Cable Communications, LLC, US
note: eero firewall on
```

- **`build`** is the commit and the transport versions, so a write-up no
  longer has to say "the commit was not recorded". `UNCOMMITTED CHANGES`
  means the run measured code that is not in any commit.
- **`nat`** is from the DHT's sampling of the addresses other nodes see us
  at.
  - `consistent`: they agree on a host and port. Hole punching relies on
    this mapping. `port preserved` is the easiest version of it.
  - `randomized`: a new external port per destination, the hard case. Two
    randomized sides cannot be punched without a relay.
  - `unknown`: too few samples agree yet.
  - `firewalled`: unsolicited packets do not reach this machine, which is
    normal behind any home router.
- **`interfaces`** counts addresses without recording them. Global IPv6
  matters because the DHT and its punching are IPv4. An address in the
  CGNAT range (100.64/10) is called out: the machine sits directly on a
  carrier NAT. Behind a home router a CGNAT is upstream and not visible.
- **`os`** is the product version (`sw_vers`, `/etc/os-release`), which
  the kernel release on the `build` line is not.
- **`access`** is the interface the route to the internet leaves by, and
  its kind: `wifi`, `ethernet`, `cellular`, `tethered`, `vpn`, or
  `virtual` (a container or VM). A gateway at an iPhone or Android
  hotspot's fixed address is flagged as a likely hotspot.
- **`vpn`** says whether that route goes through a tunnel, and on macOS
  lists the configured VPN services and their state.
- **`host firewall`** is this machine's own firewall, read without root:
  the application firewall on macOS; ufw, firewalld, and nftables on
  Linux. The router's firewall is not visible from the host. Put it in a
  `--note`.
- **`isp`** appears only with `--lookup-isp`.

These were added on 2026-10-14. All of them, and the slot start, file, and
start and end times, are also in the JSON's `environment` block.

### Writing up a run: `ENVIRONMENT.md`

Put both machines' JSON (and logs) in one directory, then:

```bash
node engine/scratch-trials-environment.js <run-dir>            # print
node engine/scratch-trials-environment.js <run-dir> --write    # write <run-dir>/ENVIRONMENT.md
```

It fills in everything the harness recorded and marks the rest `FILL IN`,
so `grep 'FILL IN'` lists what is left to write by hand. It groups files
into runs by seed and calls the receiver of the first run Machine 1,
which is [`TESTING.md`](TESTING.md)'s convention. A **Checks** section
lists what would make the run hard to read: the two sides' seeds, trial
counts, slots, or start times disagreeing, different commits, uncommitted
changes, a NAT that changed, a same-LAN connection, two randomized NATs.
`--write` does not replace an existing `ENVIRONMENT.md` without `--force`.
For JSON from before 2026-10-14 it reads what it can from the logs.

Every trial records the same NAT snapshot from its own swarm, plus the
connection's UDX counters: round-trip time, retransmits, RTO count,
packets and bytes each way, MTU. The trial line shows the short form,
`nat=consistent path=public rtt=48ms retx=0 rto=0`. Read `retx` and `rto`
beside a slow or failed trial. `path` is the kind of address the peer
connected from. `private` means the same LAN, which is not a punch across
the internet at all. The summary counts the NAT kinds across trials and
flags a NAT that changed during the run.

### Failure classes

| Outcome | Meaning | Where to look |
| --- | --- | --- |
| `ok` | Transferred, verified by the engine, and cross-checked here | — |
| `no-peer` | Timed out having seen **no** connection | Discovery or hole punching. Intermittent = flaky path; every trial = check both sides are really on the same topic. |
| `no-handshake` | Peers connected but none completed the readiness handshake | **Our code**, not the network. Start at `acceptOnce`/`connectOnce` in `engine/src/swarm.js`. |
| `attempt-cap` | The drop was burned after 100 failed PAKE confirmations | Should never appear in an unattended run on a private topic. If it does, the run is not measuring the network at all — somebody reached the nameplate and spent the drop's hundred guesses. |
| `transfer-error` | Connected and handshake fine; the transfer threw something with no code | `engine/src/transfer.js`. An uncoded error reaching this bucket is itself a small bug — see below. |
| `hash-mismatch` | The engine rejected the file: its bytes do not match the manifest digest | **Correctness bug. Stop feature work.** |
| `hash-crosscheck-disagreed` | The engine *accepted* a file this harness says is wrong | **Worse. The verification itself is broken** — `finalize()` in `engine/src/transfer.js`. |
| `size-mismatch` | The peer sent more, or fewer, bytes than its manifest declared | `engine/src/transfer.js` |
| `stalled` | The peer proved the code and then stopped sending, or never answered the offer or the last byte | A path that died without the transport noticing. The record's `error` and `phase` say which. |
| `receiver-failed` | Sender only: every byte arrived and the receiver could not keep the file | The receiver's record for the same trial: its digest disagreed, or landing the file failed. |
| `declined` | Sender only: the receiver refused the offer before any byte moved | This harness's receiver asks no person, so the reason is the engine's: a name, a size, the disk. The receiver's record says which. |
| `no-space` / `exists` | Receiver only: the declared size does not fit, or no partial could be opened without destroying a file | The receiving machine's disk or output directory, not the path |
| `drop-taken` | Another peer holding this trial's code paired first | Should never happen on a derived private code. Another machine is running the same `--seed`. |
| `connection-lost` | The socket closed or reset before the transfer finished | A punch that died mid-transfer. Before the failure-reporting work this hung forever instead of being counted. A reset carries the transport's own error as `cause`; on the sender, `phase: 'result'` means every byte went out and the receiver's record is the only one that knows whether the file landed. Until 2026-10-12 a reset arrived uncoded and was counted as `transfer-error`. |
| `unsafe-name` / `manifest-invalid` / `protocol-error` | The peer's manifest or framing was refused | On a private topic, almost always a build-version skew between the two hosts |
| `cancelled-by-peer` / `cancelled-locally` | Someone stopped the drop deliberately | Not a failure of the path. Should be zero in an unattended run. |
| `timeout-other` | Timed out without a recognized reason | Read the `error` field in the JSON. A coded engine error should never land here or in `transfer-error`; if one does, give it a row. |
| `skipped` | The slot was already over when the trial began | Clock skew, or `--slot` too short |

**`bad-proof` is gone, and its removal is worth recording** because it was
the last piece of prose-matching in this harness. It counted peers rejected
for not proving they knew the code, and it was matched by regex against an
error *message* — the exact coupling `engine/src/errors.js` exists to
remove. It was also already dead: a drop whose candidates all failed
reports `ERR_NO_HANDSHAKE`, which the table above catches first.

Failed PAKE confirmations are **per-candidate events, not trial
outcomes** — a trial can succeed having rejected several peers first, which
is the behavior the attempt cap relies on. So they are counted where they
happen, off the code `ERR_PAKE_CONFIRMATION`, and reported separately as a
`badConfirmations` total per trial plus one summary line. On a private
topic that total should be zero; a non-zero one means peers reached the
nameplate without the secret, i.e. a build skew between the two hosts or
somebody else on the topic. Check that before reading anything else in the
run.

`no-peer` versus `no-handshake` is the distinction that matters most, and it
is the one the codebase previously could not make: both used to report
`timed out looking for a peer`, which sent an investigation at the DHT when
the DHT was fine. See `timeoutMessage` in `engine/src/swarm.js`.

**`hash-mismatch` is categorically different from the others.** Everything
else is a delivery failure; this is corruption. It is never folded into
"failed" and should never be treated as a network statistic.

### How these are classified, and why it changed

Two things moved.

**Classification is keyed on `err.code`, not on error messages.** It used
to regex-match the text of an error, which coupled the only measurement
instrument this project has to prose: rewording a sentence in
`engine/src/swarm.js` would silently re-bucket results and nothing would
have said so. The codes live in `engine/src/errors.js`. The regexes remain
only as a documented fallback for errors that predate the vocabulary — a
raw socket error, or something thrown by a dependency. **If an Adhal error
starts landing in `transfer-error`, the fix is to give it a code, not to
add a pattern.**

**Hash verification moved into the engine, which changed what this tool
measures.** `receiveFile` now compares the received file against the
manifest itself, so a corrupted transfer arrives as a *rejection* rather
than as a successful receive with a mismatching digest. Without the
`ERR_HASH_MISMATCH` mapping that would land in `transfer-error`, and the
loudest output this tool has — `>> N HASH MISMATCH(ES) ... stop feature
work` — would never have fired again. That is an easy failure to miss,
because nothing would look broken; the alarm would simply be silent.

The harness's own comparison is kept, now as a labeled cross-check
reported as `hash-crosscheck-disagreed`. Reaching it means the engine
verified the file and an independent comparison disagrees, which cannot be
a corrupt transfer — the engine would have rejected it — and can only be a
bug in the verification. The summary calls that out ahead of everything
else.

### What the rate means

The summary interprets itself against the reliability bar above:

| Rate | Reading |
| --- | --- |
| ≥ 75% | Meets the reliability bar for this path. Relay is not yet on the critical path here. |
| 50–75% | The path is **flaky, not broken**. Expect single runs to fail; do not read a code bug into them. |
| < 50% | Below the kill threshold. Relay quality is the product, not an optional extra. |
| < 5 trials | Not a rate. Use `--trials 10` or more. |

## Answering a specific question: does the refresh interval matter?

`REFRESH_INTERVAL` in `engine/src/swarm.js` is 4000ms. That value was
validated only with **both peers on one machine**, where the hole punch is
trivial. For a peer joined with `server: true`, each refresh issues a DHT
*announce*, so a 4s interval re-registers holepunch relay state
continuously — a plausible problem on two firewalled NATs that does not
exist locally.

Single cross-ISP runs succeeded at both 4000 and 30000. That proves neither
value is fatal and says **nothing** about which yields a better rate. To
settle it, run the same seed count twice and compare:

```bash
# both machines
node engine/scratch-trials.js ... --seed ab-4000  --refresh 4000
node engine/scratch-trials.js ... --seed ab-30000 --refresh 30000
```

Use a different `--seed` per arm so the two arms never share topics. Do not
change the default in `swarm.js` on anything less than this.

## Interpreting honestly

- **10 trials is a small sample.** 8/10 is consistent with anything from
  roughly 50% to 95% true reliability. Treat it as "roughly 80%", not
  "exactly 80%", and prefer 20+ trials before a go/no-go decision.
- **A rate is specific to one network pair, at one time of day.** Starlink
  is a LEO satellite link; weather and satellite handover are real
  variables. Re-measure rather than assuming a number holds.
- **Both sides should report the same successes.** If the sender says `ok`
  and the receiver says `hash-mismatch`, believe the receiver — it is the
  side that verified.
- The harness measures the **direct** path only. There is no relay yet, so
  a low rate here is exactly the evidence that would justify building one.

## Recording results

Keep the JSON. `docs/ARCHITECTURE.md` records measured network findings, and
a rate with a date, a network pair, and a trial count is worth far more than
"it worked when I tried it" — which is what this tool exists to replace.
