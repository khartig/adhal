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

It is also the direct input to two things the plan already asks for:

- Section 8's primary gate — *Transfer success (direct or relay) ≥ 75%*,
  kill/pause below 50% — and *10 MB median time, good path < 30–45s*.
- Section 9 spike 1 — measuring *your* punch rate on a genuinely hostile
  network pair.

## What it does per trial

1. Derives a fresh drop code from `sha256("quay-trial:<seed>:<index>")`.
2. Creates a **new** Hyperswarm and joins the topic for that code.
3. Receiver: `acceptOnce` → `receiveFile` into a temp dir, then compares the
   hash it computed off the wire against the hash in the sender's manifest.
4. Sender: `connectOnce` → `sendFile`.
5. Tears the swarm down, deletes the received file, records the outcome and
   timings, and waits for the next slot.

Each trial gets a fresh swarm and a fresh topic, so no stale announce from
trial *n* can affect trial *n+1* — a documented failure mode in
[`ARCHITECTURE.md`](ARCHITECTURE.md) and one that would otherwise make later
trials look worse than earlier ones.

## Running it

Both machines need the repo at the same commit, `pnpm install` run, and
outbound UDP to Hyperswarm's bootstrap nodes. The harness always uses the
**public DHT** — there is no bootstrap override, because the point is to
measure the real network.

**On the receiving machine:**

```bash
cd ~/quay && git pull
node engine/scratch-trials.js --role receiver --seed run1 --trials 10 \
  --out ~/rx-trials.json 2>&1 | tee ~/rx-trials.log
```

**On the sending machine**, started within about a minute:

```bash
cd ~/quay && git pull
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
   from `(seed, index)`, so neither has to be told anything. They are
   deliberately opaque secrets rather than six-word codes: a topic is a
   32-byte hash either way, `resolveCode` handles both, and word parsing is
   already covered by `cli/test/code.test.js`. Nothing about the
   measurement changes.
2. **Trials are pinned to wall-clock slots, not to each other's progress.**
   If each side advanced when *its own* trial finished, a fast failure on
   one side against a slow timeout on the other would desynchronise them,
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

>> 80% meets plan section 8's >=75% bar for this path.
   2 trial(s) never saw a peer -- intermittent discovery or punch
   failure, which is what makes a single failing run look like a bug.
```

Both roles measure connect time from the same instant (the moment the
sender is scheduled to dial), so their numbers are directly comparable. If
they disagree by much, something is wrong with the run itself.

### Failure classes

| Outcome | Meaning | Where to look |
| --- | --- | --- |
| `ok` | Transferred, and the receiver's hash matched the manifest | — |
| `no-peer` | Timed out having seen **no** connection | Discovery or hole punching. Intermittent = flaky path; every trial = check both sides are really on the same topic. |
| `no-handshake` | Peers connected but none completed READY/ACK | **Our code**, not the network. Start at `acceptOnce`/`connectOnce` in `engine/src/swarm.js`. |
| `transfer-error` | Connected and handshake fine; the transfer threw | `engine/src/transfer.js`, framing or backpressure |
| `hash-mismatch` | Completed, but the hash differs from the manifest | **Correctness bug. Stop feature work.** |
| `timeout-other` | Timed out without a recognised reason | Read the `error` field in the JSON |
| `skipped` | The slot was already over when the trial began | Clock skew, or `--slot` too short |

`no-peer` versus `no-handshake` is the distinction that matters most, and it
is the one the codebase previously could not make: both used to report
`timed out looking for a peer`, which sent an investigation at the DHT when
the DHT was fine. See `timeoutMessage` in `engine/src/swarm.js`.

**`hash-mismatch` is categorically different from the others.** Everything
else is a delivery failure; this is silent corruption. It is never folded
into "failed" and should never be treated as a network statistic.

### What the rate means

The summary interprets itself against the plan's own thresholds:

| Rate | Reading |
| --- | --- |
| ≥ 75% | Meets section 8's bar for this path. Relay is not yet on the critical path here. |
| 50–75% | The path is **flaky, not broken**. Expect single runs to fail; do not read a code bug into them. |
| < 50% | Below section 8's kill threshold. Relay quality (section 4 item 9) is the product, not an optional extra. |
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
- The harness measures the **direct** path only. There is no relay yet
  (section 4 item 9), so a low rate here is exactly the evidence that would
  justify building one.

## Recording results

Keep the JSON. `docs/ARCHITECTURE.md` records measured network findings, and
a rate with a date, a network pair and a trial count is worth far more than
"it worked when I tried it" — which is what this tool exists to replace.
