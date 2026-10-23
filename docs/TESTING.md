# Testing

How to run Adhal's tests, which command to reach for when, and how to test
a real drop between two machines on different networks.

There are two kinds of testing here, and they answer different questions:

- **On one machine**, the test suite checks the code. Peers talk over
  in-memory streams, loopback TCP, or a DHT testnet on localhost. Nothing
  touches the public network.
- **Across two machines**, the CLIs and `engine/scratch-trials.js` check
  the network: discovery and hole punching on the public DHT, between two
  real NATs. The suite cannot see a problem there, and one drop cannot
  tell a flaky path from a broken one.

## Before you start

- Node.js 24 or later (`node -v`). On 22.x six timer tests are reported
  canceled rather than run.
- pnpm, at the version pinned by `packageManager` in `package.json`. With
  `corepack enable`, the `pnpm` command runs exactly that version. See
  [`SETUP.md`](SETUP.md).
- Dependencies installed exactly as locked:

  ```bash
  pnpm install --frozen-lockfile
  ```

All commands below run from the repository root.

## On one machine

### The commands

| Command | What it runs | Time |
| --- | --- | --- |
| `pnpm run test:fast` | Every test except those marked `slow` | ~12 s |
| `pnpm test` | Everything, including DHT testnets and child processes | ~2 min |
| `pnpm typecheck` | `tsc --noEmit` over the JSDoc types | seconds |
| `pnpm fuzz` | The fuzz harness at 100,000 iterations per target | long |
| `pnpm conformance` | The conformance harness against this repository's engine ([`CONFORMANCE.md`](CONFORMANCE.md)) | ~40 s |
| `node tools/mutate.js` | Mutation testing over the security-critical engine modules | ~1 h |
| `pnpm audit --audit-level moderate` | Known advisories in the locked dependencies, at the level CI fails on ([`DEPENDENCY-POLICY.md`](DEPENDENCY-POLICY.md)) | seconds |

`pnpm test` and `pnpm run test:fast` run `node --test` in `cli/`, where
most tests live (`cli/test/`), and then in `conformance/`
(`conformance/test/`). The helpers the CLI tests share are in
`cli/test-helpers/`, outside `cli/test/` so the runner does not count them
as tests.

### The two tiers

A test is in the slow tier when it needs a DHT testnet or spawns a CLI
process. It is marked with `slow` from `cli/test-helpers/tiers.js`:

```js
test('a dropped candidate is never counted', slow, async (t) => { ... })
```

`ADHAL_FAST=1` skips those tests and reports them as skipped, which is all
`test:fast` does. Nothing else differs, so a fast-tier pass is a real pass
of every fast test, not a smoke test.

CI runs both tiers on Ubuntu 24.04 and macOS, which must pass, and on
Windows and Ubuntu 26.04, which are advisory. It runs the fast tier first,
so an obvious break is reported in seconds.

### Running part of the suite

One file:

```bash
node --test cli/test/progress.test.js
```

One test, by a regular expression over its name:

```bash
node --test --test-name-pattern="logged while the bar" cli/test/progress.test.js
```

A file without its slow tests:

```bash
ADHAL_FAST=1 node --test cli/test/attempts.test.js
```

### Fuzzing

`cli/test/fuzz.test.js` mutates inputs to every parser that reads bytes
from a peer. The fast tier runs a small budget per target, and `pnpm fuzz`
runs 100,000. A failure prints its seed and iteration, and the seed is all
it takes to replay it:

```bash
ADHAL_FUZZ_SEED=<seed> node --test cli/test/fuzz.test.js
```

| Variable | Effect |
| --- | --- |
| `ADHAL_FUZZ_SEED` | Replay a run exactly |
| `ADHAL_FUZZ_ITERATIONS` | Iterations per target |
| `ADHAL_FUZZ_STATS=1` | Print how many inputs each target accepted and refused |

### Property-based tests

`cli/test/property.test.js` states claims about every input of some shape,
such as "however the bytes are split, the decoder yields the same frames",
and checks each on generated inputs. On a failure it shrinks the input to
a small counterexample and prints the seed. The generators and the
shrinking are in `cli/test-helpers/property.js`, with no dependency.

Every property is checked against something independent of the code
under test: `conformance/src/wire.js` (a second implementation of the wire
format), a rule restated from PROTOCOL.md, or arithmetic the test does
itself. A property that only compares a function with its own inverse
passes for code that is wrong the same way twice.

| Variable | Effect |
| --- | --- |
| `ADHAL_PROPERTY_SEED` | Replay a run exactly. One property replays alone with the same seed |
| `ADHAL_PROPERTY_RUNS` | Inputs per property (default 100). The two resume properties run an eighth as many, since each writes a file |

One property is marked `todo`: it runs and reports a known failure
without failing the suite. Its comment says what it found.

### Conformance

`conformance/` holds the published test vectors and a harness that
drives any implementation through drops over loopback TCP.
[`CONFORMANCE.md`](CONFORMANCE.md) describes both. `pnpm test` runs it
against this repository's engine, one test per scenario. To run it alone,
or a subset:

```bash
pnpm conformance
node conformance/src/cli.js --only '^R-resume' -- node conformance/adapters/engine.js
```

`conformance/test/planted.test.js` plants a bug for each kind of check in
a copy of the engine and requires the harness to catch it.

### Mutation testing

`tools/mutate.js` makes small changes to the engine modules that enforce
the protocol, one at a time, and runs the tests against each: a `<`
made `<=`, a `throw` made a no-op, a constant moved by one. A change the
tests notice is killed. One they do not is a survivor: a gap in the tests,
or a change no input can observe.

```bash
node tools/mutate.js                                  # every target, about an hour
node tools/mutate.js --files engine/src/channel.js    # one module
node tools/mutate.js --sample 100 --report out.json   # a seeded sample, with a JSON report
node tools/mutate.js --conformance                    # survivors also face the conformance harness
```

Each mutant is planted in a copy of the workspace (`tools/sandbox.js`), so
the working tree is never touched, and a run first checks that the
unmutated copy passes. The runner tries the tests most likely to notice a
change in that module first, and runs the rest of the fast tier only for
mutants that survive them. Seeds are fixed, so a run repeats, with one
exception: the fuzz harness builds some of its starting inputs from
`crypto.randomBytes`, outside its seed.

### Using them well

- **While editing, run the fast tier.** About 12 seconds is short enough
  to run after every change. Changes tested in batches are harder to
  bisect.
- **Before a commit, run `pnpm test` and `pnpm typecheck`.** The slow tier
  is where the networking code is exercised.
- **Prove a new test can fail.** Break the property it checks on purpose
  and watch it go red. Many tests here say in a comment what was broken
  to check them. Plant the break in a copy and restore from the copy,
  rather than with `git checkout`, which also discards any uncommitted
  work in the file.
- **Treat a failure that does not reproduce as a measurement, not as
  noise.** Run the test in a loop, and keep the output of the failures:

  ```bash
  for i in $(seq 1 30); do
    node --test --test-name-pattern="<test name>" cli/test/<file>.test.js \
      > /tmp/run-$i.log 2>&1 && rm /tmp/run-$i.log && echo pass || echo FAIL
  done | sort | uniq -c
  ```

  If it fails only under load, loop the whole fast tier instead. A rate,
  compared with the rate on the previous commit, says whether a change
  caused it. Failures in this repo that looked flaky have turned out to be
  real bugs.
- **Check that every source file is text.** A literal NUL or ESC byte in a
  string makes `grep` treat the whole file as binary and skip it without
  saying so. Write `'\x1b'`, never the byte itself. This prints any file
  that breaks the rule, and nothing when all is well:

  ```bash
  git ls-files -z '*.js' '*.md' '*.json' '*.yml' '*.yaml' |
    xargs -0 perl -ne 'if (/[\x00\x1b]/) { print "$ARGV\n"; close ARGV }'
  ```

### Environment variables for running the CLIs by hand

| Variable | Effect |
| --- | --- |
| `ADHAL_JOIN_TIMEOUT` | How long to wait for a peer, in ms. Defaults: 30,000 for the receiver, 120,000 for the sender. `0` waits forever |
| `ADHAL_REFRESH_INTERVAL` | How often to re-run the DHT lookup, in ms (default 4,000) |
| `ADHAL_BOOTSTRAP` | A JSON array of DHT bootstrap nodes, so a CLI can join a local testnet instead of the public DHT. The tests use it |
| `ADHAL_NO_PROGRESS=1` | No progress bar |
| `ADHAL_MAX_SIZE` | The largest transfer the receiver accepts, in bytes. `0` means no limit |

## Across two machines

### Set up both machines

```bash
git clone git@github.com:khartig/adhal.git && cd adhal   # or: cd ~/adhal
git fetch && git checkout <branch> && git pull
git log --oneline -1                      # must print the same commit on both
node -v                                   # 24 or later
pnpm install --frozen-lockfile
```

- **Use the same commit on both.** A build mismatch shows up as
  `protocol-error` or as failed confirmations, and looks like a network
  problem.
- **Allow outbound UDP** on both networks.
- **Keep both clocks NTP-synced.** The trials harness schedules by wall
  clock.
- **Run `pnpm test` on each machine first.** A local failure found now
  will not be blamed on the network later.

### One drop

**Receiver:**

```bash
node cli/src/swarm-receive.js --new ~/adhal-received   # into ~/adhal-received
node cli/src/swarm-receive.js                          # into the current directory
```

`--new` is needed when you name an output directory. With one argument
and no `--new`, the argument is taken as a drop code, and the receiver
refuses a code given on the command line.

It prints a five-word code and a QR code. Pass the code to the other side
by some other route, such as a chat message.

The receiver waits about 30 seconds for a peer. That is tight when a
person has to read the code out and start the sender, so give it longer
for a test:

```bash
ADHAL_JOIN_TIMEOUT=300000 node cli/src/swarm-receive.js --new ~/adhal-received   # 5 minutes
```

**Sender:**

```bash
head -c 10485760 /dev/urandom > /tmp/test.bin    # a 10 MB test file
node cli/src/swarm-send.js - /tmp/test.bin       # type the code at the prompt
```

The receiver shows the offer, with its name, size, and SHA-256, and asks
before writing anything. Accept it. A good drop ends like this on each
side:

- **Receiver:** `verified: the file matches the sender's manifest digest`.
- **Sender:** `verified: the receiver confirmed all <n> bytes with the same
  digest`.
- **Both:** the same `sha256:` value.

Then swap the roles and run it again. A path can work in one direction
and not the other. Add `--verbose` on both sides to print the DHT topic
when debugging discovery.

### A measured rate

One drop says that a path can work, not how often it does. For a success
rate, use `engine/scratch-trials.js`: it runs N drops back to back,
derives each trial's code from a shared seed, and classifies every
failure. Its flags, failure classes, and output are documented in
[`MEASURING-TRANSFER-RELIABILITY.md`](MEASURING-TRANSFER-RELIABILITY.md).

The commands below run 20 trials in each direction as one unattended
sequence per machine. Machine 1 receives in run A and sends in run B.
Machine 2 does the opposite.

**On both machines**, make the file each one sends:

```bash
head -c 10485760 /dev/urandom > /tmp/test.bin
```

**On either machine**, pick a start time about 5 minutes out:

```bash
echo $(( $(date +%s) + 300 ))
```

**Machine 1:** receiver for run A, then sender for run B.

```bash
E=<the start time>
D=<today, e.g. 20261012>
CONFIG=starlink-cgnat-to-comcast-home-router
RUN_DIR=~/trials/$D/$CONFIG
NOTES=(--note "<what this machine cannot detect, e.g. eero firewall on, default rules>")
mkdir -p "$RUN_DIR"
node engine/scratch-trials.js --role receiver --seed "$D-$CONFIG-a" --trials 20 \
  --start-epoch "$E" --lookup-isp "${NOTES[@]}" \
  --out "$RUN_DIR/$D-trials-a-rx.json" 2>&1 | tee "$RUN_DIR/$D-trials-a-rx.log" ; \
node engine/scratch-trials.js --role sender --seed "$D-$CONFIG-b" --trials 20 \
  --start-epoch $((E + 3000)) --file /tmp/test.bin --lookup-isp "${NOTES[@]}" \
  --out "$RUN_DIR/$D-trials-b-tx.json" 2>&1 | tee "$RUN_DIR/$D-trials-b-tx.log"
```

**Machine 2:** sender for run A, then receiver for run B.

```bash
E=<the same start time>
D=<the same date>
CONFIG=starlink-cgnat-to-comcast-home-router
RUN_DIR=~/trials/$D/$CONFIG
NOTES=(--note "<what this machine cannot detect, e.g. Starlink router, bypass off>")
mkdir -p "$RUN_DIR"
node engine/scratch-trials.js --role sender --seed "$D-$CONFIG-a" --trials 20 \
  --start-epoch "$E" --file /tmp/test.bin --lookup-isp "${NOTES[@]}" \
  --out "$RUN_DIR/$D-trials-a-tx.json" 2>&1 | tee "$RUN_DIR/$D-trials-a-tx.log" ; \
node engine/scratch-trials.js --role receiver --seed "$D-$CONFIG-b" --trials 20 \
  --start-epoch $((E + 3000)) --lookup-isp "${NOTES[@]}" \
  --out "$RUN_DIR/$D-trials-b-rx.json" 2>&1 | tee "$RUN_DIR/$D-trials-b-rx.log"
```

`--lookup-isp` sends each machine's public address to a DNS lookup, to
record its ISP. Leave it out to keep the address on the machine, and write
the ISP into `ENVIRONMENT.md` by hand. With `NOTES=()` the run records no
notes.

When both runs are done, copy the other machine's files into the same
`$RUN_DIR` and write the environment file from them:

```bash
node engine/scratch-trials-environment.js "$RUN_DIR" --write
grep -n 'FILL IN' "$RUN_DIR/ENVIRONMENT.md"
```

The `grep` lists what the harness could not detect. See
[`MEASURING-TRANSFER-RELIABILITY.md`](MEASURING-TRANSFER-RELIABILITY.md#writing-up-a-run-environmentmd).

How the schedule works:

- **Each trial gets a 135-second slot**, so 20 trials take 45 minutes.
  Run B starts 3,000 seconds after run A, five minutes after A's last
  slot. The whole sequence takes about 95 minutes.
- **The two sides never talk to each other.** They agree because they
  share the seed, the trial count, and the start time, so all three must
  be identical on both machines. The harness waits for a start time in
  the future.
- **`;` joins the two runs, not `&&`**, so run B still starts if run A
  exits with failures.
- **A seed must never be reused.** It decides every trial's code, so a
  reused one would put two runs on the same topics. The date in it keeps
  each day's runs apart.

Before leaving it to run:

- **Check the `slot start:` line on both machines.** It must show `$E`
  for run A and `$E + 3000` for run B. A mismatch means the sides are
  running different trials, and the run would report 0% on a working
  path.
- **Keep both machines awake.** On macOS, run `caffeinate -i -w $$ &` in
  the same shell first. On a Linux laptop, prefix each command with
  `systemd-inhibit --what=sleep`.

For a quick smoke run, add `--slot 60` and use fewer trials. A shorter
slot gives up on each trial sooner than the real CLI would, so do not
quote its rate.

### Reading the results

Each side ends with a summary. Look at:

- **The success rate.** The bar is 75% on a path. Below 50%, a relay
  stops being optional. Twenty trials give a rough rate, not an exact
  one.
- **The connect-time spread.** The median and p90 together.
- **`badConfirmations`.** It must be 0 on a private seed. Anything else
  means the machines are on different builds, or someone else is on the
  topic.
- **`attempt-cap`.** It should never appear in an unattended run.
- **Both sides agree.** If the sender says `ok` and the receiver reports a
  hash mismatch, believe the receiver: it is the side that verified.

### Recording results

Keep the JSON files. Add each result to "Measured on real networks" in
[`ARCHITECTURE.md`](ARCHITECTURE.md), with:

- the date;
- the commit, from each log's `build:` line, and whether it was clean;
- both machines' operating systems and networks, and each side's `nat`
  line;
- the direction, and the trial count.

A rate with those details can be compared with the next run. "It worked
when I tried it" cannot.
