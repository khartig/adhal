# Roadmap

Where Adhal is going, in what order, and what has to be true before each
step counts as done. The finished work items are summarised in §4; their
full record, with the measurements and the findings along the way, is in
[`history/WORK-RECORD.md`](history/WORK-RECORD.md). How the code is built
is in [`ARCHITECTURE.md`](ARCHITECTURE.md), and the protocol is specified
in [`PROTOCOL.md`](PROTOCOL.md).

**Numbering, permanently.** `D1`-`D7` are data-path steps. `W1`-`Wn` are
work items. No bare "item N" anywhere: the old docs used it for both, and
that collision produced at least one documented error.

---

## 1. What Adhal is for

Two people move a file directly between their machines. No account, no
server holding the bytes, no install on a third party's terms.

That sentence is not distinctive on its own: several tools claim it.
What makes Adhal distinctive is the five properties below, each a design
decision that would be expensive to reverse. That expense is what makes
them worth protecting. How they compare with other tools, and how that
will be tested, is in [`POSITIONING.md`](POSITIONING.md).

---

## 2. What it is built around

**1. Serverless-by-default rendezvous.** Discovery is the DHT. A relay is
an opt-in plug-in, never the default path when a direct connection works.
A design that routes discovery and its first hop through relay servers
cannot offer this without being rebuilt, which is why §3 fixes the
relay's constraints before any relay code exists.

**2. Protocol-first.** A published, versioned specification with test
vectors and a conformance suite ([`PROTOCOL.md`](PROTOCOL.md), W12). That
is what lets a second implementation exist, and so what lets a
one-person project outlive its author.

**3. Ephemeral-by-construction privacy.** No accounts, no persistent
identity, per-drop keys, nothing linking two drops
([`THREAT-MODEL.md`](THREAT-MODEL.md) §4). Enforced in code since W15b. It
cannot be retrofitted once linkage exists in records other people hold.

**4. Streaming and scripting.** `tar c dir | ad-hal-send <code> -` works
today; a receive that writes to stdout and stable `--json` events are W13.
It serves developers, CI and headless machines, and it lands naturally on
macOS and Linux first (§3).

**5. Published, reproducible reliability numbers.** Evidence, not a
slogan. `scratch-trials.js` runs repeated real drops, classifies every
failure by code, and reports a rate with an honest confidence bound
([`MEASURING-TRANSFER-RELIABILITY.md`](MEASURING-TRANSFER-RELIABILITY.md)).

### Deliberately not building

- **A polished GUI race.** It cannot be won by one person.
- **Browser receive.** It needs a hosted bridge, which contradicts #1.
- **Trusted-device auto-accept.** It contradicts #3.
- **Content-addressed multi-file sharing.** That is a different design.

---

## 3. Constraints that hold before the code exists

**The relay** ([`THREAT-MODEL.md`](THREAT-MODEL.md) §8, with its merge
gates):

- **Optional**, and never in the default path when a direct connection
  works.
- **Self-hostable**, with its protocol documented.
- Relay tokens derive from the **nameplate only**, never from anything
  that could be ground back to the secret.
- Investigate Holepunch's own blind-relay first: the best relay to
  operate is none.

**Platform order: macOS + Linux → Windows → Android → iOS.** macOS and
Linux are where development, testing and every measurement so far have
run, and where #4 lands. Windows is not supported for security purposes
until it is a required CI leg (Q-07). **iOS is worth sizing early:**
Holepunch's Bare runtime *may* make it reachable, which is unverified, and
"cross-OS including iOS, with no server" is the strongest version of this
project's story.

---

## 4. Done

| | Item | Outcome | Commits |
|---|---|---|---|
| Stage 0 | **W1–W8**: security hardening with no wire change | Leaked IPs purged from history; the threat model; overwrite protection, `O_EXCL`, size cap, free-space check, stall timers, per-candidate deadline; CI with a fast tier. Three bugs found by probing rather than reading | |
| Stage 1 | **W9**: the specification | [`PROTOCOL.md`](PROTOCOL.md), including the three resume traps | |
| | **W10**: PAKE selection | CPace over `@noble/curves`, checked against the CFRG vectors; hand-rolled framing kept; a checkpoint every 5 s | |
| | **W11**: v2 implemented | The handshake, the sealed channel, the full message set, the attempt cap, streaming and resume | |
| | **W15a**: five wire changes from the security review | The length bound into the tag, the topic via `lv_cat`, the EFF large wordlist, `ERR_DROP_TAKEN`, the `adhal` identifier | `f22e517`, `14c8bea`, `93d99de`, `2937f9a`, `88148a7` |
| | **W15b**: engine and CLI hardening | Terminal escaping, a fresh announce key per swarm, one descriptor per sent file, best-effort key wiping, validated environment | `2e8004a` |
| | **W15c**: consent and what the user is told | The accept prompt, codes off argv by default, contention warnings, the not-anonymous notice | `9d46439` |
| | **W15d**: tests that pin the argument | Security-property tests, the state machine, negative vectors, a fuzz harness, the security claims; the testnet pairing stall found and mitigated | `6154994`, `42f2cf7`, `550ea47`, `a09a387`, `dfc5b3f` |
| | **W16**: release documentation pass | The docs rewritten to match the code; SECURITY.md and SECURITY-REVIEW.md; this plan made a public roadmap, its finished items moved to [`history/WORK-RECORD.md`](history/WORK-RECORD.md); GitHub private vulnerability reporting on, 2026-10-14 | `7e403a0`, `6a1877e`, `15956c4`, `7269725`, `9aa0589`, `4075fc8`, `25cd39f`, `668bab4` |

The security review's 21 findings and their status are in
[`SECURITY-REVIEW.md`](SECURITY-REVIEW.md).

---

## 5. Stage 1, finishing: the freeze

- **W17 — Freeze gate.** PROTOCOL.md is tagged v2-final only when every
  line below is true and was checked by running something, not by
  reading:

  1. W15a's five wire changes are in the spec, the code and the vectors.
     Every protocol label and the QR scheme use the ASCII identifier
     `adhal`. `grep -ri quay` over the code finds nothing.
  2. Every post-CONFIRM frame is sealed with its length bound. No
     plaintext frame is written after CONFIRM, checked by a test.
  3. The consent prompt is the default on both receivers. A late peer
     gets `ERR_DROP_TAKEN` end to end.
  4. Only implemented capabilities are advertised, checked by a test.
  5. The state-machine section exists and its table-driven test passes.
  6. The negative vectors are published and pass. The fuzz harness runs
     in the fast tier and is green.
  7. The security claims section exists.
  8. `pnpm test` and `pnpm typecheck` are green on macOS and Linux. A real
     two-machine drop (macOS ↔ Linux) on the public DHT succeeds on the
     frozen wire.
  9. W16 is done, and `docs/SECURITY-REVIEW.md` shows no finding without
     a status.

  After W17, a change to the wire is a v3 break, and Q-05 can begin.

  > **Status, 2026-10-14.** Gates 1–7 and 9 hold, checked on macOS at
  > `1736d1c`: `pnpm typecheck` clean; `pnpm test` 523 passed, 1
  > skipped, 0 failed, the gate tests among them; no tracked file
  > outside the docs mentions `quay`; every finding in SECURITY-REVIEW.md
  > has a status. Gate 8 is what remains. The 2026-10-13 drops
  > ([`trials/20261013`](trials/20261013/starlink-cgnat-to-comcast-eero/ENVIRONMENT.md))
  > ran on an earlier build with no commit recorded, so they do not
  > count. Left: `pnpm test` and `pnpm typecheck` on Linux, and the
  > macOS ↔ Linux trial run on the build to be tagged, with its commit in
  > the logs. Then the tag.

---

## 6. Open findings, deferred

Each is a finding from the review that W15 did not close, with the work
item it waits for and the reason ([`SECURITY-REVIEW.md`](SECURITY-REVIEW.md)
has all 21).

| | Deferred to | Why not now |
|---|---|---|
| Q-04 layered throttling (per-source, per-key budgets) | After W14 | A Sybil attacker rotates both identifiers. W15c makes the attack visible, and W14's data shows whether it happens. |
| Q-05 independent cryptographic review | After W17 | Reviewing a moving spec wastes the review. |
| Q-06 property-based and mutation testing | W12 | Decision 6. |
| Q-07 Windows as a required CI leg | Stage 3 | Documented as unsupported for security purposes until then (W16). |
| Q-08 gating advisories, SBOM, signed releases | First release | Nothing ships yet. Every dependency is pinned exactly, and an unused one was removed in W15b. |
| Q-09 length padding, re-announce back-off | Post-freeze | Neither changes the wire. Padding only if file-size confidentiality ever becomes a stated goal. |
| Q-10 relay invariants | Before any relay code | Written into THREAT-MODEL §8 as merge gates (W16); enforced when a relay exists. Resume's half is already met: nothing is persisted, and PREFIX re-hashes the prefix. |

---

## 7. Stage 2 — prove and publish the thesis

- **W12 — Publish spec, test vectors, conformance harness** (#2). Most of
  the vectors exist (PROTOCOL §11); the harness that drives any
  implementation through a drop does not. Property-based and mutation
  testing land here too (Q-06).
- **W13 — Streaming/pipe contract + `--json` events** (#4), built on the
  existing error codes: a receive that writes to stdout, and a stable,
  documented event stream.
- **W14 — Head-to-head reliability** against other peer-to-peer
  file-transfer tools, on identical network pairs, including
  **CGNAT↔CGNAT** and symmetric NAT. Reuse `scratch-trials.js`. **This
  single experiment tests the central thesis and decides how much the
  relay matters.** The method, the tools and the network pairs are in
  [`POSITIONING.md`](POSITIONING.md) §5, and so will the results be.

---

## 8. Stage 3 — reach

macOS + Linux CLI → LAN discovery (mDNS/multicast) → macOS + Linux desktop
app → optional relay (under §3) → **Windows** → **Android** → **iOS spike,
then build**.

---

## Verification standard

Applies to this roadmap and to anything built from it.

1. `pnpm test` green. `pnpm test:fast` for iteration.
2. `pnpm typecheck` (`tsc --noEmit`) — the repo is JSDoc-typechecked.
3. **Probe, do not infer.** Every security claim in Stage 0 was checked by
   running code against the shipping path. Three defects were found that
   reading had missed, and one claim in the review that prompted the work
   turned out to be false. A finding nobody executed is a hypothesis.
4. `file <src>` must report text for every source file, and `grep` must
   find what is in them.
5. Real two-machine drop on the public DHT (macOS ↔ Linux) before calling
   a transport change safe.
