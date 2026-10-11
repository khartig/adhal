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

The security review's 21 findings and their status are in
[`SECURITY-REVIEW.md`](SECURITY-REVIEW.md).

---

## 5. Stage 1, finishing: the freeze

- **W16 — Release documentation pass.** Last, so the docs describe the
  final code.

  > **Implemented, not yet committed.** Two things are left to the
  > owner: turning on GitHub private vulnerability reporting, which is not
  > available while the repository is private, and confirming the
  > response targets in SECURITY.md, which are a commitment. Where the
  > result differed from the table below:
  > - ARCHITECTURE.md was rewritten from the code rather than edited. The
  >   old file is `history/ENGINEERING-LOG.md` whole, with a note listing
  >   its superseded passages, because its reasoning is what the design
  >   rests on.
  > - The finished work items' full record is `history/WORK-RECORD.md`.
  >   The competitor analysis moved to `POSITIONING.md`, with the
  >   positioning half of the 2026-09-18 review, so that it can grow with
  >   W14's comparison testing. Decision 3 is amended to match: the roadmap
  >   carries no competitor analysis, and the positioning document does.
  > - PROTOCOL.md kept its section numbers, so every `§` reference in the
  >   code still holds, and gained §13, the changelog. §12's odds now use
  >   the vendored list's 7,772 words, not 7,776.
  > - `scratch-trials.js` had no outcome for `ERR_DECLINED`,
  >   `ERR_DROP_TAKEN`, `ERR_NO_SPACE` or `ERR_EXISTS`, so each would
  >   have read as a generic `transfer-error`. They have outcomes now. The
  >   measuring doc's outcome table had been split by an earlier edit,
  >   and it is whole again.
  > - Both packages gained `"files": ["src"]`. A dry-run pack ships
  >   `src/` only, so no `scratch-*` file can be published by accident.
  > - The historical documents keep the names they were written under.
  >
  > Typecheck clean. The full suite passed 504 of 505, with 1 skipped on
  > this platform. Every relative link and anchor in the docs resolves. The rule from here on: **every security claim in a doc
  names the work item that makes it true** (Q-20), which is how the
  Q-01 overclaim would have been caught.

  **Decisions, 2026-10-07**, settled before any W16 edit:

  | # | Question | Decision |
  |---|---|---|
  | 1 | The name in prose | **Adhal.** It is introduced once, where the name is explained (the README's opening, SECURITY.md), as Ad-ḫal, from the Sumerian *ad-ḫal*, "secret". This supersedes the "Ad-ḫal everywhere" row below. Identifiers and wire labels are unchanged (`ad-hal`, `ADHAL_*`, `adhal`). |
  | 2 | How to report a vulnerability | **GitHub private vulnerability reporting.** No email address is published. It has to be enabled in the repository's settings before SECURITY.md is accurate. |
  | 3 | Whether this plan stays public | **Yes, as a roadmap.** The competitor analysis is removed, and the detail of finished work items moves to `docs/history/`. |

  | Doc | Change |
  |---|---|
  | `README.md` | Rewrite Status and Quickstart to match the code: accept gate, streaming, resume, and the prompt. Say that the code is a bearer capability, that Ad-ḫal is not anonymous, and that Windows is not supported for security purposes. Fix the Node floor (≥ 24, not ≥ 18). Drop the development narrative. |
  | `PROTOCOL.md` | Spec only. Move the W10/W11 amendment history into a changelog section at the end. Fix the §7.3/§7.4 order. Mark §9 (v1) as historical. Replace the `quay send -` examples with real commands. Remove competitor remarks. |
  | `THREAT-MODEL.md` | Rewrite §9 to present reality. Add the consent prompt, resume `.part` handling (`O_NOFOLLOW`, link-count check, PREFIX's one-bit oracle), the large-list entropy numbers, the DoS posture, secret memory handling, and the relay merge gates. |
  | `ARCHITECTURE.md` | Split into a current design doc and an engineering log under `docs/history/`. Fix the error-code table and the stale "code proof" and cancel-latency passages. Document `stream-handshake.js`. |
  | `IMPLEMENTATION-PLAN.md` | Fix the stale W11 and competitor-table status. Before publication, decide whether it stays public; if so, it becomes a roadmap without the competitor analysis. |
  | `REVIEW-SECURITY-AND-POSITIONING.md` | Move to `docs/history/`. It describes a code state that no longer exists. |
  | `SETUP.md`, `MEASURING-TRANSFER-RELIABILITY.md` | Fix the Node floor, the references to the deleted plan ("Phase A", "Section 8"; the same references are in `scratch-trials.js`), and the missing outcome rows. |
  | New `SECURITY.md` | Disclosure contact and response targets (Q-20). |
  | New `docs/SECURITY-REVIEW.md` | The 21 findings with their final status, framed as an AI-assisted review. The raw transcripts in `docs/audit/` stay untracked (decision 7). |
  | The name, everywhere in prose | Quay and Ad-ḫal become Adhal (decision 1). Where the name is introduced it is Ad-ḫal, in NFC (precomposed U+1E2B). Commands and identifiers in the docs use the ASCII forms from W15a item 5. |
  | Source comments and strings | Remove the remaining "item N" references, including the user-facing "pre-item-5 build" error string in `message.js`. Keep `scratch-*` out of any published package (Q-20). |

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
