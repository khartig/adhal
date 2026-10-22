# Release readiness: security checklist

What a security review of a peer-to-peer file-drop tool checks, and how
the v2 release of Adhal stands against each item. It is written for the
release decision, and for the independent reviewer of Q-05, so that they
start from a list of what is claimed, what is accepted, and what is still
open.

**How this was checked, stated first.** Each row was checked against the
code on branch `w11-protocol-v2` at `25cd39f`, on 2026-10-10, and not only
against the docs. On that tree:

- the fast tier passed: 474 passed, 31 skipped, 0 failed;
- the security test files, including their testnet cases, passed 146 of
  146: `manifest`, `hardening`, `security-properties`, `negative-vectors`,
  `cpace-vectors`, `attempts`, `channel`, `sealed-transfer`, `drop-taken`,
  and `announce-key`;
- `pnpm audit --audit-level low` reported no known vulnerabilities.

The full suite and a two-machine drop on the public DHT were **not** run
for this checklist. That drop is W17's gate 8.

**Status key.** **Covered**: implemented and pinned by a test.
**Partial**: implemented, with a stated limit. **Accepted**: documented
as not claimed ([`PROTOCOL.md`](PROTOCOL.md) §12.3). **Open**: work still
to do. **n/a**: nothing exists yet to check.

**Numbering.** Findings from the security review keep their `Q-nn`
([`SECURITY-REVIEW.md`](SECURITY-REVIEW.md)). Gaps this checklist found
that the review did not are `RR-n`, and they are numbered only here.

---

## 1. Key exchange and handshake

| Check | Status | Evidence, and what remains |
|---|---|---|
| The PAKE is implemented correctly | Partial | CPace-X25519-SHA512, checked against the CFRG vectors and 12 low-order and twist inputs (`cpace-vectors.test.js`). An all-zero shared point is refused (`cpace.js`). **Not reviewed outside the project** (Q-05). The reviewer should start with two points: `sid` is chosen by the receiver alone, so the composition is not UC-secure as composed (PROTOCOL §12.3.1), and the Elligator2 map is an experimental, underscored `@noble/curves` export, pinned to an exact version (§12.4). |
| Code entropy, and guessing is rate-limited | Covered | The secret is three EFF words, ~38.8 bits. The topic commits to the nameplate alone, so there is nothing to grind offline (PROTOCOL §2). After 100 failed confirmations, with exponential backoff, the drop is burned with `ERR_ATTEMPT_CAP`, and a reused `sid` counts as a failure (`attempts.js`, `attempts.test.js`). With no server, each peer enforces the cap itself. Per-source and per-key budgets are deferred (Q-04). |
| No man-in-the-middle, and no impersonation by racing | Covered, with an accepted limit | Each side proves the code on every connection, under role labels, so a confirmation cannot be reflected. A stripped capability fails both confirmations. Pinned by the reflection and downgrade vectors in `negative-vectors.test.js`. A late peer is told `ERR_DROP_TAKEN` (`drop-taken.test.js`). Accepted: the code is a bearer capability and the first peer to confirm wins (§12.3.3). |

## 2. Cryptographic implementation

| Check | Status | Evidence, and what remains |
|---|---|---|
| Authenticated encryption | Covered | ChaCha20-Poly1305 from Node's OpenSSL. Every frame after CONFIRM is sealed, with its length prefix as associated data. There is no unsealed mode, and one failed frame ends the channel (PROTOCOL §3.4; `channel.test.js`, `sealed-transfer.test.js`). |
| No home-rolled crypto | Partial | Every primitive comes from `@noble` or OpenSSL. The CPace composition and the framing are this project's own, as any protocol's composition is. That composition is what Q-05 reviews. |
| Nonces are never reused | Covered | Each direction has its own key and its own counter. The counter throws when it is exhausted rather than wrapping, and a channel whose two keys are equal refuses to seal (`channel.js`). Nonces are shown not to repeat across a resumed transfer (W15d). |
| Session keys are per-transfer and unpredictable | Covered | HKDF from the ISK, salted with `sid`. The ephemeral scalars are fresh per connection, the keys are used once and wiped on a best-effort basis (Q-18), and a code that leaks later does not expose earlier traffic (§12.2.7). |

## 3. The relay boundary

| Check | Status | Evidence, and what remains |
|---|---|---|
| The relay never holds plaintext or key material | n/a | There is no relay. Security does not depend on the transport: the plain-TCP case in `sealed-transfer.test.js` runs the protocol with no Noise underneath. A relay merges only through the six gates in [`THREAT-MODEL.md`](THREAT-MODEL.md) §8 (Q-10). |
| Metadata the transport leaks | Accepted | Both IPs are visible to the peer and to DHT nodes near the topic. Size and timing are visible on the path, and an idle receiver re-announces every 4 s. Both CLIs say Adhal is not anonymous. There is no padding (Q-09, post-freeze). See THREAT-MODEL §3. |
| A hostile path forces a fallback to an unsafe mode | Covered | There is no weaker mode to fall back to. A downgrade aborts the handshake. An opaque code needs `--insecure-opaque-code` (Q-15). A v1 peer gets a version-skew error, not a v1 session (`handshake.js`). Stalling or dropping is a denial of service, bounded by the stall timers (PROTOCOL §4.4), and it is not claimed against (§12.3.6). |

## 4. NAT traversal

| Check | Status | Evidence, and what remains |
|---|---|---|
| Hole punching connects to the wrong peer | Covered | Nothing rests on hyperdht or Noise authenticating the peer (§12.3.7). A wrong peer fails the per-connection confirmation, and that failure counts toward the cap. |
| Address or port spoofing during negotiation | Covered | Same argument: it can cost availability, not confidentiality. A silent candidate is dropped after 15 s, or after 5 s if it never sends a packet (W15d). |

## 5. Implementation bugs

| Check | Status | Evidence, and what remains |
|---|---|---|
| Path traversal in filenames | Covered | `safeWriteName` refuses `/` and `\` on every platform, plus `.`, `..`, NUL, control characters, and bidi overrides. `safeOutputName` checks that the resolved path stays inside the output directory. Existing files are never replaced, and partials are opened `O_EXCL` or `O_NOFOLLOW` with a link-count check (THREAT-MODEL §6). Tested with `../`, `..\..\`, and `/etc/passwd` (`manifest.test.js`). Windows is not supported for security purposes (Q-07). See RR-6 for the display spoofs that remain. |
| Memory safety in parsing and chunking | Partial | The engine is JavaScript, and its parsers are fuzzed: the fast tier runs the harness, and `pnpm fuzz` runs 100,000 iterations. The C code it inherits, `sodium-native` and `udx-native`, is not fuzzed by this project. |
| Resource exhaustion from a declared size | Covered | Frames are capped at 1 MiB before buffering, and handshake messages are capped too. Files are capped at 8 GiB by default, and the cap applies to streams. Backpressure runs in both directions, the stall timers run, and the set of seen `sid`s is bounded. The free-space check is advisory where `statfs` is missing. Pinned by `hardening.test.js`. |
| Vulnerable dependencies | Partial | Every dependency is pinned exactly, and CI installs with `--frozen-lockfile`. Advisories fail CI: `pnpm audit` at moderate, and OSV-Scanner at any severity. [`DEPENDENCY-POLICY.md`](DEPENDENCY-POLICY.md) says what to do when either fails (Q-08, `609f814`). The limit: the scans run on pushes and pull requests only, so an advisory published against an unchanged lockfile is seen at the next push. |
| Timing side channels in secret comparisons | Covered | Confirmation MACs and the resume prefix check both use `crypto.timingSafeEqual` (`handshake.js`, `transfer.js`). The remaining `Buffer.equals` calls compare public keys, or check two keys for equality as a sanity check. Neither reveals a secret. |

## 6. How these tools are attacked in practice

| Check | Status | Evidence, and what remains |
|---|---|---|
| Social engineering around the code | Partial | The receiver is asked before accepting, and is shown the name, size, digest, and any resume. Executables and double extensions are warned about even with `--yes`. Codes stay off argv by default, and both sides are told when someone else holds the code (W15c, W15a). See RR-5. |
| Compromised endpoint | Accepted | Not claimed (§12.3.4). Key wiping is best effort (Q-18). |
| Outdated clients | Open | 0.1.0 is the first release (2026-10-18). The only support policy is "the latest npm release and the default branch", and a client cannot learn that it is out of date. The wire version byte stops cross-version sessions from proceeding silently. See RR-2 and RR-3. |
| Supply chain | Partial | The pinning and gating above are in place, and each GitHub Release carries a CycloneDX SBOM for each package (`e5961d1`). From 0.1.1, both packages are published by `release.yml` through npm trusted publishing, with no npm token and a required reviewer. Each version has npm provenance, and its release has the tarballs, `SHA256SUMS`, and a Sigstore-signed GitHub attestation (Q-08; RR-4). The limits: 0.1.0 can never have provenance, since npm does not republish a version, and the native modules' prebuilt binaries are trusted as npm serves them. pnpm ≥ 10 blocks dependency install scripts by default, and this repository allows none. |
| Clones and typosquatted packages | Open | **`ad-hal`, `adhal`, `@ad-hal/cli`, and `@ad-hal/engine` were all unregistered on npm** on 2026-10-10. On 2026-10-18 they still were, and so was `ad-hal-cli`. Each returned 404 from the registry. A 404 means no public package has the name. It does not promise that npm will accept a publish under it, since its similarity checks can still refuse one. The official sources are now named in README.md and SECURITY.md. See RR-1. |

---

## 7. Open before release

Ordered by how expensive each gets to fix later.

- [ ] **RR-1 — Establish the official npm namespace, and publish the
  packages meant for distribution.** npm does not reserve names, and
  publishing an empty package only to hold a name breaks its
  name-squatting policy. So the namespace is claimed by creating the
  `ad-hal` organization, which gives the `@ad-hal` scope to its members
  alone, and is held by publishing real packages in it within a
  reasonable time:
  - [x] Create the npm account, with two-factor authentication on and
    the recovery codes stored.
  - [x] Create the `ad-hal` organization on the free plan.
  - [x] Make the packages publishable (2026-10-18). `@ad-hal/engine`
    and `@ad-hal/cli` are no longer `private`, and each has its own
    README and LICENSE. The CLI is the canonical install, and it leaves
    out the test-only loopback pair and the demos. The engine's
    `exports` keeps its internals out of reach. Both were packed,
    installed in a directory outside the workspace, and used for a real
    drop on the public DHT, whose digest matched.
  - [x] Publish the engine first, then the CLI, with `pnpm publish`,
    which turns the CLI's `workspace:*` into the engine's version. Both
    have `publishConfig.access` set to `public`. Both 0.1.0 releases are
    out (2026-10-18). npm staged them, so each package also carries a
    `0.0.0-stage` placeholder version that npm created. The source in
    both published tarballs is identical to the repository's. Installed
    from the registry, the CLI completed a real drop on the public DHT,
    and the digests matched. Neither release has provenance (Q-08).
  - [x] Name the official sources in the README and in SECURITY.md: the
    repository, `@ad-hal/cli`, and `@ad-hal/engine`. Anything else is
    unofficial.

  The workspace root, `ad-hal`, stays `private`. It is a development
  workspace, not a package, and publishing it to hold the name would be
  the squatting the policy forbids. Owning `@ad-hal` gives no claim to
  `ad-hal`, `adhal`, or `ad-hal-cli`. Those are published only if one of
  them gets a real purpose, such as a working wrapper around the CLI.
- [x] **Turn on GitHub private vulnerability reporting.** SECURITY.md was
  not accurate until it was, and it could not be enabled while the
  repository was private (W16). Done on 2026-10-14, when the repository
  went public.
- [x] **Confirm SECURITY.md's response targets.** They are a commitment
  (W16). Confirmed on 2026-10-14: 7, 14, and 90 days.
- [x] **RR-4 / Q-08 — Make the supply chain gating.** Fail CI on an
  advisory at a chosen level. Publish an SBOM, publish with npm provenance
  or signed artifacts, and publish release checksums.
  - [x] Fail CI on an advisory (2026-10-21, `609f814`). `pnpm audit`
    fails at moderate, and OSV-Scanner, which has no threshold, fails at
    any severity. Exceptions follow
    [`DEPENDENCY-POLICY.md`](DEPENDENCY-POLICY.md). Both jobs passed on
    their first run, alongside the full matrix.
  - [x] Publish an SBOM (2026-10-21, `e5961d1`). `release.yml` builds a
    CycloneDX 1.7 SBOM for each package with `pnpm sbom` and attaches
    both to the GitHub Release. v0.1.0's were attached by a manual run:
    61 components for the engine and 63 for the CLI, each with a
    license, matching pnpm's resolved production tree. They list the
    locked tree, which a user's install can differ from, since neither
    package ships a lockfile.
  - [x] Publish with npm provenance, and publish signed checksums
    (2026-10-22, `f50ebbb`, `eefc4c8`). Publishing a GitHub Release runs
    `release.yml`'s publish job in the `npm` environment, which needs a
    reviewer's approval and allows only `v*` tags. npm trusts that file
    in that environment for both packages, so no npm token is involved.
    The job packs each tarball once, attests it, publishes that file,
    and checks that the registry's SHA-512 is the file's. It then
    attaches the tarballs and `SHA256SUMS` to the release. 0.1.1 was the
    first: both versions have `https://slsa.dev/provenance/v1` on npm,
    the registry tarballs match `SHA256SUMS`, and
    `gh attestation verify` passes for both, naming `release.yml` at
    `refs/tags/v0.1.1`. Its first run published correctly, then failed
    its own check on a stale npm cache. A re-run attached the files, and
    `eefc4c8` fixes the check.
  - [x] Close the token route (2026-10-22). Both packages are set to
    "Require two-factor authentication and disallow tokens", so trusted
    publishing is the only way to publish them, and the account has no
    access tokens left. The token from 0.1.0's publish was already
    invalid when checked: npm rejected it with E401.
- [ ] **RR-2 — A version support policy.** Which releases get security
  fixes, and for how long. SECURITY.md's "Supported versions" says only
  the latest npm release and the default branch.
- [ ] **RR-3 — How a user learns of a fix.** Through three channels,
  none of which needs the client to contact a server. That keeps an
  in-client update check off the table: one would be a design decision
  weighed against the privacy properties, not a default.
  - **Release notes, on GitHub Releases**, for every published version:
    what changed, what was fixed, and whether any of it is a security
    fix. The npm package page does not show them. It shows only the
    README that was published with the version, so both package READMEs
    link to the Releases page, and that link reaches npm with the next
    publish.
  - **A GitHub security advisory** for each confirmed vulnerability,
    published from the private report once the fix is released
    (SECURITY.md). Advisories that GitHub reviews into its Advisory
    Database are what `npm audit` reports, so a user is told without
    visiting any page. That review is not instant, and whether every
    advisory for a small package is taken in has not been checked.
  - **`npm deprecate`** on each version a security fix supersedes, with
    a message naming the fixed version and the advisory. npm prints it
    on every install of that version and shows it on the package page.
    It is the only one of the three that reaches users through npm
    itself. It does not remove the version.

  Open: the Releases link is in both READMEs (2026-10-18) but is not on
  npm until the next publish. 0.1.0's release notes are on GitHub
  Releases (2026-10-21), under the tag `v0.1.0` at `e59a1c5`, the commit
  whose files match both published tarballs.
- [x] **W17 gate 8 — A real two-machine drop** (macOS ↔ Linux) on the
  public DHT, on the frozen wire. Done on 2026-10-15 at `8bc808a`, logged
  clean on both sides: 40 trials of 10 MB between macOS on eero/Xfinity
  and Linux on Starlink, 20 each way, and all 40 were confirmed on both
  sides with matching hashes ([`ARCHITECTURE.md`](ARCHITECTURE.md),
  "Measured on real networks"). An earlier run on 2026-10-13, with no
  commit recorded, had confirmed 38 of 40. Gate 8's other half, the
  suite and the typecheck on macOS and Linux, holds at `5c5029e`
  (2026-10-14), whose code `8bc808a` shares.
- [ ] **Q-05 — Independent review** of the cryptographic composition,
  after W17, against PROTOCOL §12. Possibly too expensive.

## 8. Worth considering, not blocking

- [ ] **RR-5 — An optional verify string.** A short value derived from
  the session key that both humans compare before any byte moves, like
  magic-wormhole's `--verify`. It closes the gap between "someone else
  holds the code" being reported and the transfer having already started.
  It changes the wire, so before W17 or in v3.
- [ ] **RR-6 — Names that display as something else.** Names are not
  Unicode-normalized, and zero-width characters (U+200B, U+FEFF) and
  homoglyphs are not refused. These are display spoofs, not traversal:
  `safeOutputName` still keeps the write inside the output directory.
- [ ] **Q-04** per-source and per-key throttling, after W14.
- [ ] **Q-09** length padding and re-announce back-off, post-freeze.
- [ ] **Q-07** Windows as a required CI leg, Stage 3.
- [ ] **Fuzzing the native layer** (`sodium-native`, `udx-native`). It is
  upstream's code, and probably upstream's job. Ask before assuming.
