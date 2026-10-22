# Security review: findings and status

**What this is, stated first because it sets how much weight it
deserves.** An AI-assisted security review of the v2 implementation on
branch `w11-protocol-v2` at commit `6760cae`. Seven model-generated
reviews were run. One was discarded because it described a codebase that
is not this one, and the other six were merged into the 21 findings below.
It is **not** an independent audit. An independent review of the
cryptographic composition is Q-05, and it comes after the wire format is
frozen (W17), against the claims in [`PROTOCOL.md`](PROTOCOL.md) §12.

The raw review transcripts are not published; this table is the record
(decision 7 of W15, [`history/WORK-RECORD.md`](history/WORK-RECORD.md)).
Every finding was re-checked against `3042057`, five commits after the
reviewed state, and then worked through in W15. Each status names the
commit or work item that makes it true. Where a finding is deferred, the
reason is in [`IMPLEMENTATION-PLAN.md`](IMPLEMENTATION-PLAN.md) §6.

| | Finding | Severity | Status |
|---|---|---|---|
| Q-01 | The AEAD channel was built but did not carry the transfer, and the docs said it did | High | **Closed.** Every frame after the handshake goes through the channel, with no unsealed mode (by `3042057`). The length prefix is bound into the tag as associated data (W15a, `14c8bea`). Nonces never repeat, checked over a whole resumed transfer (W15d, `42f2cf7`). |
| Q-02 | Knowing the code authorized writing any file: no consent step, first handshake wins, no RESULT | High | **Closed.** ACCEPT/DECLINE with codes, and RESULT (by `3042057`). A late peer is told `ERR_DROP_TAKEN` (W15a, `88148a7`). Both receiver CLIs ask before accepting, and `--yes` skips the question (W15c, `9d46439`). The code remains a bearer capability: [`PROTOCOL.md`](PROTOCOL.md) §12.3. |
| Q-03 | The handshake advertised `resume` and `stream` without implementing them | High | **Closed.** Both have handlers (by `3042057`). A test fails if a token is ever advertised without one (W15d, `42f2cf7`). |
| Q-04 | A nameplate holder can burn a drop, or hold candidate slots | Medium | **Partly addressed; the rest is deferred.** The receiver now says when candidates repeatedly fail or go silent (W15c, `9d46439`). Burning a drop after 100 failed guesses is deliberate (PROTOCOL §6). Layered throttling waits for W14's data on whether the attack happens. |
| Q-05 | No independent review of the cryptographic composition | Medium | **Open, and it can begin:** it waited for W17, since reviewing a moving spec wastes the review, and W17 froze the wire on 2026-10-15. The target is stated: PROTOCOL §12 (W15d, `dfc5b3f`). |
| Q-06 | Gaps in robustness testing: fuzzing, the state machine, negative tests | Medium | **Pre-freeze scope done** (W15d): the state machine, specified and tested cell by cell (`550ea47`); negative vectors and a fuzz harness (`a09a387`). Property-based and mutation testing are deferred to W12. |
| Q-07 | Windows filesystem-safety controls are unverified | Medium | **Deferred to Stage 3.** Windows is not supported for security purposes until it is a required CI leg: PROTOCOL §12.3, README. |
| Q-08 | Dependency and supply-chain assurance is advisory, not gating | Medium | **Partly addressed.** An unused dependency was removed (W15b, `2e8004a`), and every dependency is pinned to an exact version. Advisories fail CI: `pnpm audit` at moderate, and OSV-Scanner at any severity, under [`DEPENDENCY-POLICY.md`](DEPENDENCY-POLICY.md) (`609f814`). Each GitHub Release carries a CycloneDX SBOM for each package, from v0.1.0 on (`e5961d1`). Still open: npm provenance and signed checksums, due with the next npm publish. 0.1.0 can never have provenance, since it was published from a developer's machine and npm does not republish a version. |
| Q-09 | Topic, IP, and timing metadata are visible to DHT nodes; the sender is not anonymous | Medium (by design) | **Stated, not changed.** Both swarm CLIs and their `--help` say Adhal is not anonymous (W15c, `9d46439`); see [`THREAT-MODEL.md`](THREAT-MODEL.md) §3. Length padding and re-announce back-off are post-freeze, and neither changes the wire. |
| Q-10 | Future relay and resume work must not break v2's invariants | Medium (preventive) | **Resume's half is met:** nothing is persisted, and PREFIX re-hashes the prefix (W11). The relay's half is written down as merge gates in [`THREAT-MODEL.md`](THREAT-MODEL.md) §8 (W16), enforced once a relay exists. |
| Q-11 | Peer-controlled bytes reached the terminal unsanitized through error messages | Low-Medium | **Closed** (W15b, `2e8004a`). Four leaks were found and fixed, not two, and every printed line is escaped as a backstop. |
| Q-12 | The ephemeral announce-key invariant was documented but untested | Low-Medium | **Closed** (W15b, `2e8004a`). Each swarm generates its own announce keypair, a caller cannot pass one in, and a testnet test checks that two drops are seen under different keys. |
| Q-13 | The loopback `send`/`receive` CLIs had no PAKE and no encryption | Low-Medium | **Closed.** The loopback tools run the v2 handshake and channel over TCP (W11). They are labeled test-only, and the published `ad-hal-send`/`ad-hal-receive` bins are the swarm CLIs (W15c, `9d46439`). |
| Q-14 | The secret's entropy margin (~31 bits), and nameplate collisions | Low-Medium | **Closed** (W15a, `2937f9a`). The EFF large wordlist gives the secret ~38.8 bits, and a 50% nameplate collision now takes ~9,150 concurrent drops. The attempt cap's counting rules are pinned (W15d, `42f2cf7`). |
| Q-15 | `--unsafe-opaque` reintroduced offline code grinding | Low | **Closed** (W15b, `2e8004a`). The flag is now `--insecure-opaque-code`, only the exact value `1` of its variable opts in, and nothing enables it by default. |
| Q-16 | The sender stat'ed, hashed, and read the file separately (TOCTOU) | Low | **Closed** (W15b, `2e8004a`). One descriptor serves the size, the hash, and every byte sent, and a non-regular file is refused. An in-place edit still fails closed at the receiver's digest check. |
| Q-17 | CLI and environment hardening: codes on argv, bootstrap parsing, topic hex in logs | Low | **Closed.** The bootstrap variable is validated and never echoed, and the topic is printed only with `--verbose` (W15b, `2e8004a`). A code on argv needs `--code-on-argv` (W15c, `9d46439`). `--log-json` moved to W13. |
| Q-18 | Secrets and keys cannot be zeroized in memory | Low | **Best effort, and documented as such** (W15b, `2e8004a`). Handshake intermediates and channel keys are zeroed, and channel keys are single-use. Node cannot reach copies inside OpenSSL or `@noble`: [`THREAT-MODEL.md`](THREAT-MODEL.md) §7. |
| Q-19 | The `publish()` fallback uses a racy check-then-rename | Low | **Reported, not silent** (W15b, `2e8004a`). The fallback is still the only option on a filesystem without hard links, but the receiver now says when it was used. |
| Q-20 | Security process: no `SECURITY.md`, no signed releases, stale docs | Low | **Addressed in W16, except signing.** [`SECURITY.md`](../SECURITY.md) gives the disclosure route, and every security claim in a doc now names the work item that makes it true. Signed releases are Q-08's, due with the next npm publish. |
| Q-21 | The topic hash relied on a fixed-length prefix rather than an explicit delimiter | Informational | **Closed** (W15a, `93d99de`). The topic is now `BLAKE2b-256(lv_cat("adhal-v2:topic", nameplate))`. |

No finding is without a status. W17's freeze gate checks exactly that.
