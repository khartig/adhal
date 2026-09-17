This is the implementation strategy for the **ephemeral drop** product only. Household shelves, social backup, rooms, voice, and activist tooling stay out of the critical path until the gates below say otherwise.

Verified as of mid-September 2026: DashBeam is live, not deprecated — tonyantony300/dashbeam at **9.4k stars**, **v0.7.1 (1 Sep 2026)** added trusted devices and Android 12 support; iOS is still missing. Holepunch is production-maintained: hypercore **11.36.x**, ~30k weekly npm downloads, releases within days; hyperdht healthy; Hyperswarm **4.17.0**. MeshDrop remains a tiny same-stack competitor, not the market.

---

## 1. What you are building (and what you are not)

**Product:** a one-shot, no-account file drop between two devices. QR or 6-word code. LAN first, DHT second, **relay if punch fails**. Hash shown before success. Optional “Keep this device” is a _toggle_, not a second app.

**Pitch by audience**

|Audience|Pitch|Differentiator|
|---|---|---|
|Consumers|Send files between devices instantly. No login, no email, no wait.|Cross-platform AirDrop; faster than attachments|
|Privacy-conscious|We never see the file. We are not in the path unless a relay carries ciphertext.|Signal-like crypto without a phone number|
|Developers|MIT/Apache engine + documented relay. Fork-friendly.|Clear modules, not a Pear-only binary|

Do **not** market anti-surveillance, duress, traffic padding, or activist use in v1.

**Name:** pick a brand-neutral name now (working title: Shelf Drop is fine internally). Avoid “Mesh,” “Beam,” and “Drop” collisions if you can; MeshDrop and DashBeam already occupy those search terms.

**Solo-dev constraint baked in:** one desktop OS first (Windows), one engine package, one relay you can run on a $6 VPS, no App Store in phase 1.

---

## 2. Competitive map (why reliability, not anonymity)

|Dimension|You (target)|DashBeam|MeshDrop|LocalSend|OnionShare|Briar / Cwtch|
|---|---|---|---|---|---|---|
|Stack|Holepunch (UDX + Noise + Hyper*)|Iroh QUIC + tickets|Same as you|LAN HTTPS|Tor onion|Tor / Bramble|
|Setup|Code / QR|Ticket / QR / Nearby|Pair codes|Same Wi‑Fi|Tor browser path|Identity + online peer|
|Internet|Yes, via **your** relay|Yes, n0 relays + self-host|Yes, fragile|No|Yes, slow|Yes, both online|
|LAN|Must be instant|Nearby|Intended|Best in class|N/A|Bluetooth/Wi‑Fi in Briar|
|Resume|Yes|Yes (BLAKE3 blobs)|Yes (designed)|Often no|Partial|Chunks, both online|
|Browser receive|Later|**Yes (growth weapon)**|No|No|Yes (onion site)|No|
|iOS|Not v1|Missing|Android only|Yes|Yes|Limited|
|Store-ready|Sideload first|Yes (desktop/Android)|Weak|Yes|Yes|Hard|
|Battery|Low (no background mesh)|Low|Pairing loops hurt|Low|High if Tor|High|
|Trust|Capability code + optional peer key|Peer keys + tickets|Peer keys|Implicit LAN|Onion URL|Onion / Bramble|
|Stars / maturity|0|**9.4k, shipping 0.7.x**|~single digits|Huge consumer habit|~7k, mature|Niche high-risk|

**Implication:** DashBeam already owns “ticket to anyone, big files, pretty site.” You do not win by cloning tickets on a different DHT. You win if (1) LAN feels like LocalSend, (2) off-LAN **succeeds more often than MeshDrop and as often as DashBeam**, (3) “Keep” turns a one-shot into a named device without an account.

Lead with **reliability**. Anonymity is a later mode.

---

## 3. Architecture you implement (and freeze)

text

```
Device Noise keypair          ← identity, persisted locally
├── Per-peer trust records    ← pk + {stranger | paired | trusted}
├── Per-drop capability       ← 6-word / QR, time-limited topic
├── Transfer encryption key   ← one key per drop (core or stream key)
└── Relay session             ← ciphertext only; no names, no hashes in clear
```

**v1 data path (keep this small):**

1. Generate code → topic = hash(code || app-salt) (32 bytes).
2. Both peers swarm.join(topic).
3. Challenge-response: prove you know the code (HMAC over nonce). Do not trust a stranger who merely found the topic.
4. Open a Protomux channel; send manifest (name, size, chunk size, content hash).
5. Stream chunks; ack by index; persist offset for resume.
6. Receiver verifies full-file hash; atomic rename into Downloads.
7. Leave topic. If “Keep” was off, forget the peer.

**Do not use Hyperdrive/Autobase/CRDT for v1 content.** A framed stream + a tiny manifest file on disk is enough and is easier to resume and test. Hypercore is optional later when you want sparse replication to a home base.

**Relay threat boundary (document before you write the relay):**

- Sees: two connection times, approximate bytes, IPs.
- Does not see: filenames, plaintext, long-term identity (use per-drop tokens).
- Cannot join the drop without the code.
- Caps: per-token bandwidth and duration.
- Default: your hosted relay; user can paste another URL.

That write-up is also your App Review / DSA “we are not a host of user content” argument: relay is a pipe, files are not stored.

---

## 4. Implement first: easiest, highest chance of success

Do these in order. Each step is demoable in a weekend. Stop and test before the next.

| Order | Work                                                                                         | Why first                                            |
| ----- | -------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| 1     | Node CLI: two processes on one machine, localhost pipe, send 10 MB, print SHA-256 both sides | Proves chunking/resume/hash with zero NAT            |
| 2     | Same CLI over Hyperswarm on one LAN (two laptops)                                            | Proves topic join + Noise without your protocol bugs |
| 3     | 6-word code + QR encoding of the same payload                                                | UX object exists; you can screenshot it              |
| 4     | Challenge-response on the code                                                               | Stops “I guessed the DHT topic”                      |
| 5     | Manifest + progress + cancel                                                                 | Users understand failure                             |
| 6     | Interrupt (kill process) and resume from offset                                              | Your first real differentiator vs naive worms        |
| 7     | mDNS/Bonjour **or** UDP multicast name beacon on LAN                                         | Nearby list; LocalSend parity                        |
| 8     | Windows tray app wrapping the engine (Tauri or Electron)                                     | Delivery without stores                              |
| 9     | Minimal relay: TCP or WebSocket that stitches two drop-tokens                                | Unblocks cellular ↔ home NAT                         |
| 10    | Executable warning + accept screen                                                           | Abuse mitigation you can ship in a day               |

**Explicitly not in this pile:** keystore/enclave, rooms, notes, voice, Shamir, push, Play/App Store, Pear runtime, Autobase, Yjs, phone-number topics, padding, duress.

**Phase-1 test bar (your refinements, kept):**

1. Laptop ↔ phone across **home NAT, cellular, public Wi‑Fi** (three paths).
2. Kill mid-transfer; resume; hashes match.
3. Both UIs show the same SHA-256 before “Done.”
4. First public builds may cap at **50 MB** so you learn UX, not disk IO.

If (1) fails without the relay, the relay is not optional. If (1) fails _with_ the relay, stop feature work.

---

## 5. Phased plan (harder work, correct order, why)

### Phase A — Engine on a desk (weeks 1–4)

**Goal:** two Windows (or Linux) machines, same room, then same house different VLANs.

- Packages: hyperswarm, hyperdht, hypercore-crypto, protomux, compact-encoding, b4a. Pin exact versions.
- Single repo: /engine (pure JS, no Electron) + /cli.
- In-memory then file-backed receive dir.
- Tests: two child processes, real swarm, hash assert (copy MeshDrop-core’s idea, not their app).

**Why this before UI:** NAT bugs hide under React. Solo-dev rule: if you cannot reproduce a failed transfer in the CLI, you cannot fix it.

### Phase B — Human drop (weeks 4–8)

**Goal:** a person who is not you can send a file.

- Desktop UI: drop zone, code, QR, Incoming / Sending, hash, Keep toggle (persists pk only).
- LAN Nearby list.
- Default save path + “open folder.”
- Connection states in English: _Looking / Punching / Relayed / Direct / Waiting for other device / Stuck — enable relay_.
- Rate limit: one inbound unsolicited drop at a time; block list.

**Why UI now:** engine exists; you need screenshots and a closed alpha of ~20 people.

### Phase C — Relay that makes the product true (weeks 6–10, overlaps B)

**Goal:** cellular phone → home PC works when both NATs are ugly.

- Small Node/Go service: pair two sockets by drop-id, 30–60 min TTL, 1–2 GB cap to start.
- Client tries direct, then relay, never blocks sending on punch.
- Metrics only you see: punch success vs relay ratio, bytes, errors. No user analytics.

**Why after LAN:** otherwise you will debug two failures at once. **Why before stores:** this is the claim DashBeam already makes; without it you are LocalSend.

**Why before “Keep forever” mesh:** a persistent joinPeer on a phone is the background-sync trap. Ephemeral + relay is enough for strangers.

### Phase D — Closed alpha quality (weeks 8–12)

- Resume across app restart (offset on disk).
- Folder as zip-or-tree (tree only if CLI already did files well; else zip in v1).
- Windows portable .exe + NSIS.
- Crash reports **opt-in**, stripped of paths.
- Threat-model page: DHT, relay, LAN.

**Alpha gate (50 users):** ≥80% transfers complete (direct or relay), crash-free sessions ≥95%, you can classify every failure.

### Phase E — Android receive/send (months 3–5)

- Same engine on a Node thread or RN JSI; **sync-on-open only**.
- No foreground service in v1 unless Play forces it for “transfer in progress.”
- Sideload APK + GitHub Releases first. Play Store only after the encryption questionnaire and a boring privacy policy.

**Why Android before iOS:** DashBeam already has Android; AirDrop does not exist; Play is slower than sideload but easier than Apple. **Why after relay:** a phone on LTE without relay is a 1-star review.

### Phase F — “Keep this device” that is still ephemeral-first (months 4–6)

- Trusted vs paired vs stranger.
- Auto-accept only for trusted.
- Reconnect via stored pk (joinPeer) when both apps are **open**.
- Still no 15-minute wakeups. Still no Autobase.

**Why after alpha metrics:** if week-1 retention <20%, pairing-forever will not save you; the first drop is broken.

### Phase G — Reach features (only if public gate passes)

Ordered by leverage for a solo maintainer:

1. **Receive-only web page** (slow is OK) — DashBeam’s real growth hack.
2. Linux AppImage + macOS dmg (you may need a borrowed Mac / CI).
3. Home-base pin: an always-on PC that accepts drops when the laptop is shut. Still not Shamir.
4. iOS last (export compliance, local-network permission, background rules).
5. Shelves / Autobase / notes CRDT — new product.

---

## 6. Abuse, legal, stores (ship the cheap controls)

**Ship in Phase B (hours, not months):**

- Show file name, size, type **before** accept.
- Warn on .exe .msi .apk .bat .js .scr .dmg .pkg.
- Default: accept required; “allow strangers” is a setting.
- In-app block.
- Relay: cap bandwidth and TTL; one connection per token.

**Do not ship in year one:** CSAM hash DB (legal process + false positives + you become a scanner), crypto deposits for relay, age gates that imply you host UGC, report buttons that imply you can see files.

**Legal posture (research with counsel before public launch):**

- Relay as transit, not hosting — say so in ToS.
- No EU “hosting provider” features (searchable public drops, stored mailboxes) until you decide you want DSA duties.
- US encryption export: when you touch App Store / Play, answer yes to encryption and file the annual self-classification if required.
- Do not geo-block casually; a warning page for high-risk users is enough until counsel says otherwise.
- You are not ready for “anti-surveillance” claims; budget a real audit ($50k–150k) only after you have paying-adjacent users or a grant.

**Stores:** Phase 1–D = GitHub Releases only. Play/Apple are a **Phase E+** project with a demo QR for reviewers and no duress/hidden-vault language in the binary or screenshots.

---

## 7. Delivery, updates, support, money (solo)

**Delivery**

|Channel|When|Why|
|---|---|---|
|GitHub Releases (Win portable + installer)|First public bit|You control it; DashBeam-style|
|Scoop / winget|After v0.2|Windows users actually find you|
|Flathub / AUR|When Linux exists|Low support if CI builds it|
|Play internal testing|After APK is stable|Not launch-critical|
|Pear pear:// seed|Optional side artifact|Holepunch crowd only|
|Website with 60s demo video|Before asking anyone to install|MeshDrop died without surface area|

Prefer **Tauri** if you are comfortable with Rust glue; **Electron** if you want one JS brain and faster UI iteration. Solo: Electron is the higher-probability choice. Do not start on Pear as the only runtime.

**Updates**

- Desktop: electron-updater or Tauri updater against GitHub Releases, **ed25519 signed**.
- Semver: 0.x until the NAT success gate.
- Relays and clients versioned together; old clients must still receive.
- No silent auto-relay change that sends people to a new host without a note.

**Support (you will drown if this is Slack-only)**

- One GitHub Issues template: OS, NAT path (home/cell/public), direct vs relay, log snippet.
- A 15-line troubleshooting page copied in spirit from DashBeam (won’t open / empty Nearby / stall / where did the file go).
- Discussions off until you have a second helper.
- Response SLA you can keep: 72 hours on “transfer failed,” ignore feature requests during Phase A–D.

**Donations / funding**

- GitHub Sponsors + a single “Support development” link. No crypto-in-app (review + scam optics).
- Liberapay/Ko-fi fine.
- Do not put paywalls on relay in v1; cap abuse instead. A later “bring your own relay” is the honest premium.
- Apply to Open Tech Fund / NGI **only after** you have a working drop and a privacy policy — those grants expect the high-risk story you are deferring.
- AGPL vs MIT: MIT/Apache on the **engine** maximizes forks and does not scare shops; keep the name trademarked. AGPL on the app if you fear a hosted clone of the GUI. DashBeam’s AGPL did not create their user base; the website and reliability did.

**What you will not do as the only developer:** Discord community management, 24 locales, security audit theater, three stores at once, a public SDK with stability promises.

---

## 8. Metrics and kill/pivot gates

Instrument locally (counts on _your_ relay + optional opt-in client). No third-party analytics.

|Metric|Month 6 target|Kill / pause Phase F|
|---|---|---|
|Transfer success (direct **or** relay)|≥75%|<50%|
|Of successes, relay share|Whatever it is; track it|If 100% relay and you cannot explain cost|
|10 MB median time, good path|<30–45 s|>2 min on LAN|
|Crash-free sessions|≥98%|<95%|
|Week-1 retention|~40% aspirational|<20% after 100 users → fix first-drop UX, do not build shelves|
|Invites per user|0.8|<0.3 → web receive or portable receiver is the next feature, not rooms|

**Go / no-go**

|Milestone|Criteria|Decision|
|---|---|---|
|Alpha ~50|80% complete, crashes <5%|Closed beta|
|Beta ~500|Week-1 ≥35%, median 10 MB <45 s|Public 0.x|
|Public ~5k|Store rating ≥4.0 _if listed_, organic ≥30%|Phase F Keep + home base|

---

## 9. Items that need more research (do not pretend they are settled)

Do these as short written spikes (1–2 days each), not as features.

1. **Holepunch dual-NAT failure rate vs Iroh in 2026** — measure _your_ punch vs DashBeam on the same two networks. If you lose badly, relay quality is the product.
2. **Best relay transport on Holepunch** — raw UDX holepunch helper, TCP, or WebSocket-over-443 (corporate Wi‑Fi). 443 almost always wins for “public café.”
3. **mDNS vs UDP multicast vs both** on Windows home routers and guest Wi‑Fi isolation.
4. ~~**Word list** — BIP39 vs EFF short words; homoglyphs; localization.~~ **Decided with item 3: EFF short list #1**, vendored. Its words are 3–5 letters against BIP39's up-to-8, and item 3 exists to remove hand-typing friction; and a six-word BIP39 phrase reads as a wallet seed phrase, which fights §6's avoidance of crypto optics. ~62 bits over six words. Dropped the list's one hyphenated word (`yo-yo`) so the hyphen stays an unambiguous separator. Homoglyphs and localization remain open but are Phase B UI concerns, not blockers — EFF short #2 (unique 3-char prefix, edit distance ≥3) is the fallback if typo rates justify longer words. See `docs/ARCHITECTURE.md`.
5. ~~**QR payload size** on cheap Android cameras; what to put in-band vs after handshake.~~ **Decided with item 3: the typed code and nothing else**, as `QUAY1:ACID-ACORN-…` — so scanning and typing are one code path, not two. Measured: uppercase keeps it in QR alphanumeric mode, worth one version of headroom, spent on **ECC level Q at version 3 (29×29)** rather than a smaller symbol. The `QUAY1` prefix reserves room for the in-band sender public key (direct `joinPeer`, skipping the topic lookup) when items 4/7 want it. Verified by decoding the printed matrix in `cli/test/code.test.js`.
6. **Hypercore vs custom chunk stream** for files >1 GB (memory, sparse verify). Revisit before raising the 50 MB cap.
7. **blind-peer / holepunch blind peering** as a future home-base instead of your own mailbox protocol.
8. **Apple/Google exact language** for “P2P encrypted file transfer, no accounts, optional relay.” Read current guideline 5.1 + encryption questions before any iOS work.
9. **DSA / “hosting”** if you ever store an encrypted blob for async pickup.
10. **Competitor feature watch** — DashBeam trusted-devices (already ships) and iOS. If they ship iOS before you ship Android, your Phase E still stands (Windows+Android is a real market).
11. **Signing and SmartScreen / Gatekeeper** — budget time for a cheap code-signing cert; otherwise Windows will train users to click through warnings (and malware will impersonate you).
12. **IPv6 and CGNAT** on the carriers you actually use.

---

## 10. Working principle

Compete with **AirDrop** on “it just works across OSes” and with **email attachments** on speed and size. Use Holepunch because pairing-as-identity will matter in Phase F, not because Hyperswarm is a brand. Use a relay because most P2P tools die on NAT, not because you want to be Tor.

First users reward **completed transfers**. Second-wave users reward **privacy copy**. Build for the first wave. Keep the key hierarchy and “Keep this device” clean so the second wave can arrive without a rewrite.
