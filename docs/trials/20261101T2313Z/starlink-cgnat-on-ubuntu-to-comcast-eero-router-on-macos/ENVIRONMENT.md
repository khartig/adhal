# starlink-cgnat-on-ubuntu-to-comcast-eero-router-on-macos

Date: 2026-11-01, harness started 15:08 PST; first slot 15:13:53 PST; last run ended 16:47 PST
Commit: 361ddba43b74 on both machines, clean
Trials: 20 per direction
File: 10 MiB (10485760 bytes) /tmp/test.bin
Slot: 135 seconds, refresh 4000 ms
Run A: Machine 1 receiver, Machine 2 sender (seed `20261101T2313Z-starlink-cgnat-on-ubuntu-to-comcast-eero-router-on-macos-a`, slot start 1793574833, 15:13:53 PST)
Run B: Machine 1 sender, Machine 2 receiver (seed `20261101T2313Z-starlink-cgnat-on-ubuntu-to-comcast-eero-router-on-macos-b`, slot start 1793577833, 16:03:53 PST)

## Machine 1

Host: agenticMaster (linux/x64), node v24.21.0
OS: Ubuntu 24.04.4 LTS
Network/carrier/ISP: Starlink, per the run's configuration; not looked up for this run (no --lookup-isp)
Access type: Wi-Fi via wlp4s0b1 (driver b43) to the Starlink router, satellite uplink, per the run's configuration
NAT: DHT saw consistent, port translated, firewalled at start; Starlink CGNAT, per the run's configuration (the host has no 100.64.0.0/10 address, so the CGNAT is beyond the Starlink router)
Firewall/router: host firewall enabled: ufw; DHT finds it firewalled; router: Starlink, settings not recorded
VPN/relay/hotspot: VPN: not on the route; hotspot: none detected; relay: none (the harness configures no relay)
Notes: recorded as "eero firewall on, default rules". The --note was passed on this machine, but this side does not go through an eero. That wording is not accurate either: the eero app has no firewall setting. It matches, word for word, an example note that `docs/TESTING.md` gave at the time.

## Machine 2

Host: DecentralizedDefender.local (darwin/arm64), node v24.22.1
OS: macOS 27.0.1 (26A434)
Network/carrier/ISP: Comcast Xfinity, per the run's configuration; not looked up for this run (no --lookup-isp)
Access type: Wi-Fi via en0 (Wi-Fi) to an eero router on Comcast Xfinity, per the run's configuration; the eero's uplink is an Xfinity gateway in router mode
NAT: DHT saw consistent, port preserved, firewalled at start; double NAT (the eero, then the Xfinity gateway in router mode), and the port was preserved through both; no CGNAT is known on this side
Firewall/router: host firewall disabled, stealth mode off (macOS application firewall); DHT finds it firewalled; router: eero
Router configuration: recorded on 2026-11-03, and the same for every run on this network. An eero Pro 6E in Automatic (DHCP & NAT) mode, behind an Xfinity gateway in router mode: a double NAT, with the eero's own internet address private. UPnP on, which Adhal does not use (hyperswarm 4.17.1 and hyperdht 6.34.0 have no UPnP code). Port forwarding enabled, with no rules and no reservations. IPv6 off. eero Labs off. eero software 26.13.0.36807 when checked; the version at the time of the run was not recorded. Uplink: Comcast Xfinity, about 300 Mbit/s down and 35 Mbit/s up in practice (the plan says up to 1.3 Gbit/s)
VPN/relay/hotspot: VPN: not on the route; configured services: ProtonVPN (disconnected); hotspot: none detected; relay: none (the harness configures no relay)

## Results

| Run | Direction | Sender | Receiver |
| --- | --- | --- | --- |
| A | Machine 2 (macOS) → Machine 1 (Linux) | 20/20 | 20/20 |
| B | Machine 1 (Linux) → Machine 2 (macOS) | 20/20 | 20/20 |

## Checks

No mismatches between the sides.

All 80 records are `ok`: 10485760 bytes, exit 0, one candidate peer, no dropped connections, no bad confirmations, and no contract violations. Each receiver's SHA-256 matches the one it was offered, and the harness's own hash of the written file matches too. Every receiver's `done` was acknowledged.

The `env role=undefined seed=undefined trials=10` line near the top of each log is from the `--environment-only` probe printing its own default header. The run's real settings are on the line above it (`trials=20`), and they are what the JSON records.

## What the run shows

**A direct path in both directions, every time.** Starlink CGNAT on one side and an eero on Comcast on the other punched through in all 40 trials. That matches this pairing's 2026-10-15 run, which used the engine harness (`scratch-trials.js`). This run goes through the published CLIs (`ad-hal-send`/`ad-hal-receive`, version 0.1.2). Each run's 20/20 has a 95% Wilson interval of 84% to 100%.

The timings below are from the receivers' logs. The senders' figures agree to within 0.2 s, with three exceptions. In run A, the sender's connect was 1.2 s later on trial 2 and 0.3 s later on trial 7. In run B, trial 6, the receiver's transfer was 1.7 s longer than the sender's.

| Run | Direction | Connect median (p90, max) | Transfer median (p90, max) | Complete median (p90, max) |
| --- | --- | --- | --- | --- |
| A | macOS (Comcast) → Linux (Starlink) | 3.7 s (4.8, 5.3) | 9.7 s (34.3, 38.8) | 14.0 s (38.1, 42.7) |
| B | Linux (Starlink) → macOS (Comcast) | 4.4 s (7.1, 8.0) | 12.0 s (16.0, 23.6) | 17.6 s (22.6, 27.3) |

- **Run A** had the faster median transfer, about 8.6 Mbit/s for 10 MiB. Its tail was longer: trials 2, 8, and 14 took 29 to 39 s, and trials 1 and 11 took about 18.6 s. The two sides agree on those times, so the cause is the path's throughput during those trials, not either process. The CLI trials record no per-connection UDX counters, so this run cannot say whether those trials were retransmitting.
- **The Comcast uplink was not the limit in run A.** At about 35 Mbit/s up in practice, it would move 10 MiB in under 3 s, against the 9.7 s median.
- **Run B**, where Starlink is the uploading side, was slower at the median (about 7 Mbit/s) but steadier. Only trial 19 (23.6 s) stands out. Its connects were slower and more spread, from 3.0 to 8.0 s.
- The CLI trials record a NAT snapshot only at the start, not per trial, so a NAT that changed during the run would not show here.
