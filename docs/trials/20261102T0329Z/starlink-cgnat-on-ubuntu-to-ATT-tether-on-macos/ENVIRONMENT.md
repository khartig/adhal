# starlink-cgnat-on-ubuntu-to-ATT-tether-on-macos

Date: 2026-11-01, harness started 19:24 PST; first slot 19:29:09 PST; last run ended 22:10 PST
Commit: d188c2e4e902 on both machines, clean
Trials: 20 per direction
File: 10 MiB (10485760 bytes) /tmp/test.bin
Slot: 240 seconds, refresh 4000 ms
Run A: Machine 1 receiver, Machine 2 sender (seed `20261102T0329Z-starlink-cgnat-on-ubuntu-to-ATT-tether-on-macos-a`, slot start 1793590149, 19:29:09 PST)
Run B: Machine 1 sender, Machine 2 receiver (seed `20261102T0329Z-starlink-cgnat-on-ubuntu-to-ATT-tether-on-macos-b`, slot start 1793595249, 20:54:09 PST)

## Machine 1

Host: agenticMaster (linux/x64), node v24.21.0
OS: Ubuntu 24.04.4 LTS
Network/carrier/ISP: AS14593 SPACEX-STARLINK - Space Exploration Technologies Corporation, US
Access type: Wi-Fi via wlp4s0b1 (driver b43) on the Starlink network, satellite uplink, per the note and the ISP lookup. No eero on this side
NAT: DHT saw consistent, port translated, firewalled at start; Starlink CGNAT, per the run's configuration (the host has no 100.64.0.0/10 address, so the CGNAT is upstream and not visible from here)
Firewall/router: host firewall enabled: ufw; DHT finds it firewalled; router: Starlink, settings not recorded
VPN/relay/hotspot: VPN: not on the route; hotspot: none detected; relay: none (the harness configures no relay)
Notes: recorded as "starlnk wifi on Ubuntu server; eero firewall on, default rules". The Starlink Wi-Fi part is right. The eero part is left over from earlier runs and describes neither machine here: this side does not go through an eero, and Machine 2 was on a phone hotspot. That wording is not accurate either: the eero app has no firewall setting. It matches, word for word, an example note that `docs/TESTING.md` gave at the time.

## Machine 2

Host: DecentralizedDefender.local (darwin/arm64), node v24.22.1
OS: macOS 27.0.1 (26A434)
Network/carrier/ISP: AS7018 ATT-INTERNET4 - AT&T Enterprises, LLC, US
Access type: Wi-Fi via en0 (Wi-Fi) to a Samsung Galaxy S24+ hotspot, tethered over AT&T 5G at 1-2 bars, per the note
NAT: DHT saw consistent, port translated, firewalled at start; the phone's hotspot NAT, then AT&T's network. A carrier NAT there is likely but not visible from here (the host has no 100.64.0.0/10 address)
Firewall/router: host firewall disabled, stealth mode off (macOS application firewall); DHT finds it firewalled; router: none, the phone's hotspot
VPN/relay/hotspot: VPN: not on the route; configured services: ProtonVPN (disconnected); hotspot: yes, the Samsung Galaxy S24+'s Android mobile hotspot, per the note. The harness detected none: it recognizes only the iPhone hotspot's gateway address and the one older Android hotspots used; relay: none (the harness configures no relay)
Notes: AT&T tether via Samsung Galaxy S24+, 1-2 bars, 5G

## Results

| Run | Direction | Sender | Receiver |
| --- | --- | --- | --- |
| A | Machine 2 (macOS) → Machine 1 (Linux) | 20/20 | 20/20 |
| B | Machine 1 (Linux) → Machine 2 (macOS) | 20/20 | 20/20 |

## Checks

No mismatches between the sides.

All 80 records are `ok`: 10485760 bytes, exit 0, one candidate peer, no dropped connections, no bad confirmations, and no contract violations. On each receiver, the offered SHA-256, the delivered SHA-256, and the harness's own hash of the written file all match. Every receiver's `done` was acknowledged. The sender's and receiver's timings agree to within 0.6 s on every trial.

The `env role=undefined seed=undefined trials=10 slot=135s` line near the top of each log is the `--environment-only` probe printing its own default header. The run's real settings are on the line above it, and they are what the JSON records.

## What the run shows

**A direct path in both directions, every time, over a weak cellular link.** A phone tether on AT&T at 1-2 bars of 5G and Starlink CGNAT connected directly in all 40 trials. Both sides' NATs were `consistent, port translated`, so this was not the randomized-NAT case. Each run's 20/20 has a 95% Wilson interval of 84% to 100%.

The timings below are from the receivers' logs.

| Run | Direction | Connect median (p90, max) | Transfer median (p90, max) | Complete median (p90, max) |
| --- | --- | --- | --- | --- |
| A | macOS (AT&T tether) → Linux (Starlink) | 4.9 s (6.1, 6.6) | 53.6 s (95.1, 98.4) | 59.1 s (100.4, 102.9) |
| B | Linux (Starlink) → macOS (AT&T tether) | 3.8 s (6.7, 7.0) | 16.5 s (18.4, 23.2) | 20.6 s (24.3, 27.1) |

- **Run A, uploading over the tether, was the slow direction.** Its median was about 1.6 Mbit/s for 10 MiB, and its slowest trial about 0.85 Mbit/s. On 2026-11-01, Starlink took the same file in 9.7 s at the median, so the bottleneck here is most likely the tether's uplink. Run A was also uneven: transfers ranged from 39.8 to 98.4 s, and four of its last five trials (17 to 20) took 79 to 95 s.
- **Run B, downloading over the tether, was quick and steady,** at about 5 Mbit/s. Only trial 18 (23.2 s) stands out.
- **Connecting was not slowed by the weak signal.** Connect medians of 3.8 to 4.9 s are close to the 2026-11-01 Comcast run (3.7 and 4.4 s).
- **The 240 s slot left ample room.** The slowest trial completed in 102.9 s.
- The CLI trials record a NAT snapshot only at the start, and no per-connection UDX counters. So this run cannot show whether the carrier NAT changed during the run, or whether run A's slow trials were retransmitting.
