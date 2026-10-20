# 20261018 same-host-macos-starlink

Date: 2026-10-18, harness started 17:11 PDT; first slot 17:15:00 PDT; last run ended 17:58 PDT
Commit: 0e68af74539a on every machine, clean
Trials: 20 per direction
File: 10 MiB (10485760 bytes) /tmp/test.bin
Slot: 135 seconds, refresh 4000 ms
Run A: Machine 1 receiver, Machine 1 sender (seed `samehost1`, slot start 1792368900, 17:15:00 PDT)

## Machine 1

Host: DecentralizedDefender.local (darwin/arm64), node v24.21.0
OS: macOS 26.5.2 (25F84)
Network/carrier/ISP: Starlink (AS14593 on 2026-10-15), per the run's configuration; not looked up for this run
Access type: Wi-Fi via en0 (Wi-Fi) to the Starlink router, satellite uplink, per the run's configuration
NAT: DHT saw consistent, port translated, firewalled at start; per trial: consistent 40; Starlink CGNAT, per the run's configuration. The Linux machine on Starlink saw the same, port translated, on 2026-10-15
Firewall/router: host firewall disabled, stealth mode off (macOS application firewall); DHT finds it firewalled; router: Starlink, settings not recorded
VPN/relay/hotspot: VPN: not on the route; configured services: ProtonVPN (disconnected); hotspot: none detected; relay: none (the harness configures no relay)
Notes: same machine as sender; same machine as receiver

## Results

| Run | Direction | Sender | Receiver |
| --- | --- | --- | --- |
| A | Machine 1 (macOS) → Machine 1 (macOS) | 20/20 | 20/20 |

## Checks

- Run A (seed `samehost1`): both sides ran on DecentralizedDefender.local.
- Machine 1: a trial connected from a private address, i.e. the same LAN, not a punch across the internet.
