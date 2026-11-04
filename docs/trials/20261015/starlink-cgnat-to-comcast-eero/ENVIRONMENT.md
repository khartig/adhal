# 20261015 starlink-cgnat-to-comcast-eero

Date: 2026-10-15, harness started 14:21 PDT; first slot 14:25:10 PDT; last run ended 15:58 PDT
Commit: 8bc808a27b56 on both machines, clean
Trials: 20 per direction
File: 10 MiB (10485760 bytes) /tmp/test.bin
Slot: 135 seconds, refresh 4000 ms
Run A: Machine 1 receiver, Machine 2 sender (seed `20261015-starlink-cgnat-to-comcast-eero-a`, slot start 1792099510, 14:25:10 PDT)
Run B: Machine 1 sender, Machine 2 receiver (seed `20261015-starlink-cgnat-to-comcast-eero-b`, slot start 1792102510, 15:15:10 PDT)

## Machine 1

Host: DecentralizedDefender.local (darwin/arm64), node v24.21.0
OS: macOS 26.5.2 (25F84)
Network/carrier/ISP: AS7922 COMCAST-7922 - Comcast Cable Communications, LLC, US
Access type: Wi-Fi via en0 (Wi-Fi) to an eero router on Comcast Xfinity, per the run's configuration; the eero's uplink is an Xfinity gateway in router mode
NAT: DHT saw consistent, port preserved, firewalled at start; per trial: consistent 40; double NAT (the eero, then the Xfinity gateway in router mode), and the port was preserved through both; no CGNAT is known on this side
Firewall/router: host firewall disabled, stealth mode off (macOS application firewall); DHT finds it firewalled; router: eero, rules not recorded
Router configuration: recorded on 2026-11-03, and the same for every run on this network. An eero Pro 6E in Automatic (DHCP & NAT) mode, behind an Xfinity gateway in router mode: a double NAT, with the eero's own internet address private. UPnP on, which Adhal does not use (hyperswarm 4.17.1 and hyperdht 6.34.0 have no UPnP code). Port forwarding enabled, with no rules and no reservations. IPv6 off. eero Labs off. eero software 26.13.0.36807 when checked; the version at the time of the run was not recorded. Uplink: Comcast Xfinity, about 300 Mbit/s down and 35 Mbit/s up in practice (the plan says up to 1.3 Gbit/s)
VPN/relay/hotspot: VPN: not on the route; configured services: ProtonVPN (disconnected); hotspot: none detected; relay: none (the harness configures no relay)

## Machine 2

Host: agenticMaster (linux/x64), node v24.21.0
OS: Ubuntu 24.04.4 LTS
Network/carrier/ISP: AS14593 SPACEX-STARLINK - Space Exploration Technologies Corporation, US
Access type: Wi-Fi via wlp4s0b1 (driver b43) to the Starlink router, satellite uplink, per the run's configuration
NAT: DHT saw consistent, port translated, firewalled at start; per trial: consistent 40; Starlink CGNAT, per the run's configuration
Firewall/router: host firewall enabled: ufw; DHT finds it firewalled; router: Starlink, settings not recorded
VPN/relay/hotspot: VPN: not on the route; hotspot: none detected; relay: none (the harness configures no relay)

## Results

| Run | Direction | Sender | Receiver |
| --- | --- | --- | --- |
| A | Machine 2 (Linux) → Machine 1 (macOS) | 20/20 | 20/20 |
| B | Machine 1 (macOS) → Machine 2 (Linux) | 20/20 | 20/20 |

## Checks

No mismatches between the sides.
