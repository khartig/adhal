# 20261019 eero-guest-to-eero-main-hairpin2

Date: 2026-10-19, harness started 21:05 PDT; first slot 21:09:29 PDT; last run ended 21:56 PDT
Commit: 7b147e3eb7da on both machines, clean
Trials: 10 per direction
File: 10 MiB (10485760 bytes) /tmp/test.bin
Slot: 135 seconds, refresh 4000 ms
Run A: Machine 1 receiver, Machine 2 sender (seed `20261019-eero-guest-to-eero-main-hairpin2-a`, slot start 1792469369, 21:09:29 PDT)
Run B: Machine 1 sender, Machine 2 receiver (seed `20261019-eero-guest-to-eero-main-hairpin2-b`, slot start 1792470869, 21:34:29 PDT)

## Machine 1

Host: DecentralizedDefender.local (darwin/arm64), node v24.21.0
OS: macOS 26.5.2 (25F84)
Network/carrier/ISP: AS7922 COMCAST-7922 - Comcast Cable Communications, LLC, US
Access type: Wi-Fi via en0 (Wi-Fi) to the eero Pro 6E's guest network (gateway 192.168.12.1), per the run's configuration; the eero's uplink is an Xfinity gateway in router mode, on Comcast Xfinity
NAT: DHT saw consistent, port preserved, firewalled at start; per trial: consistent 20, port preserved on all 20; double NAT (the eero, then the Xfinity gateway in router mode), the same as Machine 2's, and the same public IP, which is the gateway's; no CGNAT is known on this side
Firewall/router: host firewall disabled, stealth mode off (macOS application firewall); DHT finds it firewalled; router: eero Pro 6E, guest network isolation on, other rules not recorded
Router configuration: recorded on 2026-11-03, and the same for every run on this network, except the guest network, which was on only for this run. An eero Pro 6E in Automatic (DHCP & NAT) mode, behind an Xfinity gateway in router mode: a double NAT, with the eero's own internet address private. UPnP on, which Adhal does not use (hyperswarm 4.17.1 and hyperdht 6.34.0 have no UPnP code). Port forwarding enabled, with no rules and no reservations. IPv6 off. eero Labs off. eero software 26.13.0.36807 when checked; the version at the time of the run was not recorded. Uplink: Comcast Xfinity, about 300 Mbit/s down and 35 Mbit/s up in practice (the plan says up to 1.3 Gbit/s)
VPN/relay/hotspot: VPN: not on the route; configured services: ProtonVPN (disconnected); hotspot: none detected; relay: none (the harness configures no relay)
Notes: eero guest Wi-Fi, isolated from the main LAN; same eero and Comcast public IP as the peer; router: eero Pro 6E

## Machine 2

Host: agenticMaster (linux/x64), node v24.21.0
OS: Ubuntu 24.04.4 LTS
Network/carrier/ISP: AS7922 COMCAST-7922 - Comcast Cable Communications, LLC, US
Access type: Wi-Fi via wlp4s0b1 (driver b43) to the eero Pro 6E's main network (gateway 192.168.4.1), per the run's configuration; the eero's uplink is an Xfinity gateway in router mode, on Comcast Xfinity
NAT: DHT saw consistent, port preserved, firewalled at start; per trial: consistent 20, port preserved on 19, translated on run B trial 1 (which failed like the rest); double NAT (the eero, then the Xfinity gateway in router mode), the same as Machine 1's, and the same public IP, which is the gateway's; no CGNAT is known on this side
Firewall/router: host firewall enabled: ufw; DHT finds it firewalled; router: eero Pro 6E, main network, rules not recorded
Router configuration: recorded on 2026-11-03, and the same for every run on this network, except the guest network, which was on only for this run. An eero Pro 6E in Automatic (DHCP & NAT) mode, behind an Xfinity gateway in router mode: a double NAT, with the eero's own internet address private. UPnP on, which Adhal does not use (hyperswarm 4.17.1 and hyperdht 6.34.0 have no UPnP code). Port forwarding enabled, with no rules and no reservations. IPv6 off. eero Labs off. eero software 26.13.0.36807 when checked; the version at the time of the run was not recorded. Uplink: Comcast Xfinity, about 300 Mbit/s down and 35 Mbit/s up in practice (the plan says up to 1.3 Gbit/s)
VPN/relay/hotspot: VPN: not on the route; hotspot: none detected; relay: none (the harness configures no relay)
Notes: eero main Wi-Fi on Comcast Xfinity; same eero and Comcast public IP as the peer; router: eero Pro 6E

## Results

| Run | Direction | Sender | Receiver |
| --- | --- | --- | --- |
| A | Machine 2 (Linux) → Machine 1 (macOS) | 0/10 | 0/10 |
| B | Machine 1 (macOS) → Machine 2 (Linux) | 0/10 | 0/10 |

- Run A sender, trial 1: `no-peer`
- Run A sender, trial 2: `no-peer`
- Run A sender, trial 3: `no-peer`
- Run A sender, trial 4: `no-peer`
- Run A sender, trial 5: `no-peer`
- Run A sender, trial 6: `no-peer`
- Run A sender, trial 7: `no-peer`
- Run A sender, trial 8: `no-peer`
- Run A sender, trial 9: `no-peer`
- Run A sender, trial 10: `no-peer`
- Run A receiver, trial 1: `no-peer` (phase accept)
- Run A receiver, trial 2: `no-peer` (phase accept)
- Run A receiver, trial 3: `no-peer` (phase accept)
- Run A receiver, trial 4: `no-peer` (phase accept)
- Run A receiver, trial 5: `no-peer` (phase accept)
- Run A receiver, trial 6: `no-peer` (phase accept)
- Run A receiver, trial 7: `no-peer` (phase accept)
- Run A receiver, trial 8: `no-peer` (phase accept)
- Run A receiver, trial 9: `no-peer` (phase accept)
- Run A receiver, trial 10: `no-peer` (phase accept)
- Run B sender, trial 1: `no-peer`
- Run B sender, trial 2: `no-peer`
- Run B sender, trial 3: `no-peer`
- Run B sender, trial 4: `no-peer`
- Run B sender, trial 5: `no-peer`
- Run B sender, trial 6: `no-peer`
- Run B sender, trial 7: `no-peer`
- Run B sender, trial 8: `no-peer`
- Run B sender, trial 9: `no-peer`
- Run B sender, trial 10: `no-peer`
- Run B receiver, trial 1: `no-peer` (phase accept)
- Run B receiver, trial 2: `no-peer` (phase accept)
- Run B receiver, trial 3: `no-peer` (phase accept)
- Run B receiver, trial 4: `no-peer` (phase accept)
- Run B receiver, trial 5: `no-peer` (phase accept)
- Run B receiver, trial 6: `no-peer` (phase accept)
- Run B receiver, trial 7: `no-peer` (phase accept)
- Run B receiver, trial 8: `no-peer` (phase accept)
- Run B receiver, trial 9: `no-peer` (phase accept)
- Run B receiver, trial 10: `no-peer` (phase accept)

## Checks

No mismatches between the sides.

Addresses: recorded with `--record-addresses`, then redacted before commit. Both machines' DHT-observed public IP was the same Comcast address, and it is replaced by `redacted-shared-public-ip` in every log and JSON. The ports and the private gateway addresses are kept. The unredacted files are not in the repository.

## What the run shows

**No direct path, in either direction.** All 40 records are `no-peer`. Every receiver announced within 3.4 to 7.9 s of its slot, so each trial's peer was on the DHT for the whole 120 s the sender searched. The two machines are behind one eero with one public IP, on subnets the guest network's isolation keeps apart. With the same public IP on both sides, hyperdht 6.34.0 races a LAN ping against a hole punch to the shared public address (`lib/connect.js`, lines 248-270). Isolation drops the LAN ping, and the punch needs a NAT to hairpin, which did not happen. The shared public address is the Xfinity gateway's, because the eero sits behind it in router mode (a double NAT, recorded on 2026-11-03). So the hairpin would have had to happen at the gateway, and the traffic would then have had to come back in through the eero. This run cannot tell apart three causes: the gateway does not hairpin, the eero dropped the hairpinned traffic, or the guest isolation dropped it. Either way, a relay is the only path for this pair.

## Diagnostics, 2026-10-19, between the first attempt and this run

- **Guest to main, by hand.** `scratch-serve.js` on Machine 1 (guest), `scratch-lookup.js --connect` on Machine 2 (main). Machine 2 found Machine 1's announce in 0.5 s, then the dial failed with `HOLEPUNCH_ABORTED`. A second announce under the same topic, left by an earlier `scratch-serve.js` that had exited, failed with `PEER_CONNECTION_FAILED`. So discovery works across the split, and the failure is the hole punch.
- **The control.** The same diagnostic with Machine 1 moved to the main Wi-Fi: found, and `CONNECTED` 1.3 s after the dial began. Guest isolation is the only difference between the two diagnostics.

## The first attempt

[`../eero-guest-to-eero-main-hairpin/`](../eero-guest-to-eero-main-hairpin/) holds Machine 1's logs from an earlier attempt the same evening (seed `20261019-eero-guest-to-eero-main-hairpin-a`, 20 trials planned). It was stopped after two trials, both `no-peer`, when the diagnostics above were run instead. Machine 2's files were not saved, because its run directory did not exist, and neither side wrote JSON. Its run B log is only the header: that run was stopped before its first slot. The router note there still reads `eero <model>`. It was the same eero Pro 6E.
