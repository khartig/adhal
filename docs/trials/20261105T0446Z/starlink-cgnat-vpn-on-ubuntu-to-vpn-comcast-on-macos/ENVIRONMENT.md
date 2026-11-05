# starlink-cgnat-vpn-on-ubuntu-to-vpn-comcast-on-macos

Date: 2026-11-04, harness started 20:41 PST; first slot 20:46:17 PST; last run ended 23:31 PST
Commit: d9a0598a952b on both machines, clean
Trials: 20 per direction
File: 10 MiB (10485760 bytes) /tmp/test.bin
Slot: 240 seconds, refresh 4000 ms
Run A: Machine 1 receiver, Machine 2 sender (seed `20261105T0446Z-starlink-cgnat-vpn-on-ubuntu-to-vpn-comcast-on-macos-a`, slot start 1793853977, 20:46:17 PST)
Run B: Machine 1 sender, Machine 2 receiver (seed `20261105T0446Z-starlink-cgnat-vpn-on-ubuntu-to-vpn-comcast-on-macos-b`, slot start 1793859077, 22:11:17 PST)

## Machine 1

Host: agenticMaster (linux/x64), node v24.21.0
OS: Ubuntu 24.04.4 LTS
Network/carrier/ISP: AS212238 CDNEXT - Datacamp Limited, GB. This is the network of the ProtonVPN exit server, which is all the lookup can see. GB is where the network is registered, not where the server is. The exit server was United States US-CA#856, the same as Machine 2's, as reported after the run. Underneath the tunnel: Starlink, per the note
Access type: a VPN tunnel via proton0 (ProtonVPN, WireGuard protocol, as reported after the run; this machine's note does not name the protocol), carried over Starlink Wi-Fi, per the note
NAT: DHT saw randomized, firewalled at start. This is the VPN exit's NAT. Starlink's CGNAT is inside the tunnel, so the DHT does not see it
Firewall/router: host firewall enabled: ufw; DHT finds it firewalled; router: Starlink, settings not recorded
VPN/relay/hotspot: VPN: the route to the internet went through a tunnel; tunnel interfaces up: proton0; hotspot: none detected; relay: none (the harness configures no relay)
Notes: starlnk wifi. protonVPN randomized on Ubuntu server

## Machine 2

Host: DecentralizedDefender.local (darwin/arm64), node v24.22.1
OS: macOS 27.0.1 (26A434)
Network/carrier/ISP: AS212238 CDNEXT - Datacamp Limited, GB. This is the network of the ProtonVPN exit server, as for Machine 1. It was the same exit server, United States US-CA#856. Underneath the tunnel: Comcast Xfinity
Access type: a VPN tunnel via utun4 (ProtonVPN, WireGuard protocol, per the note), carried over Wi-Fi to an eero router on Comcast Xfinity
NAT: DHT saw randomized, firewalled at start. This is the VPN exit's NAT. The eero's NAT and the Xfinity gateway's are inside the tunnel, so the DHT does not see them
Firewall/router: host firewall disabled, stealth mode off (macOS application firewall); DHT finds it firewalled; router: eero
Router configuration: recorded on 2026-11-03, and the same for every run on this network. An eero Pro 6E in Automatic (DHCP & NAT) mode, behind an Xfinity gateway in router mode: a double NAT, with the eero's own internet address private. UPnP on, which Adhal does not use (hyperswarm 4.17.1 and hyperdht 6.34.0 have no UPnP code). Port forwarding enabled, with no rules and no reservations. IPv6 off. eero Labs off. eero software 26.13.0.36807 when checked; the version at the time of the run was not recorded. Uplink: Comcast Xfinity, about 300 Mbit/s down and 35 Mbit/s up in practice (the plan says up to 1.3 Gbit/s)
VPN/relay/hotspot: VPN: the route to the internet went through a tunnel; configured services: ProtonVPN (connected); hotspot: none detected; relay: none (the harness configures no relay)
Notes: Proton VPN. Wireguard protocol. Eero router

## Results

| Run | Direction | Sender | Receiver |
| --- | --- | --- | --- |
| A | Machine 2 (macOS) → Machine 1 (Linux) | 0/20 | 0/20 |
| B | Machine 1 (Linux) → Machine 2 (macOS) | 0/20 | 0/20 |

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
- Run A sender, trial 11: `no-peer`
- Run A sender, trial 12: `no-peer`
- Run A sender, trial 13: `no-peer`
- Run A sender, trial 14: `no-peer`
- Run A sender, trial 15: `no-peer`
- Run A sender, trial 16: `no-peer`
- Run A sender, trial 17: `no-peer`
- Run A sender, trial 18: `no-peer`
- Run A sender, trial 19: `no-peer`
- Run A sender, trial 20: `no-peer`
- Run A receiver, trial 1: `no-peer`
- Run A receiver, trial 2: `no-peer`
- Run A receiver, trial 3: `no-peer`
- Run A receiver, trial 4: `no-peer`
- Run A receiver, trial 5: `no-peer`
- Run A receiver, trial 6: `no-peer`
- Run A receiver, trial 7: `no-peer`
- Run A receiver, trial 8: `no-peer`
- Run A receiver, trial 9: `no-peer`
- Run A receiver, trial 10: `no-peer`
- Run A receiver, trial 11: `no-peer`
- Run A receiver, trial 12: `no-peer`
- Run A receiver, trial 13: `no-peer`
- Run A receiver, trial 14: `no-peer`
- Run A receiver, trial 15: `no-peer`
- Run A receiver, trial 16: `no-peer`
- Run A receiver, trial 17: `no-peer`
- Run A receiver, trial 18: `no-peer`
- Run A receiver, trial 19: `no-peer`
- Run A receiver, trial 20: `no-peer`
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
- Run B sender, trial 11: `no-peer`
- Run B sender, trial 12: `no-peer`
- Run B sender, trial 13: `no-peer`
- Run B sender, trial 14: `no-peer`
- Run B sender, trial 15: `no-peer`
- Run B sender, trial 16: `no-peer`
- Run B sender, trial 17: `no-peer`
- Run B sender, trial 18: `no-peer`
- Run B sender, trial 19: `no-peer`
- Run B sender, trial 20: `no-peer`
- Run B receiver, trial 1: `no-peer`
- Run B receiver, trial 2: `no-peer`
- Run B receiver, trial 3: `no-peer`
- Run B receiver, trial 4: `no-peer`
- Run B receiver, trial 5: `no-peer`
- Run B receiver, trial 6: `no-peer`
- Run B receiver, trial 7: `no-peer`
- Run B receiver, trial 8: `no-peer`
- Run B receiver, trial 9: `no-peer`
- Run B receiver, trial 10: `no-peer`
- Run B receiver, trial 11: `no-peer`
- Run B receiver, trial 12: `no-peer`
- Run B receiver, trial 13: `no-peer`
- Run B receiver, trial 14: `no-peer`
- Run B receiver, trial 15: `no-peer`
- Run B receiver, trial 16: `no-peer`
- Run B receiver, trial 17: `no-peer`
- Run B receiver, trial 18: `no-peer`
- Run B receiver, trial 19: `no-peer`
- Run B receiver, trial 20: `no-peer`

## Checks

- Both machines are behind randomized NATs: the hard pair, which needs a relay.

Both machines ran `d9a0598`, clean. That commit includes the CLIs' `connection` counters, but every `path` here is null, because no trial ever paired.

**The `killed` flags are an artifact of the harness's timing, not hangs.** 45 of the 80 records show `killed: true`, but every one of them is bucketed `no-peer` by its own `failed` event (`ERR_NO_PEER`), which the CLI wrote before it was stopped. The CLI's join timeout fired at the end of its budget, and the CLI then took 1.1 to 1.4 s to tear down its swarm and exit. The harness sends its stop signal 1.5 s after the budget (`STOP_AFTER_BUDGET_MS` in `tools/cli-trials.js`), counted from a timer that starts before Node has loaded the CLI. So the slower teardowns were still exiting when the signal arrived. The outcomes are unaffected.

## What the run shows

**No direct path, in either direction: 0 of 80 records connected.** This is the outcome hyperdht is built to give this pair, not a measurement of bad luck. Both sides' NATs were randomized, a new external port for each destination, because both machines were behind ProtonVPN exits. hyperdht 6.34.0 does not attempt a hole punch between two randomized NATs. `lib/connect.js` aborts the attempt with `HOLEPUNCH_DOUBLE_RANDOMIZED_NATS` (line 669) once each side knows the other's NAT type. With no relay configured, nothing else can connect them. So two randomizing NATs, which in practice means a VPN at both ends, need a relay. More trials would not change that. Only a relay, or a NAT that stops randomizing, would.

- **Both machines were behind one exit server**, US-CA#856. So they very likely shared a public address as well, the situation of the 2026-10-19 hairpin run. That was not recorded: the run did not use `--record-addresses`. It does not change the result, because hyperdht refuses the punch on the NAT types alone.
- **Discovery worked.** Every receiver announced within 3.5 to 8.1 s of its slot.
- **No connection ever reached the handshake.** All 80 records have 0 candidates. The abort happens inside hyperdht, before a connection exists, and nothing in either CLI's events shows it.
- **Each side failed only when its join timeout ran out:** 235 s for receivers and 225 s for senders. Its `ERR_NO_PEER` message advises checking the code and the other side's `announced` line. Neither of those was the problem here.
- **Changed since, because of this run:** the CLIs now watch for hyperdht's refusal (`HOLEPUNCH_REFUSED` in `engine/src/swarm.js`). On the first one they print a note, or a `double-randomized-nat` warning under `--json`. When the join times out, the `ERR_NO_PEER` says that both NATs are randomized and carries `holepunchRefused`, the count. The drop still waits out its timeout rather than failing at once, because a peer on the topic need not be the intended one, and a stranger with a randomized NAT must not be able to end it. A rerun would show the warning and the count. These records predate the change.

**One VPN, at either end, does connect.**
- In the 2026-11-03 run ([`../../20261104T0050Z/starlink-cgnat-on-ubuntu-to-vpn-comcast-on-macos/`](../../20261104T0050Z/starlink-cgnat-on-ubuntu-to-vpn-comcast-on-macos/ENVIRONMENT.md)), the Mac was on this VPN setup and Linux on Starlink without one. All 40 trials connected, and 38 completed.
- After this run, the Linux machine sent this run's result files to the Mac with `cli/src/swarm-send.js`, Linux on its VPN and the Mac on none, and the transfer succeeded. That is one transfer, in one direction (Linux to Mac), outside the harness, so it shows that this pairing can connect, not a rate.
