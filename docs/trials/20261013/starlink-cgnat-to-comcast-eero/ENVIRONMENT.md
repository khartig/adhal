# 20261013 starlink-cgnat-to-comcast-eero

Date: 2026-10-13, harness started 18:04 PDT; first slot 18:07:37 PDT, last trial
ended about 19:41 PDT
Commit: not recorded; these logs have no `build:` line. Both sides ran the code
of `e3599e1`, going by the log format. Whether either tree was clean is unknown
Trials: 20 per direction
File: 10 MiB (10485760 bytes) /tmp/test.bin
Slot: 135 seconds, refresh 4000 ms
Run A: Machine 1 sender, Machine 2 receiver (seed `20261013-a`, slot start
1791940057, 18:07:37 PDT)
Run B: Machine 1 receiver, Machine 2 sender (seed `20261013-b`, slot start
1791943057, 18:57:37 PDT)

## Machine 1

Host: DecentralizedDefender.local (darwin/arm64), node v24.21.0
OS: macOS 26.5.2 (25F84), read on 2026-10-14; not recorded at the time of the run
Network/carrier/ISP: Comcast Xfinity
Access type: not recorded (Wi-Fi or Ethernet to the eero)
NAT: double NAT (the eero, then the Xfinity gateway in router mode); type not recorded
Firewall/router: eero router; host firewall not recorded. This line used to say "eero, firewall enabled", which was not accurate: the eero app has no firewall setting
Router configuration: recorded on 2026-11-03, and the same for every run on this network. An eero Pro 6E in Automatic (DHCP & NAT) mode, behind an Xfinity gateway in router mode: a double NAT, with the eero's own internet address private. UPnP on, which Adhal does not use (hyperswarm 4.17.1 and hyperdht 6.34.0 have no UPnP code). Port forwarding enabled, with no rules and no reservations. IPv6 off. eero Labs off. eero software 26.13.0.36807 when checked; the version at the time of the run was not recorded. Uplink: Comcast Xfinity, about 300 Mbit/s down and 35 Mbit/s up in practice (the plan says up to 1.3 Gbit/s)
VPN/relay/hotspot: not recorded

## Machine 2

Host: agenticMaster (linux/x64), node v24.21.0
OS: Linux; Ubuntu and version not recorded
Network/carrier/ISP: Starlink
Access type: satellite; the local link to the Starlink router is not recorded
NAT: Starlink CGNAT
Firewall/router: not recorded
VPN/relay/hotspot: not recorded

## Results

| Run | Sender | Receiver |
| --- | --- | --- |
| A (macOS → Linux) | 18/20 | 19/20 |
| B (Linux → macOS) | 20/20 | 20/20 |

Both failures are run A trials 10 and 13, `connection-lost` with "connection
timed out". On trial 10 the receiver saved and verified the file; the sender
never got RESULT. See the 2026-10-13 row of
[`ARCHITECTURE.md`](../../../ARCHITECTURE.md).
