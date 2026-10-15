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
NAT: eero home router NAT; type not recorded
Firewall/router: eero, firewall enabled; rules not recorded
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
