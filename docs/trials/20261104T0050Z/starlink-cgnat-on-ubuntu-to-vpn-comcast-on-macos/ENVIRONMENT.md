# starlink-cgnat-on-ubuntu-to-vpn-comcast-on-macos

Date: 2026-11-03, harness started 16:45 PST; first slot 16:50:27 PST; last run ended 19:32 PST
Commit: Machine 1 d188c2e4e902 (clean); Machine 2 ec7c58c0a10a (clean)
Trials: 20 per direction
File: 10 MiB (10485760 bytes) /tmp/test.bin
Slot: 240 seconds, refresh 4000 ms
Run A: Machine 1 receiver, Machine 2 sender (seed `20261104T0050Z-starlink-cgnat-on-ubuntu-to-vpn-comcast-on-macos-a`, slot start 1793753427, 16:50:27 PST)
Run B: Machine 1 sender, Machine 2 receiver (seed `20261104T0050Z-starlink-cgnat-on-ubuntu-to-vpn-comcast-on-macos-b`, slot start 1793758527, 18:15:27 PST)

## Machine 1

Host: agenticMaster (linux/x64), node v24.21.0
OS: Ubuntu 24.04.4 LTS
Network/carrier/ISP: AS14593 SPACEX-STARLINK - Space Exploration Technologies Corporation, US
Access type: Wi-Fi via wlp4s0b1 (driver b43) on the Starlink network, satellite uplink, per the note and the ISP lookup. No eero and no VPN on this side
NAT: DHT saw consistent, port translated, firewalled at start; Starlink CGNAT, per the run's configuration (the host has no 100.64.0.0/10 address, so the CGNAT is upstream and not visible from here)
Firewall/router: host firewall enabled: ufw; DHT finds it firewalled; router: Starlink, settings not recorded
VPN/relay/hotspot: VPN: not on the route; hotspot: none detected; relay: none (the harness configures no relay)
Notes: starlnk wifi on Ubuntu server

## Machine 2

Host: DecentralizedDefender.local (darwin/arm64), node v24.22.1
OS: macOS 27.0.1 (26A434)
Network/carrier/ISP: AS212238 CDNEXT - Datacamp Limited, GB. This is the network of the ProtonVPN exit server, which is all the lookup can see. The exit server's location was not recorded. Underneath the tunnel: Comcast Xfinity, per the run's configuration
Access type: a VPN tunnel via utun4 (ProtonVPN, WireGuard protocol, per the note), carried over Wi-Fi to an eero router on Comcast Xfinity
NAT: DHT saw randomized, firewalled at start. This is the VPN exit's NAT, the first randomizing NAT in these trials. `scratch-trials.js --environment-only`, run before the trials with the same VPN configuration, also saw it as randomized. The eero's NAT is inside the tunnel, so the DHT does not see it. No CGNAT is known on this side
Firewall/router: host firewall disabled, stealth mode off (macOS application firewall); DHT finds it firewalled; router: eero, per the note; its rules not recorded for this run
VPN/relay/hotspot: VPN: the route to the internet went through a tunnel; configured services: ProtonVPN (connected); hotspot: none detected; relay: none (the harness configures no relay)
Notes: Proton VPN. Wireguard protocol. Eero router

## Results

| Run | Direction | Sender | Receiver |
| --- | --- | --- | --- |
| A | Machine 2 (macOS) → Machine 1 (Linux) | 18/20 | 18/20 |
| B | Machine 1 (Linux) → Machine 2 (macOS) | 20/20 | 20/20 |

- Run A sender, trial 5: `connection-lost` (phase send)
- Run A sender, trial 10: `stalled` (phase result)
- Run A receiver, trial 5: `connection-lost`
- Run A receiver, trial 10: `connection-lost`

## Checks

- The machines ran different commits: d188c2e4e902, ec7c58c0a10a.
  Checked by hand: ec7c58c changes only files under `docs/trials/` (the 2026-11-02 results), so both machines ran the same code.

Every `ok` record is the full 10485760 bytes, with exit 0 and no contract violations. On each receiver, the offered SHA-256, the delivered SHA-256, and the harness's own hash of the written file all match. Neither failed trial left a finished file: both receivers kept a `.part` file (8978432 and 10223616 bytes) and reported the drop as failed.

The `env role=undefined seed=undefined trials=10 slot=135s` line near the top of each log is the `--environment-only` probe printing its own default header. The run's real settings are on the line above it, and they are what the JSON records.

## What the run shows

**The randomizing NAT was punched every time: 40 of 40 trials connected directly.** The Mac's VPN exit gave a new external port for each destination. The Starlink side was `consistent`. One randomizing side and one consistent side connected in all 40 trials, with no relay. Run B is 20/20 (95% Wilson interval 84% to 100%). Run A is 18/20 (70% to 97%). Neither of run A's two failures was a connection failure: both connected, then lost the connection during the transfer.

The timings below are from the receivers' logs.

| Run | Direction | Connect median (p90, max) | Transfer median (p90, max) | Complete median (p90, max) |
| --- | --- | --- | --- | --- |
| A | macOS (VPN) → Linux (Starlink) | 14.5 s (61.7, 94.1) | 9.7 s (22.4, 22.4) | 24.5 s (76.0, 103.4) |
| B | Linux (Starlink) → macOS (VPN) | 15.3 s (45.6, 45.7) | 12.0 s (14.5, 17.7) | 27.5 s (57.7, 57.9) |

- **The randomizing NAT costs time to connect, not success.** Connect medians were 14.5 and 15.3 s, against 3.7 to 4.9 s on the 2026-11-01 and 2026-11-02 runs.
  - 10 of the 40 connects took over 30 s. Nine of those ten began with a first connection that was reset (`ECONNRESET`, recorded as a dropped candidate that was neither counted nor paired), then succeeded on a later attempt. The exception is run A, trial 18, which took 94.1 s with no dropped candidate recorded.
  - The other connects took 3.4 to 25.3 s.
- **Transfer speed was normal once connected:** a 9.7 s median in run A, and 12.0 s in run B. This is close to the 2026-11-01 run without the VPN (9.7 and 12.0 s), so the tunnel did not slow the data.
- **Run A, trial 5: the path went silent during the transfer.** The receiver had 8978432 bytes when its connection closed, about 24 s after it accepted. The sender had written 9764864 bytes, and its socket reported `connection timed out` about 19 s after the receiver gave up. This trial also needed a second attempt to connect (73.0 s).
- **Run A, trial 10: the sender never saw the connection close.** The sender wrote all 10485760 bytes, then waited 120 s for the receiver's confirmation and reported `stalled`. The receiver had 10223616 bytes, 256 KiB short, when its connection closed, about 15 s after the sender's last write. The harness times come from each machine's own clock, so the 15 s is approximate.
  - **Investigated (2026-11-03): a dead path, not an Adhal bug.** Neither side closed the connection: both close reports are the transport's own `connection timed out` (`ETIMEDOUT`), which the receiver's JSON records as `socketError`.
  - In libudx at the commit udx-native 1.21.1 builds (`holepunchto/libudx#a9af5de`, `src/udx.c`), a stream closes with `ETIMEDOUT` only when unacknowledged data has gone through 6 RTO timeouts. The RTO is `srtt + 4 * rttvar`, at least 1 s and at most 30 s, and after the first timeout it re-arms at twice that. So each side gives up after roughly 13 times its own RTO.
  - The receiver's RTO, near the 1 s floor, fits its close about 15 s after the sender's last write. A sender whose RTO had grown to 8 s or more during a bulk upload through the tunnel would need over 100 s, longer than the 120 s RESULT wait left it. The run recorded no UDX counters, so the sender's actual RTO is not known.
  - A zero receive window, which libudx probes without ever timing out, is ruled out: udx-native never registers a read-buffer callback, so the advertised window stays at 4 MiB.
  - The engine did what `RESULT_TIMEOUT_MS` in `engine/src/transfer.js` is documented to do, for "a receiver that vanished without the transport noticing". It reported `stalled`, saying whether the file was saved is unknown, and the receiver kept a `.part` file to resume from.
  - What made the path go silent, in this trial and in trial 5, is not recorded.
- **Both failures were in run A,** with the Mac uploading through the tunnel. Two failures in twenty cannot show whether the direction matters.
- The CLI trials record a NAT snapshot only at the start, and no per-connection UDX counters. So this run cannot show whether the VPN's mapping changed mid-transfer, or what the path's loss and retransmits were in trials 5 and 10.
