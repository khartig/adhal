# starlink-cgnat-vpn-on-ubuntu-to-vpn-comcast-on-macos-relay

Date: 2026-11-13, harness started 17:47 PST; first slot 17:52:43 PST; last run ended 20:34 PST
Commit: baeea60070aa on both machines, clean
Trials: 20 per direction
File: 10 MiB (10485760 bytes) /tmp/test.bin
Slot: 240 seconds, refresh 4000 ms
Relay: run A receiver off (18 of 18 successes relayed), sender on (18 of 18 successes relayed); run B receiver on (20 of 20 successes relayed), sender off (20 of 20 successes relayed)
Relay server: a blind-relay running under Pear 3.6.0 (bare 1.35.0, uv 1.53.0, v8 14.8.178.31), the latest Pear when it was installed. It works directly with hyperdht. Hosted on a DigitalOcean server running Ubuntu 26.04.1 LTS (GNU/Linux 7.0.0-43-generic x86_64), as reported after the run. Named with `--relay=<key>` on Machine 2 only. The JSON records `relay: true`, never the key, by design. blind-relay: the copy bundled with Pear 3.6.0, which `pear versions --modules` lists as `^1.6.1`. That is a range, 1.6.1 or any later 1.x, so the exact bundled version is not shown. The tests here run 1.6.1. Not recorded: the server's region
Run A: Machine 1 receiver, Machine 2 sender (seed `20261114T0152Z-starlink-cgnat-vpn-on-ubuntu-to-vpn-comcast-on-macos-relay-a`, slot start 1794621163, 17:52:43 PST)
Run B: Machine 1 sender, Machine 2 receiver (seed `20261114T0152Z-starlink-cgnat-vpn-on-ubuntu-to-vpn-comcast-on-macos-relay-b`, slot start 1794626263, 19:17:43 PST)

## Machine 1

Host: agenticMaster (linux/x64), node v24.21.0
OS: Ubuntu 24.04.4 LTS
Network/carrier/ISP: AS212238 CDNEXT - Datacamp Limited, GB. This is the network of the ProtonVPN exit server, which is all the lookup can see. The exit server was United States US-CA#815, per the note: not the same one as Machine 2's (US-CA#830). Underneath the tunnel: Starlink, per the note
Access type: a VPN tunnel via proton0 (ProtonVPN; the protocol is not named in this machine's note and was not recorded), carried over Starlink Wi-Fi, per the note
NAT: DHT saw randomized, firewalled at start. This is the VPN exit's NAT. Starlink's CGNAT is inside the tunnel, so the DHT does not see it
Firewall/router: host firewall enabled: ufw; DHT finds it firewalled; router: Starlink, settings not recorded
VPN/relay/hotspot: VPN: the route to the internet went through a tunnel; tunnel interfaces up: proton0; hotspot: none detected; relay: none (--relay not given). It connected through the relay anyway, because hyperdht follows a relay the peer names, and this side did not pass `--refuse-peer-relay`
Notes: starlink wifi. protonVPN US-CA#815 randomized on Ubuntu server

## Machine 2

Host: DecentralizedDefender.local (darwin/arm64), node v24.22.1
OS: macOS 27.0.1 (26A434)
Network/carrier/ISP: AS212238 CDNEXT - Datacamp Limited, GB. This is the network of the ProtonVPN exit server, US-CA#830 per the note. Underneath the tunnel: Comcast Xfinity
Access type: a VPN tunnel via utun4 (ProtonVPN, WireGuard protocol, per the note), carried over Wi-Fi to an eero router on Comcast Xfinity
NAT: DHT saw randomized, firewalled at start. This is the VPN exit's NAT. The Eero's NAT and the Xfinity gateway's are inside the tunnel, so the DHT does not see them
Firewall/router: host firewall disabled, stealth mode off (macOS application firewall); DHT finds it firewalled; router: eero
Router configuration: as recorded on 2026-11-03 for this network, in [`../../20261105T0446Z/starlink-cgnat-vpn-on-ubuntu-to-vpn-comcast-on-macos/ENVIRONMENT.md`](../../20261105T0446Z/starlink-cgnat-vpn-on-ubuntu-to-vpn-comcast-on-macos/ENVIRONMENT.md): an eero Pro 6E behind an Xfinity gateway in router mode, a double NAT. Not rechecked for this run
VPN/relay/hotspot: VPN: the route to the internet went through a tunnel; configured services: ProtonVPN (connected); hotspot: none detected; relay: --relay given as sender and receiver
Notes: Proton VPN US-CA#830. Wireguard protocol. Eero router

## Results

| Run | Direction | Sender | Receiver |
| --- | --- | --- | --- |
| A | Machine 2 (macOS) → Machine 1 (Linux) | 18/20 | 18/20 |
| B | Machine 1 (Linux) → Machine 2 (macOS) | 20/20 | 20/20 |

- Run A sender, trial 1: `no-handshake`
- Run A sender, trial 16: `cancelled-by-peer`
- Run A receiver, trial 1: `no-peer`
- Run A receiver, trial 16: `killed-at-slot-end`

| Run | Connect median / p90 / max | Transfer median / p90 | Complete median |
| --- | --- | --- | --- |
| A | 10.5 s / 11.9 s / 25.9 s | 12.1 s / 17.4 s | 22.9 s |
| B | 18.0 s / 122.1 s / 126.7 s | 14.0 s / 19.2 s | 33.2 s |

Receiver's figures. The sender's agree to within 0.1 s.

## Checks

- Both machines are behind randomized NATs: the hard pair, which needs a relay.
- The machines ran different hyperdht versions: Machine 1 6.34.0, Machine 2 6.36.0.

**The hyperdht versions differ at one clean commit.** `baeea60` pins
hyperdht 6.36.0 (since `3499844`), and Machine 2 ran it. Machine 1 logged
6.34.0, most likely because its `node_modules` had not been reinstalled
since the update.
The run therefore pairs 6.34.0 with 6.36.0, not 6.36.0 with itself.
Whether that matters to the two failures below is not known. Before the
next run, `pnpm install` on Machine 1 and check its `build:` line.

**The relay was on one side only, Machine 2, in both runs.** That is
enough: either side naming a relay pairs both through it.

**No `double-randomized-nat` warning.** Both NATs were randomized at the
start, but on every trial the CLIs saw hyperdht's punch fail
(`holepunch-failed`: `HOLEPUNCH_ABORTED`, `CANNOT_HOLEPUNCH`, or
`REMOTE_NOT_HOLEPUNCHABLE`), not refuse (`HOLEPUNCH_DOUBLE_RANDOMIZED_NATS`).
`holepunchRefused` is empty in all four summaries. Why hyperdht reported
a failure rather than its refusal for this pair has not been looked into.

**The `killed` flags on trial 1 are the harness's timing**, as on
2026-11-04: both records were bucketed by their own `failed` event before
the stop signal arrived. Trial 16 is different, below.

## What the run shows

**The relay connects the pair that never connects without one.** The
same pairing, ProtonVPN at both ends, went 0 of 80 with no relay on
2026-11-04
([`../../20261105T0446Z/`](../../20261105T0446Z/starlink-cgnat-vpn-on-ubuntu-to-vpn-comcast-on-macos/ENVIRONMENT.md)).
With `--relay=<key>` on one side it went 38 of 40 for senders and 38 of
40 for receivers. Every trial that paired, 39 of 39, paired through the
relay (`path=relayed`), and none directly. Every sender saw the punch
fail, 3.9 to 9.1 s in, and so did 31 of the 40 receivers. That is gate 6 of THREAT-MODEL §8
seen from the other side: the relay was used only after a failed punch.
The two pairs are not identical. On 2026-11-04 both machines were behind
one exit server (US-CA#856), and here behind two (US-CA#815 and #830).

**Transfers through the relay were a little slower than direct ones.**
Transfer medians 12.1 s for macOS → Linux and 14.0 s for Linux → macOS,
about 0.87 and 0.75 MB/s, against 9.7 s and 12.0 s directly on these
networks without the VPNs (2026-11-01). Every relayed path had an MTU of
1200. Round-trip times, as each receiver measured them, had medians of
100 ms (run A) and 85 ms (run B), with one of 430 ms. The senders counted
324 to 5,500 retransmits per trial and the receivers 0 to 5. This run has
no direct baseline for those counters: the earlier CLI runs predate them.

**Connecting is the cost, and it comes from relayed attempts that fail.**
On the side with `--relay`, Machine 2, a relayed connection sometimes
opened and then closed before the readiness handshake, either reset
(`ECONNRESET`) or silent for 5 s. The other side never saw those
connections at all: its records show one candidate, the one that paired.
Each such attempt cost about 10 to 25 s before the next one.

- Run A: 17 of the 18 successes paired on the first relayed attempt, in
  6.4 to 11.8 s. Trial 9 lost one attempt first and took 25.9 s.
- Run B: 12 of the 20 paired on the first attempt, in 12.5 to 18.5 s. The
  other 8 lost 1 to 6 attempts first and took 28.9 to 126.7 s. That is
  where run B's 122 s p90 comes from. Two of them (trials 3 and 4) lost
  5 or more, enough for the receiver's `contention` warning, which is
  the same silent candidates reported as a pattern.

**Both failures are that pattern, without an end.** Run A trial 1: the
macOS sender saw 13 relayed connections in 225 s, 22 relay attempts in
all, and every one dropped before the handshake (8 reset, 5 silent). The
Linux receiver never saw one, counted 45 failed punches, and timed out
`no-peer`. So the sender's `no-handshake`, which points at Adhal's own
handshake code, is misleading here: the connections it counted never
reached the peer's application. Run A trial 16: the same, 14 dropped
attempts, until one paired at 219.9 s. With 20 s of the slot left, the
transfer got 6.2 MB of 10.5 MB to the receiver before the harness stopped
it at the end of the slot (`killed-at-slot-end`). The receiver told the
sender, which logged `cancelled-by-peer`, with the peer's reason
`cancelled at the keyboard`, which is what the CLI says when it is
interrupted. That trial would have completed in a longer slot.

What makes a relayed attempt fail is not known from these records: the
relay server on DigitalOcean, its path to either exit server, and the mismatched
hyperdht versions are all candidates. The receiving side's records do not
show the attempts at all, so the place to look is Machine 1's side of
the relay pairing, with the versions matched first.

**Read the numbers as one pair of networks and one relay.** 38 of 40 is
a 95% Wilson interval of 83% to 99%, per role, across both runs. It
shows that the relay carries this pair, not a rate for relays in general.
