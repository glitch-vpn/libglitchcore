# Benchmarks

Small numbers, taken the way described below so you can retake them. They are
here to size decisions — which engines to ship, what an idle tunnel costs —
not to win comparisons.

## Binary size

Windows `amd64` c-shared DLL, `-ldflags="-s -w"`, `with_gvisor`:

| Composition | Size |
|---|---|
| xray | 37.5 MB |
| mihomo | 60.6 MB |
| xray + mihomo | 92.3 MB |
| xray + mihomo, release tags | 69.9 MB |

"Release tags" are the Makefile's `no_tailscale no_easytier no_zerotier`, which
drop mihomo outbounds no share link reaches. Sizes were taken from a local
mingw build of each row, not the Docker release build, and other targets were
not measured for this composition.

The TUN layer changes two rows. The main variant runs xray on sing-tun, so a
build with xray and mihomo shares one stack and carries no tun2socks; xray alone
carries sing-tun in its place. Same method, with and without the
`with_tun2socks` tag:

| Composition | main (sing-tun) | with_tun2socks |
|---|---|---|
| xray | 38.9 MB | 37.6 MB |
| xray + mihomo, release tags | 65.3 MB | 70.2 MB |

Android ships one `.so` per ABI, so an APK carrying arm64 + armeabi-v7a + x86_64 pays three times
unless you split by ABI. The numbers are unstripped of Go's runtime metadata
beyond `-s -w`; upstream engine size dominates.

Method:

```sh
GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc \
  CGO_CFLAGS="-I$DART_SDK/include" \
  go build -tags="with_gvisor no_mihomo" -buildmode=c-shared -ldflags="-s -w" -o out.dll ./
```

## Memory and start time

Loopback session, proxy mode (no TUN), single VLESS link, measured from the
engine's own 1 Hz stats event three seconds after connect:

| Engine | Connect → connected | RSS | Go heap |
|---|---|---|---|
| xray | ~50 ms | 32.6 MB | 12.4 MB |
| mihomo | ~50 ms | 33.7 MB | 12.7 MB |

Read these as an order of magnitude, with the caveats attached:

* The RSS figure is the whole test process, which also hosts the in-process
  VLESS server the session connects to and the Go test harness. An embedding
  app pays its own runtime on top of the engine's, so treat the Go heap column
  as the engine's own footprint and RSS as an upper bound for a bare host.
* "Connect → connected" is a loopback handshake with no network latency and no
  TLS to a real server; against a real exit it is dominated by the round trip
  to that server. It measures the library's own startup cost, not the internet.
* Measured on Windows 11, Go 1.26.4, full composition binary.

Method: start the engine with `resolveExternalIp=0` (so the measurement does
not include an outbound HTTP fetch), wait for `EngineConnected` (501), then
read `rssBytes`/`goMemBytes` from a stats event (300) after the heap settles.

## Throughput

Through a server, throughput is bounded by the server and the path, so no
number is published for a tunnel to one. What the TUN layer itself costs is
measured with the server on the same machine, a handler that copies bytes in
place of an engine, and TCP in both directions.

sing-tun's gVisor stack takes its TCP buffer sizes from the fork; the tun2socks
bridge sets 4 MiB. On a real Linux TUN (WSL2, one process, loopback
server, MiB/s, two runs each):

| Buffers | down, 1 flow | down, 8 flows | up, 1 flow | up, 8 flows |
|---|---|---|---|---|
| 20 KiB (sing-tun's own) | 113, 118 | 427, 433 | 196, 202 | 279, 279 |
| 256 KiB | 271, 247 | 539, 518 | 181, 178 | 260, 243 |
| 1 MiB | 239, 239 | 561, 530 | 175, 177 | 258, 256 |
| 4 MiB | 240, 254 | 534, 534 | 166, 166 | 259, 244 |

A download over one flow is half as fast at 20 KiB, and any buffer from 256 KiB
up levels it; the other three columns are within noise or a little faster at
20 KiB. Against a pipe standing in for the TUN, with no delay, the two stacks
are level (66 MiB/s one flow down, 212 for eight, against the bridge's 50 and
200); with a delay of 1 ms one way in front of each stack the 20 KiB window
caps a flow near 7 MiB/s, where 4 MiB reaches 54 and the bridge 28.

Method: `go build -tags with_gvisor` of a scratch program that opens
`tun.New` with a /30 and a route for a test range, runs the stack with
`tun.NewStack` (20 KiB) or with `tun.NewGVisorStackWithOptions` and
`SetTransportProtocolOption` for the larger sizes, and dials the test range
with plain sockets. A tunnel to a real server is bounded by that path; to
size one, measure through proxy mode against your own exit.
