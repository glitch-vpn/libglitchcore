# Benchmarks

Small numbers, taken the way described below so you can retake them. They are
here to size decisions — which engines to ship, what an idle tunnel costs —
not to win comparisons.

## Binary size

Windows `amd64` c-shared DLL, `-ldflags="-s -w"`, `with_gvisor`:

| Composition | Size |
|---|---|
| awg | 11.2 MB |
| xray | 32.6 MB |
| xray + awg | 33.2 MB |
| mihomo | 40.8 MB |
| xray + awg + mihomo | 59.8 MB |

Same source, other targets, full composition: Android arm64 `.so` 63.1 MB,
Linux amd64 `.so` 69.4 MB, `glitch_vpn_core_service.exe` 59.7 MB.

Android ships one `.so` per ABI, so an APK carrying arm64 + x86_64 pays twice
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

Not published: it is bounded by the server and the path, not by this library,
so any number here would say more about the test link than about the code. If
you need one for your own capacity planning, measure through proxy mode
against your own exit — that removes the TUN stack from the picture and leaves
the engine.
