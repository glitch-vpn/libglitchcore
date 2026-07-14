# libglitchcore

[![CI](https://github.com/glitch-vpn/libglitchcore/actions/workflows/ci.yml/badge.svg)](https://github.com/glitch-vpn/libglitchcore/actions/workflows/ci.yml)

Go `c-shared` library that implements a VPN client data plane behind a plain C
FFI. Three engines are compiled in: Xray (VLESS, Trojan, Shadowsocks),
AmneziaWG (WireGuard with obfuscation, including AWG 2.0) and mihomo
(Hysteria2, WireGuard/AWG outbound). One engine runs at a time. Builds target
Android (arm64, x86_64), Windows (amd64) and Linux (amd64). The main consumer
is the [glitch_vpn_core](https://github.com/glitch-vpn/glitch_vpn_core_plugin)
Flutter plugin, but nothing in the FFI is Flutter-specific.

## FFI

The surface is engine-agnostic: `EngineStart(engineID, requestJSON)`,
`EngineStop(engineID)`, `EngineIsRunning(engineID)`, `CoreCapabilities()`.
Engine-specific settings travel inside the request JSON, so the ABI does not
change when an engine gains an option or a new engine is added.

A start request can carry:

* routing rules: three flat matcher lists (proxy, direct, block). A matcher is
  `geoip:nl`, `geosite:category-ads-all`, `domain:example.com`, `full:host`,
  `keyword:str`, `regexp:expr`, `process:app.exe` or a bare IP/CIDR. First
  match wins; evaluation order is block, direct, proxy, local networks, then
  the mode catch-all.
* DNS: plain, DoT, DoH or DoQ resolvers, and a fake-ip mode (xray and mihomo)
  where routing sees domains instead of resolved addresses. IPv6 and non-DNS
  UDP can be blocked outright.
* a balancer strategy when the config has several links, a health-probe URL,
  a uTLS fingerprint override, Mux settings and a sniffing toggle.

The data path is a TUN device (Wintun on Windows, the VpnService fd on
Android, a native tun on Linux) or, when `proxyPort` is set, a loopback SOCKS
proxy. Proxy mode needs no TUN and no elevation.

Besides engine start/stop the FFI has:

* `MeasurePings`: url-test latency for a list of share links; no engine has to
  be running;
* a tunnel liveness probe, reported together with the periodic traffic stats;
* an opt-in connection inspector: one event per routed connection with host,
  port, matched rule and chosen outbound;
* per-process routing on desktop;
* a Windows service mode (`-tags service`) where the unprivileged library
  forwards engine commands to the elevated service over named pipes.

## Building

Cross-compilation runs in Docker, driven by make:

    make build                     # full composition (xray + awg + mihomo), all platforms
    make build ENGINES="xray,awg"  # any engine subset
    make build ENGINES=awg         # the only GPL-free composition (see License)
    make test
    make clean

Artifacts appear in `build_output/ffi/`: `libglitchcore.so`/`.dll` per
platform, `glitch_vpn_core_service.exe`, the C header and `wintun.dll`.

Tests and type checks also run without Docker:

    CGO_ENABLED=0 go test -tags=with_gvisor ./internal/...
    go vet ./ ./internal/core/   # the root shell needs Dart SDK headers in CGO_CFLAGS

Engine selection maps to negative build tags (`no_xray`, `no_awg`,
`no_mihomo`); the default (tagless) build links everything, so plain `go test`
and editor tooling keep working. An excluded engine's packages stay out of the
binary entirely - CI asserts this with `go list -deps` guards per composition.
The tun2socks bridge is linked when xray is in, or when mihomo and awg are
both in (Windows Wintun cross-binding rule); mihomo-only runs native sing-tun
everywhere and comes out about a quarter smaller. `CoreCapabilities` reports
which engines a given binary has, e.g.:

    CGO_ENABLED=0 go test -tags="no_mihomo with_gvisor" ./internal/...   # xray+awg
    CGO_ENABLED=0 go test -tags="no_xray no_awg with_gvisor" ./internal/...   # mihomo-only

## Layout

The repository root contains only the `package main` FFI shell: CGo glue and
the `//export` functions. Everything else is under `internal/`.
`internal/core` holds the controller, the engine adapters, platform TUN code
and the service IPC. `internal/xrayconfig`, `internal/mihomoconfig` and
`internal/awgconfig` turn share links into engine configs. `internal/routing`,
`internal/dnsconfig`, `internal/conninspect`, `internal/logfmt` and
`internal/pinger` are engine-neutral helpers.

## Geo databases

geoip.dat and geosite.dat are not bundled, and the core does not download
them. The consumer puts the files somewhere writable and passes the directory
through the `xray.location.asset` env var (`SetEnvVar`). Without the files geo
matchers never match; nothing else is affected.

## Telemetry

None. The core connects to the VPN servers and DNS resolvers named in the
supplied config, and fetches the health-probe URL (configurable, default
`gstatic.com/generate_204`). That is the complete list of network activity.

## License

The source code is MIT, see [LICENSE](LICENSE). The license of a built binary
depends on the engine composition: any binary containing mihomo or xray links
GPL-3.0 code (mihomo, sing - xray links sing in its base transport, so its
MPL-2.0 does not exempt the binary) and is a GPL-3.0 combined work when
distributed. The awg-only composition links no GPL code. Per-composition
details and dependency attribution are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
