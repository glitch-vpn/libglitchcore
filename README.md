# libglitchcore

[![CI](https://github.com/glitch-vpn/libglitchcore/actions/workflows/ci.yml/badge.svg)](https://github.com/glitch-vpn/libglitchcore/actions/workflows/ci.yml)

A VPN client data plane you can embed. It parses share links, brings up the
tunnel, routes traffic and reports what is happening; the UI, the accounts and
the product are yours.

Three engines are compiled in and one runs at a time: **Xray** (VLESS, VMess,
Trojan, Shadowsocks with Reality/XTLS/uTLS), **AmneziaWG** (WireGuard with
obfuscation, AWG 2.0) and **mihomo** (Hysteria2, TUIC, AnyTLS, WireGuard/AWG outbound).
Targets are Android (arm64, x86_64), Windows (amd64) and Linux (amd64), behind
a plain C ABI — so it binds from Dart, Kotlin, Swift, C# or anything else with
an FFI. Ship only the engines you need: an awg-only build is 11 MB against
60 MB for all three.

Building a Flutter app? The
[glitch_vpn_core plugin](https://github.com/glitch-vpn/glitch_vpn_core_plugin)
wraps this with the platform glue already done.

## Documentation

* **[Getting Started](https://github.com/glitch-vpn/libglitchcore/wiki/Getting-Started)** — start a tunnel, read events, stop it
* **[Engine Compositions](https://github.com/glitch-vpn/libglitchcore/wiki/Engine-Compositions)** — pick your engines, see what each costs
* **[Bottlenecks](https://github.com/glitch-vpn/libglitchcore/wiki/Bottlenecks)** — the limits and sharp edges, stated plainly
* **[Benchmarks](https://github.com/glitch-vpn/libglitchcore/wiki/Benchmarks)** — size, memory and start time, with the method
* **[For Maintainers](https://github.com/glitch-vpn/libglitchcore/wiki/For-Maintainers)** — environment, gates, releases

## Contributing

The gaps we would most like help with are more protocols, more platforms and
harder testing of the routing and DNS paths — the places where a wrong rule is
a leak rather than a bug report.

Everything runs locally: `CGO_ENABLED=0 go test -tags=with_gvisor ./internal/...`
needs neither Docker nor cgo, and the loopback smoke suite exercises a real
engine without a TUN, admin rights or an external server. What we ask of a
change is in [For Maintainers](https://github.com/glitch-vpn/libglitchcore/wiki/For-Maintainers) — including how we work
with LLM assistance, which we do openly and hold to the same gate.

## Telemetry

None. The core talks to the VPN servers and DNS resolvers named in the supplied
config, and fetches the health-probe URL (configurable, default
`gstatic.com/generate_204`). That is the complete list of network activity.

## License

The source is MIT ([LICENSE](LICENSE)). A built binary's licence depends on the
engines in it: anything containing xray or mihomo links GPL-3.0 code and is a
GPL-3.0 combined work when distributed; the awg-only composition links none.
Per-composition attribution is in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
