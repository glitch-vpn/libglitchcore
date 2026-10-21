# libglitchcore

A VPN client data plane you can embed. It parses share links, brings up a
tunnel, routes traffic and reports what is happening — you keep the UI, the
accounts and the product decisions.

Three engines are compiled in and one runs at a time:

| Engine | Protocols |
|---|---|
| Xray | VLESS, VMess, Trojan, Shadowsocks (Reality, XTLS, uTLS) |
| AmneziaWG | WireGuard with obfuscation, AWG 2.0 |
| mihomo | Hysteria2, TUIC, AnyTLS, WireGuard/AWG outbound |

Targets: Android (arm64, x86_64), Windows (amd64), Linux (amd64). The API is a
plain C ABI, so it binds from Dart, Kotlin/Java, Swift, C#, Python or anything
else with an FFI; the [Flutter plugin](https://github.com/glitch-vpn/glitch_vpn_core_plugin)
is one consumer, not the only shape.

## Pages

* **[Getting Started](Getting-Started)** — start a tunnel, read events, stop it.
* **[Engine Compositions](Engine-Compositions)** — ship only the engines you
  need; sizes and licence consequences.
* **[Bottlenecks](Bottlenecks)** — what this does not do, and the sharp edges
  worth knowing before you design around them.
* **[Benchmarks](Benchmarks)** — measured binary sizes, memory and start time.
* **[For Maintainers](For-Maintainers)** — development environment, gates,
  release flow, how we work with LLM assistance.
