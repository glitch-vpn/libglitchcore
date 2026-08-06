# Engine Compositions

Nothing forces you to ship all three engines. `make build ENGINES=…` links the
subset you name, and the excluded engines' packages stay out of the binary
entirely — CI proves it with `go list -deps` guards, not by trust.

```
make build                          # xray + awg + mihomo (default)
make build ENGINES="xray,awg"
make build ENGINES=xray
make build ENGINES=awg              # the only GPL-free composition
make build ENGINES=mihomo
```

Selection maps to negative build tags (`no_xray`, `no_awg`, `no_mihomo`), so
the tagless build still links everything and editor tooling keeps working.

## What it costs

Windows `amd64` c-shared DLL, `-s -w`, `with_gvisor`:

| Composition | Size |
|---|---|
| awg | 11.2 MB |
| xray | 32.6 MB |
| xray + awg | 33.2 MB |
| mihomo | 40.8 MB |
| xray + awg + mihomo | 59.8 MB |

More numbers, and how they were taken: [Benchmarks](Benchmarks.md).

## Consequences of the choice

* **Licence.** Xray and mihomo compositions are GPL-3.0 as a whole. The
  awg-only build is the one permissive composition. This is why the license
  guard exists in CI: a stray import that drags mihomo into an awg-only build
  is a release blocker, not a style nit.
* **Protocol coverage.** awg alone means WireGuard/AmneziaWG only — no VLESS,
  no Hysteria2, and routing/DNS rules are ignored (awg is an L3 tunnel that
  takes a single plain resolver).
* **Data path.** The tun2socks bridge is linked when xray is in, or when
  mihomo and awg are both in (Windows Wintun cross-binding). A mihomo-only
  build runs native sing-tun everywhere and comes out noticeably smaller.
* **Runtime discovery.** `CoreCapabilities()` reports the engines a given
  binary actually has, so one UI can drive several compositions without
  guessing.
