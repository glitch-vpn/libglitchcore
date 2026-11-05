# Engine Compositions

Nothing forces you to ship both engines. `make build ENGINES=…` links the
subset you name, and the excluded engines' packages stay out of the binary
entirely — CI proves it with `go list -deps` guards, not by trust.

```
make build                          # xray + mihomo (default)
make build ENGINES=xray            # GPL-free
make build ENGINES=mihomo
```

Selection maps to negative build tags (`no_xray`, `no_mihomo`), so
the tagless build still links everything and editor tooling keeps working.

## What it costs

Windows `amd64` c-shared DLL from a local mingw build, `-s -w`, `with_gvisor`:

| Composition | Size |
|---|---|
| xray | 37.5 MB |
| mihomo | 60.6 MB |
| xray + mihomo | 92.3 MB |
| xray + mihomo, release tags | 69.9 MB |

More numbers, and how they were taken: [Benchmarks](Benchmarks).

## Consequences of the choice

* **Licence.** Compositions with mihomo are GPL-3.0 as a whole; a build of xray
  alone is not. This is why the license guard exists in CI: a stray import
  that drags mihomo or sing into a build without mihomo is a release blocker,
  not a style nit.
* **Protocol coverage.** WireGuard and AmneziaWG links (`awg://`,
  `wireguard://`, `wg://`, a raw `[Interface]` config) run on mihomo, so a
  build without it carries none of them.
* **Data path.** The tun2socks bridge is linked when xray is in. A mihomo-only
  build runs native sing-tun everywhere and comes out noticeably smaller.
* **Runtime discovery.** `CoreCapabilities()` reports the engines a given
  binary actually has, so one UI can drive several compositions without
  guessing.
