# Engine Compositions

Nothing forces you to ship both engines. `make build ENGINES=…` links the
subset you name, and the excluded engines' packages stay out of the binary
entirely — CI proves it with `go list -deps` guards, not by trust.

```
make build                          # xray + mihomo (default)
make build ENGINES=xray            # xray only (GPL-free with TUN_LAYER=tun2socks)
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

* **Licence.** Compositions with mihomo are GPL-3.0 as a whole, and so is a
  main-variant build of xray alone, whose TUN layer is sing-tun. A build of
  xray alone on the tun2socks bridge is not. This is why the license guard
  exists in CI: a stray import that drags mihomo or sing into a build that has
  neither the engine nor sing-tun is a release blocker, not a style nit.
* **Protocol coverage.** WireGuard and AmneziaWG links (`awg://`,
  `wireguard://`, `wg://`, a raw `[Interface]` config) run on mihomo, so a
  build without it carries none of them.
* **Data path.** One TUN layer per binary, chosen at build time. The main
  variant runs both engines on sing-tun: mihomo on its own TUN on every
  platform, Windows included, and xray fed from sing-tun's gVisor stack into
  its dispatcher, with no tun2socks in the binary. The build tag
  `with_tun2socks` selects the tun2socks bridge for xray, and for mihomo on
  Windows (and, with the Android switch, on Android), instead; a build with
  xray then links tun2socks. A mihomo-only build never links the bridge and
  comes out noticeably smaller. One layer drives the adapter in a process: in
  the tun2socks variant sing-tun's Wintun binding is linked through mihomo's
  listener and never loaded; in the main variant
  `golang.zx2c4.com/wintun` is linked through xray-core's TUN, WireGuard and
  masque packages, none of which a config the core builds reaches, and never
  loaded. `make build TUN_LAYER=tun2socks` builds the bridge variant.
* **Runtime discovery.** `CoreCapabilities()` reports the engines a given
  binary actually has, so one UI can drive several compositions without
  guessing.
