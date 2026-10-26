# Third-party notices

libglitchcore's own source code is licensed under [MIT](LICENSE). The license
of a **built binary** depends on which engines it links (selected at build time
via `make build ENGINES=...`), because Go links all dependencies statically:

| Composition | GPL code linked | Effective binary license |
|---|---|---|
| `awg` only | none | permissive (MIT + BSD/Apache deps) - proprietary use OK |
| `xray`, with or without `awg` | none (xray-core is MPL-2.0) | permissive; MPL-2.0 file-level terms apply to xray-core's files |
| any composition with `mihomo` | mihomo + sing (GPL-3.0) | **GPL-3.0 combined work** |

Note on xray: xray-core's own code is MPL-2.0, and as of v26.10.21 it no longer
links the GPL-3.0-or-later `github.com/sagernet/sing*` modules, so a
composition without mihomo carries no GPL code. The individual components keep
their own licenses listed below. Exact versions are pinned in
[`go.mod`](go.mod). CI verifies per-composition linkage with `go list -deps`
guards.

## Direct dependencies

| Component | License | Source |
|---|---|---|
| Xray-core | MPL-2.0 | https://github.com/XTLS/Xray-core |
| mihomo (Clash.Meta) | GPL-3.0 | https://github.com/MetaCubeX/mihomo |
| amneziawg-go | MIT | https://github.com/amnezia-vpn/amneziawg-go |
| tun2socks (fork of xjasonlyu/tun2socks) | MIT | https://github.com/glitch-vpn/tun2socks |
| wireguard/windows (tun/Wintun bindings) | MIT | https://git.zx2c4.com/wireguard-windows |
| go-winio | MIT | https://github.com/microsoft/go-winio |
| golang.org/x/net, golang.org/x/sys | BSD-3-Clause | https://go.googlesource.com |

## Notable transitive dependencies

| Component | License | Source |
|---|---|---|
| sing, sing-tun and other sing-* modules (metacubex forks, via mihomo) | GPL-3.0-or-later | https://github.com/MetaCubeX |
| mipstack (via mihomo) | MPL-2.0 | https://github.com/metacubex/mipstack |
| wireguard-go | MIT | https://git.zx2c4.com/wireguard-go |
| gVisor (netstack) | Apache-2.0 | https://github.com/google/gvisor |

The full transitive module list, each with its own license, is resolvable from
`go.mod` / `go.sum` (e.g. with `go-licenses report ./...`).

## Prebuilt binaries

Wintun (`wintun.dll`, shipped with the Windows artifacts) is not built from
source here; it is distributed under the terms of the Wintun
["Prebuilt Binaries License"](https://www.wintun.net/), which permits
redistribution of the unmodified DLL as part of a larger product.

## Geo databases (runtime download, not bundled)

The consumer application may download `geoip.dat` / `geosite.dat` at runtime
from the [v2fly project](https://github.com/v2fly) releases (or a
user-configured source). They are data files and are not part of the binaries.
