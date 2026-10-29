# Getting Started

## Get a build

Releases carry prebuilt artifacts per platform:

```
ffi/
  android/arm64-v8a/libglitchcore.so
  android/x86_64/libglitchcore.so
  linux/libglitchcore.so
  windows/libglitchcore.dll
  windows/glitch_vpn_core_service.exe
  windows/wintun.dll
  libglitchcore.h
```

Or build them yourself — see [Engine Compositions](Engine-Compositions) if
you do not need all three engines.

How you load the library is up to you:

* **Android** — put the `.so` files under `src/main/jniLibs/<abi>/` (or wrap
  them in an AAR) and call them through JNI, JNA or your framework's FFI. The
  library does not link the NDK's JNI headers and has no Java API of its own,
  so nothing forces a particular binding style.
* **Desktop** — load the `.dll`/`.so` with your language's FFI.
* **Flutter** — use the [plugin](https://github.com/glitch-vpn/glitch_vpn_core_plugin),
  which already carries the platform glue (TUN, Windows service, foreground
  service).

## The five calls that matter

```c
InitializeController();                    // once per process
RegisterStatusPort(port);                  // events arrive here
EngineStart("xray", request_json);         // request_json described below
EngineIsRunning("xray");
EngineStop("xray");
```

`CoreCapabilities()` returns the engines this particular binary contains, so a
UI can hide what is not there.

## Picking an awg pool's link first

A caller that has to build the TUN itself (Android's `VpnService`) needs the
addresses of the link an awg pool will use before `EngineStart`, and the core
picks that link by probing. `AwgPick(request_json)` runs the same pick and
answers with the link's position and its tunnel addresses. The caller frees
the string with `FreeStatusMessage`.

```jsonc
// request: the start request's config and opts
{"config": "awg://…#a\nawg://…#b", "opts": {"balancerStrategy": "leastping"}}
// answer
{"index": 1, "addresses": ["10.2.0.2/32", "fd00:2::2/128"], "peersCarryV6": true}
// or
{"error": "chosen awg link has no Interface address"}
```

`addresses` are the chosen link's `[Interface]` addresses, IPv4 and IPv6 in
order; `peersCarryV6` says whether any of its peers routes IPv6. The link
itself is not returned, since it carries the private key. A pool whose probes
all fail answers with its first link, as a start does; a link with no address
is an error. Addresses a TUN cannot carry (loopback, unspecified, multicast,
link-local, or a prefix that does not parse) are left out of `addresses`.
Start the engine with the whole pool and `opts.awgPicked` set to
the answer's `index`: the start then uses that link without probing again and
still reports the pool in the server event.

The call probes and parses and does nothing that needs elevation, so it runs in
the caller's process on Windows too and has no service command;
`awgPicked` travels to the service inside the start request like every other
opt.

## The start request

Everything engine-specific travels as JSON, which is why the ABI stays put
when an engine gains an option:

```json
{
  "config": "vless://…#Germany\nvless://…#Netherlands",
  "tunFd": 42,
  "logLevel": 0,
  "opts": {
    "routingTiers": "[{\"proxy\":[\"domain:vk.ru\"]},{\"direct\":[\"domain:ru\",\"geoip:ru\"]}]",
    "localNetworksDirect": "1",
    "balancerStrategy": "leastping",
    "geoAssetsDir": "C:\\ProgramData\\myapp\\geo"
  },
  "dnsConfig": {
    "mode": "fake-ip",
    "servers": ["https://dns.google/dns-query"],
    "directServers": ["192.168.1.1"]
  }
}
```

* `config` — one share link, or several separated by newlines, which turns the
  session into a balancer pool. A raw WireGuard/AmneziaWG INI config only
  goes alone; in a pool, send it as `awg://` followed by the base64url of the
  INI, with an optional `#name`.
* `tunFd` — a TUN file descriptor (Android `VpnService`). Leave it out on
  desktop, where the library opens its own adapter, or set `opts.proxyPort`
  instead for a loopback SOCKS proxy with no TUN and no elevation (xray and
  mihomo only: an awg start with it fails). Proxy mode is also the easiest way
  to try the library out. `opts.proxyUser` and
  `opts.proxyPass` put a username and password on that proxy, which then
  carries TCP only: SOCKS5 UDP cannot be tied to the login. Without them
  every local app can use it, UDP included.
* `opts` — flat string map. Routing tiers are evaluated in order, first match
  wins. Within a tier the more specific entry wins whatever its outcome, so
  `domain:vk.com` sent through the proxy is an exception to `geoip:ru` sent
  direct: `full:`, then `domain:` (more labels first), then an IP or CIDR (the
  narrower first), then `keyword:` and `regexp:`, then `geosite:` and `geoip:`
  as one rank. At equal rank block beats direct beats proxy. A block yields
  only to a more specific entry of its own kind, names or addresses: a flow
  whose name the tier sends direct is still blocked when its address is
  blocked in the same tier, and the other way round. A `process:`
  block leads its tier and the tier's other `process:` entries close it. A
  flow a `process:` proxy entry sends through the VPN meets every tier's block
  entries and goes to the proxy, so an exception to a block does not reach
  it: that path fails closed. Matchers are `geoip:nl`,
  `geosite:category-ads-all`, `domain:example.com`, `full:host`, `keyword:str`,
  `regexp:expr`, `process:app.exe` or a bare IP/CIDR. A start fails on a
  domain, `full:` or `keyword:` matcher holding a comma, and on a regexp with
  a space beside a comma: mihomo splits its rule lines there.
* `opts.awgPicked` — an awg start only: the index of the pool's link, from
  `AwgPick`, to use without probing again. An index outside the pool fails the
  start asynchronously: `EngineStart` returns, then an `EngineError` follows.
* `dnsConfig` — resolvers (plain, DoT, DoH, DoQ), fake-ip mode, a hosts table
  and separate resolvers for direct-routed names.

## Events

Everything the caller needs to render arrives on the status port as
`(code, payload)`:

| Code | Meaning |
|---|---|
| 500–507 | engine lifecycle: connecting, connected, error, disconnecting, disconnected, already running, conflict, stop rejected |
| 300 / 301 | traffic + memory stats (1 Hz), stats error; rx/tx are the session's proxied traffic on every engine, direct-routed traffic excluded |
| 302 | connected server: name, host, port, protocol, and the whole pool |
| 303 | external IPv4/IPv6 of the exit, fetched through the proxy whatever the routing tiers say |
| 400 / 401 | structured logs (off by default); 401 carries the error and fatal lines; credentials are redacted and xray masks addresses |
| 402 | per-connection inspector (opt-in) |

Registering a status port over a live engine replays the current state —
connected status, server, external IP, stats — so a restarted UI restores
itself without reconnecting.

## Geo databases

geoip.dat and geosite.dat are not bundled and never downloaded. Ship or fetch
them yourself and pass the directory as `opts.geoAssetsDir` (absolute path).
Details and failure modes: [Bottlenecks](Bottlenecks#geo-databases).

## Windows without UAC prompts

TUN mode needs elevation. The release ships `glitch_vpn_core_service.exe`: if
your installer registers it as a system service, the unprivileged library
forwards engine commands to it over a named pipe and the user sees no prompt.
Without the service, the caller has to run elevated. Proxy mode needs neither.
