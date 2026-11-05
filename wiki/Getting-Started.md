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
you do not need both engines.

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
  INI, with an optional `#name`, or as a `wireguard://` / `wg://` link in the
  form v2rayNG, v2rayN and Hiddify write. A link with `reserved` bytes runs on
  mihomo, whose WireGuard outbound sends them. SOCKS5 proxies
  (`socks://`, `socks5://`, `socks5h://`) run on xray and mihomo, HTTP proxies
  (`http://`, `https://`) on xray alone: they carry no UDP, which xray drops and mihomo would send direct. The userinfo
  is `user:pass` or its base64; `socks4://` is refused, and so is an `https://`
  proxy that asks to skip certificate checks (pin it with `pcs`).

  These links and the WireGuard ones are cut by hand, not by a URL parser:
  the fragment starts at the first `#`, the query at the first `?` before
  it, and the userinfo runs to the last `@` before the query. A userinfo that
  holds a `/` or an `@` as written must be bare base64 (letters, digits, `+`,
  `/`, `-`, `_`, then up to two `=`) that decodes, in the standard or the URL
  alphabet, padded or not, to a valid UTF-8 login with a `:` and no control
  character for `socks`, `socks5`, `socks5h`, `http` and `https`, and to
  exactly 32 bytes for `wireguard` and `wg`. Any other link holding one is
  refused, since `user:pass@good:80/@evil:80` or `goodexample/@evil:80` would
  otherwise name another server than a URL parser shows. Host and port run to the first `/` after the userinfo, and
  the path is dropped. A control character, as written or percent-decoded in
  the userinfo, the name or a query value, fails the link.
* `tunFd` — a TUN file descriptor (Android `VpnService`). Leave it out on
  desktop, where the library opens its own adapter, or set `opts.proxyPort`
  instead for a loopback SOCKS proxy with no TUN and no elevation (xray and
  mihomo). Proxy mode is also the easiest way
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
  entries and goes to the proxy, and one a `process:` direct entry sends direct
  meets them and goes direct, so an exception to a block does not reach
  either: that path fails closed. Matchers are `geoip:nl`,
  `geosite:category-ads-all`, `domain:example.com`, `full:host`, `keyword:str`,
  `regexp:expr`, `process:app.exe` or a bare IP/CIDR. A start fails on a
  domain, `full:` or `keyword:` matcher holding a comma, and on a regexp with
  a space beside a comma: mihomo splits its rule lines there.
* `opts.routingTargets` and a tier's `routes` — a route sends what it matches
  to a named server, group or chain instead of the pool. Inside a tier the
  outcomes rank block, direct, routes in the order given, proxy. The targets
  are `{"version":1,"servers":[{"id","link"}],"groups":[{"id","servers"}],
  "chains":[{"id","hops"}]}` and a route is `{"to":"<id>","match":[…]}`. An id
  is 1–16 characters of `a-z0-9`, unique across the three kinds; a group
  balances over servers with `balancerStrategy`; a chain of 2–4 distinct
  servers dials its first hop directly and every later hop through the one
  before it, and its last hop exits. A route takes no `process:` matcher. A
  start fails on an unknown version, a duplicate, unknown or malformed id, an
  empty group, a chain out of bounds or naming a server twice, more than 64
  servers, 16 groups or 16 chains, a route naming an id the targets do not
  define, and a link the engine cannot build; an older core refuses `routes`
  as an unknown field, and `CoreCapabilities()` lists `routeTargets` where they
  work. Only what a route names is built. On xray a chain takes vless, vmess,
  ss and trojan servers; a later hop keeps its host name for the hop before it
  to resolve. mihomo resolves the host of a later hop that runs over UDP
  (Hysteria2, TUIC, WireGuard) with its own resolver.
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
