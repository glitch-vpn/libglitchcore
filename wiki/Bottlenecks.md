# Bottlenecks

Known limits and sharp edges. Everything here is deliberate or upstream; where
a workaround exists it is named.

## One engine at a time

The controller runs a single engine per process. A start against a live
different engine is rejected with `EngineConflictOtherCore` (506) rather than
silently switching. Callers that offer engine choice must disconnect first.

## Routing reaches the engine only through connect

Rules are part of the start request. There is no live-update path: changing a
rule means reconnecting. This is accepted behaviour, not an oversight — the
engines rebuild their routers from a config, and a partial in-place update is
where leaks come from.

## Geo databases

The core neither bundles nor downloads geoip.dat/geosite.dat. Pass a directory
with `opts.geoAssetsDir`; it travels inside the start request, so it also
reaches the engine when it runs inside the Windows service, where an env var
set by the app process would not.

* **No default on Android or Linux.** Windows and macOS fall back to the
  directory beside the binary; Android has no such place and nothing is
  packaged in the APK, so geo rules there require `geoAssetsDir`, as they do on
  Linux.
* **mihomo's home is the same directory.** mihomo reads the .dat files from its
  home and writes `cache.db` there, so it needs a writable directory even
  without geo rules: `geoAssetsDir`, else `xray.location.asset`. On Android
  and Linux, where neither has a default, a mihomo start without one fails;
  pass the app's files directory, or set `xray.location.asset` to it once
  through `SetEnvVar`.
* **mihomo validates by loading the `cn` list.** A trimmed .dat without it is
  rejected. Upstream mihomo would delete such a file and download a
  replacement; the core verifies first and fails the start with the file
  intact, and its download URLs are blanked so nothing is fetched behind your
  back.
* **Replacing files in place needs a restart.** mihomo memoises matchers per
  directory, so overwriting geoip.dat and reconnecting keeps the old data for
  the rest of the process lifetime. Write a new directory per version.
* **A missing file fails the connect.** With geo rules present and no usable
  files, xray cannot build its config and mihomo reports the missing file.
  Loud, not silent.
* mihomo may write cache files into the directory you supply.

## DNS

* **fake-ip is xray/mihomo only.** awg takes one plain resolver from the
  config; everything else in `dnsConfig` is ignored there.
* **xray has no DoT.** `tls://` resolvers are skipped with a log line; use
  `https://`, `quic://` or a plain address.
* **`directServers` reach differs by mode.** In fake-ip both engines cover
  every direct dial. In xray's normal mode the split is expressed with
  per-server domain scopes, so a direct list of only `geoip:`/CIDR/`process:`
  entries leaves nothing to scope and the resolvers are ignored (logged). In
  `direct-all` the direct resolvers become the default and the general list is
  scoped to the explicit proxy rules.
* **A hosts entry opts its name out of fake-ip.** Static hosts are consulted
  before any nameserver, so the app gets the real address and domain-plane
  routing for that name depends on sniffing.
* **A sniffed name decides the route, not the address dialed.** A client
  whose SNI or Host names something other than the address it dials meets the
  rules of that name, so a `domain:` direct entry sends whatever address it
  dials direct. In `proxy-all` mode a `geoip:` or CIDR direct entry refuses an
  address it does not hold.
* **Hosts values are filtered per entry.** An entry with several values keeps
  only IPs (an alias target is single-valued by definition), because mihomo
  fails the whole config on a value it cannot parse and xray drops the whole
  table.

## domainStrategy: privacy and matching

`asis` (the default) never resolves for routing. `ipifnonmatch` and
`ipondemand` make xray's router resolve domain-form requests so IP rules can
match them — and in fake-ip mode those internal lookups are routed to the
direct outbound whenever one exists. The browsing domain list then leaves the
machine in the clear, which is what fake-ip otherwise prevents. Enable it only
when IP-rule matching for domain traffic is worth that.

`ipifnonmatch` resolves a name that no domain rule matched; `ipondemand`
resolves it at the first IP rule it meets. Under either of them:

* A `geoip:` or CIDR `block` or `proxy` entry takes a name when any of its
  addresses is in it. For a flow a `process:` proxy entry sends through the
  VPN, a `block` entry does so only under `ipondemand`: under `ipifnonmatch`
  that flow's name is never looked up.
* In `proxy-all` mode a `geoip:` or CIDR `direct` entry sends a flow direct
  only to an address it holds. A name it covers only in part is refused, not
  tunnelled: xray picks the outbound before it picks the address, and cannot
  fall back from one outbound to another. A fully covered name goes direct.
  With IPv6 on, a name whose AAAA address an IPv4-only list does not hold
  counts as covered in part. In `direct-all` mode such a name goes direct, as
  an unlisted one does.
* Under `ipifnonmatch`, a name xray cannot resolve matches no rule and goes to
  the first proxy server, whatever the mode. A profile with no `geoip:` or
  CIDR entry resolves nothing.

## Per-process rules are tier-blind on desktop

`process:` matchers feed a flat map consumed by the tun2socks dialer, so tier
order does not apply to them: the global priority block > direct > proxy wins.
Domain and IP matchers honour tier order normally.

## Windows

* TUN needs elevation. Without the shipped system service the caller must run
  elevated; with it, engine commands cross a named pipe and the user sees no
  prompt. Proxy mode needs neither.
* The command pipe's ACL is open to all local users, and the service runs as
  LocalSystem. Treat it as a local-trust boundary when you design an installer.
* Direct egress binds the physical NIC (`IP_UNICAST_IF`), which is what keeps
  direct traffic out of the TUN default route — but it also means a loopback
  service on 127.0.0.1 is unreachable from the direct outbound.

## Upstream quirks we live with

* xray's observatory reads its status without holding its own lock, so the
  balancer pick is read from traffic counters instead, and `-race` noise from
  that package is upstream.
* mihomo's home directory is process-global; the core re-applies it per
  connection and clears the geodata caches when it changes.
* xray no longer skips certificate verification (`allowInsecure` was removed
  on 2026-06-01). A VLESS, VMess or Trojan link that asks for it
  (`allowInsecure`, `insecure` or `allow_insecure`) fails the xray start; pin
  the certificate with `pcs`, and `vcn` for the name to check it against.
  mihomo still skips verification when a link asks, and reads `pcs` and `vcn`
  too.
