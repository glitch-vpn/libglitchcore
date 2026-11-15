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
* mihomo may write cache files into the directory you supply, except under
  the Windows service, which copies the geo files into a directory of its own
  and writes there (see [Getting Started](Getting-Started#windows-without-uac-prompts)).

## DNS

* **xray has no DoT.** `tls://` resolvers are skipped with a log line; use
  `https://`, `quic://` or a plain address.
* **A query travels as its flow would.** Through the proxy where the
  catch-all proxies, direct where it is direct, and a tier's direct names take
  `directServers`. With fake-ip off an app's query goes upstream that way, and
  the split for the names a tier sends the other way is expressed per name
  (xray: per-server domain scopes; mihomo: a nameserver policy over `domain:`,
  `full:` and `geosite:` entries), so a direct list of only
  `geoip:`/CIDR/`process:` entries leaves nothing to scope and the resolvers
  are ignored (xray logs it). In `direct-all` the direct resolvers become the
  default and the general list is scoped to the explicit proxy rules. With
  fake-ip on, mihomo answers A and AAAA from the pool and sends the rest
  upstream the same way: the filter's names, and every other record type. xray
  resolves the filter's names through the proxy; its module otherwise looks a
  name up only to dial it direct (`asis`, or `direct-all`), so the direct
  resolvers answer those lookups, the general ones behind them, and both leave
  direct. Each of xray's resolvers sends its queries under an inbound tag of
  its own, so a direct resolver that is also a general one is told
  apart. On mihomo a direct dial resolves its name through `direct-nameserver`
  - the direct resolvers, or the general ones plain when none are named: a
  direct flow is seen on the way anyway - and a resolver given by name is
  found through the session's resolvers that are addresses
  (`default-nameserver`), not mihomo's own four.
  A server's own hostname is resolved by the system resolver, from the device,
  on both engines: it has to be reached before anything can travel through it.
* **A WireGuard or AmneziaWG outbound resolves inside its tunnel** with the
  session's resolvers as its own. That outbound takes no bootstrap resolvers,
  so a resolver given by name (`https://dns.google/dns-query`) has its name
  looked up by the system resolver, from the device; a `hosts` entry for the
  resolver's name avoids that lookup.
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
match them. In `proxy-all` those lookups travel through the proxy, as the
names they are for will unless an address rule takes them, and `directServers`
are left out (logged), so a direct tier's name is resolved through the proxy
too when freedom dials it. In `direct-all` the direct resolvers answer them,
direct, and a proxied name a tier lists after an address rule is looked up
direct under `ipondemand`.

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
A flow the dialer sends direct or through the VPN still goes to the engine,
under an inbound of its own, where every tier's block meets it first. A direct
app's own DNS queries are not intercepted, so it keeps its own resolver: a
block by name meets its flows through content sniffing, and through queries it
sends the system resolver, which answer with fake IPs; an address block meets a
name once the direct outbound resolves it. Domain and IP matchers honour tier order normally.

## Windows

* TUN needs elevation. Without the shipped system service the caller must run
  elevated; with it, engine commands cross a named pipe and the user sees no
  prompt. Proxy mode needs neither.
* The service runs as LocalSystem, and its pipes admit LocalSystem, elevated
  administrators and the user at the console — or, with nobody there, the one
  user of an active remote session. Every command and every event subscriber
  is checked against that user, so after a switch of users the one switched
  away from is refused until they come back. On a switch the connection
  inspector and logging are turned off, and so they
  are while the service cannot tell who is at the machine, when only
  LocalSystem and elevated administrators may turn them back on. With several
  remote users at once and nobody at the console, only elevated
  administrators get through.
* When a different user comes to the console, the service stops the session
  the previous user started, so the new user starts with the VPN off; nobody
  being served stops nothing, the same user coming back finds it running, and
  a session LocalSystem started is left alone.
* Admission is per user, not per session: the served user is admitted from
  any session they are signed in to, and an elevated administrator's client
  stays admitted across a switch of users.
* The service draws new pipe names at each start and publishes them under
  `HKLM\SOFTWARE\glitch_vpn_core` (`CommandPipe`, `EventPipe`), a key only
  LocalSystem may write; a service that cannot publish them does not start,
  and it withdraws them when it stops. The library reads them there and
  refuses a pipe that LocalSystem or the Administrators group does not own, or
  that a process other than the service's serves. That check reads the
  service's state, which takes query-status access on it: the default
  descriptor of a service grants that to interactive users (console and
  remote desktop), so a client under a batch or network logon cannot dial.
* Each command runs while a change of served user waits for it, so every
  command returns promptly: a command that waits on another would hold up the
  change and, once the change waits, every command after it.
* The service caps the connections each pipe holds open, in total and for one
  account, and refuses any beyond them (`maxCommandConnections`,
  `maxEventConnections` and their per-caller counterparts in
  `internal/core/service_windows.go`).
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
