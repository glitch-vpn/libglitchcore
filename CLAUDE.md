# CLAUDE.md

Rules for agents working in this repository. These override default behaviour.

## 1. What this project is

libglitchcore is a Go library built as a C shared library (`-buildmode=c-shared`)
that runs VPN engines behind one FFI surface: **xray** (VLESS / VMess /
Trojan / Shadowsocks / SOCKS5 / HTTP) and **mihomo**
(Hysteria2, TUIC, AnyTLS, WireGuard and AmneziaWG). It is
consumed by the Flutter plugin
`glitch-vpn/glitch_vpn_core_plugin`, which downloads release binaries pinned by
version + sha256. Platforms: Android, Windows, Linux.

The FFI shell is `main.go` (package main, cgo exports). Everything else lives
under `internal/`. One `CoreController`, one engine at a time.

### Decisions already made — do not re-litigate

| Topic | Decision |
|---|---|
| FFI surface | **Frozen by default.** New data flows ride the status port as new event codes; new knobs ride `EngineStart`'s `Opts` map. A new C export is a last resort: it changes `libglitchcore.h`, forces ffigen regen in the plugin (CI fails on drift) and needs a service IPC command on Windows |
| Engine composition | Negative build tags `no_xray` / `no_mihomo`; the tagless build links everything. `with_gvisor` is always on in real builds and tests |
| TUN layer | One per binary, never both. The main variant (no tag) runs both engines on our sing-tun fork (`github.com/glitch-vpn/sing-tun`): mihomo natively, xray fed from sing-tun's gVisor stack into its dispatcher, and links no tun2socks; sing-tun's Wintun binding creates the adapter. The tag `with_tun2socks` puts both on the tun2socks bridge instead, with the bridge's own Wintun binding. "One Wintun binding" means one binding drives the adapter in a process: a package a build links but never calls (sing-tun's Wintun in the alternative, reached through mihomo's listener) does not count. On Windows the main variant's binding loads the `wintun.dll` beside the module that holds the core, by full path and never from the search path (the tun2socks variant's upstream binding loads by name from the executable's directory); no copy of Wintun is built into a binary. xray-core's TUN, WireGuard and masque packages link `golang.zx2c4.com/wintun`, which no config the core builds uses: `go.mod` replaces it with `third_party/wintun`, a stub that refuses every call in the main variant and the upstream binding, copied, under `with_tun2socks`; the CI guard holds the linked package to the stub's file list. `make build TUN_LAYER=tun2socks` builds the alternative. CI builds and tests every composition in both variants |
| Licensing | Repo is MIT; compositions with mihomo are GPL-3.0 combined works via `sing`, and so is every main-variant composition with xray, which links sing-tun. Only the xray-only tun2socks variant is GPL-free (the person, 2026-11-05). CI `go list -deps` guards keep excluded engines out of the link, and tun2socks out of the main variant |
| Deploy builds | `make build` (Docker) only. Local mingw builds are a compile check, never a deliverable |
| Windows elevation | Client library forwards engine commands to the `GlitchVpnCore` system service over named pipes (`useServiceIPC`); proxy mode stays in-process |
| Language | Everything in the repo is **English** (code, comments, commits, docs) |
| Docs tone | Dry, human, no AI-writing tells, no product branding — technical names only (libglitchcore, glitch_vpn_core) |

## 2. Hard rules

1. **Do not add or change C exports casually.** Prefer an event code + `Opts`
   key. If an export is unavoidable, say so and account for: header change,
   plugin ffigen regen, Windows service `dispatchCommand` case + client
   wrapper + `ipc_stub.go` stub.
2. **`//export` preambles use plain C types only.** Anything included there
   leaks into `libglitchcore.h` and breaks ffigen (see
   `notif_stats_android.go`). JNI and other native headers stay in `.c` files.
3. **Engine-specific code lives in build-tagged files.** A file importing
   `xray-core` or `mihomo` packages carries the matching
   `//go:build !no_*` tag. The CI matrix (3 compositions, each in both TUN-layer variants) and the
   license guards must stay green.
4. **Any test touching `internal/core` engine or stats paths calls
   `core.SetServiceIPC(false)` in `TestMain`.** `useServiceIPC` defaults to
   true on Windows; without this a test process attaches to the user's real
   running VPN service and can stop their session or its stats stream. Note
   that `SetStatusSink` is one of those paths: registering a sink replays the
   session, and on a client build that means an IPC command to the service.
5. **No config contents in logs or event payloads.** Share links and INI
   configs carry credentials. `ServerEvent` deliberately exposes identity only
   (name/host/port/protocol); keep it that way unless an opt explicitly asks
   for more. A wrapped error can still quote a link, so every log line and
   every lifecycle or stats-error text passes `logfmt.Scrub` on its way out
   (`emitLog` before the JSON is built, `emitStatus` for the text codes); a
   new free-text path goes through one of the two. Live-test links live
   outside the repo (`GLITCH_LIVE_LINKS_FILE`), never committed.
6. **Cross-process routing is local-first.** `engineStop` / `engineIsRunning`
   / `startStats` / `stopStats` act on the in-process engine when one runs and
   forward to the service only otherwise. A proxy-mode session must never
   translate into a command against the service's session.
7. **Comments: prefer silence.** A comment exists only for a non-obvious WHY,
   a contract, or a trap the code cannot express. Never restate the code,
   never narrate history, never explain what a name already says. One short
   line beats a paragraph.
8. **Report honestly.** If tests fail, say so with output. Never claim a build
   passed without running it. No partial work flagged as "caveat: X later" —
   implement properly or ask to defer.

## 3. Repository layout

```
main.go                    # the entire cgo/FFI shell (//export functions)
notif_stats_android.go     # extra export for the Android notification JNI
internal/
  core/                    # controller, engines, stats, liveness, ipresolve,
                           # session state, Windows service + IPC, platform TUN
  xrayconfig/              # share links -> xray config (+ balancer/observatory)
  mihomoconfig/            # share links -> mihomo config (+ proxy group)
  awgconfig/               # awg:// / wireguard:// / wg:// / INI parsing for mihomo
  serverinfo/              # link -> display identity for ServerEvent
  sharelink/               # URL-shaped links parsed with credentials kept out of errors
  vmesslink/               # vmess:// (base64 JSON and URI) -> one shape
  proxylink/               # socks:// and http(s):// proxy links -> one shape
  pinger/                  # MeasurePings (standalone per-engine probes) and the dial through one link
  linkrelay/               # OpenLinkRelay/CloseLinkRelay: a loopback SOCKS5 listener over that dial, no session
  liveness/                # up/down debounce tracker
  smoke/                   # end-to-end self-verification (integration tag)
  loopbackport/            # loopback ports free on TCP and UDP, for the tests
  routing/ dnsconfig/ logfmt/ conninspect/ procname/
tools/gonotices/           # writes THIRD_PARTY_GO_MODULES.txt (make notices)
third_party/nolzo/         # stub for github.com/rasky/go-lzo (GPL-2.0 only): refuses LZO
Makefile, Dockerfile       # deploy builds (Docker)
.github/workflows/         # ci (tag matrix + license guards), release
wiki/                      # user-facing docs (GitHub wiki page names);
                           # README stays short and links here
```

## 4. Runtime contracts

### Status port events

`(int32 code, string message)` posted to the registered Dart port; in service
mode the same pairs traverse the event pipe unmodified. The registry:

| Code | Name | Payload |
|---|---|---|
| 300 | StatsEvent | `{"rx","tx","durationMs","rssBytes","goMemBytes"[,"linkUp","probeMs"]}` |
| 301 | StatsError | text |
| 302 | ServerEvent | `serverinfo.Selection` JSON — connected server + pool; re-emitted on change and on replay |
| 303 | IPEvent | `{"ipv4","ipv6","ipv4Error","ipv6Error"}` — external IPs fetched through the tunnel |
| 400/401 | LogEvent/LogError | logfmt JSON `{ts,level,component,message}`; 401 is level error or fatal; the only codes gated by verbosity |
| 402 | ConnEvent | connection inspector record |
| 500–507 | Engine lifecycle | text; `[<engine>] <what>` |
| 508 | ServiceReattached | text `[service] Reattached`; Windows client builds: emitted once each time the client subscribes again to the service's event pipe after an earlier subscription (never on the first), so the hotspot's whole state is to be sent again |
| 600 | HotspotSharingEvent | `{"shared":"tunnel"\|"wifi"\|"none","blocked","error"}` — Windows only, see *Hotspot sharing*; a share ICS refused is `shared:"none"` with an `error` |

Adding a code means: const in `controller.go`, the same value in the plugin's
`GlitchVpnCoreFfiEventCode`, payload struct with json tags, and a smoke
subtest. Payload fields are add-only — the plugin parses leniently but renames
break it.

### Hotspot sharing (Windows)

`PrepareHotspot()` and `SetHotspotSharing(json)` (`{"on","blockWhileTunnelDown","blockedClients":[MAC…]}`,
at most 8 devices (the frames a MAC sends are dropped), the whole wanted state, idempotent) are the two exports the plugin's hotspot uses; both
answer 3 off Windows and go over the service pipe (`set_hotspot_sharing` with a result code in `data`;
`prepare_hotspot` starts the repair off the pipe and answers `{"result","done"}` to a token the client sends, asked again
until done, so no command holds the pipe while ICS restarts).
`hotspot_sharing.go` is the order over a `hotspotOS` interface (tested over fakes); the Windows calls are
`hotspot_windows.go` (HNetCfgClient.dll's undocumented sharing exports, loaded from System32; finding the
hotspot's adapter; forwarding through winipcfg), `hotspot_wfp_windows.go` (the per-device block, a filter on the MAC at the inbound Ethernet frame layer) and
`hotspot_ics_windows.go` (the repair).
The order follows the controller's own lifecycle events from `emitStatus` (the controller tracks the
phase from the start, so a hotspot turned on under a running tunnel begins from it) and the tunnel's
adapter, found by its GUID: the tunnel counts as down only when the engine says so and the adapter is
gone. Proxy mode is the session's own flag, always "down".

- The rule: forwarding on the hotspot's interface is on only while ICS's public side is the connection
  the phase wants. Unknown, refused, or a tunnel still going away is forwarding off.
- The pair ICS reports (`HNetCfgGet*Index`) is read from `HKLM\...\SharedAccess`, which any local user can
  write, so it is never evidence for forwarding: what the order knows is its own last successful
  `HNetCfgStartSharing(public, hotspot adapter)`, dropped when the hotspot's adapter goes away, comes back
  as another index, a share is refused, or the report says ICS is elsewhere. It shares again on every
  `SetHotspotSharing` and every tunnel-up. The report is believed only to take that record away, and
  names the public side of a standing pair the order stops, on the hotspot's own adapter.
- The hotspot's interface is the one Wi-Fi Direct virtual adapter that is up, found by the driver's
  component id in the network class's registry key (administrators write it), never by a name or by
  ICS's private index. With two up, or the adapters unlisted, nothing is shared or stopped on a guess and
  forwarding is turned off on every adapter that might be it, and on the last known one at every failed
  listing. With sharing on and none up the event is quiet and `blocked` for 10 s, then carries an error
  (the plugin stops the hotspot). A Windows without the sharing exports
  shares nothing, so forwarding stays off and the event says `none` with an error.
- ICS shares the physical connection, not the tunnel's adapter, while the tunnel is down: sharing the
  tunnel's turns the hotspot off when it goes. An index of an adapter that no longer exists is never the
  physical connection; the one shared last is looked at again before it is shared again.
- Every `HNetCfgStartSharing` turns forwarding on again, so forwarding is settled after each, and a
  periodic check puts it back when ICS resumes by itself. The check runs while sharing is on.
- `SetHotspotSharing` stores the state and returns; the worker applies it and answers with event 600, so
  a command never waits behind a reconcile.
- `on:false` stops the pair this order last shared by the indices it shared, even when the adapter is
  already gone (the plugin sends it once the hotspot is down); a pair it did not share is stopped only where its private
  side is the hotspot's adapter and its public side is the tunnel's adapter or a gone one. A pair on a
  physical connection is the user's own hotspot.
- Never restart `SharedAccess` while a hotspot's adapter is up: it turns the hotspot off. `PrepareHotspot`
  refuses, and looks again right before the restart. The service runs the repair off its pipe and gives a
  finished answer only to the poll sequence (token) that started it.
- The repair clears only what names an adapter that is gone (HomeNet rows, a preferred public side); a
  share of an adapter that exists is left alone. It needs the service or an elevated process.
  `INetSharingManager` answers an elevated caller only.

### Controller concurrency

- `coreMutex` guards engine start/stop bodies; quick flags are atomics.
  `emitStatus` takes only the deferred queue's leaf lock, never held across a
  callback, and is safe under `coreMutex`.
- While an FFI export runs (`inFFICall`), callbacks are deferred to one
  goroutine that delivers them in order (`deferredStatus`) — never invoke the
  sink synchronously from a leaf FFI call, and never drop an event for it.
- Every background loop follows the quit/done channel pattern (see
  `startLiveness` / `startSelectionWatch`): close(quit), wait done, and stop
  watchers **before** closing the engine instance they read.
- Session state (`serverSelJSON`, `ipStateJSON`) is cached on the controller,
  cleared via `clearSessionState` on stop and failed starts, and replayed by
  `replaySession` — on already-running starts, on status-port registration,
  and via the `replay_session` IPC command. `clearSessionState` bumps
  `sessionGen`, which is how a start that raced a stop tears down what it
  armed too late (`abortStaleEngineSession`).
- Each engine keeps an `engineSession` (`engine_session.go`) with one set of
  rules: a start counts as running from its request, so a stop then is taken;
  "already running" only for the current session's instance, and an earlier
  session's instance is replaced under `coreMutex`; a stop leaves an instance
  started as late as itself. Engines go through its helpers
  (`beginStart`/`prepareStartLocked`/`finishStart`, `stopEngineSession`/
  `stopEngineInstance`) rather than their own copies.

### Verification of a change (definition of done)

1. `CGO_ENABLED=0 go test -tags=with_gvisor ./internal/...` plus the CI tag
   matrix (`no_mihomo` / `no_xray`). A test must also hold on the GitHub
   Windows runner, which differs from a local run twice: its TEMP is an 8.3
   short path (`C:\Users\RUNNER~1\...`), so a path compared as text with one
   Windows resolved (`GetFinalPathNameByHandle`) passes locally and fails in
   CI; and it runs elevated, so what it creates is owned by the Administrators
   group (the token's default owner), not the user.
2. Smoke: `CGO_ENABLED=0 go test -tags="integration with_gvisor"
   ./internal/smoke/`. A new feature gets a subtest here — the loopback suite
   proves link → config → engine → events end-to-end with no network. The
   first run after relinking can time out (Defender scans the fresh binary);
   rerun before debugging.
3. Root cgo package: mingw gcc (`C:\ProgramData\mingw64\mingw64\bin`) +
   Flutter's Dart headers, `go vet -tags "with_gvisor"` and
   `-tags "service with_gvisor"`.
4. gofmt: the working tree is CRLF (`core.autocrlf=true`) so `gofmt -l .` is
   noise — check LF-normalized copies of changed files. Never rewrite repo
   files with PowerShell `Get-Content`/`Set-Content` (mangles emoji, adds BOM).
5. A feature is not done until the Dart plugin API and its example app are
   plumbed in the same step, in `glitch_vpn_core_plugin`.
6. Preparing a commit includes running the `style-reviewer` and
   `core-safety-reviewer` agents over the diff.

## 5. Commits and releases

- Conventional commits (`feat:`, `fix:`, `refactor:`, `chore:`), English,
  imperative. Never commit or push unless asked.
- Release = tag `v*` → GitHub Actions builds the zip → bump
  `libglitchcore_version` + `libglitchcore_sha256` in the plugin's
  `pubspec.yaml`. Unreleased core against the plugin:
  `LIBGLITCHCORE_LOCAL=/path/to/build_output/ffi`.

## 6. Commands

```bash
make build [ENGINES=xray]           # deploy build, Docker
make test                            # tests in the build container
make notices                         # rewrite THIRD_PARTY_GO_MODULES.txt after a dependency change
make notices-check                   # CI: that file is current and go.mod is tidy

CGO_ENABLED=0 go test -tags=with_gvisor ./internal/...
CGO_ENABLED=0 go test -tags="integration with_gvisor" ./internal/smoke/ -v
GLITCH_LIVE_LINKS_FILE=<path> CGO_ENABLED=0 \
  go test -tags="integration with_gvisor" ./internal/smoke/ -run TestLive -v

# root cgo vet / local DLL (compile check only, not a deliverable)
GOOS=windows CGO_ENABLED=1 CC=gcc \
  CGO_CFLAGS="-I<flutter>/bin/cache/dart-sdk/include" \
  go vet -tags "with_gvisor" ./
```
