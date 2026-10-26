# CLAUDE.md

Rules for agents working in this repository. These override default behaviour.

## 1. What this project is

libglitchcore is a Go library built as a C shared library (`-buildmode=c-shared`)
that runs VPN engines behind one FFI surface: **xray** (VLESS / VMess /
Trojan / Shadowsocks), **awg** (AmneziaWG) and **mihomo** (Hysteria2, TUIC,
AnyTLS, plus the bridge paths). It is consumed by the Flutter plugin
`glitch-vpn/glitch_vpn_core_plugin`, which downloads release binaries pinned by
version + sha256. Platforms: Android, Windows, Linux.

The FFI shell is `main.go` (package main, cgo exports). Everything else lives
under `internal/`. One `CoreController`, one engine at a time.

### Decisions already made — do not re-litigate

| Topic | Decision |
|---|---|
| FFI surface | **Frozen by default.** New data flows ride the status port as new event codes; new knobs ride `EngineStart`'s `Opts` map. A new C export is a last resort: it changes `libglitchcore.h`, forces ffigen regen in the plugin (CI fails on drift) and needs a service IPC command on Windows |
| Engine composition | Negative build tags `no_xray` / `no_awg` / `no_mihomo`; the tagless build links everything. `with_gvisor` is always on in real builds and tests |
| Licensing | Repo is MIT; compositions with mihomo are GPL-3.0 combined works via `sing`; xray and awg compositions are GPL-free. CI `go list -deps` guards keep excluded engines out of the link |
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
   `xray-core`, `amneziawg-go` or `mihomo` packages carries the matching
   `//go:build !no_*` tag. The CI matrix (4 compositions) and the license
   guards must stay green.
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
  awgconfig/               # awg:// / INI parsing -> UAPI
  serverinfo/              # link -> display identity for ServerEvent
  sharelink/               # URL-shaped links parsed with credentials kept out of errors
  vmesslink/               # vmess:// (base64 JSON and URI) -> one shape
  pinger/                  # MeasurePings (standalone per-engine probes)
  liveness/                # up/down debounce tracker
  smoke/                   # end-to-end self-verification (integration tag)
  loopbackport/            # loopback ports free on TCP and UDP, for the tests
  routing/ dnsconfig/ logfmt/ conninspect/ procname/
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

Adding a code means: const in `controller.go`, the same value in the plugin's
`GlitchVpnCoreFfiEventCode`, payload struct with json tags, and a smoke
subtest. Payload fields are add-only — the plugin parses leniently but renames
break it.

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
  armed too late (`abortStaleSession`).

### Verification of a change (definition of done)

1. `CGO_ENABLED=0 go test -tags=with_gvisor ./internal/...` plus the CI tag
   matrix (`no_mihomo` / `no_xray no_awg` / `no_mihomo no_xray`).
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
make build [ENGINES="xray,awg"]      # deploy build, Docker
make test                            # tests in the build container

CGO_ENABLED=0 go test -tags=with_gvisor ./internal/...
CGO_ENABLED=0 go test -tags="integration with_gvisor" ./internal/smoke/ -v
GLITCH_LIVE_LINKS_FILE=<path> CGO_ENABLED=0 \
  go test -tags="integration with_gvisor" ./internal/smoke/ -run TestLive -v

# root cgo vet / local DLL (compile check only, not a deliverable)
GOOS=windows CGO_ENABLED=1 CC=gcc \
  CGO_CFLAGS="-I<flutter>/bin/cache/dart-sdk/include" \
  go vet -tags "with_gvisor" ./
```
