# For Maintainers

## Environment

| Need | Why |
|---|---|
| Go 1.27.3 | matches CI; the toolchain version is pinned there |
| Docker | cross-compilation for all targets runs in the toolchain image |
| Dart SDK headers | the root FFI shell includes `dart_api_dl.h`; `go vet ./` needs `CGO_CFLAGS="-I<dart-sdk>/include"` |
| mingw-w64 (optional) | local Windows builds without Docker, e.g. `CC=x86_64-w64-mingw32-gcc` |

Day-to-day work needs neither Docker nor cgo:

```sh
CGO_ENABLED=0 go test -tags=with_gvisor ./internal/...
```

Full artifacts:

```sh
make build                    # all platforms, all engines
make build ENGINES="xray"     # one engine
make test                     # unit + smoke in the container
```

## The gate before a commit

1. `gofmt` — the tree is CRLF on Windows; check formatting on an LF copy so
   line endings do not mask a diff.
2. The tag matrix, all four rows: default, `no_mihomo`, `no_xray no_awg`,
   `no_mihomo no_xray`. An engine excluded from a build must not appear in
   `go list -deps` — that guard is a licence boundary.
3. `go vet` on the root shell with and without `-tags service`.
4. Smoke: `go test -tags="integration with_gvisor" ./internal/smoke/`. It runs
   an xray VLESS server in-process and drives the controller against
   127.0.0.1 — no TUN, no admin, no external network.
5. Windows service tests: `go test -tags="service integration with_gvisor"
   ./internal/core/`. They call the IPC dispatcher directly, so no SCM and no
   installed service are involved. CI runs this row on a Windows runner.
6. The two review agents in `.claude/agents/` over the diff.

## Traps that have cost us time

* **Test binaries and the user's live service.** On Windows `useServiceIPC`
  defaults to true, so an engine or stats call from a test can reach the
  installed `GlitchVpnCore` service and disturb a real session. Every test
  binary pins `SetServiceIPC(false)` in `TestMain`; the service build already
  has it false.
* **Ports.** A TCP-only free-port probe can hand back a port inside a Windows
  Hyper-V/WinNAT UDP exclusion range; xray binds both, so probe both.
* **Geo fixtures.** mihomo validates a .dat by loading the `cn` list, so every
  protobuf fixture carries one, otherwise the test silently goes to the network.
* **Log assertions.** Some behaviour (which resolver the DNS module picked) is
  not on the event surface. Reading the engine's log is allowed for exactly
  those cases, and the shape includes raising verbosity with a cleanup.

## Live tests

Anything that needs a real exit lives behind `GLITCH_LIVE_LINKS_FILE`:

```sh
GLITCH_LIVE_LINKS_FILE=/path/to/links.txt \
  go test -tags="integration with_gvisor" ./internal/smoke/ -run TestLive
```

One share link per line. The file stays outside the repository — links carry
credentials and must never be committed.

## Releasing

Tag `v*` → CI builds the release archive. Consumers pin the version (the
Flutter plugin does it in `pubspec.yaml` together with a sha256, and both move
in the same commit). A tag is the only way a consumer gets new opts keys, so a
core change and its plugin mirror land in the same working session but ship in
that order.

## Working with LLM assistance

We use it, on purpose, and the repository is set up for it:

* `CLAUDE.md` carries the hard rules and the decisions we do not want
  relitigated; `docs/code-style.md` carries the idioms an agent should copy
  instead of inventing.
* `.claude/agents/` holds two reviewers — one for idiom drift, one for the
  failure model (traffic misrouting, key material in logs, IPC, licence
  composition). They run over the diff before a commit.
* The gate above is what decides whether a change is good, no matter who or
  what wrote it. Generated code that cannot pass the tag matrix, the smoke
  suite and a reviewer pass is not a contribution yet.

Human contributions are held to the same bar and reviewed the same way. If you
send a PR, say what you ran — "matrix green, smoke green on Linux" tells a
maintainer more than a description of the change.
