# Code style

How this codebase solves the problems it keeps running into. Every rule here was
derived from code already in the tree, and every example is a real one,
simplified.

`CLAUDE.md` is the rulebook — what may exist, the runtime contracts, the
verification gate. This file is narrower: given that a thing is allowed, it
says which of the several working ways to write it this repository has settled
on. Sections are numbered so a review finding can point at one.

---

## 1. Controller state

### 1.1 Atomics for flags and snapshots, `coreMutex` for transitions

Engine start/stop bodies hold `coreMutex`. Anything read from another
goroutine — running flags, link state, cached JSON payloads — is an atomic:

```go
isXrayRunning atomic.Bool      // flag
linkProbeMs   atomic.Int64     // snapshot
serverSelJSON atomic.Value     // string; "" = none
```

A field guarded sometimes by the mutex and sometimes not is a finding. So is a
new `sync.Mutex` where the existing pattern (one small mutex per subsystem:
`statsMu`, `ipFetchMu`) already has an owner for that state.

### 1.2 Background loops: quit/done, stop before close

Every loop the controller starts follows `startLiveness`'s shape — local
channel copies, `close(quit)` to stop, `<-done` to wait:

```go
quit := make(chan struct{})
done := make(chan struct{})
x.selWatchQuit, x.selWatchDone = quit, done
go func() {
    defer close(done)
    for {
        select {
        case <-quit:
            return
        case <-ticker.C:
        }
        ...
    }
}()
```

The stop side **swaps the pointers out under `loopsMu`, then closes and waits
outside the lock** — holding a lock across the wait deadlocks any loop that
needs `coreMutex` (the awg passive sampler does), and the swap is what makes a
second concurrent stop safe instead of a double-close panic. A loop reading an
engine instance stops **before** the instance closes — `clearSessionState` runs
in `HandleXrayStop` ahead of the goroutine that calls
`xrayCoreInstance.Close()`. A `time.Sleep` poll, a `context.Context` where the
tree uses channels, or a goroutine with no done-wait are findings.

One sanctioned exception: the external-IP fetch worker (`ipresolve.go`) is a
single-flight busy/again worker with a generation counter instead of
quit/done, because a stop must not block on an in-flight HTTP fetch. Its rule
is that nothing it produces may escape a superseded session — the generation
is re-checked under `ipFetchMu` before the state is stored. Copy that shape
only with the same guarantee.

A start that races a stop is caught by `sessionGen`: the start captures the
generation, the stop bumps it in `clearSessionState`, and the start's tail
calls `abortStaleSession` before and after arming. Without it a stop landing
in the tail leaves the previous session's loops running — on desktop awg the
liveness prober would then measure the physical NIC and the IP fetch would
publish the user's real address as the tunnel exit.

### 1.3 Session state: cache, clear, replay

State a reattaching client needs (last ServerEvent/IPEvent) lives in
`atomic.Value` JSON strings with three obligations, all in one change:

- set through one function that dedupes by payload before emitting,
- cleared in `clearSessionState` (wired into every stop and failed-start path),
- replayed in `replaySession`.

New session-scoped state that misses one of the three legs is a finding.

## 2. Events

### 2.1 One emitter

Everything reaches Dart through `x.emitStatus(code, message)`. Only
`LogEvent`/`LogError` obey the verbosity gate; never add gating for other
codes, and never post to the sink directly.

### 2.2 Payloads: marshal structs, dedupe before emit

Event payloads are small structs with json tags, marshaled — see
`externalIPState`, `serverinfo.Selection`. The one exception is the 1 Hz stats
line, which stays `fmt.Sprintf` on purpose. Emit paths dedupe by comparing the
new payload string to the cached one; an event that re-fires identical data on
a timer is a finding.

Fields are add-only with `omitempty` for optionals. Renaming or repurposing a
field breaks the Dart parser silently — the plugin's `tryParse` returns null
and the event vanishes.

### 2.3 A new event code lands in four places

`controller.go` const, the plugin's `GlitchVpnCoreFfiEventCode` (same value),
a payload struct, a smoke assertion. A diff adding fewer than four is
incomplete.

## 3. Engine wiring symmetry

Each engine's start handler has three branches, and additions must land in all
three of each engine:

- already running → emit `EngineAlreadyRunning` + `EngineConnected` +
  `reemitSessionState()` + `startStats`,
- fresh start goroutine → on error: `clearSessionState()` + `EngineError`;
  on success: liveness, session-state init, IP-resolve config, stats,
  `EngineConnected`,
- stop handler → stop loops and clear state **synchronously**, then the async
  teardown goroutine.

A feature wired into xray but not awg/mihomo (or vice versa) without a stated
reason is a finding — `balancerStrategy` silently dropped on the awg path for
months because of exactly this.

## 4. Build-tag composition

- A file that imports an engine's packages carries that engine's negative tag:
  `//go:build !no_xray` on `xray_selection.go`, `!no_mihomo` on
  `engine_mihomo.go`. Shared code (`serverstate.go`, `ipresolve.go`,
  `liveness.go`) imports no engine packages.
- Engine registration is a build-tagged `init()`; shared code reaches engines
  only through `engineRegistry` and the `Engine` interface.
- Stubs exist for excluded compositions (`engine_state_*_stub.go`,
  `ipc_stub.go`); a new cross-cutting symbol referenced from shared code gets
  a stub in the same change.
- Anything mihomo-TUN related needs `with_gvisor` in tests; the CI matrix and
  the `go list -deps` license guards are the arbiter.
- `internal/serverinfo` deliberately re-parses links the engines also parse:
  it is imported by untagged code and must not reach `xrayconfig` /
  `mihomoconfig`. The mirrors (legacy `ss://` base64, the `+`-as-space rule in
  remarks) move together — a change to link parsing lands in both, or a link
  the engine accepts reports an empty host in the ServerEvent.

## 5. Opts

`EngineStart` knobs ride `Opts map[string]string`.

- Keys are camelCase and parsed only in `optsFromRequest` into typed
  `engineOpts` fields — engines never read the raw map.
- Parsing is forgiving with an explicit default: `boolOpt`, `intOpt`,
  `probeURLOpt` (rejects non-http(s) instead of failing the connect). A
  tri-state "on unless explicitly disabled" reads presence first:

```go
resolveIP := true
if v, ok := o["resolveExternalIp"]; ok && strings.TrimSpace(v) != "" {
    resolveIP = boolOpt(v)
}
```

- Engines ignore fields they do not support; an opt must never error an
  engine that has no use for it.

## 6. Comments

The full rule is CLAUDE.md §2.7. In this tree it means: doc comments carry a
contract or a trap, not a restatement of the signature; struct fields carry
value domains (`// vless | trojan | ss | hysteria2 | awg`); one-liner
functions carry nothing.

```go
// Bad — restates the name.
// localEngineRunning reports whether the local engine is running.

// Good — the trap the code cannot say.
// Android liveness via UAPI counters - our package is excluded from the VPN there.
```

## 7. Tests

- Unit tests construct a bare `&CoreController{}` and register a capturing
  sink via `setStatusSink` (package-internal, no replay side effects);
  restore with `t.Cleanup`.
- Timing knobs that tests need are package vars (`selectionWatchInterval`),
  overridden and restored in the test, not exported.
- Table tests where variants differ by data; separate funcs where they differ
  by flow. Test names say the behaviour, not the method.
- End-to-end behaviour belongs in `internal/smoke` behind the `integration`
  tag: `startProxyEngine` + `captureEvents` + local `httptest` upstreams. The
  smoke `TestMain` pins `SetServiceIPC(false)`; any new test binary touching
  engines does the same.
- Live tests read `GLITCH_LIVE_LINKS_FILE` and skip when unset. Links are
  never committed, never logged.
- `-race` is clean for `./internal/...`. It is **not** clean for the smoke
  suite with a leastping balancer: xray-core's `GetObservation` reads the
  observer's status slice without its lock (v1.260327.0
  `app/observatory/observer.go:41`) and its own router hits that on every
  dispatch. Do not chase those reports, and do not consume `GetObservation`
  from our side — the xray pick is read from traffic counters instead.

## 8. Windows service IPC

- Local-first: a command acts on the in-process engine when one runs and
  forwards otherwise (CLAUDE.md §2.6). New code paths inherit this by calling
  the existing `engineStop`/`startStats` helpers rather than
  `serviceXxx` directly.
- A new pipe command is three pieces in one change: `dispatchCommand` case,
  `serviceXxx()` wrapper in `ipc_windows_client.go`, no-op stub in
  `ipc_stub.go`.
- Events need nothing: every `emitStatus` pair traverses the pipe as-is.
- The command payload is a flat JSON object with snake_case action names
  (`replay_session`, `listen_stats`) and explicit field names — no positional
  data.
