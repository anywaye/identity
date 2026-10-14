# Report — roll-c5-nats-reconnect: the NATS reconnect budget expires and the outbox never recovers

## Live evidence (the measurement that carries the defect)

From the test box 2026-10-14/15, fresh install, substrate installed. `kubectl -n identity logs deploy/identity` over the window identity had been running while the broker was away:

```
$ kubectl -n identity logs deploy/identity --since=5m | grep -c "publishing an event failed"
1200
$ kubectl -n identity logs deploy/identity --since=20m | grep "connection closed" | head -1
time=2026-10-14T21:02:54Z level=WARN msg="publishing an event failed; it stays queued for retry"
  type=identity.user.created … error="outbox: publishing identity.user.created: nats: connection closed"
$ kubectl -n identity logs deploy/identity --since=20m | grep "connection closed" | tail -1
time=2026-10-14T21:11:39Z level=WARN … type=identity.api_key.created … error="… nats: connection closed"
```

- **Nine minutes of continuous failure** (21:02:54 → 21:11:39) and **1200 WARNs in five of them** (≈ 4 attempts/sec, the outbox poll loop retrying).
- Broker pod in the same window: `nats-6cb99597d4-lfw2k  1/1   Running   0     9m7s` — the broker was healthy, identity's connection was not.
- The error is terminal: `nats: connection closed` is not "broker away, will retry" but "this client has given up". Every later `Publish` sees the same string, the rows stay in `outbox_events`, and the events are silently never published for the life of the pod. The events are **not lost** (the table is durable) but they never drain.

The install's own ordering caused it: step 11 creates the broker after identity is already running, so the window of "broker away" is the installer's legitimate state and the publisher must survive it.

## The budget's arithmetic

From `go/pkg/mod/github.com/nats-io/nats.go@v1.54.0/nats.go`:

```go
const DefaultMaxReconnect = 60
const DefaultReconnectWait = 2 * time.Second
```

`nats.Connect` with `RetryOnFailedConnect(true)` reconnects a dropped connection by
default, but only within `MaxReconnect` attempts spaced by `ReconnectWait` (plus up
to 100 ms jitter). The defaults are therefore:

```
60 attempts × 2 s ≈ 120 s ≈ 2 minutes
```

Nine minutes is 4.5 budgets; 1200 publishes in five minutes is the loop proving the
budget was exceeded and never reset. When the 60th attempt fails the client
transitions to `CLOSED`, calls `ClosedHandler`, and every later `PublishMsg` returns
`nats: connection closed` immediately. The packet at `internal/outbox/nats.go` already
said the outbox exists so "the broker can be away for as long as it likes" — a two-
minute deadline contradicts that paragraph, which is why this is a defect rather than
tuning.

## What replaced it

`internal/outbox/nats.go:134`

```go
nats.MaxReconnects(-1),
```

`-1` is nats.go's documented "never give up" (`MaxReconnect < 0` disables the limit
in `selectNextServer`). The publisher's durable store is the table, so it must not
have a deadline on the broker's return. The paragraph that already argued for
`RetryOnFailedConnect` now carries the budget arithmetic and the contradiction, and
the option is stated beside that paragraph rather than as a stray line.

## What says the connection state, once

Per-publish `WARN "publishing an event failed; it stays queued for retry"` is correct
(it names `type`, `id`, `error`). What was missing is the **one line per closure**
that says the connection is away and will be retried, so an operator can tell
"broker is away" from "this pod is broken" without counting 1200 lines.

`internal/outbox/nats.go:135-144`

```go
nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
    logger.Warn("nats connection disconnected; will retry", "error", err)
}),
nats.ClosedHandler(func(c *nats.Conn) {
    if err := c.LastError(); err != nil {
        logger.Warn("nats connection closed", "error", err)
    } else {
        logger.Info("nats connection closed")
    }
}),
```

- No `ReconnectErrHandler` and no per-publish log: a line per retry is how a real
  defect gets buried.
- `NewNATSPublisher` now takes `*slog.Logger` (nil → discard) and the caller
  `cmd/identity/main.go:603` passes the process logger, so the one line appears in
  the same stream the publish failures do, with the same `error` shape.
- With `MaxReconnects(-1)` the `CLOSED` transition due to budget exhaustion never
  happens; `DisconnectErrHandler` is the once-per-outage line. `ClosedHandler`
  remains for the terminal cases (explicit `Close` or auth failure) and is asserted
  the same way.

## How recovery is proven (not just the option)

Unit tests with a **real** NATS server + JetStream (the fleet's existing idiom;
`redis-server` is exec'd for the same reason) — `internal/outbox/nats_reconnect_test.go`:

1. **Green — `TestNATSPublisherRecoversAfterExtendedOutage`** — broker up → one
   `RunOnce` succeeds and the row is `published`. Broker down → wait 700 ms
   (= 70 fast reconnect attempts, > 60 × 10 ms, so longer than the old budget;
   production would be 70 × 2 s = 140 s > 120 s). Publisher is still
   `RECONNECTING`, not `CLOSED`. Queue another row while broker is away —
   `Publish` fails (short 500 ms context so the test does not wait the 10 s
   `DefaultPublishTimeout`). Row stays `published IS NULL`. Broker back on the
   **same port** (required because the client reconnects to the same URL) with a
   JetStream stream covering `identity.>` → wait `CONNECTED` → `RunOnce` drains the
   queued row and `published_at` becomes non-NULL. A fresh publish after reconnect
   is verified by a `SubscribeSync` that receives the same envelope `id` (the
   consumer's dedupe key).

   The reconnect wait is accelerated to `10 ms` via the client's injectable path
   (`nats.ReconnectWait`) while keeping `MaxReconnects(-1)` — the same code path
   as `NewNATSPublisher`, only faster. The packet allows this when a real broker
   would make the test 2 minutes. A test that only asserts `Opts.MaxReconnect ==
   -1` is a test of the line, not of the behaviour.

2. **Green — `TestNATSPublisherMaxReconnectIsInfinite`** — asserts `pub.nc.Opts.MaxReconnect == -1`.

3. **Green — `TestNewNATSPublisherDoesNotFailWhenBrokerIsDownAtBoot`** — URL of a
   non-listening port with `RetryOnFailedConnect` still returns `nil` error and
   `RECONNECTING` with `-1`, so boot does not fail.

4. **Green — `TestNewNATSPublisherRefusesAnUnparseableURL`** (existing) — a URL
   containing a control character is still refused at boot (`url.Parse` error), so
   a typo is not swallowed.

## Controls and verdicts

| Control | Expected | Verdict |
|---------|----------|---------|
| **Green, real tree: broker away > old budget, publisher reconnects and queued rows publish** | `RecoversAfterExtendedOutage` passes, row drained after 700 ms outage | **PASS** (1.6 s) |
| **Green, real tree: malformed URL still refuses at boot** | `RefusesAnUnparseableURL` passes | **PASS** |
| **Green, real tree: broker down at boot still does not fail the process** | `DoesNotFailWhenBrokerIsDownAtBoot` passes, status `RECONNECTING` | **PASS** |
| **RED: code as it stands on `master` gives up — broker away > budget shows `connection closed` and rows never draining** | `TestNATSPublisherWithBoundedBudgetGivesUp` — same server/shutdown sequence with `MaxReconnects(5)` and `10 ms` wait, 1 s sleep > 5×(10 ms+100 ms jitter): publisher is `CLOSED`, `Publish` → `connection closed`, row never drains. This is the old defaults at small scale; production's 60×2 s would have been `CLOSED` at 120 s, nine minutes is 4.5 × that. Live evidence above is the second proof and is quoted in the commit message. | **RED proven** (old code is terminal; new code with `-1` stays `RECONNECTING`) |
| **RED: `connection closed` line emitted once per closure, not once per publish** | `TestNATSPublisherLogsConnectionStateOncePerClosure` — 5 direct `Publish` failures while `RECONNECTING` (500 ms deadline each, so the test does not wait `10 s` per event) produce exactly **1** handler line (`will retry` or `connection closed`), not 5. A thread-safe buffer is used because the handler runs on NATS's async goroutine (`go vet -race` flagged the naive `bytes.Buffer`). Before the fix there was **no** handler line, only 1200 per-publish WARNs. | **RED proven → GREEN after fix** |

Race detector is clean: `go test -race ./internal/outbox` passes (the safeBuf fix).

## Boot behaviour unchanged

- `RetryOnFailedConnect(true)` retained; a broker down at boot is `RECONNECTING` and
  `NewNATSPublisher` returns `nil` error.
- An unparseable URL (`nats://\x7f…`) still fails `nats.Connect`'s `url.Parse` before
  retry logic, so `NewNATSPublisher` returns `outbox: connecting …: parse "nats://…": net/url: invalid control character`.

## Tooling

Terminal and file tools only (Bash, Read, Edit/Write). No browser, no JS sandbox,
no `fetch(file://…)`. Gate is `bin/prime` + `go vet` + `gofmt -l` + `go test -race`
and `TEST_DATABASE_URL` for the DB tier (postgres at `127.0.0.1:15500` via
`kit`'s `cafaye-postgres`). A second `nats-server` on a fixed port is started in-
process for the reconnect tier — no external broker required.

## Files changed

- `internal/outbox/nats.go` — `MaxReconnects(-1)` + `DisconnectErrHandler`/`ClosedHandler` + expanded comment; signature `NewNATSPublisher(url string)` → `(url string, logger *slog.Logger)`.
- `cmd/identity/main.go:603` — pass `logger`.
- `internal/outbox/nats_test.go` — update 5 call sites to new signature.
- `internal/outbox/nats_reconnect_test.go` — new: `DoesNotFailWhenBrokerIsDownAtBoot`, `MaxReconnectIsInfinite`, `RecoversAfterExtendedOutage` (green), `WithBoundedBudgetGivesUp` (red), `LogsConnectionStateOncePerClosure` (red).

## Worktree

`moon/wt/roll-c5-nats-reconnect` for this repo. No second repo was touched.
