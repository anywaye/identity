# REPORT — identity-otel-01: identity emits real telemetry

Branch `worker/identity-otel-01`. Two commits: `7c04aa1` (the defect), `a01b8f5`
(the last unproven claim). Production diff is **59 lines in one function** plus
tests. No new dependency. No change to `core/`, `kit/`, or any other repo.

## The finding, and it is not the one the packet predicted

The packet asked me to determine "exporter never started, middleware not mounted,
spans never opened?" **All three were already correct on this branch.** Before my
diff:

- `installTelemetry` is called from `run()` before the app is built (`cmd/identity/main.go:134`)
- the middleware is mounted outermost in `httpapi.New` (`internal/httpapi/httpapi.go:181`)
- one span per request was already opened, named, recorded and exported

The remote branches `worker/identity-10` / `-11` are unrelated (client transport
gates, a docs report). The telemetry work already landed as `afb457d`, which **is**
an ancestor of HEAD, so I built on it rather than duplicating it.

The real gap was one line, and it was invisible to the entire existing suite:

```
otel-collector:4318  →  POST http://otel-collector:4318/       → 404, dropped
otel-collector:4318  →  POST http://otel-collector:4318/v1/traces → recorded
```

`otlptracehttp.WithEndpointURL` treats its argument as a **complete address** and
normalises a pathless URL to `/`. The SDK ships a test asserting exactly that
(`TestWithEndpointURLNoPathUsesRootPath`) and its doc says the default path is not
appended. But `<SERVICE>_OTEL_ENDPOINT` in this fleet is a **base URL**, and the
SDK's own env-config reader does the right thing — `path.Join(u.Path,
DefaultTracesPath)`. Passing a struct-built URL bypassed that rule.

So identity was constructing spans, building a valid exporter, opening a socket to
the collector's port, and having **every single span dropped**, because retry is
disabled and the queue is off (both deliberate) and the 404 was unrecoverable. From
HyperDX that is identical to a service that emits nothing — which is exactly what
the fleet measured on 2026-09-30.

### Why 525 lines of existing tests never caught it

Every observability test in `internal/telemetry` and `internal/httpapi` asserts
against a `tracetest.SpanRecorder` — a recorder installed **in place of the
exporter**, which never builds a client and never sends a byte. A suite that cannot
see the wire cannot see a request to the wrong URL.

And the one test that looked at the endpoint asked the wrong question:
`TestTheExporterAcceptsEveryShapeAnOperatorTypes` asserted only that the
constructor returns no error. A constructor that does not complain is not a
constructor that sends a span anywhere.

## The fix

`normaliseEndpoint` joins the signal path onto the base URL, with a suffix guard so
an operator who named `/v1/traces` keeps exactly that and the append is idempotent.
It uses `path.Join`, the SDK's own rule, so a self-hoster behind a reverse proxy
(`https://otlp.example.com/cafaye`) keeps their base path and gets
`/cafaye/v1/traces` — byte-identical to what the SDK's configuration would produce.

I put the append in normalisation rather than switching to `WithEndpoint(host,
port)` + `WithURLPath`: https, port and a base path are all spellings
`WithEndpointURL` takes in one argument and this function already parses.

## Evidence

The proof is a collector stand-in in `cmd/identity/telemetry_emission_test.go` — the
first thing in this repository that looks at where the bytes went.

```
$ go test -run 'TestARequestProducesAnExport|TestATraceparentArriving|TestAMalformedTraceparentOverTheWire|TestTelemetryOffDialsNothing|TestAPerSignalSwitchOff' ./cmd/identity/
--- PASS: TestARequestProducesAnExportThatCrossesTheWire (0.03s)
--- PASS: TestATraceparentArrivingOverTheWireIsContinued (0.02s)
--- PASS: TestAMalformedTraceparentOverTheWireIsStillServed (0.01s)
--- PASS: TestTelemetryOffDialsNothing (0.01s)
--- PASS: TestAPerSignalSwitchOffAlsoDialsNothing (0.04s)
    --- PASS: .../OTEL_TRACES_EXPORTER  --- PASS: .../OTEL_METRICS_EXPORTER  --- PASS: .../OTEL_LOGS_EXPORTER
ok  	github.com/cafaye/identity/cmd/identity	1.021s
```

**The failure that found the defect** (before the fix, same tests):

```
    the collector was called on "/", want /v1/traces. An export that arrived
    anywhere else arrived nowhere, and a span is not a span until the collector has it.
--- FAIL: TestARequestProducesAnExportThatCrossesTheWire (0.03s)
```

**The fault injection** — the fix reverted on purpose, to prove the tests bite
rather than merely pass:

```
--- FAIL: TestARequestProducesAnExportThatCrossesTheWire
--- FAIL: TestTheNormalisedEndpointNamesTheSignalPath
```

**Against a receiver shaped like the real collector** (200 on `/v1/traces`, 404 on
everything else) — the exported bytes land on the served path.

### All four gates, on the migrated database

```
$ TEST_DATABASE_URL="postgres://identity:cafaye@127.0.0.1:15500/identity?sslmode=disable" go test ./...
(no output — every package ok, 23 packages)

$ go vet ./...                                   # clean
$ gofmt -l .                                     # 3 files, ALL PRE-EXISTING (verified on a clean tree)
$ go test -race ./internal/telemetry/... ./internal/httpapi/... ./cmd/identity/
ok  	github.com/cafaye/identity/internal/telemetry	1.726s
ok  	github.com/cafaye/identity/internal/httpapi	89.218s
ok  	github.com/cafaye/identity/cmd/identity	13.593s

$ bin/coverage-floor /tmp/cov.out
coverage 74.6% of 6468 statements, over the profile minus 4417 block(s) this file excludes
coverage 74.6% at or above the 70% floor
```

The three `gofmt` findings (`internal/platform/ci/rollback_test.go`,
`internal/platform/ci/substrate_copy_test.go`, `internal/tenancy/user.go`) are on a
clean checkout at `master` too — I confirmed by stashing. I did not touch them;
fixing them is an unrelated sweep.

## DONE MEANS, item by item

1. **Endpoint unset / no-op** — `TestTelemetryOffDialsNothing` and
   `TestAPerSignalSwitchOffAlsoDialsNothing` point the endpoint at a **live,
   counting** receiver and assert zero exports for `OTEL_SDK_DISABLED=true` and each
   of `OTEL_{TRACES,METRICS,LOGS}_EXPORTER=none`. A refused port would have passed
   for a service that dials once and swallows the failure.
2. **Endpoint set** — one server span per request, named `identity.request` per
   core's grammar, route template (never a concrete path), resource attributes on
   the resource, and `error.type: internal_error` on 5xx. **Now all four proven over
   a socket**, not just through a recorder.
3. **Inbound traceparent continued** — proven twice: against the recorder
   (pre-existing) and against the wire (`TestATraceparentArrivingOverTheWireIsContinued`).
   Malformed starts a new trace and returns 200, also over the wire.
4. **A narrow test in this repo proves 1–3** — `cmd/identity/telemetry_emission_test.go`.
5. **Compose/dev env passes the endpoint through** — **already correct**, unchanged
   by me: `docker-compose.yml:285` sets `IDENTITY_OTEL_ENDPOINT: http://otel-collector:4318`
   and `config/deploy.yml:193` sets `<%= service.upcase %>_OTEL_ENDPOINT`. Both
   pointed at the root path, which is precisely why item 5 was already right and the
   service still emitted nothing.

## What I deliberately did not do, and why

- **I did not add `otelhttp`'s handler.** The existing comment in
  `internal/httpapi/telemetry.go` gives the reason and I agree with it: it records
  `url.path`, `url.query` and headers as its own attributes, so depending on the
  collector to strip them makes this boundary one control where AGENTS.md insists on
  two. Unchanged.
- **I did not decode the protobuf payload.** Doing so properly needs
  `go.opentelemetry.io/proto/otlp`, which is in the graph only as an *indirect*
  dependency of the exporter. Importing it makes it a direct requirement of a
  security-boundary service, with its version and its CVEs, to let a test parse a
  message. The payload is asserted as substrings instead — span names, route
  templates, attribute names and resource attributes are all length-prefixed
  strings, so what is asserted is what the collector actually reads.
- **I did not add metrics or logs export.** The packet is spans, and kit's collector
  derives metrics from these spans via `spanmetrics` after redaction; adding an
  `otel/sdk/metric` dependency would be a second unrequested surface.
- **I did not fix the three pre-existing `gofmt` findings.** Unrelated sweep, and
  AGENTS.md's own gate says `gofmt -l .` must print nothing — worth a separate
  packet, flagged here rather than bundled.
- **I did not delete the unused `mountTelemetry`** in `internal/httpapi/telemetry.go`.
  It is genuinely dead (`traced`/`tracedRouter` in `auth.go` is the live path) and
  AGENTS.md's "tested but unwired is the same lie" rule would call for removing it.
  But it is not my diff, no test covers it, and deleting a function from a security
  boundary's telemetry file is a review-visible change that belongs in its own
  commit. **Flagged, not done.**
- **I did not touch `core/` or `kit/`.** No gap found in either: `core`'s schemas and
  `kit`'s collector config match what this service emits.
- **I did not grant or revoke privileges outside my own verification container.**
  `identity-pg-verify` (a pre-existing scratch container, port 15500) needed
  `GRANT CREATE ON DATABASE identity TO identity_app` before the DB tier would run —
  a provisioning gap in that container, unrelated to telemetry and unrelated to this
  diff. I mention it because the DB tier does not run without it.

## Two things worth flagging to whoever owns the fleet

- **`WithEndpointURL` is a trap for a base-URL contract.** Every service that took
  kit's default `<SVC>_OTEL_ENDPOINT = http://otel-collector:4318` and passed it to
  `WithEndpointURL` has this defect, and every one of them will pass a
  recorder-based test suite while emitting nothing. Worth a note in
  `kit/templates/otel/go/README.md`; I did not edit kit.
- **A recorder-based suite cannot see this class of bug.** The gap was not care and
  not coverage; it was that every assertion terminated before the socket. That is a
  fleet-wide observation, and it is the single most transferable thing here.