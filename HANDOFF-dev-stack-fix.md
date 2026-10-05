# HANDOFF: dev-stack fix (two compose defects) — done; two more found, not mine

Branch `compose-dev-stack-fix`, three commits off `3c0b63b`. Diff is
`docker-compose.yml` only; no Go file, no migration, no `kit.ref`, nothing pushed.

## Done and verified

1. **`networks: [platform]`** — `8a40b63`. The service declared no network, so it
   landed on `<project>_default` while kit puts postgres on `<project>_platform`.
   `docker compose config` before the fix showed `identity: {default: null}`.
2. **`IDENTITY_SYSLOG_ADDRESS` variable** — `66b2af4`, plus the re-read cost in
   `73e9c4b`. Default is still `tcp://otel-collector:15514`; the variable carries
   the IP on a Docker Desktop / OrbStack daemon.

### Exact commands

| Command | Exit | Covers |
|---|---|---|
| `bin/dev nuke && bin/dev up` (fresh volume, IP re-read, then up again) | 0 | full stack, identity healthy on 8080, 19 migrations applied |
| `curl localhost:8080/healthz` | 200 `{"status":"ok"}` | liveness |
| `curl localhost:8080/readyz` | 200 `{"status":"ok","deps":"postgres"}` | readiness with the pool connected |
| `psql -U identity_app -d identity -tAc 'select current_user'` | `identity_app` | the app role authenticates |
| `TEST_DATABASE_URL=… bin/prime` | 0 | `go mod download && go build ./... && go test -count=1 ./...` |
| `TEST_DATABASE_URL=… REQUIRED_DB=1 go test -count=1 ./...` | 0 | 0 FAIL, 0 SKIP |
| `TEST_DATABASE_URL=… REQUIRED_DB=1 go test -race -count=1 ./...` | 0 | no data races |
| `go vet ./...` | 0 | vet |
| `bin/coverage-floor` | 0 | 74.4% over the 70% floor |
| `docker run --log-driver syslog --log-opt syslog-address=tcp://<name>:15514` | 125 | the defect, with no compose file and no cafaye |
| same, against the container's IP | 0 | the mechanism |

Two checkouts coexist via a git-ignored `.env`: `KIT_STACK_NAME=identity-compose`
and ports `16500/16510/16511/16512/16600/16700/16800`.

## Baseline failures, not from this diff

`golangci-lint run ./...` → 71 issues (errcheck 17, unused 38, staticcheck 13,
ineffassign 3). `gofmt -l .` names three files. All pre-date this branch —
`git show 3c0b63b:<file> | gofmt -l /dev/stdin` flags the same files, and the diff
touches no Go file. The repo's own `ci.yml` header already calls lint "expected
red". Not fixed; out of scope.

## Two more defects found, deliberately NOT fixed

### 1. `bin/dev` re-fetches kit every run and deletes a directory out from under a running container

`stack_is_usable` in `bin/dev` requires `templates/compose/mimir/` and
`templates/compose/loki/` and friends. The pinned ref `e69f5df` **removed mimir**
(kit's compose no longer has a mimir service or volume). So the cache never
validates, `fetch_stack` runs `rm -rf "$dest"` on every invocation, and the
collector — whose config is a **bind mount** into that directory — loses
`/etc/otel/otel-collector.yml` while running:

```
Error: failed to get config: cannot retrieve the configuration: unable to read
the file file:/etc/otel/otel-collector.yml: no such file or directory
```

Measured: first `bin/dev up` left `identity-compose-otel-collector-1` UNHEALTHY
and `bin/dev up` exited 1 with "stack did not become healthy". This is
`bin/dev`'s, i.e. kit's, and `bin/dev` is copied verbatim from kit — fixing it
here means forking kit's script, which AGENTS.md forbids ("kit's, verbatim").

Workaround used for verification: `KIT_STACK_DIR=/tmp/cafaye-kit-e69f5df`, a copy
of the pinned tree, which skips the cache and the refetch. That is bin/dev's own
documented override.

### 2. The crash layer is wired end to end and still records nothing

With the address fixed, Docker delivers to the collector's `syslog/crash`
receiver and the receiver **rejects every record**:

```
error tcp/input.go:193 Failed to write entry {"kind":"receiver","name":"syslog/crash",
"error":"expecting a version value in the range 1-999 [col 4]"}
```

46 such lines. Loki holds zero streams for `{service_name="identity"}` after a
successful probe container with the same tag. The receiver declares
`protocol: rfc5424` (kit's `otel-collector.yml:123`) and Docker's `syslog` driver
emits RFC3164 on this daemon; `--log-opt syslog-format=rfc5424` is not honoured
here either. The framing mismatch is between the **daemon's** driver and kit's
**receiver config** — neither file is identity's to change, and this is not the
defect this packet was given.

So: on a Docker Desktop / OrbStack host, identity now STARTS (was: could not
start), and its panic output is delivered to the collector but rejected there.
Whether the crash layer is *recorded* is a separate kit packet.