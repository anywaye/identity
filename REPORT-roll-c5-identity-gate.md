# REPORT-roll-c5-identity-gate.md

## Step order (what the gate job runs, and where it died)

`bin/prime` itself is three steps: `go mod download` → `go build ./...` →
`bin/provision-testdb` (only when `TEST_DATABASE_URL` is set) →
`go test -count=1 -p 4 ./...`. It writes no `suite.log`; that file is written
by the *next* CI step (`go test -v -count=1 -race ./...`), which never ran.

CI `gate` job order: pins check → `goose` install → provision role →
`goose up` + `status` → `bin/rollback` → **`bin/prime` (RED, exit 1)** →
suite.log step (never reached) → upload `suite.log` (`if-no-files-found:
error`, hence the second red).

CI run 38578538549, job 115901968841. The job log's container noise hides it,
but the step output (fetched via `gh run view … --log`) contains the cause:

```
provision-testdb: the DSN's own user can provision; using it as the admin connection
bin/provision-testdb: role identity is superuser or BYPASSRLS, which bypasses
row-level security even with FORCE. Recreate the cluster without
POSTGRES_USER=identity ...
##[error]bin/prime exited 1 — the gate is red
```

## Cause 1 (the CI red): the service container made the suite role a superuser

The service container set `POSTGRES_USER=identity`, so `identity` is the
cluster's bootstrap superuser (`rolsuper=t, rolbypassrls=t`, confirmed by
query). `bin/prime` runs `bin/provision-testdb`, whose m158 refusal fires on
exactly that — correctly: a superuser bypasses RLS even with FORCE, so a suite
run as one proves nothing about the tenancy boundary. The refusal is the
property; the container was the defect. The m156 report already prescribed this
remediation and CI was never updated to match.

Fix (commit `b39f6ff`): the container bootstraps only superuser `postgres`; a
new step provisions `identity` + `identity_app` as NOSUPERUSER login roles and
the `identity` database they own before `goose up`; new job env
`TEST_DATABASE_ADMIN_URL` (superuser, provisioning only); `bin/rollback`
connects as the superuser (it needs CREATEDB/CREATEROLE the suite role lacks).
`internal/platform/ci/rollback_test.go` now derives the `_app` role from the
suite DSN's user instead of `POSTGRES_USER`, which described the old broken
coincidence. No tolerance was added: the refusal is untouched.

## Cause 2 (found by the local replication): `bin/rollback` kept the password in the caller

`CALLER="${URL#*://}"; CALLER="${CALLER%%@*}"` leaves `user:password`, so the
script provisioned a quoted colon-named `"postgres:postgres_app"` role and
00016 died with `postgres_app is not a LOGIN role`. The old CI shape masked it:
`identity_app` already existed from the workflow step, so the bogus role was
created and dropped every run, silently. Fix (commit `0f21e05`):
`CALLER="${CALLER%%:*}"`, plus a guard asserting the strip.

## Local reproduction (exact commands)

Repro of the CI red, on the unmodified tree, against a CI-shaped container:

```
docker run -d --name ci-shape-postgres -e POSTGRES_USER=identity \
  -e POSTGRES_PASSWORD=identity -e POSTGRES_DB=identity -p 5433:5432 postgres:17-alpine
bin/provision-testdb 'postgres://identity:identity@127.0.0.1:5433/identity?sslmode=disable'
# → "role identity is superuser or BYPASSRLS …", exit 1 (byte-identical to CI)
```

Full job replication after the fix (`/tmp/gate-roll-c5/ci-repro.sh`: pinned
goose install → new provision step → `goose up` + `status` → rollback as
superuser → `bin/prime`), against a fresh `POSTGRES_USER=postgres` container
with `TEST_DATABASE_URL`/`DATABASE_URL` pointing at `identity:identity@…:5433`
and `TEST_DATABASE_ADMIN_URL` at the superuser:

```
G=/tmp/gate-roll-c5; $G/ci-repro.sh   # exit=<see below>
```

## Controls

- GREEN (real tree, CI-shaped env): full replication above — verdict below.
- GREEN (guards): `go test -count=1 ./internal/platform/ci/` → ok.
- RED (live CI on master): run 38578538549, `bin/prime exited 1`, no suite.log.
- RED (repro on old tree): provision refusal reproduced locally, exit 1.
- RED (guard follows the DSN): DSN user renamed to `suite` without new
  provisioning → both ordering tests fail; restored → green.
- RED (rollback strip): old `bin/rollback` fails the new `%%:*` assertion;
  fixed passes. The pre-fix replication failing at 00016 is the live control.
- No tolerance added, so the tolerance-red control is N/A (refusal untouched).
- `gofmt -l`, `go vet ./internal/platform/ci/`, `bash -n` on both scripts: clean.
- INDEPENDENT (not mine to run): pushed CI `gate` job — pending manager push.

## Gate verdict (local, CI-shaped)

GREEN. Command (from the worktree root, against a fresh
`postgres:17-alpine` container started with `POSTGRES_USER=postgres`,
`POSTGRES_PASSWORD=postgres`, `POSTGRES_DB=postgres` on port 5433):

```
export TEST_DATABASE_URL='postgres://identity:identity@127.0.0.1:5433/identity?sslmode=disable'
export DATABASE_URL='postgres://identity:identity@127.0.0.1:5433/identity?sslmode=disable'
export TEST_DATABASE_ADMIN_URL='postgres://postgres:postgres@127.0.0.1:5433/postgres?sslmode=disable'
go install github.com/pressly/goose/v3/cmd/goose@v3.28.0
<new provision step> ; goose -dir migrations postgres "$DATABASE_URL" up
goose -dir migrations postgres "$DATABASE_URL" status
IDENTITY_ROLLBACK_URL="$TEST_DATABASE_ADMIN_URL" IDENTITY_ROLLBACK_REQUIRED=1 ./bin/rollback
./bin/prime                                            # exit 0
```

Result (`/tmp/gate-roll-c5/ci-repro.log`): 32 `ok` package lines, 0 FAIL,
0 `--- SKIP`, 0 `(cached)`; rollback clean over all 35 migrations down and
forward; `internal/platform/ci`, `internal/migrate` and `internal/outbox` all
ok. The single `internal/outbox` failure in the intermediate run did not recur
(5x package-only green plus this full green): a load flake in an in-memory
publish/cancel race, unrelated to the topology — its only DB touch is test
setup.

Final cluster shape: `identity f/f/t/t/t`, `identity_app f/f/f/f/t`
(super/bypass/createdb/createrole/login) — the fleet topology, still inside
the m158 refusal's guard (superuser/BYPASSRLS only).
