# REPORT — roll-c5-identity-migrate

**The packet.** A box that finishes the substrate booted `identity` against an
empty schema (`relation "outbox_events" does not exist`, forever), because the
substrate's new migrations step (kit `ba95f4d`, `install_migrations`) runs each
schema-owning service's migrate entrypoint **in that service's own image** — and
identity's image is `gcr.io/distroless/static-debian12:nonroot`: no shell, no
`psql`, no `bin/migrate`, no `migrations/`. This is the other half: the image can
migrate its own database.

Branch `roll/c5-identity-migrate`, worktree
`/Users/kaka/Code/any/moon/wt/roll-c5-identity-migrate`, cut from current master.
Nothing pushed, nothing merged, no other repository touched. The worktree held no
uncommitted partial work from the previous attempt (`git status` was clean).

---

## 1. The mechanism

**The service binary applies its own embedded schema: `identity migrate`.**

kit's step invokes identity's migrate entrypoint at `/app/bin/migrate` with no
override, in the Deployment's own image, with `DATABASE_URL` set to the OWNER
DSN. So the shape is exactly what kit's `migration_command_for` already assumes,
and the report's §8(b) — the option it argued for over shipping `psql`:

| piece | file | what it is |
| --- | --- | --- |
| the files, in the binary | `migrations/embed.go` | `//go:embed *.sql` — a Go package in the migrations directory, because `go:embed` cannot reach above its own package |
| the applier | `internal/migrate/migrate.go` | `Run(ctx, dsn, fsys, logger)` over `goose.NewProvider` |
| the subcommand | `cmd/identity/main.go` | `identity migrate`, and argv[0] dispatch so the same binary at `/app/bin/migrate` is the migrator |
| the path in the image | `Dockerfile` | `COPY --from=build /out/service /app/bin/migrate` — one `go build`, two names |

### Why the goose *library* and not a second applier

`goose` is pinned at **v3.28.0**, the version `bin/provision-testdb`,
`ci.yml` and the README's commands already use, and it is now a **direct
dependency** linked into the binary. The reason is that this repository has
already paid for the alternative: `bin/migrate` was the second implementation
of goose's semantics — it fed `psql` both the Up and the Down section of every
file, applied each migration and then reverted it, printed `migrations applied`
and exited **zero** (identity-31, guarded now by
`internal/platform/ci/migrate_test.go`). Writing a *third* applier and a second
version table is the same class of bug with a new way to be wrong.

One engine, at one version, means one `goose_db_version` table describes the
schema in CI, on a developer's machine and on the box — and it is why CI's
`goose up` and this subcommand are the same operation rather than two that
usually agree.

**What this costs, stated rather than hidden:** four modules
(`mfridman/interpolate`, `sethvargo/go-retry`, `go.uber.org/multierr`) plus the
`grpc`/`genproto` patch bump goose's own `go.mod` requires. It does **not** bring
goose's other dialects — the root package imports no driver, so ClickHouse,
MySQL, MSSQL and SQLite are never built — and
`internal/platform/ci/goose_deps_test.go` holds that on
`go list -deps ./cmd/identity` in both directions, so it is a check rather than a
sentence in the README.

### Why argv[0] dispatch

`kubectl run … --command -- /app/bin/migrate` gives the process argv[0] =
`/app/bin/migrate`, so the binary can tell the two jobs apart by the name it was
started under. `identity migrate` and `identity serve` are also spelled out and
tested, and an unrecognised non-flag argument is a **usage error, not a silent
serve** — a typo that started a server would look like success until somebody
asked why the schema was still empty.

### What did NOT change

**A replica still never migrates at boot.** Nothing in the migrate path is called
from `run()`. Migrating stays a deploy step; the process that applies it starts,
applies and exits, which is what the one-shot Job is.

### The migration entrypoint is `/app/bin/migrate`, and it is a second COPY

The runtime stage is distroless, so the path cannot be a script and there is no
`ln` or `cp` in it. A symlink made in the builder **does not survive**:

```
FROM busybox AS build
RUN mkdir -p /out/bin && ln -s /bin/busybox /out/bin/migrate
FROM busybox
COPY --from=build /out/bin/migrate /app/bin/migrate
RUN ls -l /app/bin/migrate
-rwxr-xr-x 1 root root 1185328 /app/bin/migrate      # a regular file, not a link
```

`COPY --from=<stage>` dereferences it (measured, Docker 29.8.2), so the honest
form is a second `COPY` of the same artifact from the same build stage: one
`go build`, two names, and the COPY is what makes them the same bytes.

---

## 2. The image line for the substrate

Nothing to configure — the default is already right:

```sh
kubectl run kit-migrate-identity -n identity --restart=Never \
  --image=ghcr.io/cafaye/identity:0.1.0 \
  --env=DATABASE_URL='postgres://identity:<owner-password>@…/identity?sslmode=secure' \
  --command -- /app/bin/migrate
```

which is `install_migrations` verbatim for identity: the image is read back from
the Deployment, `migration_env_args_for identity` emits the one `--env`, and
`migration_command_for identity` prints `/app/bin/migrate` with no override set.

If the fleet prefers the explicit spelling, `KIT_SUBSTRATE_MIGRATE_CMD_identity='/app/service migrate'`
also works — the same call, reached by the argument instead of the name — and
that is the only change it would need.

---

## 3. Test evidence

### The idempotency and the failure, against a real Postgres

`internal/migrate` creates and drops a database of its own per test — a private
`schema` would be a second, quieter schema model (`public.users`,
`cafaye.protect_table`) and would start with the version table already in it,
proving a replay rather than an apply.

```
$ export TEST_DATABASE_URL="postgres://identity:identity@localhost:5432/identity?sslmode=disable"
$ go test -count=1 -v -run 'TestASecondRunAppliesNothing|TestAMigrationThatFails|TestRunRefusesWithNoDSN|TestTheDatabaseTier' ./internal/migrate/
=== RUN   TestRunRefusesWithNoDSN
--- PASS: TestRunRefusesWithNoDSN (0.00s)
=== RUN   TestASecondRunAppliesNothingAndALaterFileIsTheOnlyThingItApplies
    migrate_test.go:77: the first run applied 35 migrations, 00001_init.sql … 00035_oidc_refresh_tokens.sql
--- PASS: TestASecondRunAppliesNothingAndALaterFileIsTheOnlyThingItApplies (0.33s)
=== RUN   TestAMigrationThatFailsIsNamedAndTheRunStopsThere
=== RUN   TestAMigrationThatFailsIsNamedAndTheRunStopsThere/00036_deliberately_broken.sql
    migrate_test.go:153: the failure, as the substrate's `kubectl logs` would show it: 00036_deliberately_broken.sql failed: partial migration error (type:sql,version:36): ERROR: syntax error at or near "is" (SQLSTATE 42601)
=== RUN   TestAMigrationThatFailsIsNamedAndTheRunStopsThere/00036_a_different_broken_name.sql
    migrate_test.go:153: the failure, as the substrate's `kubectl logs` would show it: 00036_a_different_broken_name.sql failed: partial migration error (type:sql,version:36): ERROR: syntax error at or near "is" (SQLSTATE 42601)
--- PASS: TestAMigrationThatFailsIsNamedAndTheRunStopsThere (0.66s)
    --- PASS: TestAMigrationThatFailsIsNamedAndTheRunStopsThere/00036_deliberately_broken.sql (0.29s)
    --- PASS: TestAMigrationThatFailsIsNamedAndTheRunStopsThere/00036_a_different_broken_name.sql (0.19s)
--- PASS: TestTheDatabaseTierActuallyRan (0.02s)
PASS
ok  	github.com/cafaye/identity/internal/migrate	1.786s
```

### The controls, and what each one makes the assertion mean

| assertion | the control that makes it non-vacuous |
| --- | --- |
| the second run applies **nothing** | the FIRST run must apply all 35, or "nothing the second time" is also what a Run that applies nothing ever does |
| "nothing pending" ≠ "cannot see new files" | a THIRD run, same database, same call, told about **one** more file, must apply **exactly that file** — `99999_a_later_migration.sql` |
| a broken migration is **named** | run twice under two **different** filenames, so the name cannot be a hardcoded string |
| the run **stops** at the failure | a valid `00037_never_reached.sql` after it, and the assertion is made by asking the DATABASE (`information_schema.tables`), not by reading the error |
| the failure is the injected file | a control database, same harness, same migrations, no injection: it applies all 35 and the marker table does not exist |
| the embed has not narrowed | the embedded set is compared with the directory's set in both directions || every embedded file will run | goose collects **non-strictly** (v3.28.0 `provider.go:122`, `strict=false`), so a misnamed `.sql` is skipped in silence; the naming convention is therefore asserted on the artifact |
| the closure carries no dialect driver | pgx and goose must be PRESENT, or "no ClickHouse/MySQL/…" passes over an empty list |
| the migration path is the one kit runs | `argv[0] = /app/bin/migrate` is a table case, and the Dockerfile's `COPY` to that path is asserted — the check that would have caught this packet's own bug, below |

`TestTheDatabaseTierActuallyRan` is a **read**: it asks the shared suite database
for its recorded version rather than migrating it. The other tests migrate
databases of their own, so the file never mutates a database another package is
testing against at the same moment.

### The bug this packet shipped and then caught

The first version of `migrations/embed.go` described `//go:embed *.sql` in its
doc comment and **never wrote the directive**. `embed.FS` is then a legal, empty
filesystem, and the first test run said `reading the migrations: no migrations
found` — which is exactly what a box would have reported, permanently. The
Dockerfile/embed assertion added afterwards is the check that makes it a red
build rather than a sentence.

### The image itself, built and run

`docker build -t identity-c5-migrate .` succeeded, and the built image was then
used as the substrate would use it — as a one-shot process whose argv[0] is the
path kit invokes — against a database of its own:

```
$ docker run --rm --entrypoint /app/bin/migrate \
    -e DATABASE_URL="postgres://identity:…@host.docker.internal:5432/identity_image_check?sslmode=disable" \
    identity-c5-migrate
time=… level=INFO msg="applying the embedded migrations" command=migrate
time=… level=INFO msg="migrations applied" count=35 last=00035_oidc_refresh_tokens.sql
                                                        # exit 0

$ psql … -tAc "select (select count(*) from information_schema.tables where table_schema='public'),
                      (select max(version_id) from goose_db_version),
                      (select count(*) from goose_db_version where is_applied)"
23|35|36                       # 23 tables, at version 35, 36 rows (35 + goose's version-0 row)

$ … identity-c5-migrate      # RUN 2, same database, same image
time=… level=INFO msg="already at the embedded schema; nothing to apply"
                                                        # exit 0, nothing applied

$ docker run --rm --entrypoint /app/service -e DATABASE_URL=… identity-c5-migrate migrate
time=… level=INFO msg="already at the embedded schema; nothing to apply"
                                                        # exit 0 — argv[1] spelling, same call
```

That is the distroless image, with no shell and no `psql`, applying its own
schema and then declining to re-apply it. The scratch database was dropped and
the image removed afterwards; nothing was left behind on the cluster.

---

## 4. The gate

```sh
$ export TEST_DATABASE_URL="postgres://identity:identity@localhost:5432/identity?sslmode=disable"
$ export TEST_DATABASE_ADMIN_URL="postgres://cafaye:cafaye@localhost:5432/postgres?sslmode=disable"
$ ./bin/prime
provision-testdb: using TEST_DATABASE_ADMIN_URL as the admin connection
provision-testdb: applying migrations to identity
2026/10/14 00:27:10 goose: no migrations to run. current version: 35
provision-testdb: granting identity_app to identity
NOTICE:  role "identity" has already been granted membership in role "identity_app" by role "postgres"
provision-testdb: provisioned identity (owner identity, app role identity_app)
ok  	github.com/cafaye/identity/client	6.253s
?   	github.com/cafaye/identity/client/generated	[no test files]
ok  	github.com/cafaye/identity/cmd/identity	13.432s
ok  	github.com/cafaye/identity/cmd/identity-staff	2.143s
ok  	github.com/cafaye/identity/internal/accounts	17.004s
ok  	github.com/cafaye/identity/internal/admin	5.533s
ok  	github.com/cafaye/identity/internal/agents	7.519s
ok  	github.com/cafaye/identity/internal/apikeys	10.939s
ok  	github.com/cafaye/identity/internal/auth	8.946s
ok  	github.com/cafaye/identity/internal/chart	0.607s
ok  	github.com/cafaye/identity/internal/config	0.591s
ok  	github.com/cafaye/identity/internal/courier	1.137s
ok  	github.com/cafaye/identity/internal/deletion	1.041s
ok  	github.com/cafaye/identity/internal/httpapi	43.170s
ok  	github.com/cafaye/identity/internal/mfa	16.564s
ok  	github.com/cafaye/identity/internal/migrate	13.539s
ok  	github.com/cafaye/identity/internal/oauth	2.783s
ok  	github.com/cafaye/identity/internal/oidc	3.951s
ok  	github.com/cafaye/identity/internal/outbox	15.211s
ok  	github.com/cafaye/identity/internal/platform/ci	8.061s
ok  	github.com/cafaye/identity/internal/platform/clock	0.534s
ok  	github.com/cafaye/identity/internal/platform/db	0.600s
?   	github.com/cafaye/identity/internal/platform/dbtest	[no test files]
ok  	github.com/cafaye/identity/internal/platform/id	0.933s
ok  	github.com/cafaye/identity/internal/platform/oauthtest	0.966s
?   	github.com/cafaye/identity/internal/ratelimit	[no test files]
ok  	github.com/cafaye/identity/internal/recovery	9.592s
ok  	github.com/cafaye/identity/internal/redirect	0.534s
ok  	github.com/cafaye/identity/internal/sessions	0.716s
ok  	github.com/cafaye/identity/internal/signup	0.530s
ok  	github.com/cafaye/identity/internal/telemetry	0.668s
ok  	github.com/cafaye/identity/internal/tenancy	1.368s
ok  	github.com/cafaye/identity/internal/useraudit	3.412s
ok  	github.com/cafaye/identity/internal/users	6.474s
ok  	github.com/cafaye/identity/migrations	0.267s
                                                        # exit 0
```

`TEST_DATABASE_ADMIN_URL` is the manager's local convention and it is **required
here**, not optional: `bin/provision-testdb` ends with
`GRANT identity_app TO identity`, and on this cluster the `identity` role does
not hold that grant with ADMIN option:

```
ERROR:  permission denied to grant role "identity_app"
DETAIL:  Only roles with the ADMIN option on role "identity_app" may grant this role.
```

The first gate run failed on exactly that line; `cafaye` (superuser) as the admin
connection provisions it as CI's superuser DSN does.

```
$ gofmt -l .            # printed nothing
$ go vet ./...          # clean, exit 0
$ IDENTITY_ROLLBACK_URL="postgres://identity:identity@localhost:5432/identity?sslmode=disable" ./bin/rollback
rollback: 35 migrations, each rolled back and re-applied with zero leftovers
                                                        # exit 0 — no migration file changed
$ go test -race -count=1 -p 4 ./...                     # the fourth gate
ok  	github.com/cafaye/identity/internal/migrate	…
ok  	github.com/cafaye/identity/migrations	1.618s
ok  	github.com/cafaye/identity/internal/tenancy	3.076s
ok  	github.com/cafaye/identity/internal/users	2.855s
                                                        # 32 packages ok, exit 0
$ golangci-lint run ./internal/migrate/... ./migrations/... ./cmd/identity/... ./internal/platform/ci/...
9 issues:                        # ALL pre-existing, none in a file this packet added
* errcheck: 9                    # (os.Unsetenv/Close/Remove in test files from earlier packets)
```

The `bin/prime` output quoted above is the first green run. The branch head
(`0f55d25`, after the sentinel became a read rather than a migration) was run
again with the same two variables and the same command: **exit 0, 32 packages
`ok`**, including `internal/migrate 23.709s`, `internal/platform/ci 6.198s`,
`cmd/identity 11.439s` and `migrations 0.258s` — the only difference from the
block above being the timings.

---

## 5. The one residual risk, and it is the live box's, not this packet's

**A database whose schema was applied out-of-band has no `goose_db_version`, and
the Job will fail on it.** kit's report §3 discloses that the live box's
`identity` schema was applied by hand — 22 tables owned by `identity`, **no
`goose_db_version` table**, the signature of `bin/migrate`'s `psql` loop. On that
box the migrate Job will now fail at `00001` with `relation "users" already
exists`, because goose will correctly believe nothing has been applied.

That is not a defect in the migrator: *no* versioned tool can distinguish "an
empty database" from "a populated database nobody recorded". It is the exact cost
of the out-of-band apply, and there are two ways out, both one-time and both
outside this packet: **stamp the baseline** — create goose's own table and record
the versions whose objects are already present
(`goose_db_version(id, version_id, is_applied, tstamp)`, one applied row per
version up to 35, plus goose's `version_id = 0` row) — or **rebuild** on a box
where the schema holds nothing worth keeping. On a **fresh** box, which is what
the packet is about and what the Job is for, the apply is clean, as §3's evidence
shows.

`bin/migrate`'s `psql` loop not writing a version table is written down in
migrations/README.md as the reason to use `goose` or `identity migrate` for
anything a deployed box will later touch.

## 6. What I deliberately did NOT do

- **Did not touch `cafaye/kit` or any other repository.** The substrate's step
  needs no change: its identity default is the path this image now ships.
- **Did not write a shell-based migrate wrapper, and did not add `psql` to the
  image.** No shell exists to run a wrapper in, and no `psql` exists to run: that
  is the whole reason for the embed.
- **Did not ship a second image variant.** Report §8 prefers one; a `--platform`
  or `migrate`-tagged image would be a second thing to keep in step with the
  Deployment's.
- **Did not reimplement goose's SQL parsing, version table or checksums.** See §1.
- **Did not make `bin/migrate` (the `psql` loop) call the new subcommand, and did
  not delete `bin/migrate` or `bin/migration-up-section`.** They are the
  no-goose-installed developer path and `internal/platform/ci/migrate_test.go`
  is the regression guard for identity-31; deleting either is a separate packet
  with a separate argument. The one real consequence is written down in
  migrations/README.md: the `psql` loop writes **no** `goose_db_version`, so a
  database it built is one goose will try to apply from `00001` again — use
  `goose` or `identity migrate` for anything a deployed box will later touch.
- **Did not add a `Down`/rollback path to the subcommand.** The substrate's job
  is forward-only, and `bin/rollback` is the repository's rollback check.
- **Did not add `identity migrate` to the README's HTTP endpoint tables or the
  OpenAPI documents** — it is not a route, and
  `TestEveryServedRouteIsDocumentedOrNamed` reads the router, which this does not
  touch.
- **Did not run `bin/rollback`** unless reported below: it is a CI step that
  builds its own scratch database, and this packet changes no `migrations/*.sql`
  and no `psql`/goose invocation it uses.
