# Migrations

Schema for `identity`, as goose SQL files. One migration per file, named
`NNNNN_snake_case_description.sql`, applied in filename order.

`goose` is a **command line tool** and is not installed into the image. The
**library** it ships (`github.com/pressly/goose/v3`, pinned to the same
`v3.28.0` the CLI is) is linked into the `identity` binary, so the image can
apply these files with no shell, no `psql` and no CLI — see "The image migrates
itself" below. The CLI remains the thing a developer and CI use; the two are
the same engine at the same version, sharing one `goose_db_version` table.

## The convention

Every migration file carries goose's annotations. `-- +goose Up` and
`-- +goose Down` delimit the two directions, and statements that goose's parser
would misread are wrapped in `StatementBegin`/`StatementEnd`:

```sql
-- +goose Up
CREATE TABLE accounts (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE accounts;

-- +goose StatementBegin
CREATE INDEX CONCURRENTLY accounts_name_idx ON accounts (name);
-- +goose StatementEnd
```

`CREATE INDEX CONCURRENTLY`, `DO $$ ... $$` and any statement containing a
semicolon inside a string or dollar-quoted body **must** be wrapped in
`StatementBegin`/`StatementEnd`, or goose will split it into fragments and
execute half of it.

Rules that matter for review:

- **`Down` is required.** If a migration cannot be reversed, say why in a
  comment next to an empty `Down` rather than omitting the section. A file with
  no `Down` cannot be rolled back and will block an incident.
- **No edits to an applied migration.** The table records version, timestamp
  and a checksum. Changing a file that has already run somewhere makes goose
  refuse to apply anything after it. Write a new migration instead.
- **One logical change per file.** Never bundle "add users" with "add
  accounts", even in a packet where they are obviously related. They roll back
  separately or not at all.
- **No data backfill in a migration that also changes schema.** A backfill that
  touches every row locks the table. Schema first, backfill as a separate
  migration with a batched `UPDATE`.

## The image migrates itself

`identity migrate` applies everything pending and exits. It needs nothing but
`DATABASE_URL`:

```sh
docker run --rm -e DATABASE_URL="$DATABASE_URL" identity migrate
```

The files are embedded in the binary (`migrations/embed.go`, `//go:embed *.sql`)
and applied by the goose library, so the runtime image — distroless, no shell,
no `psql` — is the only artifact involved. `/app/bin/migrate` is the same binary
under a second name (a symlink to `/app/service`), because that is the path kit's
substrate already invokes for identity; the binary dispatches on the name it was
called under. `identity serve` is the default and is what a replica boots into:
**the service still never migrates at boot**, which is the rule above and not a
detail — a rolling deploy with two versions live would race, and a failed
migration would take the process down with it.

The substrate's migrations step is what runs it in a cluster, as its OWNER role,
in the same image the Deployment runs — one one-shot `kubectl run … -- /app/bin/migrate`
per schema-owning service. Re-running it is a no-op: goose records what it has
applied, so a second run has nothing pending.

**`bin/migrate` (the `psql` loop) and `identity migrate` are two front ends on
one engine's worth of semantics, but only one of them records versions.** The
`psql` loop exists for a machine with no goose installed and applies the Up
section of every file without writing `goose_db_version` — so a database it built
is one goose will try to apply from `00001` all over again. Use `goose` (or
`identity migrate`) for anything a deployed box will later touch;
`bin/migrate` is for a throwaway dev database. This is the reason the `psql` path
is not what the substrate invokes.

## Running migrations

`DATABASE_URL` must be exported. In dev that is the compose service; in prod it
comes from the same secret the service reads.

```sh
goose -dir migrations postgres "$DATABASE_URL" status    # what has been applied
goose -dir migrations postgres "$DATABASE_URL" up        # apply everything pending
goose -dir migrations postgres "$DATABASE_URL" up-by-one  # one at a time, for prod
goose -dir migrations postgres "$DATABASE_URL" down      # roll back the last one
goose -dir migrations postgres "$DATABASE_URL" create add_accounts
```

The `create` subcommand scaffolds a correctly named and annotated file; edit the
statements into the body. It numbers itself from the highest existing file.

Install it with `mise` (see the root `mise.toml`) or
`go install github.com/pressly/goose/v3/cmd/goose@latest`.

**The gate installs the pinned version for you.** `bin/prime` runs
`bin/provision-testdb`, which resolves goose and, if no `v3.28.0` is found,
installs exactly that version into `$(go env GOPATH)/bin` — never `@latest`,
for the reason below. You do not need goose on your PATH to run the gate.

## Dev

The compose stack in `docker-compose.yml` starts `postgres:17-alpine` and
waits for it to report healthy, so the database is accepting connections before
the service comes up:

```sh
docker compose up -d --wait postgres
docker compose exec postgres pg_isready -U identity
```

**The gate provisions the test database itself.** When `TEST_DATABASE_URL`
names a local host, `bin/prime` runs `bin/provision-testdb` before the suite:
it creates the owner role, the app role and the database if they are absent,
applies every migration with the pinned goose, and runs
`GRANT identity_app TO identity` — the membership the tenancy tests' `SET ROLE`
needs. It is idempotent, so a second run changes nothing. So the inner loop is:

```sh
TEST_DATABASE_URL="$DATABASE_URL" ./bin/prime            # full gate, provisions first
TEST_DATABASE_URL="$DATABASE_URL" ./bin/prime --fast     # non-db tier, no database
```

A DSN naming a non-local host is refused, never provisioned: the gate must
never create something on a database it was not pointed at. And provisioning
preserves the owner/app-role split — it does not "fix" a permission problem by
making the suite run as the owner, which would silently disable every
row-level-security policy in `00016`.

`goose up` is a **deploy step and is above the suite**, never part of the same
command. A suite run against an unmigrated database fails on
`relation "public.users" does not exist` — loud, but it reads like a bug in the
code rather than a pipeline that is wired wrong, and that is the whole reason the
two are separate commands. [CI](../.github/workflows/ci.yml) runs them as two
steps in that order and asserts the order. `bin/provision-testdb` is the same
ordering, inside the gate, for the test database.

**`TEST_DATABASE_URL` IS THE OWNER, and the pool under test is not.** One
variable, two roles, because no single role can both apply migrations and seed
fixtures the application is then supposed to be unable to see. `dbtest.Pool`
connects as `<that user>_app` — kit's rule, and the same one `protect_table`
defaults to — so a suite run against an owner DSN exercises the role production
runs under, with production's policies on. Anything a test does as DDL or
`TRUNCATE` (a `DROP TABLE` to force a 500, a `CREATE TRIGGER` to fail an audit
write) goes through `dbtest.OwnerPool` or the owner half of
`dbtest.SchemaWithOwner`, because those are ownership privileges and
`identity_app` must not have them.

`docker-compose.yml` publishes Postgres on host port 5432. If something already
listens there — a local Postgres install is the common case — the compose port
bind fails, or a host-side DSN silently reaches the *other* server and fails with
`role "identity" does not exist`. Either way the fix is the same: point
`DATABASE_URL` and `TEST_DATABASE_URL` at the port the compose stack actually
got, not at the one you assumed.

`TEST_DATABASE_URL` gates **most of the suite**, not two tests: eleven of the
fifteen packages open a pool. Without it they skip, and
`internal/mfa`'s `TestTheDatabaseTierActuallyRan` fails rather than skips, so
`go test ./...` is red without it. That is deliberate — see the Testing section
of the [README](../README.md).

## Prod

Migrations are a **deploy step, not a service step**. The service never migrates
itself on boot: a rolling deploy with two versions live would race, and a failed
migration would take the process down with it.

1. Run `goose ... up-by-one` as a single ordered job before the new image rolls
   out. Add each migration to a later release than the code that first needs it,
   so the currently-deployed version still works against the old and the new
   schema. Expand the contract, backfill, then contract in a subsequent release.
2. Fail the deploy on a non-zero exit. A migration that half-applied is worse
   than one that did not run, and goose stops at the first failure.
3. Take a backup first. A `Down` that is exercised in an incident is a first
   resort, not a plan.
4. Watch lock waits. An `ACCESS EXCLUSIVE` lock taken by a long-running `ALTER`
   blocks every query behind it, and the service's readiness probe will not save
   you: it only knows whether it can connect.

## Where the schema is going

Not written yet. Accounts and memberships, OIDC, MFA and API tokens have all
landed; each arrived as its own numbered migration with the tests that prove it
(PLAN.md §3). `00014` (address verification) and `00015` (`recovery_tokens`) are
the recovery packet's two, and the next thing this schema will want is a sweep job
for expired rows — `recovery_tokens_expires_at_idx` already exists so it is one
statement, and the read queries filter on `expires_at` in the meantime so an
unswept row is harmless.
