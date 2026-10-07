# REPORT — identity-w77-gatefast

**Base commit:** `35a7bac` (Merge worker/identity-w65-mailcontract)
**Branch:** `worker/identity-w77-gatefast`
**Commits landed:** `2678fc7`, `63908d8`

## What the packet delivers

Two separable improvements to identity's gate:

1. **Self-provisioning test database** (`bin/provision-testdb`) — the gate
   provisions ANY database name in the DSN, creating the owner role, app
   role, database, all 27 migrations, and the `GRANT identity_app TO
   identity` the tenancy tests need. Idempotent. Refuses non-local hosts.

2. **`--fast` tier** (`bin/prime --fast`) — runs the complement of the
   declared db tier (13 packages) for the inner loop, skipping the 16
   database packages. An anti-rot check refuses to run if a pool-opening
   package is missing from the declared tier.

## The `--fast` tier

**What it runs:** the 13 packages that do not open a pool — `client`,
`internal/config`, `internal/platform/ci`, `internal/platform/clock`,
`internal/platform/db`, `internal/platform/id`, `internal/platform/oauthtest`,
`internal/redirect`, `internal/signup`, `internal/telemetry`,
`internal/tenancy`, plus `client/generated` (no test files).

**What it skips:** the 16 packages declared in `gate.yml`'s `#   db-tier: `
list — every package whose test binary links `internal/platform/dbtest`.

**The honest skip line** (captured from a real run):

```
FAST: 13 packages run, DB tier NOT run (16 packages). Use ./bin/prime for the full gate.
```

**The anti-rot check:** a package whose test binary links `internal/platform/dbtest`
but is NOT in the declared tier fails the gate, naming the package. Proven
red two ways: `internal/platform/ci/fast_tier_test.go` (declaration against
`go list`, both directions) and `TestTheFastTierRefusesAnUndeclaredPoolPackage`
(stubbed `go` that lies about one package's deps).

## Self-provisioning proof

**Non-default database name:** `identity_prov_probe` — pointed the DSN at a
database that did not exist, and the gate created it from scratch:

```
provision-testdb: creating database identity_prov_probe (owner identity)
provision-testdb: applying migrations to identity_prov_probe
2026/10/07 11:51:32 OK   00001_init.sql (2.62ms)
...
2026/10/07 11:51:32 OK   00027_user_preferences.sql (2.5ms)
2026/10/07 11:51:32 goose: successfully migrated database to version: 27
provision-testdb: granting identity_app to identity
provision-testdb: provisioned identity_prov_probe (owner identity, app role identity_app)
```

**Idempotency:** a second run against the same database is a no-op:

```
provision-testdb: applying migrations to identity_prov_probe
2026/10/07 11:51:47 goose: no migrations to run. current version: 27
provision-testdb: granting identity_app to identity
provision-testdb: provisioned identity_prov_probe (owner identity, app role identity_app)
```

## The gate run

**Command:**

```sh
TEST_DATABASE_URL='postgres://identity:cafaye@127.0.0.1:15527/identity_w77_gate?sslmode=disable' \
  mise exec -- ./bin/prime
```

**Exit code:** 0

**Package count:** 29 packages total — 27 with tests (all `ok`), 2 with no
test files (`client/generated`, `internal/platform/dbtest`).

**Provisioning:** the gate created `identity_w77_gate` from scratch, applied
all 27 migrations, granted the app role, then ran the full suite.

## Decision on `zzz_injected_failure_test.go`

**The file does not exist in the worktree.** The manager's `git status`
snapshot listed it as untracked (`??`), but it is not present. The
predecessor evidently deleted it before being killed — consistent with the
predecessor's log showing it concluded the test was "recursive and slow and
should be removed" (`TestTheFastTierRunsTheComplement` runs the real
`--fast` from within the fast tier).

**Decision: the file was a scratch proof that must not be committed, and it
is not in the tree.** Nothing to delete; nothing to commit. The anti-rot
check it was scratching around is instead proven by
`TestTheFastTierRefusesAnUndeclaredPoolPackage` in
`internal/platform/ci/fast_tier_test.go`, which uses a stubbed `go` rather
than recursing into the real gate.

## Files changed

| File | Change |
|------|--------|
| `bin/prime` | `--fast` flag, fast tier block, provision-testdb call |
| `gate.yml` | db-tier declaration (16 packages), `--fast` documentation |
| `bin/provision-testdb` | new — self-provisioning script |
| `internal/platform/ci/fast_tier_test.go` | new — declaration check + anti-rot proof |
| `migrations/README.md` | gate provisions the DB, pinned goose, inner loop |
