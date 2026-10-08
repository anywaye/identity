# m158 — Provisioning rejects unsafe roles before side effects

## Verdict

**Harness ordering defect corrected.** `REPORT-m156-identity-fresh-gate-rls-bypass.md` diagnosed the gate failure correctly (bootstrap superuser via `postgres:17-alpine` + `POSTGRES_USER=identity` ⇒ `rolsuper=t, rolbypassrls=t` ⇒ RLS bypass even with `FORCE`) and added a refusal in `bin/provision-testdb` with the correct actionable error text. That refusal sat **after** `CREATE ROLE`, `CREATE DATABASE`, `goose up`, and `GRANT` (lines 261–280 pre-fix). Running the script against the unsafe cluster therefore minted a disposable DB, applied 30 migrations, and issued the grant before printing the refusal — a post-mutation failure.

This packet **moves** the same two `rolsuper`/`rolbypassrls` checks to the earliest point after the admin connection is resolved and verified, before any mutation, preserving the exact error text m156 added. A new static-order regression in `internal/platform/ci/provision_testdb_test.go` proves the refusal precedes every side effect and that no trailing check remains after `GRANT`. No product RLS policy, migration, or tenancy assertion was weakened.

## What changed

### `bin/provision-testdb`

* Before: identifier validation → `role_exists` → `CREATE ROLE owner` → `CREATE ROLE app` → `CREATE DATABASE` → `goose up` → `GRANT` → **refusal** → `log provisioned`.
* After: identifier validation → **`app_role` derived, then superuser/BYPASSRLS refusal for `$owner` and `$app_role`** → `role_exists` → `CREATE ROLE` → `CREATE DATABASE` → `goose up` → `GRANT` → `log provisioned`.

The refusal block (header comment plus the two `select rolsuper`/`rolbypassrls` queries and their `fail` messages) is byte-identical to m156's text — only its position moved, with an added sentence in the header noting that the m156 position was post-mutation and this one is pre-mutation (m158). The late block after `GRANT` was deleted; there is no duplicate.

Placement rationale:

* After the admin DSN is chosen and verified (`select rolsuper or (rolcreaterole and rolcreatedb) … | grep -q t`, stderr visible) — so the `psql` the check runs against is known to be a superuser-capable connection.
* After identifier validation (`^[a-z_][a-z0-9_]*$`) — so the role names interpolated into `where rolname = '$owner'` are safe.
* Before any `CREATE ROLE`/`CREATE DATABASE`/migration/`GRANT` — so a run against an unsafe cluster fails in seconds with the actionable message and creates **no** disposable DB on `identity_gate_m147_clean`'s cluster or on a uniquely-named test DB.

An absent role yields zero rows (`"" != "t"`), so the check passes on a clean cluster and a fresh `identity_app` that does not yet exist is not spuriously refused; only a pre-existing superuser/BYPASSRLS role fails. Newly created roles are `NOSUPERUSER NOBYPASSRLS` by default, so a second post-creation check would be redundant.

### `internal/platform/ci/provision_testdb_test.go`

* New `TestProvisionTestDBUnsafeRoleRefusalIsBeforeAnySideEffect`:
  * Reads `bin/provision-testdb` as text (same helper as the other provisioning tests).
  * Locates the two refusal queries (`select rolsuper from pg_roles where rolname = '$owner'` / `'$app_role'`), the admin verification probe (`rolsuper or (rolcreaterole and rolcreatedb)`), and the five side effects (`CREATE ROLE $owner`, `CREATE ROLE $app_role`, `CREATE DATABASE $dbname`, `"$goose_bin" -dir "$ROOT/migrations" postgres "$dsn" up`, `GRANT $app_role TO $owner`).
  * Asserts `firstRefusal < firstSideEffect` and `lastRefusal < firstSideEffect`; asserts no `rolsuper`/`rolbypassrls` remains after `GRANT` (catches a duplicate early+late); asserts the five substrings of actionable error text m156 introduced are still present; asserts the refusal is after the admin verification probe.
  * Intended red on m156's tree (refusal at byte ~12566, first side effect `CREATE ROLE $owner` at ~10669) — verified red in Q1. Green after the move.

### Tenancy assertion

`internal/tenancy/tenancy_test.go:194-214` (`the owner and app roles are not superuser or BYPASSRLS`) is unchanged — the suite still diagnoses a superuser cluster at test time if provisioning were bypassed. No product code changed.

### `REPORT-m156-identity-fresh-gate-rls-bypass.md`

No wording correction was needed. The report already states the fix as `bin/provision-testdb:258-278 — after GRANT, queries pg_roles…` — i.e. post-mutation — so it does **not** imply pre-mutation. The evidence of `rolsuper=t`, catalog `t/t`, and focused green/diagnostic tests remains valid and is referenced here as the diagnosis this packet re-positions.

## Verification (focused, as instructed; no full prime)

```
go test -run TestProvisionTestDBUnsafeRoleRefusalIsBeforeAnySideEffect ./internal/platform/ci/ -count=1 -v
# pre-fix → FAIL: refusal appears AFTER first side effect (CREATE ROLE $owner)
#             + still checks rolsuper after GRANT
# post-fix → PASS (0.00s)

go test ./internal/platform/ci/ -run ProvisionTestDB -count=1 -v
# TestProvisionTestDBRoleCreationUsesAStdinVariable: PASS
# TestProvisionTestDBOldFormIsRejectedAndTheNewFormDeliversAVariable: PASS
# TestProvisionTestDBUnsafeRoleRefusalIsBeforeAnySideEffect: PASS
# TestProvisionTestDBIsValidBash: PASS

bash -n bin/provision-testdb  # → ok
go vet ./internal/platform/ci/  # → no output
```

Full `mise exec -- ./bin/prime` was **not** run per brief (manager owns the merged gate). The gate's failing tier is the ordering proof above; the tenancy suite exercises the same superuser condition on a real DB when `TEST_DATABASE_URL` is set.

No disposable databases were created by this packet's script changes (the verification is a source walk, not a live `bin/provision-testdb` run). `site-launch-*` was not touched. No `bin/prime` was run.

## Commits in this packet

* `b3e089c` — `m158 Q1: red regression — unsafe-role refusal must precede any side effect` (failing test, no script change)
* `7c3b01e` — `m158: refuse superuser/BYPASSRLS before any provision side effect` (script reordered + report)

Worktree: `/Users/kaka/Code/any/moon/cafaye/identity-worker-system-admin`
Branch: `m147-identity-system-admin`
