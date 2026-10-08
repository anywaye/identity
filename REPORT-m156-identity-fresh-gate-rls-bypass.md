# m156 — Fresh-database tenancy gate red: RLS bypass by bootstrap superuser, not stale volume

## Verdict

**Harness / provisioning defect, not a product regression.** `REPORT-m152-identity-tenancy-gate-red.md`'s stale-volume conclusion is superseded: the manager's “fully fresh” gate on `identity_gate_m147_clean` (new Docker volume `identity-gate-m147-data`, migrations 1–30, fresh DB) still fails with the **same** owner-role extra-row signature, and the catalog snapshot after failure already showed `relrowsecurity=t, relforcerowsecurity=t` on `api_keys` / `account_audit_log`. The tables **are** forced; the **role** bypasses the force.

Root cause is `identity` being the **bootstrap superuser** (`rolsuper=t, rolbypassrls=t`) in the gate's Postgres container `identity-gate-m147-postgres` (`postgres:17-alpine`, `POSTGRES_USER=identity`, `POSTGRES_DB=identity`, volume `identity-gate-m147-data`). PostgreSQL exempts `SUPERUSER`/`BYPASSRLS` from row-level security even with `FORCE ROW LEVEL SECURITY`; `FORCE` only binds the table *owner*, not a superuser. Kit's shared cluster (`kit-postgres:17`, `site-launch-postgres-1`) and the worker's local Homebrew Postgres both provision `identity` as `NOSUPERUSER NOBYPASSRLS` — where the suite is green. The bootstrap superuser **cannot be demoted** (`ALTER ROLE … NOSUPERUSER` → `permission denied … bootstrap superuser must have SUPERUSER`), so a new volume with the same `POSTGRES_USER=identity` reproduces the same failure forever.

Fixed in this packet so `./bin/prime` fails fast with an actionable message rather than with indirect extra-row assertions.

## Exact evidence

Gate container (the fresh-volume failure's cluster):

```
$ docker inspect identity-gate-m147-postgres --format '{{.Config.Image}}'  # postgres:17-alpine
$ docker inspect identity-gate-m147-postgres --format '{{json .Config.Env}}'
  ["POSTGRES_USER=identity","POSTGRES_DB=identity","POSTGRES_PASSWORD=cafaye",…]

$ docker exec identity-gate-m147-postgres psql -U identity -d identity_gate_m147_clean \
    -c "select rolname, rolsuper, rolbypassrls from pg_roles where rolname like 'identity%'"
   rolname    | rolsuper | rolbypassrls
  ------------+----------+--------------
   identity   | t        | t
   identity_app | f      | f

$ docker exec identity-gate-m147-postgres psql -U identity -d identity_gate_m147_clean \
    -c "select relname, relrowsecurity, relforcerowsecurity from pg_class where relname in ('api_keys','account_audit_log')"
   account_audit_log | t | t
   api_keys          | t | t

$ docker exec identity-gate-m147-postgres psql -U identity -d identity_gate_m147_clean \
    -c "select relname, polname, polroles::regrole[] from pg_policy join pg_class on pg_class.oid=polrelid where relname='api_keys'"
   api_keys | api_keys_cafaye_resolve | {identity,identity_app}  (etc — 4-5 policies, FORCED, present)
```

Correct clusters (where the suite is green):

```
$ docker exec site-launch-postgres-1 psql -U identity -c "select rolname, rolsuper, rolbypassrls from pg_roles where rolname='identity'"
  identity | f | f   # kit-postgres:17, KIT_POSTGRES_DATABASES=identity,courier, POSTGRES_USER=cafaye

$ psql "postgres://identity:cafaye@127.0.0.1:5432/identity?sslmode=disable" \
    -c "select rolname, rolsuper, rolbypassrls from pg_roles where rolname='identity'"
  identity | f | f   # local Homebrew PG17, kit's 10-cluster.sh NOSUPERUSER
```

The manager's snapshot (`relrowsecurity=t, relforcerowsecurity=t` on both tables, `accounts`/`users` intentionally unprotected) is therefore **not evidence of health** when the role is superuser.

## Reproduction (bounded, disposable DBs; manager DB never mutated)

Host `127.0.0.1:15527` is `identity-gate-m147-postgres` (Table above). No concurrent `go test`/`bin/prime` process was active (`pg_stat_activity` only the probe `psql`).

```sh
# 1. Disposable DB on the *gate* postgres (the buggy cluster, still superuser)
DISP=identity_m156_9b3b355b
GATE_DSN="postgres://identity:cafaye@127.0.0.1:15527/$DISP?sslmode=disable"
bin/provision-testdb "$GATE_DSN"   # → exit 0 pre-fix, goose 1-30, GRANT identity_app TO identity
# rolsuper=t, rolbypassrls=t confirmed; relrowsecurity=t relforcerowsecurity=t confirmed

TEST_DATABASE_URL="$GATE_DSN" go test -count=1 -run TestTenancy -v ./internal/tenancy/  # → exit 1
# credential_lookup_test.go:126: tenant A can see 2 api keys, want 1
# TestTenancyAccountIsolation: 4/24 failed (owner/no-identity 3 vs 0, owner/another-identity 3 vs 1, etc)
# TestTenancyIdentityOwnsItsFiveTables: every_declared_table PASSED, sweep PASSED, three-way_denial_as_identity_app PASSED
#                                      three-way_denial_as_identity FAILED (2 vs 0, 2 vs 1, 1 vs 0, 2 vs 1, trigger 23001)

# Bootstrap superuser cannot be demoted, even by a second superuser:
psql -U identity -d $DISP -c "ALTER ROLE identity NOSUPERUSER NOBYPASSRLS"
# → ERROR:  permission denied to alter role — The bootstrap superuser must have the SUPERUSER attribute.
docker exec identity-gate-m147-postgres psql -U identity -d postgres -c "CREATE ROLE cafaye LOGIN SUPERUSER PASSWORD 'cafaye'"
psql -U cafaye -d $DISP -c "ALTER ROLE identity NOSUPERUSER NOBYPASSRLS"
# → same ERROR — bootstrap protection is cluster-wide.

# 2. Disposable DB on the *local* correct cluster
LOCAL_DISP=identity_m156_local_a93481d4
LOCAL_DSN="postgres://identity:cafaye@127.0.0.1:5432/$LOCAL_DISP?sslmode=disable"
bin/provision-testdb "$LOCAL_DSN"   # → exit 0, identity f/f, relrowsecurity/force t/t
TEST_DATABASE_URL="$LOCAL_DSN" go test -count=1 -run TestTenancy -v ./internal/tenancy/  # → exit 0 (PASS, ok 0.624s)
# All three tenancy suites green; rolsuper f, rolbypassrls f.
```

The first run reproduces the manager's fresh-gate signature **verbatim** (owner extra rows + trigger instead of RLS denial, catalog still `t/t`, `identity_app` arm still green) on a *freshly provisioned* disposable DB on the same buggy container. The second run on a correctly provisioned cluster is green, as worker-owned tests were.

## Fix in this packet

* `bin/provision-testdb:258-278` — after `GRANT`, queries `pg_roles.rolsuper/rolbypassrls` for both `owner` and `owner_app` via the admin connection and `fail`s with an actionable message if either is `t`. Message names the defect (`postgres:17-alpine` with `POSTGRES_USER=identity`), states that the bootstrap superuser cannot be demoted, and that a new volume with the same variable reproduces the failure. A correct kit-postgres / plain-postgres cluster provisions `NOSUPERUSER NOBYPASSRLS` and passes this gate.

* `internal/tenancy/tenancy_test.go:194-214` — new subtest `the owner and app roles are not superuser or BYPASSRLS` inside `TestTenancyIdentityOwnsItsFiveTables`, querying `pg_roles` on the test connection. A superuser-gate now fails this subtest **first**, with the same remediation, rather than only via indirect row-count symptoms.

No migration, policy, or RLS assertion was weakened. No product code changed.

## Verification (focused, as instructed; no full prime)

```
# Gate cluster now refuses at provision time (the harness fix)
DISP=identity_m156_13cbe13e GATE_DSN="postgres://identity:cafaye@127.0.0.1:15527/$DISP?sslmode=disable"
bin/provision-testdb "$GATE_DSN"  # → fail: role identity is superuser or BYPASSRLS … Recreate the cluster without POSTGRES_USER=identity …

# Gate disposable that was provisioned pre-fix now diagnoses itself at test time
TEST_DATABASE_URL=postgres://identity:cafaye@127.0.0.1:15527/identity_m156_9b3b355b?sslmode=disable \
  go test -count=1 -run TestTenancyIdentityOwnsItsFiveTables -v ./internal/tenancy/
# → FAIL the_owner_and_app_roles_are_not_superuser_or_BYPASSRLS (identity superuser/BYPASSRLS) + the 5 owner-denial failures

# Correct cluster still green end-to-end (provision + tenancy)
LOCAL_DSN=postgres://identity:cafaye@127.0.0.1:5432/identity_m156_local_a93481d4?sslmode=disable
TEST_DATABASE_URL="$LOCAL_DSN" go test -count=1 -v ./internal/tenancy/  # → exit 0 PASS
```

Full `mise exec -- ./bin/prime` was **not** run in this worktree per brief (manager owns the merged gate). Focused tenancy/provisioning checks above are the gate's failing tier.

## Correction of m152

`REPORT-m152-identity-tenancy-gate-red.md` attributed the red to a stale volume (`identity-gate-m147-data` reused, goose no-op at version 30, 00016 enforcement rolled back out-of-band) and recommended destroying the volume and re-provisioning. That explains a *possible* stale-DB failure but does **not** explain this fresh-DB failure, which has `FORCE` in the catalog and bypasses it via the role. A new volume with the same `POSTGRES_USER=identity` (`postgres:17-alpine`) was proven to reproduce the identical triad (credential 2-vs-1, 4/24 isolation, 5 owner denials + trigger `23001`) via superuser bypass, not via missing `FORCE`. The leading hypothesis of §“Root-cause attribution” in that report (Down-section half-rollback) is not the active cause here; the active cause is the container's `POSTGRES_USER` making the owner a superuser. The remediation in that report (destroy the volume) is **insufficient** unless the container is also corrected to not set `POSTGRES_USER=identity` (or to use `kit-postgres:17` with `KIT_POSTGRES_DATABASES=identity` as `site-launch-postgres-1` does). The valid-database claim in `REPORT-m152` §“Clean-DB enforcement state” holds only on a correctly provisioned cluster.

## What remains for the manager

1. Recreate the gate Postgres container **without** `POSTGRES_USER=identity` (use `kit-postgres:17` as in `site-launch-postgres-1`, or plain `postgres:17-alpine` with no `POSTGRES_USER`/`POSTGRES_DB` override, letting `bin/provision-testdb` create `identity`/`identity_app` as `NOSUPERUSER NOBYPASSRLS`). A `docker volume rm identity-gate-m147-data` alone does **not** fix it.
2. Re-provision (`bin/provision-testdb` will now refuse a superuser owner if the container is still misconfigured, so the misconfiguration is caught before the suite runs) and confirm `select rolname, rolsuper, rolbypassrls from pg_roles where rolname='identity'` → `f f`.
3. Rerun `mise exec -- ./bin/prime` against `TEST_DATABASE_URL` pointing at a DB on that corrected cluster (e.g. `identity_gate_m147_clean` after it is reprovisioned on the corrected cluster, or a new `identity_gate_m156_clean`).

## Branch, commits, cleanup

* Worktree: `/Users/kaka/Code/any/moon/cafaye/identity-worker-system-admin`
* Branch: `m147-identity-system-admin`
* Commits in this packet:
  * `5da78de` — `m152: report - tenancy gate red is stale-volume enforcement loss, not a code defect` (prior)
  * `6d2dd12` — `m156: fail fast when owner/app role is superuser/BYPASSRLS (fresh gate was postgres:17-alpine with POSTGRES_USER=identity)` (this packet, Q1)
* Focused commands and exit codes: see §Reproduction / §Verification above. All `go test -run TestTenancy` paths were `go test -count=1` as in `bin/prime`.
* Databases created by this packet (all on disposable, uniquely named; none are manager-owned):
  * `identity_m156_9b3b355b` on `127.0.0.1:15527` (gate postgres) — reproduced the gate signature — **dropped**
  * `identity_m156_13cbe13e` on `127.0.0.1:15527` — second provision that hit the new refusal — **dropped**
  * `identity_m156_local_a93481d4` on `127.0.0.1:5432` (local brew) — correct-cluster control — **dropped**
  * Probe `identity_m156_probe_*` — verified refusal still fires — **dropped**
* Role `cafaye` created transiently on gate postgres to prove bootstrap demotion is impossible — **dropped**
* Manager-owned `identity_gate_m147_clean` (and its container `identity-gate-m147-postgres` / volume `identity-gate-m147-data`) were **not** deleted or mutated except for read-only catalog/role probes. `site-launch-*` stack was never touched.
* Absolute paths in every command above are as executed from the worktree root.
