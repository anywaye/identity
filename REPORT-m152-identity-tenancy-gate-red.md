# m152 — Merged Identity tenancy suite red: diagnosis

## Verdict

**Not a product regression. No code fix warranted; no code changed.**

All three gate failures are the signature of **missing RLS enforcement
(`FORCE ROW LEVEL SECURITY`, possibly RLS/policies) on the real tables in the
gate database** — owner-role reads bypassing policies — reproduced verbatim in
this packet by fault injection. The merged tree is green on clean databases,
alone and under concurrent load. The gate database
(`identity_gate_m147_merged` on volume `identity-gate-m147-data`) was almost
certainly **stale (volume reused across merged-gate attempts)**, so
"migrations 1–30 succeeded" was a goose no-op at version 30 over tables whose
enforcement had been rolled back out-of-band. Recommended manager action:
destroy the volume (or use a new DB name), re-provision from scratch, rerun
prime. Details below.

## Gate evidence (manager's summary, merged m147+m147b+m151 tree)

- `TestTenancyACredentialResolvesByTheDigestTheCallerPresentedAndNothingElse`:
  tenant A saw 2 API keys, expected 1.
- `TestTenancyAccountIsolation`: 4/24 assertions failed; alpha/beta/no-identity
  reads observed extra rows.
- `TestTenancyIdentityOwnsItsFiveTables`: 5 assertions failed with extra rows;
  cross-account UPDATE on append-only `account_audit_log` got the append-only
  trigger error instead of a zero-row RLS denial.

## What was ruled out (with evidence)

1. **Shared-DB fixture interference across packages.** `go test ./...` runs
   packages in parallel on one `TEST_DATABASE_URL`, but every interference
   path is closed in this tree:
   - `isolation.sql` reads only per-session TEMP tables; nothing cross-session
     can add rows to them.
   - Identity state (`cafaye.account_id`, `cafaye.credential_digest`) is a
     transaction-local GUC (`is_local => true`); it cannot leak across
     sessions, let alone processes.
   - `cafaye.unprotected_tables()` is scoped to schemas the substrate was
     applied in (derived from `_cafaye_*` policies), plus `cafaye` and the
     *caller's own* `pg_temp` — concurrent `test_<hex>` fixture schemas carry
     no policies and are out of scope. Proven empirically: a lingering
     `test_m152linger.account_users` clone (`LIKE ... INCLUDING ALL`, no RLS)
     left `TestTenancyAccountIsolation` green on its own.
   - Tenancy seeds use random UUIDs and roll back (`seedAuditRows`) or delete
     (`seedCredentialRows`/`seedJoinRows`) their fixtures. Verified on a fresh
     DB: after the credential test, `accounts`/`api_keys`/`users` counts are
     all 0. (The accounts-table cleanup works because `accounts` itself is
     unprotected — no `account_id` — so the owner-side `DELETE` is effective
     and cascades to `api_keys`.)
2. **A change-related defect.** `git log` on `migrations/00016*`,
   `internal/tenancy/`, and the credential/resolve path shows no enforcement
   change in m135/m147/m147b/m151. m147's only migration is `00030`
   (`users.is_staff` boolean on the unprotected `users` table); m151 touches
   only `bin/provision-testdb`. `grep` over the tree: no Go code issues
   `DISABLE ROW LEVEL SECURITY`, `DROP POLICY`, or touches `FORCE`.
3. **Deterministic-ID / cleanup collisions.** Tenancy tenant IDs are
   `gen_random_uuid()` per run; nothing deterministic to collide.

## Reproduction (bounded, disposable DBs; manager's DB never touched)

Host `127.0.0.1:15527` was unreachable (container gone), so all work used the
local cluster with uniquely named disposable databases. `identity`/`identity_app`
roles pre-existed (cluster convention password `cafaye`); only new databases
were created, both dropped afterwards.

- Provision: `bin/provision-testdb
  "postgres://identity:cafaye@127.0.0.1:5432/identity_m152_gate?sslmode=disable"`
  (admin via local superuser) → exit 0, goose to version 30.
- Focused, exact command:
  `TEST_DATABASE_URL='postgres://identity:cafaye@127.0.0.1:5432/identity_m152_gate?sslmode=disable'
  go test -count=1 ./internal/tenancy/` → **exit 0** (`ok ... 1.062s`).
- Concurrency simulation (same shared DB, prime-style `-p`):
  `go test -count=1 -p 3 ./internal/tenancy/ ./internal/outbox/ ./internal/accounts/`
  → **exit 0**, all three packages ok.
- Clean-DB enforcement state confirmed: all five identity tables
  `relrowsecurity=t, relforcerowsecurity=t` with 4–6 policies each.

## Fault injection reproduces all three symptoms verbatim

On a second disposable DB (`identity_m152_q2`, freshly provisioned, green
baseline confirmed), enforcement was removed on two tables only:

```sql
ALTER TABLE api_keys NO FORCE ROW LEVEL SECURITY;
ALTER TABLE account_audit_log NO FORCE ROW LEVEL SECURITY;
```

`go test -count=1 -v ./internal/tenancy/` → **exit 1**, with:

- `credential_lookup_test.go:126: tenant A can see 2 api keys, want 1 ...`
  — verbatim gate symptom 1 (case-0 tripwire; owner bypasses the policy).
- `2 of 24 account-isolation assertions failed` naming exactly the two sweep
  assertions, actual listing `account_audit_log` and `api_keys` as
  `row level security is not FORCED, so the table owner bypasses it`.
  The gate saw 4/24 with read-side extras too — the wider variant of the same
  fault (more tables unforced, and/or the temp fixture itself unforced from a
  stale-substrate volume, see below); every additional unforced table adds
  sweep/read failures in this exact shape and no other shape does.
- Five-tables denial arms failing as `identity` with extra rows
  (`read 2 rows, want 0/1`; `read 1 of THAT tenant's rows, want 0`), plus
  `the cross-account UPDATE raised ERROR: account_audit_log is append-only;
  UPDATE is not permitted (SQLSTATE 23001)` — verbatim gate symptom 3. The
  RLS `using` denial matches zero rows and raises nothing; the trigger error
  proves the row *matched*, i.e. the owner bypassed the policy.
- Control direction: `three-way_denial_as_identity_app` still **PASSED**
  throughout — a non-owner is always filtered, so this fault is visible only
  on owner-role reads. Prediction for the gate log: failures skew to the
  owner columns/arms. No other package in the suite reads real protected
  tables as the owner (`dbtest.Pool` is the app role; `Schema` clones carry
  no RLS), which is why only `internal/tenancy` went red.

## Root-cause attribution

No merged commit can produce this state via `goose up`: `protect_table`
enables + forces RLS and (re)creates the four named policies on every run.
The state *is* producible by `00016`'s **Down** section
(`migrations/00016_account_isolation.sql:1025-1056`), which issues
`ALTER TABLE ... DISABLE ROW LEVEL SECURITY` *before* the `DROP POLICY`
statements, one statement per transaction — an interrupted or completed
out-of-band replay leaves tables unprotected (with or without policies) while
the append-only trigger from `00012` stays in place. That combination —
trigger present, enforcement absent — is exactly the gate's symptom 3.

The gate ran `goose up` to version 30 with "success" and still had
unenforced tables. On a truly fresh database that is impossible; on a
**reused volume** (`identity-gate-m147-data` across merged-gate attempts) it
is the expected outcome: goose reports success as a no-op at version 30 and
never re-applies `00016`'s Up. The container is gone (port 15527 closed), so
the volume's actual state cannot be inspected from here — this last link is
the leading hypothesis, not a proven fact. What *is* proven is that (a) the
code is green on clean databases, and (b) enforcement loss reproduces every
reported symptom verbatim while nothing else can.

## Remaining manager gate

1. Destroy volume `identity-gate-m147-data` (or provision under a new database
   name; do not reuse `identity_gate_m147_merged` without recreating it).
2. Re-provision from scratch (`bin/provision-testdb` or prime's built-in
   provisioning) and confirm `relforcerowsecurity=t` on the five tables.
3. Rerun `./bin/prime`. No code change in this packet; nothing to review
   beyond this report.

## Cleanup performed here

Dropped disposable databases `identity_m152_gate`, `identity_m152_q2` and the
`test_m152linger` probe schema from the local cluster. Pre-existing roles
(`identity`, `identity_app`) untouched. No Docker used. No full prime run.
Manager's database never accessed (host unreachable the entire run).
