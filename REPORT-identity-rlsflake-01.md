# REPORT — identity-rls-flake-01

**Packet:** the shared test database keeps ending up with RLS disabled.
**Date:** 2026-10-06. **Branch:** `worker/identity-w22-rlsflake`.
**Commit:** `8a54b59` — tenancy: the catalog proof reads the public row, not a clone's.

## The diagnosis

**The public tables were never damaged.** `TestTenancyIdentityOwnsItsFiveTables`
was reading a **clone's** catalog row, not the public table's.

The proof's catalog query was:

```sql
select … from pg_class c where c.relname = $1
```

— no schema filter, no `ORDER BY` — and the old code read **one row** of what
could be many, never checking that the answer was exactly one.

`internal/platform/dbtest/dbtest.go`'s `Schema`/`SchemaWithOwner` clones every
one of the five protected tables into a `test_<hex>` schema with
`CREATE TABLE … (LIKE public.… INCLUDING ALL)`. `INCLUDING ALL` copies
columns, defaults, constraints, indexes and statistics — and **not** row-level
security, and **not** policies. The clone is dropped at test cleanup, so a
clone outlives its test whenever a suite is killed mid-run (a `t.Cleanup`
does not run on SIGKILL), and several were running against the shared
database on the damaged days.

Two properties of Postgres turn that ambiguity into the reported failure:

1. **The plan is a Bitmap Heap Scan once the catalog holds enough
   same-named relations**, and a bitmap heap scan returns rows in **physical
   heap order**, not index order. (With few matches the planner picks an
   index scan on `pg_class_relname_nsp_index`, where `public` sorts before
   `test_*` and the public row always wins — which is why the test passes
   when the tenancy package runs alone, and why it survived as long as it
   did.)
2. **The public table's physical position is not stable.** `ANALYZE`,
   `TRUNCATE` and `ALTER TABLE` all write a *new* `pg_class` tuple under
   MVCC, and the new tuple version lands **after** every clone created since
   the last move. Autoanalyze fires on the public tables during any full
   suite (the DML volume alone trips it), and `dbtest.Reset` truncates them.

So the failing sequence is: a clone is created → the public table's tuple is
moved by analyze/truncate/alter → the proof's query matches both, the plan
is a bitmap heap scan, the clone's tuple is physically first → the proof
reads `relrowsecurity=false, relforcerowsecurity=false, policies=false` and
reports the public table broken. Rebuilding the database "fixed" it only
because a fresh database has no clones; the next full run re-created them.

## The deterministic reproduction

Built on a scratch database (`rls_repro2`, since dropped — the shared
`identity` database was not touched):

1. Applied the migrations with `goose up`. `public.account_users` reads
   `(relrowsecurity=t, relforcerowsecurity=t)` — healthy.
2. Moved the public tuple the way `ALTER TABLE` does
   (`disable`/`enable`/`force row level security`): its `pg_class` tuple
   went from ctid `(14,1)` to `(14,19)`, physically **after** the clone at
   `(14,11)`.
3. Created 1200 `account_users` clones (the regime several concurrent
   workers produce) and `ANALYZE pg_class`.
4. Ran the **old query, unmodified, through the real pgx client stack**
   (a scratch program issuing the test's exact SQL with `$1`):

   ```
   account_users          first row: enabled=false forced=false acct_index=true policies=false    (plus 1201 more rows the old code never read)
   ```

   and the **actual old test code from `HEAD`** against that database, 3
   runs out of 3:

   ```
   --- FAIL: TestTenancyIdentityOwnsItsFiveTables/every_declared_table_is_enabled_and_FORCED
       account_users: row level security is NOT enabled, so no policy on it is ever evaluated
       account_users: NOT set FORCE ROW LEVEL SECURITY. …
   ```

   — the packet's exact signature, against a public table that reads
   `(t, t)`. (A third message also fires — "enabled with no policy" —
   which is itself the tell: the row read had no policies, so it was a
   clone, not the public table.)

## Why the migration-replay hypothesis is refuted

- **No code in this repository replays migrations against the shared
  database.** Every `goose`/`Down(`/`DISABLE ROW LEVEL SECURITY` hit in
  the tree is a message string or a CI test for the migrate scripts
  themselves. The suites run `go test ./…`; nothing runs `goose down`.
- **The signature cannot come from an interrupted `00016` Down.** That
  section disables RLS before dropping policies — but `DISABLE ROW LEVEL
  SECURITY` does **not** clear `FORCE` (measured on a scratch table:
  `enable`+`force` → `(t,t)`; `disable` → `(f,t)`). An interrupted replay
  therefore reads `(false, true)` and prints only **one** of the two
  reported lines. The reported `(false, false)` — both lines, on
  `account_users` and `account_invitations` — is a clone's row and nothing
  else. (The migration comment in `00016` claiming Postgres clears both
  reloptions on `DISABLE` is wrong; worth a separate packet, as is the
  comment's sibling claim in the same file.)

## The fix

Kept from the previous attempt's partial work (it was correct), with one
comment corrected to claim only what this packet verified:

- `internal/tenancy/tenancy_test.go` — the proof's query is now
  `catalogProof`, scoped to `relnamespace = 'public'::regnamespace and
  relkind = 'r'`, and `protectedCatalogRow` **fails the test unless the
  answer is exactly one row**. The scope narrows nothing the proof claims:
  identity's tables live in `public`, and a table that migrates elsewhere
  is a fact the proof should report, not a row to skip.
- `TestTenancyCatalogProofReadsThePublicRowNotAClone` — the regression
  test. It builds the thing that fooled the proof (a same-named clone in a
  `test_` schema, indexes and no RLS, exactly what `dbtest.Schema`
  produces), asserts the unscoped count is ≥ 2 (the old query's ambiguity,
  deterministic), and asserts the scoped query answers with exactly one
  row, the public table's, protected. **Verified to have teeth**: with the
  scope removed it fails ("returned more than one row … the scope is
  broken"), and it passes against the scratch database where the old query
  fails 3/3.
- `rlsDiagnosis` — every finding now carries a sentence that tells the two
  real causes apart: policies still installed means an interrupted
  migration replay (re-apply the migrations); policies gone means a
  database that does not have identity's migrations applied (rebuild it).
  The test was not weakened, skipped, or quieted in any way.

## Verification

- Old code (from `HEAD`, unmodified) fails 3/3 against the scratch
  database with the clone regime; fixed code passes against the same
  database and against the real `identity` database.
- `bin/prime` green (24 packages, `go test -count=1 -p 4 ./…` against the
  shared cluster), output pasted below.
- `go vet ./…` clean; `gofmt -l .` lists only three files that were
  already unformatted at `HEAD` (untouched by this packet);
  `go test -race ./internal/tenancy/` green.

```
ok  	github.com/cafaye/identity/client	4.717s
?   	github.com/cafaye/identity/client/generated	[no test files]
ok  	github.com/cafaye/identity/cmd/identity	2.301s
ok  	github.com/cafaye/identity/internal/accounts	17.954s
ok  	github.com/cafaye/identity/internal/admin	4.756s
ok  	github.com/cafaye/identity/internal/apikeys	14.942s
ok  	github.com/cafaye/identity/internal/auth	12.594s
ok  	github.com/cafaye/identity/internal/config	0.565s
ok  	github.com/cafaye/identity/internal/courier	1.047s
ok  	github.com/cafaye/identity/internal/httpapi	50.803s
ok  	github.com/cafaye/identity/internal/mfa	16.559s
ok  	github.com/cafaye/identity/internal/oauth	4.842s
ok  	github.com/cafaye/identity/internal/oidc	2.471s
ok  	github.com/cafaye/identity/internal/outbox	3.802s
ok  	github.com/cafaye/identity/internal/platform/ci	3.270s
ok  	github.com/cafaye/identity/internal/platform/clock	0.926s
ok  	github.com/cafaye/identity/internal/platform/db	0.618s
?   	github.com/cafaye/identity/internal/platform/dbtest	[no test files]
ok  	github.com/cafaye/identity/internal/platform/id	1.047s
ok  	github.com/cafaye/identity/internal/platform/oauthtest	0.900s
ok  	github.com/cafaye/identity/internal/recovery	14.722s
ok  	github.com/cafaye/identity/internal/sessions	1.133s
ok  	github.com/cafaye/identity/internal/telemetry	0.635s
ok  	github.com/cafaye/identity/internal/tenancy	0.527s
ok  	github.com/cafaye/identity/internal/useraudit	3.461s
ok  	github.com/cafaye/identity/internal/users	0.883s
```

## Notes

- The previous attempt's partial work (the scoped query, the exactly-one-row
  assertion, the regression test, the diagnosis messages) was judged
  **correct and kept**; one comment in it asserted a specific measurement
  ("two `test_*` schemas … days after") that could not be verified against
  the shared cluster, and it was rewritten to claim only what this packet
  reproduced.
- Scratch databases `rls_repro` (previous attempt's) and `rls_repro2` (this
  packet's) were dropped after the work; the shared `identity` database was
  never dropped, recreated, or migrated against.
- Two things this packet found but did **not** change, both candidates for
  their own packet: the `00016` comment claiming `DISABLE ROW LEVEL
  SECURITY` clears `FORCE` (it does not), and the fact that a killed suite
  leaves `test_*` clone schemas behind (the debris that makes the clone
  count — and with it the plan choice — grow between runs).
