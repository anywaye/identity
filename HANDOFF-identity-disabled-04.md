# HANDOFF — identity-disabled-04

Who turned this person off, and when.

**Branch** `worker/disabled-04` · **Base** `aaace6f` on `master` · not pushed, not
merged.

A disable records nothing today. This packet builds `user_audit_log`, writes the row
in the same transaction as the revocation, and says so plainly where it stops.

---

## 1. What landed

| Piece | Where |
|---|---|
| The table, the append-only trigger, the app-role grant | `migrations/00022_user_audit_log.sql` |
| The store — `Append` and nothing else | `internal/useraudit/` |
| `auth.UserAuditRecorder`, `auth.ErrNoUserAuditRecorder` | `internal/auth/service.go` |
| The write, as the 4th statement of `Disable` and the 2nd of `Enable` | `internal/auth/service.go` |
| `DisableInput` / `EnableInput`; the caller threaded onto the context | `internal/auth/service.go`, `internal/httpapi/operator.go` |
| The wiring | `cmd/identity/main.go` |
| Both dbtest lists (TRUNCATE **and** per-schema `LIKE` + trigger) | `internal/platform/dbtest/dbtest.go` |
| A commit-time check on the trigger pair | `internal/platform/ci/audit_trigger_test.go` |

## 2. The two questions the packet asked me to answer by name

### 2.1 Does `Enable` record an event? — **Yes.**

I decided to record it, and the argument is in `auth.Service.Enable`'s header. The
short version: the pair "who turned this person off, and when" is always asked
together, and an operator who disables a user in error and re-enables them an hour
later has — in the trail's terms — disabled them with no end. A trail that holds only
the first half answers one question and is silent on the one that follows it.

`Enable` consequently **opened a transaction**, which it did not have before. That is
the real cost and it is worth naming: until this packet `Enable` was one statement and
correctly took none. There is now a second write, and a re-enable that lifted the
column without recording would leave an operator believing a person is *still*
disabled while the service has let them straight back in — a half-applied state that
looks correct from both sides.

It does **not** need the access-token revoker, and its absence from `Enable`'s
preamble is deliberate: a re-enable mints nothing and revokes nothing.

### 2.2 Does the log have a reader? — **No. This is deliberate and it is a debt.**

There is no route, no scope, and **no `List` method**. Three reasons, in order:

1. The packet said add no route, and I agree — a half-built read endpoint is worse than
   none.
2. I did not add a `List` either, because a method with no caller is what AGENTS.md
   calls "a tested but unwired method": it would be covered by a test exercising an API
   no deployment reaches, and the next packet would inherit a function whose only
   proven use is its own test. `Store.Pool()` exists instead, which is what a test or
   an operator with `psql` needs.
3. **The reader will need a new scope, and that scope does not exist.**
   `users:disable` is an operator scope and its natural reader is an operator — but
   `GET` on a trail is a *read*, and nothing in `internal/apikeys` grants a
   machine-only scope without an account behind it. This is the same wall D14 hit from
   the other side: the write side needed no account because a disable names a person,
   and the read side has the identical problem.

**That is the next packet's opening, written down rather than started:**

> Add a read for `user_audit_log` — `GET /v1/users/{userID}/audit` — behind a **new
> operator scope** (`users:audit`, say). It must not reuse `users:disable`: that scope
> may name *any* user on the deployment, and a read scope that wide would hand every
> operator the disable history of every person on the fleet. If the intended reader is
> narrower than "any operator", that is a scoping decision of its own and belongs in
> DECISIONS.md before the route, not after.
>
> The query is a keyset page over `(occurred_at DESC, id DESC)` and **the cursor must
> carry `(occurred_at, id)` together** — a timestamp-only cursor drops records sharing
> the boundary instant, which this service's clock makes the normal case. That is why
> 00022 has **no index**: the packet adding the reader adds the index with the query,
> on 00021's and 00002's argument.

## 3. Tests, and the defects I injected to watch them go red

Every behavioural test was proven by injecting the real defect. These are the actual
failures I observed:

| Defect injected | Test that caught it | Failure text |
|---|---|---|
| Removed `CREATE TRIGGER user_audit_log_append_only` from 00022 | `TestTheAuditTriggerListNamesRealObjects` | "installs no trigger of that name… reads as coverage and is decoration" |
| Moved the writer out of the transaction onto `s.read` | `TestADisableWritesItsRecordInsideTheTransaction` | "written through `auth.markerQuerier({reader})`, want the TRANSACTION's querier" |
| Recorded `useraudit.Action("user.exploded")` | `TestTheDisableRecordNamesTheOperatorAndTheSubjectAndWhen` | "the action is `user.exploded`, want `user.disabled`" |
| Stopped threading the caller onto the context | `TestTheOperatorRouteHandsTheUseCaseItsOwnIdentity` | 500 instead of 204 (`errNoOperatorActor`) |

The third is the packet's "closed set refused at the point of use" requirement, proven
from the writer's side. From the store's side it is
`TestTheClosedSetIsARefusalNotASchemaCheck`, which asserts **both** halves: `Append`
refuses an unknown action, **and the database accepts one** — because a `CHECK`
constraint would make adding an action a migration.

### 3.1 An injection that went red for the WRONG reason

Worth recording, because it nearly became a false proof. My first attempt at defect 2
replaced the in-transaction `Append` with a post-transaction one but **left
`return s.uow.Do(...)` in place**, so the injected block was unreachable dead code. The
test went red — with *"the recorder was asked 0 times"* — which is a **false** signal
here: zero calls is exactly what a *correct* implementation plus a broken fixture
produces. I only caught it because the message did not match the defect. A test I had
not watched fail for the right reason would have shipped a proof of nothing.

### 3.2 "A check over nothing is green" — guarded twice

Two named guards, because this repository has been bitten by a comparison of two empty
things twice already:

- `useraudit.tableExists` — every test in `internal/useraudit/store_test.go` resolves
  the relation before reasoning about its contents.
- `auth.requireUserAuditTable` — the same, in the integration tier, where the counts
  are against rows a real disable wrote.

Both assert `to_regclass('user_audit_log')` **resolves to the right name**, not merely
that a query returns. And the fake records its call **before** returning its injected
error, so the failure path is not asserted against an empty slice — the `disabled-03`
scar, written the other way round on purpose.

## 4. Two premises in the packet that did not survive contact with the code

Both were measured before I did the correct thing.

### 4.1 "find how `internal/platform/ci` does it for the account one and mirror it"

There is **no such test**. The account trigger's existence is not walked by any Go
test in `internal/platform/ci`. What actually exists is:

- `bin/rollback`'s `census()` — a SQL query over `pg_class`/`pg_trigger` that
  enumerates **every** object, so a new trigger is covered the day it is written with
  no edit anywhere;
- `internal/admin/store_test.go` — behavioural proofs that UPDATE and DELETE are
  refused.

So there was nothing to mirror. I built both halves instead:

- `internal/platform/ci/audit_trigger_test.go` — the commit-time half, which runs in
  `bin/prime` with no database: that the function and the trigger are written down,
  that they fire on **`UPDATE OR DELETE` and not `INSERT`** (the subtle one — a
  `BEFORE UPDATE`-only trigger passes every existence check and still lets a trail be
  emptied), and that the `Down` drops both objects.
- `internal/useraudit/store_test.go` + `internal/auth/disabled_integration_test.go` —
  the database half, against rows a real disable wrote.

**Caveat stated in the file's own header:** the CI check cannot establish that the
trigger *fires* — a plpgsql body that parses and does nothing satisfies every
assertion in it. It catches a trigger deleted from a migration; the store tests catch
one that exists but does not work. Neither is sufficient alone.

### 4.2 "Two actor ids … it is why both columns are NOT NULL"

Correct as written, and I implemented it that way. But the packet's `What to expect to
touch` list omits **`migrations/00019_app_role_dml.sql`**'s consequence: `identity_app`
is the role production runs as, and `account_audit_log`'s grant came from
`cafaye.protect_table` inside 00016. **`protect_table` refuses a table with no
`account_id`** (00019's own header says so), so there was no substrate call to make —
the grant had to be written into 00022 itself:

```sql
GRANT SELECT, INSERT ON TABLE user_audit_log TO identity_app;
```

Two privileges, not four. `UPDATE`/`DELETE` are **deliberately not granted**: the
trigger refuses them, so granting them would be a privilege whose only possible
outcome is an error. Verified on the cluster after `goose up`:

```
app_can_insert=true    app_can_update=false
```

Without this line the table would have applied cleanly and failed on the first
production disable — invisible to `go test` unless a test happens to run as
`identity_app` against `public`.

## 5. One decision I made that the packet did not ask for

**`Disable` and `Enable` now take an input struct.** `Disable(ctx, userID, at)` had
nowhere to put the actor's two ids and the trace id, so the signature had to change.

I passed them **positionally-by-instead-of-struct** rather than as extra positional
arguments because with `(ctx, userID, actorUserID, actorKeyID, traceID, at)` there is
nothing in the signature to stop the **subject's** id being written where the **actor's**
belongs — and an audit row that indicts the person who was disabled is worse than no row
at all. `DisableInput`/`EnableInput` make that a named-field mistake, and
`TestTheDisableRecordNamesTheOperatorAndTheSubjectAndWhen` asserts subject and actor
against **different** uuids so a swapped pair cannot pass.

This is a breaking change to `httpapi.Auth` and to `auth.Service`'s constructor. It
ripples through 9 test fixtures; all are updated, and each got the real
`useraudit.NewStore(pool)` so that a nil recorder can never make a test in another file
answer `ErrNoUserAuditRecorder` by accident.

## 6. Gates — real exit status, all of them

| Gate | Result |
|---|---|
| `go build ./...` | 0 |
| `go vet ./...` | 0 |
| `gofmt -l .` | 3 files, **all pre-existing on `aaace6f`** and untouched by me |
| `goose up` (00022) | applied, version 22 |
| `go test -count=1 ./...` with `TEST_DATABASE_URL` | **exit 0**, 24 packages ok |
| `go test -race -count=1 ./internal/auth/ ./internal/httpapi/ ./internal/platform/...` | **exit 0** |
| `go test -count=1 ./...` **without** the DSN | **exit 1** — by design, `TestTheDatabaseTierActuallyRan` |
| `bin/coverage-floor` | `coverage 75.0%` over the 70 floor |

`gofmt -l .` names `internal/platform/ci/{rollback,substrate_copy}_test.go` and
`internal/tenancy/user.go`. I verified each was already unformatted at `aaace6f` before
touching anything and did not fix them; every file I touched is formatted.

### 6.1 `bin/rollback` could not be run here, and I did not fake it

It failed for an environmental reason worth recording: it derives the app role from
whoever is connected (`APP_ROLE="${CALLER}_app"`), so run as `identity` it could not
`CREATE DATABASE`, and run as the superuser `cafaye` it wants `cafaye_app`, which does
not exist on this cluster. **Creating that role on a shared cluster to make a check
pass is not something I was willing to do unasked.**

So I verified 00022's `Down` the direct way. It is the **last** migration, so
down-then-up is exactly reversible, and I measured the catalog on both sides:

```
BEFORE:  public_table=1  public_func=1  trigger=1
after down:  public_table=0  public_func=0      ← no orphans
after up:    public_table=1  trigger=1
             app_can_insert=true  app_can_update=false
```

The `Down` leaves nothing behind, and re-applying restores the trigger and exactly the
two intended privileges. **The full 22-migration rollback has not been exercised**;
CI runs it on a properly provisioned cluster.

## 7. Not done

- **No route, no scope, no `List`** — §2.2. This is the packet's biggest open debt and
  the next packet's opening.
- **No index.** Deliberate, on 00021's argument: nothing reads the table. The header
  records the index that lands with the reader that needs it.
- **No `account_id` anywhere**, and `TestTheTableCarriesNoAccountColumn` asserts it at
  the schema level — including against a *nullable* one, which would be worse than
  either extreme.
- **No `affected` and no `target` columns**, argued in the migration header: nothing in
  `Disable` returns a count, and a number somebody estimated is exactly what
  `admin.Entry`'s doc says must not reach an audit row.
- **No RLS and not in `tenancy.identityTables`** — `protect_table` cannot protect a
  table with no `account_id`, and there is no tenancy boundary in a table whose subject
  is a person (D14). Deliberate omission, stated in the migration header.
- **`DECISIONS.md` and `AGENTS.md` are untouched.** D14's "no account anywhere" is
  unchanged by this packet and a new decision was not made. AGENTS.md's references to
  `internal/adminaudit` were already stale before I arrived — that package does not
  exist and the real one is `internal/admin`.
- **`README.md` endpoint table is untouched** — no route, so no row.
- Not pushed, not merged, no other repository touched.

## 8. If you are picking this up

1. Read `migrations/00022_user_audit_log.sql` first. Every decision above is argued
   there and the arguments are the deliverable as much as the SQL is.
2. The reader is the open item — §2.2 has the scope problem stated. **Do not reuse
   `users:disable` for it.**
3. `internal/platform/ci/audit_trigger_test.go` names its own pair in a literal list on
   purpose. A third audit table needs an entry there, or the check silently stops
   covering it — which is the failure mode §3.1 is a cautionary tale about.
4. `dbtest`'s **two** lists, not one. A table missing from the per-schema `LIKE` list
   does not fail loudly; it fails as a missing relation, which reads like an isolation
   bug.