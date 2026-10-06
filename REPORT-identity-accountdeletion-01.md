# REPORT — identity-accountdeletion-01

**Branch:** `worker/identity-w19-deletion` · **Base:** `74c4b9b` · **Commit:** `bbcb43c` ·
**Status: work landed and read; the gate is NOT verified — see §7.**

**A note on the filename, so the next reader is not confused.** An earlier report for
this packet exists at `REPORT-identity-account-deletion-01.md` (487 lines), committed
inside `bbcb43c` by the previous attempt. This file is a second, independent reading of
the same diff, written at the manager's request because the previous attempt's
conclusions are void — its model endpoint stalled before the report could be
delivered, and a report nobody delivered is a report nobody can check. Where I have
checked the earlier report against the diff, its claims hold; the places where the
tree and any report disagree are in §6. Nothing in this file should be read as
confirming the earlier one.

---

## 1. What the packet set out to do

The brief (`m41-identity-accountdeletion-01.md`) closes a parity gap: a user cannot
delete their own account. `FEATURE-PARITY.md` §1 lists it ABSENT; every
deletion-adjacent piece exists in isolation (session revocation, API-key revocation,
membership rows, owned accounts) but nothing ends a person's presence in the system.

The brief asked for:

1. **`DELETE /v1/me`** (or the route name matching existing conventions), requiring a
   live, authenticated session.
2. **Semantics, in one transaction**: the user row deleted (or anonymised — pick one,
   document why); the personal account and its memberships go with it; team accounts
   the user merely belongs to survive, losing only the membership row; a team account
   the user *solely owns* handled explicitly — refuse naming the accounts, or
   cascade — **pick one and document why** (refusal is the safer default and is
   acceptable); every credential revoked; an `identity.user.deleted` outbox event
   written in the same transaction.
3. **Tests**: the happy path; the sole-owner refusal; another user's team account
   surviving; revoked credentials stopping authentication; the outbox row existing in
   the same transaction.

Constraints the work was held to: no changes to `courier/`, `billing/`, `parlor/` or
any other repository; no weakened or skipped existing tests; and the RLS caveat —
`dbtest.Schema` clones tables with `LIKE … INCLUDING ALL`, which does not copy
row-level security, so boundary tests must run against the real policies.

## 2. What the commit actually does, section by section

`bbcb43c` — 33 files, +3691/−36. One route, one transaction, one migration, plus
three defects found on the way and fixed.

### 2.1 The route

`internal/httpapi/deletion.go`, mounted by a dedicated `registerDeletionRoute` on the
**auth** registrar, not the tenancy one — its subject is a person, not one of their
memberships (DECISIONS.md D14), and `TestEveryMountedRouteIsAnAccountRoute` refuses a
non-account path in `registerTenancyRoutes`.

- **`204`, no body, no `Content-Type`** — nothing to describe; the same answer
  `DELETE /v1/session` gives.
- **Session-only, and by omission rather than by a check.** The handler resolves the
  caller with `currentUser`, exactly as `GET /v1/me` does. There is no
  `sessionCredentialOnly` wrapper (that middleware does not authenticate, it only
  refuses the api-key prefix) and no scope check: a scoped token resolves to no
  session and gets the same one 401. The route is deliberately absent from
  `accountRouteScopes` (a row there would be a type with no enforcement behind it)
  and from `matrixEndpoints()` (that walk reads `registerTenancyRoutes` only).
- **Anonymous → one 401, and a second DELETE with the same (now dead) session is also
  a 401** — never an "already deleted", which would be an oracle for which user ids
  are real. Both properties have rows in `anonymous_familyAudit()` and
  `deletion_test.go`.
- **409, not 422**, for the sole-owner refusal: the request was well-formed and
  understood; what conflicts is an account's state. The code is the declared
  `CodeAccountOwnershipConflict` (`account_ownership_conflict`), new in
  `internal/httpapi/problem.go`, with a title in the fixed `titles` map — a code
  absent from that map renders the fallback "Request failed", which would have shipped
  a refusal whose summary says nothing about ownership. It is deliberately not
  core's reserved `conflict`: a machine consumer switching on `code` must be able to
  tell "retry or reconcile" from "this person must stop owning something first".

### 2.2 The transaction

`internal/deletion/service.go` — `Service.Delete`, one `UnitOfWork.Do`, five steps
whose order is the whole of it:

| # | Step | Why here |
|---|------|----------|
| 1 | `SolelyOwnedTeamAccounts` — the only read-before-write | asked before anything is removed, so a refusal touches no row and writes no event; asked before the memberships go, or the answer would be a lie |
| 2 | `RevokeEveryCredential` (sessions, then OIDC access tokens) | the cascade would do this invisibly; the sweep is a statement somebody can attribute, and it runs first so the tables are emptied by an attributable statement |
| 3 | personal accounts deleted **by name**, after a second `BeginUser` | nothing cascades between `accounts` and `users`; the re-begin is required because step 1's loop leaves the transaction standing in the last account it counted, under which the personal-account read silently returns `[]` |
| 4 | the user row (`users.Store.DeleteForAccount`) | fires the FK cascade over `sessions`, `connected_accounts`, `account_users`, `api_keys`, `recovery_tokens`, `mfa_credentials`, `mfa_challenges`, `oidc_auth_requests`, `oidc_access_tokens` |
| 5 | `identity.user.deleted` into the outbox | last, so it cannot fail after the work is done and leave the work done |

All five roll back together. The transaction stands in as the **user**
(`tenancy.BeginUser`), not an account — the two GUC setters write the same GUC, so
the per-account identity of step 1 cannot be held alongside it, which is what makes
the re-begin in step 3 a requirement rather than tidiness.

The sweep (`internal/deletion/sweep.go`) is a value type built from the same two
stores the rest of the process uses, duplicating `recovery`'s two statements in
recovery's order (sessions, then tokens) rather than exporting that package's
unexported method — the duplication is held to the original by a test that asserts
the same two tables are swept in the same order. `NewSweeper` **refuses half a
wiring**: a sweeper that ends sessions and leaves every access token standing is a
wiring bug that should stop the process at construction, not reach a user request.
The `CredentialSweeper` seam itself may be nil (every table it touches cascades
anyway), and then the deletion still removes the rows — an end state that is correct
and an audit trail that is silent.

### 2.3 The two decisions

**A solely-owned team account is a REFUSAL, not a cascade.** `409`, code
`account_ownership_conflict`, `detail` naming **every** such account by name *and*
slug. Nothing is written. Cascade-deleting a team account takes, in one statement: the
api keys its other members hold, the OIDC registrations their products depend on, the
pending invitations it still wants, and the memberships themselves — every one of
those belongs to somebody who did not ask to disappear. Transfer was also rejected:
`accounts.Service.TransferOwnership` exists, but transfer needs a **recipient**, and
the only people who know who should inherit a workspace are the ones still in it. So:
refuse, name it, let the owner hand over ownership through
`POST /v1/accounts/{accountID}/ownership-transfers`, and the refusal disappears. The
bar is the **owner** role, not membership: an account with a second owner never
blocks anybody, even if that owner has never logged in, because every owner-only
route in `internal/httpapi` keys on that role.

**The user row is DELETED, not anonymised.** `DELETE FROM users WHERE id = $1`.
Anonymisation would need a tombstone column and every read of `users` filtering on it
— and the thing anonymisation exists to serve is already kept somewhere this
deletion does not touch: `user_audit_log` has **no** foreign key to `users` (00022,
deliberately), and `identity.user.deleted` carries the id. `accounts` has **no**
foreign key to `users` in either direction (00005), so the personal account is *not*
cascaded by deleting the user; it is removed by name, before the user row, and that
ordering is load-bearing.

### 2.4 The migration

`migrations/00023_user_deletion_set_null.sql` (217 lines, Up and Down). Four columns
named a user with `ON DELETE RESTRICT`, each protecting a record **somebody else
owns**; three of them made self-service deletion impossible for anybody who had ever
invited somebody, registered an OIDC client, or revoked a key — a raw 500 from the
database. The migration changes three to `ON DELETE SET NULL`, which keeps the row
and gives up only the pointer:

| Column | What it took |
|---|---|
| `account_invitations.invited_by` | `DROP NOT NULL` first — `SET NULL` on a `NOT NULL` column is refused. The invitation survives with no sender; `accepted_by` is what matters once redeemed, and it is unconstrained (00007). |
| `oidc_clients.created_by` | Straight swap. 00009 keeps registrations rather than deleting them; a RESTRICT on the creator undid that for exactly the person most likely to delete. |
| `oidc_clients.revoked_by` | Straight swap **plus** relaxing `oidc_clients_revocation_is_whole` to `(revoked_at IS NOT NULL OR revoked_by IS NULL)`. The old pairing CHECK would have refused the very `SET NULL` this migration performs — leaving it would have traded one refusal for another and passed every test fixture. The relaxed form says what the table means: a live registration may have no revoker; a revoked one may have lost theirs. Forgetting who withdrew something must never un-withdraw it. |

Not `CASCADE` anywhere: every one of these rows belongs to an **account**. The
fourth RESTRICT (`api_keys.revoked_by`) was measured, found **unreachable**, and
deliberately left alone: `apikeys.Store.RevokeAllForMember` sets `revoked_by` to the
same user its `WHERE` filters `user_id` on, so any row referencing the departing
person through `revoked_by` is also referencing them through a `ON DELETE CASCADE`
FK, and PostgreSQL removes it through the cascade before the RESTRICT check can see
it. The real property is stronger than the one first asserted: the revoked key is
**gone with its holder**, not un-revoked. Leaving the FK RESTRICT is the safe
direction — if a path is ever added where one admin revokes a *colleague's* key, the
deletion fails loudly naming this constraint, and whoever adds it reads 00023.

The `Down` is honest about its own cost: rows the Up produced (`revoked_by IS NULL`
with `revoked_at` set; invitations with no sender) cannot be restored — there is no
value to put back, because the person is gone — so the Down **fails on such a table**
rather than inventing an attribution or deleting the record. Rolling back is only
possible on a deployment where no user has deleted their account since it was
applied.

### 2.5 Findings on the way — three real ones, all fixed

**(a) RLS hides the *other* owners, so the sole-owner question needs a per-account
identity.** The natural SQL — one statement with `NOT EXISTS (… other owners …)` — is
wrong under the real policies and right under `dbtest.Schema`, which clones tables
without RLS. `account_users_cafaye_members` (00018) admits the caller with
`user_id = cafaye.current_user_id()`; standing in as the user you see your *own*
membership rows and nothing else, so the subquery is filtered to the empty set
*before PostgreSQL evaluates it*, `NOT EXISTS` is vacuously true for every account,
and **every** account you own is reported as one you solely own. Observable
consequence: a user who is one of two co-owners is told they cannot delete their
account, and transferring ownership does not help because the second owner is never
counted. The fix is the two-phase loop: list the team accounts you own (as the user,
where every matched row is your own), then switch to each account in turn
(`tenancy.BeginAccount`) and ask `CountOwners`, which
`account_users_cafaye_select` admits. `CountOwners` already takes `FOR UPDATE`, so
the answer is a lock rather than a snapshot.

**(b) A latent namespace race in `internal/tenancy`'s boundary test.**
`TestTenancyIdentityOwnsItsFiveTables` read `pg_class where c.relname = $1` with **no
namespace filter**. Every `dbtest.Schema` call creates `test_<hex>` clones with
`LIKE … INCLUDING ALL`, and `LIKE` does not copy RLS — so the cursor could land on a
clone and report a perfectly enforced boundary as unenforced. The filter's absence
predates this work; the baseline suite passed because the timing fell its way, and
one more package in the tree was enough to lose it. Fixed with
`and c.relnamespace = 'public'::regnamespace` — a *stricting*, and the flake it
removes is the entire point of the assertion.

**(c) `coverage-exclusions`' statement figure was wrong by a third.** It claimed 6418
statements in the generated block; the measured figure is **4852** (both from
`bin/coverage-floor` and a direct profile read). Overstated, and no assertion read it
— which is that entry's own documented failure mode ("a statement count is not
derivable without a coverage profile and this entry is read without one") recurring.
Restated to the measured figure, and the entry's reason now carries the full
restatement history including this packet's own: the operation moved the excluded set
27602 → 27936 lines (334 — the cheapest operation in the file's history, because a
204 has no request or response body), and adding the `account_ownership_conflict`
problem code to the 409 example moved it 27936 → 27939 lines and **not one
statement** (an enum member is a constant; the other three lines are gofmt
re-aligning the const block). The floor did not move and must not: it is a floor
over hand-written code.

**Also: `gofmt -l .` was not clean at `74c4b9b`.** Three files lacked a trailing
newline (`internal/tenancy/user.go`, `internal/platform/ci/rollback_test.go`,
`internal/platform/ci/substrate_copy_test.go`). Fixed — one byte each, the latter
two whitespace-only — because the gate requires it and one of the three is a file
this packet depends on.

### 2.6 Supporting changes, the ones that are easy to miss

- **`internal/platform/dbtest/dbtest.go`** — the clone schemas' three foreign keys
  moved from `RESTRICT` to `SET NULL` to match 00023. Without this, every other
  package's tests that clone these tables would be testing a schema that no longer
  exists.
- **`internal/outbox/users.go`** — `EventUserDeleted = "identity.user.deleted"` and
  `NewUserDeleted`. The payload is a user id and nothing else, deliberately: by the
  time the event is written the `users` row is *gone inside the same transaction*,
  so a payload carrying the email would be the only surviving copy of the address,
  in the one table every subscriber on the platform can read. The event is emitted
  **undeclared** — core 0.2 ships no catalog row and no payload schema for a user
  deletion, and declaring it fails `event.payload-schema-missing` — so it is pinned
  in `internal/platform/ci/event_grammar_test.go`'s `knownUndeclaredEvents` with the
  reason. Deleting that pin without declaring the event is a red build.
- **The four walk literals.** `servedRoutes`, `walkOptions`,
  `mountedFamilyRoutes` and the claims-faults `walkOptions` all gained
  `deletion: newFakeDeletion()`, and `conditionalSurfaces` in `router_walk_test.go`
  now lists `deletion` by name. This is the completeness obligation AGENTS.md
  describes: a field left out of an `options` literal is a surface the walk cannot
  see, and a route no walk sees needs no document, no README row and no
  enumeration-audit row — `internal/httpapi` was fully green with `DELETE /v1/me`
  mounted and completely undocumented before the field existed. `newAuditFixture`
  now wires the **real** deletion service (with a no-op sweeper, so the anonymous
  probe never reaches a credential statement) rather than a double, because a fake
  would keep answering 401 even if the handler's authentication were deleted.
- **`openapi/v1.yaml`** — the `DELETE /v1/me` operation with `operationId
  deleteCurrentUser`, the 409 example, the problem-code enum member, and the version
  pin `1.10.0 → 1.11.0`. **`README.md`** — one endpoint-table row. **`client/`** —
  `DeleteCurrentUser` on the wrapper (returning the 409 as the `*ProblemError` it is,
  not a sentinel, per `errors.go`'s design), the transport method, and the
  regenerated `api.gen.go`.
- **`cmd/identity/main.go`** — the deletion service is built inside `buildAuth`
  because that is where the pool, the shared account store and the outbox already
  are; it uses `acctboundary.TxRunner` (so a request arriving carrying an account is
  not left standing in nobody's account) and `NewSweeper(sessions, oidc)`. With no
  pool there is no deletion service, `WithDeletion(nil)` leaves the route unmounted,
  and the deployment answers 404 rather than 500 — a fact about the deployment rather
  than an error in a user's request.

## 3. What was deliberately not done, and why

- **No `user_audit_log` row.** A deletion is self-service only, so the actor *is* the
  subject and the row would say "user X deleted themselves" — nearly content-free.
  Adding `ActionUserDeleted` to a closed set validated in Go is its own change with
  its own obligations. If an operator surface for deletions arrives, it needs a real
  actor field and this argument stops applying.
- **No anonymisation, no tombstone.** §2.3.
- **No transfer.** §2.3.
- **No `courier`/`billing` change, and there are no consumers.** The packet forbids
  modifying them and the constraint is right: cleanup of a third party's data is that
  party's decision about its own tables. A `billing` subscriber wants to move the
  customer to cancelled-and-retained rather than purged; a `courier` subscriber wants
  to stop mail to an address that no longer has a user. Neither can decide that from
  inside `identity`. The event is the handoff.
- **Not in the authorization matrix.** It walks `registerTenancyRoutes`; adding it
  there is forbidden by `TestEveryMountedRouteIsAnAccountRoute`. The session/token
  axis the matrix cannot express is covered by the handler tests instead.
- **The outbox publisher is not started.** `outbox.NewStore` ships with
  `NoopPublisher` and `main` deliberately does not start the publish loop, so in
  every current deployment these events accumulate unpublished — including the eight
  tenancy events emitted before this one. A consumer built before the publisher runs
  will see nothing and must not conclude the event does not exist.

## 4. What future consumers of `identity.user.deleted` should do

The payload is `{ "user_id": "…", "specversion": "1.0", "id": "…", "type":
"identity.user.deleted", "source": "identity", "subject": "<user_id>", "time": "…" }`.

1. **Be idempotent on `id`.** Delivery is at-least-once; `id` is the dedupe key and
   `Store.Append` uses `ON CONFLICT DO NOTHING`.
2. **Read the `user_id` as a dead reference, not a lookup key.** `GET /v1/users/{id}`
   is not a route on this service and will not become one. If you hold a customer
   record keyed by user id, decide now whether it is anonymised, tombstoned, or
   deleted — that policy is yours, and this service has no opinion on it.
3. **Do not expect the email.** It is not in the payload and cannot be: the address
   exists nowhere in the platform after this transaction.
4. **Do not re-drive deletion on a retry.** Unlike `identity.session.revoked` ("drop
   whatever you cached against them"), this event's subject no longer resolves.
   Re-driving it against a re-created account of the same id is a confusion this
   service cannot detect.
5. **Do not treat it as `identity.user.disabled`.** A disabled user is still here;
   `user_audit_log`'s `user.disabled` is the record of an *operator* turning somebody
   off. This route has no operator — the actor *is* the subject — so conflating them
   would put "they asked for it" and "we did it to them" on one wire type.
6. **Expect nothing about accounts.** The event does not say which accounts the
   person was in; at the moment it is written most of them are gone with them, and
   the survivors were never this service's to enumerate.

## 5. Tests: what exists, and the honest limit of what I know

I read every test file in the commit. Here is what they assert; **I did not run any
of them** (§7).

`internal/deletion` — 16 tests across three files:

| File | Runs against | Holds |
|---|---|---|
| `service_test.go` (4) | fakes | the four writes and their order in one transaction; the refusal naming every account; a team account the user only belongs to is never queried for ownership; a failed account removal leaves the user row |
| `sweep_test.go` (3) | fakes | the sweep is two statements, sessions first; `NewSweeper` refuses half a wiring; a sweep failure stops the deletion |
| `deletion_rls_test.go` (9) | **real policies, real FKs** (`dbtest.Pool`, the app role) | the user row goes; the membership goes and the other member's team account survives; the refusal against a real schema; the session stops authenticating; the three migration cases (pending invitation, revoked key, OIDC registration); the event exists in the same transaction; the happy path emits the event |

`internal/httpapi/deletion_test.go` — 5 tests: 204 with no body and no
`Content-Type`; 409 with a stable code and a readable detail; a 500 that does not leak
the constraint name; the anonymous 401 with the service never called; the idempotent
second call.

The boundary tests run against `dbtest.Pool` — the real `public` schema with
migrations/00016's policies live — not against `dbtest.Schema` clones, for the reason
the brief gives: the clones carry no RLS, so a deletion tested there would pass
against tables that permit what production refuses. The fixtures use per-test unique
names and register their own cleanup, because `dbtest.Pool` hands out a pool on the
migrated schema that every other package in the repository also writes to.

Two harness traps are documented in the test files themselves and are worth
recording: `t.Fatalf` inside a `UnitOfWork.Do` callback **hangs the pool** (it is
`runtime.Goexit`, so the runner never regains control, never rolls back, never
returns the connection), and an assertion on a policy-protected table needs an
identity or it is meaningless — `SELECT count(*)` on a bare pooled connection
returns 0 for "the row was deleted" **and** for "the row is right there and you may
not see it", so the RLS tests stand in as the account (`countInAccount`) and run a
positive control *before* the deletion (`mustSee`).

## 6. Things I noticed that are not blockers

The manager asked for honest eyes rather than a second author, so here is what I
found that a reader should know. None of it changes the packet's correctness as far
as I can tell without running the gate:

1. **`users.Store.DeleteForAccount`'s doc comment says the cascade fires on "six
   tables" and then lists nine** (`sessions`, `connected_accounts`, `account_users`,
   `api_keys`, `recovery_tokens`, `mfa_credentials`, `mfa_challenges`,
   `oidc_auth_requests`, `oidc_access_tokens`). A stale count in a comment; the list
   is the accurate part. Cosmetic.
2. **The earlier report quotes the coverage-exclusions line figure twice, as
   27936 (§3.4b) and 27939 (§9).** The tree is consistent — the entry's own reason
   explains both (the operation moved it to 27936, the problem-code enum to 27939)
   — so the earlier report's §3.4(b) figure was the intermediate one. No action.
3. **The earlier report's gate output was not produced against the environment the
   brief names.** The brief says the shared cluster is running on port 15500 and
   tests need only `TEST_DATABASE_URL` against it; the earlier report says the
   shared `cafaye-postgres-1` was recreated underneath that work (another worktree's
   `docker compose`, same project name) and the gate was run against a dedicated
   container on port 15519 with a `NOSUPERUSER` owner role. The reasoning given is
   sound (a bootstrap superuser has `BYPASSRLS` and then `internal/tenancy`
   correctly reports every boundary in this service as inert), but it means the
   evidence in the earlier report is not evidence about the shared cluster, and the
   manager's gate run is the one that counts in both directions.
4. **The commit message's summary is accurate.** One route, one transaction, one
   migration — plus, not mentioned in the message, the three incidental fixes in
   §2.5 and the `gofmt` bytes. The message is not wrong; it is incomplete in the
   direction of modesty.

## 7. The gate: not verified here, by instruction

I ran nothing. No `bin/prime`, no `go test`, no `go vet`, no `gofmt`, no database,
no docker — the manager's instruction, because a gate run here would contend with
another identity worker's investigation on the shared test database, and because the
previous attempt's conclusions are void.

What that means, stated plainly:

- The earlier report (§7 of `REPORT-identity-account-deletion-01.md`) contains what
  appears to be complete, verbatim gate output: 25 packages ok under `bin/prime`,
  clean `go vet` and `gofmt -race`, and `bin/coverage-floor` at 74.8% against the
  70% floor. **I cannot confirm any of it.** I did not run it, the environment it
  was run in is not the one the brief names (§6.3), and a dead attempt's evidence is
  not evidence.
- What I *can* say is weaker and still useful: the test files exist, they assert
  what §5 says they assert, the walk literals and audit rows that AGENTS.md requires
  are present in the diff, and the code I read is internally consistent with its own
  documentation. That is a reading, not a verification.
- **Verification of the gate is the manager's step, running after this report.** The
  four commands are `bin/prime`, `go vet ./...`, `gofmt -l .` (must print nothing),
  and `go test -race ./...`, with `goose up` above them and
  `TEST_DATABASE_URL="postgres://identity:cafaye@localhost:15500/identity?sslmode=disable"`
  from the `identity` service's own `DATABASE_URL` in `docker-compose.yml`. If any
  of it is red, the most likely places to look are the ones this packet touched
  most: the `internal/deletion` boundary tests against the real policies, and the
  tenancy boundary test whose race this packet fixed.
