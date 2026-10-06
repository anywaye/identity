# REPORT-identity-displayname-01

**Packet:** identity-w20-displayname — a user has a display name, readable and writable.
**Branch:** `worker/identity-w20-displayname`
**Commits:** `cb4dbf3` (implementation) + `36900c5` (first report) + this review's fix commit (below)
**Date:** 2026-10-06

## What shipped

| Piece | Where |
|---|---|
| Migration | `migrations/00023_user_display_name.sql` — nullable `text` column, no default, no unique constraint, no index |
| Domain | `internal/users/users.go` — `User.DisplayName *string`, `MaxDisplayNameLength = 64`, `ValidateDisplayName` |
| Store | `internal/users/store.go` — `UpdateName(ctx, q, userID, name *string)`; `userColumns` and both scans updated |
| Use case | `internal/auth/service.go` — `Service.UpdateDisplayName`; `UserStore` interface extended |
| Handler | `internal/httpapi/auth.go` — `handleUpdateMe`, `PATCH /v1/me`, `userResponse.DisplayName` with `omitempty` |
| Contract | `openapi/v1.yaml` — `updateCurrentUser` operation; `User` schema gains optional `display_name` |
| Client | `client/` regenerated (oapi-codegen v2.8.0, pinned) |
| Docs | `README.md` endpoint table; `coverage-exclusions` restated |

## The previous attempt's partial work

The worktree held a complete, correct implementation from the previous
attempt. I reviewed every file, kept all of it, and finished the packet
from there. Three defects found and fixed in review:

**1. The coverage-exclusions statement figure was wrong.** The entry
claimed the generated file held 6418 statements before and after this
packet ("6418 to 6418 — 0 statements"). Measured the way the entry
itself prescribes (`go test -coverprofile` over `./client/generated/`,
summing `numStmt`), the tree holds **6528** statements. The entry says
the figure is measured rather than carried forward, so it now says
6528, and the delta is recorded as 110 statements (the generated parse
function's per-status `json.Unmarshal` calls and header bindings — four
documented statuses, a new parse function, unlike identity-disabled-01's
two responses that extended an existing one). The `lines=` figure
(28016) was correct and is the one under test. The floor did not move.

**2. The no-index test could never fail.** `TestDisplayNameCarriesNoIndexAndNoUniqueConstraint`
counted indexes with `c.relname = 'users'` — the index's OWN name, which
can never equal the table's name in the same schema. The count was
always 0, so the test would have passed against a database where
someone had added an index on the column: a comparison that never fires
is indistinguishable from a correct one. Fixed with a schema-filtered
query over `pg_index` (which covers unique constraints too, since a
unique constraint is implemented as an index) plus a CONTROL: the same
query shape run against `email` must find `users_email_key`, proving
the query can find an index when one exists.

**3. The document promised a refusal the handler does not make.** The
OpenAPI marked `display_name` as `required` in the request body, but
the handler deliberately decodes an omitted field as the empty string
(which clears) — the route has exactly one field, so there is no "leave
it unchanged" to express. Fixed by dropping `required` from the
document, which is the direction the repo's drift rule cares about: a
document must not promise what the router does not deliver. The
regenerated client's request field moved from `string` to `*string`
with `omitempty` — the same set-or-clear semantics the handler has, and
a change that breaks no one because the method is new. The
coverage-exclusions entry was restated a second time (28021 lines,
6528 statements unchanged — five lines, all of them the property
description the generator copies into the struct's comment).

Also fixed: three comments that claimed `/v1/me`'s projection is exactly
two fields (`recovery.go`, `recovery_test.go`, `handleMe`'s doc comment)
— stale the day the optional third field landed — and one redundant,
imprecise sentence in `updateMeRequest`'s doc comment.

## Design decisions

- **NULL is the one "no name".** No default, no backfill, no `''`. A
  second representation of the same state is a second thing to disagree
  with the first. Same argument as `email_verified_at` (00014) and
  `disabled_at` (00021).
- **Not an identifier.** No unique constraint, no index. Nothing looks a
  user up by name; the email is the identifier and it is the one with the
  unique index. `TestUsersHasExactlyOneApplicationUniqueIndexAndItIsOnEmail`
  still passes.
- **Empty string clears.** The column returns to NULL. The two ways of
  asking for "nothing" (empty string, omitted field) both arrive at the
  store as nil.
- **Length enforced in the handler**, where the refusal is a 422 naming
  the field (`validation_failed` / `too_long` on `display_name`) rather
  than a 500 from a database constraint. The store does not re-check.
- **`display_name` omitted when unset** in `GET /v1/me`, not null. A
  client written against the two-field response cannot tell a user with
  no name from a user whose name this service has never heard of; a
  null would be a third answer to "what is this person called".
- **The write lives on `auth.Service`**, not the handler: the read half
  (`Authenticate`) is there, and a handler reaching for a pool to write
  one field would be a second composition root for the same row.
- **No scope row needed.** `/v1/me` is session surface, not an account
  route; `accountRouteScopes` and the authorization matrix are
  account-scoped and unchanged. The anonymous enumeration audit gained
  the `PATCH /v1/me` row (401 — no identifier arrives from a stranger).

## Evidence the tests fail without the fix

Stashing the implementation (store, domain, use case, handler, schema,
client, exclusions, README) and keeping the tests:

```
internal/users/store_test.go:332:13: created.DisplayName undefined (type User has no field or method DisplayName)
internal/users/store_test.go:360:18: store.UpdateName undefined (type *Store has no field or method UpdateName)
internal/auth/service_test.go:140:4: u.DisplayName undefined (type users.User has no field or method DisplayName)
internal/auth/service_test.go:1227:18: f.svc.UpdateDisplayName undefined (type *Service has no field or method UpdateDisplayName)
internal/httpapi/auth_test.go:984:9: f.user.DisplayName undefined (type users.User has no field or method DisplayName)
FAIL	github.com/cafaye/identity/internal/users [build failed]
FAIL	github.com/cafaye/identity/internal/auth [build failed]
FAIL	github.com/cafaye/identity/internal/httpapi [build failed]
```

The tests cannot compile against the base tree — the symbols they
exercise do not exist. With the implementation restored, all three
packages pass.

## Gate

`bin/prime` (with `TEST_DATABASE_URL` set, migrations applied):

```
ok  	github.com/cafaye/identity/client	2.258s
?   	github.com/cafaye/identity/client/generated	[no test files]
ok  	github.com/cafaye/identity/cmd/identity	2.747s
ok  	github.com/cafaye/identity/internal/accounts	20.287s
ok  	github.com/cafaye/identity/internal/admin	5.650s
ok  	github.com/cafaye/identity/internal/apikeys	16.919s
ok  	github.com/cafaye/identity/internal/auth	13.563s
ok  	github.com/cafaye/identity/internal/config	0.638s
ok  	github.com/cafaye/identity/internal/courier	1.258s
ok  	github.com/cafaye/identity/internal/httpapi	53.770s
ok  	github.com/cafaye/identity/internal/mfa	17.839s
ok  	github.com/cafaye/identity/internal/oauth	4.689s
ok  	github.com/cafaye/identity/internal/oidc	2.122s
ok  	github.com/cafaye/identity/internal/outbox	4.891s
ok  	github.com/cafaye/identity/internal/platform/ci	3.362s
ok  	github.com/cafaye/identity/internal/platform/clock	0.564s
ok  	github.com/cafaye/identity/internal/platform/db	0.945s
?   	github.com/cafaye/identity/internal/platform/dbtest	[no test files]
ok  	github.com/cafaye/identity/internal/platform/id	1.176s
ok  	github.com/cafaye/identity/internal/platform/oauthtest	0.955s
ok  	github.com/cafaye/identity/internal/recovery	15.210s
ok  	github.com/cafaye/identity/internal/sessions	1.256s
ok  	github.com/cafaye/identity/internal/telemetry	0.713s
ok  	github.com/cafaye/identity/internal/tenancy	0.952s
ok  	github.com/cafaye/identity/internal/useraudit	3.598s
ok  	github.com/cafaye/identity/internal/users	1.271s
```

Also green: `go vet ./...`, `go test -race ./...` (all 24 packages),
and the coverage floor — `bin/coverage-floor` over the whole-suite
profile: **75.1% at or above the 70% floor**.

## Notes for the manager

- **`gofmt -l .` prints three files** (`internal/platform/ci/rollback_test.go`,
  `internal/platform/ci/substrate_copy_test.go`, `internal/tenancy/user.go`).
  These are pre-existing at `74c4b9b` — verified by stashing this packet's
  changes and re-running. Left alone to keep the diff narrow; they are
  not this packet's defect.
- **The tenancy test flaked once under the full suite** and it is worth
  knowing about for the merge: `TestTenancyIdentityOwnsItsFiveTables`
  queries `pg_class` by `relname` with NO schema filter, so any
  `test_*` schema left on the shared cluster by a concurrent worker's
  dbtest run matches — and while another worker's suite was running
  against the same cluster, one such schema's `oidc_clients` row
  (RLS off) was scanned first and the test failed. It passes when run
  alone and passed on the final full run. Not this packet's defect, but
  it will bite other packets too until the query gets a schema
  predicate.
- **The coverage-exclusions reader works.** My first restatement of the
  entry put ASCII double quotes inside the quoted `reason="..."` string,
  terminating it early; `bin/coverage-floor` rejected the entry
  outright. The reader caught a malformed declaration on the spot,
  which is the failure this file exists for.
- **Merge watch:** other workers are landing changes on `users` and
  `httpapi`. The touchpoints are `userColumns` (store.go), the `User`
  struct, the `Auth`/`UserStore` interfaces, and `registerRoutes`. The
  `userResponse` change is additive and optional, so `/v1/me` consumers
  are unaffected until they choose to read the new field.
