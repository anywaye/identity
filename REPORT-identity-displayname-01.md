# REPORT-identity-displayname-01

**Packet:** identity-w20-displayname — a user has a display name, readable and writable.
**Branch:** `worker/identity-w20-displayname`
**Commit:** `cb4dbf3` (on top of `74c4b9b`)
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
from there. One defect found and fixed:

**The coverage-exclusions statement figure was wrong.** The entry
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

Also fixed: three comments that claimed `/v1/me`'s projection is exactly
two fields (`recovery.go`, `recovery_test.go`, `handleMe`'s doc comment)
— stale the day the optional third field landed.

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
ok  	github.com/cafaye/identity/client	3.982s
?   	github.com/cafaye/identity/client/generated	[no test files]
ok  	github.com/cafaye/identity/cmd/identity	3.966s
ok  	github.com/cafaye/identity/internal/accounts	32.424s
ok  	github.com/cafaye/identity/internal/admin	6.828s
ok  	github.com/cafaye/identity/internal/apikeys	27.086s
ok  	github.com/cafaye/identity/internal/auth	21.093s
ok  	github.com/cafaye/identity/internal/config	0.653s
ok  	github.com/cafaye/identity/internal/courier	1.316s
ok  	github.com/cafaye/identity/internal/httpapi	100.058s
ok  	github.com/cafaye/identity/internal/mfa	35.831s
ok  	github.com/cafaye/identity/internal/oauth	8.917s
ok  	github.com/cafaye/identity/internal/oidc	3.130s
ok  	github.com/cafaye/identity/internal/outbox	10.470s
ok  	github.com/cafaye/identity/internal/platform/ci	4.813s
ok  	github.com/cafaye/identity/internal/platform/clock	1.534s
ok  	github.com/cafaye/identity/internal/platform/db	1.582s
?   	github.com/cafaye/identity/internal/platform/dbtest	[no test files]
ok  	github.com/cafaye/identity/internal/platform/id	2.047s
ok  	github.com/cafaye/identity/internal/platform/oauthtest	2.315s
ok  	github.com/cafaye/identity/internal/recovery	27.924s
ok  	github.com/cafaye/identity/internal/sessions	2.441s
ok  	github.com/cafaye/identity/internal/telemetry	1.387s
ok  	github.com/cafaye/identity/internal/tenancy	1.062s
ok  	github.com/cafaye/identity/internal/useraudit	6.317s
ok  	github.com/cafaye/identity/internal/users	0.947s
```

Also green: `go vet ./...`, `go test -race ./...` (all 24 packages),
and the coverage floor — `bin/coverage-floor` over the whole-suite
profile: **74.8% at or above the 70% floor**.

## Notes for the manager

- **`gofmt -l .` prints three files** (`internal/platform/ci/rollback_test.go`,
  `internal/platform/ci/substrate_copy_test.go`, `internal/tenancy/user.go`).
  These are pre-existing at `74c4b9b` — verified by stashing this packet's
  changes and re-running. Left alone to keep the diff narrow; they are
  not this packet's defect.
- **The local Postgres restarted mid-run** and the database came back
  fresh, so migration 00023 had to be re-applied before the suite. The
  migration is idempotent-safe to re-apply on a fresh database via
  `goose -dir migrations postgres "$DATABASE_URL" up`.
- **Merge watch:** other workers are landing changes on `users` and
  `httpapi`. The touchpoints are `userColumns` (store.go), the `User`
  struct, the `Auth`/`UserStore` interfaces, and `registerRoutes`. The
  `userResponse` change is additive and optional, so `/v1/me` consumers
  are unaffected until they choose to read the new field.
