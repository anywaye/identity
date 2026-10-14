# REPORT-m147-identity-system-admin.md

Packet m147: Identity's human staff surface for the Parlor system-admin console.
Branch `m147-identity-system-admin`. Q1 commit `594b599`; this report covers the
incremental commit on top of it.

## What shipped

- `users.is_staff` (migration `00030`, applied cleanly to a scratch Postgres 18
  via `goose up` → `successfully migrated database to version: 30`): boolean,
  `NOT NULL DEFAULT false`, dropped on `Down`.
- `users.Store.SetStaff` — only writer of the column; sole caller is
  `cmd/identity-staff` (`grant`/`revoke`/`status`, `DATABASE_URL` in hand).
  No HTTP route writes the column (`CreateParams` has no staff field; new rows
  read `IsStaff=false`, pinned by `TestANewUserIsNotStaff`).
- `users.Store.Search`: bounded substring over email/display_name, LIKE-escaped,
  `LIMIT` clamped to `[1, 50]`; returns `DirectoryEntry{id, email,
  display_name, disabled_at, email_verified_at, created_at}` (nullable
  timestamps as `*time.Time`, no credential material).
- Staff HTTP surface (`internal/httpapi/staff.go`, mounted unconditionally off
  `auth`): `GET /v1/operator/me` → `200 {user:{id,email,staff:true}}`;
  `GET /v1/operator/users?query=&limit=` → `200 {users:[...]}` (`[]` when
  empty; timestamps present-as-null); `POST
  /v1/operator/users/{id}/disable|enable` → `204` via the existing
  `auth.Service` transaction with `{ActorUserID: staff, ActorKeyID: nil,
  TraceID}`. Gate: machine key → 403, non-staff (incl. tenant admins) → 403,
  anonymous/bad session → 401; gate runs before subject parsing.
- `useraudit.Actor`: zero `KeyID` is a human-session row (`HumanSession()`),
  user+trace still required; machine gate (`operatorActorFrom`) keeps the
  strict promise (500 on zero key).
- Contract chain: `openapi/v1.yaml` 1.13.0 (4 ops, `OperatorMe`,
  `StaffDirectory`, `StaffDirectoryEntry` with `type: [string, "null"]`
  timestamps), regenerated client (all 41 old methods intact + 4 new),
  `Transport` + `Client` wrappers, README rows (spelled without query string
  per the claims reader), CHANGELOG entry, version pin `1.13.0`,
  `coverage-exclusions` restated (lines 29644→31055 measured, statements
  6875→7280 measured from coverprofile numStmt sum), `gate.yml` db-tier gains
  `cmd/identity-staff`.
- `Dockerfile` builds/copies `/app/identity-staff` beside `/app/service`;
  ENTRYPOINT unchanged. `cmd/identity-staff/packaging_test.go` holds the shape
  without Docker. README documents the one-shot k3s Job (same image, command
  override, `envFrom` the existing `identity-secrets` secret that already
  carries `DATABASE_URL`).
- `DECISIONS.md` **D19** revises D14's "no platform-admin role" for this
  surface; D14/machine routes untouched.

## Verification (exact, narrow only — no bin/prime, no Docker, no full gate)

- `set -o pipefail; TEST_DATABASE_URL="postgres://identity:cafaye@localhost:55433/identity?sslmode=disable" go test ./internal/users/ ./internal/useraudit/ ./cmd/identity-staff/ -count=1` →
  `ok users 0.922s`, `ok useraudit 3.474s`, `ok cmd/identity-staff 1.591s`,
  PIPELINE-EXIT=0 (scratch Postgres 18 cluster in $TMPDIR, trust auth, roles
  `identity` (superuser, scratch only) + `identity_app`, DB `identity`,
  migrations 1–30 applied).
- `TEST_DATABASE_URL=... go test ./internal/httpapi/ -count=1` → `ok` (27.5s;
  includes new staff suite, drift both directions, README claims, census walk
  + anonymous probes through real services).
- `go test ./client/ -count=1` → `ok` (regen, transport coverage, leak sweep).
- `TEST_DATABASE_URL=... go test ./internal/auth/ -count=1` → `ok` (7.2s).
- `go test ./internal/platform/ci/ -run 'TestTheCoverageExclusionIsOnlyGeneratedCode|TestTheDeclaredDbTier'` → both PASS.
- `go vet` on all touched packages → clean; `gofmt -l` → empty;
  `GOOS=linux go build ./cmd/identity-staff/` → OK.
- Without `TEST_DATABASE_URL`, the 5 DB tests in `cmd/identity-staff` SKIP
  (dbtest harness behavior); pure tests (parse, packaging) PASS. The
  manager-observed full-`./...` failures without a database (`apikeys`, `mfa`,
  `courier`, `recovery`, `TestTheDatabaseTierActuallyRan`) are the repo's
  by-design red without Postgres, unrelated to this packet; re-running the
  four checks that named this packet's files (README claims, version pin,
  coverage-exclusions, db-tier) now passes — see above.

## Not done / handoff notes

- `cafe contract lint` not run (core repo not in scope here); document validates
  against the repo's own reader + examples tests.
- No Docker build run: packaging is asserted by `packaging_test.go` only.
- D19 notes two open items: console read of `user_audit_log` (needs a `List` +
  index per 00022's plan) and ending live sessions on staff revoke.
- Scratch Postgres left running on port 55433 (`$TMPDIR/pg-m147`); disposable.

## Correction commit (m147b, comment-only)

- `0251c70` — "m147b: staff decision cross-references point to D19, not D17".
  The staff ADR landed as D19 (D17 already governs the `created_at` clock);
  three staff sentences still named D17 and now name D19. Changed files only:
  `README.md` staff-console section, `internal/httpapi/staff.go` package
  comment, `migrations/00030_user_is_staff.sql` header comment (one line each,
  no behavior/document/migration change).
- Checks: `git diff --check` → clean (exit 0); exact `rg` over the three
  files → `D17` matches: none; `D19` matches: one per file
  (`README.md:880`, `staff.go:25`, `00030_user_is_staff.sql:8`). Remaining
  `D14` hits in those files are the machine-routes decision, untouched by
  design. No build, unit suite, Docker, or prime run (comment-only repair).
