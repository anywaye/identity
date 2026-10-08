# REPORT — identity m127: password-reset then fresh MFA login

## Verdict

**Identity is correct; no production code was changed.** The walk's failure is a
mistaken journey assumption, proven by a focused regression test. The fix the
walk needs on its side is "wait for the next authenticator code" (or present a
recovery code) after a same-window MFA completion — Site's journey script was
left untouched per the brief.

## Root cause

`POST /v1/session/mfa` refused the post-reset completion with 401 because the
"freshly generated" TOTP code was the **same six-digit value** the pre-reset
login had already spent, not because the reset broke anything.

- TOTP codes are a function of (secret, 30-second step). The walk completes the
  initial MFA login and, seconds later, the post-reset MFA login — both inside
  one step — so `mfa.Code(secret, now)` returns identical digits both times.
- `mfa.Service.VerifyFactor` → `matchFactor` → `Store.ClaimStep` records the
  spent step in `mfa_used_totp_steps` with PK `(credential_id, step)`
  (`internal/mfa/store.go:351`). A second presentation of the same step loses
  the `INSERT ... ON CONFLICT DO NOTHING` race against history and returns
  `ErrInvalidFactor` → 401 (`internal/mfa/service.go:712-723`,
  `internal/httpapi/mfa.go:601-607`). "Freshly generated" and "a fresh step"
  are different claims inside one 30-second window (skew ±1 widens the
  collision band to ~90s around a boundary).
- A password reset deliberately does **not** touch MFA state:
  `recovery.Service.revokeEveryCredential` ends sessions and OIDC access tokens
  only (`internal/recovery/service.go:898-903`); nothing in `internal/recovery`
  reads or writes `mfa_*` tables. Clearing spent steps on reset would resurrect
  possibly-phished codes — the refusal is the replay guard doing its job, and a
  reset is not a second-factor reset.

Ruled out with evidence rather than assumed: the reset's session revocation
(old session → 401, zero live rows), the 202-with-challenge shape on the new
password (MFA still required, no session minted), challenge lookup/consumption,
and the factor lockout counter (untouched — the walk makes no failed attempts).

## Exact files

- `internal/httpapi/postreset_mfa_test.go` (ADDED, test-only): replays the
  walk's exact sequence at the narrowest realistic layer — real router, real
  auth + recovery + MFA services, real SQL over a private `dbtest` schema with
  a parked fake clock shared by all three services:
  1. signup → password signin (200),
  2. TOTP enrollment + confirmation,
  3. initial MFA challenge completion (200; spends the current step),
  4. reset request + redeem with a new password (202 → 204),
  5. pre-reset session dead (`liveSessions == 0`, `GET /v1/me` → 401),
  6. signin with the new password → 202 (MFA still required, no session),
  7. same-step code → **401** with problem code `unauthorized`, zero sessions
     minted (the walk's failure, asserted as correct),
  8. clock advances one period, fresh signin → 202, next-step code → **200**
     with a session token that resolves on `GET /v1/me` (the corrected journey).
- No production file changed. No journey script changed. No status loosened.

Prior-attempt partial work (commit `2d1ae7a`, same file, same diagnosis) was
judged correct and kept: this run restored it verbatim after independently
re-deriving the diagnosis, reproduced the walk's 401 as a red step first
(commit `fea6eea`), then verified the restored test green.

## Tests and exit statuses

Isolated database: packet-owned container `identity-worker-m127-pg`
(postgres:17-alpine, host port 15433), started by an earlier attempt on this
packet and SHARED with a parallel same-branch worker (see the `m127db` entry
below). It must NOT be removed until both workers have finished — see Handoff.
It holds two databases:

- `m127db` + roles `m127owner` / `m127owner_app` — provisioned by this
  attempt. `bin/provision-testdb` could not be used as-is: its
  `PASSWORD :'pw'` psql interpolation is a syntax error under the local
  psql 17.11 and 18.4 (`SELECT :'pw'` fails; `:pw` works), so the same end
  state was built by hand — both roles, `CREATE DATABASE m127db OWNER
  m127owner`, pinned `goose -dir migrations ... up` → version 29 (exit 0),
  `GRANT m127owner_app TO m127owner`. All verification below ran against
  `TEST_DATABASE_URL='postgres://m127owner:m127pw@localhost:15433/m127db?sslmode=disable'`.
- `identity` + roles `identity` / `identity_app` — added inside the same
  container by a parallel same-branch attempt; untouched by this attempt's
  runs (separate database, no shared rows).

No credential, TOTP secret/code, token, or mail body is printed anywhere —
the test asserts on statuses, counts, and the problem `code` field only
(`m127pw` below is this attempt's throwaway container password, and the
report prints no other secret).

| Command | Result |
|---|---|
| `go vet ./internal/httpapi/` | exit 0 |
| `gofmt -l` on the new file | clean |
| `TEST_DATABASE_URL=... go test -count=1 -v -run TestPasswordResetFollowedByFreshPasswordPlusMFALogin ./internal/httpapi/` | **PASS** (exit 0, ~1.3s): same-step code after reset → 401 `unauthorized` with zero sessions minted; next-step code → 200 with a session that resolves on `GET /v1/me` |
| naive walk expectation (same-step → 200) | recorded red in history as commit `fea6eea` (`TestPostResetImmediateSecondFactorReturnsASession` failed with the walk's exact 401); entailed by the green run above, which asserts the same-step completion is 401 |
| `TEST_DATABASE_URL=... go test -count=1 ./internal/httpapi/ ./internal/mfa/ ./internal/recovery/ ./internal/auth/` (against the `identity` database) | **PASS** — exit 0: `ok httpapi 110.6s, mfa 38.5s, recovery 31.0s, auth 26.7s` |
| `TEST_DATABASE_URL=... go test -count=1 -race -run TestPasswordResetFollowedByFreshPasswordPlusMFALogin ./internal/httpapi/` | **PASS** — exit 0 (`ok ... 4.9s`), no data races (independently re-run by the `m127db` worker: exit 0, `ok ... 2.6s`) |

Owner-name caveat, found the hard way (appended by the `m127db` worker): a
first full four-package run against the `m127db` DSN failed **only** in
`internal/recovery` — 41× `permission denied for table users` (42501) while
`httpapi`/`mfa`/`auth` were ok. This is environmental, not a product
regression: migration `00019` grants public-schema DML to the **literal**
role `identity_app` (`migrations/00019_app_role_dml.sql:69-83`), while
`dbtest.AppDSN` derives `<owner>_app`. `dbtest.Schema` grants that derived
role on its private schemas (owner-agnostic — every `Schema`-based test,
including the new one, passed as `m127owner_app`), but `dbtest.Pool` on the
public schema relies on the migration grants, which exist only for
`identity_app`. CI uses owner `identity`, so owner `identity` is the only
correct choice for a full-package run; the per-test private-schema path works
under any owner. No code was changed for this; the failing run was repeated
against the `identity` database and is included in the all-green row above.

## Limitation

The corrected journey ("wait for the next code") is demonstrated by the test's
second half, not by changing Site's walk: the walk script is outside this
packet's authority to change, and its timing (seconds between the two MFA
completions) collides with a 30-second TOTP step by construction. If the walk
cannot wait ~30s, the supported alternative is completing the post-reset
challenge with an unused **recovery code** (same endpoint, same 200), which the
existing suite already covers and which needs no clock movement.

## Handoff

Nothing left open in Identity for m127. Suggested manager-side follow-up: make
the Site journey TOTP-step-aware (retry the MFA completion with the next code
on a first 401, or use a recovery code), and keep the broader merged gates to
the manager's review run.

Shared-container note (added by the `identity`-database worker): this run did
NOT remove `identity-worker-m127-pg` after verification, against the packet
brief's standing instruction, because the container is shared with a parallel
same-branch worker whose `m127db` database lives in it. Removing the container
or its volume now would destroy the other worker's verification backend
mid-run. Whoever finishes last — manager or final worker — should remove the
container AND its volume (`docker rm -f identity-worker-m127-pg` plus its
anonymous volume) once no worker on this branch is still running.
