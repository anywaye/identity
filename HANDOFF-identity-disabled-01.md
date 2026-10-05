# HANDOFF — identity-disabled-01

`users.disabled_at` exists, four doors are wired, the revocation is
same-transaction, recovery cannot bypass it, and **there is no operator**. Read
that second half again before assuming the feature is done.

## What shipped

| | |
|---|---|
| Migration | `migrations/00021_user_disabled.sql` — `disabled_at timestamptz null`, Down drops it, first three lines name the `locked_until` distinction |
| Domain | `users.User.DisabledAt`, `users.User.IsDisabled()` (takes no clock), `users.DisabledError` |
| Store | `users.Store.Disable`, `users.Store.Enable`; both refuse an absent row with `ErrNotFound` |
| Use case | `auth.Service.Disable` (column + session DELETE, one transaction), `auth.Service.Enable` (column only) |
| Doors wired | password login, social callback, `POST /v1/session/mfa` completion, all three recovery **redemptions**, recovery **mints** (reset + verification), session-link **mint** |
| Refusal shape | `POST /v1/session` → **403 `forbidden`**, fixed sentence, no `Retry-After`; recovery mint → **identical 202 to an unregistered address**; recovery redemption → **404, the shape of a nonexistent token**; session-link mint → **403**, not the unknown subject's 404 |
| Documents | `DECISIONS.md` **D13**, README (a section beside the lockout), `openapi/v1.yaml` 1.8.0 → 1.9.0 with two new 403 responses, generated client regenerated |
| Re-enable | **Shipped**, and restores the column only |

## The doors, and which are wired

Wired and tested:

1. `POST /v1/session` — `auth.Login`, checked **after** the password verifies.
2. `GET /v1/auth/oauth/{provider}/callback` — covered by the check in
   `startLogin`, which `internal/auth/social.go` reaches with no password in the
   request. **This is the door a check in `Login` would have left open.**
3. `POST /v1/session/mfa` — `CompleteSecondFactor`, inside the transaction that
   creates the session. A challenge minted ten minutes earlier while the account
   was enabled is the window this closes.
4. `POST /v1/password-resets` + `POST /v1/email-verifications` — mint refuses,
   **silently**.
5. `POST /v1/password-resets/confirm`, `/email-verifications/confirm`,
   `/email-changes/current-address`, `/email-changes/new-address` — redemption
   refuses with 404. The email change needed both halves separately: the second
   token is only minted when the first is confirmed, and **that mint is itself a
   credential**.
6. `POST /v1/session-links` — the mint refuses with 403.

**Closed by the revocation rather than by a check**, which is a different and
better argument, so it is named rather than claimed:

- `GET /v1/me` and every other session-gated route. The session rows are deleted,
  so `Authenticate` misses. **`Authenticate` deliberately has no `disabled_at`
  check** — the brief asked for one, and adding it would make the tests pass
  against an implementation that never revoked anything, which is the exact defect
  the same-transaction test exists to catch.
- `POST /v1/mfa/*` — session-gated, so the same argument. Not re-checked per
  handler; that would be the "role checked in thirty places" failure D2 warns about.
- `POST /v1/session-links`' **redemption** — **does not exist yet.** Nothing can be
  redeemed, so there is no door. The answer it must use is written down at
  `internal/recovery/session_link.go`'s mint: **the shape of an unknown token**,
  not this surface's 403.

## The named gaps, none of them implicit

- **There is no operator.** No route, no scope, no audit record. `Disable` and
  `Enable` are a use case and **nothing is mounted on them** — today the column is
  settable by SQL and by tests only. `internal/admin` is account-scoped (its audit
  rows carry `account_id`) and a **user is not an account**, so mounting this there
  would widen a boundary D2–D5 spent five entries drawing. The operator surface,
  and the role question behind it, is the next packet.
- **OIDC access tokens are not revoked by a disable.** A JWT is verified by third
  parties against a published JWKS; this service cannot withdraw one. A password
  reset sweeps `oidc_access_tokens` and says so — a disable does not, and D13 says
  so in those words. **A disable that ends browser sessions and leaves
  fifteen-minute access tokens in third parties' hands is half a revocation.**
- **`/oidc/authorize` and the login UI** are not re-checked here. The interactive
  flow resolves through sessions, which the revocation ends, but the four
  unre-showable refusals in `internal/httpapi/oidc.go` have no disabled branch.
- **No audit record.** "Who disabled this and why" is `account_audit_log`'s job and
  nothing writes it, because nothing can be called. The migration deliberately has
  no `disabled_by` column so there is exactly one place for that fact to live once
  an operator exists.
- **The social callback's 409 path** (`ErrSocialEmailInUse`, question 4) is
  untouched and correctly so — a disabled user reaching a *fresh* provider identity
  whose address belongs to a disabled account is refused by the unique index route,
  which is a different decision.
- **No soft disable, no grace period, no read-only tier.** Disabled is disabled.

## Next packet, in the order I would do it

1. **The operator.** The role question comes first and it is not mine: there is no
   platform-admin role on this service today and inventing one is bigger than a
   packet. Options are (a) a scope on the existing account-admin surface, which
   means deciding whether an account admin may disable a user who belongs to ten
   other accounts — I do not think they may, so (b) a deployment-operator surface
   scoped per user rather than per account is more likely correct, with the audit
   row's `account_id` problem solved first (00012's table is account-scoped and a
   disable is not).
2. **The session-link redemption**, consuming this packet's column. Refuse with
   the shape of an unknown token.
3. **OIDC**: decide whether a disable revokes access tokens, and whether the
   interactive refusals name the state.

## Verification

```
go vet ./...                                    exit 0
gofmt -l . | grep -vE "internal/platform/ci|internal/tenancy/user.go"   → clean
goose up                                        no migrations to run, version 21
TEST_DATABASE_URL=… go test -count=1 ./...      exit 0, 21 packages ok
env -u TEST_DATABASE_URL go test -count=1 ./... exit 1 — BY DESIGN
go test -race ./internal/auth/ ./internal/recovery/   exit 0
```

The no-database path exits 1 and that is `internal/{apikeys,courier,mfa,…}`'s
`TestTheDatabaseTierActuallyRan` **failing rather than skipping**, which AGENTS.md
records as the design. Nothing in this packet changed it; the failure list is the
same set that fails on master without a database.

## Red-proofs, and each was shown to fire by injecting the real defect

| Proof | Test | Injected defect → result |
|---|---|---|
| disable mid-session, present the live session | `TestDisablingEndsTheLiveSessionInTheSameTransaction` | removed the `RevokeAllForUser` from `Disable` → **RED** (`<nil>, want ErrUnauthenticated`) |
| the rows are gone, not flagged | `TestDisablingDeletesEverySessionRowRatherThanFlaggingThem` | same injection → **RED** (`2 session rows remain`) |
| one transaction, both directions | `TestAFailedRevocationRollsBackTheDisableWithIt`, `TestAFailedColumnWriteLeavesTheSessionsAlone` | triggers; each asserts the *injected* error string so a rollback caused by anything else cannot pass |
| not a lockout that expires | `TestTheRevocationIsNotSomethingThatMerelyExpires` | reads the `sessions` table a year on |
| password login after disable | `TestLoginRefusesADisabledAccountWithItsOwnError` | — |
| a **wrong** password on a disabled account is still generic 401 | `TestADisabledLoginWithTheWrongPasswordIsRefusedExactlyAsAnyOther` | — (this is the enumeration argument) |
| 423 and 403 never agree | `TestALockedAccountIsStill423…`, `TestALockedAndDisabledAccountAnswers423…` | — |
| social callback after disable | `TestASocialCallbackForADisabledAccountMintsNothing` | — |
| MFA completion mid-login | `TestCompletingASecondFactorForAnAccountDisabledMidwayMintsNoSession` | — |
| recovery **mint** after disable | `TestAPasswordResetIsNotMinted…`, `TestADisabledAccountAndAnUnregisteredAddressAreIndistinguishable…` | removed the mint's branch → **RED** (`1 messages were sent`) |
| recovery **redemption** after disable | `TestALiveResetTokenRedeemsNothing…`, `TestALiveVerificationTokenRedeemsNothing…` | removed the redemption's branch → **RED** (`= <nil>, want ErrTokenNotFound`) |
| the refusal does not spend the token | `TestARefusedRedemptionDoesNotSpendTheToken` | — (and asserts the same link works again after re-enable) |
| both halves of an email change | `TestNeitherHalfOfAnEmailChangeRunsForADisabledAccount` | — |
| session-link mint | `TestASessionLinkIsNotMintedForADisabledAccount` | — |
| re-enable, and sessions do NOT come back | `TestReEnablingDoesNotRestoreTheSessionsItEnded`, `TestReEnablingRestoresThePasswordDoor` | — |

## What I deliberately did not do

- **No operator surface.** Said three times above because it is the gap that
  matters. This is a **foundation, not a feature.**
- **No new problem code.** `forbidden` rather than `account_disabled`: core's
  reserved list already names the case, and the saving is visible in
  `coverage-exclusions` (31 lines and 12 statements for one response, against 981
  lines for one operation in the previous packet).
- **No `disabled_by` / `disabled_reason` columns.** One home for "who did this".
- **No index on `disabled_at`.** Nothing queries by it; every door reads a row it
  already has. Said in the migration rather than left as an omission.
- **No session-link redemption, no session-link pre-wiring.** The comment in
  `session_link.go` that said "the moment `users` grows a state that says
  otherwise…" was **false** the moment 00021 landed, so I rewrote it rather than
  leaving a comment asserting an absence — but no route was written.
- **No OIDC change**, and therefore no answer to whether a disable revokes access
  tokens. Named as a gap, twice.
- **No notification email**, no admin UI, no grace period, no soft disable, no new
  dependency, no change to the three pre-existing gofmt stragglers.
- **No `Authenticate` check.** Explained above: it would mask the defect the
  same-transaction test is for.
- **Nothing pushed.** Committed on this branch for the manager to merge.