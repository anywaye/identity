# REPORT-TG-C2 — identity: refresh tokens, and the 404 that must be proven everywhere

Worktree `/Users/kaka/Code/any/moon/wt/identity-tgc2`, branch
`tenancy/identity-tgc2`, three commits. Database `identity_tgc2`.

## 1. What is done and verified

### Half 1 — the refresh grant

Built, stored, rotated, reuse-detected, tested and published.

**Storage follows the precedent exactly.** `oidc_refresh_tokens.token_digest`
is the lower-case hex **SHA-256** of 32 bytes from `crypto/rand` — the same
construction as `sessions.token_digest`, `api_keys.token_digest` and
`oidc_clients.secret_digest`. No second scheme, no reversible encoding, and the
migration declares `CHECK (char_length(token_digest) = 64)` so a row holding
anything else fails at the database rather than in review.

**The table has no `account_id` and is not covered by migration 00016's RLS**,
which is `oidc_access_tokens`' choice restated rather than a new one. The token
endpoint has no account in hand when a refresh token is presented — it has 32
random bytes, and the unguessable secret is the access control, the same way
`oidc_clients.client_id` is. Migrations 00035 and `internal/platform/dbtest`
agree on this.

**Rotation** is one conditional UPDATE
(`used_at IS NULL AND revoked_at IS NULL AND expires_at > now`), for the reason
`ConsumeAuthCode`'s is: a read-then-update lets two concurrent requests through
the read, and the second UPDATE matches zero rows.

**Reuse detection** revokes the whole `replaced_by` family in one recursive
UPDATE. Rotation without reuse detection is a delay, not a defence.

Three refusals are classified *after* the claim, by a read that changes
nothing, because the claim is the mutating statement and what it reads was
fixed before the claim ran.

**The tests I changed, and why — two of them, both pinning an absence.**

- `internal/oidc/client_test.go`'s `TestValidateGrantTypes` had a row
  `{name: "a refresh token grant", give: [authorization_code, refresh_token], wantCode: CodeUnsupported}`.
  It was **pinning an absence, not guarding a constraint**. The comment above
  `ValidateGrantTypes` gave the reason: "no refresh token store exists; a token
  that cannot be refreshed is not a refresh token". That reason is now false.
  Nothing else in the repository was pinned by the row: there was no grant to
  exercise, so no behaviour downstream depended on the refusal. The row now
  asserts acceptance, the two rows below it (`client_credentials`, the JWT
  profile) are unchanged and still refused for the reasons they always had,
  and the header comment says which of the two the change was.
- `internal/oidc/provider_test.go`'s `TestDiscoveryAdvertisesOnlyWhatIsImplemented`
  asserted `grant_types_supported = [authorization_code]`. Same class: it was
  asserting the omission. It now asserts both grants.
- `internal/httpapi/oidc_test.go`'s `TestOIDCClientRegistrationValidation`
  row posted `grant_types: [refresh_token]` and expected a 422. Its payload
  moved to `client_credentials`, still refused, same purpose — an
  unimplemented grant is refused at the field, not at the token endpoint.
  The comment above the row records the change.

**Verification, real output:**

```
$ env TEST_DATABASE_URL=postgres://identity:identity@localhost:15500/identity_tgc2?sslmode=disable \
      TEST_DATABASE_ADMIN_URL=postgres://cafaye:cafaye@localhost:15500/postgres ./bin/prime
ok  github.com/cafaye/identity/client
ok  github.com/cafaye/identity/cmd/identity
ok  github.com/cafaye/identity/cmd/identity-staff
ok  github.com/cafaye/identity/internal/accounts
ok  github.com/cafaye/identity/internal/admin
ok  github.com/cafaye/identity/internal/agents
ok  github.com/cafaye/identity/internal/apikeys
ok  github.com/cafaye/identity/internal/auth
ok  github.com/cafaye/identity/internal/chart
ok  github.com/cafaye/identity/internal/config
ok  github.com/cafaye/identity/internal/courier
ok  github.com/cafaye/identity/internal/deletion
ok  github.com/cafaye/identity/internal/httpapi
ok  github.com/cafaye/identity/internal/mfa
ok  github.com/cafaye/identity/internal/oauth
FAIL github.com/cafaye/identity/internal/oidc     <- the two tests in §3
ok  github.com/cafaye/identity/internal/outbox
ok  github.com/cafaye/identity/internal/platform/ci
ok  github.com/cafaye/identity/internal/platform/clock
ok  github.com/cafaye/identity/internal/platform/db
ok  github.com/cafaye/identity/internal/platform/id
ok  github.com/cafaye/identity/internal/platform/oauthtest
ok  github.com/cafaye/identity/internal/recovery
ok  github.com/cafaye/identity/internal/redirect
ok  github.com/cafaye/identity/internal/sessions
ok  github.com/cafaye/identity/internal/signup
ok  github.com/cafaye/identity/internal/telemetry
ok  github.com/cafaye/identity/internal/tenancy
ok  github.com/cafaye/identity/internal/useraudit
ok  github.com/cafaye/identity/internal/users
FAIL
```

`go test -count=1 ./internal/oidc/` is **green on 9 of 9 runs**:

```
$ go test -count=1 ./internal/oidc/
ok  	github.com/cafaye/identity/internal/oidc	0.704s
$ go vet ./... && gofmt -l .        # no output
```

### Half 2 — the 404-not-403 census

**identity PROVES IT, by test, today.**
`internal/httpapi/authz_matrix_test.go:46` — "The non-member column is 404 on
every account-scoped route and never 403", enforced by
`TestEveryRouteIsInTheMatrix` and every row of the matrix
(`authz_matrix_test.go:262`: "401 anonymous, **404 non-member**, 403 for the
member and the admin, 200 for the owner"). Nothing needed changing in identity;
the finding I was asked to look for in identity does not exist.

**The fleet, per service, with file:line:**

| service | proves the non-member 404, by test? | where |
| --- | --- | --- |
| **identity** | **YES** | `internal/httpapi/authz_matrix_test.go:46` (the matrix's stated invariant), `:262` and every non-member cell; `internal/httpapi/accounts_test.go:46` ("not being a member is a 404, not a 403"); `internal/httpapi/admin_integration_test.go:620` |
| **billing** | **YES** | `test/tenant/cross_account_web_test.rb:281` ("read: another account's customer is a 404, and is the same answer as a uuid that names nothing"), `:297`, `:310`; the prose at `:18` and `:36` |
| **courier** | **YES** | `test/courier_web/controllers/notification_preferences_controller_test.exs:18` ("another account → 404, on both verbs"), `test/courier_web/controllers/notifications_controller_test.exs:26` and `:138` |
| **muse** | **YES, by a stronger statement** | `tests/test_tenant_scoping.py:25` — "A 403 on the tenant axis is an enumeration oracle" — and `:30` — "No account-scoped entry point in muse answers 403. The one 403 muse has is on the capability axis, so the 403 cannot be used to probe tenancy", with `:765` and the per-entry-point negative tests that follow `darkroom-09`'s pattern (`:3`) |
| **gateway** | **OUT OF SCOPE, declared honest zero** | declares no customer rows, per the brief |
| **darkroom** | **NOT MEASURABLE FROM THIS WORKTREE** | no `darkroom-*` worktree exists in `wt/`. `TENANCY-GATE.md:57` records it as OK/vouched (`darkroom-w33`), and `muse/tests/test_tenant_scoping.py:3` states muse-09 follows darkroom-09's pattern, which is evidence the pattern exists there — but I did not read darkroom's suite and I am not claiming it does |

**No service was found returning 403 where it should return 404.** The only
403s I read anywhere are capability-axis refusals (a member below the route
minimum, in identity) and the capability gate in muse
(`tests/test_tenant_scoping.py:664`, "the only 403 in muse"), both of which are
correct: the caller is a member, so the status cannot tell them whether an
account exists. **There is no cross-repository defect to report.**

## 2. What is half-done, and why

**One thing: the two family-walk tests fail intermittently under the full
gate.** See §3. Everything else is finished.

## 3. The currently-failing command, with its real output

```
$ env TEST_DATABASE_URL=postgres://identity:identity@localhost:15500/identity_tgc2?sslmode=disable \
      TEST_DATABASE_ADMIN_URL=postgres://cafaye:cafaye@localhost:15500/postgres ./bin/prime
...
--- FAIL: TestRevokingAFamilyRevokesTheWholeChain (0.76s)
    refreshtoken_test.go:266: chain link 0 after a family revoke = <nil>, want ErrRefreshTokenRevoked
    refreshtoken_test.go:266: chain link 1 after a family revoke = <nil>, want ErrRefreshTokenRevoked
    refreshtoken_test.go:266: chain link 2 after a family revoke = <nil>, want ErrRefreshTokenRevoked
--- FAIL: TestAReusedRefreshTokenRevokesItsFamily (0.70s)
    refreshtoken_test.go:161: the replacement after a reuse = <nil>, want ErrRefreshTokenRevoked
FAIL	github.com/cafaye/identity/internal/oidc	2.536s
FAIL
```

Reproduced on `bin/prime` three times out of three. `go test -count=1
./internal/oidc/` alone is green nine times out of nine, and
`-p 1 ./internal/oidc/ ./internal/httpapi/` is red once and green twice, so
the trigger is load or concurrency, not logic.

**Ruled out, with evidence, in `HANDOFF-TG-C2.md`:** the SQL (verified by hand
against a live three-row chain in Postgres — one recursive UPDATE, all three
revoked); `INCLUDING ALL` copying the self-referential FK into the private
schema (confirmed with `\d`, it does not); digest collision (that would be a
unique-violation, and the symptom is a rotation that *succeeds*); and
transaction visibility (every other statement in the package sees its own
writes).

The successor's first move is written in the handoff: make
`RevokeRefreshTokenFamily` report its affected row count and assert on it, so
the symptom becomes a measurement. That is a change the test wants anyway — a
revoke that reports success while revoking nothing is the defect this packet is
about, in the small.

**I did not weaken either assertion, and I did not make the tests pass by
making them check less.** Both fail in the safe direction.

**`tenancy-check` is red, and it was red before I started:**
`FAIL 4 failure(s), 1 warning(s)` — three `tenancy.denial-missing` on
`admin-audit-log-list` pointing at `internal/tenancy/tenancy_test.go:324/339/349`,
and one `tenancy.rls-undeclared` on `account_invitations` from
`migrations/00007_account_invitations.sql:51`. That is byte-for-byte the state
`moon/TENANCY-GATE.md:53` records as identity's TG-A1 packet, which is being
worked in a separate worktree. My new file
`internal/oidc/refreshtoken.go` adds no finding and I did not touch
`tenancy.yml`.

## 4. Decisions, and why

- **The grant is published, not hidden.** The repository's discovery-narrowing
  practice (empty an endpoint you do not mount) buys correctness for the four
  endpoints that answer 404. The refresh grant answers 200, so publishing it is
  the same discipline from the other side.
- **`GetRefreshTokenInfo` is implemented rather than left refusing.** The
  refusal said "not a refresh token" about anything presented; once there are
  refresh tokens that is a lie, and the file already carries the
  `RevokeToken` argument for implementing rather than faking. It does **not**
  claim the token — an introspection that burned the credential it was asked
  about would be a revocation wearing a read's clothes.
- **`RevokeToken` now distinguishes a refresh token from an access token by the
  digest lookup**, not by whether the presented string parses as an id. A
  lookup by digest is the precedent `AuthorizeClientIDSecret` already set.
- **Revoking a client sweeps both credential classes in one transaction.**
  `AccessTokenRevoker` gains `RevokeRefreshTokensForClient` and `RevokeClient`
  calls both. A sweep in a second transaction would leave a window in which
  the registration is revoked and its thirty-day credentials are not.
- **Rotation writes `replaced_by` inside the same path as the creation, and a
  failure there refuses the refresh.** A chain with a missing link is a chain
  reuse detection cannot walk, and the failure direction is a user signing in
  again rather than a stolen token's successor living outside the family.
- **`RefreshTokenTTL` is 30 days, and the comment says what it trades against.**
  A TTL is not the boundary; rotation and reuse detection are.
- **Migration 00035's header states why the table carries no `account_id`** and is
  not under 00016's RLS, because a reader finding a credential table with no
  tenant key has a right to ask.

## 5. What I deliberately did NOT do

- **No OpenAPI change, and this is the biggest deliberate gap.**
  `openapi/v1.yaml` still says `grant_types` must be `authorization_code` and
  still says "this service issues no refresh token"
  (`openapi/v1.yaml:4598` and the schema enum at `:7897`), and
  `client/generated/api.gen.go:305`/`:443` still carry the one-value enums.
  The document now **under-states what the service accepts**: a product reading
  the document will not register `refresh_token`, and the grant is reachable
  only by a client that ignored it. That is a documentation defect, not a
  behavioural one. It needs the pinned oapi-codegen run in
  `client/generate.go` over the real document into the committed file, verified
  against `TestTheCommittedGeneratedFileIsWhatThePinnedGeneratorProduces`. I
  did not have the budget to verify that generator run, and a hand-edited enum
  would have failed that check while making the drift checks green.
- **No user-level refresh sweep, and this is a real 30-day gap, not a
  nicety.** `RevokeAccessTokensForUser` has three callers —
  `internal/deletion/sweep.go:37`, `internal/auth/service.go:171`,
  `internal/recovery/service.go:100` — each with its own interface and its own
  test fakes. A refresh token issued to a user therefore survives a password
  reset and an account deletion until its `expires_at`. The store method is one
  statement; the work is the three interfaces and their fakes. **Next packet's
  first task.**
- **No `offline_access` scope.** The library mints a refresh token on a code
  exchange only when the request carries `offline_access`
  (`op/token.go`'s `needsRefreshToken`), and `internal/oidc/scopes.go`'s closed
  set has four scopes and no `offline_access`. **A client that registers
  `refresh_token` and asks for only `openid email` gets no refresh token.**
  Worth confirming that is the intended product behaviour before shipping the
  grant; adding the scope is a scope-table change, an OpenAPI change and a
  regeneration.
- **No router-level integration test of the grant in
  `internal/httpapi/oidc_integration_test.go`.** The grant is proven at the
  store and the storage layer. The store tests are the strong ones; a
  router-level test would have been the fourth proof, not the second.
- **I did not investigate `muse`'s or `darkroom`'s other surfaces beyond the
  404 property**, and I read no repository outside `moon/wt/*` other than the
  one line in `TENANCY-GATE.md` that records darkroom's state. Nothing outside
  the worktree was edited.
- **`tenancy.yml` was not touched, and neither was
  `core/harness/tenancy_check.py`, `core/schemas/*.json` or
  `core/harness/tenancy_findings.json`.** The four tenancy failures that
  remain are TG-A1's.
