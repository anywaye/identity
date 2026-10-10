# HANDOFF-TG-C2 — refresh tokens in identity, and the 404-not-403 census

Worktree `wt/identity-tgc2`, branch `tenancy/identity-tgc2`, three commits.
Everything here is what a successor needs instead of rediscovering it.

## What is DONE and green

1. **The refresh grant, end to end.**
   - `migrations/00035_oidc_refresh_tokens.sql` — the table. `token_digest`
     is `char_length = 64`, the lower-case hex SHA-256 of 32 bytes from
     `crypto/rand`, the same construction as `sessions.token_digest`,
     `api_keys.token_digest` and `oidc_clients.secret_digest`. No second
     scheme. No `account_id`, and not covered by 00016's RLS, which is
     `oidc_access_tokens`' choice restated: the token endpoint has no
     account in hand when a refresh token is presented, it has 32 random
     bytes.
   - `internal/oidc/refreshtoken.go` — the model, the digest mint, and four
     refusals (`ErrNoRefreshToken`, `ErrRefreshTokenExpired`,
     `ErrRefreshTokenRevoked`, `ErrRefreshTokenReused`).
   - `internal/oidc/storage.go` — `CreateAccessAndRefreshTokens`,
     `TokenRequestByRefreshToken`, `GetRefreshTokenInfo`, and `RevokeToken`
     extended to tell a refresh token from an access token by the digest
     lookup rather than by whether the string parses as an id.
   - `internal/oidc/provider.go` — `GrantTypeRefreshToken: true`, and the
     discovery document publishes `[authorization_code, refresh_token]`.
   - `internal/oidc/client.go` — `SupportedGrantTypes` gains `refresh_token`.
   - `internal/oidc/service.go` — `AccessTokenRevoker` gains
     `RevokeRefreshTokensForClient`, and `RevokeClient` sweeps BOTH credential
     classes in the ONE transaction that revokes the registration.
   - `internal/platform/dbtest/dbtest.go` — the private schema clones
     `oidc_refresh_tokens`. A table added by a migration and not cloned here
     breaks every database test in every pool-opening package, not only the
     feature's own. The list in that file is a completeness obligation.

2. **Rotation and reuse detection.** One conditional UPDATE claims the token
   (`used_at IS NULL AND revoked_at IS NULL AND expires_at > now`), so two
   concurrent presentations cannot both win. A reuse revokes the whole
   `replaced_by` chain in one recursive UPDATE.

3. **Tests.** `internal/oidc/refreshtoken_test.go`, six database tests.

4. **Half 2, the census.** See `REPORT-TG-C2.md` in this repository, or the
   final message of the session. Identity proves the property at
   `internal/httpapi/authz_matrix_test.go:46` and `:262`.

## What is NOT done, and it is ONE thing

**The two family-walk tests fail intermittently under the full gate.**

    --- FAIL: TestRevokingAFamilyRevokesTheWholeChain (0.76s)
        refreshtoken_test.go:266: chain link 0 after a family revoke = <nil>, want ErrRefreshTokenRevoked
    --- FAIL: TestAReusedRefreshTokenRevokesItsFamily (0.70s)
        refreshtoken_test.go:161: the replacement after a reuse = <nil>, want ErrRefreshTokenRevoked

    $ env TEST_DATABASE_URL=postgres://identity:identity@localhost:15500/identity_tgc2?sslmode=disable \
          TEST_DATABASE_ADMIN_URL=postgres://cafaye:cafaye@localhost:15500/postgres ./bin/prime
    FAIL github.com/cafaye/identity/internal/oidc    (29 of 30 packages ok)

### Reproduced as

- `go test -count=1 ./internal/oidc/` — **green, 9/9 runs**.
- `bin/prime` — **red, 3/3 runs**, on those two tests only.
- `go test -count=1 -p 1 ./internal/oidc/ ./internal/httpapi/` — red once,
  green twice. Intermittent.

### What is already ruled out

- **The SQL is correct.** Verified by hand, live, against a three-row chain in
  Postgres: one recursive `UPDATE ... FROM chain` revoked all three.
      create schema probe2; create table probe2.rt (id uuid primary key,
        replaced_by uuid references probe2.rt(id), revoked_at timestamptz);
      -- two UPDATEs to build the chain, then the same recursive statement
      -- the store runs: select count(*) -> 3
- **`INCLUDING ALL` does not copy the self-referential FK** into the private
  schema, so `replaced_by` is not constrained against `public`.
  Confirmed with `\d` on a clone.
- **It is not digest collision** — that would be a unique-violation error, and
  the symptom is a rotation that SUCCEEDS.
- **It is not a transaction-visibility problem** — the same `db.Querier` is
  used for the writes and the revoke, and every other statement in the package
  sees its own writes.

### The successor's first move

The failure is "rotation of a chain link succeeds after the family revoke",
which means `RevokeRefreshTokenFamily` affected zero rows. Instrument it: make
`RevokeRefreshTokenFamily` return the affected row count (or log it), and assert
in the test that the count is what the chain length says. That turns a
symptom into a measurement, and it is a change the test wants anyway — a revoke
that reports success while revoking nothing is the defect the brief is about,
in the small.

Two candidates worth checking before anything else:

1. **`db.Direct.Queryer()` under `-p 4` load.** If it acquires a pooled
   connection and issues `SET search_path` per connection while pgx caches
   prepared statements per connection, a statement planned against `public`
   would be a different answer to the same query text. Check
   `internal/platform/db/`. This is the hypothesis that fits "passes alone,
   fails under load".
2. **`RevokeRefreshTokenFamily` planning.** Postgres plans a `WITH RECURSIVE`
   data-modifying statement once. If the plan is shared while the search_path
   is per-connection, the answer would be load-dependent. Making the schema
   explicit in the statement (`UPDATE <schema>.oidc_refresh_tokens`) is not
   possible from the store, but `dbtest` could set the search_path in the DSN
   instead of with `SET`.

**Do not fix this by relaxing the assertions.** Both tests fail in the safe
direction (they refuse to accept a token they should refuse) and both are
honest.

## What I deliberately did NOT do

- **No OpenAPI change.** `openapi/v1.yaml` still says a registration's
  `grant_types` must be `authorization_code` and its description still says
  "this service issues no refresh token", and the generated client
  (`client/generated/api.gen.go`) still carries the one-value enum. The
  document therefore now under-states what the service accepts. It is a
  **documentation defect, not a behavioural one**, and it needs
  `client/generate.go`'s pinned oapi-codegen run over the real document into
  the committed file. I did not have the budget to verify that generator run
  against `TestTheCommittedGeneratedFileIsWhatThePinnedGeneratorProduces`, and
  a hand-edited enum would have failed it. The drift checks are about routes
  and methods, not enums, so nothing went red — which is exactly why it is
  written down here rather than left to be noticed.
- **No user-level refresh sweep.** `RevokeAccessTokensForUser` has three
  callers (`internal/deletion/sweep.go`, `internal/auth/service.go`,
  `internal/recovery/service.go`), each of which declares its own interface,
  and a refresh token now survives a password reset and an account deletion
  until its `expires_at`. That is a **real gap with a 30-day window** and it is
  the next packet's first task, not a comment. `RevokeRefreshTokensForUser` on
  the store is one statement; the work is the three interfaces and their test
  fakes.
- **No `offline_access` in the scope list.** The library only mints a refresh
  token on an authorization-code exchange when the request carries
  `offline_access` (`op/token.go`'s `needsRefreshToken`), and
  `internal/oidc/scopes.go`'s closed set has four scopes and no
  `offline_access`. **A client that registers `refresh_token` and asks for only
  `openid email` gets no refresh token.** Confirm that behaviour is intended
  before shipping the grant to a product, and if it is not, add the scope to
  the closed set — which is a scope-table change, an OpenAPI change and a
  client regeneration.
- **No HTTP-level integration test of the grant in
  `internal/httpapi/oidc_integration_test.go`.** The grant is proven at the
  store and the storage layer, not through the router. The store tests are the
  strong ones; a router-level test would have been the fourth.
- **The `tenancy-check` failures are TG-A1's, not mine.** 4 failures and 1
  warning, byte-for-byte the state `moon/TENANCY-GATE.md:53` records: three
  `tenancy.denial-missing` on `admin-audit-log-list` pointing at
  `internal/tenancy/tenancy_test.go:324/339/349`, and one
  `tenancy.rls-undeclared` on `account_invitations` from
  `migrations/00007_account_invitations.sql:51`. My new file
  `internal/oidc/refreshtoken.go` adds no finding, and I did not touch
  `tenancy.yml`.
