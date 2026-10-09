# REPORT — W1-P2: public agent registration + scoped token lifecycle

**Branch** `agents-first/w1p2` (7 commits on top of the W1-P1 merge `e9e6b38`).
**Gate** `bin/prime` green on this worktree's own database `identity_w1p2`
(`TEST_DATABASE_URL=postgres://identity:identity@localhost:15500/identity_w1p2?sslmode=disable`,
`TEST_DATABASE_ADMIN_URL=postgres://cafaye:cafaye@localhost:15500/postgres`).
Also green: `gofmt -l .` (nothing), `go vet ./...`, and `go test -race` over
`internal/agents`, `client/...` and `internal/httpapi`.

## What landed

The endpoint `caf agent register` calls, and the bearer-token lifecycle, on the
agent principals W1-P1 put in place.

- **`POST /v1/agents`** — public, unauthenticated, rate-limited
  (`RATE_LIMIT_AGENT_REGISTER`, default 5/min). Body `{name, username?}`. 201 is
  `{agent{…, status:"unclaimed"}, api_key{…, token}, claim{url, expires_at}}`: the
  bootstrap token and the claim link are the response's two plaintext secrets,
  each shown once, each stored only as a SHA-256. The username is auto-generated
  with an in-request retry loop.
- **`POST /v1/agents/claim-link/refresh`** — agent bearer credential; regenerates
  the claim URL and leaves the agent unclaimed. A refresh against a claimed agent
  is 404.
- **Token lifecycle** — `POST /v1/agents/tokens` (create), `GET /v1/agents/tokens`
  (list / "show"), `DELETE /v1/agents/tokens/{tokenID}` (revoke),
  `POST /v1/agents/tokens/{tokenID}/rotate`, over the agent's own credential, in
  the account-api-keys shape.

## The pieces

| Area | Change |
|---|---|
| Migration | `00034_agents_username.sql` — the globally-unique `username` W1-P1 deferred, with a shape CHECK and a partial unique index |
| `internal/agents` | `username.go` (generation/validation), `register.go` (Register + RefreshClaimLink + WithClaimUI), `tokens.go` (Authenticate/Issue/List/Revoke/Rotate); store gained `OwnerByTokenDigest`, the username column, `ErrUsernameTaken`; `Agent.Username`, `NewService(opts…)` |
| `internal/httpapi` | `agents.go` extended with four handlers + `agentCredentialOnly`; wired from `registerRoutes` (not `registerTenancyRoutes` — none of these routes is account-scoped) |
| Config | `AGENT_CLAIM_UI_URL` (validated, optional) + `RATE_LIMIT_AGENT_REGISTER`; both wired in `main.go` |
| Contracts | `openapi/v1.yaml` — six operations, nine schemas, an `agents` tag, a reusable `RateLimited` response; `client/generated/api.gen.go` regenerated (pinned v2.8.0); `client/transport.go` gained the six `Transport` methods; `coverage-exclusions` restated; README endpoint tables + six anonymous-enumeration audit rows |

## The four tripwires the route surface had to satisfy (all green)

`TestEveryServedRouteIsDocumentedOrNamed` (docs↔router),
`TestEveryRouteThatAnswersAnAnonymousCallerIsInThisAudit` (34 routes ↔ 34 rows),
`TestTheReadmeEndpointTablesAreTheRoutesTheRouterServes`,
`TestTheCommittedGeneratedFileIsWhatThePinnedGeneratorProduces`,
`TestTheTransportCoversEveryOperationInTheDocument`, and the client coverage
exclusion fingerprint (`files=`/`lines=`). Reusing the existing `o.agents` field
for the whole surface meant `conditionalSurfaces` needed no edit and the walks
saw the new routes the moment they saw the claim route — one field, six checks.

## Proofs the brief named (all present, all green)

- happy path — `TestTheRegistrationHTTPShapeIsTheContract`,
  `TestRegisterMintsEverythingAndWritesNoPlaintext`
- conflict-retry — `TestRegisterRetriesOnAUsernameCollisionWithoutDisclosingIt`,
  `TestTheRegistrationRetriesAUsernameCollisionWithoutSayingTaken`
- refresh-without-claiming — `TestRefreshGivesANewLinkAndDoesNotClaim`,
  `TestRefreshRefusesAClaimedAgent`,
  `TestTheRefreshRegeneratesALinkAndKeepsTheAgentUnclaimed`
- rate limit — `TestTheAgentRegistrationRateLimitRidesTheRealLimiter` (real limiter)
- no plaintext stored — `TestRegisterMintsEverythingAndWritesNoPlaintext` reads the
  row back and asserts the token and link digests are SHA-256 and neither plaintext
  is in any column

## Decisions recorded (DECISIONS.md D20)

1. **The handle is globally unique** — per-account uniqueness cannot fire on
   unclaimed agents (NULL account ⇒ Postgres keeps them distinct), so it would be
   arithmetic that never conflicts; a global unique index is what the retry runs
   into. The display *name* stays non-unique.
2. **Registration never says "taken"** — a generated collision retries under the
   hood; only a *supplied* handle that survives the budget is a 422 naming
   `username`. No route elsewhere answers "is this handle taken", so it is not an
   enumeration oracle.
3. **The claim screen base is configured, optional, validated** — `AGENT_CLAIM_UI_URL`
   is the agent mirror of `OIDC_LOGIN_UI_URL` (D10 restated), optional so a
   deployment without agents is not a boot failure, and an empty base 503s
   registration rather than minting an unclaimable agent.
4. **"Scoped token" means revocable-on-a-principal, not a scope array — yet.** 00031
   left `scopes` off `agent_tokens` for this packet to declare against a route that
   exists; the routes it would gate are W1-P3/W2, so this packet adds no column and
   invents no vocabulary.

## The Idempotency-Key, stated honestly

The refresh accepts the `Idempotency-Key` and **logs it beside the trace id**; it
is not stored and not a stored-response replay — `agent_events` has no idempotency
column, and each refresh deliberately mints a fresh link (a retry gets a new,
fresher one). The endpoint is idempotent in *effect* (never claims, never fails
because a prior refresh already replaced the link), which is what the CLI's retry
actually depends on. A full courier-style replay cache was ruled out this packet:
it would buy nothing (the link must be fresh) and cost a table.

## Environment gotcha (persist it)

The `identity` login role on the shared `localhost:15500` cluster pre-existed with
a password that was **neither** the brief's `identity:identity` nor AGENTS.md's
`cafaye`, so `bin/provision-testdb` (which only sets a password on CREATE, and the
role already existed) failed `SASL auth`. Fix, as the `cafaye` superuser:
`ALTER ROLE identity PASSWORD 'identity'; ALTER ROLE identity_app PASSWORD 'identity';`
Then the documented `identity:identity` DSN provisions. Whoever brings up the next
identity worktree against this cluster needs the same two lines, or a fresh volume.

## Successor's first move — W2-P2 (identity): claim binds

Everything below is substrate; the next packet is the claim half. When you pick it
up: `agents.Service.Claim` (W1-P1) is the seam. Flip `unclaimed → claimed`, set
`claimed_by_account_id`, **mint the scoped token against the scope vocabulary you
declare**, and write `ActionClaimed`. Two things this packet deliberately left you:
(a) `agent_tokens` has no `scopes` column — add it with the vocabulary, one name
against a route that exists, and enforce it where the token is resolved
(`ByTokenDigest`, *not* `OwnerByTokenDigest`); (b) the entitlement grant on claim
is conductor's (W2-P3, D4) — an agent can never grant itself anything, so the
mint you add at claim is account-scoped and human-approved only.
