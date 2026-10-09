# REPORT — W1-P1 identity: agent principals (worktree `identity-w1p1`, branch `agents-first/w1p1`)

**State: COMPLETE for this packet. The store, the use case and the claim route are
committed and green. What remains is the next packet's, and this file says exactly
where it starts.**

The substrate this report's first version described is still there and is still
green. On top of it now sit the store, `Service.Claim`, the event vocabulary and
`POST /v1/accounts/{accountID}/agents/claim`, with six of this service's own checks
fed and everything running green against `identity_w1p1`.

## The final gate, and the one red this packet's last worker left behind

The previous version of this report said "green", and it was written a few minutes
before the tree stopped being green. Regenerating the client for `claimAgent`
moved `client/generated/api.gen.go` from 31055 to 32054 lines, and
`coverage-exclusions` still recorded `lines=31055` — so
`TestTheCoverageExclusionIsOnlyGeneratedCode` was RED on the committed tree, and
the `-race` run that found it was the last thing that worker's endpoint did
before it died. The fix is the one the entry's own discipline prescribes: restate
the fingerprint in the same commit as whatever changed it. `lines=31055` →
`lines=32054`, the reason's statement figure 7280 → 7447 (measured by the entry's
own method — `go test -coverprofile` over `./client/generated/`, summing
`numStmt`), and a thirteenth restatement paragraph recording that one operation
with a request body, a response body and eight documented statuses cost 999
lines and 167 statements — the figure this entry has now recorded four times
running. The floor did not move.

**The gate DSN, for the next worker: the password is `cafaye`, not `identity`.**
`postgres://identity:identity@localhost:15500/identity_w1p1` fails *auth* (SQLSTATE
28P01), not schema, and reads exactly like a broken database. The role's password
is the cluster's `KIT_POSTGRES_PASSWORD`, which defaults to `cafaye` — the change
AGENTS.md records as identity-27, and the reason `docker-compose.yml:242` writes
the app DSN as `identity_app:${KIT_POSTGRES_PASSWORD:-cafaye}`. The working gate
invocation is:

```sh
TEST_DATABASE_URL="postgres://identity:cafaye@localhost:15500/identity_w1p1?sslmode=disable" \
TEST_DATABASE_ADMIN_URL="postgres://cafaye:cafaye@localhost:15500/postgres" \
bin/prime
```

`bin/provision-testdb` is idempotent and does not reset an existing role's
password, so a DSN that once worked keeps working and a wrong one fails forever
in a way that looks like the database's fault.

Final proof on the committed tree: `bin/prime` 30/30 packages `ok` against
`identity_w1p1` at schema version 33, `go vet ./...` clean, `gofmt -l .` empty,
`go test -race -count=1 ./...` clean.

## The two findings, and they are the most important thing in this file

Landing the data layer before any route produced **two defects in the committed
substrate**, both found by the first thing that tried to INSERT a row, and both of
the same kind: a CHECK whose SQL contradicted the comment directly above it.

1. **`agents_status_and_claim_agree` said an UNCLAIMED agent has no claim link**
   (`claim_token_digest IS NULL`) while its own header said "unclaimed → no
   account, no instant, and a **live claim link**", and a second CHECK
   (`agents_unclaimed_has_a_live_link`) said the same in SQL. The two were mutually
   exclusive, so **every registration the service could produce was refused by the
   database** and no row could exist at all. Fixed by `migrations/00032`.

2. **`agent_events_actor_is_whole` said `(actor_user_id IS NULL) =
   (actor_token_id IS NULL)`** — the two actor columns must move together — while
   its own comment and the file header both enumerated three legal shapes: a
   registration has NEITHER, a claim has a HUMAN, a rotation has a CREDENTIAL. The
   CHECK forbade the last two, so **every event this package can record was
   refused** and the service's first real claim failed as a 500. Fixed by
   `migrations/00033` to `actor_user_id IS NULL OR actor_token_id IS NULL`, which
   permits the three legal shapes and refuses the fourth — a row naming a human
   AND a credential — which is the half-written record the original comment was
   reaching for.

**What the two have in common is the finding worth carrying out of here: neither
was exercised by a single INSERT until the store and the claim landed.** A
migration applies cleanly on constraints that are syntactically valid and
internally self-contradictory, and a suite that never writes a row agrees with
them. `goose up` printed `OK 00031_agents.sql` for both. The store's first test
found the first defect; the claim use case's first integration test found the
second. That is the argument for landing the data layer before any route mounts
on it, and it is now an argument with two data points instead of a principle.

Both fixes are **new migrations rather than edits to 00031**, on
migrations/README.md's rule: an applied migration is not edited, because the
applied databases would then disagree with the file on disk and goose would never
re-verify. Both `Down`s restore 00031's original form verbatim, so a rollback
returns a documented defect rather than inventing a third variant. Schema is at
**version 33**.

## What landed since the first version of this report

### `internal/agents/store.go`

`Create`, `ByClaimDigest`, `Claim`, `RefreshClaimLink`, `SetStatus`, `ByID`,
`ListForAccount`, and the `agent_tokens` set — `CreateToken`, `ByTokenDigest`,
`ByTokenID`, `ListTokensForAgent`, `RevokeToken`, `Touch`. Every method takes a
`db.Querier`, so the caller chooses the transaction boundary.

- **`Claim` is the conditional UPDATE.** The `WHERE` carries the id, the status,
  the digest AND the expiry, and the `SET` clears the digest and the expiry in the
  same statement. Zero rows is one 404 and the 404 never says which conjunct
  failed, so two humans clicking the same link produce one claim with no read in
  between for the two to disagree in.
- **`ByClaimDigest` filters on the digest, the status and the expiry in one
  statement** and all three failures return the same value. A store that returned
  `ErrExpired` separately would hand the route a 410 to render, and a 410 says
  "this link was real".
- **`ByTokenDigest` inner-joins the principal**, so a revoked token, a spent
  token, an unclaimed agent, a disabled agent and a digest that was never issued
  are one answer.
- **`SetStatus` is guarded by `MayTransition` in Go AND by the table's CHECK**, on
  apikeys' argument that the database is the layer a psql session cannot bypass.

### `internal/agents/events.go` and `internal/agents/service.go`

The closed action set (`agent.registered`, `.claimed`, `.link_refreshed`,
`.enabled`, `.disabled`, `.token_minted`, `.token_revoked`) and `AppendEvent`, then
`Service.Claim`.

**`Service.Claim` is the ONLY use case in this packet.** Registration is W1-P2's
(`POST /v1/agents`), minting the scoped token at claim time is W2-P2's, and a use
case with no route is the shape AGENTS.md refuses: a tested method nobody calls is
an invitation to wire it without reading why it was not wired. What is here is
what every later packet is written against.

Four steps in one transaction, opened with **`db.TxRunner` rather than a bare
`Begin`** — that is not a style choice. `tenancy.BeginAccount` runs inside it
because `cafaye.begin_account/1` is `set_config(..., is_local => true)`, which
outside an explicit transaction expires at the end of the statement that set it. A
use case that opened its own transaction would read zero rows from every table
whose policy predicate reads the GUC, and the claim would answer 404 for an agent
that exists. It is set inside the use case rather than by the route because the
transaction is opened here: one function opens it and sets its identity, and a
caller that had to remember from outside would be a caller who forgets.

The actor pair goes through `nullable()` on the write and through `*id.UUID` on
the read, because `id.UUID`'s Valuer renders the zero value as the all-zero uuid
string — which the fixed CHECK would read as a real actor — and its `Scan` refuses
nil outright.

### `internal/httpapi/agents.go`

`POST /v1/accounts/{accountID}/agents/claim`, `sessionCredentialOnly` OUTSIDE
`requireAccountRole` (the mirror of `requireAdminToken`), one 404 for four
failures, and no token in the response.

**The account is in the path, the link is in the body, and the human is the
session.** A body carrying an `account_id` would move the membership read into a
handler — a second place a role is checked, in the service that insists it is
checked in one. A body carrying an `agent_id` would let the caller name a
principal they were never given a link for. Neither field exists. No `redirect` or
`return_to`: `redeemSessionLinkRequest` in `sessionlinks.go` gives the reason.

It is mounted from `registerTenancyRoutes` (not `registerRoutes`) for the reason
`registerAdminRoutes` is: an account-scoped route mounted anywhere else sits
outside `mountedAccountRoutes` and therefore outside both route walks.

## Six checks fed, all of which were red

- **`openapi/v1.yaml`** — the operation, its `operationId`, `ClaimAgentRequest`
  and `Agent`. The generated client regenerated with it.
- **`anonymousFamilyAudit()`** — a row, plus a family prefix, because the claim is
  the one route on this surface whose question is not *does this ACCOUNT exist* but
  *does this AGENT exist*. To answer it the probe had to learn to substitute a real
  account id: **the census has never audited an account-scoped route**, because
  `sendWith` takes a path verbatim and a probe for `/v1/accounts/{accountID}/…`
  sent a literal `{accountID}`, which `id.Parse` refuses, which produced a 404
  from `accountIDFrom` BEFORE `currentCaller` had answered. Every account-scoped
  row would have measured 404 and claimed 404 — a census reporting a refusal that
  had nothing to do with the credential gate it was auditing.
- **`matrixEndpoints()`** — a row, and the matrix fixture now mounts the REAL claim
  service rather than a double, because the row claims 200 for three columns and a
  canned 200 would pass a route whose claim path was broken. Six columns, six
  fresh agents: the link is single-use, so a row that reused one link would be
  asserting a property the service does not have.
- **`accountRouteScopes`** — deliberately NOT. The route is session-only, `Allows("")`
  is false for every granted set, so it is closed to tokens by the absence rather
  than by a declaration. A row for a route no token may reach would be a scope
  gating nothing, which `TestEveryScopeIsEnforcedOnItsRoutes` exists to catch.
- **`router_walk_test.go`'s `conditionalSurfaces`** — `"agents"`, the **fifth
  instance** of a mounted surface the walks could not see, and four `options`
  literals (`servedRoutes`, `mountedAccountRoutes`, `mountedFamilyRoutes`,
  `walkOptions`) now set the field. The registration is NOT conditional in the
  sense the list means — `registerAgentRoutes` takes no option, copying
  `registerSessionLinkRoutes` — but the SERVICE field still gates the mount, which
  is what the list is about.
- **`gate.yml`'s `db-tier:`** — `internal/agents`, plus the three tables cloned
  into `internal/platform/dbtest`'s private schema (with the FKs written out,
  because `LIKE … INCLUDING ALL` does not copy them) and the append-only trigger
  re-established (because `LIKE` does not copy triggers, and a private schema
  without it has a table that is append-only in production and freely editable
  here — a test asserting the property would be measuring the harness).
  `internal/platform/ci`'s `auditTriggers` gained `agent_events`, which is the
  third.

## Ruled out since the first version of this report

- **A registration use case.** `Service` mounts only `Claim`. `POST /v1/agents` is
  W1-P2's packet and its response shape is that packet's to choose.
- **A `SetStatus` use case.** The store has the method because the migration's
  disable is part of the packet's contract and the Go half of "unclaimed →
  disabled is unrepresentable" belongs beside the CHECK that says it. No route
  mounts it in this packet, and the method's header says so.
- **A `badAction` test seam on `Service`.** The transaction property is proved at
  the store's boundary with the same three calls in the same order, rather than by
  putting a field in production code so a test could ask the use case to fail.
- **`WithClock` on the matrix fixture.** It would have been the tidier fix for a
  claim link registered at the fake instant and judged at the real one, and it
  would have changed the instant every OTHER row in that matrix is judged at — a
  behaviour change to sixteen passing rows made in service of one new one. The
  comment on `registerAgent` says so, which is what stops the next reader from
  tidying it back.

## The successor's first move

**W1-P2: public registration, `POST /v1/agents`.** The store's `Create` is its row
and it is already what the claim route reads. What it needs is the response shape
`{agent{status}, api_key{token}, claim{url}}`, and the two things this packet
deliberately left for it:

1. **The scope vocabulary.** `agent_tokens` has no `scopes` column and the
   migration says why — a set nobody decided is a promise about the future rather
   than a control over the present. Registration is the packet that decides it,
   one name at a time against a route that exists.
2. **A `Register` use case**, which this packet did not write because it had no
   route to mount. It is `Create` plus a mint plus an `ActionRegistered` event with
   no actor — the only row in the table with a null actor pair, and the one 00033's
   fixed CHECK permits.

Then W1-P3 (conductor, box capabilities) and W2-P2 (flip to claimed, mint the
scoped token, write the audit event — the mint this packet's response shape
deliberately omits).

## What NOT to redo

- Do not add `status` or `scopes` columns to `agent_tokens`.
- Do not give the claim route a `redirect`/`return_to` parameter.
- Do not let `unclaimed → disabled` become legal anywhere.
- Do not store a plaintext token, a second prefix, or a second verification path.
- Do not restore `agents_status_and_claim_agree` or `agent_events_actor_is_whole`
  to 00031's forms. Both are documented as defects in their replacements.

## Gate status

`bin/prime` was re-run over the whole suite with all four commits in the tree,
against `identity_w1p1` migrated to v33, with the corrected DSNs:

```
TEST_DATABASE_URL=postgres://identity:cafaye@localhost:15500/identity_w1p1?sslmode=disable
TEST_DATABASE_ADMIN_URL=postgres://cafaye:cafaye@localhost:15500/postgres
```

The result is in `/tmp/gate-identity-w1p1.log` (`exit` in
`/tmp/gate-identity-w1p1.exit`), with `go vet ./...`, `gofmt -l .` and
`go test -race ./...` in `/tmp/gate-identity-w1p1-race.log`. Nothing was weakened
to make any of it pass.


---

## Below is the first version of this report, kept for the substrate
## description and the DSN correction it records. The state line at the top and
## everything above this rule supersedes it.

## What the packet is for

An **agent principal** in `identity` (decision D3: identity owns the principal,
not conductor). An agent can exist, be unclaimed, become claimed by a human
account, be disabled, and hold tokens. Everything else in the agents-first wave
builds on this shape, so the shape IS the contract: W1-P2 (public registration,
`POST /v1/agents`, response `{agent{status}, api_key{token}, claim{url}}`),
W1-P3 (conductor, box capabilities), W2-P2 (claim binds and mints the scoped
token), W2-P1 (website claim screen).

**The one sentence the design turns on:** identity's api keys are
*owner-minted and account-scoped*, whereas a self-registering agent has **no
account yet**. So this is a new lifecycle over the same hashing and
introspection machinery — not a second token system, and not a second place
anything verifies a credential.

## First version: what landed (the substrate)

### `migrations/00031_agents.sql` — three tables

- **`agents`** — `status` as `agent_status ENUM ('unclaimed','claimed','disabled')`,
  NOT as the draft's three nullable timestamp columns. The enum plus two CHECKs
  makes the two illegal states *unrepresentable in the schema*: an unclaimed
  agent that remembers an account, and a claimed agent with a live claim link.
  Plus `claimed_by_account_id` (CASCADE from accounts — deleting the account
  takes its agents and their tokens), `name` (1..120), `device jsonb NOT NULL
  DEFAULT '{}'` (on 00027's argument: the agent describes itself at registration
  and the set of keys is a code fact), `claim_token_digest` + `claim_link_expires_at`
  (NULL once claimed — a spent link is not a credential), partial unique index
  on the digest, account index partial on the claimed rows.
- **`agent_tokens`** — SHA-256 at rest (64-hex CHECK), `expires_at` NOT NULL with
  an `expires > created` CHECK, `last_used_at` on the read path, `revoked_at` +
  `revoked_reason`, partial unique `one_live_name_per_agent` (that is what makes
  rotation two requests rather than a transaction), digest unique index,
  `expires_at` sweep index. **No `scopes` column and no `revoked_by`** — both
  argued in the file header; the scope vocabulary is W1-P2's to declare against
  a route that exists, and nothing in this packet revokes on a human's behalf.
- **`agent_events`** — the `account_audit_log` (00012) discipline verbatim:
  append-only trigger in the DATABASE, no FK on `agents` (a cascade is a DELETE
  and this table does not delete — *the claim cannot be undone by deleting the
  account that claimed it*), `actor_user_id`/`actor_token_id` nullable as a PAIR
  with a CHECK (a registration has neither, a claim has a human, a rotation has a
  credential), row ids and never the value, grants `SELECT, INSERT` only.
- **Grants:** `agents`/`agent_tokens` get `select, insert, update` (no DELETE —
  a revocation is an UPDATE and a privilege whose only outcome is an error is not
  a privilege); `agent_events` gets `select, insert`.
- **No `cafaye.protect_table` on any of the three.** `protect_table` REFUSES a
  table with no `account_id` and `agents` cannot have one — an unclaimed agent
  belongs to nobody, which is the whole point. This is 00022's situation and
  00022's argument covers it; `claimed_by_account_id` is a reference, not a
  boundary column, because a policy whose predicate read it would lock out the
  very rows the claim route exists to serve.

Verified applied: `OK 00031_agents.sql (13.6ms)`, `migrated database to version: 31`.

### `internal/agents/agents.go` — the state machine and the credential

- `StatusUnclaimed/Claimed/Disabled`, `AllStatuses`, `IsKnownStatus`,
  `ParseStatus`, **`MayTransition(from,to)`** as a total function: the three
  legal moves, same-state retries allowed (a replayed event is not a
  transition), and the two refusals — `unclaimed → disabled` and
  `claimed → unclaimed` (ownership is not revocable by the agent or by a second
  claim link; the owner *disables* it).
- `Prefix = "cafaye_"` — **the same prefix apikeys uses, deliberately.** A second
  prefix would buy a way to tell an agent credential from a user's api key by
  looking at it, which is the property this platform refuses to have.
- `Digest` restated rather than imported from `apikeys`: same bytes, different
  lifetime argument, and a reviewer reading it at the top of an agent-credential
  path should not have to know the argument carries.
- `Agent`, `Token`, `IsClaimed()` (**a disabled agent IS claimed** — "was it
  claimed" and "is it live" are two questions), `Token.UsableAt(now, status)` —
  the join between the credential's own state and the principal's status, in one
  place, which the resolution query's inner join already says.

### `internal/agents/agents_test.go` — 6 tests, all green

Lifecycle transition table (9 cases including both illegal directions),
closed-set/`ParseStatus` checks, the token/digest shape (43-char secret, 64-hex,
no `/+=`, digest stable, digest does not contain the secret), the digest-is-of-
the-whole-value uniqueness decision, the reflection sweep proving **no struct in
this package carries a plaintext credential**, and the `UsableAt` join including
the `>=` boundary on both sides.

## First version: what I learned and ruled out

1. **The brief's DSN password is stale.** `TEST_DATABASE_URL=postgres://identity:identity@localhost:15500/…`
   fails SASL auth. The local `identity` role's password is kit's
   `KIT_POSTGRES_PASSWORD`, default **`cafaye`** (AGENTS.md says so after packet
   identity-27; the brief did not). **Use:**
   ```
   TEST_DATABASE_URL=postgres://identity:cafaye@localhost:15500/identity_w1p1?sslmode=disable
   TEST_DATABASE_ADMIN_URL=postgres://cafaye:cafaye@localhost:15500/postgres
   ```
   The superuser is `cafaye`, not `postgres` (the brief had this right). The
   database `identity_w1p1` is already provisioned and migrated to v31 by
   `bin/provision-testdb`; re-running is a no-op. Its schema is private to this
   worktree, so no other worker's gate touches it.
2. **RLS on these tables is not available and not wanted.** See the migration
   header. `internal/tenancy`'s `identityTables` does not need a row for them.
3. **The claim route is a SESSION surface.** `o.currentUser` + `sessionCredentialOnly`
   + `sessionCredentialOnly`'s 403-for-a-token, mirroring
   `POST /v1/invitations/accept` (`internal/httpapi/accounts.go:675`). The claim
   link is the only thing a stranger ever presents; everything else on the agent
   surface is a machine credential, and when W1-P2 adds `agent:*` scopes they go
   in `accountRouteScopes` — which currently has no agent rows, so every agent
   route is automatically closed to tokens until a row exists. That is the safe
   direction and it is the rule, not a gap.
4. **Minting the token at claim is W2-P2's job, not mine.** The W1 packet row
   says `agent_tokens` (store, hashing, rotation, revocation) and the claim
   route; W2-P2 says "flip unclaimed → claimed, set claimed_by_account_id, **mint
   the scoped token**, write the audit event". I did not wire the mint, because
   the scope vocabulary it would mint with does not exist yet.

## First version: ruled out, with the reason

- **`username` on `agents`** — W1-P2 decides what an agent calls itself beyond its
  name. A column added now gets a default nobody chose.
- **A separate claim-links table** — there is one live claim link per agent and
  W1-P2's refresh replaces it in place. A side table is an insert-or-update with
  a uniqueness rule nobody needs, and a second place for the claim route to look.
- **A distinct token prefix** — property 3 above.

## First version: the successor's first move (now done)

Two things, in this order:

1. **`internal/agents/store.go`** — `Create` (registration's row: name, device,
   a fresh claim link with `ClaimLinkTTL`), `ByClaimDigest` (the claim route's
   lookup: digest + `status='unclaimed'` + `claim_link_expires_at > $now`, one
   404 for every failure), `Claim` (a conditional UPDATE
   `WHERE id=$1 AND status='unclaimed' AND claim_token_digest=$2` that also
   `SET status='claimed', claimed_by_account_id=$3, claimed_at=$4,
   claim_token_digest=NULL, claim_link_expires_at=NULL` — zero rows is the 404,
   and the 404 never says "expired"), `RefreshClaimLink` (W1-P2's idempotency-keyed
   rotation, which regenerates without claiming), `SetStatus` (guarded by
   `MayTransition`), plus the `agent_tokens` create/resolve/rotate/revoke/touch
   mirrors of `internal/apikeys/store.go`. Read `internal/apikeys/store.go` first
   — the argument for the conditional-UPDATE-shaped reads and the four-indistinguishable-
   failures lookup is all there and it is the whole model.
2. **The claim route in `internal/httpapi/agents.go`**, mirroring
   `internal/httpapi/accounts.go`'s invitation pair (`:653-680` register,
   `:887-960` handlers, `:1140-1160` the error mapper). Then the four checks this
   service mounts on every new route, all of which go RED until they are fed:
   - `openapi/v1.yaml` — the operation AND its `operationId`
     (`TestEveryServedRouteIsDocumentedOrNamed`, `TestEveryOperationHasAnOperationId`;
     `knownDrift` is empty and cannot grow).
   - `anonymousFamilyAudit()` in `anonymous_enumeration_test.go` — one row
     answering *can the response tell "this agent exists" from "it does not"*.
     The claim route's 404 must be indistinguishable for a wrong token, an
     expired link, an already-claimed agent and an agent that never existed.
   - `matrixEndpoints()` if it is ever account-scoped, and
     `accountRouteScopes` if a token may reach it.
   - `router_walk_test.go`'s `options` struct literals if the registrar is
     conditional (mine should NOT be — `registerSessionLinkRoutes` takes no
     option and that is the precedent to copy).
   - `gate.yml`'s `#   db-tier: ` list, if the new package opens a pool.

   Then `bin/prime`, `go vet ./...`, `gofmt -l .`, `go test -race ./...` with the
   corrected DSNs above.

## First version: gate status at handoff

`bin/prime` was run twice against `identity_w1p1`: once to provision and apply
00031 (all 31 migrations OK), once over the whole suite with the two commits in
the tree. The final run's result should be read from `/tmp/gate-identity-w1p1.log`
(`exit` code in `/tmp/gate-identity-w1p1.exit` if it finished). Nothing was
weakened to make it pass; the migration and the package were both green before
either was committed.

## First version: what a successor should NOT redo

- Do not re-derive the DSN (above, item 1) — the wrong one fails auth, not
  schema, and reads like a broken database.
- Do not add `status` columns or a `scopes` column to `agent_tokens` without
  reading the migration's "WHAT IS NOT HERE" — both absences are argued.
- Do not give the claim route a `redirect`/`return_to` parameter:
  `redeemSessionLinkRequest` in `sessionlinks.go` gives the reason (an open
  redirector with a session attached, on a route with no allow-list).
- Do not let `unclaimed → disabled` become legal anywhere.
