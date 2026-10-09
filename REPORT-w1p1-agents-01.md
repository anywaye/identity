# REPORT — W1-P1 identity: agent principals (worktree `identity-w1p1`, branch `agents-first/w1p1`)

**State: PARTIAL, honest, two commits. The gate is running as I write this.**
The substrate is committed and green on its own tests. What is NOT committed is
the store, the service use cases and the claim route — the successor's job, and
this file says exactly where to start.

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

## What landed

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

## What I learned and ruled out

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

## Ruled out, with the reason

- **`username` on `agents`** — W1-P2 decides what an agent calls itself beyond its
  name. A column added now gets a default nobody chose.
- **A separate claim-links table** — there is one live claim link per agent and
  W1-P2's refresh replaces it in place. A side table is an insert-or-update with
  a uniqueness rule nobody needs, and a second place for the claim route to look.
- **A distinct token prefix** — property 3 above.

## The successor's first move

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

## Gate status at handoff

`bin/prime` was run twice against `identity_w1p1`: once to provision and apply
00031 (all 31 migrations OK), once over the whole suite with the two commits in
the tree. The final run's result should be read from `/tmp/gate-identity-w1p1.log`
(`exit` code in `/tmp/gate-identity-w1p1.exit` if it finished). Nothing was
weakened to make it pass; the migration and the package were both green before
either was committed.

## What a successor should NOT redo

- Do not re-derive the DSN (above, item 1) — the wrong one fails auth, not
  schema, and reads like a broken database.
- Do not add `status` columns or a `scopes` column to `agent_tokens` without
  reading the migration's "WHAT IS NOT HERE" — both absences are argued.
- Do not give the claim route a `redirect`/`return_to` parameter:
  `redeemSessionLinkRequest` in `sessionlinks.go` gives the reason (an open
  redirector with a session attached, on a route with no allow-list).
- Do not let `unclaimed → disabled` become legal anywhere.
