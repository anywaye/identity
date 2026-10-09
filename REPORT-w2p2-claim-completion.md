# W2-P2 — identity: the claim completes, mints, and gates

**Packet** `W2-P2` of the agents-first wave, on `identity`. Branch
`agents-first/w2p2`, commits `cebc761`, `801791a`, and the two that follow this
report. Gate database `identity_w2p2` on the shared `localhost:15500` cluster.

The previous attempt of this packet left nothing — `git status` was clean on the
`w1p2` merge, so this run started from the merged W1-P2 tree rather than from a
partial. Nothing was discarded.

## What the packet is for

AGENTS-FIRST.md's flow, step ③: an agent registers itself unclaimed, a human
opens the claim URL and clicks Approve, and from that click the agent belongs to
a human account and holds a credential. W1-P1 landed the binding and W1-P2 the
registration and token lifecycle; this packet closes the loop — the claim now
also mints the credential the agent presents, and an agent that has not been
claimed may not act on anything.

The downstream entitlement grant is conductor's (W2-P3). Nothing here grants
one, and D4 is the reason: an agent that could approve its own claim would be an
agent approving its own purchase.

## The two decisions, and where they are recorded

**The mint is inside the claim's transaction.** `agents.Service.Claim` is now
five statements in one `TxRunner`: digest the link, resolve it (one statement
filtering digest, status and expiry), the conditional UPDATE that actually
decides, the credential, and two events. The two events are `agent.claimed` and
`agent.token_minted`, and the second one's actor is the **human** — `Event.UserID`
and not the credential that was just minted. That is a security statement rather
than bookkeeping: recording the token as its own actor would say the agent issued
itself a credential by being claimed, which is the story D4 refuses.

The credential is named `claimed`, not a second `bootstrap`.
`agent_tokens` has a partial unique index on one live name per agent, so a shared
name would refuse the claim outright — and the two names read as a history in a
management list.

**The gate is a middleware, not a branch.** `agentClaimedOnly` wraps
`agentCredentialOnly` and adds "has a human claimed this principal". It is a
middleware for the reason `requireAdminToken` and `requireSessionLinkMint` are
outside the chain: wrapped inside a handler the property is whatever that
handler remembered, and the route added next is the one without it.

An authenticated-but-unclaimed principal gets **403 `agent_unclaimed`** with a
`detail` that names the remedy. It is 403 rather than 401 because the credential
resolved — the principal is real, the token is live, and what is missing is a
human's click, which a new credential does not fix.

The one route an unclaimed agent may still reach is `POST
/v1/agents/claim-link/refresh`, and that exception is named rather than
discovered: it is the only road out of the state a human is being asked to
finish. Closing it would leave an agent whose link expired before its human got
to it unclaimable by anybody. A refresh does not claim, does not mint and does
not bind.

Both decisions are in **DECISIONS.md D21**.

## What was proved

| property | where |
|---|---|
| the claim mints a credential that resolves | `TestAClaimMintsTheCredentialItPresents` (internal/agents) and `TestTheClaimAHumanCompletesRendersTheCredentialTheAgentPresents` (httpapi) |
| only the digest is stored; the plaintext is nowhere | the same two tests read the row back |
| the mint's actor is the human | `TestAClaimMintsTheCredentialItPresents` |
| single use, on the wire | `TestTheSameClaimLinkCannotBeSpentTwice` |
| wrong account, and the owner can still claim afterwards | `TestAClaimByAHumanWhoIsNotInThatAccountIsRefused` |
| an unclaimed agent gets 403 `agent_unclaimed` on every acting route, and the refresh stays open | `TestAnUnclaimedAgentGetsNothing` |
| the claim is still session-only | `TestTheClaimRefusesACredentialThatIsNotABrowserSession` |

The happy-path HTTP test proves the minted token **works** rather than merely
being present: it uses the value from the claim response as a bearer credential
on `GET /v1/agents/tokens`, a claimed-only route. A credential the claim renders
but the agent cannot use is a decoration, and reading the row back would not
have caught that.

## Two behaviours changed from W1-P2, deliberately

1. `agent_events` for a claim is now **two** rows. `TestAClaimBindsTheAgentAndRecordsWhoDidIt`
   asserted one and now asserts two.
2. The self-service token lifecycle is **closed to an unclaimed agent**.
   `TestTheAgentTokenLifecycleOverHTTP` previously drove it with the
   registration's bootstrap token against a principal with no account; it now
   claims the agent first, through the real route. This is the D4 reading of
   "an agent acting alone gets nothing" and it is the packet's most
   behaviour-changing decision.

## Two things a reader should know before touching the generated client

**The new response schema is called `ClaimedAgent`, and the name is forced.**
oapi-codegen derives the response struct from the `operationId`, so a schema
called `ClaimAgentResponse` produces two Go types with one name and a file that
does not compile. This was measured on the first regeneration, not reasoned
about.

**The coverage-exclusion's statement figure is 8221, re-measured.** The entry was
34965 lines; the regenerated file is 35193. The 774-statement jump is recorded
because it is the interesting kind: **no operation was added**. This document
has four earlier entries establishing that adding a response costs roughly
nothing (three lines and zero statements for a problem code; 127 lines and zero
statements for `account_disabled`). What moved here is a response schema becoming
a NEW type with a nested `IssuedAgentToken` property, and a nested object
generates a parse function, `json.Unmarshal` branches and a `Valid()` switch. A
response that gained a nested object is a new schema in everything but name.

## The environment gotcha, for the successor

Two lines, as the W1-P2 report said, and they were needed again:

```sql
ALTER ROLE identity PASSWORD 'identity';
ALTER ROLE identity_app PASSWORD 'identity';
```

Then `TEST_DATABASE_ADMIN_URL='postgres://cafaye:cafaye@localhost:15500/postgres'
./bin/provision-testdb
'postgres://identity:identity@localhost:15500/identity_w2p2?sslmode=disable'`.

`newAgentServer` grew `WithTenancy`, which is what mounts the account-scoped
routes at all. Without it the agent test server offered registration and the
self-service half and **no way for a human to finish claiming anything** — which
is the shape of bug the router walks exist to catch, introduced quietly by a test
fixture.

## Successor's first move — W2-P3 / conductor

The claim is complete and auditable from identity's side. What is not built, in
the order the flow needs it:

1. **The entitlement grant on a claim** (conductor). D4 says an agent acting
   alone gets nothing, so this must be reachable by the claim event or by a
   reconciled Stripe Payment Link and by neither of those by the agent. The
   `agent.claimed` event is the hook: it carries the claiming account's id and
   the human.
2. **`agent_tokens` still has no `scopes` column.** The vocabulary is declared
   "one name at a time against a route that exists" (migration 00031), and the
   first route an agent token would gate is box enrollment. Enforce it at
   `ByTokenDigest` and not at `OwnerByTokenDigest`, as the W1-P2 report says.
3. **No route lists an account's agents.** `agents_account_idx` exists for it
   and `agents.Service.ListForAccount` does not. The claim screen's re-visit and
   the owner's management list both need it, and the index says which shape.

## Gate

`bin/prime` green (30 packages), `go test ./...` green with a coverage profile,
`go test -race ./...` green, `gofmt -l .` silent, `go vet ./...` silent,
`bin/coverage-floor` green at **73.4%** against the 70% floor. The client
regeneration gate passes with the regenerated file committed.
