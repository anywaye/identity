# REPORT — repair-c: the claim preview and the agent home route the clients call

Worktree `/Users/kaka/Code/any/wt/identity-repair-c`, branch
`agents-first/repair-c`. Commits: `378eccc` (the routes and the substrate) and
the follow-up that lands the client, the document version and the coverage
restatement. Gate database `identity_repair_c` on the shared `localhost:15500`
cluster.

## The environment gotcha, for the successor

Two lines, as before, and both were needed again:

```sql
ALTER ROLE identity PASSWORD 'identity';
ALTER ROLE identity_app PASSWORD 'identity';
```

Then
`TEST_DATABASE_ADMIN_URL='postgres://cafaye:cafaye@localhost:15500/postgres'
./bin/provision-testdb
'postgres://identity:identity@localhost:15500/identity_repair_c?sslmode=disable'`.

**`./bin/prime` provisions its own database and needs the admin variable too.**
Running it with only `TEST_DATABASE_URL` set fails at `bin/provision-testdb: no
admin connection works` before a single test runs, which reads like a broken
harness rather than a missing variable. Export both.

## What the packet was for

Two routes the clients already call and identity did not mount:

1. `GET /v1/agents/claim/{token}` — the website's claim screen calls it
   (`src/lib/upstream.ts:536-540`, driven by `getAgentClaim` and
   `useAgentClaimPreview`) to render its first frame. Because identity's failures
   are one collapsed shape, a **live** claim link answered the same 404 a wrong
   one does, and the screen's own allow-list comment says so in as many words.
2. `GET /v1/agents/home` — `cafe agent whoami` calls it
   (`cafaye/cafe/internal/agent/endpoint.go:26`, `store.go:274`).

## What landed

**`GET /v1/agents/claim/{token}`**, anonymous, rate-limited on the registration's
own terms. `agentClaimPreviewResponse` is the website's own shape, read out of
`src/lib/identity.ts`'s `AgentClaim` and the screen at
`src/app/agents/claim/[token]`: seven flat fields, and `device` passed through
whole because its keys are the agent's own vocabulary. The use case is
`agents.Service.PreviewClaim` — a **separate method**, not a flag on `Claim`,
because `Claim` mints and a flag on it has to be honoured by six statements.

**`GET /v1/agents/home`**, behind `agentCredentialOnly`. The agent's identity,
its status and the account that claimed it by row id. It needs no service call:
`agentCredentialOnly` already resolved and re-read the principal.

**The two decisions worth a reader's time** are recorded in DECISIONS.md D22:
why the preview is a method and not a flag, and why the home is *not*
`agentClaimedOnly` (`cafe agent whoami` is the verb an **unclaimed** agent runs to
find out whether anybody has claimed it, and a 403 there would answer "you are
not claimed" by refusing to say who is asking).

## The new-route checks, fed rather than avoided

Both routes sit on the `agents` surface already in `conditionalSurfaces`, so the
walks saw them on the day they mounted — which is why they went red immediately
and the red was the work order:

- `TestEveryServedRouteIsDocumentedOrNamed` → two OpenAPI operations
  (`getAgentClaimPreview`, `getAgentHome`) with their schemas and the `token`
  path parameter.
- `TestEveryRouteThatAnswersAnAnonymousCallerIsInThisAudit` → two rows, one per
  anonymous route, each answering the file's own question in a sentence.
- `TestTheReadmeEndpointTablesAreTheRoutesTheRouterServes` → rows in both README
  tables.
- **`TestTheCommittedGeneratedFileIsWhatThePinnedGeneratorProduces` and
  `TestTheTransportCoversEveryOperationInTheDocument`** went red for a reason
  worth naming: the generator refuses `path '/v1/agents/claim/{token}' has 1
  positional parameters, but spec has 0 declared`. I had written the path without
  a `parameters:` block. The client had to be REGENERATED (`go generate
  ./client/`) and the hand-written `Transport` + `Client` wrapper extended, which
  is the gate working as designed rather than an obstacle.
- `TestTheCoverageExclusionIsOnlyGeneratedCode` → the regeneration moved
  `client/generated` from 35199 to 36045 lines, so `coverage-exclusions` was
  restated, with the statement figure re-measured (8412, from the coverprofile)
  rather than carried forward. The floor did not move.
- The document version pin moved to 1.14.0 with the reason written beside the
  constant.

## Proofs

`internal/agents/preview_test.go` — over the real SQL: the fields the screen
reads, that a preview **writes nothing** (asserted by claiming the SAME link
afterwards and getting a credential), and that the four ways a link is dead are
one value — with the negative control that a link nobody ever issued is the one
that must never resolve.

`internal/httpapi/agents_preview_integration_test.go` — over the real router and
the real SQL: the seven-field shape against the website's reader, the collapse,
the changes-nothing property (row counts before and after, because the credential
list sits behind `agentClaimedOnly` and an unclaimed agent cannot list them), the
claimed and unclaimed halves of the home, the mis-presentation table, and the
rate-limit wiring.

**Two faults were injected and both tests went red**, which is the only reason to
believe either of them: answering 200 for a dead link failed all three collapse
rows, and dropping `device` from the response failed the shape assertions.

## Findings a successor should read

1. **`instance` in the problem body echoes the claim link.** `writeProblem` sets
   `p.Instance = r.URL.Path` in one shared place, so the preview's 404 body
   carries `/v1/agents/claim/cafaye_…` back to the caller. I left it, and the
   argument is written into the test: the only caller who ever sees it is the one
   who already holds that 256-bit secret, and the same value is already in every
   HTTP access log and the browser's own history. **The alternative is a change
   to the shared writer, which touches every problem response in the service and
   is a packet of its own.** If a reviewer disagrees, that is the change.
2. **An empty path segment is chi's own 404, not this route's.** chi does not
   route `/v1/agents/claim/` to the handler at all, so it answers "no route matches
   this request" before any code of ours runs. That 404 names no agent and no
   link, so it discloses nothing, but it is a different body — which is why the
   empty-token row is proved in `internal/agents` and not in the HTTP table.
3. **`agents` has no row-level security and `migrations/00031` says why** (the
   table has no `account_id`), so the preview read works with the app role and
   needs no tenancy boundary. A live link names an unclaimed principal and there
   is no account in the flow.

## Not done

- `go test -race ./...` was not run over the whole tree in this attempt. The
  affected packages (`internal/httpapi`, `internal/agents`, `client`) were run
  without `-race` under `./bin/prime`. **The successor's first move is
  `TEST_DATABASE_URL=… go test -race ./internal/httpapi/ ./internal/agents/
  ./client/`** — the mutex-guarded `routeTable` in this package is the known
  flake source, and AGENTS.md holds all four gates.
- The website's allow-list comment naming this gap
  (`⚠ THIS ROUTE IS NOT IN IDENTITY YET`) is in another repository and was not
  touched.
