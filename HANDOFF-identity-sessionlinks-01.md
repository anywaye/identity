# HANDOFF — identity-sessionlinks-01

Branch `worker/session-links-01`. One commit landed: the token machine's fourth
purpose and its store tests, plus a fix to five schema assertions that could not
fail. **Neither route exists.** What is below is what the next session needs in
order to finish the packet, in the order the house rules require it.

## The state

| | |
|---|---|
| landed | `PurposeSessionLink` (`session_link`), `SessionLinkTTL` 10m, `MaxSessionLinkTTL` 1h, `allPurposes()`, `callerDeliveredPurposes`, migration `00020`, `internal/recovery/session_link_test.go` |
| not landed | the scope, `POST /v1/session-links`, `POST /v1/session-links/redeem`, `main.go` wiring, the four house tables (matrix / scopes / anonymous audit / drift), README |
| verified | `go build ./...`, `go vet ./...`, `gofmt`, `go test -count=1 ./...` (exit 0, 23 packages), `go test -race ./internal/recovery/` (ok), `go test ./...` with no `TEST_DATABASE_URL` (exit 1, by design — see below) |

**A scope cannot be landed alone.** `TestEveryScopeIsEnforcedOnItsRoutes` walks
`apikeys.AllScopes()` against the router, so adding the constant without the
route that enforces it turns the build red. That is the vocabulary working as
designed, and it means step 1 below cannot be a small commit.

## The database, before anything else

The brief's verify block says `docker compose up -d --wait postgres` and
`postgres://identity:identity@localhost:5432/identity`. **Neither is usable in
this workspace:**

- kit's `postgres` service publishes **15500**, and `identity-pg-verify` already
  holds that port. It belongs to somebody else — never stopped, never removed,
  and not started over.
- the local Postgres 18 on **5432** has no `identity` role at all
  (`FATAL: role "identity" does not exist`), so README.md:1293's DSN does not
  authenticate against the machine's own cluster either.

`identity-pg-verify` IS an identity verification cluster, at migration 18 before
this branch and 20 after, and it answers on:

```sh
export DATABASE_URL="postgres://identity:cafaye@localhost:15500/identity?sslmode=disable"
goose -dir migrations postgres "$DATABASE_URL" up
TEST_DATABASE_URL="$DATABASE_URL" go test ./...
```

Note the password: **`cafaye`, not `identity`.** The role takes
`KIT_POSTGRES_PASSWORD`, which is what AGENTS.md's identity-27 note says and what
the brief's DSN predates. Whether README.md:1293 wants correcting is a separate
decision and was not taken here.

## Step 1 — the scope and the mint route, together

`internal/apikeys/apikeys.go`. Name: **`sessions:write`**.

`read` is not in the vocabulary and must not be added for this: a link token is
minted, not listed, and a scope nobody exercises is a promise about the future.
Read the block comment on the scope list before writing the name — "there is NO
scope for sessions" is in it, and this feature is the case that changes that
sentence, so the sentence has to change with a reason in it, not around it.

`internal/httpapi/sessionlinks.go`, new file:

- `registerSessionLinkRoutes(r chiRouter)`, called from `registerRoutes`
  **unconditionally** — both routes need only a database, and a conditional
  surface is one thing more to add to `options` and to
  `TestEveryConditionalSurfaceIsVisibleToTheWalk`.
- `requireSessionLinkMint(next)` — machine credential only, modelled on
  `requireAdminToken`: a session gets **403**, not 401, and the middleware runs
  outside anything else so the property is a property of the surface.
- The scope gate itself: the mint route is **not** account-scoped, so
  `accountRouteScopes` does not apply. Check `caller.Key.Allows(...)` directly,
  or give the route an account path — do not invent a `requireAccountRole`
  wrapper for a route with no account in its path.

Unknown subject, decided: **404 with a problem document**. Behind a machine
credential the self-service calculus does not apply — there is no anonymous
stranger to protect, and a credential holding `sessions:write` is already inside
the trust boundary, so a caller that asks for a user who is not there is entitled
to be told. Write this in DECISIONS.md with the contrast against the
self-service flows (which answer 202 to an unknown address precisely because
they have no credential). Do not let it drift: the same route must not answer
"accepted" for an unknown subject, which would mint a token for nobody.

TTL: optional, ≤ `MaxSessionLinkTTL`, default `recovery.SessionLinkTTL`. Over the
ceiling is a **422**, never a silent clamp.

Response: `{token, expires_at}`, `201`. The token is rendered once, through the
existing redacting path if there is one; check `internal/httpapi`'s recovery
handlers for how a mailed token is written.

## Step 2 — the redeem route, and the MFA decision

`POST /v1/session-links/redeem`, body `{token}`, **public** (like
`POST /v1/session/mfa`, it is a challenge-shaped credential, not a session).
The response must be byte-for-byte `sessionResponse` + `setSessionCookie` from
`auth.go` — call those two, do not re-create them, and assert it.

**Ship the MFA refusal.** `internal/mfa` already knows how to answer "is this
account enrolled", and the honest shape is: a mint request for an MFA-enrolled
subject is refused with a precise problem code, tested, and the redeem route has
no code path that could bypass it. A refusal is shippable; a threaded challenge
flow on an unauthenticated route is a second authentication surface and is a
packet of its own. Say which one shipped, loudly, in the report.

Disabled/revoked user: `users` has the column; the redeem transaction must read
it and refuse. The refusal must be `recovery.ErrTokenNotFound`'s *shape* — the
same status, code and body as an unknown token — or the redeem route becomes an
"is this account disabled" oracle for a stranger holding a dead link.

## Step 3 — the four house tables, or the build is red

For each of the two routes, in this order: `openapi/v1.yaml` with an
`operationId`; `matrixEndpoints()`; `anonymousFamilyAudit()` (the redeem route is
reachable with no credential, and its row must answer the enumeration question in
one sentence); and `TestEveryRouteIsInTheMatrix`. Then README: route table,
scopes table, and a section beside Recovery saying the caller owns delivery and
landing.

## The red proofs already banked

Each was shown to fire by injecting the fault. Re-run them after step 1 — they
are the only evidence the machine is still a machine.

```
widened purpose CHECK   -> the database accepted a purpose this build does not
                           implement (x2 — Go and schema, both directions)
no expiry CHECK         -> the database accepted a token that expires the
                           instant it was created
no target CHECK         -> the database accepted a password reset token carrying
                           a target address
no first-side CHECK     -> ConfirmEmailChangeCurrent: no live recovery token
                           matches that
Consume without IS NULL -> 8 of 8 concurrent spends succeeded, want exactly 1
no TTLFor case          -> TTLFor(session_link) = 30m0s, want 10m0s
```

## The defect worth not rediscovering

Five schema assertions were `QueryRow(...).Scan(nil); err == nil`. `QueryRow`
defers a statement error to `Scan`, and `Scan` on a successful `INSERT` with no
result set returns `ErrNoRows` — **also an error**. Both directions were an
error, so the assertion held for any database whatsoever, including one with no
CHECK at all. They are `Exec` now, in `message_and_store_test.go` (x4),
`email_change_test.go` and `session_link_test.go`.

Anything else in this repository asserting "the database refuses X" with a
`QueryRow` and a nil destination is still vacuous. It is worth a grep before the
next schema packet.