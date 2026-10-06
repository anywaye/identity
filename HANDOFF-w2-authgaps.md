# HANDOFF — W2: identity, the Jumpstart auth gaps

**Branch:** `worker/w2-authgaps` · **Not pushed** (manager pushes) · **Base:** `1de6ef1`

## What the packet was for

Close three gaps against Jumpstart's authorization model: **account ownership
transfer**, **sudo / step-up re-auth**, and **impersonation**. The brief says to
pick *the one or two* that can be finished and verified properly, and prefers
transfer first.

**One of three is done: ownership transfer, complete and verified. Sudo and
impersonation are untouched.** Section "What I deliberately did NOT do" below says
why, with the specific obstacle each one hit.

## The database, first — read this before running anything

The suite is **green** (exit 0) with the manager's canonical DSN, which is the
compose stack, not a hand-built local cluster:

```sh
TEST_DATABASE_URL="postgres://identity:cafaye@127.0.0.1:15500/identity?sslmode=disable" go test -count=1 ./...
```

I spent roughly fifteen minutes of the hour on the wrong database. I built a local
cluster at `postgres://kaka@localhost:5432/identity`, and `dbtest.AppDSN` derives
the app login role as `<owner>_app` — so the pool connected as `kaka_app`, which
`migrations/00019_app_role_dml.sql` never grants to, because that migration
**hardcodes `identity_app`** rather than deriving it. 47 database tests failed
with `permission denied for table users`. That is not a repository defect and not
mine to fix; the manager's DSN is the answer and it was already in the tree's own
reports.

The one thing worth keeping from that detour: **`00019`'s hardcoded `identity_app`
against `00016`'s derived `current_user || '_app'` is a latent trap.** It works on
any cluster kit provisioned and breaks on any cluster that was not, and the
failure is a permission error rather than a role error. It is a one-line
observation for whoever owns the migrations, not a change I made.

## What is done and verified

`POST /v1/accounts/{account_id}/ownership-transfers` — routed, documented,
generated, gated, and in the authorization matrix.

**Commits (5, including the manager's mid-flight snapshot `45c1c54`):**

| commit | what |
|---|---|
| `d6eb144` | the transfer rules as a use case, with the negative tests |
| `587efee` | the route, the OpenAPI document, the matrix row, the regenerated client |
| `45c1c54` | *manager's* snapshot of the handler tests — superseded by `ee5dda4` |
| `ee5dda4` | the handler tests, and the fix to one that was passing for nothing |

### No migration, and that is a finding rather than an omission

Ownership in this repository is already the `owner` role on `account_users`
(`migrations/00005` has the enum; `00006`'s comment says "ownership is a role on
`account_users`, not a column"). So a transfer is two `SetRole` calls and an event
inside one transaction. There is nothing in `migrations/` to review, and adding a
migration would have meant adding a second source of truth for the same fact.

### The four rules, in the order they are answered

`accounts.Service.TransferOwnership`, `internal/accounts/service.go`:

1. caller is not this account's **owner** → `ErrNotOwner` (403)
2. account is **personal** → `ErrNotTransferable` (422)
3. fewer than **two members** → `ErrNotTransferable` (422)
4. new owner is the **caller** → `ErrTransferToSelf` (422)

**The order is the argument, and it is load-bearing.** The caller's authority is
settled before anything is said about the account, so an admin who asks learns
only that they are not the owner — not whether the account is personal, not how
many members it has. Reordering checks 1 and 2 turns every admin of every account
into a probe for its shape. `internal/accounts/transfer_test.go` asserts the
refusals against a **real store over real SQL**, so "a fake that always says the
caller is the owner" cannot hide a missing check.

### Three decisions worth a reviewer's attention

**The previous owner becomes `admin`, not `member`.** Jumpstart's comment is
"Previous owner roles are unchanged". Jumpstart stores ownership as a boolean on
the account *alongside* a separate `admin` boolean, so "unchanged" means the admin
flag survives. Here a membership is exactly one of three ordered roles, so
"everything they had except ownership" is precisely `RoleAdmin`. Demoting to
`member` would strip rename, invite and remove on the day of the handoff — and it
is what keeps a transfer **reversible**: an heir who turns out to be unavailable
is a problem a previous owner who can no longer administer the account cannot fix.

**The heir is promoted before the previous owner is demoted.** Inside one
transaction the account passes through "two owners", never through "none". The
commit is what makes the intermediate state unobservable from outside.
`guardLastOwner` is deliberately not consulted and the comment says why.

**One event, not two `role_changed` events.** `identity.account.ownership_transferred`
names both sides (`previous_owner_id`, `new_owner_id`, `transferred_by_id`). Two
independently ordered role-change events for one atomic change would let a
consumer interleave either with anything else and reconstruct an account with two
owners or none — exactly the states the transfer exists to prevent. The type is
pinned as undeclared in `knownUndeclaredEvents` with its reason (core has no
catalog row for it), and `cafaye.yml`'s gap note was restated from five types to
six.

### Verification, with the runs behind it

```sh
# full suite
TEST_DATABASE_URL="postgres://identity:cafaye@127.0.0.1:15500/identity?sslmode=disable" \
  go test -count=1 ./...                                          # exit 0, 24 ok, 0 FAIL

go vet ./...                                                      # exit 0
gofmt -l .   # clean apart from three files that are dirty at 1de6ef1:
             #   internal/platform/ci/rollback_test.go
             #   internal/platform/ci/substrate_copy_test.go
             #   internal/tenancy/user.go
```

The three gofmt files are pre-existing and I did not touch them. I confirmed that
by stashing everything and running `gofmt -l .` on `1de6ef1`.

**Negative cases, all asserted, none assumed:**

| asserted | where |
|---|---|
| a non-owner (admin, member) cannot transfer | `TestANonOwnerCannotTransfer` |
| an owner of a *different* account cannot | `TestAStrangerCannotTransferEvenWithAnAccountID` |
| a personal account cannot — with a second member, so it is refused for the right reason | `TestAPersonalAccountCannotTransfer` |
| a one-member account cannot — and naming a stranger does **not** admit them | `TestAnAccountWithOneMemberCannotTransfer` |
| an owner naming themselves is its own refusal | `TestTransferToTheCurrentOwnerIsRefused` |
| a failing outbox rolls back **both** role changes | `TestTransferFailsWithoutMutatingAnythingWhenTheEventCannotBeWritten` |
| matrix: 401 anon, **404 non-member**, 403 member, 403 admin, 200 owner | the `transfer ownership` row |

The transaction test is in the direction that matters: a service that rolled
everything back would pass every happy-path test perfectly.

### The check that did not exist

`TestABodyThatNamesAnActorIsRefusedRatherThanHonoured`. `decodeBody` uses
`DisallowUnknownFields`, so a body carrying `"actor"` is a 422 and the handler is
never entered. That is stronger than ignoring an unknown field, and it is
enforced by a mechanism belonging to another route — so it needed its own test.

### One test of mine was passing for nothing

`TestTheCallerComesFromTheCredentialAndTheHeirFromTheBody` originally read the
recorded use-case call and asserted on it **without checking the request had been
accepted**. It passed under `go test -run Transfer` and failed the full suite,
where a sibling test showed the real behaviour: the `"actor"` body is rejected,
so the recorded call is all zeros and the three assertions pass on an untouched
double. `ee5dda4` asserts the status first and splits the extra case out. It is in
the commit message because it is the kind of defect a reviewer should be able to
find without reading this file.

## The checks that fired without being asked

- `TestTheReadmeEndpointTablesAreTheRoutesTheRouterServes` — failed on the missing
  README row. Three README rows added (route list, endpoint table, scope table).
- `openapi_drift_test.go` — passed first time, because the document was written
  in the same commit as the route.
- `TestTheCoverageExclusionIsOnlyGeneratedCode` — failed at 26627→27602 lines.
  Restated with a **measured** 6418 statements (`go test -coverprofile` over
  `./client/generated/`, summing `numStmt`), never carried forward.
- `TestTheTransportCoversEveryOperationInTheDocument` — failed on the new
  operationId. `Transport` method + `Client` wrapper added, and
  `TestTheClientNeverPrintsACredential`'s sweep covers the new signature.
- `TestTheManifestDeclaresEveryEmittedEvent` — failed on the new event type.
- `TestEveryRouteIsInTheMatrix` — failed on the missing row.

## Decisions and why

**`ownership-transfers` is a collection, not a PUT of the account.** Ownership is a
role on a membership, not a field, so there is no account resource whose current
representation of "owner" a `PATCH` could be. The plural resource is what lets
the response — both memberships — be something a client renders without a second
request.

**The response carries both memberships.** The person who made the request is the
previous owner; they need to know what they are now, and this service is the only
thing that knows. `account.role` carries the same answer at the account level.
Note that `account.role` is resolved by the middleware **before** the write, so
after a transfer it still reads `owner`. That is asserted explicitly in
`TestTheTransferResponseCarriesBothMembershipsAndTheDemotion` with a comment
saying why — it is correct, and it looks like a bug.

**One error for two facts (`ErrNotTransferable`).** "Personal" and "one member"
are 422 for the same client-facing repair — this account is not one that changes
hands — and separating them would invite a client to distinguish them for no gain.

**`new_owner_user_id` is 404, not 422.** "This is not an id we issued" and "this
is one and you may not have it" are not distinguishable from outside. A 422 would
make the request body a probing surface.

**No admin-audit-log record.** The transfer is a session-route mutation, and
`internal/admin`'s `Audited` is for the token-only admin surface. Deliberate, and
flagged here as the weakest seam in this packet: **the outbox event is currently
the only record that a transfer happened.** If audit becomes a requirement, this
is the gap.

## What I deliberately did NOT do, and why

**Sudo / step-up re-auth — not started, and it is the one to pick up.** Its
interesting property is the one the brief calls out: `URI.parse(redirect_to).path`
keeps only the path, so the post-sudo redirect cannot escape to another host. That
property cannot live in a handler. It belongs beside whatever **assembles** the
destination, and this repository has no such assembler: `identity` renders no HTML
(AGENTS.md D10, three checks behind it), so there is no form posting to
`/users/sudo` and no page to return to. The redirect rule has no call site here.
Sudo is a **session state + a gate on other routes**, and mounting it means
inventing the surface it protects — which is a design decision, not a port. Doing
it badly in twenty minutes would have meant a redirect helper with no user, which
is exactly the "tested but unwired" shape AGENTS.md says to delete rather than
leave.

**Impersonation — not started, and its missing prerequisite is a schema.** The
rule the brief names is real and simple: check staff on the **true** user, never
the impersonated one. But `internal/users` has **no `staff` column** (checked:
`migrations/00002_users.sql` through `00022`), so "is this user staff" has no
answer in this repository. And the rule cannot be half-ported: a service that
resolves the effective user without also resolving the true one has no way to
enforce "no privileges the true user lacks", because there is nowhere to read the
truth from. Worse, impersonation cuts across **every** authorization decision in
the service — `requireAccountRole` reads a membership resolved from a session, and
`currentCaller` is the single place a caller is resolved. It is not a new route; it
is a change to the one function that decides who is asking. That is a packet with
its own matrix review, not one hour.

**No mail.** Jumpstart notifies the new owner. `internal/courier` has a
`RecoveryMailer` that **refuses to construct** without a link template for every
purpose it can deliver, and the recovery purpose set is closed. Adding a
purpose-independent notification mailer is a courier change with a config
contract, and the outbox event already carries both sides for whatever consumes
it.

**No migration, no new dependency, no `docker-compose.yml` edit, no route/document
or existing assertion weakened.** All four held.

## Successor's first move

For **sudo**, start by answering one question in `DECISIONS.md`: *which route
requires re-authentication, and what is its session state?* Concretely — read
`internal/sessions/sessions.go` and decide whether a `sudo_at` is a column on
`sessions` or a claim in the session row, then write the redirect-path helper as
a pure function with a table test over
`https://evil.test/x`, `//evil.test/x`, `/\evil.test`, and
`/ok?next=https://evil.test`. That pure function is worth committing on its own
even before anything calls it — it is the part that cannot be got wrong later.

For **impersonation**, the first move is a decision, not code: does "staff" mean a
column on `users` (a migration, and then who sets it), or a membership in a
reserved account, or an api key scope? Whichever it is, it is a privilege that
already exists nowhere in this service, and it needs its own scope row and its own
column in the matrix before a route is written.

Either way: **`TEST_DATABASE_URL` first.** Fifteen minutes of this hour went into
a cluster that was never going to work.