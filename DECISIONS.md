# Open decisions

Every question this repository has not been told the answer to, numbered, with
the call that was made so the work could continue and the cost of making the
other one.

This file did not exist before packet `identity-09`. The two places an open
question in this repository used to live were `moon/DECISIONS.md` — which numbers
`MD…` and holds questions about the workspace rather than about one service — and
a `> DECISION NEEDED (…)` callout in `cafaye.yml`, which is where the
`openapi/v1.yaml` scope-claim question lives and which core's D6 shape moved
away from. Neither is identity's own record, and a packet that had to escalate
something had nowhere to put it. So the file is `DECISIONS.md` at the repository
root, numbered from D1, and the callouts in `cafaye.yml` keep pointing at the
question they raise.

**A settled decision moves into the [CHANGELOG](CHANGELOG.md)'s decision table
and its entry here is deleted; the number is never reused.**

| # | Question | Call made |
| --- | --- | --- |
| [D1](#d1-twelve-served-operations-are-in-no-document) | twelve served operations are in no document — document them, or rule them out of the contract? | **RULED by `identity-28`: they are contract surface.** All twelve documented; `knownDrift` empty and pinned at empty — see [the ruling](#d1-ruled-2026-10-02-by-packet-identity-28-option-1-and-here-is-why) |
| [D2](#d2-the-privilege-boundary-of-the-admin-surface) | what exactly may an account admin do that a member may not? | RULED: one sentence, and the code says exactly it. Three operations, two scopes, one table |
| [D3](#d3-where-the-audit-record-lives-and-why-nothing-can-edit-it) | where does the admin audit record live, and how is it made un-editable? | RULED: `account_audit_log`, append-only in the DATABASE, no foreign key to `accounts` |
| [D4](#d4-the-admin-surface-is-token-only) | may a browser session reach the admin surface? | RULED: no. Token-only, and the refusal is asserted per route |
| [D5](#d5-bulk-and-single-revocations-do-not-share-a-shape) | does a bulk revocation take the same request shape as a single one? | RULED: no. `confirm` in the body, a higher minimum, and both counts returned |
| [D6](#d6-the-generated-client-commits-a-dependency-that-md6-said-it-would-not) | the generated client commits a runtime dependency, which MD6 said it would not — and it takes the coverage floor | RULED, with MD6's stated REASON corrected: the client ships here, generated, and the dependency is paid for |
| [D8](#d8-one-link-template-for-four-messages-and-what-the-deployment-inherits) | one link template served all four messages — so a verification mail's button opened the password-reset screen. What does the template a deployment already set now MEAN? | RULED: it is the DEFAULT for every purpose with no template of its own, so nothing breaks at boot, and a purpose with neither is refused by name at startup |
| [D9](#d9-registration-publishes-that-an-address-is-taken-and-that-is-the-last-one) | `POST /v1/users` answers `409` for a taken address, so an unauthenticated caller can discover whether anybody has an account here. Is that disclosure accepted, or does registration change shape? | RULED for now: it is accepted, and it is named. Closing it is a decision about products, not about identity |
| [D10](#d10-identity-renders-no-html-and-the-browser-belongs-to-parlor) | `identity` must not have its own views — the frontend belongs to `parlor`. But the page *is* the AS's user-agent interaction, and OpenID Connect Core §3.1.2.1 makes that part of the provider's job. Does the page move, and if so, what crosses the boundary and what does not? | RULED: it moves. identity keeps every authorization decision and hands the browser to a configured login UI. The contract is published in `internal/oidc/loginui.go` and `openid/openid.yaml` |
| [D12](#d12-an-unknown-subject-is-a-404-behind-a-machine-credential-and-a-202-in-front-of-a-stranger) | the session-link mint names a subject. The self-service flows answer `202` for an unknown address because they have no credential. What does this one answer? | RULED: **404 with a problem document**, because the caller already holds `sessions:write` and there is no anonymous stranger left to protect. The contrast with the self-service flows is the decision, not the status |

## D1: twelve served operations are in no document

> **RULED 2026-10-02 — [option 1, below](#d1-ruled-2026-10-02-by-packet-identity-28-option-1-and-here-is-why).** Everything in this section is the finding and the two calls as `identity-09` left them; the ruling is the section after it, and the twelve are now documented.

**Raised** 2026-09-30 by packet `identity-09`, which added the document-versus-
router tripwire (`internal/httpapi/openapi_drift_test.go`) and found this on its
first run. It is a finding, not a nuisance, and it is the seventh such check in
the fleet to fire.

**What was found**, read out of chi's own walk of the router and out of both
committed documents rather than off a list anybody wrote:

- **Ten tenancy operations.** `POST` and `GET /v1/accounts`,
  `GET`, `PATCH` and `DELETE /v1/accounts/{account_id}`,
  `GET /v1/accounts/{account_id}/members`,
  `POST /v1/accounts/{account_id}/invitations`, `PATCH` and
  `DELETE /v1/accounts/{account_id}/members/{user_id}`, and
  `POST /v1/invitations/accept`. Served since the accounts packet. In neither
  `openapi/v1.yaml` nor `openid/openid.yaml`, and not in the README's endpoint
  table either — so the document, the manifest's `exposes.api` and the README all
  describe a smaller service than the one that runs.

  They are not untested. All ten are rows in the authorization matrix, and seven
  of them declare a scope in `accountRouteScopes`, so they are gated, scope-
  checked and exercised. What is missing is that nobody ever wrote down that they
  are contract surface. That is the specific shape of the gap: **checked for
  authorization, unrecorded as contract.**

- **Two OIDC operations.** `POST /oidc/authorize` and `POST /oidc/userinfo`.
  `registerOIDCRoutes` mounts `GET` and `POST` on both, and says why in a
  comment: OpenID Connect Core permits both and "a product behind a strict
  corporate proxy may have no choice". `openid/openid.yaml` wrote down only the
  `GET`.

  This one is worth reading twice, because it is **billing's bug, already here**.
  billing's first drift check compared paths and never `route.verb`, so
  `resources :customers, only: %i[… update]` emitting both `PATCH` and `PUT`
  passed it: one path on each side, and the comparison reported agreement while
  `PUT /v1/customers/{id}` was served in a money-handling service and written
  down nowhere. The shape is identical here, on the OIDC surface of the service
  that issues every credential in the platform.

**What this packet did, and why not more.** `identity-09` was scoped to add a
check and explicitly not to add operations, so the two obvious fixes were both
closed: writing the twelve operations into `openapi/v1.yaml` is a content change
this packet may not make, and calling them "not client operations" in an
exclusion list would be false about all twelve — they are the most client-facing
routes in the service.

So the twelve sit in `knownDrift` in `openapi_drift_test.go`, which is named for
what it is rather than for what it excuses, and which:

- cannot grow — `TestKnownDriftIsExactlyTheRoutesItClaimsToBe` fails on a
  thirteenth entry, so a new undocumented route is red whether or not anybody
  remembers that file;
- cannot be emptied either, so the list cannot be deleted instead of the routes
  being fixed;
- is checked for staleness in both directions — an entry naming a route the
  router no longer serves, or one a document now describes, is a failure.

**The two calls available**, and this packet did not make either:

1. **They are contract surface; document them.** Twelve operations with full
   request and response schemas, an `info.version` bump, a CHANGELOG entry naming
   the operations added, and rows in the README's endpoint table. This is the
   answer that makes `knownDrift` empty and is almost certainly right for the ten
   tenancy routes — the platform generates clients from these documents, and a
   product that cannot call `POST /v1/invitations/accept` from a generated
   client has a real gap. The cost is a large document change in a packet that
   has to be its own, and it should be reviewed as contract rather than as
   bookkeeping.

2. **They are not contract surface; rule them out of it, in writing.** The
   `/v1/accounts` collection routes are the arguable ones: `GET /v1/accounts`
   answers "which accounts does this **user** belong to", which is a session's
   question and not a token's, and the README already argues a machine credential
   is not entitled to an inventory of every tenant its owner is in. If that logic
   extends to "these are never client operations", it has to be recorded — in the
   document's own header and in the README, which is what courier's
   `openapi_document_test.exs` requires of its own exclusions, and what makes the
   ruling a claim rather than a gap the check happened to miss.

The two OIDC `POST`s are not seriously arguable under either answer: the code
says both methods are deliberate, so the document either gains a `post` beside
its `get` or the router drops the `POST`. Dropping it would contradict the
comment that justifies it, and would break a product behind a strict corporate
proxy, which is the case the comment names.

**What is not an answer**: growing `knownDrift`, or adding a prefix filter to the
check. Both make a red go away without making the service true, and the first is
the failure mode the packet's own test exists to catch.

**Update from `identity-11` (the admin surface).** This packet added three
operations to the router and `knownDrift` **did not grow** — it is still twelve,
and `TestKnownDriftIsExactlyTheRoutesItClaimsToBe` still pins it at twelve. The
three were **documented** in `openapi/v1.yaml` under a new `admin` tag, with
operationIds, request and response schemas, and `info.version` bumped to 1.4.0.

That is the answer to D1's option 1, applied to three operations, and it is
evidence rather than argument: adding a route to this service is a routine
operation when the route is documented, and the twelve below are still
undocumented because nobody has done it for them.

**A finding worth recording, because it is about this file's own check.**
`identity-11` found that `TestEveryServedRouteIsDocumentedOrNamed` — the reverse
direction, the check holding these twelve — **passed green while three
undocumented operations were mounted**. `servedRoutes` builds an `options` struct
literal to make every conditional surface take its "configured" path, and the new
`admin` field was not in it, so `registerAdminRoutes` returned early and the walk
read a smaller service than the one that runs. `TestEveryRouteIsInTheMatrix` was
blinded the same way, at the same time.

The check went green **by not checking**, which is the one outcome this file
exists to prevent, and it happened to the check written to catch precisely that.
`internal/httpapi/router_walk_test.go` now holds the property:
`TestTheDriftWalkSeesTheAdminSurface` and `TestTheMatrixWalkSeesTheAdminSurface`
assert the walks FIND the routes, and `TestEveryConditionalSurfaceIsVisibleToTheWalk`
keeps a list of every surface field that can cause a registrar to skip its routes.

The general lesson, and the reason it is in DECISIONS.md rather than only in a
test comment: **a struct literal used to configure a check is a completeness
obligation, and nothing about it looks like one.** A conditional route makes the
omission silent and the suite green.

## D1 RULED, 2026-10-02, by packet `identity-28`: option 1, and here is why

**The ruling.** All twelve are contract surface. The ten tenancy operations are
written into `openapi/v1.yaml` under a new `tenancy` tag with request and
response schemas, operationIds and the full status table; the two OIDC `POST`s
are written into `openid/openid.yaml` beside the `GET` they duplicate.
`info.version` is **1.7.0**. `knownDrift` is **empty**, and pinned at empty.

### Why option 1, stated as the argument rather than as the preference

The alternative was not "document them or leave them broken forever" — it was
"rule them out of the contract, in writing". That would have produced a document
that describes a service that does not exist, and it would have been defensible
prose. Three facts make it wrong here.

1. **The strongest evidence for option 1 was already in the document.** The
   `bearerToken` scheme's required-scopes table has named `getAccount`,
   `listMembers`, `renameAccount`, `inviteMember`, `changeMemberRole`,
   `removeMember`, `deleteAccount`, `listAccounts`, `createAccount` and
   `acceptInvitation` since 1.4.0 — the operationIds, by name — because seven of
   those routes enforce a scope and a scope that gates a route no document
   declares is a promise with nothing behind it. So this repository was already
   committed to these being client operations; it had not noticed that it had.
   The ten names in the table are now the method names on every generated client,
   and the table and the document agree for the first time.

2. **The customer-facing cost was measured, not estimated.** `cafaye-ts` is the
   TypeScript client `parlor` itself calls and the one a customer writes against.
   Its generated identity methods were `createClient`, `createSession`,
   `deleteSession`, `getCurrentUser`, `getEmailVerificationStatus`, `getMfaStatus`,
   `getOidcClient`, `introspectApiKey`, `listAccountAuditLog`, `listApiKeys`,
   `listOidcClients`. **No `createAccount`. No `inviteMember`. No
   `acceptInvitation`.** A customer could list an account's API keys and OIDC
   clients and had no way to make the account. We are selling hosted identity to
   a customer who cannot onboard a tenant through the client we ship, and that is
   not a documentation debt — it is the product's first call failing.

3. **The "not client operations" ruling could not have covered the OIDC pair at
   all**, and could not have covered the account detail honestly. `GET
   /v1/accounts/{account_id}` and `GET /v1/accounts/{account_id}/members` are
   member-and-role reads on a product's own tenant: the two operations a settings
   page cannot be built without. Only the **three collection operations** are
   genuinely session-shaped, and they are not excluded — they are documented with
   `security: [sessionCookie]` and a 403 on a token, which is the accurate
   statement and is strictly better than a sentence in a header saying "these are
   never client operations".

### What it cost, honestly

- **A large contract change in one commit**, reviewed as contract rather than as
  bookkeeping. That was the cost `identity-09` named, and it is real: about
  900 lines of `openapi/v1.yaml` and the whole of the Go client regenerated on
  top of it.
- **One response shape changed**, on the two member-list operations. See below;
  it is a behaviour change and it is stated in the document's own version history
  rather than only here.
- **`knownDrift`'s "cannot be emptied" clause had to be rewritten**, because the
  clause was written against a list of *known bugs* where deleting an entry could
  have meant deleting the memory of a gap. That is no longer the shape: the list's
  own comment now records all twelve and the commit that closed them, so the
  memory survives the removal. `TestKnownDriftIsEmptyBecauseEveryServedOperationIsDocumented`
  pins it at zero and its failure message is the whole of the argument for why a
  future entry is not the answer.

### The defect this packet found by having to document the response

`membershipResponses` in `internal/httpapi/accounts.go` projected only `Role`,
because `accounts.MemberSummary` is shaped for `ListMine` ("which accounts does
this user belong to") and carries the ACCOUNT and the role and no user.
`Members` reuses the same struct for the other direction, and the wire carried:

```json
[{"account_id":"","user_id":"","role":"admin","created_at":"0001-01-01T00:00:00Z"}]
```

**A member list whose entries cannot be told apart, on the two operations whose
whole purpose is to be acted on by `user_id`.** `PATCH` and `DELETE
/v1/accounts/{account_id}/members/{user_id}` both need a user id the response did
not carry, so nothing in the service could have rendered or removed a member.

Two honest readings, and the packet took the first:

- **The alternative was to leave those two operations in `knownDrift`** with a
  reason naming this blocker. That is the escape the brief allows and it would
  have been defensible.
- **The other was to fix the projection** — four fields on `MemberSummary`, two
  on the select list, four lines in the projection — and document the shape that
  results. It was chosen because a documented operation whose response cannot
  identify its own subject is a contract that lies green, which is the most
  expensive kind of wrong in a document; and because **no client can be reading
  the old shape**, since these operations were in no document at all, so there is
  no migration and no consumer with a switch on it.

`TestEveryMemberInAMemberListIdentifiesItself` holds the result, on both routes,
by asserting that every entry names a user, names the account, and carries a
non-zero `created_at`.

### What is still true, and what this ruling does NOT cover

- **The neighbouring event gap is untouched and still real.** identity emits five
  events no manifest declares: `identity.account.created`, `identity.member.
  invited`, `identity.member.accepted`, `identity.member.role_changed`,
  `identity.member.removed`. This packet **re-verified the blocker against core at
  `5ec0cec` and it still holds**: core's `schemas/events/identity/` has `api_key`,
  `mfa`, `oidc_client`, `session` and `user` and **no `account/` and no
  `member/`**, and `identity.member.accepted` has no catalog row at all under that
  name (core calls the fact `identity.member.joined`). Declaring the five today
  would trade a silent gap for five `event.payload-schema-missing` reds and one
  `event.unknown-published`. So they stay undeclared, pinned with a reason in
  `internal/platform/ci/event_grammar_test.go`. **What core needs, if it takes
  this: five files at `schemas/events/identity/account/created.schema.json` and
  `schemas/events/identity/member/{invited,accepted,role_changed,removed}.schema.json`,
  plus a catalog row for `identity.member.accepted` or a recorded ruling that
  `accepted` and `joined` are the same fact.** That is core's packet, not this one.
- **A second defect was found while verifying and is NOT fixed by this packet.** See
  the CHANGELOG entry and the report: **a revoked invitation still redeems.**
  `Store.InvitationByToken` has no `revoked_at` filter and
  `Store.MarkInvitationAccepted`'s conditional UPDATE requires only
  `accepted_at IS NULL`, so `POST /v1/invitations/accept` creates a membership
  from a token an admin explicitly withdrew — and leaves a row with both
  `accepted_at` and `revoked_at` set, which `migrations/00013`'s own header says
  cannot happen. `TestTheRevokedInvitationIsActuallyDead` passes while this is
  true because it posts the redemption **with no credential** and reads the 401 as
  the refusal. That is a security finding on the admin surface and it belongs to
  its own packet; it is recorded here so it is not lost, and nothing in this
  packet's document change depends on it.
- **`D9`'s 409 on `POST /v1/users` is still open** and untouched. This packet
  documents the tenancy surface and says nothing about registration.
- **core's D25** — may a service document `/healthz` and `/readyz`? — is still
  core's. identity documents both and this ruling does not touch that.

## D2: the privilege boundary of the admin surface

**Raised** 2026-09-30 by packet `identity-11`, which added the admin surface and
had to say what it was for before it could be reviewed.

**Ruled: an account admin may revoke pending invitations to their own account and
read that account's admin audit log — authority over other people's pending
access, and nothing else.**

One sentence, and the reason for insisting on one sentence rather than a
paragraph is the sentence's own failure mode: **a role checked in thirty places
is a role that will be checked in twenty-nine of them.** So the sentence is not
documentation of a boundary, it is the boundary, and the code says exactly it:

| operation | minimum | scope |
| --- | --- | --- |
| `GET /v1/accounts/{id}/admin/audit-log` | admin | `audit_log:read` |
| `DELETE /v1/accounts/{id}/admin/invitations/{id}` | admin | `account_invitations:write` |
| `POST /v1/accounts/{id}/admin/invitation-revocations` | **owner** | `account_invitations:write` |

Three rows in `accountRouteScopes`, and there is no fourth without a decision:
`TestTheScopeTableIsTheWholeBoundary` fails if the table gains an admin route, and
a new capability is a new scope in `internal/apikeys`, which is a file whose whole
argument is that a token is granted exactly what it names.

**The one-sentence test, and what it rules out.** Read the sentence and ask what
is not in it:

- **Not "manage the account".** `accounts:write` already covers rename, invite
  and remove-member, and an admin holds it. The admin surface is *not* that
  surface and deliberately overlaps none of it.
- **Not "read anything about members".** `accounts:read` covers that.
- **Not "see the account exists".** The trail is a record of *authority being
  used over time*, which is a different sensitivity from the account's current
  shape — which is why it has its own scope rather than riding on `accounts:read`.
  A CI token that can read the account should not thereby hold a standing record
  of every administrative action taken against it.
- **Not "act for any user".** There is no impersonation here, and adding it would
  be a fourth capability the sentence does not contain.

**Why invitation revocation, specifically.** 00007's own comment says a user
deletion is "refused by the database until they are revoked, which is a later
packet" — this is that packet's schema half. It is also the operation with the
right blast radius to justify a separate surface: an admin who sent an
invitation to the wrong distribution list needs to recall it, and the obvious
implementation (`DELETE` the row) would have destroyed the answer to "was this
revoked, or was it always broken?" — the same support question that keeps revoked
api keys and OIDC clients. So `revoked_at` is a column and the row is kept
(00013), and revoking **frees the address to be invited again**, which is the
whole point of the operation.

**Not a decision this packet could make:** a *platform* admin — one operator
across every tenant — does not exist and is not implied. The sentence is scoped
to "their own account" and the code enforces it: a token presented against a path
naming a different account is a 404 from `requireAccountRole`'s existing
membership lookup, and `TestAnAdminCannotReadAnotherAccountsTrail` proves it
over real SQL. A cross-tenant operator surface is a different design with
different answers, and building it needs a decision this packet may not make.

## D3: where the audit record lives and why nothing can edit it

**Raised** 2026-09-30 by packet `identity-11`.

**Ruled: `account_audit_log`, in identity's own database, appended in the same
transaction as the mutation, and refused `UPDATE` and `DELETE` by a database
trigger.**

**Why the same transaction, and how it is not merely intended.** Every operation
on `admin.Service` goes through `Audited`, which takes the mutation as a callback
and runs it inside the transaction that also writes the record. There is no
exported method that mutates without recording, so "somebody added an admin
action and forgot the audit row" is not a mistake this package's shape permits —
it needs a new exported method, which a review sees.

The proof is in both directions and both are asserted against a real database
with a `BEFORE INSERT` trigger that raises
(`TestAFailedAuditWriteRollsBackARealMutation`,
`TestAFailedMutationRollsBackARealAuditRecord`):

- the audit write fails → the transaction rolls back → **the mutation did not happen**
- the mutation fails → the transaction rolls back → **no record claims it did**

Asserting the happy path would have proved nothing, which is why the negative
proofs are the ones that carry the weight and the positive one
(`TestTheAuditRecordIsWrittenInTheSameTransactionAsTheAction`) exists only to
show the happy path writes *both* rows — a service that rolled back everything
would pass the negatives perfectly.

**Why the immutability is in the DATABASE and not in Go.** Three layers, in the
order a reviewer asks:

1. `GET` is the only method mounted on the audit path —
   `TestTheAuditTrailIsNotWritableThroughThisAPI` walks the router, because a
   check inside the handler would pass with a `DELETE` registered beside it.
2. `AuditStore` has `Append` and `List` and nothing else, so there is no
   function to call.
3. **The table refuses `UPDATE` and `DELETE`** (00012's trigger).

The third is the one that settles it, and the reason is that the first two only
describe *this codebase*: a repair script, an operator with `psql`, or a future
packet all bypass Go entirely, and the requirement is that the record survives
the admin whose action is in it. `TestTheAuditRecordCannotBeUpdated` and
`TestTheAuditRecordCannotBeDeleted` issue the statements **directly against the
pool**, which is what makes them proofs rather than restatements of the service's
own API.

**Why there is no foreign key to `accounts`, and this is the load-bearing line of
00012.** Every other table in this schema cascades from `accounts`. A cascade is a
`DELETE`, and this table does not delete — so a cascading account deletion would
be blocked, and `DELETE /v1/accounts/{account_id}` is a shipped route a tenant may
legitimately call. Exempting the cascade is not reliably possible: a trigger
cannot tell a cascading delete from a deliberate one.

Dropping the reference instead buys the strongest form of the property:

> **The admin surface cannot delete its own audit log by deleting the account.**

The shortest route from "an admin did something questionable" to "there is no
record of it" would otherwise be one request, and this packet's requirement would
be satisfied by the router rather than defeated by it. The rows become
unreachable through the API and are retained for an operator reading the table
directly. Same for the actor: `actor_key_id` is a bare uuid, so revoking or
deleting the credential does not erase what it did
(`TestTheAuditLogCannotBeReachedByRevokingTheToken`).

**Never a credential.** `actor_user_id` and `actor_key_id` are row ids, and there
is no field anywhere in `internal/admin` that a token could be written into. That
is structural, not a convention: `apikeys.Key` has a `TokenDigest` field, a
handler holds one, and an audit log is exactly where a careless
`fmt.Sprintf("%+v", caller)` would end up.
`TestNothingOnThisSurfaceCanRecordAToken` reflects over the types that reach the
table and fails if any grows a field that could hold a value, and
`TestAnAdminActionNeverWritesACredential` checks all four places a record could
leak — response body, audit row, application log, and problem document.

## D4: the admin surface is token-only

**Raised** 2026-09-30 by packet `identity-11`.

**Ruled: no admin route is reachable with a user session. A session is refused
with 403, and the refusal is asserted per route rather than in a helper.**

The security argument is the packet's: a session is a browser credential, and an
admin surface a session cookie opens is an admin surface one CSRF away from being
somebody else's. The second argument is this one, and it is the more interesting:
**an admin action must be attributable to a credential.** Every action on this
surface is recorded against the api key's row id, so a token is something an
audit record can *name* and a session is not. `adminActorFrom` refuses a caller
whose `KeyID` is zero rather than writing a record naming no credential.

This is the exact mirror of `sessionCredentialOnly`, and the two together mean no
route in this service is reachable by both kinds of credential unless somebody
wrote that down deliberately. `requireAdminToken` runs **outside**
`requireAccountRole`, which is what makes it a property of the surface: a check
inside a handler has whatever that handler remembered, and the route added next
is the one without it.

**Two consequences worth recording, because both are visible in the matrix and
both would otherwise read as bugs.**

- **The anonymous column is 403 on these three routes and 401 on every other row
  of the authorization matrix.** `requireAdminToken` runs first, so a request
  with no credential at all is refused as a *wrong kind of caller* — and on a
  route whose entire authentication story is "a scoped api key", that is the more
  informative answer than "who are you". `expectedStatus` in the matrix had to
  have its override checked *before* its authentication check for this to be
  recordable at all; it was the other way round, and the three rows were silently
  being answered 401 for a service that does not give that.
- **The matrix has a genuine hole on this surface, and it is stated rather than
  papered over.** The matrix's six columns are six *sessions*, so on a token-only
  surface every column is a 403 and the matrix carries no positive cell for these
  three routes at all. The token/session axis is the authorization this packet
  adds and the matrix cannot express it. What covers it instead:
  `TestNoAdminRouteIsReachableWithASessionAlone` (per route),
  `TestAnAdminTokenHoldingNeitherScopeIsRefused`,
  `TestTheBulkRouteIsOwnerOnly` (per role), and the rows are in the matrix so
  `TestEveryRouteIsInTheMatrix` still demands them.

**R2, the accountless token.** A service-to-service token with no `account_id` is
**refused, not defaulted**, and this packet did not need to build the refusal
because `api_keys.account_id` is `NOT NULL` and `claims.ClaimsFor` returns
`ErrNoAccountID`. What the packet owes is the *proof per route*, and that needs a
double: a token with no account would mismatch the path's account and be refused
**incidentally**, by the account comparison every account route already runs — so
a test using the real service would pass while proving nothing about the admin
surface. `TestATokenWithNoAccountIsRefused` manufactures the specific shape with
every scope in the vocabulary, so nothing about the scope gate can be what
refuses it, and asserts per route that the use case is never reached.
`TestAnAccountlessTokenCannotReachTheAdminSurface` records *why* the double is
needed, by asserting the row is unrepresentable in the schema.

## D5: bulk and single revocations do not share a shape

**Raised** 2026-09-30 by packet `identity-11`.

**Ruled: a bulk revocation requires `confirm: true` in the body, a named array of
at most 50, and an OWNER — where the single revocation needs none of those and an
admin.**

A bulk operation is the one where an off-by-one is an outage, so it does not look
like the single one, and the difference is in the **request shape** rather than in
a dialog — because a dialog is not something an API client has.

| | single | bulk |
| --- | --- | --- |
| request | `DELETE …/invitations/{id}` | `POST …/invitation-revocations` with a body |
| confirmation | none — the URL names the one row | **`confirm: true` required** |
| array | none | **required, 1–50** |
| minimum | admin | **owner** |
| response | 204 | `{requested, revoked}` |

**Why `confirm` is in the body and not a query parameter:** so that the request
that performs the operation and the request that describes it are the same bytes.
A `?confirm=true` is one link-builder's accident away from being sent without an
operator reading it, and the array is exactly the thing that must not be sent by
accident. Absent, `false` and the wrong JSON type are all the same 422 — a client
that got a different answer for `false` than for absent would have learned which
one it sent — and an unknown field is a 422, so a client misspelling `confirm` as
`confirm_all` is told rather than proceeding.

**Why the single route needs no `confirm`:** the URL names the one thing being
changed, so there is nothing in it that could be misread as "and everything else".
Adding a `confirm` field there would mean a client that forgot to send it gets a
422 on a safe, idempotent, single-row operation —
`TestTheSingleRouteNeedsNoConfirmation` exists because the tidying instinct is to
add it.

**Why owner and not admin:** revoking one invitation is a decision about a person.
Revoking every pending one is a decision about the account, it is the operation a
departing employee's automation might fire on a schedule, and there are only two
roles above `member` — the smaller one already has the single-revocation route.

**Why both counts are returned.** `revoked` is frequently smaller than
`requested`, because an id that was already revoked, or one belonging to another
account, changes no rows. A response carrying only one number would be a client
unable to tell "you asked for four and four went" from "you asked for four and
two went because two were never there" — and on an admin surface that is the
difference between a completed task and an incident.

**Why the bounds are refused and not clamped.** A request for 500 rows that
quietly received 100 has been told a lie about how much of the trail it has read,
and an operator building an export produces a short one without knowing
(`TestTheAuditLogBoundsAreEnforced`). Same reasoning for the 50-id array: a
request naming a thousand invitations that revoked the first fifty and reported
nothing is the outage this design exists to make harder.

**The cursor, and a bug this packet's own test found.** `before` is an **opaque
token encoding the row's `(occurred_at, id)` pair together**, returned as `next`.
The first implementation paged on `occurred_at < $before` alone and
`TestTheListIsBoundedAndNewestFirst` failed it: two records sharing an instant —
ordinary here, because the service's clock is a timestamp and not a sequence — put
one of them on each side of the boundary and it was **never returned at all**. A
cursor that is a timestamp is a cursor that drops rows.

It is opaque rather than two query parameters because a client handed
`?occurred_at=…&id=…` will eventually send one without the other, and each half
alone is that bug. It is a keyset rather than an offset because an offset is wrong
the moment a row is appended between two requests — which here is the normal
case: somebody is performing admin actions while somebody else pages through the
record of them. And a cursor this build did not issue is a **422 naming `before`**,
not a silent first page, because on a trail "your token was wrong" and "the records
are missing" are very different conclusions.


## D6: the generated client commits a dependency that MD6 said it would not

**Raised** 2026-09-30 by packet `identity-10`, which added `client/` — the Go client,
generated from `openapi/v1.yaml` by oapi-codegen v2.8.0, committed, with a
hand-written wrapper over it.

**What MD6 says, and why it is the reason this entry exists.** MD6 ruled "generate for
TypeScript and Go, hand-write the unified client, and do not generate Python yet",
and gave the reason for Go in one sentence: oapi-codegen "reaches `identity`'s
existing stack with no new dependency at runtime: it is a `go:generate` tool, not a
library a user imports. A generated client that compiles to ordinary structs and an
ordinary HTTP call has no supply-chain surface a user has to trust, because there is
nothing to trust after generation."

**That sentence is half right, and the half that is wrong is the load-bearing half.**
Measured, not assumed:

- **The generator really is not a dependency.** The `//go:generate` line is pinned to
  `v2.8.0`, and `go run <module>@<version>` resolves in module-aware mode, so
  oapi-codegen never appears in `go.mod`. That half of MD6's sentence is exactly
  right, and it is the same relationship goose is in for `migrations/README.md`.
- **The generated code IS a dependency.** `client/generated/api.gen.go` imports
  `github.com/oapi-codegen/runtime` for parameter binding and for its `UUID` and
  `Email` types. `go.mod` gains three modules: `oapi-codegen/runtime`,
  `apapsch/go-jsonmerge/v2` and `google/uuid`. A consumer who imports this client
  gets all three.

**What it costs, stated precisely, because "no new dependency" is the claim and the
claim is now false in a way somebody has to be able to check.**

| | before this packet | after |
| --- | --- | --- |
| `go.mod` modules added | 0 | 3 |
| `go list -deps ./cmd/identity \| grep oapi-codegen` | empty | **empty** |

**The shipped binary is unaffected**, and that is the part that matters for a service
which is the platform's security boundary. The dependency is in the module graph, in
the client package, and in anything that imports the client — not in the artefact
`identity` builds. `TestTheServiceBinaryDoesNotReachTheGeneratedClient` in
`client/transport_test.go` holds that as an executable claim, because a comment about
a supply-chain property is not a supply-chain property.

**The call, and the cost of the other one.**

1. **The client ships here, generated, and the three modules are paid for. CHOSEN.**
   The dependency is real, bounded, Apache-2.0, and stays out of the binary. The
   alternative costs more than it saves: the drift gate, the credential-leak test and
   `go vet` all run on the client *because* it is in this module and therefore in
   `bin/prime`'s `./...`. Moving it to its own module would leave the coverage floor
   untouched and leave the client ungated — the failure this repository is built
   against. AGENTS.md's own position is that "a green build with the database tier
   silently skipped is a false claim", and an ungated client is the same shape.

2. **Hand-write the Go client, like Python. REJECTED.** It would remove the three
   modules and cost the platform the drift gate's other half. MD6 already answers
   this: at 45 operations a hand-written client is "about a day per language" and
   "genuinely better", and re-decides "when it doubles". identity alone is at 20.

**WHY GO GENERATES AND PYTHON DOES NOT**, restated here because the asymmetry is a
ruling and not an accident, and the next person to see it should not "fix" the
inconsistency:

- **Go has a mature 3.1 generator whose output is reviewable.** oapi-codegen v2.8.0
  emits typed structs and a `Client` interface, produces byte-identical output across
  runs, and is Apache-2.0. Its output is ordinary Go — structs, an interface, an
  `*http.Response` — so the artefact a consumer reviews is the artefact they compile.
- **Python's generators impose a runtime.** hey-api's Python generator is v0.0.24
  and emits parameterless methods with unsubstituted path templates, so it would emit
  a request for the literal string `/v1/accounts/{account_id}/oidc-clients`.
  openapi-generator's Python output is correct but 3.1 is beta there and it inverts
  `const` discriminants to `any`, defeating compile-time narrowing on exactly the
  problem-details shape this platform uses.
- **So the asymmetry is about the generator, not about the language.** Go's toolchain
  makes generation a build-time concern; Python's tools make it a runtime one. A
  hand-written Python client has the smaller attack surface of the two, and that is
  not a close call.

**THE PART THAT IS STILL OPEN, and it is a manager's call, not this packet's.**

Adding 10,334 lines of committed, generated, **0%-covered** code to a module measured
at 74.7% takes it to **45.9%**. `ci.yml`'s coverage floor is 70, so the `coverage`
step goes red on this commit.

This packet did **not** move that floor, and did not add a filter to the coverage
measurement, because both are the shape of thing this repository forbids: making a
red go away by changing the check rather than the thing being checked. The numbers
are given here so the decision is available rather than buried.

The three answers, in the order this packet would rank them:

1. **Exclude `client/generated` from the coverage measurement.** It is generated
   output, and the repository already takes that position for lint in
   `.golangci.yml`, for exactly the stated reason. This is the closest analogue and
   the most defensible. It is a change to a CI check and belongs to whoever owns the
   floor.
2. **Lower the floor to the measured 45.9%.** Cheap, and honest about what the number
   now measures, but it makes the floor much weaker for the hand-written code it was
   there to protect.
3. **Move the client to its own module** (`client/go.mod`). Restores the service's
   coverage exactly and keeps the binary clean, and costs the client its place in
   `bin/prime` — so it needs a second gate, which AGENTS.md calls "a second thing to
   be wrong".

Whichever is chosen, it is a decision about the repository's coverage policy rather
than about this client, and it is recorded here rather than made silently.

### ANSWERED 2026-09-30 by packet `identity-12-coverage`: option 1, and why not 2

MD16 in the workspace `DECISIONS.md` ruled it. This records what was actually done
here rather than a summary of the ruling.

**Option 1, taken.** `coverage-exclusions` at the repository root declares
`client/generated` — one entry, one directory, with a reason, an owner, a `since`, an
`until`, the `files=` and `lines=` it covers, and the floor it was justified against.
`bin/coverage-floor` reads it, filters the profile, prints the measured number, the
excluded set and the floor in one block, and compares.
`TestTheCoverageExclusionIsOnlyGeneratedCode` in `internal/platform/ci` walks the tree
and fails if anything under the excluded directory is not itself generated, or if the
recorded file and line counts no longer match.

**Option 2 refused, and the numbers here are why.** This tree measures **44.6%** with
the generated client in it and **73.6%** without it. A floor of 45 is a threshold
chosen to be met: the gap it absorbs is a real regression in hand-written code, and
the generated code's weight in the denominator never changes, so the gap would be
permanent and invisible. Keeping 70 means the floor is still the number that was
measured against the code somebody wrote.

**The floor was not moved, and no test was added to generated code.** A test written
against `client/generated/api.gen.go` would be deleted by the next `go generate` and
the coverage would not survive a week — the same argument the lint exclusion in
`.golangci.yml` makes, for the same file, in the same shape.

### What is still open, and it is a different question from the one above

**Option 3 is not answered, and it is the correct long-term shape.** A generated SDK
is a different artefact with different properties, and a separate Go module makes the
boundary a compile-time fact rather than a config entry. It is not done here because
it changes the import path of a published client, which is a decision with a
deprecation window attached.

The signal to settle it is the one MD16 names: **a second repository asking for a
generated client.** Before then, `coverage-exclusions`'s `until=2027-03-31` fails the
build, so the question is asked on a date rather than whenever somebody is under
pressure.

### WHY THE MECHANISM LIVES HERE AND NOT IN kit, which is a judgement and not a fact

The shared workflow should carry the *mechanism* and each repository its own
*declaration* — that is the right shape and it is what the brief asks for.

It is not here for one concrete reason: **identity's enforcing coverage step is its
own `coverage` step in the `gate` job, and kit's cannot enforce anything in this
repository at all.** kit's `test` step runs with no database, so
`internal/mfa`'s `TestTheDatabaseTierActuallyRan` fails first and the run never
reaches a coverage step. A mechanism in kit would therefore not be the mechanism this
repository uses: identity would still need its own copy, and a copy in a repository
that cannot read kit's at run time is a drifting copy with extra steps — the argument
`templates/tier/skip-allowlist` already makes about the fleet-wide file.

So the mechanism is here, the declaration is here, and `kit` is untouched, which also
means this packet does not collide with `kit-04`, live in that repository.

**What kit should grow, and when.** A `coverage-exclusions` input on the reusable
workflow plus the filter, so a second repository gets the mechanism without writing
it. The test that should move with it is the "every `.go` file under the excluded
directory is generated" walk — that is the load-bearing part and the part a consumer
is most likely to skip. **Do it as a kit packet, not by copying a file across**: a
copy is a second dialect of the same rule, which is the thing this packet was told not
to create.

**And the disagreement that leaves behind.** `coverage-fail-under: '70'` is still
passed to kit. kit's step computes `total:` over the whole profile and cannot be told
about this declaration, so it would read 44.6% if it ever ran. Left alone on purpose:
lowering the input to 45 is option 2, and 0 would be weakening a gate to make a build
green. The threshold is stated in both files, and
`TestTheCoverageFloorInTheDeclarationIsTheFloorsFloor` fails if they stop being the
same number.

## D7: the mail seam has two methods, and this repository wires the one that fails

**Raised** 2026-10-01 by the recovery packet, which added password reset, address
verification and address change — three flows that can only be finished by proving
you can read an inbox, and therefore three flows that need to send mail.

**The problem.** courier is the platform's mail service and its delivery path is not
finished. So identity has to send mail it cannot yet send, and there are three
shapes this could take.

1. **Talk to courier's HTTP API anyway, and let it 503 in development.** Rejected: it
   invents a contract against a service whose real one is in flight, so the adapter
   would be written against a guess and thrown away.
2. **Implement sending inside identity** — an SMTP client, a provider SDK, a queue.
   Rejected, and this is the one worth being explicit about: it would be
   *reimplementing courier inside the security boundary*. Two delivery paths means
   two sets of retry semantics, two places a message can be lost, and two answers to
   "is this deployment actually configured to send". The brief for this packet said
   not to build courier's adapter, and the architecture says the same thing
   independently.
3. **One substitutable seam, wired to a mailer that fails loudly. CHOSEN.**

**The seam, and why `Ready` is not padding.** `recovery.Mailer` is two methods:

```go
type Mailer interface {
    Send(ctx context.Context, m Message) error
    Ready(ctx context.Context) error
}
```

`Ready` exists because every request flow must know whether a message *can* be
delivered **before** it decides whether to mint a token — and it must know before it
looks the address up. Without that ordering, a deployment with no mail answers `503`
for a registered address and `202` for an unregistered one, and "503 against 202" is
an account-existence oracle. The cheapest version of that bug is the kind that only
shows up in the one deployment where nobody is testing. So the flow asks the seam
first, and both answers come from the same place.

`Ready` must not send anything and must be cheap: it is on an anonymous request path,
so an implementation that performed a real delivery there would mail an empty message
on every password-reset request anybody ever asked for.

**Why the message is a rendered value, not a template name.** `Send` takes a
`Message` whose `Subject` and `Body` are already strings. There is no `Template`
field, and there is deliberately no code path where a delivery adapter chooses what
the mail says. The moment `Message` grows a `Template`, identity has taken courier's
rendering decisions and the two will disagree. Four templates live in
`internal/recovery/message.go` as `strings.Replacer`s, so there is no inline body
literal anywhere in a handler — which is a brief requirement and also the only way
"the mail says X" is reviewable in one file.

**Why `main` wires `Unavailable{}` and not a logger.** `Unavailable` is a struct (not
a nil `Mailer`, so no caller has to decide whether nil is a supported configuration)
whose `Send` and `Ready` both return `ErrNoMailer`. Every route that needs to send
answers `503 service_unavailable` with a sentence naming the deployment problem.

The tempting alternative is a mailer that logs the message so an operator can see it
"worked". That is exactly the wrong shape for this particular message: **the body
contains a live single-use credential**. A reset token in a log aggregator — which is
searchable, retained, and usually readable by everyone who can read a deployment's
metrics — is a reset token anybody who can read the logs can redeem. So the mailer
fails loudly instead, and `TestNoRecoveryTokenReachesTheLogs` is the executable form
of that decision.

**Wiring courier is three lines** in `buildRecovery`, and that is the test of whether
this was the right shape: the seam has exactly one production implementation and it
is the one that refuses. Nothing in `internal/recovery` mentions courier, SMTP, or
any provider, so the future adapter lands in one function in `cmd/identity` and the
use cases do not change.

**THE COST, STATED PLAINLY.** As wired, **a user who forgets their password cannot
recover.** The flows are complete and tested; there is nowhere for the link to go.
That is recorded in README.md's "Not built yet" with the reason, because the honest
state for "we depend on a service that is not ready" is a paragraph and not a
stub that returns 202 and drops the mail.

## D8: one link template for four messages, and what the deployment inherits

**Raised** 2026-10-02 by packet `identity-26`, after `identity-24` drove the flows
end to end against a real courier and found the verification mail's button pointing
at the password-reset screen.

**The problem.** `RecoveryMailer` held ONE `LinkTemplate` for all four of its
messages, and the design was defended at length in `internal/courier/mailer.go`: a
template with `{token}` beats a base URL plus a platform-chosen convention, and
`ValidateLinkTemplate` refuses a template that cannot render a working link. The
argument is sound **for a recovery link**. It was then applied to a verification
link, which is not a recovery link, and the result was a mail that renders
perfectly, passes every assertion in the repository, and sends the reader to a
screen where the token is a `404`.

The single template had to go — one template for two purposes is a template that
must be wrong for one of them. **What had to be decided is what the variable that
already exists now means**, and that is a question about deployments rather than
about code.

**The four shapes.**

1. **Require `EMAIL_VERIFICATION_LINK_TEMPLATE`.** Correct in the strictest sense and
   rejected: it refuses to start every installation that exists, on the security
   boundary, to fix a defect introduced after they were configured. The brief for
   this packet names that outcome as the one to avoid.
2. **Derive the verification path from the reset one** — replace the last path
   segment, or append a convention. Rejected: it is the platform choosing a
   product's URL, which is the exact thing `LinkTemplate` exists to avoid, and it is
   wrong for every product whose confirm screen is not spelled the way identity
   guessed. It would also make the defect **invisible in a way the chosen answer
   does not**: a derived path looks configured, and an operator reading the config
   would have nothing to notice.
3. **Make the legacy variable mean "recovery" specifically**, so a verification link
   becomes mandatory. Same failure as 1, wearing a hat.
4. **RULED: `RECOVERY_LINK_TEMPLATE` is the default for every purpose that has no
   variable of its own.** A purpose names a template and gets it; a purpose that
   names nothing takes the default; a purpose with neither its own nor the default
   is a **startup failure naming the variable**.

**Why 4, and what it costs.** The cost is real and is the whole of the argument:
**an unmigrated deployment's address-confirmation link still points at whatever its
one template says.** The compatibility promise is about booting and about the reset
link continuing to work, and it does not pretend to fix the verification link for a
deployment that has not configured one — because fixing it automatically means
guessing where the screen is.

So identity says it out loud instead. `buildMailer` warns on startup when any
purpose resolves to the shared default, naming the purpose and the variable that
would give it a link of its own. That warning is the load-bearing part of the
decision, and it is there because **nothing else in the process can see the
problem**: the send succeeds, the token redeems at its own endpoint, every existing
test is green, and the reader is the only person who discovers they are on the wrong
screen. A compatibility promise that is silent about its own remaining cost is a
worse trade than one that names it.

**Why a purpose with NEITHER is a boot failure rather than a fallback.** The
fallback is the defect. A deployment that sets `PASSWORD_RESET_LINK_TEMPLATE` and
forgets it also dropped its default for verification has, by omission, reproduced
exactly the state this decision exists to end — and it would do so with every mail
rendering correctly. Failing at boot costs one line in a startup log naming the
variable; failing later costs a user.

**The checks, and what each one is for.** The interesting question was never the
configuration shape — it is that **nothing about a URL says which screen it opens**,
so no assertion about bytes can catch this. Identity cannot catch it either, except
where it has its own endpoints:

- `internal/courier/link_purpose_test.go` builds the mailer from an
  **`internal/config` environment** rather than from a Go literal — a relationship
  between two links can only be tested by something that can express it — sends a
  reset and a verification through the real flows over a real database, and asserts
  the two rendered links have **different paths** and that **each token redeems at
  its own endpoint and is refused at the other**. The token is read back out of the
  URL rather than out of the message, because the claim is about what the *recipient*
  holds.
- The same file holds a **negative control**: one template for both purposes really
  does render one link for both messages, so the inequality above is a comparison and
  not a tautology.
- The inequality was shown to fire by injecting the real defect — making the
  verification purpose read the reset variable — which reds at the path comparison
  with a message naming what a reader would have found.

**WHAT WAS DELIBERATELY NOT DONE.** courier was not touched. `verify_email` still
maps onto courier's `welcome`, which is the honest mapping and stays: what changed
is the **link**, not the message kind. There is still no `email_verification` type in
courier, and this decision does not argue for one.
## D9: registration publishes that an address is taken, and that is the last one

**Raised** 2026-10-02 by packet `identity-27`, which removed an
account-enumeration oracle from `POST /v1/email-verifications` and then audited every
route a stranger can reach.

**What identity-27 removed.** `POST /v1/email-verifications` answered **409** for an
address whose account had already proved its address, and 202 for everything else.
The route declares `security: []`, so no credential was required: a caller posting a
list of addresses could read the statuses back as a list of **verified accounts**. The
branch was defended on user-experience grounds — a client told "we emailed you" on
the strength of a refused request renders a confirmation screen the user cannot leave
— and never accounted for who was asking. It is gone, and the fact it published is
available safely on `GET /v1/email-verification`, which requires a session and answers
200 for every signed-in account.

**What the audit found afterwards, which is why this entry exists.** One route on this
service answers an anonymous caller with a status that distinguishes existence, and it
is not the one just fixed:

> **`POST /v1/users` answers `409 conflict` for an address that is already registered.**

One unauthenticated request per candidate address, no side effect, no cooldown, and it
covers **every** account rather than only the verified ones. So "does an account exist
for this address" is not a secret identity keeps, and any argument that another route's
disclosure is serious has to start by acknowledging this one.

**RULED: it stands, it is named, and closing it is a decision about products.**

Why it cannot simply be removed:

1. **One account per address is a database fact.** `users.email` carries a unique
   index. A registration cannot complete for a taken address, so a caller has to be
   told rather than left watching a request time out.
2. **There is no other route that can answer it.** Not the verification request — that
   is exactly the route identity-27 had to blind, because answering it honestly is the
   oracle. Not the login, which answers one 401 for everything. Registration is the
   only operation whose entire purpose is to create the row, so it is the only place
   the caller can learn whether the row is there.

The three shapes that would close it, and what each costs:

| shape | what it does | why it is not this packet's call |
| --- | --- | --- |
| answer `202` and mail a "somebody tried this" message | hides the bit; leaks it to the mailbox owner | requires a message identity does not have a template for, and tells a stranger's inbox about an account it does not have |
| register into a pending state and confirm by mail | the honest fix; the bit never exists | **changes what a registration means for every product in the fleet**, and adds a route, a table state and a login branch |
| a separate `GET /v1/email-availability` | same oracle, one endpoint instead of a side effect | it is the same disclosure wearing a new name, and it adds a surface to remove later |

The middle one is very likely right eventually, and it is a product decision with a
migration attached: every existing product has a flow that assumes a `201` means the
account exists and can be signed into. **identity does not get to make that call for
them**, so what this entry does is make the disclosure impossible to forget.

**What is held instead, so the disclosure stays exactly one bit.**
`TestRegistrationPublishesOnlyThatAnAddressIsTaken` registers two accounts — one whose
address is proved and one whose is not — and asserts the two `409`s are the same seven
fields and the same fixed sentence. `Problem` is compared as a whole document rather
than by grepping the bytes, because a grep cannot see a field added later and fires on
the envelope's own fixed text (`trace_id`, `instance: /v1/users`, and the word
"account" in the sentence that has to be there).

**And the second, smaller leak, which the same audit measured.**
`POST /v1/session` answers **423** for a locked account, and the lock is checked
*before* the password — so a stranger who posts five wrong passwords and then a sixth
reads 423 where an address with no row would have read 401. Six requests per
candidate, and the only side effect is a lockout the attacker caused themselves.

It was left in place, and the reasoning is that it is strictly dominated by the
registration `409`: same fact, one request instead of six, no state change. What the
423 adds is "…and it is locked right now", for an account the attacker had to lock.
`TestALockedAccountIsToldApartOnlyFromThePassword` holds the leak, measures it, and
asserts the honest answer survives — a user who mistyped five times is still told to
wait fifteen minutes rather than being told "wrong password".

**THE ANSWER THAT WOULD CHANGE BOTH** is the middle row above. If registration stops
answering "that address is taken", then the lockout's 423 becomes the only existence
oracle on this service rather than the second one, and it should move to the same
ruling: check the lock after the password, and pay one argon2id to keep the refusal
honest for the account's owner.

**WHERE THE OTHER ROUTES STAND.** The rest of the anonymous family answers no, each
with a test: `internal/httpapi/anonymous_enumeration_test.go` is the census, and its
table is required to be exactly the mounted family in both directions — a route added
under those prefixes is red until somebody has answered the question for it.
`POST /v1/introspections` answers **yes on purpose** and says so in a test, because
resolving a presented token is what an introspection endpoint is for; its protection is
the credential the caller must present.

## D10: identity renders no HTML, and the browser belongs to parlor

**THE OWNER'S RULE** is that `identity` must not have its own views — all frontend
is handled by `parlor`. `identity` violated it in exactly one place and it was easy
to find: `internal/httpapi/oidc.go` carried an inline `html/template` literal of
about thirty lines, the password step and the TOTP challenge step, rendered by
`writeHTML`. There were no `.html`, `.tmpl` or `.gohtml` files anywhere in the
repository, so that one literal was the whole of the frontend surface.

**AND THE OBVIOUS MOVE IS THE WRONG ONE**, which is why this is a decision rather
than a deletion. The page is not a settings screen. It is the OpenID Connect
authorization server's **user-agent interaction** — the form a person fills in
during an authorization-code flow — and OpenID Connect Core §3.1.2.1 makes
authenticating the end user part of the AS's job while §3.1.2.6 is about the
credentials themselves. **A provider that removes the page without replacing it is
an authorization server that cannot log a human in**, and it would still publish a
working discovery document saying that it can. So the page moves, and the work is
in what crosses the boundary.

**RULED: the decision stays here, the rendering does not.**

| Stays in `identity` | Goes to the login UI |
|---|---|
| is this browser signed in, and did *it* start this flow | which form to render, and how it looks |
| is this password correct, is the account locked | the product's name, as **untrusted text** |
| the MFA challenge, and its per-factor lockout | autocomplete, inputmode, focus, everything a keyboard and a screen reader need |
| the `__Host-session` cookie | nothing that is a credential |
| minting the authorization code | — |
| every refusal's `code`, and the sentence attached to it | how to *word* a refusal it has been given |

### Why the browser takes the extra hop, rather than `/oidc/authorize` redirecting straight to the login UI

The library asks the client implementation for a login URL, and
`protocolClient.LoginURL` could have returned the configured address directly —
one redirect fewer, and the obvious implementation. It returns
`PathLogin + "/" + requestID` instead, and that hop buys three things:

1. **Every question on it is a question about a credential.** Is this browser
   signed in, did *it* start this flow, is this password correct, may a code be
   minted. An authorization decision made by a page on another origin is not a
   decision this service made.
2. **No CORS, anywhere.** A login UI that has to ask identity a question about the
   browser's session would need `Access-Control-Allow-Origin` on identity, and the
   packet that forbids `Access-Control-Allow-Origin: *` still stands. The hop
   removes the question rather than answering it across a boundary.
3. **The login-CSRF refusal has one place to live.** D5's defence is a flow cookie
   set at `/oidc/authorize` and required before any completion. On a hop owned by
   this service that check is a top-level GET answered by a handler in the same
   repository as the cookie. On the login UI's origin it would be a decision made
   somewhere else, or not made at all.

The silent path — a user who already has a session going straight through with a
code, which is what makes signing in to a second product not require typing the
same password twice — is on that hop, and so is the `403` that refuses a signed-in
browser arriving with no flow cookie.

### Why `OIDC_LOGIN_UI_URL` is required and has no default

A default would have to be an address compiled into this binary, naming a service
that shares no module and no release train with it. A compiled-in default that is
wrong is wrong in every deployment at once, and a deployment that has to override
it has to know it exists. So there is no default, and a block with an issuer, a key
and no login UI **refuses to start** — a startup failure and not a degraded mode,
for the reason the OIDC and courier blocks already are one: a provider that mounts
and cannot complete a flow is worse than one that does not mount, because the
failure is discovered by a user at a product rather than by an operator at boot.

This breaks every deployment that boots today, and unlike [D8](#d8-one-link-template-for-four-messages-and-what-the-deployment-inherits)
there is no backwards-compatible spelling of it: the page this change removes is
the only one there was. That is accepted rather than papered over, because the
alternative — a default that silently points at a form nobody wrote, or a mount
that answers `503` — is strictly worse than a boot failure. The variable is named
in the refusal, in the startup log line, and in the README's configuration table.

### The two cookies became `SameSite=None`, and the argument

The form is now a top-level cross-site POST from the login UI's origin to this
one. A `SameSite=Lax` cookie is not sent on a cross-site POST, so the state cookie
would not arrive and **every sign-in would be refused at the CSRF check**. This is
not a subtle degradation; it is a login form that cannot be submitted.

What it costs is a transport relaxation and not a binding one. `SameSite` governs
*when* a cookie is sent; the property the state defends is that its value is
unguessable and unreadable by any other origin, and that is `__Host-` (no
`Domain`, so a subdomain takeover cannot write it) plus `HttpOnly` plus 32 bytes
of `crypto/rand`. A request from an attacker's page now carries the cookie and
cannot know what is in it, so `oauth.VerifyState` fails for every value the
attacker chose — the same outcome `Lax` produced, by a different route. The flow
cookie and the session cookie stay `Lax`, because neither is ever read on a
cross-site POST: the flow cookie is read on a top-level GET (the one case `Lax`
still permits) and the session cookie is only ever *set* on a top-level response.

`TestTheInteractionCookiesAreNoneAndTheFlowAndSessionCookiesAreNot` holds all
four, because a change to any one of them is invisible until a sign-in breaks.

### A refusal a login UI could render is a redirect, not a status

The `401` and the `423` used to be rendered into the page with an `Error` string.
Silently dropping them would land a user on a blank form with no idea why their
password failed, so they **travel**:

    <OIDC_LOGIN_UI_URL>?request_id=…&state=…&step=…&error=…&error_detail=…&retry_after=…

`error` is the contract and `error_detail` is a sentence for a person — the same
split the problem envelope makes between `code` and `detail`, which is why the
codes overlap the problem codes where they mean the same thing
(`account_locked` is the same word, on purpose). The 423's wait travels as
`retry_after` in whole seconds rather than in a `Retry-After` header, because **a
browser following a `302` does not read headers** and a lockout the UI cannot
render as a wait is a lockout the user experiences as a frozen page.

The dividing line is whether the refusal can be re-shown. Four cannot, and are
problem documents: a request id that does not exist (nothing to render, nothing
to post back), a body that will not parse, a signed-in browser with no flow cookie
(the D5 refusal, which must say "this sign-in was not started here"), and a server
error (whose reader is an operator with the log, and `trace_id` is what they need).

**The alternative that was rejected** is carrying only a `code` and letting the UI
write its own sentence. It is a worse fit for this fleet than it looks: every
refusal in this service is already one sentence for every way it can fail — see
D9 and the challenge-step refusal, which deliberately does not say whether a code
was mistyped, replayed or expired — and duplicating those sentences in a second
repository is the defect `identity-26` and `identity-27` exist to prevent. Carrying
both means the sentence has one home and the code has one home, and the UI can
override the wording without the override being load-bearing.

### What the login UI must do, which this repository cannot check

`client_name` and `login_hint` are **untrusted text**. `client_name` is whatever an
account owner typed into a registration and `login_hint` is whatever the client
sent; both are percent-encoded here, and the login UI must escape them again on
render. That was a real attack when the page was here — a registration called
`<script>…</script>` ran a script on the login page for *every product* — and it is
still a real attack, one repository over. Nothing in this repository can assert
that the far side escapes, so the requirement is written into `openid/openid.yaml`
and into `internal/oidc/loginui.go` where the escaping argument lives, and
`TestLoginRedirectEscapesWhatTravelsInIt` holds this side of it.

### The claim is checked, not asserted

"Identity serves no HTML" is the kind of claim that decays, so it is three tests in
`internal/platform/ci` — the package that guards the gate itself:

- no `.html`, `.htm`, `.tmpl`, `.gohtml` or `.tpl` file is committed;
- no Go file carries a markup string literal or imports `html/template`, with four
  named allowances, each with its reason, and a **stale allowance is a failure**;
- no response anywhere on the router answers with a `Content-Type` that names a
  document, or with a body on a redirect.

The third exists because of the mistake this packet was most likely to make, and
it is worth naming: **`http.Redirect` is correct Go and it writes HTML.** It writes
a one-line anchor body and `Content-Type: text/html; charset=utf-8`, because
RFC 9110 §15.4 recommends it for a user agent that cannot follow a redirect. So
`oidcRedirect` and `delegateOIDC` both write the status and the headers
themselves, and the first red proof here was `oidcRedirect` replaced with
`http.Redirect` — which the tests caught with a 210-byte anchor and a
`Content-Type` header, and which then caught a *second* leak: `delegateOIDC` was
copying the library's headers verbatim, so `/oidc/authorize` answered
`Content-Type: text/html; charset=utf-8` with an empty body until it dropped
`Content-Type` and `Content-Length` alongside the bytes.

### What was NOT changed, deliberately

- **No CORS headers.** Orthogonal to this packet; the prohibition stands.
- **`PathLogin` is still this service's**, and `protocolClient.LoginURL` is still
  the address the library redirects to. That is the hop.
- **The password check, the MFA branch, the challenge token, the per-factor
  lockout and the account lockout** all go through the same `internal/auth` calls
  `POST /v1/session` makes. One credential store, one password check, one counter.
- **The client-facing protocol is untouched.** `/oidc/authorize` still answers
  `302`, the flow still ends at a `302` to the client's `redirect_uri` with a
  `code`, and no discovery metadata changed. A browser flow is a browser flow and
  the number of fields in a form is not part of the protocol.

## D11: "my accounts" is a THIRD scope, and it is a policy rather than a join filter

`GET /v1/accounts` answered `[]` for a user who owned three accounts, and it
answered `[]` without an error, a 401, or a red assertion anywhere. The query
was correct, the membership rows were in the table, and the product rendered
"you are not a member of any account".

The cause is that the fleet has had two scopes since kit's substrate landed,
and this endpoint needs a third:

| scope | set by | answers |
|---|---|---|
| `cafaye.account_id` | `begin_account` | *which account* a request stands in |
| `cafaye.credential_digest` | `begin_credential` | *which credential* a caller presented |
| `cafaye.user_id` | `begin_user` | *who* the caller is |

`account_users` was protected by `protect_table`, so it carried exactly the
first scope's policy: `account_id = (select cafaye.current_account_id())`. A
caller who has signed in and has not yet chosen an account is not standing in
one — that is what makes them a caller rather than a tenant — so that predicate
was not true for every row they own, and the row filter took all of them.

Measured against this repository's migrations on PostgreSQL 17.11, three
accounts, two users, as the table owner with `FORCE` on:

| context | rows visible in `account_users` |
|---|---|
| none | 0 |
| `begin_user(one)` | 2 — the two accounts he is a member of |
| `begin_user(two)` | 1 — his own only |
| `begin_user(one)`, `where account_id = beta` | 1 — his own membership, not a browse |
| `begin_user(one)`, `where user_id = two` | 0 |
| no `begin_user`, `where account_id = beta` | 0 |
| `begin_user(ccc…)` for a user with no membership | 0 |
| `begin_user(one)`, then `INSERT` | `42501`, `new row violates row-level security policy` |
| `begin_account(beta)` + `begin_user(one)` | 3 — beta's two members plus his own |

That last row is permissive-policy semantics and is not an accident: two
select policies on one table are OR-ed, so a caller standing in an account sees
that account's members exactly as before, and additionally sees their own
memberships everywhere else. Nothing that used to be readable stopped being
readable.

**Why a THIRD POLICY rather than a query change.** The tempting fix is to scope
the join in Go — read the membership rows through the login role, or query with
an explicit `where user_id = $1` from a table nobody else can read. Both were
rejected, and the second is the interesting one: a predicate written into a
query is a predicate every future caller of that query must remember, and the
row that reaches `store.ListForUser` next will be somebody else's. The database
is the only place where "you may see your own memberships, and only your own" is
true of the table rather than of the one function that remembered.

**Why not `begin_account` per account, discovered by trial.** Because a caller
does not know which accounts he is in — that is the question — so it would be a
loop over an unbounded unknown that asks the boundary "does this account have
this user in it" once per account in the fleet.

**Why `begin_user` is NOT wired into `TxRunner`.** `internal/tenancy/user.go`
offers `BeginUser` and deliberately leaves it out of the runner, and
`accounts.Service.ListMine` opens its own transaction through the same `s.uow`
every write in that service uses. `TxRunner`'s argument is that *every*
account-scoped write passes through it, so "every write runs under an identity"
is a property of one type; that argument does not carry over to one read that
one endpoint makes, and paying a statement on every transaction of every request
to satisfy it is the cost `scope.go` already declines for the account seam.

**The cost, which is the thing to remember.** Forgetting `begin_account` makes
*every* account-scoped read empty, which is loud and gets debugged in minutes.
Forgetting `begin_user` makes *one screen* empty while everything else in the
product works, which reads as a missing grant and not as a missing scope. That
asymmetry is why the package doc in `user.go` and the substrate's own closing
paragraph both name it, and why the fix is one function with a doc comment rather
than a line inside a loop.

## D12: an unknown subject is a 404 behind a machine credential, and a 202 in front of a stranger

`POST /v1/session-links` names the subject it mints for: `{user_id,
expires_in?}`. The question this decision answers is what the route says when
that `user_id` is not a user.

The answer is **404 with a problem document**, and the fact that it disagrees
with every other route in this service that takes an identifier from a caller
is the whole of it.

**THE CONTRAST, STATED AS A TABLE, because it is easy to read one row and apply
it everywhere.**

| route | credential required | unknown identifier answers | why |
|---|---|---|---|
| `POST /v1/password-resets` | none | `202 {"status":"accepted"}` | there is no caller to protect — publishing "no such account" would be a free enumeration oracle for every address an attacker types |
| `POST /v1/email-verifications` | none | `202 {"status":"accepted"}` | same, and the 409 that used to stand here was [D9](#d9-registration-publishes-that-an-address-is-taken-and-that-is-the-last-one)'s cousin, found and removed by identity-27 |
| `POST /v1/email-changes` | session | `401` with no session | the caller has not proved anything, so the request never reaches the lookup |
| **`POST /v1/session-links`** | **api key with `sessions:write`** | **`404 not_found`** | **there is a caller, it is inside the trust boundary, and it is entitled to know** |

**WHY IT IS SAFE HERE AND NOT ON THE ROWS ABOVE.** The enumeration property
protects somebody who has proved nothing. A credential holding
`sessions:write` is not that: it is a grant somebody made deliberately, it is
recorded against an `api_keys` row, and it is revocable. Such a caller asking
"does this user id exist on this deployment" is asking a question it is already
entitled to ask — it could learn the same thing from `GET /v1/accounts/:id` and
from the introspection endpoint. Refusing the answer here would protect nothing
and cost the caller a `422`-shaped guess on every retry.

**WHY IT IS NOT 422.** A `422` says "this request is not acceptable". The
request was fine; the thing it named is not there. core's convention is that
`404` is for a resource the caller may not see or does not exist, and here the
two are the same answer to the same question, which is what `404` is for. The
detail names no fact beyond the absence.

**WHY IT IS NOT 202.** `202` is the self-service flows' whole enumeration
defence, and using it here would be a lie in the other direction: this route
either writes a row or it does not, and a caller that received `202` for a
subject that is not a user would believe a link existed for nobody.

**THE THING THAT WOULD OVERTURN THIS.** If a deployment ever exposed the mint
without the credential — a route variant, an internal-only port, a future
`POST /v1/session-links` for a self-service "sign in on another device" flow —
this decision inverts completely and the answer becomes `202` with a body that
says nothing at all. The property that makes 404 safe is the middleware, not the
handler: `requireSessionLinkMint` refuses everything that is not a scoped api
key, so the 404 is only ever reachable by a caller inside the boundary. Moving
the decision into a handler would have made it depend on which handler ran, and
that is the shape of thing this repository refuses.

**AND THE REFUSAL THAT IS *NOT* IN THIS TABLE, because it is a different
question.** A subject who exists and has a second factor is `409 conflict`,
which publishes that the account exists — which is safe for the same reason the
404 is, and which would not be on a route without a credential. And the subject
lookup runs BEFORE that check, so an unknown subject is a 404 rather than a
409: the two must not be told apart, or the 409 becomes a probe for which ids
are enrolled.

## D13: `disabled_at` is a person, not a policy — and it says so

**Raised** 2026-10-05 by packet `identity-disabled-01`, which added
`users.disabled_at` and the doors that read it.

**WHAT IT IS.** A nullable `timestamptz` on `users`. Null is active. There is no
`false`, no counter, and no expiry. No "who disabled" or "why" columns either: the
audit log is the house's answer to that, and a pair of columns here would be a
second, deletable copy of what `account_audit_log` holds append-only in the
database.

**WHAT IT IS NOT, AND THIS IS THE ENTRY'S FIRST CLAIM.** It is not
`locked_until`. A lockout is automatic, temporary, and expires by itself — five
consecutive wrong passwords buy fifteen minutes and the account is usable again
with no human involved. A disable is deliberate, indefinite, and set by a person
who could equally have deleted the row. Conflating them is not untidy, it is a
security bug with a specific shape: a "disable" implemented as a lockout with a
longer expiry lifts itself after a quarter of an hour, and the account nobody
thought about for fifteen minutes is quietly usable again.

### The refusal shape: `403 forbidden`, checked after the password

**RULED.** A disabled login is **`403 forbidden`**, with a fixed detail sentence,
**no `Retry-After`**, and no new problem code.

**Why not 423.** A 423 in this service means "locked, retry at", carries a
`Retry-After`, and is rendered by every client that knows the code as a countdown.
A disabled account is not coming back at any time, so that header would be a
promise nothing keeps and a countdown that ends in a second refusal. It is also the
conflation above, in the one place where a client would act on it: a caller told
"locked, retry in 15 minutes" who is actually disabled will keep trying.

**Why not 401.** The caller proved the password. `401` says their password is
wrong, which is false, and sends them into a reset loop that cannot help them —
while making the account's state invisible to the only person who can act on it.
This is the same reasoning D9 records for the lockout: "a user who mistyped five
times is still told to wait fifteen minutes rather than being told 'wrong
password'."

**Why `forbidden` and not a new code.** core's reserved list already names this
case, and a code invented for something core describes is a code somebody has to
reconcile later. `account_locked` earns its own because 423 is a status core has no
name for; this is not.

**And the enumeration reasoning, which is the load-bearing part.** The lockout's
423 leaks: it is checked *before* the password, so a stranger reads it after six
unauthenticated requests, and D9 keeps it as strictly dominated by registration's
409. **This check is after the password is verified.** A caller who receives "this
account is disabled" has already proved they hold the credential and therefore
already knew the account existed. So naming the state is not a trade against
enumeration — it is free, and it is *strictly better positioned than the 423 sitting
three lines above it on the same route*. Move the check above the password and it
becomes a one-request oracle for every disabled account on the service, which is
worse than the leak D9 accepted.

The order is therefore the ruling, not an implementation detail:
`TestADisabledLoginWithTheWrongPasswordIsRefusedExactlyAsAnyOther` holds the
stranger's answer, and the census row in
`internal/httpapi/anonymous_enumeration_test.go` says so on the route.

### The doors, and where the check lives

Password login, the social callback, the second step of a two-factor login, and
every recovery redemption. Two placement decisions are load-bearing:

- **The check is in `startLogin`, not in `Login`.** `internal/auth/social.go`
  resolves a provider identity to a local user and arrives at `startLogin` with no
  password anywhere in the request. A check written in `Login` would have left the
  social door open, and the way that defect stays invisible is that a social
  sign-in for a disabled account WORKS — every test green, nothing in the logs.
  One line that both doors pass through is what makes the second door's coverage a
  fact about the code rather than about whether somebody remembered.
- **`CompleteSecondFactor` carries it too.** A challenge was minted ten minutes
  earlier while the account was still enabled, and that door is reached by a token
  rather than by a user row, so the gate that covered the first half does not cover
  the second. Ten minutes is long enough for an administrator to act inside.

### Revocation is same-transaction, and it is DELETE

`auth.Service.Disable` deletes the user's session rows and stamps the column in
**one transaction**. A column write and a later sweep is a window whose length is
not a number anybody chose; the DELETE makes the window zero, and a request in
flight dies at its next store read.

The ordering is sessions-then-column: if the column write fails the transaction
rolls back and nothing is lost, and the reverse order would leave an account
reading as disabled to an operator while its sessions are still live.

It is **DELETE and not a flag** — the same rule 00003 states and `TestTheClaimWalk`
depends on — and that is also why `Authenticate` needs no check of its own. The row
is gone, so the lookup misses for a reason the caller cannot distinguish from a
token that never existed. A service that made this a soft flag on the session would
pass every door test above it and still be holding live sessions.

**Both failure directions are tested against real SQL**, with a trigger making each
half fail, because `fakeUnitOfWork` cannot roll anything back and a double-based
suite would pass against an implementation that set the column and swept the
sessions separately.

### Recovery cannot bypass it, and its two refusals have different shapes

Minting **refuses silently**: a disabled account is sent nothing, and the response
is byte-identical to an unregistered address's. Those routes are anonymous, so any
difference — a status, a slower response, a message that arrives — is a list of
disabled accounts for anyone posting a list of addresses. That is the oracle D9
records and identity-27 removed from this package's sibling route.

Redemption **refuses with the 404 a nonexistent token gets.** The token in the body
*is* the credential on those routes, so the caller is the owner or whoever took the
link, and an answer that named the account's state would publish it to exactly the
person the operator acted about. The owner's honest sentence is on the login, which
names it to somebody who has proved their password.

**A refusal does not spend the token.** An operator who disabled an account did not
also decide to invalidate the link already in its owner's inbox, and spending it
would make re-enabling leave the user with a dead link and no session —
indistinguishable from a service that lost their state. Every redemption refuses
while the account is disabled, so the live token costs nothing, and lifting the
disable restores the flow the user started.

The email change needed both halves closed separately, because the second token is
only minted when the first is confirmed and that mint is itself a credential.

### The session-link mint says 403 and its redemption will not

`POST /v1/session-links` refuses a disabled subject with **403**, not the `404` an
unknown subject gets, and that is D12's ruling pointed the other way: the caller
holds `sessions:write` and is an operator with authority over somebody else's
account, so there is no stranger to protect and a `404` would send them looking for
a user id that is not missing.

The redemption does not exist yet, so there is nothing to refuse today and no link
can become a session at all. When it is written it must use the **shape of an
unknown token**, for the reason the recovery redemptions do: the token is the
credential there. The two answers differ and neither is the other's — which is the
whole content of the rule.

### What is deliberately NOT here

**An operator.** No route, no scope, no audit record, and no way for a human to
disable an account. `Disable` and `Enable` are a use case and nothing is mounted on
them.

That is a gap with a reason rather than an omission. `internal/admin` is
**account**-scoped: its audit rows carry an `account_id`, its privilege boundary is
one sentence about account admins and invitations, and a **user is not an account**
— the same person belongs to several. Mounting this behind that boundary would
widen a boundary D2–D5 spent five entries drawing, in a packet whose subject is
something else, and the honest answer to "who may turn an account off" is a role
decision this packet should not make for the fleet.

**An enforcement without an operator is a foundation, not a feature**, and this
entry says so rather than letting the column imply a capability. The operator
surface — and the role question that goes with it, because "a platform admin" does
not exist on this service today and inventing one is a bigger decision than a
packet — is named in `HANDOFF-identity-disabled-01.md`.

### What is deliberately NOT here, second: a soft disable

No read-only mode, no grace period, no "disabled but the owner can still download
their data" tier. Disabled is disabled. A partial version is a different concept
with a different name, and `users` would need a second column to express it.

### What this packet did not decide

Whether OIDC access tokens issued before a disable stop working. A JWT is verified
by third parties against a published JWKS and this service cannot revoke one; that
is the same position `recovery`'s reset takes, which sweeps `oidc_access_tokens` and
says so. **An operator reading this entry should know the OIDC surface is not
closed by a disable**, because a disable that ends browser sessions and leaves
fifteen-minute access tokens in third parties' hands is half a revocation and the
other half is a product decision about how quickly an identity provider can be made
to disbelieve its own key.

---

## D14: the operator is a machine credential with `users:disable`, and no account at all

**Raised** 2026-10-06 by packet `identity-disabled-02`, which mounted the operator
surface D13 said was missing.

D13 named the gap honestly: `Disable` and `Enable` were a use case and nothing was
mounted on them, "because the honest answer to 'who may turn an account off' is a
role decision this packet should not make for the fleet." This entry is that
decision.

### What it is

`POST /v1/users/{userId}/disable` and `POST /v1/users/{userId}/enable`, reachable by
a **scoped api key holding `users:disable`** and by nothing else. `204`, no body. The
gate is `requireOperatorToken` in `internal/httpapi/operator.go`, and the scope is
declared by two rows in `accountRouteScopes` beside the session-link mint's — read
through the same `scopeRequiredBy`, so deleting a row **closes the route to tokens**
rather than ungating it.

### Why not the account-admin surface

**A user is not an account.** The same person belongs to as many accounts as they
like, so an account admin's authority is over *their account* and its members'
pending access, and the person in front of them is also somebody else's employee.
Granting account admin the power to disable would mean one tenant could reach a user
who also works for another tenant, which is precisely the reach D2–D5 spent five
entries refusing.

There is no honest way to scope it by account instead. The tenancy rules rest on
"every query is scoped by `account_id` from the token", and this action has no
account to scope by — its subject is the person rather than one of their
memberships. Inventing one is where the danger is: the obvious invention is "the
caller's own account", and a user belonging to ten tenants would then grant tenant
one that power ten times over, once per membership.

So the surface has **no account in the path, no role minimum, and no route under
`/v1/accounts/…` that consults `users:disable`**. An account-scoped credential is
refused on these routes whatever its role and whatever else it holds, and that
refusal is a check with a name —
`TestAnAccountScopedCredentialCannotDisableAUser` — because it is the boundary
D2–D5 drew and a future packet widening this to "admins may too" would be invisible
everywhere else.

**What the scope buys, stated as what it does not:** it does not restrict by tenancy
at all. A token holding `users:disable` may name **any** user on the deployment.
That is a fact about the scope rather than a shortcut around the tenancy rules — the
rows beside it restrict by account because an account is what they act *on*, and this
one acts on a person — and it is why the grant is per deployment, deliberate, and
revocable on its next request like any other.

### Why a machine credential and not a session

An operator is a deployment fact, not a login, and the subject of the action is a
person. A browser session here would be an account turning **itself** off or on, and
there is no version of that which is not either a self-harm button or a privilege
escalation. It is the same rule `requireAdminToken` and `requireSessionLinkMint`
already enforce and for the same reason: a session is a cookie, and a cookie is one
CSRF away from being somebody else's.

The second reason is audit-shaped and is why the credential kind is load-bearing
rather than tidiness: a machine credential has a **row id** an audit record can name,
and a session does not. That argument is D4's, and it is inherited rather than
re-decided.

### The refusals, and where the enumeration line sits

| presented | answer |
|---|---|
| a scoped api key holding `users:disable` | `204` |
| a browser session | `403` |
| an account-scoped credential, any role, any other scope | `403` |
| no credential at all | `403` |
| a token that resolves to no key | `401` |
| a user id this service never issued | `404` |

**403 for a session and for no credential, 401 for a token that resolves to nothing.**
The first two are statements about the *surface* — it is reachable by a scoped api key
and by nothing else, so "you are not a token" is true of a stranger exactly as it is
of a signed-in person, and a 401 would send a client hunting a login problem that does
not exist. The third caller HAS a credential; 403 says it may not use this route.
`Allows("")` is false for every granted set, so deleting the scope row closes the route
rather than opening it.

**The 404 is deliberate and is D12 pointed the same way.** These routes are behind
the operator credential, so there is no anonymous stranger to protect and an operator
told "no user with that id" can act on it. Everywhere else an unknown subject answers
`202` with a constant body, because those routes have **no credential** and "no such
account" there is a free enumeration oracle. This surface's anonymous answer is a
**403 that arrives before the path is parsed**, so a real user id, an invented one and
a malformed one are all the same answer — which is the row
`anonymous_enumeration_test.go` records, and the reason a stranger learns nothing
about which users exist.

**A user's disabled state is published in exactly one place**, and it is unchanged
from D13: the login, after the password verifies. Naming it here would publish it to
whoever asked, for no benefit — a client asking "is this account disabled?" is asking
about a person, and the operator surface's answer is about performing an action.

### Idempotence, and why there is no `409`

Disabling a disabled account is a `204`, and so is enabling an enabled one. An
operator re-applying a state from a script is not making a mistake, and a caller that
had to read the column first to find out would be doing an extra round trip to learn
something the row's absence already tells it. There is no `409` for "it was already in
that state" to be wrong about, and no `confirm` field, because the URL names the one
thing being changed — the difference from the bulk admin revocation, where the subject
is an array.

### What is deliberately NOT here

- **No audit record.** `account_audit_log` is account-scoped and its trigger refuses
  `UPDATE` and `DELETE`; a user-scoped audit table is a real decision with a real
  shape, and it is the next commit of this packet rather than a guess made while
  mounting a route. **A disable is currently unattributable.** That is named rather
  than hidden, and it is the reason the handoff leads with it.
- **No OIDC access-token sweep.** D13 named it as the other half of the revocation;
  `auth.Service.Disable` sweeps sessions today and the OIDC table is untouched. The
  password reset sweeps `oidc_access_tokens` in the same transaction as its own
  revocation, so the pattern exists to extend — and until it is extended, **a disable
  leaves fifteen-minute access tokens valid in third parties' hands.** Half a
  revocation is the reason this packet exists, so this gap is the one to close first.
- **No interactive OIDC refusal.** The four unre-showable refusals in
  `internal/httpapi/oidc.go` have no disabled branch. The interactive flow resolves
  through sessions, which the revocation ends, so the practical exposure is a
  challenge minted before the disable — the same window `CompleteSecondFactor` closes
  and this surface does not.
- **No notification, no bulk, no expiry, no soft disable, no read-only tier.** Disabled
  is disabled, and one user is one request.
- **No platform-admin role.** The role question was answered as a *scope on a machine
  credential*, which is a smaller invention; there is still no `platform_admin` role
  on this service and this entry does not create one.

## D15: revoking YOUR OWN current session is allowed, and the 404 is one document

**Raised** 2026-10-06 by packet `identity-sessions-01`, which added `GET /v1/sessions`
and `DELETE /v1/sessions/{sessionId}`.

The packet offered two answers for the current session and asked for one to be picked
and written down. Three decisions came out of it that a later packet will otherwise
re-open by accident.

### Revoking the session you are using is ALLOWED

`DELETE /v1/sessions/{id}` where `id` is the session the request arrived on is a
`204`, and the caller is signed out.

The alternative — a `409` with "that is your current session, use
`DELETE /v1/session`" — was rejected for a reason about the API's shape rather than
about security. `DELETE /v1/session` already revokes the caller's current session
with no complaint and no body. A second route that refuses to do the same thing when
the id is spelled out is a route whose refusal is a puzzle: the client has to know a
rule that exists to serve the client rather than to protect anything. Nothing is
gained by the refusal, because the caller already holds the credential they are
revoking — there is no privilege to escalate into.

**And the `204` sets no cookie.** That is the part with a real failure mode in it.
The handler is not told which session the request arrived on — `Authenticate`
resolves a token to a *user* and does not say which row it came from — so clearing
the cookie would be a guess, and the guess is wrong exactly when it hurts: the user
is on the device they are using, clicking "sign out" on a *different* one. Guessing
wrong in that direction signs them out of the device in front of them to end a
session somewhere else. `DELETE /v1/session` is the route that clears the cookie, and
a client that wants both calls both.

### The 404 is ONE document for all four ways of not owning a session

Never existed, somebody else's, already revoked, and the nil uuid. A `403` against a
`404` would let **any signed-in caller** probe whether a given session id belongs to a
live session anywhere in this deployment — a question about another person's
credential, answered to a stranger, over a table full of credentials.

The caller here is already authenticated, so nothing about *their own* account is at
stake in the answer. That is exactly why this is safe where D12's 202-in-front-of-a-
stranger is not: the difference is not the status, it is whether the caller has proved
they hold a credential at all. A malformed id is a `404` and not a `422` for the same
reason — the path is part of a resource's identity, so "not an id this service issued"
must be the same answer as "one it issued and it is not yours".

### These two routes are NOT account-scoped, and there is no scope for them

`/v1/sessions` is under `/v1`, not under `/v1/accounts/{accountId}`, and both routes
are **absent from `accountRouteScopes`**. A session belongs to a USER, and one person
is in as many accounts as they like — the same argument D14 makes for the operator
surface, and the reason there is no "my accounts" tenancy that "my sessions" could be
scoped by. A row in the scope table would be a scope gating nothing, which
`TestEveryScopeIsEnforcedOnItsRoutes` exists to catch; a scoped api key is refused
with `403` by `sessionCredentialOnly` instead, which is a middleware and therefore a
property of the surface rather than of the handlers.

### What is NOT decided here

- **`last_used_at` does not exist.** `00003` has `created_at` and `expires_at` and
  nothing maintained since. Writing a last-used timestamp is an UPDATE on the
  authentication path for every authenticated request, and the listing does not need
  it: `created_at`, `expires_at`, the user agent and the address are enough to
  recognise a session, and `current` tells a client which one it is on. A future
  packet that wants it should decide about the write before deciding about the column.
- **No "sign out of all my other sessions".** That is what a password reset, an MFA
  change and an operator disable already do through `revokeEveryCredential`, and a
  separate route for it would be a second implementation of one rule.

## D16: SIGNUP_SIGNING_KEY has three answers, one per manifest, and none is a production key

**Raised** 2026-10-07 by packet `identity-w63-bootkey`. The fleet narrowed to a
launch stack and identity could not boot from any manifest the repository ships:
`config.Load` refuses to start without `SIGNUP_SIGNING_KEY`, and no manifest
supplied it — not `docker-compose.yml`, not `config/deploy.yml`, not `.env`, not
the CI boot job. A launch blocker, not a missing feature.

The tension is real. The repo's own tests treat this as *the deployment's* key: a
literal in the binary "would sign nothing" and a deployment's key is the only one
that means anything. A committed, usable production key would be a forgery tool —
anyone could mint signup timestamps. But a stranger must be able to run the stack
from a fresh clone, and kit's `.env.example` says outright that it carries
"development credentials for a container bound to the host loopback".

### The ruling: dev default, production required, CI test value

1. **Local / compose — a dev default that is obviously a dev default.**
   `docker-compose.yml` supplies `SIGNUP_SIGNING_KEY: ${SIGNUP_SIGNING_KEY:-<dev
   value>}` so `docker compose up` works on a fresh clone with no `.env` editing.
   The value is the base64url of `identity-development-signup-key!` — 32 ASCII
   bytes, so it decodes to exactly 32 bytes and passes the length check. It is
   not random and not secret: it is the same on every dev machine, and anyone who
   reads the file can mint signup timestamps for a stack that carries it — which
   is what a development stack wants, and what a production stack must never do.
   A deployment that wants a different key sets `SIGNUP_SIGNING_KEY` in `.env`;
   the interpolation is the whole of the override.
2. **Production / Kamal — required, operator-supplied, never defaulted.**
   `config/deploy.yml` lists `SIGNUP_SIGNING_KEY` in `env.secret`, read from the
   operator's environment via `.kamal/secrets`. There is no default anywhere on
   this path: a deploy that does not supply it fails at boot, which is the
   behaviour that already exists and is preserved.
3. **CI — a test value.** The boot job generates an ephemeral key per run, masks
   it, and prints only its length. CI is not a deployment, and the compose file's
   development default is what a production key must never look like.

### What was rejected, and why

- **A committed production-plausible key.** Anyone could mint signup timestamps
  for every signup form this service serves. The repo's own `signup_wiring_call_test.go`
  says a literal in the binary "would sign nothing" — the same argument applies to
  a literal in a manifest, with the added defect that a manifest is the one place
  a deployment copies from.
- **A placeholder like `changeme`.** It fails the 32-byte length check and turns a
  working dev loop into a confusing startup error. The default must be a literal
  32-byte base64url string, generated once.
- **No default anywhere.** A fresh clone that meets a startup error naming a
  variable it has never heard of is a broken install path. The dev default is
  what makes `docker compose up` work; the label in the comment above it is what
  keeps it honest.
- **The obvious mint command.** `openssl rand -base64 32` emits the standard
  alphabet and one `=` of padding; `base64.RawURLEncoding.DecodeString` rejects
  both, so a correctly-random key pasted from that command fails boot with
  "it is not base64url". The documented command is
  `openssl rand -base64 32 | tr '+/' '-_' | tr -d '='`.

### The proof is an agreement test, not a literal

`cmd/identity/compose_boot_test.go` reads the identity service's environment out
of `docker-compose.yml`, resolves its `${...}` forms the way compose does, and
boots the real `main()` with exactly that. A hand-written env literal in the test
would pass on the day the manifest breaks — which is exactly the defect this
packet exists to close. The test was committed red (the manifest carried no key,
so the child died at `config.Load` naming the variable) and went green when the
manifest gained the dev default.

### What is NOT decided here

- **`MFA_ENCRYPTION_KEY`, `OAUTH_ENCRYPTION_KEY` and `OIDC_SIGNING_KEY` are the
  same shape and the same problem.** They each gate a *feature* that is allowed
  to be absent, so they keep their supported absent states. If the fleet ever
  makes any of them unconditional, it needs the same three-manifest ruling — and
  the same agreement test, reading the value out of the manifest rather than
  asserting a literal.
