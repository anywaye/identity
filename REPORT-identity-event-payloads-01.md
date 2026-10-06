# REPORT — the events a mailing consumer needs carry what the mail needs

**Packet:** identity-w25-payloads
**Branch:** `worker/identity-w25-payloads`
**Date:** 2026-10-07
**Gate:** `bin/prime` green — 24 packages, `go vet` clean, `gofmt` clean,
`go test -race` clean, coverage 75.0% (floor 70%).

---

## 1. The one-paragraph version

Three identity events describe facts a consumer would mail about, and none
carried the address — or the credential — the mail is sent to. The fleet's only
consumer is courier, and courier cannot look anything up: no identity client,
no identity credentials, no identity tables (REPORT-courier-consumer-invite-01.md
§2.6, where the two lookups and the token re-read were each refused, and the
refusals recorded as decisions). So the facts now travel in the payloads, at
the builders, so no call site can forget them. **What changed is what the
events carry, never when they are emitted.**

The previous attempt's partial work was reviewed and kept: the three builders
and the two recovery call sites were correct as left. What was missing was the
rest of the packet — `accounts.NewService` takes a new `UserEmailReader`
dependency and nine call sites did not compile, the outbox tests still used
the old builder signatures, the new fields had no tests, and core's payload
schema for `identity.session.revoked` pinned the two-field shape the third
event now breaks. All of it is finished here.

## 2. What each event now carries

### 2.1 `identity.member.invited` — `acceptance_token`

`internal/outbox/tenancy.go`, `NewMemberInvited`. The payload gains
`acceptance_token`: the one-time invitation token, which identity returns once
in the `201` and stores only as a SHA-256 digest. The builder refuses to build
a payload with an empty token, so an event announcing an invitation nobody can
redeem cannot be emitted at all.

**THE URL-BASE FINDING, which is the packet's §1 question.** The packet asked
for `acceptance_url` and said: find how `POST /v1/password-resets` gets its
link base and follow that config; if none exists, report it and add the token.
**There is no such base configuration, and the reason is structural.** The
recovery flow's links are configured PER PURPOSE, not from a base URL:
`internal/config`'s `linkTemplateVariables` names exactly two purposes —
`PASSWORD_RESET_LINK_TEMPLATE` and `EMAIL_VERIFICATION_LINK_TEMPLATE` — and
`recovery.Purpose` has four members (`password_reset`, `verify_email`,
`email_change`, `session_link`), none of which is an invitation acceptance.
`internal/courier`'s `linkPurposeFor` maps only the two purposes that have a
courier template. identity renders no HTML (DECISIONS.md D10), so there is no
accept-screen route in this service whose URL could be configured, and
inventing one would put identity's guess into every invitation mail on the
platform — the exact thing `LinkTemplate` exists to avoid.

So the fallback the packet specified is what shipped: **the token travels, and
composing the accept URL is the consumer's job.** The manager decision this
implements (REPORT-courier-consumer-invite-01.md §2.4) is that the
token-in-a-mail is the same credential class as the reset links identity
already mails; courier re-reading the token was refused three times and stays
refused; a redeem-by-id route is a bigger design than this packet and is not
built here. The report's own wording is the contract: *"ADD THIS. Or a
fully-formed redeem URL, which is better: the platform's accept route is not
courier's to know."* The token is the half of that sentence this service can
honestly produce; the URL is courier's to compose from the platform's accept
route, which is courier's knowledge and not identity's.

### 2.2 `identity.member.accepted` — `email`

`internal/outbox/tenancy.go`, `NewMemberAccepted`. The payload gains `email`:
the MEMBER's address — the registered user who redeemed the token — read
inside `Accept`'s transaction through a new `UserEmailReader` seam on
`accounts.Service` (satisfied by `*users.Store`, the same narrow-interface
shape `internal/recovery` declares as its own `UserStore`). It is the member's
address and not the address the invitation was sent to: the token is not bound
to an address, so the two are different facts and only one of them is the
person who joined. The builder refuses an empty address.

### 2.3 `identity.session.revoked` — `email`

`internal/outbox/recovery.go`, `NewSessionsRevoked`. The payload gains
`email`, required and refused when empty, because both notices this event can
trigger are mailed: "your password was changed" (reason `password reset`) and
"your email address was changed" (reason `email address changed`). Both call
sites updated: `RedeemPasswordReset` reads the user inside its transaction
before building the event; `ConfirmEmailChangeNew` reads the user AFTER
`SetEmail` in the same transaction, so for the email-change reason the address
is the NEW one — the address the user holds when the event is built. That
choice (new, not old) is recorded here rather than hidden at the call site:
the move and the event are one transaction, the row holds the new address when
the builder reads it, and a notice confirming a change belongs at the address
the account now uses. The old-address-as-warning alternative is a courier
packet's decision about which inbox to warn, not a fact this service can
offer — the event is one field, not two.

`NewUserEmailVerified` is unchanged and its comment now says why: no consumer
mails on it (the verification flow mails the link, not a confirmation after),
so it still carries neither address nor token. When one does, the field is
added at the builder.

## 3. What core's contract said

**The envelope does not pin payloads.** `core/schemas/event-envelope.schema.json`
treats `data` as opaque — "its shape is the per-event schema at
`schemas/events/<service>/<entity>/<action>.schema.json`, which core owns" —
and identity's `Envelope.Validate()` checks the envelope, not the payload. So
no addition could violate the envelope contract.

**`identity.session.revoked` HAS a payload schema, and it pinned the shape:**
`additionalProperties: false`, `required: [user_id, reason]`. Adding `email`
to the payload without extending it would have made every emitted event
invalid against the platform's own contract. Per the packet's §4, the schema
was extended in the same change, in core, on branch
`worker/identity-event-payloads-01`:

- `core/schemas/events/identity/session/revoked.schema.json` — `email` added
  to `required` and to `properties` (`format: email`, same shape as
  `user/created`'s), with the why in the description: the consumer is
  cross-service and cannot read the user row.
- `core/examples/valid/events/identity/session/revoked.data.json` — the valid
  example gains `email` (a new required field invalidates the old example;
  core's `test_payload_schema_examples_validate` is what enforces that).
- `core/examples/invalid/README.md` — the negative example's violation count
  goes three → four (the absent `email` is now also a `required` violation).

Core's own gate (`bin/prime`) is green on the branch: 299/299 passed, plus the
67-case red proof. The schema's provenance `$comment` was refreshed to this
packet's identity commit, and `fleet.yml`'s `sourceCommit` for identity moved
with it — the citation test
(`test_a_payload_schema_cites_the_commit_its_publisher_was_read_at`) requires
all nine identity payload schemas, the producer ledger and fleet.yml to agree
on one commit, and the only direction it allows is re-reading every schema at
the new commit. Eight were re-read and found unchanged; the ninth is the
extension above.

**`identity.member.invited` and `identity.member.accepted` have NO payload
schema in core** — measured, not assumed: `core/schemas/events/identity/`
holds `api_key`, `mfa`, `oidc_client`, `session` and `user`, and no `member/`.
That is the pre-existing gap DECISIONS.md D1 and the courier report's finding 3
both name (declaring the five undeclared tenancy events fails core's
`event.payload-schema-missing`). **This packet does not create those schemas**:
the packet's §4 permits extending a schema that pins a shape, and creating five
is a core release decision, not a one-line fix. The consequence is stated
rather than papered over: a consumer in another language still has nothing to
generate against for the two member events, and the gap is now one packet
closer to being the only thing standing between the fleet and a complete
catalog.

**Nothing in core's contract forbade the extension.** `docs/event-naming.md`'s
rows describe the facts, not the payload fields: the `session.revoked` row
says `data.reason` is the closed set of two, which remains true. The
`member.invited` row says `data.invitation_id` is the thing to act on, which
also remains true.

## 4. Tests

- `internal/outbox/tenancy_test.go` — `TestMemberInvitedEnvelope` and
  `TestMemberAcceptedEnvelope` updated to the new signatures and asserting the
  new fields travel; two new refusal tests (empty token, empty member address)
  pin the fail-closed halves.
- `internal/outbox/recovery_test.go` (new) — `TestSessionsRevokedEnvelope`
  asserts the payload and the envelope; `TestSessionsRevokedCarriesTheEmailChangeReason`
  pins the second reason and its address; refusal tests for the empty email and
  the unknown reason; `TestUserEmailVerifiedEnvelope` pins the deliberate
  one-field omission so a future field here is a decision, not an accident.
- Every existing call site of the three builders compiles and passes unchanged
  in behavior; the only edits are the new arguments the new signatures require.

## 5. What each unblocked consumer should do first

**The invitation mail (courier's `MemberInvited` handler).** It refuses today
with `:missing_acceptance_url`. The event now carries `acceptance_token`, so
the handler's first move is: compose the accept URL from the token and the
platform's accept route — the route the invitation's own redemption uses
(`POST /v1/invitations/accept` with the token, per `openapi/v1.yaml`) — and
refuse by name if the token is absent, the same way it refuses today. The
template still needs `account_name` and `invited_by`, which remain
unrecoverable without an identity client (§2.6 of the courier report): those
are still a refusal until either the event carries them or the manager rules
otherwise. The token-in-a-mail is the same credential class as the reset links
— treat it as one in courier's own handling.

**The password-changed notice.** `identity.session.revoked` with reason
`password reset` now carries the user's address. The first move is a new
consumer for that type (the §9 pattern from the courier report: `consumes:`
entry, registry row, handler), mailing "your password was changed" to
`data.email`. The address-moved notice (reason `email address changed`) is the
same handler with the second reason — and the open question for that packet is
whether the warning belongs at the NEW address (where this event's `email`
points) or the OLD one (where the account owner would still be reading). This
packet chose new because that is the fact the event carries; ruling otherwise
is a payload change, not a consumer change.

**The membership confirmation.** `identity.member.accepted` now carries the
member's address, so a "welcome to the account" mail is unblocked the same
way. Note it is the member's address, not the invitee's — the two differ
whenever an invitation is redeemed by somebody other than the address it was
sent to.

## 6. Housekeeping

- **Core:** branch `worker/identity-event-payloads-01` — the schema extension
  with its valid/invalid examples, then the sourceCommit move across all nine
  citations, the producer ledger and fleet.yml. Core's `bin/prime` green on the
  branch (299/299, red proof 67/0). Not merged — the merge is the fleet's sync
  decision.
- **No event emission timing changed.** No route, scope, or manifest row
  changed. No existing test was weakened or skipped.
- **The `identity.member.accepted` vs `identity.member.joined` naming
  divergence is untouched** — still the recorded manager decision in
  `internal/outbox/tenancy.go`, still open as core catalog business.
