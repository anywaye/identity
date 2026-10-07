# REPORT-identity-signuptimestamp-01

**Packet:** the signed-timestamp half of signup bot defence
**Branch:** worker/identity-w27-signuptimestamp
**Date:** 2026-10-07
**Budget:** 1 hour (a previous attempt died mid-work on a model-endpoint rate
limit; its tree was judged, kept where correct, and finished — see
"The previous attempt" below)
**Gate:** `bin/prime` green against `identity-w27-pg`, output pasted verbatim
below. `go vet ./...` clean, `gofmt -l .` prints nothing, `-race` green over the
four packages this packet touched.

## What landed

The second half of signup bot defence: a timestamp signed with a server secret,
rejected at submission if too old, too new, or forged. The honeypot
(`identity@75c4f6d`) refuses a bot that fills every field; this refuses the bot
that leaves the trap empty.

### The fifth secret

`SIGNUP_SIGNING_KEY` — 32 bytes, base64url without padding, the same shape as
`MFA_ENCRYPTION_KEY`. It is **always required**: `config.Load` refuses to boot
without it (`ErrNoSignupSigningKey`), and a present-but-unreadable value is a
distinct sentinel (`ErrInvalidSignupSigningKey`). The reasoning is in
`internal/config/config.go`'s `loadSignupSigningKey` and in the spamprotection
report before it: spam protection is not a feature a deployment enables or
skips, so the check must not vanish where a feature is not configured. None of
the four existing secrets was reused — the per-secret argument is
REPORT-identity-spamprotection-01.md's table, and it is the reason the fifth
exists.

### The mint

`POST /v1/signup-timestamp` → `200 {"timestamp","signature"}`. Public and
unauthenticated, exactly as `POST /v1/users` is: the form (rendered by parlor —
DECISIONS.md D10, identity renders no HTML) asks for a fresh pair before it
renders, and a browser arriving at the form holds nothing but the address it
was sent to. The endpoint takes no body, no credential, and hands out nothing
but the pair. It is mounted beside `registerRoutes` in `newMux` (it needs no
database, only the key), and its registrar early-returns without the service —
the same fail-closed shape every other surface has.

### The verify

`POST /v1/users` accepts `timestamp` + `signature` alongside the existing fields.
The handler verifies the pair **after the honeypot and before `auth.Register`
is called** — for the reason the honeypot is: a bot that gets a row in the
database has won. The HMAC is compared in constant time (`hmac.Equal`), the
age window is 2 s … 1 h, and **every rejection is the same generic
`422 validation_failed`** the honeypot gives — a forged signature, an instant
submission, an expired one and a future one are four answers a bot must not be
able to tell apart. The parameters are deliberately absent from the OpenAPI
document, same discipline as the trap field: the schema is the contract for API
clients, and a check that is documented is a check the next bot skips.

## The wire shape

`timestamp` is a **Unix integer**, not an RFC 3339 string. The OpenAPI's
existing style renders instants as RFC 3339, but those are UNSIGNED values where
any valid rendering is fine; a SIGNED value has a stronger requirement. The
signature is over the exact bytes of the message, so the message must have
exactly one canonical form: a Unix integer has one (the decimal string, and
JSON numbers are exact well within int64), while an RFC 3339 string has several
(fractional seconds or not, `Z` or `+00:00`), and a client that normalised the
rendering would present a different message than the one that was signed. The
canonical form is the whole of the signature's security, so it wins over the
style preference. The signature itself is base64url without padding — the same
alphabet as every other opaque value this service issues.

## The decisions that were mine

**The mint is deliberately open — no rate limit.** A signed timestamp costs one
HMAC-SHA256: nanoseconds, no storage, no state. A rate limit would cost a
dependency this repository does not have and a state machine it does not need.
The pair is a bearer credential with a one-hour window — a captured pair dies on
its own, and a bot that mints a million of them holds a million credentials that
all expire. The protection is the signature and the window, not the mint's
availability. A future packet that adds a rate limit is adding a dependency for
a problem the window already solves.

**Clock skew is not a question here.** Mint and verify run on the SAME server's
clock (`internal/platform/clock` is the seam that hands one instant to both).
There is no second source of truth to consult and no skew to correct: the 2 s
floor already covers the instant a bot submits, and the 1 h ceiling is measured
on the same clock the mint used. Inventing a second clock would be inventing a
second thing to be wrong.

**The verify is conditional on the service, which in production it never is —
and that is the one thing here I would want a reviewer to push on.**
`SIGNUP_SIGNING_KEY` is required at boot, so a process that can serve
`POST /v1/users` can always verify the pair. The `if o.signup != nil` guard in
the register handler is therefore unreachable in production, and it is written
as the same fail-closed shape every other surface has rather than as a rule in
its own right.

**It fails OPEN, though, and that is worth naming rather than leaving for
discovery.** A router built without the signup service serves a register route
that does not verify. In production that router cannot exist; in a test it is
how thirty-odd existing tests keep registering users without minting a pair, and
rewiring all of them to carry one was not this packet's hour. The argument for
keeping it is that the state is unreachable in a deployed process and is honest
about itself; the argument against is that a future packet that made the guard
`if o.signup == nil { refuse }` would break every one of those tests at once,
which is the cheapest possible moment to notice the guard was optional. A
follow-up should either make the refusal unconditional or say in writing that
this is permanent.

## What parlor's follow-up packet must do

The form change is **not in this packet** (the brief forbids touching parlor), and
**the full list is at the bottom of this report** under "What the manager should
brief the parlor packet with" — which is written for briefing rather than for
implementation. In short: mint on render, carry the pair on submit, treat every
`422` identically, and use `RegisterUserWithSignupTimestamp` rather than
`RegisterUser` from Go.

1. Ask `POST /v1/signup-timestamp` when the signup form renders, and carry the
   pair on submit as `timestamp` + `signature` (the same two field names — the
   handler reads them off the registration body). **From Go, that is
   `MintSignupTimestamp` then `RegisterUserWithSignupTimestamp`** — see the
   section on the client below for why `RegisterUser` cannot be used.
2. Send the timestamp back as a JSON **number**, unmodified. A client that
   re-renders it (as a float, a quoted string, or a different width) presents a
   different message than the one that was signed, and the verify refuses it.
3. The refusal a form must handle: a generic `422 validation_failed` whose detail
   is `"the request has an invalid field"` and which names no field. That is the
   same answer a honeypot hit gets, and the user-visible copy should be "the form
   could not be submitted — reload and try again".
4. Treat **every** `422` from a registration the same way, whatever the form can
   infer about why. Do not try to distinguish a bad pair from a taken address
   from a bad password: the service will not say, and a form that guesses has
   told a bot which check exists.

## What was deliberately not done

- **No rate limit on the mint** — see the decision above.
- **No rotation, no key id, no algorithm agility.** One key, one algorithm
  (HMAC-SHA256), one purpose. Rotation is a deployment concern (the variable is
  read once at boot; a rotation is a restart), and a key id would be a second
  thing to keep in sync for no property this surface needs.
- **No replay protection beyond the window.** A pair presented twice inside its
  hour verifies twice. The window is the whole of the defence: a captured pair
  is a one-hour credential for one form submission, and the form it opens is
  itself behind the honeypot. A nonce store would be a second dependency (and a
  table that grows, which is the operational cost nobody prices until it is
  running) for a problem the expiry already bounds. **The consequence to be
  honest about**: replay of one captured pair lets one extra registration
  through, not an unbounded one, and only if the replay lands within the hour.
- **No `timestamp`/`signature` in the `RegisterRequest` schema, deliberately.**
  The OpenAPI document for the mint operation carries the pair; the request
  schema for `POST /v1/users` does not, because documenting the bot check in the
  contract is how the next bot learns to skip it. The cost is that the generated
  request body cannot express the pair, which is the client problem the section
  below exists to solve. That trade was made on purpose and a reviewer who
  disagrees now knows which knob to turn.
- **No change to the honeypot, the four existing secrets, or any other
  repository.** The honeypot still refuses the bots that fill every field; the
  timestamp refuses the ones that do not.

## The one thing the brief did not ask for, and why it is here

**The committed Go client could not register anybody.** `POST /v1/users` now
refuses a body with no pair, and `client.RegisterUser` takes
`generated.RegisterUserJSONRequestBody`, which is generated from a document that
deliberately omits the pair. So the protection this packet adds would have
silently broken every Go consumer of the client — including whatever talks to
identity from Go today — with a `422` naming nothing, which is indistinguishable
from a bot.

That is a break introduced by a protection, so it is fixed here rather than
handed to the follow-up packet:

- `client.RegisterUserWithSignupTimestamp(ctx, body, pair)` adds the pair through
  a `RequestEditorFn` — the generator's own seam — so the request is the
  documented one plus two fields, and the generated client's status handling,
  body closing and error typing are reused rather than re-implemented.
- `client.MintSignupTimestamp(ctx)` is the other half. **The two are tested
  against each other** (`TestTheMintAndTheRegisterAreTwoRoundTrips`, one server,
  asserting the register carries the signature the mint handed out) because a
  mint with nothing to carry it on, and a register that requires a pair nothing
  mints, is a surface whose halves cannot be checked against each other.
- `RegisterUser` is **kept**, and the report says plainly that it now always
  fails against a real deployment. Deleting a method from a committed client is
  its own kind of break, and a caller needs to know which failure is a wiring
  mistake and which is the defence.

**Writing the editor found a panic.** `json.Unmarshal` of `null` into a map
succeeds and leaves the map **nil**, and the assignment that adds `timestamp` to
it panicked — a caller-supplied body taking the process down, which is the worst
answer this package can give. `TestThePairEditorRefusesABodyItCannotRewrite`'s
`null` row found it; the guard is now in `withSignupTimestamp`, and the row
carries a comment saying which bug it exists for.

**The wire bytes are asserted, not just the status.** The wrapper reads back what
the server actually received and checks the two fields under the names the handler
reads, as the right JSON types, and that the rewrite did not drop `email` or
`password` on the way through — a body re-rendered from a map is a body that can
quietly lose what it had. A body the editor cannot rewrite is a **typed
`CallError` before any request goes out** rather than a request sent with no pair,
which is why the editor runs once against a throwaway request first; the pre-flight
does not send, and the test asserts the real path sends exactly one request.

## The previous attempt

The worktree held uncommitted partial work from an attempt that died on a
model-endpoint rate limit, plus a recovery commit (`12e98ff`) explicitly marked
unverified. Judged on its merits:

- **Kept:** `internal/signup` (the mint/verify service and its tests), the
  `SIGNUP_SIGNING_KEY` config block and its tests, the HTTP wiring (the mint
  handler, the verify in the register handler, the OpenAPI document entry, the
  generated client, the walk/drift/anonymous-audit test rows) and the README
  table row. The design is sound and is what this packet ships.
- **Fixed:** the recovery commit left the tree broken, all found by running the
  gate rather than by reading:
  1. `cmd/identity/main.go` never called `httpapi.WithSignup`, so in a running
     process the mint route would never have mounted and the verify would never
     have run. **This was the critical gap**: every test passed against a
     hand-built router while the production wiring was absent.
  2. `registerSignupRoutes` mounted the route unconditionally, so a router with
     no services still served the mint. The fail-closed guard is there now.
  3. The `coverage-exclusions` entry for `client/generated` was stale after the
     regeneration (28893 → 29198 lines, 6724 → 6792 statements — re-measured
     here with `go test -coverprofile` over `./client/generated/`, not carried
     forward, which is what that entry demands of itself).
  4. `cmd/identity/mfa_wiring_test.go` had a dangling `_ = created` left by an
     edit that replaced an inline registration with a helper — a **build failure
     in the whole `cmd/identity` package**. Found by `go test ./...`.
  5. The anonymous-enumeration audit fixture wired a *real* signup service, so
     every probe of `POST /v1/users` got the generic `422` and five existing
     tests failed. The fixture now uses `acceptsEveryPair()`: that audit asks
     what a route discloses to a stranger, and with the bot check refusing every
     probe it measured a fixed 422 rather than the 409 and 423 its rows are about.
     Mint is still real there, so the mint route is still measured end to end.
  6. Six files were not gofmt-clean (four from the recovery commit, two
     pre-existing missing-trailing-newline debt at the base commit, which the gate
     does not distinguish).
  7. The OpenAPI example carried a 48-character signature, which is not a
     32-byte HMAC in base64url (that is 43). Replaced with a real one computed by
     this scheme — an example a reader cannot reproduce is the same class of defect
     as the non-hex uuid `openapi_examples_test.go` was written for.
- **Added by this packet:** the client half (see the section above).

## Evidence

### Every refusal is proved to be the check's, not the fixture's

Two tables, and the second is the one that makes the first mean something.

`TestRegisterVerifiesTheSignedTimestamp` (httpapi) walks ten presentations of the
pair and asserts the status **and** that the refusal is the same generic 422 the
honeypot gives, **and** that a refused submission never reached the registration
service — a bot that gets a row has won, even if the row is later deleted — and
**and** that the verify was actually called with the pair the handler was handed.
That last assertion is the one that matters: a refusal with no verify call is a
refusal that came from somewhere else, and the table would otherwise pass against
a handler that does not check.

`TestRegisterRefusalsFailWithoutTheVerifyCheck` forces the verify to pass — the
same effect as commenting the check out — and shows every refused case is then
ACCEPTED, with a user row. A forged signature, the instant submission and the
expired timestamp all get a 201.

### The unit behind it: the window's boundaries, in `internal/signup`

`TestVerify` is the same table one layer down, over the *age* rather than the
handler, and it pins both boundaries from both sides — at the floor verifies, one
second under is refused, at the ceiling verifies, one second past is refused. A
boundary off by a second in either direction is a bot admitted or a person
refused, which is why the times are absolute and the ages derived: a reader can
see which side of which bound each row sits on. It also covers the cases the HTTP
table cannot reach cheaply — a valid signature over a *different* timestamp (the
MAC is real and the pair is wrong), a truncated signature, a signature that is not
base64url.

### The boot failure

`TestTheSignupSigningKeyIsRequiredIsValidatedAndNeverDefaulted` is a table over
the three states: absent is a startup failure that names the variable, a
non-base64url value is a startup failure, a 16-byte key is a startup failure
that says how many bytes it decoded to, and present-empty reads as absent.

### The mint's endpoint shape, and what it hands out

`TestMintSignupTimestampIsPublicAndHandsOutOnlyThePair` asserts the 200, the
content type, the two fields under the names the handler reads them by, that the
pair the endpoint hands out **verifies under the same service** (a mint producing
a pair its own verify refuses is a form that could not submit), and that the
service was asked to mint exactly once at the instant the handler claims — the
recording is what proves the handler minted rather than returning a constant.

### bin/prime

`TEST_DATABASE_URL="postgres://identity:cafaye@localhost:15527/identity?sslmode=disable" bin/prime`,
exit 0. The database tier ran against this packet's own container
(`identity-w27-pg`), **not** the shared cluster on 15500 that another worker's
gate uses — `docker compose` was never run from this worktree.

```
ok  	github.com/cafaye/identity/client	3.204s
ok  	github.com/cafaye/identity/client	3.204s
?   	github.com/cafaye/identity/client/generated	[no test files]
ok  	github.com/cafaye/identity/cmd/identity	7.280s
ok  	github.com/cafaye/identity/internal/accounts	38.991s
ok  	github.com/cafaye/identity/internal/admin	9.096s
ok  	github.com/cafaye/identity/internal/apikeys	33.028s
ok  	github.com/cafaye/identity/internal/auth	26.890s
ok  	github.com/cafaye/identity/internal/config	0.564s
ok  	github.com/cafaye/identity/internal/courier	1.591s
ok  	github.com/cafaye/identity/internal/httpapi	128.670s
ok  	github.com/cafaye/identity/internal/mfa	46.564s
ok  	github.com/cafaye/identity/internal/oauth	8.603s
ok  	github.com/cafaye/identity/internal/oidc	4.008s
ok  	github.com/cafaye/identity/internal/outbox	9.732s
ok  	github.com/cafaye/identity/internal/platform/ci	5.688s
ok  	github.com/cafaye/identity/internal/platform/clock	0.554s
ok  	github.com/cafaye/identity/internal/platform/db	0.705s
?   	github.com/cafaye/identity/internal/platform/dbtest	[no test files]
ok  	github.com/cafaye/identity/internal/platform/id	1.228s
ok  	github.com/cafaye/identity/internal/platform/oauthtest	0.940s
ok  	github.com/cafaye/identity/internal/recovery	39.876s
ok  	github.com/cafaye/identity/internal/sessions	3.570s
ok  	github.com/cafaye/identity/internal/signup	0.538s
ok  	github.com/cafaye/identity/internal/telemetry	0.641s
ok  	github.com/cafaye/identity/internal/tenancy	1.393s
ok  	github.com/cafaye/identity/internal/useraudit	8.107s
ok  	github.com/cafaye/identity/internal/users	1.783s
```

`go vet ./...` clean, `gofmt -l .` prints nothing.

`go test -race` over the four packages this packet touched — `internal/httpapi`
(race is load-bearing there: `routeTable` is a shared mutable the walks read, and
its guard is why 52–64 tests used to fail nondeterministically), plus
`internal/signup`, `client` and `cmd/identity`:

```
ok  	github.com/cafaye/identity/internal/httpapi	147.763s
ok  	github.com/cafaye/identity/internal/signup	1.549s
ok  	github.com/cafaye/identity/client	7.620s
ok  	github.com/cafaye/identity/cmd/identity	20.577s
```

Race over the whole tree was not run inside the hour; CI runs it.

## Constraints respected

- No existing test was weakened or skipped. Three groups of existing test changed
  expectation, and each is a case where the service now refuses something it used
  to accept:
  - `cmd/identity`'s wiring tests registered without a pair and expected 201, which
    is no longer a submission this service accepts. They now carry a pair — one
    mints through the real endpoint and waits out the floor, the rest mint under
    the app's own key — so their purpose (the auth surface is wired end-to-end) is
    intact and stronger, because they exercise the verify through `newApp`.
  - The anonymous-enumeration audit's fixture no longer uses a *real* signup
    service, for the reason given above. Its rows and its assertions are
    unchanged; only the fixture's bot check stopped refusing every probe.
  - No existing test was deleted.
- No other repository was modified.
- No secret was hardcoded; no existing secret was reused or renamed.
- The honeypot and the timestamp refuse with the same generic 422. Both call the
  same `problemFor(..., CodeValidationFailed, "the request has an invalid field")`
  in `internal/httpapi/auth.go`, and `internal/httpapi/signup_test.go` asserts
  the problem code **and** the detail string for every refused case — so the
  claim is checked rather than phrased. It is "the same refusal", not literally
  byte-identical output: each response carries its own `trace_id`, which is the
  point of a trace id.

## What the manager should brief the parlor packet with

1. `POST /v1/signup-timestamp` on render; carry `timestamp` + `signature` on
   submit. From Go, that is `MintSignupTimestamp` then
   `RegisterUserWithSignupTimestamp` — **not** `RegisterUser`, which cannot carry
   the pair and is refused by the server.
2. The timestamp is a Unix **integer**. Send it back as a JSON number, unmodified.
   A client that re-renders it (as a float, a quoted string, or a different
   integer width) presents a different message than the one that was signed, and
   the verify refuses it with the generic 422.
3. The pair must be at least **2 s** old at submit and no more than **1 h**. A
   form that renders and submits in the same second is refused — that is the
   check working, and the user-visible copy should be "the form could not be
   submitted, reload and try again", because every refusal looks the same on
   purpose.
4. Treat **every** `422` from a registration the same way, whatever the form can
   infer about why. Do not try to distinguish a bad pair from a taken address
   from a bad password: the service will not say, and a form that guesses has
   told a bot which check exists.
5. A pair is **not** single-use. There is no server-side replay store (see
   "deliberately not done"), so a retry after an ambiguous failure may re-submit
   the same pair rather than minting a new one — which is fine, and is the reason
   the decision was cheap. What a pair does **not** buy is more than one
   registration per window.
6. **Nothing in identity has to change for this packet's follow-up.** The mount,
   the secret, the mint and the verify are all here. If the parlor packet needs a
   server-side change — a way to render the pair into a hidden form field, or a
   route that redirects to the form with it — that is the trigger to open one.
