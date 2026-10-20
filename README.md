# identity

**Current direction (2026-10-19):** Ship is the product. The cafaye stack is internal infrastructure; we are not selling or supporting it as a standalone product as of this date. We continue to develop and improve it, treating the founder as the primary customer and keeping "build once, run everywhere" true, with the expectation that it may be offered again later.

`identity` is the cafaye service that knows who someone is: auth, sessions,
MFA, accounts and tenancy, social login, and OIDC. Every other cafaye service —
billing, courier, gateway, parlor — asks this one who is calling and what they may
do. It is the platform's security boundary, and the reason `PLAN.md` §3 singles it
out for a user-run security review before the phase closes.

**Social login and OIDC are two different directions and the list above holds
both.** This service is an OpenID Connect **provider** — it issues tokens to
products that register with it — and it is also a **client** of Google and GitHub,
which is what the two `/v1/auth/oauth/*` routes are. Conflating the two is how
"OAuth" came to sit in this paragraph and in `cafaye.yml`'s `description` while
nothing served it: a bare "OAuth" beside "OIDC" reads as one capability wearing
two names. See [Social login](#social-login-what-it-was-and-what-it-is) for the
record.

Roughly 253 Go files and 125k lines under `internal/`, across twenty
implemented packages (`accounts`, `sessions`, `users`, `auth`, `mfa`,
`recovery`, `oidc`, `oauth`, `tenancy`, `admin`, `apikeys`, `outbox`,
`platform`, …), with 156 test files. Eighteen migrations define the schema;
`openapi/v1.yaml` is the contract.

What it serves:

```
POST   /v1/users                                  registration
POST   /v1/session                                sign-in
DELETE /v1/session                                sign-out
GET    /v1/sessions                               where am I signed in
DELETE /v1/sessions/{sessionID}                   sign out of one of them
POST   /v1/session/tokens                         exchange a session for one account-scoped token
GET    /v1/me                                     who am I
PATCH  /v1/me                                     set display name and theme
POST   /v1/mfa/enrollments                        MFA enrolment + confirm
POST   /v1/mfa/recovery-codes                     recovery codes
POST   /v1/password-resets                        password reset + confirm
POST   /v1/email-verifications                    email verification
POST   /v1/email-changes                          change address
POST   /v1/auth/oauth/{provider}                  Google / GitHub sign-in
GET    /v1/auth/oauth/{provider}/callback         provider callback

POST   /v1/accounts                               create an account (tenant)
GET    /v1/accounts                               list them
GET    /v1/accounts/{accountID}                   read it
PATCH  /v1/accounts/{accountID}                   update it
DELETE /v1/accounts/{accountID}                   delete it
GET    /v1/accounts/{accountID}/members           list members
POST   /v1/accounts/{accountID}/members           add a member
PATCH  /v1/accounts/{accountID}/members/{userID}  change a role
DELETE /v1/accounts/{accountID}/members/{userID}  remove a member
POST   /v1/accounts/{accountID}/ownership-transfers   hand it to another member
POST   /v1/accounts/{accountID}/invitations       invite
POST   /v1/invitations/accept                     accept one
POST   /v1/accounts/{accountID}/agents/claim      claim an agent principal (+ its token)
GET    /v1/accounts/{accountID}/admin/invitations/{invitationID}
DELETE /v1/accounts/{accountID}/admin/invitations/{invitationID}
POST   /v1/accounts/{accountID}/api-keys          scoped machine credentials
GET    /v1/accounts/{accountID}/admin/audit-log   who did what

POST   /v1/agents                                register an agent (public, unclaimed)
GET    /v1/agents/claim/{token}                  the claim screen's preview (anonymous)
GET    /v1/agents/home                           who this agent credential is
POST   /v1/agents/claim-link/refresh             reissue its claim link (does not claim)
POST   /v1/agents/tokens                         mint a bearer token
GET    /v1/agents/tokens                         list them
DELETE /v1/agents/tokens/{tokenID}               revoke one
POST   /v1/agents/tokens/{tokenID}/rotate        rotate one in place

GET    /.well-known/openid-configuration          it is an OIDC *provider*
POST   /v1/introspections                         token introspection
```

It is both directions of "OAuth", which is the distinction the paragraph above
is about: an **OIDC provider** that issues tokens to registered clients, and an
**OAuth client** of Google and GitHub via the two `/v1/auth/oauth/*` routes.

Security properties worth naming, because they are the reason to prefer this
over a hosted auth service: passwords are argon2id; session, invitation and
recovery **tokens are stored as SHA-256 digests**, never as presented values, so
a database dump yields nothing usable; accounts carry an ordered role enum
(`owner` > `admin` > `member`) so authorization is a comparison rather than a
set of independent booleans; and every privileged action is written to an
account audit log.

**What it is not.** Resource-level sharing is not in scope here. There is no
audit, assignment or document concept in `migrations/` — identity answers *who
is this and what may they do about the account*. Anything scoped to a specific
audit belongs to the service that owns audits, keyed by an account id from
here. That boundary is deliberate; see `tenancy.yml` and `account_scope.yml`.

### What still gates it

`gate.yml` measures this, and is worth reading before trusting a local green.
Two commands exist and they are not the same: `bin/prime` for developers
(measured green, 335s wall, exit 0) and a stricter CI job that adds `-race`,
`goose up`, `go vet`, `gofmt`, a coverage floor, and five cold boots of the
real binary. CI once could not apply the migrations at all — it ran a bare
Postgres service container with no init script, so the role `protect_table`
requires did not exist. That is fixed and recorded in `CHANGELOG.md`.

The readiness probe is still the honest minimal one:

```
$ curl -s localhost:8080/healthz
{"status":"ok"}

$ curl -s localhost:8080/readyz
{"status":"ok","deps":"none"}
```

`deps:"none"` is accurate for this service's current check set, not a stub: it
reflects what `readyz` is configured to verify, and Postgres is not in that
set. Treat it as a liveness signal, not a dependency check.

## Licence

**Business Source Licence 1.1** — [LICENSE](LICENSE). Free to run, free to
self-host, and never to offer identity as a competing service.

That is `OPS-D2` in `cafaye/notes/ops.md` (line 176): the framework stays open,
the services move to BSL, and BSL rather than AGPL "because the buyers are
teams and AGPL makes their lawyers twitchy". The principle behind the split is
stated there too (line 429) and is worth quoting to a prospect rather than
paraphrasing — **the mint is the moat, the redeemer is not**. This repository is
the redeemer.

What that means in practice, and the two dates in the file that matter:

- **You can run it.** Production use, on your own box, without asking and
  without paying. No requirement to publish your changes or to tell us you made
  them.
- **What you may not do is offer it as a competing service.** That is the whole
  of the restriction. It is not a feature flag, a licence-key check, a usage
  meter or a nagscreen — nothing in this codebase enforces it, because a
  restriction the software has to check is a restriction a fork removes.
- **On 2030-10-10 the Change Date arrives** and the Licensed Work becomes
  Apache-2.0. Four years from 2026-10-10, which is the interval the brief fixed
  and the one BSL's own Terms name as the default.
- **There is no Additional Use Grant**, and the `Parameters` block says `None`
  on purpose. An Additional Use Grant is a *narrowing* — "limited production
  use", a named subset — and what Cafaye Ops promises is the whole of
  non-competing production use rather than a carve-out of it.

**Third-party components keep their own licences and notices**, preserved in the
applicable source files. Nothing here asserts Cafaye ownership over third-party
work.

The grant is declared in three places that must agree, and each of them is a
file a reader actually opens: [LICENSE](LICENSE), and the `info.license` block of
both contracts — [openapi/v1.yaml](openapi/v1.yaml) and
[openid/openid.yaml](openid/openid.yaml). `cafaye.yml` carries a comment rather
than a field: core owns the manifest schema
(`../core/schemas/cafaye.manifest.schema.json`), it sets
`additionalProperties: false` and lists no `license` key, and a document with
one fails validation — measured, not inferred. The reason is written down in
`cafaye.yml` itself, so that the next person to look for a licence field there
finds out why there is not one instead of adding a violation.

## Why chi

Chi over echo: same five routing features, a fraction of the dependencies, and
`net/http` is the type it serves, so a handler is a plain
`func(http.ResponseWriter, *http.Request)` with no framework types in the
signature. It is a router, not a framework — nothing in `internal/` needs to
know chi exists to be tested.

## Dependencies

The scoped API token packet added **none**, which is the point worth stating: a
credential that is a random value in a column, hashed with `crypto/sha256` and
looked up by an indexed equality, needs nothing from outside the standard library.
There is no signing key to load, no key to rotate and no trust anchor to publish —
which is one of the reasons this credential is a row lookup rather than a JWT, and
one of the reasons it has no cost at boot.

Direct dependencies, each with a cause:

- `chi` — routing, above.
- `pgx` — Postgres. The pool and the `SKIP LOCKED` claim in the outbox.
- `alexedwards/argon2id` — password hashing. Go's standard library has no
  password KDF and `x/crypto` ships only the raw primitive with no encoded-digest
  format or parameter handling, so this is the one case where the standard
  library genuinely cannot do the job. It is not a framework, it has no
  transitive dependencies of its own, and reimplementing argon2id in `internal/`
  would be far more dangerous than depending on it. It arrives with the auth
  packet; the scaffold had only the first two.
- `zitadel/oidc` — the OpenID Connect **provider**. The protocol is not
  reimplemented here: the library owns the OAuth 2.0 and OIDC state machines, and
  `internal/oidc` supplies the two things a library cannot have, which are a
  storage implementation over this service's own tables and a login UI bound to
  this service's own sessions. `refs/oidc` (v3.51.10) is the library, read for
  its examples.
- `github.com/pquerna/otp` — TOTP, RFC 6238. The algorithm is the specification, and a
  private implementation of a specification is a vulnerability with tests: this
  library owns the base32 of the shared secret, the HMAC, the dynamic truncation,
  the six-digit zero-padding and the constant-time comparison, and `internal/mfa`
  never computes any of them. What `internal/mfa` owns is the three decisions the
  specification does not make: which steps are candidates (the library's own
  windowed `ValidateCustom` returns a bool and the replay guard needs to know which
  step matched), how long a code is accepted, and whether a step has been spent.
  It brings `github.com/boombuler/barcode` indirectly, for a QR-code method this
  service does not call. Arrives with the MFA packet.
- `github.com/oapi-codegen/runtime` — **for the generated client only, and this is
  the one that corrects MD6.** MD6 said the Go client "reaches `identity`'s existing
  stack with no new dependency at runtime", on the grounds that oapi-codegen is a
  `go:generate` tool rather than a library a user imports. **The GENERATOR is right
  and is not a dependency**: the `//go:generate` line is pinned to `v2.8.0` and
  `go run <module>@<version>` resolves in module-aware mode, so oapi-codegen never
  appears in `go.mod` at all. **The code it EMITS is a dependency**, and it imports
  this module for parameter binding and for its `UUID` and `Email` types. That brings
  two more (`apapsch/go-jsonmerge/v2` and `google/uuid`), so three in total.

  **None of the three reaches the service's binary.** `client/` is not imported by
  `./cmd/identity` and never should be: a service that called its own API over HTTP
  would add a network hop to itself and depend on a client to do what its own stores
  already do. `go list -deps ./cmd/identity | grep oapi-codegen` is empty, and
  `TestTheServiceBinaryDoesNotReachTheGeneratedClient` holds that as a check rather
  than a claim. The full reasoning, including what it costs the coverage floor, is
  [DECISIONS.md](DECISIONS.md) D6 — and what it costs is answered there now: the
  generated client is **excluded from the coverage measurement** by a declared path,
  with the floor left where it was. See "The coverage floor, and what it is a
  percentage of" below.

- `go-jose/v4` — **forced, not chosen.** `op.SigningKey` returns a
  `jose.SignatureAlgorithm` and `op.Key.Key()` holds a `jose` key, so the
  library's storage interface cannot be implemented without importing it. It
  arrives with 21 other indirect modules (`rs/cors`, `zitadel/schema`,
  `bmatcuk/doublestar`, `otel`, `gorilla/securecookie` and their closures).
  `go mod tidy` is idempotent and `go.sum` is committed.

- `github.com/pressly/goose/v3` (v3.28.0) — **the migrator, and it is a
  dependency now because the image has no other way to migrate.** The runtime
  stage is distroless: no shell, no `psql`, and no `migrations/` — so the
  substrate's one-shot migrate Job had nothing to run, and a box booted against
  an empty schema. The library is linked in at exactly the version the CLI is
  pinned to in `bin/provision-testdb` and `ci.yml`, so one engine and one
  `goose_db_version` table describe every database. The alternative — a second
  applier over pgx — was refused on this repository's own evidence: `bin/migrate`
  was the second implementation, and applying both goose sections in order is
  what it cost (identity-31). It brings four modules
  (`mfridman/interpolate`, `sethvargo/go-retry`, `go.uber.org/multierr`, and a
  patch bump of `grpc`/`genproto` that goose's own `go.mod` requires). It does
  **not** bring goose's other dialects: the root package imports no driver, so
  the ClickHouse, MySQL, MSSQL and SQLite dependencies in goose's `go.mod` are
  never built. `TestTheServiceBinaryCarriesNoDatabaseDriverButPgx` holds that on
  the binary's own dependency closure (`go list -deps ./cmd/identity`), in both
  directions, so it is a check and not a sentence here.

Two more, and both are the floor rather than a choice among alternatives:

- `go.opentelemetry.io/otel/sdk` and
  `go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp` (v1.46.0) —
  identity emits OpenTelemetry spans into the collector that ships with kit's
  stack, so "where did that 500 come from" is a question with an answer rather
  than a log tail. Without these two, identity cannot emit a span at all.
  **grpc, the protobuf runtime and grpc-gateway arrive transitively**, through
  `otlpconfig`; that is a cost of the OTLP exporter's own configuration path, not
  a second transport this service asked for.
  - **Deliberately not `go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp`.**
    Its handler records `url.path`, `url.query` and request headers as its own
    span attributes. Those are exactly the values a redacting collector strips,
    and stripping them downstream is one control; `internal/httpapi/telemetry.go`
    is hand-rolled so that what identity records is *only* what
    `internal/telemetry`'s allowlist permits. Two controls beat one, and the
    second one is the one this repository tests.
  - **Deliberately not `otel/sdk/metric`.** Metrics come from kit's collector's
    `spanmetrics` connector, which derives them from spans *after* redaction — so
    a derived metric can never carry a dimension the allowlist stripped, and
    there is no second definition of the same series anywhere in the fleet.
  - **Deliberately not `otel/log`.** Logs are the container's stdout: compose's
    `logging:` driver ships them to the collector's `syslog/crash` receiver, which
    makes a panic a log record with a `service.name` on it and adds no
    per-language dependency to this module.

## Running it

Nothing but Go is needed, and no database is required — v0 supports an unset
`DATABASE_URL`:

```sh
mise install          # or use any Go >= 1.26
go run ./cmd/identity # http://localhost:8080
```

Or the gate, which is what CI runs:

```sh
bin/prime   # go mod download && go build ./... && go test ./...
```

With the database:

```sh
docker compose up -d
curl -s localhost:8080/readyz    # {"status":"ok","deps":"postgres"}
```

## Configuration

Read from the environment at startup, validated, and never mutated afterwards.
A value that is present but invalid fails startup rather than falling back to a
default, so a typo in a deployment is a crash with a message instead of a
service quietly listening on the wrong port.

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8080` | TCP port to bind. Must be 1-65535. |
| `DATABASE_URL` | *(unset)* | Postgres DSN. Optional in v0; unset means no pool and no readiness dependency. |
| `NATS_URL` | *(unset)* | The broker the outbox publisher publishes to. Optional, and unset is a supported state rather than an error: the outbox table, the loop and the `Publisher` interface all exist, and a deployment that has not wired a broker accumulates rows in `outbox_events` until it does — the rows are the promise, and they drain the moment a broker is configured. Set it and the publisher loop starts at boot, publishing each event on the subject equal to its `type` (no mapping, no prefix rewriting) over JetStream, and marking `published_at` from the broker's ack. A value that does not parse fails the boot. **The stack must define a JetStream stream whose subject filter covers what identity publishes (e.g. `identity.>`)** — a publish to a subject no stream matches is refused by the broker, which leaves the row claimable with `attempts` incremented and `last_error` naming the refusal: loud, and the direction a misconfiguration should fail in. |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. Drives `log/slog`. |
| `RATE_LIMIT_WINDOW` | `1m` | How long a rate-limit window lasts, shared by every route on the unauthenticated auth surface. Fixed, not sliding: a sliding window needs per-client state this in-process limiter does not keep, and the cost of a fixed one is a burst of up to 2× the limit at a window boundary — accepted because the alternative is a shared store, which one launch replica does not have. A present-but-unparseable or non-positive value is a startup failure. |
| `RATE_LIMIT_SIGNUP` | `10` | Requests per window for `POST /v1/users`, keyed on client address. Ten is above any human typing and below a spray; the honeypot and signed timestamp are the bot deterrence, this is the bound. |
| `RATE_LIMIT_SIGNIN` | `20` | Requests per window for `POST /v1/session`, keyed on client address. Higher than signup because a human retries a mistyped password — and the per-account lockout (5 failures / 15 min) is the second line this backs up. |
| `RATE_LIMIT_SIGNUP_TIMESTAMP` | `30` | Requests per window for `POST /v1/signup-timestamp`, keyed on client address. The cheapest route on the surface — one HMAC, no database — and the one a bot polls before each signup attempt, so it is bounded even though it mints nothing. |
| `RATE_LIMIT_RECOVERY` | `5` | Requests per window for the two anonymous recovery request routes (`POST /v1/password-resets`, `POST /v1/email-verifications`), keyed on client address. The lowest limit on the surface because every accepted request sends email: the bound is on outbound mail, not on attempts. |
| `REQUIRE_EMAIL_VERIFICATION` | `false` | **Gate sign-in on a proved address. Off by default, and the default is parity, not an oversight**: the reference this fleet matches (Jumpstart Pro) does not use Devise's `:confirmable`, so an unverified address can sign in there. When `true`, `POST /v1/session` refuses an unverified account with `403 email_not_verified` — **after** the password verifies, so a caller told so has already proved they hold the credential. The risk the flag exists to close: an address nobody has proved can hold a session. A present-but-unreadable value is a startup failure — a deployment that believes the gate is on and is not is the worse of the two states. |
| `SIGNUP_SIGNING_KEY` | *(none — required)* | base64url, **exactly 32 bytes**. The HMAC-SHA256 key `POST /v1/signup-timestamp` signs the pair with — the second half of signup bot defence. **The one secret with no supported absent state**: unset is a startup failure, not a reduced surface, because a process that could boot without it would serve an undefended signup form. `docker-compose.yml` supplies an obviously-development default (the base64url of `identity-development-signup-key!`) so a fresh clone boots; production sets it in `.kamal/secrets` via `config/deploy.yml`, and there is no default on that path. Mint one with `openssl rand -base64 32 \| tr '+/' '-_' \| tr -d '='` — plain `openssl rand -base64 32` emits standard base64 with one `=` of padding and fails the boot with "it is not base64url". |
| `OIDC_ISSUER` | *(unset)* | The OpenID Connect issuer. Required with `OIDC_SIGNING_KEY`, `OIDC_SIGNING_KEY_ID` and `OIDC_LOGIN_UI_URL` — all four together, or none of them. |
| `OIDC_SIGNING_KEY` | *(unset)* | PEM-encoded RSA private key, ≥ 2048 bits. PKCS#1 and PKCS#8 both load. |
| `OIDC_SIGNING_KEY_ID` | *(unset)* | The `kid` published in the JWKS and signed into every token. 1-64 characters of `A-Z a-z 0-9 . _ -`. |
| `OIDC_LOGIN_UI_URL` | *(unset)* | **The page that asks a person for their password.** `identity` renders no HTML, so this is required and there is no default: a provider that cannot send a browser anywhere to authenticate refuses to start. Absolute, `http`/`https`, a path is fine, and **no query and no fragment** — identity merges its own parameters into the query. See [the redirect contract](#the-sign-in-interaction-and-the-login-ui). |
| `OIDC_ALLOW_INSECURE` | `false` | Permits an `http` issuer. For `localhost` and compose stacks only. |
| `MFA_ENCRYPTION_KEY` | *(unset)* | base64url, **exactly 32 bytes**. Seals the TOTP secret at rest. Never generated. Unset means MFA is not turned on: the management routes are absent and the login challenge is still enforced. A value of the wrong length is a startup failure. |
| `MFA_ISSUER` | `cafaye identity` | The account label an authenticator app displays. A display string, not a secret; changing it does not affect any confirmed credential. |
| `COURIER_BASE_URL` | *(unset)* | The mail service's base URL. With `COURIER_TOKEN` and a link template it makes recovery deliverable; unset, the recovery routes stay mounted and answer `503` with a sentence naming the problem. `http` is accepted for a compose stack. |
| `COURIER_TOKEN` | *(unset)* | The service credential courier authenticates `POST /v1/messages` with. Never logged, never rendered. **This must hold the same identity-issued API key that courier holds as `COURIER_IDENTITY_TOKEN`** — courier introspects the token identity presented on the inbound request, and identity lets a token caller introspect only itself, so two distinct keys produce identity's `403` and courier's `503` with nothing in either repository to explain it. `docker-compose.yml` requires the variable from the host environment, and its failure message is that sentence. |
| `OAUTH_REDIRECT_BASE_URL` | *(unset)* | **This service's own public base URL**, and every provider callback is built from it — never from a request's `Host`. Point it at the app's origin and not at identity's address unless identity *is* the origin the browser returns to. `http`/`https`, a path prefix is fine, no query and no fragment. |
| `OAUTH_ENCRYPTION_KEY` | *(unset)* | Standard base64 of exactly 32 raw bytes, sealing provider tokens at rest. Never generated. A value of the wrong length or the wrong alphabet fails the boot **even with no provider configured**. |
| `OAUTH_GOOGLE_CLIENT_ID` / `OAUTH_GOOGLE_CLIENT_SECRET` | *(unset)* | The Google pair. **Both or neither**: one half is a startup failure, and a provider with no credentials is not mounted at all rather than mounted and 404. |
| `OAUTH_GITHUB_CLIENT_ID` / `OAUTH_GITHUB_CLIENT_SECRET` | *(unset)* | The GitHub pair, with the same both-or-neither rule. |
| `OAUTH_GOOGLE_AUTHORIZE_URL` | `https://accounts.google.com/o/oauth2/v2/auth` | Where the browser is sent for a Google code. One of the seven **endpoint overrides**: read once at startup, deployment configuration only, and never influenced by a request, a header or a query parameter. |
| `OAUTH_GOOGLE_TOKEN_URL` | `https://oauth2.googleapis.com/token` | Where the Google code is exchanged for a token. A present-but-undialable value **fails the boot naming this variable** rather than falling back to Google's real endpoint — a deployer who set it and silently got the default would have a working sign-in flow pointing somewhere they did not choose. |
| `OAUTH_GOOGLE_USERINFO_URL` | `https://openidconnect.googleapis.com/v1/userinfo` | Where Google's access token is presented to learn who the user is. |
| `OAUTH_GITHUB_AUTHORIZE_URL` | `https://github.com/login/oauth/authorize` | GitHub's authorize endpoint. Same three rules as Google's. |
| `OAUTH_GITHUB_TOKEN_URL` | `https://github.com/login/oauth/access_token` | GitHub's token endpoint. |
| `OAUTH_GITHUB_USERINFO_URL` | `https://api.github.com/user` | GitHub's identity call. |
| `OAUTH_GITHUB_EMAILS_URL` | `https://api.github.com/user/emails?per_page=100` | GitHub's address list, dialled only when `/user` comes back with no address. **A query is allowed here and a fragment is not** — a fragment is never sent to a server, so an override carrying one is silently a different URL from the one that was written. There is no `OAUTH_GOOGLE_EMAILS_URL`, and setting one fails the boot: Google returns the address on the identity call, so there is no second call to point anywhere. |
| `RECOVERY_LINK_TEMPLATE` | *(unset)* | **The link for every purpose that has no template of its own.** `https://app.example.com/reset?token={token}` is a working example, and `{token}` is required. **This is the single template a deployment set before the per-purpose variables existed, and it is honoured** — so setting it alone keeps an existing deployment booting with the links it had, which for the configuration that shape was introduced to replace means the address-confirmation link still points at the password-reset screen. Setting it is enough to deliver; setting it *alone* is a migration still in progress. |
| `PASSWORD_RESET_LINK_TEMPLATE` | *(unset)* | Where the **password reset** link points. Overrides `RECOVERY_LINK_TEMPLATE` for that purpose only. `docker-compose.yml` supplies it from `APP_BASE_URL` (default `http://localhost:3997`, the local parlor's dev port). |
| `EMAIL_VERIFICATION_LINK_TEMPLATE` | *(unset)* | Where the **address confirmation** link points. Overrides `RECOVERY_LINK_TEMPLATE` for that purpose only — and setting this one variable is the whole migration out of the state above. `docker-compose.yml` supplies it from `APP_BASE_URL` (default `http://localhost:3997`, the local parlor's dev port). |
| `INVITATION_LINK_TEMPLATE` | *(unset)* | Where the **invitation** link points — the accept screen parlor serves. **Required at boot whenever the courier block is wired** (`COURIER_BASE_URL` + `COURIER_TOKEN` + a recovery template): the invite route is mounted unconditionally, so a deployment that can send mail and cannot say where invitation links go fails at send time on every invite. It is not a recovery purpose and has no default — inheriting the reset template would mail a link to a screen that cannot redeem an invitation token. `docker-compose.yml` supplies it from `APP_BASE_URL`. |
| `IDENTITY_OTEL_ENDPOINT` | `http://otel-collector:4318` | The OTLP endpoint spans go to. **The only contract** (core D16), and the collector that ships with kit's stack is just its default value — so tracing is on by default and a deployer who already runs Datadog or Grafana sets one variable and kit's stack goes quiet. Unset costs spans and nothing else: no queue, no retry loop, no dial at boot. | **The only contract** (core D16), and the collector that ships with kit's stack is just its default value — so tracing is on by default and a deployer who already runs Datadog or Grafana sets one variable and kit's stack goes quiet. Unset costs spans and nothing else: no queue, no retry loop, no dial at boot. |
| `IDENTITY_TENANT_ID` | *(unset)* | The `tenant_id` **resource** attribute. Never a span attribute — see the allowlist rule in [AGENTS.md](AGENTS.md). Unset by default, because an empty one shows up as a second service row in every collector's service list. |
| `DEPLOYMENT_ENVIRONMENT` | *(unset)* | The `deployment.environment` resource attribute. An enum in core's resource schema (`development`/`test`/`staging`/`production`), so there is no fourth spelling to invent. |
| `OTEL_SERVICE_VERSION` | *(detected)* | The `service.version` resource attribute. Absent is treated as "unknown" rather than defaulted to a string, because a configured-but-empty version renders as a second service row in a collector's service list. |

## Endpoints

| Route | Response | Meaning |
|---|---|---|
| `POST /v1/accounts` | `201 {…}` | Create an account; the caller becomes its **owner**. Only a name — the slug is derived and `409 conflict` if it is taken. **Session only.** |
| `GET /v1/accounts` | `200 [{…}]` | The accounts this **user** belongs to, each with the caller's role **in it**. `[]` and not `null`. **Session only.** |
| `GET /v1/accounts/:id` | `200 {…}` | One account and its members. `404` for a non-member, never `403`. Member. |
| `PATCH /v1/accounts/:id` | `200 {…}` | Rename. **The `slug` does not move** — a handle that changed would break every link already sent. Admin. |
| `DELETE /v1/accounts/:id` | `204` | Delete, with everything under it. Irreversible, no `confirm` field. **Owner**, `accounts:delete`. |
| `GET /v1/accounts/:id/members` | `200 {memberships, role}` | The account's members, newest first, plus the caller's own role. Every entry names its `user_id`. Member. |
| `POST /v1/accounts/:id/invitations` | `201 {…, token}` | Invite somebody. `token` is returned here and never again. **The invitation is emailed** when this deployment can send mail — `INVITATION_LINK_TEMPLATE` is required at boot whenever the courier block is wired — and the send happens after the invitation commits: a send that fails is a `500`, and the invitation row survives it, revocable and re-invitable. A deployment with no mail path creates the invitation and mails nothing; the `201` does not say an email was sent. `owner` is a 422; only an owner may invite an `admin`. Admin. |
| `PATCH /v1/accounts/:id/members/:userId` | `200 {…}` | Change a role. `422 last_owner` rather than leaving an account unadministerable. **Owner.** |
| `DELETE /v1/accounts/:id/members/:userId` | `204` | Remove somebody, and stop their scoped tokens on their next request. An admin may not remove an owner. Admin. |
| `POST /v1/accounts/:id/ownership-transfers` | `200 {account, new_owner, previous_owner}` | Hand the account to a member who is **already in it**. The new owner gets `owner`; **the previous owner becomes `admin`**, which is what keeps a transfer reversible. `422 not_transferable` for a personal account or one with a single member, `422 transfer_to_self` for naming yourself, `404` for somebody who is not a member — a transfer does not invite. The caller's authority is asked of the credential, never of the body. **Owner.** |
| `POST /v1/invitations/accept` | `200 {…}` | Accept an invitation, signed in as the invited user. `404` for anything that is not a live token, `410` for one that expired or was spent. **Session only.** |
| `POST /v1/accounts/:id/agents/claim` | `200 {id, name, status, claimed_at}` | Bind an **agent principal** to the account. The claim link is the only thing in the body and the only thing that names the agent — the account is the path, the human is the session — and it is the one credential a stranger ever presents here. `404` for a wrong token, an expired link, an already-claimed agent and an agent that never existed: one answer for all four, so a guessed link says nothing about which agent it might have been. `422` for an empty body. The claim is **single-use and conditional** — the update carries the digest and the status in its `WHERE`, so two clicks produce one claim. **Session only:** a scoped api key is `403`. The 200 carries the agent **and the bearer credential the claim minted for it** — one transaction, because an agent that is bound and holds no credential is a claim a human completed and an agent cannot use. `token.token` appears there and nowhere else. It is not an entitlement: the entitlement grant on a claim is conductor's (W2-P3), and D4 keeps an agent from granting itself one. Member. |

| `GET /v1/agents/claim/:token` | `200 {id, name, username, status, created_at, device, claim_expires_at}` | **Preview an agent claim** — the first frame of the website's claim screen, and what `getAgentClaim` calls. **Anonymous and unauthenticated**: the link in the path IS the credential (256 bits of `cafaye_` entropy, stored only as a SHA-256 digest), and a human has to be told whose agent it is before they have signed in. It is a **read that changes nothing** — no claim, no credential, no event row; the use case has no access to the credential machinery, and the proof is that a link still claims after it has been previewed. `device` is the agent's own free-form document and carries no schema: the keys are its vocabulary, and the client keeps the string values and skips the rest. `claim_expires_at` is a fact about the LINK, never a countdown — when it passes the same 404 arrives. `404 not_found` for a **wrong token, an expired link, an already-claimed agent and an agent that never existed: one answer for all four**, the same collapse the claim route makes, because the read filters the digest, the status and the expiry in one statement. No 410, no 409, and the token in the path is never parsed so a malformed segment is a 404 and not a 422. `429` rate-limited on the client and the route. |
| `GET /v1/agents/home` | `200 {id, name, username, status, claimed, claimed_by_account_id?, claimed_at?}` | **Who this agent credential is**, and the `cafe agent whoami` read. Authenticated with the agent's own bearer token, resolved through the agent table. The body is the caller's own identity, its lifecycle status and the account that claimed it — **by row id and nothing more**: not the account's name or members, because this route does not read the account through an agent's credential. `claimed` is the ownership question, not the liveness one — a disabled agent is claimed. **Open to an unclaimed principal, and that is the point:** it is gated by `agentCredentialOnly` and not `agentClaimedOnly`, so an agent that registered itself runs whoami and gets `claimed: false`, which is the answer it exists to read. Gating it the other way would answer "you are not claimed" by refusing to say who is asking. No token and no digest in the body. `401` with no credential, before any path is read. |
| `POST /v1/agents` | `201 {agent, api_key, claim}` | **Register an agent** — public, unauthenticated, and the step-① endpoint `cafe agent register` calls. Body `{name}`, optional `username`. The response carries **two secrets, each shown once**: `api_key.token` (the bootstrap bearer credential) and `claim.url` (the link a human opens to claim). Both are stored only as SHA-256 digests; no endpoint re-reads either. The agent comes back `unclaimed` (D4) with no account. A **generated username collision is retried** under the hood, so the endpoint never answers "taken" and cannot be used to probe which handles exist; a malformed handle, or a *supplied* one that survives the retry budget, is a `422` naming `username`. `429` rate-limited on the client and the route, `503` when no claim screen (`AGENT_CLAIM_UI_URL`) is configured — refused rather than minting an unclaimable agent. |
| `POST /v1/agents/claim-link/refresh` | `200 {agent, claim}` | **Reissue an agent's claim link without claiming it.** Authenticated with the agent's own bearer token, which resolves against the agent table. Gives a fresh claim URL and changes nothing else — the agent stays `unclaimed`. A refresh against a **claimed** agent is a `404`, the same answer a wrong token gets, so "give me a new link" can never act as "claim me" (D4). The `Idempotency-Key` correlates the agent's retries in the audit trail but does **not** cache: every refresh mints a new link. `401` with no credential. |
| `POST /v1/agents/tokens` | `201 {id, name, expires_at, token}` | **Mint a bearer token the agent holds.** Same shape as the account api-keys mint, over the agent's own credential. `token` returned here and nowhere else; a durable SHA-256 at rest. `403 agent_unclaimed` for a live credential whose principal no human has claimed (D4: an agent acting alone gets nothing), naming the remedy in the `detail`. `409 conflict` for a second live token of one name. `expires_in` is seconds from now (90-day default, 365-day ceiling, `0`/negative is `422`). "Scoped" means *held by one principal and revocable on it*; the per-capability scope vocabulary arrives with the routes it will gate, so a token minted now gates only its own management surface. |
| `GET /v1/agents/tokens` | `200 [{id, name, expires_at, …}]` | The agent's credentials, newest first, **revoked ones included**. `[]` and not `null`. **No token and no digest** in the body. `403 agent_unclaimed` for a live credential whose principal no human has claimed (D4: an agent acting alone gets nothing), naming the remedy in the `detail`. |
| `DELETE /v1/agents/tokens/:tokenID` | `204` | Revoke one of the agent's own credentials. The row is kept. `403 agent_unclaimed` for a live credential whose principal no human has claimed (D4: an agent acting alone gets nothing), naming the remedy in the `detail`. `409 conflict` if already revoked, `404` for an id that is not this agent's. `401` with no credential, before the id is parsed. |
| `POST /v1/agents/tokens/:tokenID/rotate` | `201 {id, name, expires_at, token}` | **Rotate a credential in place**: revoke the old and mint a new one of the same name in one call, so there is no window with no live token under that name. `403 agent_unclaimed` for a live credential whose principal no human has claimed (D4: an agent acting alone gets nothing), naming the remedy in the `detail`. `409` if the credential is already revoked, `404` for an id that is not this agent's. |
| `GET /healthz` | `200 {"status":"ok"}` | Liveness. Always 200 while the process serves — it never touches a dependency, so a database outage cannot get the process restarted out from under in-flight work. |
| `GET /readyz` | `200 {"status":"ok","deps":"postgres"}` | Readiness. 200 when every dependency answers, `503 {"status":"unavailable",...}` otherwise, with each probe bounded at 2s. |
| `POST /v1/signup-timestamp` | `200 {"timestamp","signature"}` | **Mint a signed timestamp pair for the signup form.** Public and unauthenticated, exactly as `POST /v1/users` is. The pair is an HMAC-SHA256 over the Unix `timestamp`, keyed with `SIGNUP_SIGNING_KEY` — a server secret the client cannot sign, so identity mints and the same secret verifies. The form (parlor) asks for a fresh pair before it renders and carries it on `POST /v1/users`. The pair is a bearer credential: it expires one hour after it is minted, and a timestamp younger than two seconds is refused because a bot submits instantly. Every refusal at submission — forged, instant, expired — is the same generic `422` as the honeypot's, so a bot cannot tell which check caught it. `429 rate_limited` past `RATE_LIMIT_SIGNUP_TIMESTAMP` per client address. |
| `POST /v1/users` | `201 {"id","email"}` | Register. `409 conflict` if the address is taken, `422 validation_failed` with `errors[]` on a bad field, `400 invalid_json` on a malformed body, `413 payload_too_large` past 4 KB. The form (parlor) sends a hidden `website` honeypot field; a populated value is refused with the same generic `422` before any row is created. It also carries the `timestamp` + `signature` pair from `POST /v1/signup-timestamp`; a missing, forged, instant or expired pair is refused with that same generic `422`, before any row is created. `429 rate_limited` past `RATE_LIMIT_SIGNUP` per client address. |
| `POST /v1/session` | `200 {"token","expires_at"}` | Log in. Sets the `__Host-session` cookie to the same token. `401 unauthorized` for any unusable credential, `423 account_locked` with `Retry-After` while locked, `403 email_not_verified` when `REQUIRE_EMAIL_VERIFICATION` is on and the account's address is not proved (after the password verifies). `429 rate_limited` past `RATE_LIMIT_SIGNIN` per client address. |
| `POST /v1/session/mfa` | `200 {"token","expires_at"}` | Answer a second factor and **only then** get the session. `{challenge?, code}` — the challenge from a `202`, and a TOTP code or a recovery code. | |
| `DELETE /v1/session` | `204` | Revoke the current session and clear the cookie. `401` if no credential was presented. |
| `POST /v1/session/tokens` | `200 {token, expires_at}` | **Exchange the session for a short-lived access token bound to ONE account** — for consumers that scope by a single account and verify RS256 tokens off `/.well-known/jwks.json` (billing is the first; its verifier requires a singular `account_id`, and profile-scope access tokens carry `accounts`, an array — the cross-repo disagreement recorded in billing's `REPORT-billing-21-authorization`). `{account_id, audience}`: the account is **named by the caller and the membership is checked here**, so nothing ever picks `accounts[0]`. Claims are `iss`, `aud`, `sub`, `iat`, `exp`, `jti`, `account_id` — minimal, and deliberately without the `accounts` array. `404` for an account the caller is not in (and for one that does not exist — one sentence for both, so this route cannot walk ids), `422` for a field that is missing or malformed, `500` when the signer fails. **Session only:** a scoped api key is `403`, because a machine credential must not mint a token that asserts a person's identity. |
| `GET /v1/sessions` | `200 {sessions: [{id, created_at, expires_at, user_agent, ip, current}]}` | **Every session this account holds**, newest first, `[]` and never `null`. **No token and no digest is rendered** — the row's id is the whole of what a client gets, plus what a person recognises: when it started, when it dies, the user agent and address as recorded. `current` marks the session this request arrived on, so a UI need not ask the user which device this is. Expired rows are omitted, so every entry is a button that does something. `401` for an unusable credential rather than an empty list — an empty list would tell a client its session is fine. **Session only:** a scoped api key is `403`. |
| `DELETE /v1/sessions/:sessionId` | `204` | Revoke **one** of the caller's own sessions. `404` for all four ways of not owning it — never existed, somebody else's, already revoked, and the nil uuid — with **one fixed sentence**, because a 403 against a 404 would let any signed-in caller probe whether a session id is live in this deployment at all. A malformed id is a `404` and not a `422` for the same reason. **Revoking the session you are using is allowed** and signs you out; the `204` sets no cookie, so use `DELETE /v1/session` to also clear the browser's. **Session only:** a scoped api key is `403`. |
| `GET /v1/auth/oauth/:provider` | `302` | **Start a social sign-in.** Redirects the browser to the provider with a fresh `state` and sets `__Host-oauth-state`. **No credential, and none can be presented** — a browser holds nothing here but the cookie this route just set. `404` for a provider this deployment has no credentials for *and* for a name that does not exist, because telling them apart enumerates the configuration. A session cookie is read only to record an **intention**: if one resolves, the callback will *link* rather than sign in. Absent entirely when no provider is configured. |
| `GET /v1/auth/oauth/:provider/callback` | `200 {token, expires_at}` | **Finish it.** **No credential here either** — the state cookie is the whole of what authenticates the round trip, and it is compared *before* the code is spent. Three shapes: `200 {token,…}` a sign-in; `202 {mfa_required,…}` an account with a second factor, so no session is minted and you finish at `POST /v1/session/mfa`; `200 {linked_provider}` the link path, which mints **nothing**. `400` for a state mismatch, a declined consent or a refused code; `409` when the provider's address already belongs to an account here — **it refuses the sign-in rather than signing into that account**; `502` when the provider is unreachable. |
| `GET /v1/me` | `200 {"id","email"}` | The authenticated user. `display_name` is present only when set; `theme` is present only when the user has chosen one — an absent `theme` means the system theme. `401` with no usable credential. |
| `PATCH /v1/me` | `200 {"id","email","display_name"?,"theme"?}` | Set or clear the caller's display name and theme. `{display_name}` — trimmed, max 64 chars, empty string clears. `{theme}` — `light` or `dark`; an omitted field clears it back to the system theme, the same omission rule `display_name` has (the reference's `theme.blank?` is an absence, not a value, so the empty string is refused). `422 validation_failed` on an over-length name or a theme outside the closed set. `401` with no usable credential. |
| `DELETE /v1/me` | `204` | Delete the caller's own account: the user row, their personal account, their memberships, and every credential they hold. `409` naming each account when the caller solely owns a team account — nothing is deleted. `401` with no usable credential. Session-only; no scope authorises it. |
| `POST /v1/accounts/:id/oidc-clients` | `201 {id, client_id, client_secret, …}` | Register a relying party. **Owner only.** `client_secret` is returned here and never again. |
| `GET /v1/accounts/:id/oidc-clients` | `200 [{id, client_id, name, …}]` | The account's registrations, newest first. `[]` and not `null`. **Owner only.** |
| `GET /v1/accounts/:id/oidc-clients/:clientId` | `200 {id, client_id, …}` | One registration. `clientId` is the row id, not the `client_id` the product presents. **Owner only.** |
| `DELETE /v1/accounts/:id/oidc-clients/:clientId` | `204` | Revoke a registration, and every access token issued against it, in one transaction. `409 conflict` if already revoked. **Owner only.** |
| `GET /v1/mfa` | `200 {"enabled", …}` | Whether the caller has a second factor, when they enrolled, and how many recovery codes are left. `200` with `{"enabled":false}` when they have none — not a 404. |
| `POST /v1/mfa/enrollments` | `201 {"enrollment_id","secret","provisioning_uri",…}` | Generate a TOTP secret and store it **unconfirmed**. `secret` and `provisioning_uri` are returned here and never again. `{code}` is required to **replace** an existing factor. |
| `POST /v1/mfa/enrollments/:id/confirm` | `200 {"enabled","recovery_codes",…}` | Prove you can produce a code, which makes MFA live and **revokes every session the user holds**. `recovery_codes` is returned here and never again. |
| `POST /v1/mfa/recovery-codes` | `200 {"recovery_codes",…}` | Issue a new set and destroy the old one, in one transaction. Requires a factor. |
| `DELETE /v1/mfa` | `204` | Turn MFA off. Requires a factor, and revokes every session. `409 conflict` if MFA is not on. |
| `POST /v1/accounts/:id/api-keys` | `201 {id, name, scopes, …, token}` | Mint a scoped API token. **Owner only.** `token` is returned here and never again. `409 conflict` if this account already has a live key of that name. |
| `GET /v1/accounts/:id/api-keys` | `200 [{id, name, scopes, …}]` | The account's credentials, newest first, **revoked ones included**. `[]` and not `null`. **Owner only.** |
| `DELETE /v1/accounts/:id/api-keys/:keyId` | `204` | Revoke a credential. The row is kept. `409 conflict` if already revoked, `404` for an id that is not there or not in this account. **Owner only.** |
| `POST /v1/introspections` | `200 {active, …}` or `200 {"active":false}` | What a presented token may do, and for which account. Needed because the token is opaque. |
| `POST /v1/session-links` | `201 {token, expires_at}` | **Mint a delegated session link** for a subject you name. `sessions:write`, **scoped api key only** — a browser session is `403`, and so is presenting no credential at all. `404` for a subject that is not a user, which is deliberate here and the opposite of the self-service routes below; `409 conflict` for a subject with a second factor, because a link cannot answer a challenge; `422` for a window over the hour ceiling. The link is **not delivered by this service** and there is no redirect parameter — the caller owns both. |
| `POST /v1/session-links/redeem` | `200 {token, expires_at}` | **Redeem a delegated session link** for a browser session, **byte-for-byte what a correct password on `POST /v1/session` produces**. The link **is** the credential: no other credential is required, a browser session changes nothing, and a scoped api key is `403`. `404` for all six ways of being wrong — never existed, expired, spent, another flow's, a disabled subject, an enrolled one — with one fixed sentence, so a holder of a dead link learns nothing about the account it was for. A refused redemption **does not spend the link**. |
| `GET /v1/accounts/:id/admin/audit-log` | `200 {entries, next?}` | The account's admin audit trail, newest first, **append-only**. Bounded: `limit` defaults to 25 and is refused above 100; `before` is an opaque cursor. **Admin, `audit_log:read`, scoped api key only.** |
| `DELETE /v1/accounts/:id/admin/invitations/:invitationId` | `204` | Revoke one pending invitation. The row is kept with `revoked_at`, and the address is freed to be invited again. `409 conflict` if already accepted or revoked, `404` for an id not in this account. **Admin, `account_invitations:write`, scoped api key only.** |
| `POST /v1/accounts/:id/admin/invitation-revocations` | `200 {requested, revoked}` | Revoke up to 50 pending invitations in one transaction, **one** audit record for the lot. `confirm: true` and a non-empty array are both required. **Owner, `account_invitations:write`, scoped api key only.** |
| `POST /v1/users/:userId/disable` | `204` | **Turn a person's account off**, and end every session it holds in the same transaction. `users:disable`, **scoped api key only**, and **no account anywhere** — an account admin, `owner` included, cannot call this, because no route under `/v1/accounts/…` consults `users:disable`. A browser session is `403`, so is presenting no credential, and so is an account-scoped token with any other scope. `404` for a user id this service never issued, which is deliberate here and the opposite of the anonymous routes below. Repeating a disable is a `204`, not a `409`. |
| `POST /v1/users/:userId/enable` | `204` | Lift a disable. **Restores the column and nothing else** — the sessions the disable ended are gone and the owner signs in again, and a recovery link they already hold works again because a refused redemption never spent its token. Same credential, same `403`s. |
| `GET /v1/operator/me` | `200 {user: {id, email, staff}}` | **The signed-in staff user's own operator status**, and nothing about anybody else's. `401` with no usable credential; `403` for a scoped api key and for an authenticated session whose user is not staff — a tenant admin's included, because no account role implies global staff authority. |
| `GET /v1/operator/users` | `200 {users: [{id, email, display_name?, disabled_at, email_verified_at, created_at}]}` | **The bounded staff directory.** `?query=` is required and must be at least two characters; `?limit=` defaults to 25 and is refused over 50. The timestamps are present as null when never — never omitted. Minimal projection only — no password, API key, recovery, MFA secret or session token data. Same `401`/`403`s as above, and the gate runs before the query is read. |
| `POST /v1/operator/users/:userId/disable` | `204` | **Turn a person's account off, as a staff human.** The same transaction as the machine route — sessions, access tokens, column, audit row — with the signed-in staff user as the recorded actor and no api key. **Signed-in staff session only**: a machine key is `403`, a non-staff session is `403`, no credential is `401`. `404` for a user id this service never issued. |
| `POST /v1/operator/users/:userId/enable` | `204` | Lift a disable, as a staff human. **Restores the column and nothing else.** Same credential, same `403`s. |
| `POST /v1/password-resets` | `202 {"status":"accepted"}` | Mail a single-use link, valid 30 minutes. **The same body for every address** — registered, unregistered, or inside the one-minute cooldown — so it cannot be used to discover who has an account. `503` when the deployment cannot send mail. `429 rate_limited` past `RATE_LIMIT_RECOVERY` per client address. |
| `POST /v1/password-resets/confirm` | `204` | Set the new password and **revoke every session and every live access token**, in one transaction. Mints no session; sign in again. `404` for anything that is not a live token — never existed, expired, spent, or another flow's. |
| `POST /v1/email-verifications` | `202 {"status":"accepted"}` | Mail a link proving the address **already on the account**. Registration does not send one. **The same body for every address, including one whose account has already proved it** — the route needs no credential, so a status that differed would publish a list of verified accounts. Ask `GET /v1/email-verification` if you need to know. `429 rate_limited` past `RATE_LIMIT_RECOVERY` per client address. |
| `POST /v1/email-verifications/confirm` | `204` | Mark the address proved. **Revokes nothing and mints nothing** — a verification is a fact about an address, not a credential. `404` for anything that is not a live token, **including a token of the wrong length**. |
| `GET /v1/email-verification` | `200 {email, email_verified, email_verified_at?}` | Whether the caller's own address is proved — **the authenticated route for that question**, and the one a client should ask where it used to read a 409. `email_verified_at` is **absent** when it was never proved, which is a different state from a proved address that has since been changed. |
| `POST /v1/email-changes` | `201 {current_email, new_email, expires_at}` | Start a move. A link goes to the address the account has **now**; nothing moves until two addresses have each confirmed. `409 conflict` if the new address is taken, `422 already_current` if it is the one already there. |
| `POST /v1/email-changes/current-address` | `202 {"status":"accepted"}` | Prove the current address; a second link is then minted for the **new** one. The body deliberately does not say where it went. |
| `POST /v1/email-changes/new-address` | `200 {…, email_verified:false}` | Complete the move: the address changes, the verification is **cleared**, and every session and access token is revoked. `email_verified` is false on purpose — reading an inbox is not proof the address is yours. |
| anything else on `/v1` | `404 not_found` | A problem document, not chi's default plain text. |

**Every route in that block refuses a scoped API token with 403**, and two of them
require a session. A credential that could start an email change could move an
account's recovery path, and a credential that could mint a password reset is a
takeover with a delay rather than a break-in — so there is no scope in the machine
vocabulary for any of it, and there is not going to be one. The four redemption
routes are anonymous, because the token in the body **is** the credential.

### Social login: two routes, and neither of them takes a credential

`GET /v1/auth/oauth/{provider}` and `GET /v1/auth/oauth/{provider}/callback` are in
the table above and they are a browser round trip, not an API integration. **Both
are reachable with no credential at all** — `security: []` in
[`openapi/v1.yaml`](openapi/v1.yaml), and a caller integrating them sends no
`Authorization` header because there is nothing to send. What travels with the
request is the `__Host-oauth-state` cookie this service set on the way out, and
the `state` query parameter is compared against it **before** the code is spent.
A caller who cannot produce that cookie cannot finish the flow.

**Where the flow goes is deployment configuration, and the seven endpoint overrides
are how you change it.** Set `OAUTH_GOOGLE_AUTHORIZE_URL`, `OAUTH_GOOGLE_TOKEN_URL`,
`OAUTH_GOOGLE_USERINFO_URL` and the three `OAUTH_GITHUB_*` equivalents (plus
`OAUTH_GITHUB_EMAILS_URL`) and the whole round trip — the redirect the browser
follows, the exchange, and the identity call — runs against those addresses instead
of Google and GitHub. They are read once at startup, so they need a restart, and a
value that is present but undialable fails the boot naming the variable instead of
falling back. **A test in this repository never needed them** — it builds a
`Provider` literal — but a real process cannot build one, which is why they exist:
an end-to-end run against a fake IdP needs a real identity to aim at one.

What they are **not** is a per-request switch. There is no route, header or query
parameter that reaches them, because which endpoint this service dials is where an
outbound call carrying somebody's authorization code goes, and a caller who could
choose it would be choosing that.

Getting this wrong is the security bug rather than the documentation bug. A reader
who assumed these two rows are session-gated would invent a middleware that is not
there; a reader who assumed they are unrestricted would be describing a service
that does not exist.

Four properties a client integrating this has to know, and each is a decision
rather than an omission:

- **An address a local account already holds refuses the sign-in.** The callback
  answers `409 conflict` and mints nothing, and the caller is told to sign in
  locally instead. It does **not** silently sign into that account. This is
  Jumpstart Pro's behaviour (`elsif User.exists?(email: auth.info.email)` →
  `flash.alert` → redirect to login) and it is the anti-account-takeover rule:
  somebody who controls a provider account carrying another person's address must
  not be able to walk into it.
- **A provider address is only believed when the provider says it is verified.**
  Any path that resolves a callback to a user by email requires `email_verified`
  from the provider. Google's claim was not read while the surface was unmounted
  and it is read now; an unverified address is a suggestion, not a claim about
  identity, and one that reached a `users.email` lookup would be an account
  takeover with a login page in front of it.
- **The link path mints no session.** If the caller held a resolving session when
  they started, the callback attaches the provider identity to *that* user and
  answers `200 {linked_provider}` with no `token` field at all. Which of the three
  success shapes happened is decided by the intention recorded when the flow
  **started**, not by the session cookie the callback happens to find — a
  cross-site GET can make a signed-in browser arrive at that path.
- **Tokens from the provider are encrypted at rest** (`internal/oauth`'s
  `SocialSealer`) and expiry is judged with a 30-minute skew, so a provider token
  is never used in the minute before it dies.

Absent entirely when no provider is configured — a deployment with no OAuth client
credentials answers `404` on both paths rather than redirecting a browser to a
provider it cannot authenticate with. A provider configured with **only half** its
credentials is a **startup failure**, not a disabled provider: a "Continue with
Google" button that 404s because a secret went missing is a support call that
should have been a failed deploy.

### Recovery: one token machine, three flows

Password reset, address verification and address change are three features and one
lifecycle: mint 256 bits, store only their SHA-256, mail them, expire them, and
spend them with a conditional write that makes a second presentation a refusal. So
they are one package (`internal/recovery`) and one table with a `purpose` CHECK,
rather than three packages with three token formats and three answers to "is this
still live". A `password_reset` token presented to the verification route is a 404,
not a different error.

**The email change has two sides and the second token does not exist until the first
is redeemed.** A stolen session can start one, and what it produces is a link in the
victim's inbox and nowhere else — the attacker cannot advance it, and the victim gets
the one warning they would otherwise never get.

#### The fourth purpose: a delegated session link, and what this service does not do with it

`session_link` is a fourth `purpose` on that same table, with the same lifecycle —
mint 256 bits, store only the digest, expire, spend with the same conditional write
— and it is the only purpose **this service does not mail**. Everything above exists
because a person cannot finish the flow without an inbox; a session link has no inbox
behind it, because the caller holding `sessions:write` already has a channel to the
browser in front of the user. So there is no message body, no `Mailer.Ready` check,
and no fourth delivery path beside courier's for a message nobody asked identity to
send.

**THE CALLER OWNS DELIVERY AND LANDING, and there is no column for either.** The
`recovery_tokens` row carries no redirect, no landing URL and no project name, and
`TestASessionLinkIsOneRowOfTheMachineAndNothingElse` fails if one of those columns
appears. A row that carried a redirect would make this service an open redirector
for every caller registered against it — and "the word for any caller here is the
caller" is why this README does not name a product: the mechanism has no opinion
about who is using it.

**The window is ten minutes with a one-hour ceiling, and over the ceiling is a `422`
rather than a clamp.** The other three windows are sized around delivery and this one
is not delivered at all, so there is no mail latency to absorb. The ceiling is
published rather than configured because it is the number that decides how long a
delivered link stays live; a caller that asked for a day and received an hour has
been told a lie about a credential it is about to hand to somebody else.

**A subject with a second factor is refused at the mint, not challenged at the
redeem.** See [DECISIONS.md D12](DECISIONS.md) for why a subject that does not exist
is a `404` here and a `202` on every self-service route above.

**THE REDEMPTION IS PUBLIC, AND THE TOKEN IS THE CREDENTIAL.** No other credential is
required, a browser session in the header changes nothing, and a scoped api key is
`403` — the mint is reachable by a credential holding `sessions:write`, and one that
could both mint and redeem would take a browser session without a browser. On success
it answers **byte-for-byte what a correct password produces on `POST /v1/session`**:
the same body, the same `Set-Cookie` attributes and the same expiry, because the
handler calls `sessionResponse` and `setSessionCookie` rather than re-creating them,
and `TestTheRedeemedSessionIsByteForByteTheSessionAPasswordLoginMints` walks both
responses to say that calling them is not merely a claim.

**The mint's two refusals are REPEATED at the redemption, because they were about a
moment that has passed.** No link for an enrolled or a disabled subject exists *at mint
time*, and ten minutes is long enough for both to change inside it. A user who enrolls
in MFA after the link was minted must not redeem it: that would turn a delegated link
into a complete login for an account whose owner chose two, which is the same downgrade
the mint's `409` exists to prevent arriving through the other door. A threaded
challenge here would be a second authentication surface on an unauthenticated route,
and it is a packet of its own.

**Every refusal on that route is the shape of a link that never existed, and a refusal
spends nothing.** One `404`, one fixed sentence, for all six ways of being wrong —
including a disabled subject and an enrolled one, because those are facts about an
**account** and the token is the credential: the caller is the subject or whoever took
the link, so a `403 disabled` or a `409 second factor` would publish the account's state
to exactly the person the operator acted about. The link is left **live**, so
un-disabling or un-enrolling restores the flow the operator interrupted instead of
leaving the user with a dead link and no explanation. The `503` is the one answer that
is not that shape, because "this deployment cannot ask" is a fact about the server and
not about anybody's account.

**Delivery goes through one seam with two methods, and this repository does not
implement the delivery.** `recovery.Mailer` is `Send` and `Ready`; the second exists
so a request flow can ask whether a message *can* be delivered before it mints
anything, which is what keeps a deployment without mail from turning "503" into an
account-existence oracle. `main` wires `recovery.Unavailable{}`, which **fails** —
every path that needs to send answers `503` with a sentence saying why. That is
deliberately not a mailer that logs: a reset token in a log aggregator is a reset
token anybody who can read the logs can redeem. courier is the platform's mail
service and its delivery path is unfinished; wiring it is three lines in
`buildRecovery` (see DECISIONS.md D7).

**Email bodies carry no URL.** identity does not know the product's route shapes, so
the body carries the token, the address and the deadline, and the product builds the
link. The token is never in a subject line.

**A cooldown is not a rate limiter.** `RequestWindow` is one minute per address per
purpose, and a request inside it mints nothing, sends nothing, and answers
identically. It does not supersede a live link: a request route that invalidated one
would let anybody invalidate a victim's pending reset. It does nothing about a flood
spread across a thousand addresses and is not per-client. Per-source throttling
belongs to courier, which is in the path of every message this service sends — this
is a declared gap, not an oversight.

**A reset and an email change end sessions and OIDC access tokens, and not scoped
API keys.** Same rule and same reasoning as MFA: a key is a credential somebody
deliberately created for a script, and silently revoking one breaks a CI job with
nothing in the response saying why. Verification revokes nothing.

**Both anonymous request routes answer the same bytes for every address, and
`internal/httpapi/anonymous_enumeration_test.go` is the census that says so.** The
question behind both is "does an account exist for this address?", so a status that
differed on either would be an account-enumeration oracle to anyone posting a list of
addresses — and the route that had one is why the census exists:
`POST /v1/email-verifications` answered **409** for an address whose account had
already proved it, which on a route with no credential was a list of verified
accounts. It answers 202 now, for every address. **The fact itself is still published,
on `GET /v1/email-verification`, which requires a session** — a client that needs to
tell a user "this address is already verified" asks the route that knows who is
asking.

Two disclosures on this surface are left open deliberately and named, rather than
quietly reclassified: `POST /v1/users` answers `409` for an address that is taken
(one account per address is the unique index, and a caller registering has to be told
— see DECISIONS.md D9), and `POST /v1/session` answers `423` for a locked account,
which a stranger can reach by failing five passwords themselves. Both are pinned to
the smallest disclosure they must be by tests in the same file.

**No message is ever logged**, and `TestNoRecoveryTokenReachesTheLogs` drives all
three flows through a logger that keeps everything to prove it.

### The admin surface, and why it is a separate thing

Three operations, and the privilege boundary is one sentence:

> An account admin may revoke pending invitations to their own account and read
> that account's admin audit log — authority over other people's pending access,
> and nothing else.

It is a sentence rather than a paragraph because a role checked in thirty places
is a role that will be checked in twenty-nine of them. So the sentence is not
documentation of a boundary, it is the boundary, and the code says exactly it:
three rows in `accountRouteScopes`, two scopes, and a new row without a new scope
fails a test.

**A browser session cannot reach any of it, and a machine credential is the point
rather than a limitation.** Every action is recorded against the api key's **row
id**, so a token is something an audit record can name and a session is not. This
is the mirror image of the session-only surfaces above, and the two together mean
no route in this service is reachable by both kinds of credential unless somebody
wrote that down deliberately.

**Every action is recorded in the same transaction as the mutation.** A revocation
that commits and an audit row that does not is a revocation nobody can account
for, so `admin.Service` has no method that mutates without recording: the mutation
is a callback run inside the transaction that writes the record. Both failure
directions are tested against a real database with a trigger that raises.

**The record cannot be edited, including by the admin whose action is in it.**
`GET` is the only method mounted on that path, the store has no update or delete,
and — the one that settles it — **the table refuses `UPDATE` and `DELETE`** in the
database. A guarantee written in Go does not bind a `psql` session or a future
packet. The table also has **no foreign key to `accounts`**, so the admin surface
cannot delete its own audit log by deleting the account.

**Bulk and single do not share a shape**, because a bulk operation is where an
off-by-one becomes an outage:

| | single | bulk |
|---|---|---|
| confirmation | none — the URL names the one row | **`confirm: true`, in the body** |
| minimum | admin | **owner** |
| response | `204` | `{requested, revoked}`, and they differ |

The reasoning, the rejected alternatives and the two OIDC-shaped consequences
(the anonymous column is `403` here rather than `401`, and the authorization
matrix has no positive cell for a token-only surface) are in
[DECISIONS.md D2–D5](DECISIONS.md).

Every non-2xx is `application/problem+json` per core's error envelope, including
`404` and `405`. The `trace_id` in the body always matches the `X-Trace-Id`
response header, and internal failures are logged with that id rather than
described to the caller.

### **Every row of the table above is in a document, and that is what closed**

Until packet `identity-28`, the ten tenancy rows at the top of that table were
**served, gated, in the authorization matrix and — for seven of them — carrying a
declared scope, and written down in no document at all.** Not in
`openapi/v1.yaml`, not in `openid/openid.yaml`, and not in this table either. Two
OIDC operations were in the same position: `POST /oidc/authorize` and
`POST /oidc/userinfo` are mounted deliberately, and `openid/openid.yaml`
declared only the `GET` on each.

What that cost, in the only terms that matter: **a client generated from this
service's documents could read an account's API keys and register its OIDC
clients, and had no method at all for creating the account, inviting anybody into
it, or accepting an invitation.** We are selling hosted identity to a customer who
cannot onboard a tenant through the client we ship.

All twelve are documented now — the ten tenancy operations under a new `tenancy`
tag in `openapi/v1.yaml`, the two `POST`s beside their `GET`s in
`openid/openid.yaml` — and `openapi/v1.yaml` is at **1.7.0**. `knownDrift` in
`internal/httpapi/openapi_drift_test.go` is **empty**, pinned at empty, and the
twelve it held are named in full in **[D1](DECISIONS.md)** along with the ruling.

**Closing it changed one response shape, and it is worth knowing about.** The
`members` / `memberships` arrays on `GET /v1/accounts/:id` and
`GET /v1/accounts/:id/members` used to carry an empty `user_id` and a zero
`created_at` on every entry: `membershipResponses` filled only `role`, because
`accounts.MemberSummary` is shaped for "which accounts does this user belong to"
and carries no user. A member list nobody could tell apart, on the two operations
whose whole purpose is to be acted on by `user_id`. Nothing consumed it — those
operations were in no document, so no generated client had a method for either,
which is also why it went unnoticed — and every entry is now the membership it
claims to be. `TestEveryMemberInAMemberListIdentifiesItself` holds it.

**Adding a route is a normal operation here, and this is the second worked
example.** Packet `identity-11` added three admin operations and documented all
three, and the list stayed at twelve. Packet `identity-28` documented the
remaining twelve and the list went to zero. A packet that finds itself tempted to
add an entry is being told the truth by the tripwire — the answer is to document
the route, or to rule it out of the contract **in writing in the document and
here**, never to name it in a list.
The `/v1` routes exist only when `DATABASE_URL` is set. Without it they are
absent, so a missing database is a clear `404` rather than a pile of `500`s.

With no `DATABASE_URL`, readiness is `200 {"status":"ok","deps":"none"}` — there
is nothing to check, and saying so is more useful to an operator than an empty
list or a 200 that looks identical to a healthy probe.

Probe failures are logged with the underlying error and **never** returned to the
caller: an unauthenticated request to `/readyz` must not be a way to learn that
a database host is `10.0.0.5` or that a password was rejected.

### Multi-factor authentication

TOTP with recovery codes. The only thing MFA is for is being hostile to somebody
who has stolen a password, so every decision below is about that.

**A correct password does not mint a session.** `POST /v1/session` answers **202**
for an account with a second factor and **200** for one without:

```
POST /v1/session {"email","password"}
  → 200 {"token","expires_at"}                  no second factor; here is your session
  → 202 {"mfa_required":true,"challenge","expires_at"}   one is required

POST /v1/session/mfa {"challenge","code"}
  → 200 {"token","expires_at"}
```

The `202` body has **no `token` key at all**, not an empty one, and no session
cookie is set. `POST /v1/session/mfa` is the only route in this service that turns
a second factor into a session, and it mints the session inside the same
transaction that consumes the challenge — so a challenge cannot be answered twice
and a code cannot buy two sessions.

The challenge travels in **the cookie or the body**, and both are supported on
purpose: core's conventions say "no cookies for API traffic" and
`POST /v1/session` already returns the token in the body as well as the cookie, so
a second step that read the challenge only from a cookie would leave every
non-browser client unable to finish a two-factor login.

#### Enrolling

Four requests, and the middle one is the point.

1. `GET /v1/mfa` — is there already a second factor, and how many recovery codes
   are left? The count is here so a client can say "2 left — print a new set"
   while there are still two.
2. `POST /v1/mfa/enrollments` — generates a secret and stores it **unconfirmed**,
   returning the base32 `secret` and an `otpauth://` `provisioning_uri`. Neither is
   ever returned again: a user who loses them starts a new enrollment, which mints
   a new secret. The enrollment expires in ten minutes and is **not MFA** — the
   login path reads only confirmed rows, which is what makes "stored but never
   confirmed" mean "authenticates nothing".
3. `POST /v1/mfa/enrollments/{id}/confirm {"code"}` — proves you can produce a
   code. This makes MFA live, issues ten recovery codes (returned once, and there is
   no endpoint that re-reads them), emits `identity.mfa.enabled`, and **revokes
   every session the user holds**, including the one this was done from.
4. Done. Every later `POST /v1/session` answers 202 until a code is presented.

**Why enabling revokes every session.** A session minted under a one-factor policy
was minted on a password alone. Leaving it alive after the user opts into a second
factor means the attacker holding it does not have to solve the new problem at all.
It costs the user every other device they were signed in on, and that is the price
of the change meaning something. Disabling revokes every session for the mirror
reason: a user who turns MFA off has very often had it turned off *for* them.

#### Replacing the secret

`POST /v1/mfa/enrollments` on an account that already has a credential starts a
**rotation**, and it takes a second factor. The old secret stays **live until the
replacement is confirmed**, so an abandoned rotation costs nothing; on confirmation
the old credential is deleted, its recovery codes go with it, and both
`identity.mfa.enabled` events fire — a rotation is a genuine change, and a consumer
that only heard about the first enrollment would be holding a stale picture.

#### Disabling

`DELETE /v1/mfa {"code"}` requires a second factor. A password is not accepted and
there is no path through this service that would let one be. A recovery code works,
which is the escape hatch a user with a lost phone needs and the reason recovery
codes exist.

#### The skew window

**One step either side**, so a TOTP code is live for **90 seconds** rather than 30.

Zero skew would be tighter and is wrong in practice: it refuses any code typed in
the seconds either side of a step boundary, which is exactly when a user is most
likely to be reading digits off a screen — and the users it refuses are the ones
with the worst network and the least accurate autocorrect. A second factor with a
visible failure rate does not get retried; it gets turned off, and a user with MFA
off is worse off than a user with MFA and a support ticket.

Two steps or more is the other error, and it is the one RFC 6238's implementers
drift towards. Every step of skew is thirty more seconds during which a phished or
shoulder-surfed code still works, and one more six-digit value an attacker gets to
guess. The window is the *only* thing that grows with skew, so it is held at the
smallest value that tolerates real drift.

What one step does not buy is worth stating rather than hiding: it tolerates up to
**thirty seconds of clock drift in either direction and no more**. A phone
forty-five seconds fast spends half of every period showing a code two steps ahead,
and that code is refused — a fifteen-second wait, every thirty seconds, for that
phone. No skew value fixes it without a window wide enough to be a security
decision rather than a tolerance. What makes the ninety seconds survivable is the
replay guard: a captured code is good for **exactly one use**, however long it
stays inside the window.

#### Replay, and why the guard is a set

The standard attack against TOTP is a photograph of the code and a race to use it,
and it is the thing most implementations get wrong. This service remembers the
**exact steps consumed**, in a table whose primary key is
`(credential_id, step)`:

- It refuses a step that was **spent** and accepts one that was **not**, in any
  order. A single "highest step accepted" bigint cannot make that distinction: below
  its mark it does not know whether a step was spent or merely old, so it refuses
  correct codes whenever a phone's clock is corrected backwards, a user switches to
  a backup authenticator that is behind, or a device re-syncs time mid-window.
- It is atomic without a lock. `INSERT … ON CONFLICT DO NOTHING` is one statement,
  so fifty requests carrying the same code resolve to one winner and forty-nine
  refusals with nothing to roll back.
- It is bounded. Every acceptance prunes the steps below the window in the same
  transaction, so the table is the size of the enrolled population rather than the
  size of the login history.

The cost of claiming the step *before* the session exists is stated where it is
paid, in `mfa.VerifyFactor`: a database failure between the claim and the session
write leaves the step spent and the user waiting thirty seconds for the next code.
The alternative — claiming only inside the session's transaction — means a replayed
code never reaches the failure counter at all, because the claim and the refusal
would roll back together, and a code that cannot be counted is one an attacker may
present without limit.

#### A disabled account, and how it is not a locked one

`users.disabled_at` is the one state on this table a **person** decides. Null is
active; there is no `false`, no counter, and no expiry.

**It is not `locked_until`, and the difference is not a degree.** A lockout is
automatic, temporary, and ends by itself: five consecutive wrong passwords buy
fifteen minutes and then the account is usable again with nobody involved.
`disabled_at` is deliberate, indefinite, and set by somebody who could equally have
deleted the row. Reading one as the other is how a "disable" ends up lifting itself
after a quarter of an hour because it was implemented as a lockout with a longer
expiry — so the two never share a status, a response, or a sentence. A locked
account is `423 account_locked` with a `Retry-After`; **a disabled one is `403
forbidden` with no `Retry-After` at all**, because it is not coming back at any time
and a client that believed a countdown would poll a route whose answer cannot
change. The whole ruling is [DECISIONS.md D13](DECISIONS.md).

Three properties, each with a test:

- **Every door refuses, and the password door is where the decision is anchored.**
  `POST /v1/session` checks it **after** the password verifies, so the honest answer
  is free: a caller told "this account is disabled" has already proved they hold the
  credential and therefore already knew the account existed. Move that check above
  the password and it becomes a one-request existence oracle — strictly worse than
  the 423 on the same route, which is checked *before* the password and is measured
  in D9. A wrong password on a disabled account is still the generic `401`.
  `internal/auth`'s check lives in `startLogin` rather than in `Login`, because the
  social callback resolves to a local user and arrives at the same place with no
  password in the request — a check written in `Login` would have left that door
  open, and the way that defect stays invisible is that a social sign-in for a
  disabled account works.
- **Disabling ends live sessions in the same transaction that writes the column.**
  There is no sweeper and no grace window to reason about: the `sessions` rows are
  deleted, so a request already in flight dies at its next store read and a token
  that used to work misses for a reason the caller cannot tell from one that never
  existed. `Authenticate` needs no check of its own *because* the rows are gone —
  which is why revocation is `DELETE` and not a flag.
- **Recovery is not the way back in.** It is the one flow that exists to let a
  locked-out user recover, so it is the one that must not work past somebody's
  decision. Minting refuses **silently** — a disabled account is sent nothing and
  the response is byte-identical to an unregistered address's, because those routes
  are anonymous and any difference would publish a list of disabled accounts to
  anyone posting a list of addresses. Redemption refuses with the **404 a
  nonexistent token gets**: the token in the body *is* the credential, so the caller
  may be whoever took the link, and telling them why would publish the account's
  state to exactly the person the operator acted about. The owner's next stop is the
  login, which tells them the truth.

#### An unverified address, and the operator's choice

`users.email_verified_at` records that somebody proved they can read the address on
the account. **Nothing in v0 requires it for sign-in, and that is parity rather than
a gap**: the reference this fleet matches (Jumpstart Pro) uses `has_secure_password`
and does not use Devise's `:confirmable`, so an unverified address can sign in
there. Gating sign-in on verification would be a deviation from the thing the fleet
exists to match.

So the choice is the operator's, and it is one variable: **`REQUIRE_EMAIL_VERIFICATION`**
(default `false`). When it is `true`, `POST /v1/session` refuses an unverified
account with **`403 email_not_verified`** — its own code, sharing neither the
lockout's `423` nor its sentence, because the two have different remedies: a locked
account retries at a time, an unverified one clicks a link.

The refusal is anchored **after the password verifies**, exactly as the disabled
check above is, and for the same reason: a caller told "this account's email
address is not verified" has already proved they hold the credential and already
knew the account existed, so the answer reveals nothing a stranger did not earn.
The check lives in `startLogin` rather than `Login` so the social callback — which
arrives with no password — passes through the same line. A wrong password on an
unverified account is still the generic `401`, whatever the flag says.

The risk the flag exists to let an operator close: **an address nobody has proved
can hold a session.** A deployment that sells to a regulated market, or has been
through an incident, sets one variable and gets a documented, tested gate. Nobody
who does not set it sees any change.

**There is an operator, and it is deliberately not the admin surface.**
`POST /v1/users/:userId/disable` and `/enable` are reachable by a **scoped api key
holding `users:disable`** and by nothing else. `internal/admin` is **account**-scoped
— its audit rows carry an `account_id`, its privilege boundary is one sentence about
account admins and invitations — and a user is not an account, so mounting this there
would have meant inventing a tenancy for an action whose subject is a person. The
obvious invention, "the caller's own account", is the defect: a user who belongs to
ten tenants would grant tenant one the power to reach the employee tenant two also
employs, ten times over. So there is **no account in the path, no role minimum, and
no route under `/v1/accounts/…` that consults `users:disable` at all** — an
account-scoped credential is refused on these routes whatever its role and whatever
else it holds, and that refusal is the boundary rather than a gap in it. A browser
session is refused too: an operator is a deployment fact, not a login, and the
subject here is a person, so a session would be an account turning itself off or on.
The whole decision is [DECISIONS.md D14](DECISIONS.md).

Re-enabling ships, because an irreversible disable is a different feature with a
different name. It restores the column and nothing else: **the sessions the disable
ended do not come back**, since they were minted before the account was turned off,
and the owner signs in again. A refused recovery redemption does not spend its
token either, so a link already in an inbox still works once the disable is lifted —
an operator who turns an account off did not also decide to invalidate the mail.

The `POST /v1/session-links` mint refuses a disabled subject with **403** rather
than the `404` an unknown subject gets: that route is behind a scoped api key, so
the caller is an operator, and a `404` would send them looking for a user id that
is not missing. Its *redemption* does not exist yet — that is the next packet, and
the answer it must use is named at its definition in
`internal/recovery/session_link.go`.

#### The staff console is a human surface, and the machine one is untouched

`GET /v1/operator/me`, `GET /v1/operator/users`, and
`POST /v1/operator/users/:userId/disable|enable` are the Parlor operator
console's contract: a signed-in **staff** human's session, and nothing else. A
scoped api key is `403` on all four, exactly as a session is `403` on the
machine operator routes — the two credentials do not cross, so the
`user_audit_log` row can always say whether a person or a pipeline acted. A
staff disable runs the same transaction as a machine one; its audit row names
the staff user's id and no api key. No account role reaches these routes: staff
is a property of the user (`users.is_staff`, default false), not of a
membership, and the whole revision is [DECISIONS.md D19](DECISIONS.md).

Staff is **granted by an operator, never by the service itself**. There is no
bootstrap route, no default staff account and no grant button: the only writer
of the column is the `identity-staff` command, which ships in the SAME image
as the service (`/app/identity-staff`, built beside `/app/service` — never the
entrypoint) and runs as a one-shot Job with an overridden command:

```yaml
# One-shot k3s Job (Argo/substrate): the same image the Deployment runs,
# with the command overridden. No shell, no new service, no HTTP involved.
apiVersion: batch/v1
kind: Job
metadata:
  name: identity-staff-grant
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: identity-staff
          image: "<the same image:tag the Deployment runs>"
          command: ["/app/identity-staff"]
          args: ["grant", "kaka@example.com"]
          envFrom:
            # The exact existing secret the Deployment reads
            # (chart `secretName`, default `identity-secrets`), which already
            # carries the `DATABASE_URL` key the service boots with.
            - secretRef:
                name: identity-secrets
```

The command needs what the service needs and nothing else: `DATABASE_URL`
with write access to the `users` table, and no HTTP surface at all. Granting
is idempotent, revoking takes effect on the next request (the gate reads the
row every time), and an unknown address is an error naming the address rather
than a row. Locally, the same binary runs from source:

```sh
DATABASE_URL="postgres://…" go run ./cmd/identity-staff grant kaka@example.com
DATABASE_URL="postgres://…" go run ./cmd/identity-staff revoke kaka@example.com
DATABASE_URL="postgres://…" go run ./cmd/identity-staff status kaka@example.com
```

Keep the existing machine-key operator endpoints working for automation; the
human path is intentionally separate.

#### The lockout is per-factor

`mfa_credentials.failed_attempts` is the second factor's counter.
`users.failed_login_attempts` is the password's. They are separate rows, and that
separation is the property: **five TOTP guesses have not spent five password
guesses, and five wrong passwords have not moved the second factor's.** Both run
`sessions.Lockout`'s arithmetic — one implementation, two counters — because a
second implementation in `internal/mfa` would be a second place for the thresholds
to drift, and the drift would be invisible until a user was locked out for the
wrong number of minutes.

Both are five attempts and fifteen minutes, deliberately the same numbers: a user
who mistypes three times should not be punished differently depending on which
field they got wrong. What differs is the counter. The second factor's lockout is
`423 account_locked` with `Retry-After`, exactly as the password's is.

One honest interaction: the challenge lives ten minutes and the lock lasts fifteen,
so a user who trips the lockout waits longer than their challenge lives and has to
start the login again. The alternative — a challenge TTL longer than the lockout —
would mean holding a permission to finish a sign-in for a quarter of an hour.

#### What is stored, and what a database dump yields

| Column | Stored | A dump alone yields |
|---|---|---|
| `mfa_credentials.secret_ciphertext` | AES-256-GCM under `MFA_ENCRYPTION_KEY`, with the user id as AAD, `v1`-prefixed base64url | Nothing presentable. The key is in the environment, not in the row. |
| `mfa_recovery_codes.code_digest` | SHA-256 of an 80-bit `crypto/rand` value | Nothing. 2⁸⁰ candidates is not a computation. |
| `mfa_challenges.token_digest` | `sessions.Digest` — SHA-256 of a 256-bit token | Nothing. Same construction as every other credential column here. |

**There is no column in this schema that holds a working second factor**, and
`TestADatabaseDumpYieldsNoWorkingSecondFactor` is the test that says so over a real
Postgres rather than in a comment.

**Why the TOTP secret is encrypted and not hashed.** Every other credential column
in this service is a one-way function of the presented value, and a TOTP secret is
the exception. The authenticator computes `HMAC(secret, counter)` and so does this
service, so the secret has to be **recovered**, not verified: a digest of it would
verify against nothing, exactly as a digest of a password is useless when the
protocol asks for the password itself. Encryption is the only transformation that
satisfies both halves.

**The trade-off, stated because it is the cost of that choice.** Encryption is
recoverable by anyone holding the key, so the boundary is the key and not the row.
A hash has no such boundary — it is one-way forever. What this service gives up is
the ability to survive losing `MFA_ENCRYPTION_KEY`: on a lost key every sealed
secret is unreadable, every enrolled user fails **closed** at their second factor,
and the only way back is a recovery code or a support ticket. That is a real
operational cost, and it is why the key belongs in the same secret store as
`OIDC_SIGNING_KEY` and is **never generated at boot** — a generated key would mean
every restart invalidates every enrolled user's secret, and a restart is not
something anybody decides to do. `MFAEncryptionKeyConfigured` and
`ErrNoMFAEncryptionKey` keep the absent case a supported state rather than a
silent one.

**Why recovery codes are SHA-256 and not argon2id.** Eighty bits of `crypto/rand`
has no structure to guess, so a memory-hard hash would buy nothing the entropy has
not already bought and would cost tens of milliseconds on every sign-in that
reaches for it. Argon2id exists to make **guessing** expensive and there is nothing
here to guess. Eighty bits is a **floor**: a six-digit recovery code hashed with
SHA-256 would be walked in microseconds, and the dump would be a set of working
second factors.

#### Configuring it

`MFA_ENCRYPTION_KEY` is base64url, **exactly 32 bytes**, read from the environment.
Present-but-unreadable is a startup failure and not a warning, because an operator
who pasted a 16-byte key believes they have 128 bits of entropy protecting every
second factor on the platform.

Absent is a supported state, and it degrades in **one direction only**:

- The management routes (`/v1/mfa` and everything under it) are **absent** — a
  `404`. A user must not be talked into enrolling a factor this process could not
  later verify.
- `POST /v1/session/mfa` is **still mounted**, because it needs no key: deciding
  that an account has a second factor is a query on a boolean column. A user who
  enrolled elsewhere is refused at their second factor rather than being let in on
  their password, and the absence of the management routes says nothing about
  whether this one exists.

A third outcome — a user with MFA trying to disable it on a keyless deployment —
gets `503 service_unavailable` with a sentence saying what is wrong, because a user
told only "try later" retries forever and an operator told `internal` goes looking
for a database problem that is not there.

#### What is NOT built

No **"trust this device"** cookie and no re-authentication grace period. A trusted
device is a real feature and a real attack surface — it is a bearer token with no
expiry and no second factor behind it — and it belongs in its own packet with the
trade-off written down. Until then, every sign-in needs both factors.

### Scoped API tokens

The credential that is **not** a browser session. For a script, a CI job, or
another service.

There are three credentials here and they are not interchangeable, because their
failure modes are genuinely different. A session is browser-shaped and dies in
weeks. An OIDC access token is a JWT for a *third party holding a browser*,
verifiable against the published JWKS with no call back here. A scoped API token is
a first-party machine credential: opaque, long-lived, revocable, and carrying a
scope set. Routing one through another's machinery would give each of them the
wrong properties — a JWT cannot be revoked before its `exp` arrives, and a session
cannot carry a scope set an operator curated.

**The wire format** is `cafaye_` plus 43 base64url characters:

```
cafaye_Zq3vK7mXpR2tY8wB4cN6dF0gH1jK5lM9oP3qS7uV2wX4yZ8
└──────┘└──────────────────────────────────────────────────┘
  7              43 characters of 32 bytes of crypto/rand
```

The prefix is a feature and the feature is **recognition**. A secret that leaks
into a CI log, a shell history, a support ticket or a paste buffer is recognised
as a cafaye credential by its first seven characters, which turns "somebody has to
work out which of these strings is working" into a `grep`. It is the prefix rather
than a marker in the middle because a scanner — and a truncated log line — looks at
the first bytes.

The same prefix is the **discriminator** at the door: a session token is looked up
in `sessions` and an api key in `api_keys`, and the shape decides which table is
touched before any query runs. A value of the wrong kind is never looked up in the
wrong place, so "is this token live" cannot be answered by the response time of the
wrong index.

**What is stored** is the SHA-256 of the presented value and nothing else. The
plaintext exists once, in the `201`. Not argon2id, and the reasoning is
`internal/sessions/token.go`'s with the difference this credential's lifetime makes:
a slow hash would cost every authenticated machine request tens of milliseconds
across the platform, and what it buys is nothing — 256 bits of `crypto/rand` has
no structure to guess. The hash is a **deterministic** function because the lookup
is "hash what was presented and find the row", and a salted password hash cannot be
looked up at all.

#### A token carries a scope set, not a role

**This is the property worth reading twice.** A token names a user and an account.
Its authority is re-evaluated on **every request** against that user's *current*
membership, so:

- **removing somebody from an account stops their tokens on the next request**,
  with no cache to expire and nothing to sweep;
- **a demotion takes effect immediately** — the route's 403 appears on the request
  after it, and only on the routes the new role cannot reach;
- **re-inviting them does not bring the tokens back.** The removal also revoked
  what they held, in the same transaction, because re-evaluation alone was not
  enough: the same person re-invited at the same role satisfies the membership join
  again, and a contractor's CI credential that died at offboarding would quietly
  start working the day somebody re-added them. That is a bug this service's own
  test found and the assertion to read is the *last* one in
  `TestARemovedMembershipStopsTheTokenOnTheNextRequest`.

The difference between a credential and a permission is exactly this. A token
stores no role, so there is no stored role to go stale.

#### The scope vocabulary

Eight names, a closed set, and every one of them is a capability an existing route
already enforces a different way. That is the test of a real scope: removing it
removes access to something that exists. The shape is core's
(`resource:action`, from `docs/openapi-conventions.md`'s `invoices:write`), and
`darkroom` already publishes `assets:read` / `assets:write` in the same form.

| Scope | Routes it is enforced on |
|---|---|
| `accounts:read` | `GET /v1/accounts/:id`, `GET /v1/accounts/:id/members` |
| `accounts:write` | `PATCH /v1/accounts/:id`, `POST /v1/accounts/:id/invitations`, `PATCH` and `DELETE /v1/accounts/:id/members/:userId`, `POST /v1/accounts/:id/ownership-transfers` |
| `accounts:delete` | `DELETE /v1/accounts/:id`, and nothing else |
| `oidc_clients:write` | all four `/v1/accounts/:id/oidc-clients` routes |
| `audit_log:read` | `GET /v1/accounts/:id/admin/audit-log` |
| `account_invitations:write` | `DELETE /v1/accounts/:id/admin/invitations/:invitationId`, `POST /v1/accounts/:id/admin/invitation-revocations` |
| `sessions:write` | `POST /v1/session-links` — **the only scope whose route turns an opaque value into an authenticated browser session** |
| `users:disable` | `POST /v1/users/:userId/disable`, `POST /v1/users/:userId/enable` — **the only scope with no account behind it**, and no account route consults it |

**Where the vocabulary came from:** `openapi/v1.yaml` and the route table, read
rather than invented. `accounts:delete` is separate from `accounts:write` because
it is the only one of them that cannot be undone, and because its route's minimum
is `owner` where everything else is `admin` — a token carrying `accounts:write`
and held by somebody who later becomes a member is already refused on the role
check, so the extra scope is for the owner case, where the role gate alone would
let it through. `oidc_clients:read` does not exist: both `GET`s are owner-only
routes whose response *is* the integration's configuration, so a separate read
scope would be a name nobody in this service has a use for.

**What is deliberately absent, and every absence is a refusal rather than an
oversight:**

- **no scope for the second factor.** A token cannot read whether an account has
  MFA, enrol one, rotate one or turn one off. A machine credential that could
  disable a second factor is a credential whose theft is a *downgrade* rather than
  a break-in, so the routes refuse a token outright rather than consulting a list.
- **no scope for SESSIONS — and this is the sentence `sessions:write` changed, so it
  is worth reading rather than inheriting.** A token still cannot create, read or
  revoke a browser session, and it still cannot complete a second-factor login; the
  session routes refuse a token outright and no scope changes that. What
  `sessions:write` buys is **minting a link**: a single-use token worth ten minutes
  that a *caller* delivers to a browser and that redeems into a session for the
  subject it names. A link is not a session — possession of one is not proof of
  anything, it is a delegation somebody chose to make over a channel they already
  own — but it is the closest this vocabulary comes to an authentication
  credential, which is why it is granted deliberately, why a mint for an
  MFA-enrolled subject is refused rather than served with a challenge, and why the
  redemption route is public. There is no `sessions:read` and there will not be one:
  a link is minted and handed over, so there is nothing to list.
- **no scope for the api keys themselves.** A credential that can mint more
  credentials is a privilege-escalation path with a nice UI.
- **no scope that means "everything."** Not `*`, not `accounts:*`, not one named
  `admin`. "Read this account" and "delete this account" are two decisions a person
  makes twice.
- **no scope for the account *collection* routes.** `GET /v1/accounts` answers
  "which accounts does this **user** belong to", and a token is bound to one
  account. A CI job holding a credential for one tenant is not entitled to an
  inventory of every other tenant its owner is in.

**And the one scope that is not bounded by an account, which is the rule above with
its limit rather than an exception to it.** Every other scope here can only be used
against the account the token was minted for — core's "every query is scoped by
`account_id` from the token". `users:disable` names **no account at all**, because a
user is not an account: the same person belongs to as many accounts as they like,
so there is no single account whose tenancy would mean "the accounts this token may
act on" for an action whose subject is the person rather than one of their
memberships. A token holding it may name **any** user on the deployment, so it is
minted per deployment, deliberately, and it is revocable on its next request like any
other. What the tenancy rule buys is that a token cannot reach *across* tenants with
the scopes it was issued; this one reaches across tenants **by being granted it on
purpose**. See [DECISIONS.md D14](DECISIONS.md).

**A session carries no scopes and is not refused for that.** A session is a human's
credential with the full authority of its role; a token is a narrowed one. That
asymmetry is the whole difference between the two, and it is why the scope check is
skipped for a session rather than failing it.

A route with **no declared scope is closed to tokens** — `Allows("")` is false for
every granted set — so a new account route added by a later packet is unreachable
by a machine credential on the day it lands, not on the day somebody notices it was
never gated. `TestEveryAccountRouteDeclaresItsScope` and
`TestEveryScopeIsEnforcedOnItsRoutes` walk the router in both directions.

#### Expiry

**Optional, with a default, and a ceiling.** Omit `expires_in` and the credential
lives **90 days**. Ask for more and the ceiling is **365**. Ask for `0` or a
negative number and you get a `422`, because that is where "never expires" would
have gone and it is not something this build offers.

The 90 is a judgement about two failure modes rather than a round number: long
enough that a CI job somebody set up in a hurry does not fail on a Tuesday three
months later, and short enough that "we rotated our tokens" happens without anybody
having to decide to make it happen. A permanent credential has no such moment, and
that is the whole of the decision.

**What it costs, stated because it is real:** a CI credential has to be replaced
every quarter, and that is friction on precisely the use case that motivates the
feature. What it buys is a moment at which a credential nobody is using gets
noticed — and `last_used_at` is how that moment is acted on rather than guessed at.
Rotation is two requests, not a maintenance window: revoke, then mint. Mint the new
one first if you cannot afford the gap, and revoke the old one when it works.

`last_used_at` is accurate to within **five minutes**, deliberately. A CI token at a
thousand requests a second must not put a thousand `UPDATE`s a second on one row,
and a single row's lock is a queue. The write is conditional on the stored value
being stale, so there is no read-modify-write and zero rows updated is a success.

#### One-time display

`token` is in the `201` body and **nowhere else, ever**. Not in the list, not in a
single-token read, not in the introspection response, not in the log, not in the
event payload. A caller that loses it mints another.

`TestTheSecretIsOnTheWireOnceAndNowhereElse` asserts it on the wire, and then
searches at rest: the whole row as JSON, the whole table, and every event payload
in the outbox, for the plaintext, for the plaintext without its prefix, and for its
digest. The digest has to be *found* in that search, or the test would pass on a
table that stored nothing at all.

There is no "reveal" endpoint, and there is no "rotate" endpoint either — changing
a token's authority means minting a new one, which means a new secret and a revoked
old one, so "change the scopes" is exactly "rotate" spelled two ways and a second
spelling is a second way to get the security property wrong.

#### Refusals are all the same refusal

Unknown, revoked, expired, and one whose owner has been removed from the account
are all **401** with the same body. `TestEveryRefusalIsTheSameResponse` also
covers the things a machine will present at this endpoint by accident — a session
token, a JWT, a truncated paste, the digest itself, binary noise — and asserts the
`type`, `title`, `status`, `code` and `detail` are identical across all of them.

**The timing story is structural rather than a promise about
`subtle.ConstantTimeCompare`.** The store never sees the presented value: `Digest`
turns *anything* into a well-formed 64-character hex string, and the query is an
ordinary indexed equality on that. So there is no length comparison anywhere on the
path for an early return to skip, and no function whose runtime reveals how much of a
guess was right. A constant-time compare is what you reach for when a stored secret
is compared byte by byte, and nothing here does that.

#### Introspection, and the two claim names

A token is opaque: it has no claims inside it and there is no published key set to
verify it against. So `POST /v1/introspections` is how a resource server learns
what a token may do. The response is RFC 7662's shape, and the path is under `/v1`
because core's rule says every path in this document is — if core fixes an
introspection path, that is the row to change.

An unusable token answers **`200 {"active": false}`** and nothing else. The status
is 200 rather than 404 because the endpoint succeeded; the answer is that the token
is not active. Unknown, revoked, expired and orphaned are indistinguishable, which
is the whole point: a caller who can tell them apart learns whether a leaked value
was live.

The caller's *own* standing is a different question with different statuses, because
it is a different fact about the request: `401` with no credential, `403` for a
token asking about somebody else's. A token may introspect **itself** — the case a
CI job needs when it wants to know why it is being refused — and a session may read
a token in an account it owns.

> **The capability set is emitted TWICE, as `scopes` and as `scope`, byte for byte
> identical.** That is a deliberate interim and it is not this service's contract.
> core's `docs/openapi-conventions.md:134` requires a claim named `scopes`;
> `gateway/src/middleware/jwt.ts:32` reads `scope`, splits it on whitespace, and
> treats an absent claim as an empty set. The fleet has not agreed, the question is
> open as **MD7**, and picking a side here would mean rotating every credential
> already in a customer's hand. Emitting both means whichever name wins, the other
> is a one-line removal from `internal/apikeys/claims.go` and **nothing has to be
> reissued**. Two names is not a contract.
>
> The shape is a space-separated **string**, not an array: that is the one shape
> both sides can read. gateway's verifier does `raw.split(/\s+/)` and refuses a
> non-string claim, so an array is a token the gateway will not parse at all.

**`account_id` is required and there is no `sub` fallback.** `sub` is the **user**
the token names; `account_id` is the tenancy boundary and it is always present. A
token with no account cannot be used against any account, so it is answered
`{"active": false}` rather than issued a subject to guess a tenancy key from. The
alternative — falling back to `sub`, as gateway's `limitKey` does today — would give a
service-to-service token a *user* as its tenancy key, and a bug in one service that
keys on `sub` becomes a cross-tenant read rather than a `403`. Whether gateway's
fallback is safe is **MD8** and is not decided here; what is decided here is that
identity never produces a token that needs it.

### The OpenID Connect provider

`identity` is a first-class OIDC **provider**, so any product signs users in
against cafaye itself rather than configuring Google OAuth per product — and the
JWT verification every other cafaye service already does against identity's JWKS
becomes a standard, interoperable surface.

These routes exist only when the four `OIDC_*` variables above are all set AND
`DATABASE_URL` is set. Without them they are absent, so the failure is a clear
`404` rather than a pile of `500`s.

| Route | Response | Meaning |
|---|---|---|
| `GET /.well-known/openid-configuration` | `200` | OpenID Connect Discovery. |
| `GET /.well-known/oauth-authorization-server` | `200` | RFC 8414. The same document; the library does not register it, identity does. |
| `GET /.well-known/jwks.json` | `200 {"keys":[…]}` | RFC 7517. One key, `use: sig`, `alg: RS256`. Public half only. |
| `GET,POST /oidc/authorize` | `302` | The authorization endpoint. Requires PKCE with `S256`. `redirect_uri` matched **exactly**. |
| `GET /oidc/authorize/callback` | `302` | The sign-in interaction's return leg. Mints the code. |
| `GET,POST /oidc/login/:requestId` | `302` | The sign-in interaction. **This service renders nothing**: the GET redirects to `OIDC_LOGIN_UI_URL` and the POST completes or redirects back. Sessions, cookie and password check all stay here. |
| `POST /oidc/token` | `200 {access_token, id_token, …}` | `grant_type=authorization_code` and nothing else. HTTP Basic client auth. |
| `GET,POST /oidc/userinfo` | `200 {sub, email, …}` | The claims the token was granted, and only those. |
| `/oidc/introspect`, `/oidc/revoke`, `/oidc/end-session`, `/oidc/device_authorization` | `404 not_found` | Not built, on any method — the row carries no method because there is nothing behind it to answer one. Absent from the discovery document too. |

**TWO ERROR SHAPES, AND THE SPLIT IS DELIBERATE.** `/v1/*` and the
`/oidc/authorize` pre-checks answer `application/problem+json`; everything else
under `/oidc/*` answers RFC 6749's `{"error": …}`. An off-the-shelf OIDC client
library cannot parse a problem document, and interop with one is the entire
point of the surface. The two documents that describe the two — `openapi/v1.yaml`
and `openid/openid.yaml` — exist for the same reason.

The claims:

- `sub` — the user. The same for every client.
- `email`, `email_verified` — on the `email` scope. **`email_verified` is always
  `false`**: this service has no email-verification column yet, so there is
  nothing it could prove, and `true` would be a claim about something nobody has
  checked. It is present and false rather than absent, because a relying party
  that cannot see the field has to assume it is verified.
- `name` — on the `profile` scope. The personal account's name, derived from the
  email's local part. A stand-in, not a user-chosen name.
- `accounts` — on the `accounts` scope. An **array** of `{account_id, name, slug,
  role, personal}`. An array and not a single `account_id` because a user of a
  cafaye product is in a personal account and usually several team accounts, and a
  token carrying one of them would be wrong for the others. core's conventions ask
  for `account_id`; this is the multi-account form of that fact.
- `scope` — the capability scopes, space-delimited. `email` and `profile` are
  userinfo scopes and live in the ID token and at userinfo instead; an address is
  not a capability.

Two decisions the manager may want to rule on, both recorded in the code:

- The `scope` claim is spelled `scope`, not `scopes`. RFC 9068 registers that
  name and `gateway`'s verifier splits on exactly that string; core's prose says
  `scopes`. One line in `internal/oidc/storage.go` either way.
- An unknown scope at `/oidc/authorize` is **400** with a problem envelope, as
  the packet specifies. core scopes 400 to "malformed syntax the client could not
  have known" and 422 to "semantically wrong", so this is a deliberate departure
  and it is listed under "Known gaps" in `openid/openid.yaml`.

### The sign-in interaction, and the login UI

**`identity` renders no HTML.** There is no view, no template and no page; the
form a person fills in is served by `parlor` and its address is
`OIDC_LOGIN_UI_URL`. The whole of the browser-facing frontend this service used to
have was one `html/template` literal of about thirty lines, and this is the
decision that removed it — the reasoning, and the two properties that had to be
kept while removing it, are in `DECISIONS.md` **D10** and in
`internal/oidc/loginui.go`.

The flow is four moves and two of them are redirects:

```
GET  /oidc/authorize            302 -> /oidc/login/{request_id}   (this service)
GET  /oidc/login/{request_id}   302 -> <OIDC_LOGIN_UI_URL>?…      (the login UI)
POST /oidc/login/{request_id}   302 -> <redirect_uri>?code=…      (this service)
                                 …or 302 back to the login UI carrying the refusal
```

**Why the extra hop rather than sending the browser straight from `/oidc/authorize`
to the login UI.** Every question on that second hop is a question about a
credential — is this browser signed in, did *it* start this flow, is this password
correct, may an authorization code be minted — and an authorization decision made
by a page on another origin is not one this service made. The hop costs one round
trip and buys three things: no CORS anywhere (identity sends no CORS headers, and
that is not negotiable), no credential crossing an origin boundary, and one place
where "may this browser authenticate this request" is decided. The silent path —
a user who already has a session going straight through with a code — is on that
hop, and so is the login-CSRF refusal that guards it.

**A deployment with an issuer and a key and no login UI refuses to start.** A
provider that cannot send a browser anywhere to authenticate is a provider that
publishes a working discovery document and cannot complete a single flow, which
is worse than not being a provider because the failure is found by a user rather
than by an operator.

**What travels to the login UI.** `request_id`, `state` and `step` are always
present; `client_name`, `login_hint`, `error`, `error_detail` and `retry_after`
appear when they have something to say. **An absent `error` and an empty one are
different** — a login UI that switches on `error` must not show a failure banner
on a sign-in that is going fine. `client_name` is a row an account owner typed and
`login_hint` is a string the client chose, so **both are untrusted text and the
login UI must escape them**; that was a real attack when the page was here and it
is still a real attack, one repository over.

`error` is the contract and `error_detail` is a sentence for a person — the same
split the problem envelope makes between `code` and `detail`. The codes are
`interaction_expired`, `missing_credentials`, `invalid_credentials`,
`challenge_rejected` and `account_locked`, and the last is the same word the JSON
surface uses for the same lockout on purpose.

**What comes back.** `POST /oidc/login/{request_id}`, form-encoded, with
`{state, email, password}` on the first step and `{state, code}` on the second.
That is a top-level **cross-site** POST, so the state and MFA-challenge cookies
are `SameSite=None; Secure` for the duration of the interaction. That is a
transport change and not a weakening: both cookies are `HttpOnly` and
`__Host-`-prefixed, so the login UI's origin can neither read nor forge them, and
the CSRF property is the unguessable value in a cookie the other origin cannot
read — which is unchanged. Under `Lax` the flow would simply not work. The flow
cookie and the session cookie stay `Lax`; nothing a login UI does needs them to be.

**A refusal a login UI could render is a redirect, not a status.** A wrong
password, an empty form, a refused code and a lockout all answer `302` back to the
login UI with the reason, on whichever step it belongs to, with a **fresh** `state`
so the form can be submitted again. The three that cannot be re-shown are problem
documents: a request id that does not exist (nothing to render, nothing to post
back), a body that will not parse, a signed-in browser with no flow cookie (the
login-CSRF refusal, which says "this sign-in was not started here"), and a server
error, which has a `trace_id` for an operator.

**Nothing in this service answers with a document.** Not a page, and not a
redirect body either: `http.Redirect` would write a small HTML anchor and set
`Content-Type: text/html; charset=utf-8`, because RFC 9110 §15.4 recommends it for
user agents that cannot follow a redirect, and this service has no such user
agent. `internal/platform/ci` walks the router and the source on every commit and
refuses either.

## Layout

```
cmd/identity/main.go   thin entrypoint: load config, build the app, serve, drain on SIGTERM
internal/config/       environment in, validated Config out
internal/httpapi/      the router, the probes, and the v1 auth surface
internal/auth/         register, login, resolve — the use cases and their ordering
internal/mfa/          the second factor: credentials, challenges, codes, lockout
internal/users/        accounts and the email-uniqueness rules
internal/sessions/     session tokens, hashing and revocation
internal/oidc/         the OIDC provider: storage adapter, registrations, the key
internal/accounts/     the tenancy use cases: accounts, memberships, invitations
internal/admin/        the admin surface: invitation revocation, and the audit trail
                       that records it. The two are one package because no method
                       here mutates without recording — see DECISIONS.md D3
internal/apikeys/      scoped API tokens: the wire format, the scopes, the claims
internal/oauth/        the social-login CLIENT side: state, token cipher, provider
                       registry, code-for-token exchange, the userinfo calls, and
                       the connected_accounts store. Mounted by internal/httpapi/
                       oauth.go as the two routes in the endpoint table above; see
                       "Social login" for the round trip and the four decisions
                       that are contract rather than description
internal/outbox/       transactional event envelope, SKIP LOCKED claim, publisher
internal/platform/db/  the pgx pool, and the readiness ping
internal/platform/ci/  the test that keeps .github/workflows/ci.yml honest, and
                       the one that holds config/kamal-backup.yml and
                       config/deploy.yml to their cross-file secret contract
client/               THE GO CLIENT — a generated transport and the wrapper over it
migrations/            goose SQL files
config/                THE DEPLOYMENT CONFIG: deploy.yml (the Kamal config, and the
                       backup accessory that runs the backup) and kamal-backup.yml
                       (what is backed up, where, for how long). Both copied from
                       cafaye/kit at the ref in kit.ref; see "Backups"
```

`cmd/` + `internal/` is the layout from `refs/goreleaser`. `main` owns nothing
but process lifetime: everything testable lives in `internal/`, and the pieces
`main` does own — the socket, the drain, the signal handling — are in an `app`
type that the tests drive directly.

`client/` is the one directory that is not under `internal/`, and that is the whole
reason for it: **`internal/` is by definition unimportable, and a client no consumer
can import is not a client.** It is not reachable from `./cmd/identity` either, which
is what keeps the client's dependencies out of the service's binary.

## The Go client

`client/` is the third of the fleet's clients, after `cafaye-ts` and `cafaye-py`, and
the one where the generator is right. Two layers, and the split is MD6's:

```
client/generated/api.gen.go   GENERATED, COMMITTED. oapi-codegen v2.8.0 over
                              openapi/v1.yaml: 43 typed operations and a Client
client/generate.go            the //go:generate line, pinned to v2.8.0
client/oapi-codegen.yaml      the generator's configuration
client/transport.go           the interface the generated client satisfies
client/client.go              the hand-written client: 43 typed methods
client/credentials.go         which credential this is, and where it may be sent
client/baseurl.go             where requests go, in a documented order
client/errors.go              RFC 9457 problem to typed error, typed fallback
client/redact.go              the scrubber, and the all-or-nothing rule
client/safetolog.go           a redacting formatter for the generated secret types
```

**Why Go generates and Python does not is a ruling, not an accident**, and it is
written down in [DECISIONS.md](DECISIONS.md) D6 so the next person does not read the
inconsistency as a mistake. In short: Go has a mature OpenAPI 3.1 generator whose
output is ordinary Go — structs, an interface, an `*http.Response` — so generation is
a build-time concern. Python's generators impose a runtime one: hey-api's is v0.0.24
and emits parameterless methods with unsubstituted path templates, and
openapi-generator's Python output is beta on 3.1 and inverts `const` discriminants to
`any`. A hand-written Python client has the smaller attack surface, and it is not a
close call.

**Four things the wrapper owns**, because the generated client cannot: which credential
this is, where requests go, RFC 9457 mapping, and being the public surface.

**Base URLs have no default.** `ResolveBaseURL` consults, in order: the `BaseURL`
option, `$CAFAYE_IDENTITY_BASE_URL`, `$CAFAYE_BASE_URL`, and then **throws**. The
document's own `servers:` entry is deliberately not a default — it would send a
self-hoster's traffic to somebody else's deployment and it would *succeed*, so nothing
would look wrong until somebody read a log.

**A credential reaches no string a human reads.** Every string the client builds out
of anything a caller or a service supplied goes through `Redactor.String`, redaction is
all-or-nothing, and the credential lives inside **closures** rather than in struct
fields — `fmt` prints an exported field by value under `%#v`, and that verb does not
consult `String()`, so a `token string` field is a leak no method can intercept.

**An unknown problem code is a typed error**, so `errors.As(err, &ProblemError)` works
against every code including the four this document already describes that core's
reserved list does not have.

**Regenerating is a gate, not a suggestion:**

```sh
go generate ./client/     # writes client/generated/api.gen.go
```

`TestTheCommittedGeneratedFileIsWhatThePinnedGeneratorProduces` runs that same
generator over the same document into a temporary directory and fails when the
committed file differs, and CI fails the build when four named security tests do not
PASS by name — among them the credential-leak test, the unknown-problem-code test, the
regeneration gate and the lint-exclusion narrowness check.

## The URLs a recovery link points at

**identity does not know where a product puts its reset screen, and it does not
guess.** A deployment says, per purpose, and identity substitutes the token. The
template is a whole URL with `{token}` in it, and the substitution is the only
thing identity writes — so the path, the host, the query parameter name and whether
the token is in the path at all are the deployment's to choose.

| Purpose | Variable | Example | Redeemed by |
|---|---|---|---|
| Password reset | `PASSWORD_RESET_LINK_TEMPLATE` | `https://app.example.com/reset?token={token}` | `POST /v1/password-resets/confirm` |
| Address confirmation | `EMAIL_VERIFICATION_LINK_TEMPLATE` | `https://app.example.com/verify-email?token={token}` | `POST /v1/email-verifications/confirm` |
| Invitation | `INVITATION_LINK_TEMPLATE` | `https://app.example.com/invitations/accept?token={token}` | `POST /v1/invitations/accept` |

**These are two links and they must be two screens.** A verification token
presented to a password-reset screen is a `404` — the tokens live in one table
behind a `purpose` column, so one is not the other — and a reader who follows the
wrong link is told nothing happened. The single-template design this replaced is
defended at length in `internal/courier/mailer.go` and it is sound *for a recovery
link*: a template with `{token}` beats a base URL plus a platform-chosen
convention. It was applied to a verification link too, and the result was a mail
that rendered perfectly, passed every assertion in this repository, and sent the
user somewhere useless. Nothing about a URL says which screen it opens, which is
why the check that catches it reads the rendered link and redeems what is in it:
`TestAVerificationLinkIsNotThePasswordResetLinkAndEachRedeemsAtItsOwnEndpoint`.

Three things are refused at boot, for every template and not just once: no
`{token}` (a link with no credential on it), a relative URL (courier's schema says
`format: uri`, and a mail cannot render one), and a fragment (a mail client does
not send a fragment to a server, so a token in one never reaches the screen that
redeems it). `internal/config` and `internal/courier` each apply all three, and
they must agree — one is the deployment's boot and the other is the constructor,
and a deployment that boots on what the client would refuse is a deployment that
starts and then cannot send.

### Migrating from one template to two

`RECOVERY_LINK_TEMPLATE` is the link for **every** purpose that has no variable of
its own, so a deployment that has only ever set that one keeps booting with the
links it had. That is the compatibility promise and it is deliberate; the cost is
that an unmigrated deployment's address-confirmation link still points wherever its
single template says, which for the configuration that shape was introduced to
replace is the password reset screen.

So identity does not hide it. On startup, a deployment with any purpose resolving
to the shared default gets a warning naming that purpose and the variable that would
give it a link of its own, and nothing else in the process can see the problem: the
send succeeds, the token redeems at its own endpoint, and the reader is the only one
who finds out. Adding `EMAIL_VERIFICATION_LINK_TEMPLATE` is the whole migration;
`PASSWORD_RESET_LINK_TEMPLATE` can wait, or be set at the same time, or the legacy
variable can be deleted once both are in place.
## Testing

**`go test ./...` is red on a machine with no database, and that is the design.**
`internal/mfa`'s `TestTheDatabaseTierActuallyRan` FAILS rather than skips when
`TEST_DATABASE_URL` is unset, because every test in that file is a database test
and a skip there reads like coverage. A green suite that never touched Postgres
verified nothing, so the suite says so.

The database tier, once the schema is applied:

```sh
docker compose up -d --wait postgres
goose -dir migrations postgres "$DATABASE_URL" up
TEST_DATABASE_URL="postgres://identity:cafaye@localhost:15500/identity?sslmode=disable" go test ./...
```

**That DSN was wrong in two ways until 2026-10-05, and both were measured rather than
guessed.** A command in this section that *looks* like the gate and is not the gate is
the same family of defect as the single-link-template bug the recovery suite just
fixed: it looks like an instruction, it is followed, and it fails somewhere far from
its cause.

| | was | is | what the wrong value does |
|---|---|---|---|
| password | `identity` | `cafaye` | `password authentication failed for user "identity"` |
| port | `5432` | `15500` | connects to a *different cluster* — or to none |

**THE PASSWORD IS THE CLUSTER'S, NOT THE SERVICE'S**, which is what
[AGENTS.md](AGENTS.md)'s identity-27 note says and what `docker-compose.yml` states
where it interpolates `${KIT_POSTGRES_PASSWORD:-cafaye}`: kit's shared cluster gives
every role `$POSTGRES_PASSWORD`, and isolation is by privilege and never by secret.
The literal `identity` was correct only while identity ran its own container with its
own password.

**THE PORT IS KIT'S, AND `5432` IS NOT THIS SERVICE'S TO CLAIM.** kit publishes the
shared postgres on **15500**, and on a machine where 15500 is already held, that is
also where a developer reaches an identity verification cluster. Write `5432` and
`psql` answers `FATAL: role "identity" does not exist` — a sentence about a *role*,
produced by a server this repository has nothing to do with, which sends the reader
looking for a migration rather than for a port.

**TAKE THE DSN FROM THE FILE RATHER THAN TYPING IT**, and that is the whole of the
correction:

```sh
# one source, interpolated, follows an overridden cluster password
dsn=$(grep -o 'postgres://identity_app[^ ]*@postgres:5432/identity' docker-compose.yml)
# host-side equivalent: same credentials, kit's published port
TEST_DATABASE_URL="postgres://identity:${KIT_POSTGRES_PASSWORD:-cafaye}@localhost:15500/identity?sslmode=disable" go test ./...
```

Migrations are a deploy step, so they are not a test step — `goose up` is its own
command above the suite, and a suite run against an unmigrated database fails
loudly with `relation "public.users" does not exist` rather than skipping.

**`internal/courier`'s live tier SKIPS loudly instead, and the difference is
deliberate.** Four tests in that package drive a real courier process, and they
read `TEST_COURIER_URL` and `TEST_COURIER_TOKEN`. Without them they **skip**, and
the skip message names what would have been proven and how to run it — it is not a
bare `t.Skip`, because a skip that says nothing is a test that silently passes
without proving anything, which is the thing this section is about.

The reason is the same one `TestTheDatabaseTierActuallyRan` gives for failing,
applied to the tier it actually applies to: **CI supplies a database and cannot
supply a courier.** The `gate` job declares postgres as a service container and
applies the migrations above the gate, so an absent `TEST_DATABASE_URL` there is a
misconfigured *run* and failing is honest. A courier would need a second service
with its own database, its own migrations and its own principal resolver — the same
seam that keeps the database tier in a separate `gate` job at all — so an absent
`TEST_COURIER_URL` is an environment that *cannot run* the test, and skipping with a
name is honest. A test that hard-failed on it would make the package unrunnable
everywhere, and a permanently red gate is a red gate nobody reads.

So the e2e file is not deleted, and what it cannot prove offline is proved offline
instead: `wiring_test.go` holds the request identity, the closed body, and the
**stable `Idempotency-Key`** (the property that stops a double-clicked reset mailing
twice); `client_test.go` holds courier's request contract; `recorded_test.go` holds
courier's byte-for-byte answers. What is left for the live tier is the one claim a
fixture cannot make about itself: that a real implementation of courier's document
accepts these bytes.

CI knows about the skip rather than discovering it. `E2E_SKIP_EXCEPTIONS` in the
`gate` job names exactly those three tests; both no-skip checks subtract them by
whole name and still fail on any other skip. `internal/platform/ci` holds that list
to those three names in **both** directions — it cannot grow, and it cannot be
emptied — so the exemption cannot widen by accident, and a real skip cannot be
hidden by deleting an entry.

With no `TEST_DATABASE_URL`: **961 PASS lines, 364 SKIP, and 2 FAIL** — both
fails are `TestTheDatabaseTierActuallyRan`, one in `internal/mfa` and one in
`internal/apikeys`, and both are the point. With it:
**1544 PASS lines, 0 SKIP, 0 FAIL**, no data races under `-race`.

(Those figures were measured on this tree. The numbers this section used to
carry — 776/309/1 and 1254 — were already stale before the tripwire packet: at
`bff6333`, the same commands gave 923/364/2 and 1506. A stale count in a
document about what the suite proves is the same class of problem as a stale
route list, so it is worth writing down that it happened.)

### **The document-versus-router tripwire**

`internal/httpapi/openapi_drift_test.go` is the check that holds
`openapi/v1.yaml` and `openid/openid.yaml` to the router, in both directions, by
**method and path** — never by count, because one operation added and one removed
leaves the count alone. It is the last such check owed in the fleet, and it is the
one that found the twelve undocumented operations described above — **which is why
`knownDrift` is now empty and pinned at empty.**

Four things about it are worth knowing before you touch a route:

- **The method comes from chi's own walk of the tree `New` assembles**, never
  from the path string. billing's first drift check compared paths and never
  `route.verb`, so `PUT /v1/customers/{id}` was served in a money-handling
  service with nothing written down about it — one path on each side, and the
  comparison reported agreement. That shape was live here too, on
  `POST /oidc/authorize` and `POST /oidc/userinfo`, and identity-28 closed it by
  documenting the POST beside the GET rather than by narrowing the check.
- **Both documents are read** and the union is the contract. Nine of the eleven
  `/oidc/*` and `/.well-known/*` routes are documented in the sibling document,
  so a check reading only `openapi/v1.yaml` would have had to declare all eleven
  undocumented, which is false about nine of them.
- **There is no prefix filter, and `knownDrift` is empty.** Every route is in a
  document; a route that is in neither fails the suite, and any entry added to
  `knownDrift` fails a second test that names the two legitimate ways to close
  one. `strings.HasPrefix(path, "/v1")` is a guess about intent, and it cannot
  see a method.
- **The check is shown biting, on the twelve it once admitted.**
  `internal/httpapi/known_drift_test.go` takes the *real* router walk and the
  *real* documents, removes this packet's entries, and asserts all twelve come
  back unexplained. It is not a fixture — it is the same expression
  `TestEveryServedRouteIsDocumentedOrNamed` evaluates, pointed at the state the
  repository was in on 2026-09-30.
- **The document is parsed without a YAML dependency.** `go.mod` has none and
  this adds none; the reader takes the `paths:` block by indentation, states the
  subset it understands, and raises on every way it could under-read. Two empty
  sets agree, and that is how a check over nothing goes green.

So adding a route means adding its document entry, with an `operationId` — that
is the name of the method on every generated client in the fleet. The gate says so.

### **The claims-versus-router tripwire, and the tripwire's own tripwire**

A perfect OpenAPI document is not the same as an honest repository. `README.md`
said this service does OAuth social login, its roadmap checked the box off, and
`cafaye.yml` — the manifest a customer is handed — claimed the capability. The
documents were **honest the whole time**: not one of them ever declared a
social-login operation, because there was no route for one. Every claim was in
prose, and `openapi_drift_test.go` reads `paths:` blocks, so it could not see any of
it.

Those three claims were **wrong in opposite directions, and the fix for one was
the defect in the other.** This repository shipped a README promising a feature
that answered 404; the tripwire built to catch that had its failure printed
inside the file, and acting on it meant mounting the surface — so the honest
answer to "the README claims a route that does not exist" was to add the route.
It exists now, documented in both documents and described above, and the tripwire
is deleted. `internal/httpapi/oauth_absent_test.go` asserted the surface was still
unmounted and **its failure message was the work order**; finishing that work meant
deleting the file, because an absence test that outlives the absence is the
repository lying to itself in a file nobody reads.

**It was also green the whole time, which is the part worth keeping.** `social` was
a conditional surface that neither router walk set, so `servedRoutes` walked a
service without the two social routes in it, every claim check above reported
agreement about a smaller service, and the tripwire for this exact surface never
went red. `internal/platform/ci` caught the shape the second time (`admin`, then
`recovery`, now `social`); what is new is *which* check was blinded. The first two
were reverse-direction documentation checks. This one was the absence check whose
failure message was the work order, so the repository could not learn it had a
problem. It stayed green for a whole packet for one more reason worth naming: a
redeclared constant meant `go vet ./internal/httpapi/...` failed, and **a package
that does not compile cannot run the test that would have caught it.** A compile
break in the test package is the one failure mode that hides a tripwire.

`router_walk_test.go`'s `conditionalSurfaces` now names `social`, and
`TestTheDriftWalkSeesTheSocialLoginSurface` asserts a **route** rather than a field
— the assertion shape that survives a registrar that mounts nothing.

`internal/httpapi/claims_test.go` closes that, holding three more places to the
same router walk, **in both directions**:

| Claim | Held by |
|---|---|
| README endpoint tables | `TestTheReadmeEndpointTablesAreTheRoutesTheRouterServes` |
| README roadmap checkboxes | `TestEveryCheckedRoadmapItemIsBackedByTheRouter` |
| `cafaye.yml` capability list | `TestTheManifestDescribesOnlyCapabilitiesThisServiceHas` |

It **found the manifest claim and the roadmap claim by name on its first run**,
which is the evidence that it would have found them before. A fourth file,
`claims_reader_test.go`, injects faults into the readers themselves — a malformed
route row, a block-scalar description, an emptied roadmap — because a check over
nothing is green, and a reader that under-reads reports agreement over a subset.

`claims_faults_test.go` holds the walk itself: it asserts a route from **each**
conditional surface is visible (not that a field was set, which passes against a
registrar that mounts nothing), that two options literals stay in step, and that
each claim check goes **red** on a route that does not exist.

One of those two red cases is `a social-login route with no README row`, which
drives `undocumentedSocialLoginRoutes` with an injected
`/v1/auth/oauth/{provider}/disconnect`. It used to inject the **real** callback and
assert that any social-login route was a problem; inverted, the injection has to be
a path no provider serves and the README does not describe, so the check now means
"a social-login route with no documentation beside it" rather than "any social-login
route at all". What that costs is in the commit message: the case is mechanically
subsumed by the general served-but-undocumented case beside it, so what is preserved
is the narrowing to the prefix and a failure message that names the social surface
— not an independent signal.

That difference is the only thing that tells "ran" from "skipped" from the
outside, and the wall-clock is where it shows. Same command, same machine, only
`TEST_DATABASE_URL` differing:

| package | no database | with the tier |
|---|---|---|
| `internal/accounts` | 0.36s | 83s |
| `internal/httpapi` | 1.4s | 110s |
| `internal/mfa` | 2.0s | 90s |
| `internal/auth` | 1.8s | 55s |
| `internal/outbox` | 2.5s | 46s |

SIGTERM handling is not asserted through a mock: `TestMainHandlesSIGTERM` runs
the real `main()` in a child process, waits for it to report that it is serving,
sends the signal, and requires a clean exit. There are no `time.Sleep` calls in
this repository — every wait is on a channel the code under test signals, or on
a failure deadline (PLAN.md §3).

## CI

`.github/workflows/ci.yml` calls kit's reusable workflow for the shared half and
runs this repository's own for the rest:

```yaml
uses: cafaye/kit/.github/workflows/ci.reusable.yml@master
```

`ci (kit: go)` is **expected red**, and that is a conflict with kit's own rules
rather than a choice made here: kit's checklist ends with "The workflow is green
on the adoption PR" and kit's AGENTS.md says "Never weaken a check to make the
gate green". Two steps are red, both structurally.

- `test` runs `go test` with no Postgres, and a caller cannot hand a reusable
  workflow a service container (`services:` is not one of the keys GitHub accepts
  on a calling job). `TestTheDatabaseTierActuallyRan` fails the moment
  `TEST_DATABASE_URL` is absent, so making this step green from here would mean
  un-failing that test — the weakening kit forbids.
- `lint` runs golangci-lint, and this tree has no `.golangci.yml`, so it is the
  default set: 31 issues (errcheck 13, unused 9, staticcheck 6, ineffassign 3).
  With kit's config it is 83, so copying the config makes it redder, not greener.

The caller cannot even mark the job non-blocking: `continue-on-error` is not one
of the keys GitHub accepts on a job that calls a reusable workflow. **Require
`gate` in branch protection.** Delete the `ci` job when kit's Go job grows a
`services`/`env` seam, and not before on the strength of a green run.

`gate` is the job to read. Postgres 17.11 as a service, `goose up` as its own step
above the gate, `bin/prime` unmodified, and then the assertions: the database tier
**derived from the tree**, a floor on its PASS count, zero `--- SKIP:` lines, 23
named security tests that have to appear in the log by name, `go vet`, `gofmt -l`,
a `git diff --exit-code` on `go.mod`/`go.sum`, and a coverage floor. `MFA_ENCRYPTION_KEY`
is generated from `/dev/urandom` per run, masked, and printed nowhere.

The floors are decrease detectors, not targets: a green run means nothing was
deleted, skipped or excluded since they were measured. They are currently 1254
for the suite and 1166 for the tier, both measured from a complete run with the
tier applied.

`internal/platform/ci` is the test for that file. It parses no YAML — a YAML
dependency would move `go.mod`, and AGENTS.md's rule is that `go.mod` moves only
for a stated cause — and it is what catches the `uses:` path drifting back to a
directory GitHub cannot resolve, the `versions:` literal drifting away from
`go.mod`, migrations moving below the suite, the SKIP check disappearing, and a
named security test being renamed.

### The coverage floor, and what it is a percentage of

`gate`'s `coverage` step runs `bin/coverage-floor`, and this is the one number in
this repository whose denominator is a decision rather than a fact.

Go's `go tool cover -func` prints a `total:` over **every** block in the profile,
and it has no flag to leave a path out. `client/generated/api.gen.go` is 12,284
lines of committed oapi-codegen output with **3,001 statements and no test**, so it
drags module coverage from **73.6% to 44.6%** — measured, both ways, on this tree,
by `go test -count=1 -race -coverprofile=coverage.out ./...` against Postgres.

Two things that would have been one-line edits, and neither was taken:

- **Lowering the floor to 45.** A floor catches a *decrease*, and 70 was measured
  against hand-written code. Lowering it admits a real 29-point regression in
  hand-written code permanently, because the generated file's weight in the
  denominator never changes.
- **Adding tests to the generated code.** They would be deleted by the next
  `go generate`, so the coverage would not survive a week.

So `client/generated` is excluded, by a **declared** path in
[`coverage-exclusions`](coverage-exclusions) at the repository root:

```
excluded coverage client/generated files=1 lines=12284 coverage-fail-under=70 \
  reason="oapi-codegen v2.8.0 output …" owner=identity since=2026-09-30 until=2027-03-31
```

**Declared, never inferred.** The alternative — skipping any file whose header says
`// Code generated … DO NOT EDIT.` — fails toward *less* coverage: the header is
written by whichever generator ran, and one that stops writing it silently
un-excludes a quarter of the module while the floor stays at 70. An inferred
exclusion that fails toward *more* coverage is safe. One that fails toward less is
not.

**A directory, because the tool takes a package and not a file.** That is coarser
than the anchored regex the lint exclusion uses for the same file, and the
coarseness is paid for by
`TestTheCoverageExclusionIsOnlyGeneratedCode`, which enumerates every `.go` file
under `client/generated` and fails if one is not itself generated.
`client/` would be a perfectly legal declaration and it would exempt `baseurl.go`,
`credentials.go`, `errors.go`, `redact.go` and every test in the package.

**The entry must earn its place.** Reason, owner, `since`, `until`, the `files=`
and `lines=` it covers, and the floor — and **an entry matching nothing is a
failure** (kit's rule 4, from ESLint's `reportUnusedDisableDirectives`). The
`files=`/`lines=` fingerprint is what turns "a file appeared under the excluded
directory" into a red build instead of a silent change of denominator.

**The three facts are printed together, on a green run too.** `bin/coverage-floor`
emits the measured number, the excluded set with its reason and owner, and the
floor, in one block, before it compares them:

```
coverage 73.6% of 4628 statements, over the profile minus 2257 block(s) this file excludes
excluded — 1 declared entry/entries in coverage-exclusions:
  client/generated  files=1 lines=12284  owner=identity since=2026-09-30 until=2027-03-31
      reason: oapi-codegen v2.8.0 output for openapi/v1.yaml, …
floor 70%  (coverage-fail-under, restated here so the measured number, the excluded set and the floor are read together)
coverage 73.6% at or above the 70% floor
```

"coverage 73.6% (floor 70%)" on its own is decoration: a reader cannot tell 70% of
what. **No percentage is written into `ci.yml`**, which is why the one that used to
be there is gone rather than updated.

**The floor is still the floor.** `TestTheCoverageFilterCanFail` runs the real
script over twenty-two broken declarations and profiles, and includes a module at
**69.9%** (red) and one at **70.1%** (green), with the exclusion in place and
unchanged. It also includes **699 of 999 statements — 69.97%, which prints as
"70.0"** — and that one is red, because the comparison is
`covered * 100 < floor * total` in integers rather than against the printed number.
Go's own tool rounds the same way and kit's step compares the rounded value, so this
is stricter than the tool it replaces: that tool's job is to report and this one's is
to refuse. An exclusion that made coverage unrestrictable would fail that test.

**Where the mechanism lives, and the disagreement it leaves.** It lives here, not
in kit — identity's *enforcing* coverage step is its own, in `gate`, because kit's
`test` step runs with no database and dies before reaching a coverage step at all.
kit is untouched. The consequence, stated rather than hidden: kit's coverage step
computes `total:` over the whole profile and cannot be told about this declaration,
so `coverage-fail-under: '70'` is still passed to it and it would read 44.6%. That
input is left alone on purpose — 45 is the rejected option and 0 is a weakened gate
— and the threshold is checked in three places by
`TestTheCoverageFloorInTheDeclarationIsTheFloorsFloor`. The full reasoning is in
[DECISIONS.md](DECISIONS.md) D6.

**What is still open.** Generating the client into its own Go module, which makes
the boundary a compile-time fact rather than a config entry. It changes the import
path of a published client, so it waits; the signal is a second repository asking
for a generated client, and `until=2027-03-31` fails the build in the meantime.

## Backups

**A scheduled dump is configured. No backup has been taken, and nothing here
claims one has.** This section is written so that sentence is impossible to
miss, because the failure mode is a README that reads as reassurance.

Two files, committed together and copied from cafaye/kit at the ref in
`kit.ref`:

| File | What it is |
|---|---|
| [`config/kamal-backup.yml`](config/kamal-backup.yml) | what to back up, where, and for how long |
| [`config/deploy.yml`](config/deploy.yml) | the Kamal config, including the `backup` accessory that runs the first |

Both were accepted by the real binaries — kamal 2.12.0 and kamal-backup 0.5.2:
`kamal config` renders the deploy config, and `kamal-backup validate` resolves
every secret the backup config names out of the backup accessory's environment.
That second check is the load-bearing one, because it is a **cross-file**
contract that no per-file parse can see — a secret named in `kamal-backup.yml`
and missing from the accessory's `env.secret` list is valid YAML in both files,
each internally consistent, and a deployment failure. Removing one secret from a
copy of this pair and re-running `validate` reproduces that failure with
`RESTIC_REPOSITORY or RESTIC_REPOSITORY_FILE is required`, which is how the
claim above is known to bite rather than assumed to.

**Those binaries are not in this repository's gate**, and a check that runs only
on a machine that happens to have kamal and the gem installed is a check that
runs for whoever has them and for nobody else. So the same contract is asserted
on every commit by
[`internal/platform/ci/backup_config_test.go`](internal/platform/ci/backup_config_test.go):
every secret the backup config names is declared by its accessory, the accessory
mounts the file, `app:` names this service, and the configured schedule and this
section's data-loss window agree with each other. Each of those four was checked
by injecting the fault it exists to catch — removing the secret, removing the
mount, renaming the service, shortening the schedule — and watching the
corresponding test go red.

### What covers what

`pg_dump` of **one** Postgres database — the one `DATABASE_URL` names — piped
through restic into a Cloudflare R2 bucket. It is a dump of the **whole**
database, not a table list, so it covers all seventeen of identity's tables:
`users`, `sessions`, `recovery_tokens`, `api_keys`, the four `mfa_*` tables,
the three `oidc_*` tables, `accounts`, `account_users`,
`account_invitations`, `account_audit_log`, `outbox_events` and
`connected_accounts` (defined, unwritten — see "Not built yet"). A table added by
a later migration is covered without touching this config, which is the reason
there is no table list here to fall out of date.

**No database name is written anywhere in the config**, which is the reason the
backup cannot be pointed at a different database than the service. The
connection is `{ secret: DATABASE_URL }` — the same DSN the service opens. An
operator note that follows from that: the `postgres` accessory in
`config/deploy.yml` sets only `POSTGRES_PASSWORD`, so the image's defaults name
the role and database, and a deployment's `DATABASE_URL` has to match those
rather than the `identity`/`identity` pair `docker-compose.yml` provisions
locally.

Retention is roughly 26 snapshots: every one from the last week, one a day back
a month, one a week back two months, one a month back a year, two a year
indefinitely. **The oldest restorable thing is about a year old.**

### What it does not cover

- **A dump is one point in time, not a running log.** See the window below.
- **Postgres roles and tablespaces.** The dump carries no `CREATE ROLE` and no
  ownership. Restoring into a differently-named role means that role has to
  exist first.
- **The keys.** A restic repository is encrypted with `RESTIC_PASSWORD` and
  nothing else — **lose it and every snapshot is permanently unreadable,
  including ones you have not lost yet.** `MFA_ENCRYPTION_KEY` is a second such
  value: without it `mfa_credentials.secret_ciphertext` is unreadable, so a
  restored MFA enrolment cannot be verified. `OIDC_SIGNING_KEY` is a third, and
  it is not a column: without it every token in the restored database fails
  verification, which is service-wide breakage rather than an unreadable table.
  All three must be stored **somewhere other than the repository**.
- **Any object storage or uploaded files — because identity has none.** This is
  the verified fact rather than a general caveat: there is no `storage_key`, no
  bucket, no multipart upload, no attachment, and no `os.Create` /
  `os.WriteFile` / `os.MkdirAll` anywhere in `cmd/`, `internal/` or `client/`.
  The image is distroless-nonroot with no shell. A restored database has nothing
  pointing at anything outside Postgres, which is *not* true of darkroom, whose
  `assets` rows point at bytes in a bucket a `pg_dump` cannot reach.
  **The day a packet adds an upload or a bucket, this paragraph becomes the first
  thing to lose** and `paths:` becomes a decision rather than an omission.
- **A second copy of anything.** There is one restic repository in one bucket on
  one provider. `prune` deletes from it by design and nothing else keeps a copy,
  and **R2 has no object versioning and no Object Lock** — a deleted object is
  gone. This meets 3-2-1's off-site rule and neither of its other two. The
  mitigation is bucket access control, not the retention policy.
- **A backup that nobody notices failing.** The scheduler logs a failure and
  sleeps the interval. **The alert is the backup** — if nobody watches the
  accessory's log, a nightly failure is invisible for a day and a backup failing
  for a week is not a backup.

### The data-loss window

**With the configured `schedule: 1d`, up to 24 hours of committed transactions
are lost if the primary database is destroyed.**

That number is not a wall-clock deadline, and three details all push it wider
rather than narrower:

1. **It is measured from when the previous backup _finished_.** The scheduler's
   loop is *run a backup, then sleep the interval*, so one cycle is the interval
   **plus the previous run's duration**. `pg_dump` also opens a single
   repeatable-read transaction, so the snapshot is taken at the **start** of the
   dump — the gap between two snapshot points is that whole cycle.
2. **There is no WAL shipping and no base backup.** This is a scheduled dump,
   not point-in-time recovery. `kamal-backup` will not do PITR for you; the next
   step is Postgres's own continuous archiving, which is an infrastructure
   decision rather than a config one.
3. **A failed backup is not retried until the next interval.** A dump failing
   for six hours has not been retried six times. The operator-facing half: a
   failure does not update the state file, so the next backup is already due and
   `kamal-backup backup` by hand retries immediately.

### Turning it on

Committed is not running. An operator still has to:

```sh
# 1. The R2 bucket must exist BEFORE the first backup. `init_if_missing: true`
#    initialises the repository inside a bucket you created; it does not create
#    the bucket. This is the difference between "backups are on" and "backups are
#    on after somebody created the bucket".
# 2. Six secrets in .kamal/secrets: DATABASE_URL, DATABASE_PASSWORD,
#    RESTIC_REPOSITORY, RESTIC_PASSWORD, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY.
#    DATABASE_PASSWORD must equal the password inside DATABASE_URL, and identity
#    itself never reads it — it exists so pg_dump gets the credential in its
#    environment rather than in its argv.
# 3. The five non-secret KIT_* variables the ERB in config/deploy.yml requires:
#    KIT_SERVICE, KIT_REGISTRY_ORG, KIT_REPO, KIT_WEB_HOST, KIT_APP_DOMAIN.
kamal setup
kamal accessory boot backup

# Take one now, ignoring the schedule, and prove it wrote something:
kamal accessory exec --reuse backup kamal-backup backup --force
kamal accessory exec --reuse backup kamal-backup list
kamal accessory exec --reuse backup kamal-backup evidence   # keep this output
```

**Then drill it before you need it.** A backup nobody has restored is a
hypothesis. `cafaye/kit`'s `templates/kamal/drill.sh`, copied to `bin/drill`,
restores into a scratch database, asserts the tables came back with rows, and
drops the scratch database on every exit path:

```sh
bin/drill --table users --table sessions --table api_keys
```

This repository does **not** contain `bin/drill` yet. Copying kit's `drill.sh`
into `bin/` is a separate, unmade change, and until it is made the restore path
is described in `cafaye/docs`'s
[backup-and-restore runbook](https://github.com/cafaye/docs) rather than being
exercisable from here.

## Migrations

goose SQL files in `migrations/`, numbered and annotated. `goose` is a CLI
tool; its **library** is linked into the binary at the same pinned version so the
image can apply the embedded files itself (`identity migrate`, see
[migrations/README.md](migrations/README.md)). `00001_init.sql` establishes the convention and
`00002`–`00004` create `users`, `sessions` and `outbox_events`, `00005`–`00008`
the tenancy and social-login tables (`00008`'s `connected_accounts` is defined and
unused — the social-login surface is not mounted, see "Not built yet"), `00009` the
OIDC ones, `00010` the four MFA
tables, and `00011` the `api_keys` table, and `00016`–`00018` the account-isolation
substrate itself: kit's `protect_table`, the credential-resolution audit, and the
caller scope that lets `GET /v1/accounts` answer the question it exists to answer
(see D11). Migrations are a deploy step, not a boot
step — see [migrations/README.md](migrations/README.md).

## Image and chart

Multi-stage, `CGO_ENABLED=0`, `gcr.io/distroless/static-debian12:nonroot`. No
compiler and no shell in the shipped image:

```sh
docker build -t identity .
docker run --rm -p 8080:8080 identity
```

**The image migrates its own schema, because there is no shell to migrate it
with.** `migrations/*.sql` are embedded in the binary and `identity migrate`
applies them; the same binary is also shipped at `/app/bin/migrate`, which is
the path kit's substrate invokes for identity, so a box's migrate Job needs no
configuration:

```sh
docker run --rm -e DATABASE_URL="$DATABASE_URL" identity migrate
```

The entrypoint is still `/app/service` and a replica still never migrates at
boot — see [migrations/README.md](migrations/README.md) for the mechanism, the
substrate's line, and the one caveat worth knowing.

### What a push to master publishes

`.github/workflows/publish.yml`, on every push to `master`:

```yaml
jobs:
  publish:
    uses: cafaye/kit/.github/workflows/publish.reusable.yml@master
    with:
      push: true
```

That is a **caller**, not a copy — kit's template, verbatim. One `uses:`
publishes **both** artifacts a deploy consumes: the image `config/deploy.yml`
deploys (`ghcr.io/<org>/<repo>:sha-<commit>`, plus `master`, plus `latest`)
and the chart the Argo CD `Application` pulls
(`oci://ghcr.io/cafaye/charts/identity:<chart version>`). The composition
lives in kit, so a fix to how either artifact is built reaches here on
kit's next push with no pull request against this repository.

Before the caller existed, `config/deploy.yml` named an image and `kamal
deploy` pulled it, and **nothing in this repository produced it** — the
`docker build` above was the whole story, on one person's machine. A deploy
config naming an image nothing produces is a document, not a plan. The chart
half of that gap survived until identity-w98: the chart landed while the
caller still named kit's image workflow, so the Application pulled a tag no
pipeline wrote.

Four things worth knowing:

- **The image name is not written here.** The reusable workflow derives it from
  `github.repository` and lowercases it, because `ghcr.io/Cafaye/Identity` 404s
  on a registry that requires lowercase paths.
- **`packages: write` is granted here**, because a reusable workflow can request
  a permission but cannot grant itself one. The missing line shows up at the push
  as a 401, which reads like a bad password rather than like the missing line.
- **Tags are `sha-<commit>`, `master`, and `latest`** — no semver. Cutting a
  release is a decision, not a side effect of a merge.
- **The chart's `version` is the OCI tag, and it is the tag the substrate's
  `Application` must match.** `chart.reusable.yml` reads name and version from
  `chart/Chart.yaml` — they are not inputs — and a Helm chart's OCI tag is its
  `version`. `Chart.yaml` says `0.1.0`; the Application pins
  `targetRevision: 0.1.0`. Bump one without the other and the deploy never
  happens: Argo reports no error, it just never finds the artifact.

A pull request does not trigger it: only `master` holds deployable commits, and a
PR build would run untrusted code against a registry write.

## Not built yet

Everything below is a later packet, and none of it is stubbed to look finished: the
admin API, and key rotation.

**"Sign out of one session" stops at one.** `GET /v1/sessions` and
`DELETE /v1/sessions/:sessionId` are here, and "sign out **everywhere**" is not a
different route — it is what a password reset, an MFA change and an operator
disable already do, through `revokeEveryCredential`. There is no endpoint that
means "end all my other sessions and keep this one", and that is worth saying
rather than leaving to be discovered: the listing has no `POST`-shaped sibling and
the OpenAPI document describes none.

**There is no `last_used_at`.** `sessions` records `created_at` and nothing since —
so a listing entry can tell you when a session started and when it dies, and not
when it was last used. Writing one means an UPDATE on the authentication path for
every authenticated request, which is a real cost on the hottest statement in the
service and a decision rather than a field. `updated_at` exists on the table from
`00003` and is not maintained either, which is the same fact stated twice: a
timestamp this service does not write must not appear in a response as though it
did.

## Social login: what it was, and what it is

**This section used to be titled "Social login is not built, and the code that looks
like it is", and it was true.** There was no "Continue with Google" and no
"Continue with GitHub" — no route, no handler, no use case, and nothing in either
OpenAPI document. The path a social callback would have used is
`/v1/auth/oauth/{provider}/callback`, built by `Provider.RedirectURI` in
`internal/oauth/provider.go`, and **nothing served it.** A product that integrated
against it got a `404`, a clean one from a router that never had the route, rather
than a `500` from a half-built flow.

**It is mounted now.** `GET /v1/auth/oauth/{provider}` and
`GET /v1/auth/oauth/{provider}/callback` are in the endpoint table above, they are
in `openapi/v1.yaml` under the `social-login` tag with `operationId`s, and the round
trip is described under [Social login](#social-login-two-routes-and-neither-of-them-takes-a-credential).
This section is kept because the record is the point: **this repository shipped a
README promising a feature it did not have**, and a reader who arrives at a corrected
paragraph saying "OAuth was never mounted" — next to a router that serves it — will
conclude the README is unreliable. For this one repository it demonstrably was, and
the honest response is the history rather than a silence.

What each piece is now:

| Piece | State |
|---|---|
| `internal/oauth/state.go` | **Live**, twice over. `NewState`/`VerifyState` guard the OIDC login's round trip and the social one. |
| `internal/oauth/provider.go` | **Live.** Google and GitHub endpoint definitions, the configured-provider `Registry`, and `RedirectURI`. `registerSocialRoutes` mounts the routes under the prefix `RedirectURI` builds, and `TestTheSocialLoginPrefixIsTheOneTheProviderBuilds` calls the real function rather than re-spelling the string. |
| `internal/oauth/client.go` | **Live.** The code-for-token exchange and the userinfo calls, with a real timeout and a response cap. |
| `internal/oauth/cipher.go` | **Live.** AES-256-GCM for the provider tokens, with a versioned prefix. |
| `internal/oauth/store.go` | **Live** and tested against a real database. `connected_accounts` is written to: one row per linked provider identity. |
| `internal/oauth/settings.go` | **Live.** `internal/config` reads it — five variables, and a provider with **only half** its credentials is a startup failure rather than a disabled provider. |
| `migrations/00008_connected_accounts.sql` | Applied **and written to.** The table and its `oauth_provider` enum were there before this surface existed, and were empty; that was the tell. |
| `internal/httpapi/oauth.go` | **Exists.** The two handlers, the state cookies, and the error mapping. |
| `internal/httpapi/claims_test.go`'s `undocumentedSocialLoginRoutes` | The inverse of the deleted tripwire: a social-login route with no documentation beside it is a failure. |

### Four places said it shipped, and each was wrong, and fixing it meant mounting it

The claim was not subtle. It was in the opening paragraph, in the roadmap, in
`cafaye.yml`'s `description`, and — implicitly, and worst of all — in a directory
of correct, well-tested, database-backed code. `internal/httpapi/openapi_drift_test.go`
could not see any of it, because **none of it is in a `paths:` block**: the OpenAPI
documents were honest the whole time, and a service can have a perfect contract and
still advertise an endpoint that does not exist.

So there is a second check, `internal/httpapi/claims_test.go`, holding the
README's endpoint tables, the roadmap's checkboxes and the manifest's capability
list to the same router walk — **in both directions**. It found the manifest claim
and the roadmap claim by name on its first run, which is the evidence that it
would have found them before.

And a third, `internal/httpapi/oauth_absent_test.go`, which asserted the surface was
**still not mounted** and whose failure message was the work order for whoever
mounted it. **Its own header named the rule**: *mounting social login without
deleting this file is not finishing the work; deleting it is a review-visible act,
which is the only honest way for an absence to become a presence.* It is deleted.

### The two decisions that were open, and how they were settled

A callback has to answer one question: *which user of this service is the person who
just came back from Google?* There are four answers and only some of them are
obvious. Jumpstart Pro — the parity baseline — makes all four explicit, and its
callback is the reference for the shape:

- the provider identity is already linked → sign that user in;
- someone is signed in and has not linked this provider → attach the link;
- **the provider returns an email that matches an existing user who has never linked
  this provider → refuse**, and send them to the password flow;
- the provider identity is new and no user holds the address → create the user.

The third is the one that matters, and it was a **product decision, not an
implementation detail**: refusing means a person who signed up with a password
cannot later use "Continue with Google" until they set a password, and permitting it
means an email assertion from a third party is enough to take over an account. The
wrong choice here is silent and permanent, and this service is the security
boundary.

**It refuses.** `ErrSocialEmailInUse` → `409 conflict`, nothing minted, and the
person is told to sign in with that account instead. That is Jumpstart's behaviour
(`elsif User.exists?(email: auth.info.email)` → `flash.alert` → redirect to login)
and it is the anti-account-takeover rule: somebody who controls a provider account
carrying another person's address must not be able to walk into that account. The
cost is real and is the cost of choosing correctly — a password user who later
clicks "Continue with Google" has to sign in the way they signed up.

The second open item is **Google's `email_verified`**, which the tripwire recorded as
"decoded with no check, while GitHub's path refuses an unverified address, so the two
providers are not held to the same bar". It is read now: **any path that resolves a
callback to a user by email requires the provider to assert the address is
verified.** An unverified address is not a claim about identity, it is a suggestion,
and one that reached a `users.email` lookup would be an account takeover with a
login page in front of it.

Two more properties shipped with the surface, both written up under
[Social login](#social-login-two-routes-and-neither-of-them-takes-a-credential):
provider tokens are **encrypted at rest**, and expiry is judged with a **30-minute
skew** so a token is never used in the minute before it dies.

**Where a social callback renders, and what it redirects to on failure, is still a
contract this repository has not made.** A social sign-in is a `302` out to a
provider and a `302` back, and the failure path is half the feature — a person
whose provider declined consent, or whose callback was rejected, has to be told
something. Every surface here answers `application/problem+json` to a programmatic
client, and the one exception is the OIDC login page. The callback here answers
problem documents too, on the reasoning that a redirect target for a failure is a
product's decision and this service renders no HTML at all. A product integrating
this decides where those refusals go; that is a gap rather than a mistake, and it
is the next thing to settle.

`connected_accounts` was left in place rather than dropped for a whole packet while
it sat empty, and that was right: an applied migration is not edited, and a `DROP
TABLE` on the security boundary to tidy up an unused table is a bigger intervention
than leaving it. What it must never be is *invisible*, and for a packet it was
invisible only to somebody who already knew to look — the tripwire was the thing
that made it a named gap rather than a quiet one.

Three things on the recovery surface are **not** here, and each is a decision rather
than an oversight:

- **No mail delivery.** The `Mailer` seam is one interface with two methods and
  `main` wires `Unavailable{}`, so every route that needs to send a message answers
  `503 service_unavailable` with a sentence naming the deployment problem. The flows
  are complete and tested over a recording double; the delivery path is courier's,
  and courier has not finished it. **A user who forgets a password today cannot
  recover**, because there is nowhere for the link to go — which is the honest state,
  and the alternative (a mailer that logs, so an operator can see it "worked") would
  put a live credential in a searchable log.
- **No registration-time verification mail.** `POST /v1/users` sends nothing and a
  client that wants an address proved calls `POST /v1/email-verifications`
  afterwards. Registration is the one request that must not start failing because a
  mail provider is unavailable, and the cost is one extra call in a product. **And
  that route answers the same 202 whether or not the account has already proved its
  address**, so a client cannot use it to find out — it asks
  `GET /v1/email-verification`, with a session, when it needs to know.
- **No sweeper for expired recovery tokens.** `recovery_tokens_expires_at_idx` is in
  the migration so the job is one statement when somebody wants it; in the meantime
  the read query filters on `expires_at`, so an unswept row is harmless.

**A single logout emits no event.** `identity.session.revoked` is declared and
emitted only where *every* credential the account holds is gone — a password reset
or an email change. `DELETE /v1/session` ends one session and announces nothing, so a
subscriber cannot tell "this person signed out" from "this person's credentials are
all gone". That gap is named rather than papered over by emitting the wrong type for
a single revocation.

Three things in the scoped-api-token area are specifically **not** here, and each
is a decision rather than an oversight:

- **No sweep revokes a user's api keys when MFA is enabled.** `sessions` is swept
  when a second factor goes on and off, and the argument for sweeping a token is
  stronger — a token is long-lived, named, visible in a settings page, and is
  exactly what an attacker with a stolen password would mint before the user
  notices. It is not wired because doing it **silently breaks a CI job**: the user
  turns on MFA and an unrelated service starts answering 401, with nothing in the
  MFA response saying why. Doing it honestly needs the count of what was revoked in
  that response, which changes a landed contract and belongs to whichever packet
  owns the MFA surface. The index is already there
  (`api_keys_user_idx`) and the one-statement sweep is written; the *decision* to
  call it is not made here.
- **No sweeper emits `identity.api_key.revoked` for an expiry.** core's catalog
  row says "A scoped API token is revoked or expired" and the expiry half of that
  has no producer: there is no job. `api_keys_expires_at_idx` is in the migration
  so the job is one statement when it lands, and an expired token is already
  refused on resolution.
- **No rotation endpoint and no reveal endpoint.** "Rotate" is revoke-then-mint,
  two requests, deliberately: a rotation endpoint that has to preserve the name
  would be a second spelling of the same security property. And there is nothing to
  reveal.

Inside the OIDC provider, specifically not built: refresh tokens (access tokens
live fifteen minutes and cannot be renewed), the implicit flow, client
credentials, the JWT profile grant, `private_key_jwt` client authentication,
dynamic client registration, token introspection, the revocation endpoint,
end-session, the device flow, and a consent screen. Each one is a refusal at the
point a client would reach for it, and each is absent from the discovery
document, rather than a stub that looks finished.

**A product cannot register itself.** Client management is owner-gated on an
account, reusing `RequireAccountRole`, because `identity` has no platform-admin
role yet — the admin API is a later packet, and a rule this service cannot
express would be a rule with a bypass in it.

## Roadmap

- [x] Skeleton: config, `/healthz`, `/readyz`, pgx pool, graceful shutdown
- [x] Migration convention, image, compose stack
- [x] Password auth, sessions, lockout
- [x] Error envelope, trace ids, panic recovery
- [x] Outbox: transactional events, SKIP LOCKED claim, publisher loop
- [x] Email verification, password reset, email change (flows complete; the mail
      delivery path is courier's and is not wired)
- [x] OAuth (social login) as a CLIENT of Google and GitHub — `internal/oauth`
      plus two routes. No `goth`: this repository has no OAuth library dependency,
      and the previous version of this box claimed one.
- [x] Accounts, memberships, roles, invitations
- [x] OIDC provider (zitadel/oidc)
- [x] MFA: TOTP + recovery codes
- [x] Scoped API tokens (`cafaye_`-prefixed, four scopes, revocable, expiring)
- [ ] Admin API
- [x] Authorization matrix suite (route table × role × anonymous)

See [AGENTS.md](AGENTS.md) for the conventions this repository follows and
[CHANGELOG.md](CHANGELOG.md) for what has landed.
