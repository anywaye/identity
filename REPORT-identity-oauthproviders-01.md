# identity-oauthproviders-01 — Microsoft ships, Apple is a design

**Branch:** `worker/identity-w28-oauthproviders`
**Packet:** identity-w28 — a third and fourth social provider: Microsoft, then Apple
**Outcome:** Microsoft is wired end to end and committed. Apple did not fit the
budget with tests and is stopped at the design below, per the brief's instruction
to write the design rather than half-build the mechanism.

## What shipped

### 1. The enum migration — `migrations/00025_oauth_provider_microsoft.sql`

`ALTER TYPE oauth_provider ADD VALUE 'microsoft'`, and nothing else. The value is
the whole of the migration: a provider's endpoints are pinned in
`internal/oauth/endpoints.go`, its credentials are environment, and its closed-set
membership is `knownProviders` in `internal/oauth/provider.go`. The column is the
one place a provider name is *stored*, so it is the one place a new one has to be
declared.

**Only `microsoft`.** Apple's value is deliberately deferred. `knownProviders` and
the enum are held together by `TestKnownProvidersMatchesTheNamesTheEnumAccepts`,
which fails on a value in one and not the other — and an `apple` value with no
provider behind it would be a name the database accepts and no registry can
resolve: a deployment that configured it would serve a 404 for a provider its own
schema calls legitimate, and nothing would report the mismatch. Apple's value
arrives with Apple's packet, in the same migration that adds the provider.

**Two Postgres findings, both recorded in the migration's comments:**

- **`ADD VALUE` inside goose's transaction: fine.** PostgreSQL refuses
  `ALTER TYPE ... ADD VALUE` in a transaction block when the new value is then
  *used* in that same transaction (before PG 12 it refused it in a transaction at
  all). Goose wraps each migration in one. This migration adds the value and uses
  nothing, so the restriction never engages — verified by running `goose up`
  against the packet's own container. A future migration that added a value and
  immediately wrote a row with it would have to be split into two.
- **`DROP VALUE` does not exist.** PostgreSQL parses it and answers `0A000`,
  "dropping an enum value is not implemented". The only route is recreating the
  type, which means dropping `connected_accounts.provider` and its unique index
  with it. The Down is therefore empty with the reason stated, per the migrations
  README's rule for a migration that cannot be reversed. The practical consequence
  is in the comment: a deployment that needs to undo this backs up
  `connected_accounts` first and rebuilds the type by hand.

### 2. Microsoft — wired through every layer

| Layer | Change |
|---|---|
| `internal/oauth/endpoints.go` | `MicrosoftAuthorizeURL` / `MicrosoftTokenURL` / `MicrosoftUserInfoURL` — the `common` tenant, v2.0 endpoints, Graph's OIDC userinfo |
| `internal/oauth/provider.go` | `ProviderMicrosoft` constant, `knownProviders` entry, `Microsoft()` constructor, `providerByName` case |
| `internal/oauth/client.go` | `case ProviderMicrosoft` in the identity switch + `microsoftIdentity` decoder |
| `internal/oauth/settings.go` | `Microsoft ProviderSettings` field, `providers()` table row |
| `internal/config/config.go` | `OAUTH_MICROSOFT_CLIENT_ID` / `_CLIENT_SECRET` + three endpoint override variables, `oauthEndpointVars` rows, `loadOAuth` block |
| `internal/platform/oauthtest` | `Providers()` returns the Microsoft provider pointed at the fake |

**Scopes:** `openid email profile offline_access`. `offline_access` is a *scope*,
not a parameter — Microsoft's v2.0 platform issues a refresh token only when it is
asked for, the same reason Google's `access_type=offline` exists. There is no
`EmailsURL`: Microsoft's userinfo returns the address on the identity call, the
way Google's does.

**The trust model, which is the one real decision.** Microsoft's userinfo
endpoint does not return an `email_verified` claim. The reason is not that
Microsoft forgot: the `email` claim is present only for an address Microsoft
itself verified as part of the account, and the claim is a first-party statement
about that account rather than a user-entered string. So the decoder holds
Microsoft to GitHub's `/user` standard — the provider's identity call is trusted
to only ever carry a verified address — and not to Google's stricter one, because
the thing Google's check defends against (an account holder typing an arbitrary
address) is not a thing a Microsoft account can do. The reasoning is in the
`microsoftResponse` comment in `internal/oauth/client.go`, and the consequence —
if Microsoft ever serves an unverified address, this decoder would accept it —
is stated there rather than hidden.

**No OpenAPI or generated-client change.** The social routes are mounted
generically (`GET /v1/auth/oauth/{provider}` and its callback) and no document in
this repository declares a social-login operation — the routes are documented as
configuration-shaped. Adding a provider is a code-and-config change, not a
contract change. The generated client is untouched.

### 3. Tests

| Test | What it evidences |
|---|---|
| `TestClientIdentityReadsMicrosoft` (`internal/oauth/client_test.go`) | The happy path through the same fake server google and github use. **This is also the evidence the flow fails without its adapter**: `Client.Identity` switches on the provider name and the default branch answers `ErrUnknownProvider`, so removing `case ProviderMicrosoft` turns this test red — verified by removing the case and watching it fail with `unknown oauth provider: "microsoft" has no identity endpoint` |
| `TestAFreshMicrosoftIdentityCreatesTheAccount` (`internal/auth/social_test.go`) | The use-case happy path: a fresh Microsoft identity creates the user, the session, and a connected account keyed on `(microsoft, uid)` |
| `TestSettingsValidateRejectsAHalfConfiguredProvider` — new `microsoft without a secret` case | The startup failure on half-credentials, held to the same rule for the third provider |
| `TestLookupOnAnEmptyRegistryRefusesEverything` — `ProviderMicrosoft` added | The 404 for an unconfigured-but-known provider |
| `TestRegistryLookupDoesNotDistinguishUnconfiguredFromUnknown` — `ProviderMicrosoft` added | The unconfigured/unknown indistinguishability, for the third provider |
| `TestTheProviderDefinitionsAreFixed` — new `microsoft` row | The provider-specific invariants: name is the enum value, no extra authorize option (offline access is a scope, not a parameter), no emails endpoint, all three endpoints non-empty |
| `TestSettingsValidateAcceptsAWorkingConfiguration` — extended to three providers | The stable order claim now covers google, github **and** microsoft |
| `TestEveryOAuthEndpointHasAVariableAndEveryVariableHasAnEndpoint` and siblings (`internal/config/oauth_endpoints_test.go`) | The endpoint-override table walks in both directions for the third provider's three endpoints |
| `TestKnownProvidersMatchesTheNamesTheEnumAccepts` — **updated** | The enum reader now reads the `CREATE TYPE` in 00008 *and* the `ADD VALUE` in 00025, so the check's subject is the enum a migrated database actually has. A check that read only the CREATE TYPE would report agreement on the day a provider is added — the one day it is worth anything |

`bin/prime` is green against the packet's own container
(`TEST_DATABASE_URL=postgres://identity:cafaye@localhost:15528/identity?sslmode=disable`),
output pasted below.

## Apple — the design, stopped at the budget

Apple's `client_secret` is not a static secret. It is a JWT this service **signs**,
and that is a real mechanism with its own key management. It did not fit the
remaining budget with tests; this is the design, per the brief.

### The signing shape

The token endpoint (`https://appleid.apple.com/auth/token`) requires a
`client_secret` that is an ES256 JWT:

- **Header:** `{"alg": "ES256", "kid": "<the platform key's ID>"}`
- **Claims:** `iss` = the Apple Developer Team ID, `iat` = now, `exp` = now + up
  to 6 months (Apple's maximum), `aud` = `https://appleid.apple.com`, `sub` = the
  Services ID (the client ID)

The secret is valid for up to 6 months, so minting it **once at startup** and
caching it is the standard approach — no per-request signing, no key rotation
machinery. The minted JWT drops into the existing `Provider.ClientSecret` field,
so the exchange path (`oauth2Config`, `Client.Exchange`) needs **no change**.

### Where the key lives in config

Four new variables, following the existing per-provider pattern:

| Variable | Contents |
|---|---|
| `OAUTH_APPLE_CLIENT_ID` | The Services ID |
| `OAUTH_APPLE_TEAM_ID` | The Apple Developer Team ID |
| `OAUTH_APPLE_KEY_ID` | The platform key's ID (the JWT `kid`) |
| `OAUTH_APPLE_PRIVATE_KEY` | The .p8 PEM contents |

The secret is minted in `loadOAuth` (or a small helper in `internal/oauth`) from
the four inputs. If any one is missing, the provider is half-configured and
startup fails with `ErrIncompleteProvider` — the existing rule, unchanged. The
signing uses `go-jose/v4`, which is already a direct dependency (the OIDC
provider's `op.SigningKey` returns a `jose.SignatureAlgorithm`), so **no new
dependency**.

### The two real mechanism differences

1. **There is no userinfo endpoint.** The identity comes from the `id_token` — a
   JWT — in the token response. The client would need to: extract `id_token`
   from the response (`token.Extra("id_token")`), verify its signature against
   Apple's JWKS (`https://appleid.apple.com/auth/keys`), and read `sub` and
   `email` from the verified claims. That means an `IDToken` field on `Tokens`,
   a JWKS fetch-and-verify path, and a decoder that trusts a verified JWT claim
   rather than a userinfo call. None of it exists today, and it is the bulk of
   the work.
2. **`response_mode=form_post`.** Apple requires a POST callback when the `name`
   scope is requested. The honest scope for this service is `openid email` only
   — the name is not available on subsequent authorizations anyway — which keeps
   the callback a GET and the existing route unchanged. Requesting `name` would
   need a second, POST callback route.

### Two product decisions the design needs

- **Private email relay.** Apple's "Hide My Email" yields a
  `@privaterelay.appleid.com` address. It is verified by Apple and controlled by
  the user, so accepting it is the safe default — but it is a product call, not a
  security one.
- **The enum value.** Arrives with Apple's packet, in the same migration that adds
  the provider — for the reason the Microsoft migration's comment gives.

## What parlor needs to render the new buttons

The identity service's social routes are generic: `GET /v1/auth/oauth/{provider}`
starts the flow, and the callback is handled entirely by identity. So parlor's
work is:

1. **The provider list.** The buttons are google, github and now microsoft.
   Identity deliberately exposes no "list providers" endpoint — the 404 for an
   unconfigured provider is the same as for a nonexistent one, and that
   indistinguishability is the security property. So parlor's list is either
   hardcoded per deployment or set by parlor's own configuration; it is not
   something identity can tell it without breaking the 404 shape.
2. **The start URL for each button:** `GET /v1/auth/oauth/{provider}` with the
   provider name in the path. The button is a link, not a form.
3. **The callback is identity's.** Parlor renders no callback page; identity
   answers the callback with a session cookie and a JSON body (see
   `internal/httpapi/oauth.go`'s header for why it does not redirect to a landing
   page — that is a configured-destination decision for a later packet).

A follow-up packet in `parlor` owns the button rendering and the provider list.

## Gate output

```
$ TEST_DATABASE_URL="postgres://identity:cafaye@localhost:15528/identity?sslmode=disable" bin/prime
ok  	github.com/cafaye/identity/client	3.780s
?   	github.com/cafaye/identity/client/generated	[no test files]
ok  	github.com/cafaye/identity/cmd/identity	2.319s
ok  	github.com/cafaye/identity/internal/accounts	16.359s
ok  	github.com/cafaye/identity/internal/admin	5.427s
ok  	github.com/cafaye/identity/internal/apikeys	13.379s
ok  	github.com/cafaye/identity/internal/auth	11.257s
ok  	github.com/cafaye/identity/internal/config	0.561s
ok  	github.com/cafaye/identity/internal/courier	1.130s
ok  	github.com/cafaye/identity/internal/deletion	1.041s
ok  	github.com/cafaye/identity/internal/httpapi	50.262s
ok  	github.com/cafaye/identity/internal/mfa	17.004s
ok  	github.com/cafaye/identity/internal/oauth	5.023s
ok  	github.com/cafaye/identity/internal/oidc	3.110s
ok  	github.com/cafaye/identity/internal/outbox	4.479s
ok  	github.com/cafaye/identity/internal/platform/ci	4.007s
ok  	github.com/cafaye/identity/internal/platform/clock	1.073s
ok  	github.com/cafaye/identity/internal/platform/db	0.617s
?   	github.com/cafaye/identity/internal/platform/dbtest	[no test files]
ok  	github.com/cafaye/identity/internal/platform/id	0.959s
ok  	github.com/cafaye/identity/internal/platform/oauthtest	0.978s
ok  	github.com/cafaye/identity/internal/recovery	11.778s
ok  	github.com/cafaye/identity/internal/sessions	1.351s
ok  	github.com/cafaye/identity/internal/telemetry	0.784s
ok  	github.com/cafaye/identity/internal/tenancy	0.849s
ok  	github.com/cafaye/identity/internal/useraudit	2.486s
ok  	github.com/cafaye/identity/internal/users	1.447s
```

`go vet ./...` and `gofmt -l .` are clean. The database container
(`identity-w28-pg`, port 15528) is left running for the manager to reclaim.
