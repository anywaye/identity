# identity-appleoauth-01 — Apple ships, the fourth provider

**Branch:** `worker/identity-w30-apple`
**Packet:** identity-w30 — a fourth social provider: Apple
**Outcome:** Apple is wired end to end and committed. Both of Apple's
mechanisms — the client_secret this service **signs** and the id_token it
**verifies** — are implemented with their negative tests, and the enum value
lands in the same migration as the provider.

## Where the work was when this attempt started

The previous attempt left substantial uncommitted work in the worktree. It was
mostly right and is kept: the secret minting (`internal/oauth/apple.go`), the
id_token verifier, the migration, the provider wiring, the config variables and
the oauthtest fake were all present and correct in shape. Four things were
wrong or missing, and this attempt fixed them:

1. **A compile error** in `internal/oauth/apple_test.go` — `iat < now - 60`
   compared a `float64` to an `int64`. The package did not build.
2. **Stale "apple"-as-unknown-provider examples.** Now that `apple` is a real
   provider, every test that used the string `"apple"` to mean "a provider
   this service has never heard of" was wrong. `store_test.go` used it as an
   out-of-enum value (the test failed: the enum now accepts `apple`);
   `provider_test.go`, `settings_test.go` and a `provider.go` comment used it
   as an unknown name. All now use `"netflix"`.
3. **No endpoint-override variables.** Brief §4 says config.go gets
   "`oauthEndpointVars` rows" and to wire "exactly as microsoft did". The
   partial work added none, which left
   `TestEveryOAuthEndpointHasAVariableAndEveryVariableHasAnEndpoint` silently
   skipping Apple. Added `OAUTH_APPLE_AUTHORIZE_URL` and `OAUTH_APPLE_TOKEN_URL`
   (see the JWKS decision below for why there is no `OAUTH_APPLE_JWKS_URL`).
4. **No use-case happy path.** The W28 report listed
   `TestAFreshMicrosoftIdentityCreatesTheAccount` as the evidence that the
   provider name reaches the store. Added the Apple equivalent.

## What shipped

### 1. The secret — an ES256 JWT, minted once

`oauth.MintAppleClientSecret` (`internal/oauth/apple.go`) signs Apple's
`client_secret`: an ES256 JWT with header `{"alg":"ES256","kid":<key id>}` and
claims `iss`=team id, `iat`=now, `exp`=now+180 days, `aud`=`https://appleid.apple.com`,
`sub`=services id. It is minted **once at startup** in `loadOAuth` and cached —
the secret is valid for months, so there is no per-request signing and no
rotation machinery. The minted JWT drops into `Settings.Apple.ClientSecret`, so
`oauth2Config` and `Client.Exchange` needed **no change**. Signing uses
`go-jose/v4`, already a direct dependency — **no new dependency**.

Four credential variables, following the existing per-provider pattern:
`OAUTH_APPLE_CLIENT_ID` (Services ID), `OAUTH_APPLE_TEAM_ID`,
`OAUTH_APPLE_KEY_ID`, `OAUTH_APPLE_PRIVATE_KEY` (the `.p8` PEM contents). An
empty input is the supported absent state (`"", nil`); a **partial** input is
the half-configured refusal — `ErrIncompleteProvider`, the existing rule
unchanged. An unparseable private key is a startup failure naming the variable.

### 2. The identity — verify the `id_token`, which is the whole of the risk

Apple has **no userinfo endpoint**. The identity comes from the `id_token` in the
token response, so the trust model is the OIDC one: the claims are trusted
because Apple's own published key signed them, not because this service asked
Apple about them with a bearer token. That is a **stronger** guarantee than the
userinfo call gets.

`Client.Exchange` extracts `id_token` from the response (`token.Extra("id_token")`)
into a new `Tokens.IDToken` field, for every provider — an id_token this service
does not use is inert. `Client.Identity` gained a `case ProviderApple` that
calls `appleIdentity`, which:

1. refuses a response with no id_token (`ErrProviderUnavailable`),
2. parses the JWT with an **allowed-algorithm list** (`ES256` only) — the
   algorithm-confusion defence,
3. looks up the key by the token's **own `kid`** in Apple's JWKS,
4. verifies the signature against that key,
5. checks `iss`, `aud` (against this service's client id) and `exp`,
6. refuses an explicit `email_verified: false` (`ErrNoEmail`),
7. reads `sub` and `email` from the **verified** claims only.

The JWKS fetch (`getJWKS`) is bounded by `maxIdentityBytes` and every failure is
`ErrProviderUnavailable` — from here a JWKS endpoint that cannot be read is
indistinguishable from one that is down.

**`response_mode=form_post` is avoided by scope, not by a second route.** Apple
requires a POST callback only when the `name` scope is requested. The honest
scope here is `openid email` — the name is not available on later authorizations
anyway — so the callback stays a GET and the existing route is unchanged.
Requesting `name` would mean a second, POST callback route and a name this
service could display once and never again.

### 3. The enum value, in the same migration as the provider

`migrations/00026_oauth_provider_apple.sql` — `ALTER TYPE oauth_provider ADD
VALUE 'apple'`, and nothing else, in the same migration that adds the provider.
The migration's comment records the two Postgres findings from 00025 (`ADD
VALUE` inside goose's transaction is fine because the value is used nowhere in
the same transaction; `DROP VALUE` does not exist, so the Down is empty with the
reason stated) and why the value and the provider land together:
`TestKnownProvidersMatchesTheNamesTheEnumAccepts` holds `knownProviders` and the
enum together, and a value in one and not the other is a name the database
accepts and no registry can resolve.

### 4. Wiring, per layer

| Layer | Change |
|---|---|
| `internal/oauth/endpoints.go` | `AppleAuthorizeURL` / `AppleTokenURL` / `AppleJWKSURL` — pinned, like the other three |
| `internal/oauth/provider.go` | `ProviderApple` constant, `knownProviders` entry, `Apple()` constructor, `providerByName` case, `JWKSURL` field |
| `internal/oauth/apple.go` | `MintAppleClientSecret`, `appleIdentity`, `verifyAppleIDToken`, `getJWKS` |
| `internal/oauth/client.go` | `Tokens.IDToken` field, `id_token` extraction in `Exchange`, `case ProviderApple` in the identity switch |
| `internal/oauth/settings.go` | `Apple ProviderSettings` field, `providers()` table row |
| `internal/config/config.go` | four credential variables + `OAUTH_APPLE_AUTHORIZE_URL` / `OAUTH_APPLE_TOKEN_URL`, two `oauthEndpointVars` rows, `loadOAuth` block |
| `internal/platform/oauthtest` | ES256 keypair, JWKS endpoint, id_token minting, `WithUnpublishedKey`, `Providers()` returns Apple |

**No OpenAPI or generated-client change.** The social routes are mounted
generically and no document declares a social-login operation.

### The JWKS decision — the one endpoint that is NOT overridable

There is deliberately **no `OAUTH_APPLE_JWKS_URL`**. The JWKS document is the
**trust root** for Apple's id_token — the one provider whose identity this
service verifies against a published key rather than reads from a userinfo
call. A deployment that could point it anywhere could point it at a key document
of its own, and then the id_token it verifies would be one the deployment signed
itself: a complete authentication bypass. The authorize and token URLs carry no
such power, because an id_token returned by whichever token endpoint is still
verified against the **pinned** Apple JWKS before a single claim is read. So
Apple's key document is the one endpoint this service refuses to let a deployment
choose. The two overridable endpoints follow the same pattern as the other three
providers, and `TestEveryOAuthEndpointHasAVariableAndEveryVariableHasAnEndpoint`
now walks all four providers in both directions.

## The private email relay — a product call, recorded not refused

Apple's "Hide My Email" yields a `@privaterelay.appleid.com` address. It is
verified by Apple and controlled by the user, so **accepting it is the default**
and that is what shipped: the address is read from the verified id_token like any
other and passes through the same `users.ValidateEmail` normalization. The
decision is recorded here rather than silently either accepting or rejecting it
because it is a product call, not a security one — if the fleet ever wants to
distinguish relay addresses (to display them differently, or to refuse them for
some flow), that is a deliberate change to `appleIdentity`, not a config flag.

## Tests

| Test | What it evidences |
|---|---|
| `TestMintAppleClientSecret` (`internal/oauth/apple_test.go`) | The minted secret's shape: header `alg`/`kid`, claims `iss`/`aud`/`sub`, the `exp` bound (future, no further out than 180 days), `iat` about now, and the signature verifies against the public key |
| `TestMintAppleClientSecretRefusesAHalfConfiguredInput` | Each of the four inputs missing in turn → `ErrIncompleteProvider` |
| `TestMintAppleClientSecretWithNoInputs` | The empty input is the supported absent state, not an error |
| `TestMintAppleClientSecretRefusesABadPrivateKey` | An unparseable key is a startup failure |
| `TestClientIdentityReadsApple` (`internal/oauth/client_test.go`) | The happy path: exchange extracts the id_token, identity fetches the JWKS and verifies before reading a claim. Also the evidence the flow fails without its adapter |
| `TestClientIdentityRefusesAnAppleIDTokenSignedByAnUnpublishedKey` | **The negative test that proves the verifier verifies.** The fake signs with a key its JWKS does not publish; the verifier finds no key for the kid and refuses. A token signed by a key Apple does not publish is a token Apple did not sign |
| `TestClientIdentityRefusesAnAppleIDTokenWithNoIDToken` | A response with no id_token is not an identity, and the JWKS is not even fetched |
| `TestAppleCredentialsAreMintedAtLoad` (`internal/config/oauth_apple_test.go`) | The four inputs mint a secret at `Load`, and the built provider carries it |
| `TestAHalfConfiguredAppleProviderFailsStartup` | Some of the four and not all → `ErrInvalidOAuth` wrapping `ErrIncompleteProvider` |
| `TestAnUnparseableApplePrivateKeyFailsStartup` | A bad key fails the boot naming the variable |
| `TestAppleEndpointOverridesReachTheBuiltProvider` | The two overrides reach the built provider; the JWKS URL stays pinned |
| `TestWithNothingSetApplesEndpointsAreTheDefinitions` | With nothing overridden, Apple's endpoints are the definitions |
| `TestAFreshAppleIdentityCreatesTheAccount` (`internal/auth/social_test.go`) | The use-case happy path: a fresh Apple identity creates the user, the session, and a connected account keyed on `(apple, uid)` |
| `TestSettingsValidateRejectsAHalfConfiguredProvider` — new `apple without a secret` case | The startup failure on half-credentials, held to the same rule for the fourth provider |
| `TestLookupOnAnEmptyRegistryRefusesEverything` / `TestRegistryLookupDoesNotDistinguishUnconfiguredFromUnknown` — `ProviderApple` added | The 404 for an unconfigured-but-known provider, for the fourth provider |
| `TestTheProviderDefinitionsAreFixed` — new `apple` row | Name is the enum value, no extra authorize option, no userinfo endpoint, JWKSURL non-empty |
| `TestSettingsValidateAcceptsAWorkingConfiguration` — extended to four providers | The stable order claim now covers google, github, microsoft **and** apple |
| `TestEveryOAuthEndpointHasAVariableAndEveryVariableHasAnEndpoint` — **updated** | The walk now covers all four providers in both directions, so Apple's two overridable endpoints are checked and the absence of a JWKS override is the design |
| `TestKnownProvidersMatchesTheNamesTheEnumAccepts` — **updated** | The enum reader now reads the `CREATE TYPE` in 00008 **and** the `ADD VALUE` in 00025 **and** 00026 |

`bin/prime` is green against the packet's own container
(`TEST_DATABASE_URL=postgres://identity:cafaye@localhost:15528/identity?sslmode=disable`),
output pasted below. `go vet ./...`, `gofmt -l .` and `go test -race ./...` are
clean.

## What parlor needs to render the new button

The identity service's social routes are generic, so parlor's work is:

1. **The provider list.** The buttons are google, github, microsoft and now
   apple. Identity deliberately exposes no "list providers" endpoint — the 404
   for an unconfigured provider is the same as for a nonexistent one — so
   parlor's list is hardcoded per deployment or set by parlor's own
   configuration.
2. **The start URL:** `GET /v1/auth/oauth/{provider}` with the provider name in
   the path. The button is a link, not a form.
3. **The callback is identity's.** Parlor renders no callback page.

A follow-up packet in `parlor` owns the button rendering and the provider list.

## Gate output

```
$ TEST_DATABASE_URL="postgres://identity:cafaye@localhost:15528/identity?sslmode=disable" bin/prime
ok  	github.com/cafaye/identity/client	3.835s
?   	github.com/cafaye/identity/client/generated	[no test files]
ok  	github.com/cafaye/identity/cmd/identity	3.246s
ok  	github.com/cafaye/identity/internal/accounts	32.362s
ok  	github.com/cafaye/identity/internal/admin	7.242s
ok  	github.com/cafaye/identity/internal/apikeys	26.098s
ok  	github.com/cafaye/identity/internal/auth	21.478s
ok  	github.com/cafaye/identity/internal/config	0.612s
ok  	github.com/cafaye/identity/internal/courier	1.276s
ok  	github.com/cafaye/identity/internal/deletion	1.275s
ok  	github.com/cafaye/identity/internal/httpapi	98.415s
ok  	github.com/cafaye/identity/internal/mfa	30.457s
ok  	github.com/cafaye/identity/internal/oauth	8.371s
ok  	github.com/cafaye/identity/internal/oidc	3.381s
ok  	github.com/cafaye/identity/internal/outbox	5.924s
ok  	github.com/cafaye/identity/internal/platform/ci	4.551s
ok  	github.com/cafaye/identity/internal/platform/clock	0.521s
ok  	github.com/cafaye/identity/internal/platform/db	0.599s
?   	github.com/cafaye/identity/internal/platform/dbtest	[no test files]
ok  	github.com/cafaye/identity/internal/platform/id	0.599s
ok  	github.com/cafaye/identity/internal/platform/oauthtest	0.841s
ok  	github.com/cafaye/identity/internal/recovery	29.946s
ok  	github.com/cafaye/identity/internal/sessions	1.564s
ok  	github.com/cafaye/identity/internal/telemetry	0.657s
ok  	github.com/cafaye/identity/internal/tenancy	0.874s
ok  	github.com/cafaye/identity/internal/useraudit	5.603s
ok  	github.com/cafaye/identity/internal/users	1.613s
```

The database container (`identity-w30-pg`, port 15528) is left running for the
manager to reclaim.
