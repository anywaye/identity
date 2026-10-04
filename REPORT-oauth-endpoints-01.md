# REPORT — identity: make OAuth provider endpoints overridable from the environment

Branch `worker/oauth-endpoints-01` in `wt-oauth-endpoints-01`. Three commits, no
push, no merge, no other worktree touched.

```
fbee699 docs: the endpoint overrides in the variable table, and how a local stack aims them
9ce8097 config: read the endpoint overrides, and name the variable that was refused
55e10fa oauth: let the environment point the provider endpoints anywhere
```

## What I built

Seven variables, each overriding one provider endpoint, defaulting to the URL this
service already dialled.

| Variable | Default |
|---|---|
| `OAUTH_GOOGLE_AUTHORIZE_URL` | `https://accounts.google.com/o/oauth2/v2/auth` |
| `OAUTH_GOOGLE_TOKEN_URL` | `https://oauth2.googleapis.com/token` |
| `OAUTH_GOOGLE_USERINFO_URL` | `https://openidconnect.googleapis.com/v1/userinfo` |
| `OAUTH_GITHUB_AUTHORIZE_URL` | `https://github.com/login/oauth/authorize` |
| `OAUTH_GITHUB_TOKEN_URL` | `https://github.com/login/oauth/access_token` |
| `OAUTH_GITHUB_USERINFO_URL` | `https://api.github.com/user` |
| `OAUTH_GITHUB_EMAILS_URL` | `https://api.github.com/user/emails?per_page=100` |

**`internal/oauth/endpoints.go` (new, 223 lines).** The seven defaults are named
constants there, and `Google()` / `GitHub()` now read them — so there is exactly one
definition of Google's authorize URL in the repository, and an override that
re-typed one would be the second spelling. The same file holds
`ProviderEndpoints` (the override struct), the one `overrides()` list that both
`applyTo` and `validate` walk, `ErrInvalidEndpoint`, `EndpointError` and
`validateEndpointURL`.

**`internal/oauth/settings.go`.** `ProviderSettings` gains `Endpoints`;
`Validate` refuses an undialable override; `Providers()` applies them onto the
definition before the credentials go on. `Validate` and `Providers` now share one
`providers()` table rather than `Validate`'s anonymous slice and `Providers`'
positional pairing with a credentials map, because `validate` has to know *which*
provider an override names before it can tell whether that provider has that
endpoint at all.

**`internal/config/config.go`.** Seven constants, one `oauthEndpointVars` table
used twice (read the block, name the variable in a refusal), and
`oauthEndpointVariable`, which turns the `*EndpointError`'s provider+field into
`OAUTH_GOOGLE_TOKEN_URL`.

**Docs.** The `OAUTH_*` rows in README's variable table — which did not exist at all,
so the six credential variables the previous packet reads were in no table either —
plus a paragraph in the social-login section, and a commented block in
`docker-compose.yml` where the fake-IdP packet will look.

### The rules, and where they are held

- **Absent is a supported state.** An unset (or present-but-empty, which is how
  compose passes an unset variable) field keeps the default:
  `TestAnAbsentEndpointOverrideKeepsTheDefaultsAndBoots`.
- **Present but wrong fails startup, naming the variable.** Not a fallback: a
  deployer who set `OAUTH_GOOGLE_TOKEN_URL` and silently got Google's real endpoint
  would have a *working* sign-in flow pointing somewhere they did not choose,
  holding this service's client secret, with no way to find out.
  `TestAMalformedEndpointOverrideFailsStartupNamingTheVariable` (7 variables × 4
  malformed values), `TestAMalformedEndpointOverrideIsRefusedAndNamesTheEndpoint`.
- **Deployment config, never per-request.** `applyTo` runs once on the value
  `Settings.Providers()` built at startup; nothing mutates a `Provider` afterwards.
  There is no route, header or query parameter in the path — the authorize URL is
  `provider.AuthCodeURL(state, provider.RedirectURI(o.social.RedirectBase()))` at
  `internal/httpapi/oauth.go:212`, and that redirect URI comes from the registry's
  configured base, not the request. I did not add a test at the HTTP layer for
  this; see *What I deliberately did not do*.
- **A query is allowed, a fragment is not.** GitHub's own default carries
  `?per_page=100`, so a rule refusing queries would refuse the default this service
  ships with; a fragment is never sent to a server, so accepting one would make the
  override silently a different URL from the one written.
  `TestAQueryIsAllowedAndAFragmentIsNot`.
- **An override for an endpoint a provider does not have is refused**, not ignored.
  Google returns the address on the identity call, so there is no `/user/emails` to
  point anywhere; a variable that existed for it would be a lie in the table rather
  than a feature. `TestAnOverrideForAnEndpointAProviderDoesNotHaveIsRefused`.
- **An override changes no other part of a provider** — not the name, not the
  scopes, not Google's `access_type=offline`:
  `TestAnOverrideChangesNoOtherPartOfAProvider`, plus its own test because the
  offline option is invisible in any URL comparison.
- **`knownProviders` is untouched.** An unlisted name is still a 404, not a lookup,
  so an unknown provider and an unconfigured one stay indistinguishable. The
  completeness walks go the other way from that rule on purpose: `oauthEndpointVars`
  is walked in **both** directions against the definitions
  (`TestEveryOAuthEndpointHasAVariableAndEveryVariableHasAnEndpoint`), and the
  settings table against `knownProviders` in both directions
  (`TestEveryProviderThisServiceOffersIsInTheTable`). A missing endpoint variable
  fails a deploy; a missing *provider name* in a config table is silent, because the
  provider still builds and still signs in.

## Tests — exact command and real output

```sh
go test -count=1 ./internal/oauth/... ./internal/config/...
```

```
ok  	github.com/cafaye/identity/internal/oauth	1.236s
ok  	github.com/cafaye/identity/internal/config	0.762s
```

Also run: `go build ./...`, `go vet ./internal/config/... ./internal/oauth/...`,
`gofmt -l internal/config internal/oauth` (both silent). `docker-compose.yml` parses
(`ruby -ryaml` — the compose stack itself needs `kit.ref` merged, which it is not
here).

The tier reports **10 `--- SKIP:`** lines — `internal/oauth/store_test.go`, the
database tier, because this machine has no `TEST_DATABASE_URL`. Those are pre-existing
and unrelated to this packet; CI fails on any `--- SKIP:` line and runs the tier
above `goose up`. Every test I added passes without a database.

**The defaults regression guard**, which is the one that matters most:
`TestUnsetOverridesLeaveTheShippedEndpointsAndParameters` spells all seven literals
out again *in the test* rather than comparing to the constants — a test comparing a
default to its own definition passes when the definition is wrong.
`TestWithNoOverridesSetTheOnlyOutboundCallsAreTheShippedEndpoints` goes further and
records the URLs actually dialled through a refusing `RoundTripper`: with nothing
set, the only addresses this process asks for are Google's token and userinfo
endpoints and GitHub's token and `/user`.

### Mutation checks (injected, then reverted)

| Injected fault | What turned red |
|---|---|
| `GoogleAuthorizeURL` → `…/MUTATED/auth` | the defaults guard, the "unset keeps the default" test, the authorize-URL test |
| `applyTo` made a no-op | the wire test (`TokenUserInfoAndEmailsOverrides…`) and the authorize-URL test |
| `oauthEndpointVariable` forced to return `""` | the naming test — and, because it checks `errors.Is(err, oauth.ErrInvalidEndpoint)` too, the `%w` chain |
| the `OAUTH_GITHUB_EMAILS_URL` row deleted from the table | `TestEveryOAuthEndpointHasAVariableAndEveryVariableHasAnEndpoint`: *"github.EmailsURL is an endpoint this service dials and no variable sets it"* |

One assertion I wrote was **wrong and the test caught it**: my first version of the
"nothing is dialled" test asserted that no request is made at all. It failed, showing
x/oauth2 asks for a token twice (once per client-auth style) and that GitHub's
`/user/emails` is only reached after `/user` answers — so the test now compares the
set of URLs actually dialled, which is the stronger claim anyway.

## What I deliberately did not do

- **No change to `knownProviders`, the registry, the routes, the OpenAPI documents,
  or the 404 shape.** No new provider, no "configured but not usable" error, no
  error text naming a provider's existence.
- **No per-request, per-header or per-route override, and no "test mode".** A flag
  that turns on non-production endpoints per request would be the SSRF the brief
  names; the variables are read once, which is what makes them safe.
- **No HTTP-layer test for the SSRF property.** It belongs in `internal/httpapi`
  (drive `GET /v1/auth/oauth/google?redirect_uri=…&host=…` against a registry with an
  override and assert the `Location` host), which is outside the narrow tier this
  packet was given. The property holds by construction today
  (`internal/httpapi/oauth.go:212`, above) and is not asserted anywhere. **This is the
  one real gap** — see the handoff.
- **No discovery of the endpoints from the provider's
  `.well-known/openid-configuration`.** `Google()`'s argument for pinning survives
  being configurable: what changed is who a deployment trusts, not what it trusts by
  default.
- **No change to `internal/platform/oauthtest`.** Its `Server.Provider` still
  rewrites the four fields on a `Provider` literal, which is right for an in-process
  test and now also has a real-process equivalent.
- **No full gate.** `go test ./...` needs Postgres (`internal/mfa` fails rather than
  skips without it); the manager runs the whole gate on the merged result.
- **I did not fix the stale paragraph in `internal/oauth/settings.go`** that claimed
  nothing constructs a `Settings` — it was already false before this packet
  (`loadOAuth` has built one on every `Load` for a packet). I replaced it with the
  truth and the record of the falsehood, because I was editing the file and a false
  claim about a live path is what the repository's own history section is about.

## For the next packet — pointing a real identity at a fake IdP

This is what the packet was blocked on, so in the order you will hit it:

1. **Set all four for the provider you are faking.** The authorize URL is a *browser*
   redirect, so the fake IdP has to be reachable from the browser (Playwright), not
   just from identity's container. The token, userinfo and emails URLs only need to be
   reachable from identity. In compose, `http://` is accepted for all of them
   (`validateEndpointURL` allows `http` and `https`).
2. **Both halves of the credentials are required**, or the routes are not mounted at
   all and you get a clean 404 rather than a redirect:
   `OAUTH_GOOGLE_CLIENT_ID` + `OAUTH_GOOGLE_CLIENT_SECRET` (or the GitHub pair).
   `OAUTH_ENCRYPTION_KEY` must be standard base64 of exactly 32 raw bytes, and
   `OAUTH_REDIRECT_BASE_URL` must be set whenever a provider is.
3. **Restart after setting them.** They are read once, in `config.Load`.
4. **`OAUTH_REDIRECT_BASE_URL` is where the browser returns to, and it must be the
   origin serving the app**, because the callback sets the session cookie there. If
   it names identity's own address instead, the round trip completes and the last
   step fails — or worse, sets the cookie on the wrong origin. This is the deployment
   fact the packet exists to make testable, and now it is testable.
5. **A malformed value is a boot failure naming the variable**, so a typo shows up as
   `invalid OAuth configuration: OAUTH_GOOGLE_TOKEN_URL: the google endpoint override
   TokenURL is not usable: scheme "" is not http or https` rather than as a sign-in
   that mysteriously keeps working.
6. **There is no `OAUTH_GOOGLE_EMAILS_URL`** and setting an equivalent on Google
   fails the boot. The fake IdP must return the address from the identity call for
   Google, and may return `email: null` from GitHub's `/user` to exercise the emails
   call.
7. What the fake must answer, since these are the shapes `internal/oauth` decodes:
   `/token` form-encoded (`access_token`, `token_type`, optional `refresh_token`,
   `expires_in`); Google's userinfo with `sub`, `email`, `email_verified: true`; and
   GitHub's `/user` with a numeric `id` plus `login`. `internal/oauth/endpoints_test.go`
   has a working `fakeProvider` that answers all four, and
   `internal/platform/oauthtest` is the fuller version if you need the error paths.

## Handoff

1. **The full gate, on a machine with Postgres** — not run here, it needs a database:

   ```sh
   docker compose up -d --wait postgres
   goose -dir migrations postgres "$DATABASE_URL" up
   TEST_DATABASE_URL="postgres://identity:cafaye@localhost:5432/identity?sslmode=disable" bin/prime
   go vet ./... && gofmt -l . && go test -race ./...
   ```

   `gofmt -l .` will print `internal/platform/ci/rollback_test.go`. **That is
   pre-existing** — committed in `55b4441`, untouched by this packet. Flag it, do not
   fold it into this branch.
2. **The one missing assertion: the endpoints cannot be reached from a request.**
   Suggested location `internal/httpapi/oauth_endpoints_test.go`: build a registry
   from a `Settings` with credentials and every endpoint pointed at an
   `httptest.Server`, mount the social routes, request
   `GET /v1/auth/oauth/google?redirect_uri=https://evil.test&host=evil.test`, and
   assert the `Location` is the override's host, the `redirect_uri` query parameter is
   the configured base's, and `evil.test` was never dialled. `internal/httpapi` cannot
   import `internal/platform/oauthtest` (cycle), so the fake is `httptest` directly —
   or the assertion belongs in `internal/oauth`, which has no request to offer.
3. **The fake-IdP packet itself** — unblocked. Nothing above depends on it.
