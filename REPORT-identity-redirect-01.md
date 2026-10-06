# REPORT — identity-redirect-01

**Worktree:** `identity-w29-redirect` · **branch:** `worker/identity-w29-redirect`
**Packet:** the redirect-after-sensitive-change rule as a pure function

## 0. The short version

`internal/redirect` is a new package with one function, `Allow(target string) bool`,
and one table test. It answers one question — *may the post-change redirect go to
this URL?* — with no database, no HTTP and no clock, so any service in the fleet
can copy or import it without ceremony. **Zero wiring**: no route, handler or
response shape was changed. The deliverable is the function and its table, so
that wiring it later is a one-line change per route rather than a security
review per route.

The rule: **same-origin relative paths are allowed; everything else is refused.**
The allowed set is exactly one shape — a string that begins with a single `/` —
and the implementation is three prefix checks.

| | |
|---|---|
| new package | `internal/redirect` (1 import: `strings`) |
| new exported symbols | 1 (`Allow`) |
| table cases | 17 (4 allowed, 13 refused) |
| routes changed | **0** |
| gate | `bin/prime` green, 25 packages (24 before + this one) |

## 1. The rule, and why it is that rule

`Allow` returns true only for a string that begins with exactly one `/`:

| shape | answer | why |
|---|---|---|
| `/ok` | allowed | a same-origin path |
| `/ok?next=https://evil.test` | allowed | the path is same-origin; the query is the caller's separate decision |
| `https://evil.test/x` | refused | an absolute URL names its own origin |
| `//evil.test/x` | refused | protocol-relative — another origin in a path's clothes |
| `/\evil.test` | refused | the WHATWG parser folds `\` to `/` for special schemes, so this *is* `//evil.test` in a standard browser — and Go's `url.Parse` does not fold it, so a check written against Go's parser alone waves it through |
| `https://identity.example.com/x` | refused | a lookalike host; resemblance is the attack |
| `https://identity.cafaye.com/x` | refused | the product's *own* host, still refused — see below |
| `""` | refused | the caller applies its own default; the helper never invents a destination |

**"Same-origin" means RELATIVE, and that is a choice with a reason.** The
function is pure: no request, no Host header, no configured origin to compare
against. An absolute URL therefore cannot be answered "yes" honestly even when
the host is exactly the product's, and a host allow-list would be a second
thing to get stale, per deployment and per environment. The OIDC client table
is the only allow-list of hosts this service keeps, and it is per-client by
design. A relative path is the one shape that cannot name another host, so a
relative path is the only shape allowed.

**The query string is not this function's decision.** `/ok?next=https://evil.test`
is allowed because the path is same-origin; what the caller does with `next` is
the caller's own policy, and this package does not have the context to make it.

**The empty string is refused, with a documented default.** The package comment
states the convention — the caller substitutes its own default, conventionally
`/` — and the helper never substitutes one itself: a default chosen here would
be inherited by every future caller, reviewed or not, and a silent safe answer
is the thing this package exists to eliminate.

The table also pins the bypass classes a naive check misses: `///evil.test/x`
(the WHATWG special-authority-ignore-slashes state skips the extra slashes),
`\/evil.test` and `\\evil.test/x` (backslash folds with no leading slash to
catch), `  //evil.test/x` (browsers strip leading whitespace before parsing, so
the browser sees a protocol-relative URL where the string says something else),
`ok` (a bare relative reference — same-origin only after the browser resolves
it against the request path, which this function cannot see), and
`javascript:alert(1)` (a scheme is not a path).

## 2. Routes that should adopt the helper next

None of these routes accepts a caller-supplied redirect today — that is the
current design, and `internal/recovery/recovery.go:136` and
`internal/httpapi/sessionlinks.go:229` say so in comments that were written
before this helper existed. They are named here in the order they should adopt
it, by the risk of the day they grow a `redirect` parameter:

1. **`POST /v1/session-links/redeem`** — the highest-risk adoption because the
   route is **public**: it mints a browser session from a token in the request
   body. A `redirect` here would be a value this service stores about somebody
   else's front end and hands back on a route with no credential attached. If
   it ever grows one, `redirect.Allow` is the whole check.

2. **`GET /v1/auth/oauth/:provider/callback`** — the OAuth round trip ends with
   the browser holding a session (or a `202` sending it to MFA). A `return_to`
   parameter is the classic open-redirect vector on exactly this route, and
   the state cookie is the only thing authenticating the round trip.

3. **`POST /v1/password-resets/confirm`** — sets a new password and revokes
   every session and live access token in one transaction. The response already
   says "sign in again"; a `redirect` back to where the user came from is the
   natural next product request, and it arrives on a route whose whole job is
   invalidating credentials.

4. **`POST /v1/mfa/enrollments/:id/confirm`** — makes a factor live and revokes
   every session. Same shape as above: a sensitive change, then the browser
   lands somewhere.

5. **`POST /v1/email-verifications/confirm`** and **`POST /v1/email-changes/*`**
   — the mail-link flows. The link is the credential and the landing page is
   the caller's; these are the routes where a `redirect` would most plausibly
   be added "for convenience", which is why the helper should already exist.

**Already safe, and why they do not need the helper:** `/oidc/authorize` and the
OIDC token endpoint redirect only to `redirect_uri` values allow-listed at
client registration (exact match, `TestOIDCRedirectURINotOnTheAllowList`), and
the login hop goes to `OIDC_LOGIN_UI_URL`, which is configured at deploy time
and validated at startup (`internal/oidc/loginui.go`). Neither target is
caller-supplied at request time.

## 3. Gate

`bin/prime` against the packet's own container (`identity-w29-pg`, port 15519),
`TEST_DATABASE_URL` set, full output in §4. `go vet ./...` and `gofmt -l .`
clean; `go test -race -count=1 -p 4 ./...` green.

One environment note: the container is a plain `postgres:17.6` with no kit init
script, so the `identity_app` LOGIN role that kit's cluster normally provisions
(`templates/compose/postgres/initdb/10-cluster.sh`) did not exist, and migration
`00016_account_isolation.sql` failed at `cafaye.protect_table` until it was
created. The role was provisioned the way kit provisions it (`LOGIN`,
`NOSUPERUSER`, `NOCREATEDB`, `NOCREATEROLE`, `NOREPLICATION`, granted to
`identity` so the owner can impersonate the weaker role). The container is
left running for the manager to reclaim.

## 4. `bin/prime` output

```
ok  	github.com/cafaye/identity/client	3.554s
?   	github.com/cafaye/identity/client/generated	[no test files]
ok  	github.com/cafaye/identity/cmd/identity	2.166s
ok  	github.com/cafaye/identity/internal/accounts	22.443s
ok  	github.com/cafaye/identity/internal/admin	6.144s
ok  	github.com/cafaye/identity/internal/apikeys	23.065s
ok  	github.com/cafaye/identity/internal/auth	16.102s
ok  	github.com/cafaye/identity/internal/config	0.616s
ok  	github.com/cafaye/identity/internal/courier	1.213s
ok  	github.com/cafaye/identity/internal/deletion	1.261s
ok  	github.com/cafaye/identity/internal/httpapi	84.073s
ok  	github.com/cafaye/identity/internal/mfa	21.009s
ok  	github.com/cafaye/identity/internal/oauth	3.524s
ok  	github.com/cafaye/identity/internal/oidc	2.349s
ok  	github.com/cafaye/identity/internal/outbox	4.496s
ok  	github.com/cafaye/identity/internal/platform/ci	5.719s
ok  	github.com/cafaye/identity/internal/platform/clock	0.557s
ok  	github.com/cafaye/identity/internal/platform/db	0.858s
?   	github.com/cafaye/identity/internal/platform/dbtest	[no test files]
ok  	github.com/cafaye/identity/internal/platform/id	0.652s
ok  	github.com/cafaye/identity/internal/platform/oauthtest	0.922s
ok  	github.com/cafaye/identity/internal/recovery	27.700s
ok  	github.com/cafaye/identity/internal/redirect	1.009s
ok  	github.com/cafaye/identity/internal/sessions	1.683s
ok  	github.com/cafaye/identity/internal/telemetry	0.717s
ok  	github.com/cafaye/identity/internal/tenancy	0.962s
ok  	github.com/cafaye/identity/internal/useraudit	6.642s
ok  	github.com/cafaye/identity/internal/users	1.692s
```
