# identity-w51-preferences — report

**Branch:** `worker/identity-w51-preferences` (worktree
`/Users/kaka/Code/any/wt/identity-w51-preferences`)
**Packet:** FEATURE-PARITY row 52, the preferences half — a `preferences` column
and the one key the reference puts in it.
**Status:** complete. The gate passes; the evidence is at the end of this report.

## What shipped

| Piece | Where |
| --- | --- |
| Migration `00027_user_preferences.sql` — `preferences jsonb NOT NULL DEFAULT '{}'::jsonb` | `migrations/` |
| `users.Preferences` (one field) and `users.ValidateTheme` | `internal/users/users.go` |
| The column in `userColumns`, the scan, and `Store.UpdateTheme` | `internal/users/store.go` |
| `auth.Service.UpdateTheme` | `internal/auth/service.go` |
| `GET`/`PATCH /v1/me` carry `theme` | `internal/httpapi/auth.go` |
| OpenAPI: `theme` on the `User` schema and on the PATCH body | `openapi/v1.yaml` |
| The generated client, regenerated and committed | `client/generated/api.gen.go` |
| The coverage-exclusion restatement the regeneration forces | `coverage-exclusions` |
| README endpoint table, CHANGELOG | `README.md`, `CHANGELOG.md` |

The previous attempt's committed layer (migration, `Preferences`, `ValidateTheme`
as it stood, `Store.UpdateTheme`, and the store tests) was kept; the handler,
the OpenAPI, the tests and the docs were finished or rewritten from it. What
changed from that attempt is **decision 1**, below — it was the one open
question, and the brief's own test specification settles it against what the
previous attempt chose.

## Decision 1 — an omitted `theme` on `PATCH /v1/me` CLEARS it

**The call.** An omitted theme returns the profile to the system theme. This
matches the sibling: `display_name` clears on omission, and the route now has
one omission rule, not two.

**The reasons.**

1. **The brief's default, and its test list.** The brief says "match the
   sibling unless you have a reason not to", and its minimum test list
   specifies that `""` is *rejected* — which is only coherent if omission is
   the clearing act. The previous attempt chose "leave unchanged" with `""` as
   the clearing value; that contradicts the brief's explicit test
   specification, and a worker brief's test list is a harder constraint than
   its default preference.
2. **One rule per route.** A client that learns "a field I do not send returns
   to its zero state" learns the whole route. A second field with a second
   omission semantic makes the contract harder to learn than the data loss it
   prevents — and the loss is not prevented, only moved: under either rule, a
   theme-only update still clears the (frozen) display name.
3. **The reference's own shape.** Jumpstart's system theme is
   `theme.blank?` — a *blank*, i.e. an absence. In a JSON document the blank
   is the omitted key, not the empty string. Omission-as-clear is the faithful
   translation; `""`-as-clear invents a second representation of the same
   state, which is the thing this repository's `display_name` comments argue
   against in other places.

**The cost, named.** A client that updates only their display name clears
their theme. That is the same contract the route already has in the other
direction (a theme-only update clears the name), it is documented on the
request field, in the OpenAPI document and in the README, and it is the
price of one omission rule.

**How the system theme is reached.** Omit the field. `PATCH {"display_name":
"Kaka"}` clears a previously-set theme; the response omits `theme`, and
`GET /v1/me` omits it too.

## Decision 2 — `GET /v1/me` omits `theme` when nothing is set

**The call.** The key is absent, never `null` — `display_name`'s `omitempty`
precedent, and the same reasoning: "no theme" and "the system theme" are one
state, and a second representation of it is a thing to keep in step with
another. The OpenAPI `User` schema carries `theme` as an optional `enum:
[light, dark]` property, matching how `display_name` is carried.

## The closed set

`"light"`, `"dark"`, and **absent** (the system theme). Nothing else is a
theme:

- `"blue"`, `"system"`, `"DARK"`, `" dark "`, `""` → `422 validation_failed`
  with one field error `theme / invalid_format` — the existing error shape,
  not a second one.
- A non-string (`42`) → `400 invalid_json` from the decoder, before
  validation runs: the request was not understood, rather than understood and
  unacceptable.
- A refused theme writes nothing: the validation happens before either store
  call, so a rejected value cannot take the display name down with it, and
  the stored preference is unchanged (asserted end-to-end).

## The per-user test

`TestEndToEndThemeIsPerUser` (`internal/httpapi/auth_routes_integration_test.go`)
registers two users, logs both in, and asserts the boundary both ways: the
first user's `dark` is invisible to the second user's `GET /v1/me`; the
second user's `light` leaves the first user's `dark` untouched. It reads as
the tenancy-adjacent behaviour it is — the row the handler reads is the
caller's own, and a preference does not cross the credential boundary.

## What was ruled out

- **The previous attempt's "leave unchanged"** — see decision 1. Its reason
  (silent loss for name-only updates) was weighed and outweighed; the cost is
  named there.
- **A `theme` text column.** The reference stores a jsonb document; the next
  key this profile wants is one Go change and one UPDATE, not one migration.
- **Speculative preference keys.** The reference has exactly one key. A
  `preferences` bag of fields nobody asked for is the thing the packet brief
  says this packet must not become.
- **An explicit `null` on `GET`.** A second representation of the system
  theme; see decision 2.
- **A second error shape.** The refusal is the existing `invalid_format`
  field error, the same 422 an over-length name gets.
- **A `theme` value of `""` as the clearing case.** The system theme is an
  absence, not a value; see decision 1.

## Tests

Unit (`internal/httpapi/auth_test.go`, `internal/users/users_test.go`):
set `light`/`dark` and read them back; the invalid table (`""`, `"blue"`,
`"system"`, `"DARK"`, `" dark "`) refused with the 422 field error and
nothing written; a non-string refused with 400; omission clears (and the
write arrives as nil); `GET` projects the theme present-only-when-set.

End-to-end (`internal/httpapi/auth_routes_integration_test.go`, real SQL
through the suite's own migrated-schema path): the full lifecycle
(absent → dark → light → cleared by omission); the per-user boundary; the
refused values leaving the stored preference unchanged.

Store (`internal/users/store.go` tests, committed by the previous attempt and
kept): set and read back both values; nil clears to the same "no theme" a
new user has; a missing user is `ErrNotFound`.

## The gate

`mise exec -- ./bin/prime` with
`TEST_DATABASE_URL=postgres://identity:cafaye@127.0.0.1:15527/identity?sslmode=disable`,
all 27 migrations applied to the test database (the suite's own path — `dbtest`
clones the migrated `public.users`, so the `preferences` column is reached
only because `00027` was applied). Exit 0, output verbatim:

```
ok  	github.com/cafaye/identity/client	3.463s
?   	github.com/cafaye/identity/client/generated	[no test files]
ok  	github.com/cafaye/identity/cmd/identity	4.723s
ok  	github.com/cafaye/identity/internal/accounts	20.988s
ok  	github.com/cafaye/identity/internal/admin	5.278s
ok  	github.com/cafaye/identity/internal/apikeys	17.256s
ok  	github.com/cafaye/identity/internal/auth	14.293s
ok  	github.com/cafaye/identity/internal/config	0.566s
ok  	github.com/cafaye/identity/internal/courier	1.172s
ok  	github.com/cafaye/identity/internal/deletion	1.175s
ok  	github.com/cafaye/identity/internal/httpapi	63.603s
ok  	github.com/cafaye/identity/internal/mfa	22.506s
ok  	github.com/cafaye/identity/internal/oauth	5.336s
ok  	github.com/cafaye/identity/internal/oidc	2.506s
ok  	github.com/cafaye/identity/internal/outbox	5.771s
ok  	github.com/cafaye/identity/internal/platform/ci	4.144s
ok  	github.com/cafaye/identity/internal/platform/clock	0.543s
ok  	github.com/cafaye/identity/internal/platform/db	0.620s
?   	github.com/cafaye/identity/internal/platform/dbtest	[no test files]
ok  	github.com/cafaye/identity/internal/platform/id	1.083s
ok  	github.com/cafaye/identity/internal/platform/oauthtest	0.716s
ok  	github.com/cafaye/identity/internal/recovery	18.315s
ok  	github.com/cafaye/identity/internal/redirect	1.198s
ok  	github.com/cafaye/identity/internal/sessions	0.948s
ok  	github.com/cafaye/identity/internal/signup	0.604s
ok  	github.com/cafaye/identity/internal/telemetry	0.715s
ok  	github.com/cafaye/identity/internal/tenancy	0.873s
ok  	github.com/cafaye/identity/internal/useraudit	4.953s
ok  	github.com/cafaye/identity/internal/users	1.016s
```

Two gate runs before this one are worth recording, because both failures were
the repository's own checks doing their job. The first failed at
`TestTheCommittedGeneratedFileIsWhatThePinnedGeneratorProduces`: the OpenAPI
document had changed and the generated client had not been regenerated —
fixed by `go generate ./client/`. The second failed at
`TestTheCoverageExclusionIsOnlyGeneratedCode`: the regeneration moved the
excluded set and `coverage-exclusions` had not been restated — fixed by
re-measuring the file (29644 lines, 6875 statements) and rewriting the entry
in the same commit, which is the discipline that check exists to enforce.
