# REPORT: `mvp-identity-social-01`

**Repo:** `cafaye/identity` · **Branch:** `worker/identity-social-01` · **Base:** `5b28213`
**Commits:** `26c991c`, `e237109`, `8a1f8c8` — committed, not pushed, not merged.

---

## 1. What the defect was

Social login was written and unreachable. Concretely, on master `5b28213`:

- `internal/auth/social.go` — 514 lines, the account-takeover decision, **no test**.
- `internal/oauth/provider.go` — 259 lines, the configured-provider refusal, **no test**.
- `internal/httpapi/oauth.go` — 510 lines, two handlers, **never reached from a process**.
- `httpapi.WithSocial` — defined at `oauth.go:146`, **no call site anywhere**.

So `options.social` was nil in every process, `registerSocialRoutes` returned at its
first line, and the two routes were not on the wire. A deployment that set all six
`OAUTH_*` variables got a clean 404 for a feature it had been given credentials for.

The packet is right that this matters: `MVP-SCOPE.md` puts GitHub identity in the MVP,
and `PLAN.md:68` says the owner reviews these diffs personally because identity is
security.

---

## 2. Every claim in §2 and §3, re-measured

Re-checked against the tree rather than taken from the packet. Two claims are **wrong**
and one is **incomplete**; all three are reported here rather than quietly worked around.

| Packet claim | Measured | Verdict |
|---|---|---|
| `social.go` is 514 lines | 514 | ✅ |
| no `social_test.go` | absent | ✅ |
| the four outcomes untested | untested | ✅ |
| `ErrSocialEmailInUse` at `social.go:95` | `:95` | ✅ |
| mapped to 409 at `httpapi/oauth.go:401` | `:401` | ✅ |
| `httpapi/oauth.go` written, never mounted | written; **mount was called**, but unreachable | ⚠️ see §3 |
| `provider.go` — GitHub + Google, `NewRegistry` | confirmed, 6 files / 5 tested | ✅ |
| the rest of `internal/oauth` each has a test | `cipher`, `client`, `settings`, `state`, `store` all tested | ✅ |
| `go build ./...` exit 0 | exit 0 | ✅ |
| `go vet ./internal/httpapi/ ./internal/auth/` exit 0 | exit 0 | ✅ |
| **`registerSocialRoutes` has zero call sites** | **it is called, at `auth.go:195`** | ❌ **wrong** |
| **`git log -S"registerSocialRoutes" -- internal/httpapi/httpapi.go` returns nothing** | returns nothing; **the call is in `auth.go`, not `httpapi.go`** | ❌ **wrong, and the search explains why** |
| **`WithSocial` appears only at its own definition** | confirmed — that part is right | ✅ |

### 3. The false premise, corrected

The packet says the routes were "never called from the router, not once, ever." **They
were.** `internal/httpapi/auth.go:195`:

```go
	// And the social-login surface, which is also reachable with no credential …
	o.registerSocialRoutes(r)
```

`git log -S"registerSocialRoutes" -- internal/httpapi/` returns two commits
(`10a23c3`, `968f749`), and `git log -S"o.registerSocialRoutes(r)"` returns `10a23c3`
— the recovery commit named in §3. The packet's `git log` was scoped to
`internal/httpapi/httpapi.go`, and the call is in `auth.go`. A search scoped to one file
answers a question about that file.

**This does not rescue the packet's conclusion.** The surface was still unreachable, for
the reason the packet's other claim identifies correctly: `WithSocial` had no call site,
so `options.social` was nil, so the registrar returned before registering anything. The
inferred cause was wrong; the conclusion was right; the *fix* (call `WithSocial`) is the
same either way. Worth recording because "the mount was already there" is the kind of
correction that, unexamined, leads a future worker to conclude the wiring is fine.

### 4. §4's finding, confirmed and then some

`httpapi.Social` (`oauth.go:129`) needs three methods. `*oauth.Registry` has `Lookup`
(`provider.go:205`) and `RedirectBase` (`provider.go:214`). **`Callback` is absent** —
`grep "func (r \*Registry)"` returns four methods and none is `Callback`. Confirmed.

**I supplied it with a narrow adapter** (`internal/httpapi/social_wiring.go`), not a method
on `Registry`. Adding `Callback` to `Registry` is impossible: it would need to name
`auth.SocialCallbackInput` and `auth.LoginResult`, and `internal/auth` imports
`internal/oauth` — so `internal/oauth` cannot import `internal/auth`. `Registry` cannot
name the type that finishes the round trip. That is a package cycle, not a preference.

The adapter lives in `internal/httpapi` rather than `cmd/identity` because a type declared
in `cmd` cannot be named by a test, so the wiring would be reachable only by starting a
process. `httpapi` already imports both packages (for `Social`'s own signatures), so
nothing new is imported.

### 5. A second gate no comment mentions — **finding, not fixed**

`registerRoutes` returns at its **first line** when `options.auth` is nil
(`auth.go:125`), *before* reaching `registerSocialRoutes` at `auth.go:195`. So the social
routes are gated on an auth service **as well as** on a provider.

Neither comment says so. `oauth.go:140-145` states the rule as "the routes are ABSENT
when no provider is configured"; `auth.go:190-194` says "absent unless a provider is
configured." Both are incomplete. The whole truth is *"absent unless a provider **and** an
auth service are configured."*

**The code is right.** A social sign-in creates a user row through `auth.Service`, so a
process with no database cannot complete one — a mounted start route there would send a
browser to a provider and answer 500 on the way back. The failure direction is fail-closed.

**I did not fix it**, for two reasons. Moving the call above the guard would mount a flow
that cannot work. And correcting the comments is a change to a surface this packet is told
to leave alone; the tripwire now documents the real precondition, and §8 names it for the
manager.

---

## 6. What landed

### Commit `26c991c` — the registry's tests, and the wiring

`internal/oauth/provider_test.go` + `provider_migration_test.go`, and
`internal/httpapi/social_wiring.go` + `social_mount_test.go`.

Three refusals in `Registry` are security decisions, and each is asserted:

- **Half-configured providers are dropped.** Three ways (neither half, id only, secret only) —
  the code tests `ClientID == "" || ClientSecret == ""`, and a one-case test passes against an
  inverted condition.
- **`Lookup` is identical for "unconfigured here" and "does not exist".** `errors.Is` is *not*
  sufficient, and the test says why: a wrapper reading `"google is not configured on this
  deployment"` satisfies every `errors.Is` in the repository and still enumerates the
  configuration to an unauthenticated caller, who can ask for every name in the closed set and
  read which come back with the extra sentence. The test substitutes the caller's own name out
  of both messages and requires what remains identical.
- **`Empty` is a routing decision.** Both directions asserted — "true when bare" and "true
  always" both pass a bare-only test.

`knownProviders` is held against the `oauth_provider` enum by **reading
`migrations/00008_connected_accounts.sql`**, not by restating it. A Go copy goes stale
exactly when a provider is added, which is the only day the check is worth anything. A read
that returns nothing **fails loudly** rather than comparing against an empty slice and agreeing.

### Commit `e237109` — the use case's tests

`internal/auth/social_test.go`. The five reachable shapes across `Callback`'s two branches,
each in its own fixture:

| Input | Outcome | Asserted |
|---|---|---|
| provider identity seen, sign-in | `signInAs` | session; **1** user; credentials rewritten |
| address already taken, sign-in | **REFUSAL** | `ErrSocialEmailInUse`; 0 rows; 0 sessions |
| address free, sign-in | `createAndSignIn` | user + tenancy + event + account **in one transaction**; session |
| identity is somebody else's, link | **REFUSAL** | `oauth.ErrAlreadyLinked`; row **unchanged** |
| identity is theirs or free, link | `link` | **no session, no token** |

### Commit `8a1f8c8` — the mount, and the tripwire that covers it

`cmd/identity/main.go` (`buildSocial` + the `WithSocial` call) plus two test files.

---

## 7. Security decisions, made legible

This is the section the owner will read. Each refusal: **what it prevents, and what an
attacker gets past it.**

### The address collision — the takeover, and the one that matters

**The attack.** An attacker sets the address of a provider account they control to a
victim's address on this service. They arrive at the callback with an authorization code the
provider considers verified. Question 1 does not fire (never seen). Question 3 does not fire
(not signed in). Question 4 is the only thing between them and the victim's account: if this
service linked on collision, the attacker's provider identity attaches to the victim and the
next callback signs them in. **Full account takeover, from an address, with no credential.**

**Why refusing is right.** Email from an OAuth provider is not proof of control of that
mailbox, and `users.email` is unique. A colliding address is either an attacker who set it, or
the same person arriving two ways. There is no third option. The refusal is a support call;
auto-linking is an incident.

**What an attacker gets past it: nothing.** The refusal discloses that an account exists for
that address — to an anonymous caller. It is safe because question 4 is reachable only with a
code a provider issued for an address **the provider has itself verified**
(`internal/oauth/client.go` refuses an unverified address on both providers). The caller has
already proved control of that mailbox; they could learn the same by asking Google.

**What makes that true, and it is not an accident:** the unverified-address refusal in
`oauth/client.go`. Without it, an attacker who can set an arbitrary address on a provider
account walks straight into this 409 with a guess, and the guess becomes a takeover.
`email_verified` is not read for tidiness — it is what makes question 4 safe to ask out loud.
**These two decisions are load-bearing on each other. Neither is safe alone.** I have tested
both halves.

**What the tests assert beyond the error:** that **no connected account was written** and
**no user was created**. An implementation that detected the collision, created nothing, and
still called `store.Create` would pass an error-only assertion and have performed the link
it claims to refuse.

### Why the refusal is *only* on the sign-in path

The mirror case, and the half a reader is most likely to get wrong. A signed-in person whose
provider account reports an address belonging to a **different** account here is **not**
refused — they are signed in as themselves.

Questions 1–3 are decided by the **provider's own identifier**, a fact about the provider's
account rather than about a mailbox. A person signed in as themselves is signing in as
themselves, and their provider address colliding with another account's is not evidence of
anything. Jumpstart Pro's `attach_account` does not ask question 4 either. Adding it to the
link path would refuse a legitimate operation for a reason that does not apply. Tested with
the **same address** as the refusal above and a different input — an implementation that
hoisted the check above the `if !in.LinkTo.ID.IsZero()` branch passes both refusal tests and
breaks this one.

### Linking mints nothing — four assertions, not one

`link` returns a `LoginResult`, which **has** `Token`, `ExpiresAt`, `Challenge` and
`MFARequired`. So "linking mints nothing" is four facts about a value being left zero, not a
statement about a distinct type — and any edit that starts populating one produces a working,
compiling, plausible implementation of a security hole. All four are asserted.

`MFARequired` is the subtle one. `internal/httpapi/oauth.go:305-317` decides which of three
responses to write by reading `!owner.ID.IsZero()` **first** and `result.MFARequired` second —
so a spurious `true` changes nothing today and changes the response **the moment somebody
reorders those two branches**. From one boolean.

### Why the callback returns `LoginResult` at all

A social sign-in that minted a session for an account with a confirmed second factor would
be the largest hole in this file. The defence is structural: `Callback` ends in
`s.auth.startLogin`, the same call a password login makes, so there is **no field of this
result from which a session can be had without the second factor having been presented**.
Tested on **both** paths that mint — a returning user and a brand-new account, plus a
single-factor control that proves the challenge came from the account's factor and not from
the callback refusing to mint at all.

### Where judgement was mine

**Adapter over `Registry` method.** Forced by a package cycle (§4). The alternative — moving
the use case's decision into `internal/oauth` — would put the account-takeover decision in the
package that talks to third parties and has no business making it. Rejected.

**`NewSocial` returns an untyped nil.** `WithSocial` guards on `if s != nil`, so a
`(*socialWiring)(nil)` boxed in a `Social` would be non-nil as an interface, defeat the guard,
and panic on the first `Lookup`. Tested on the value `options.social` actually holds, not just
the return.

**`registry == nil` is checked before `registry.Empty()`.** `Empty` dereferences, and a panic
at boot on a misconfigured deployment is worse than two absent routes. Ordering is the
property; a test asserts it explicitly rather than inferring it from a nil return.

**Source-reading tripwire.** `cmd/identity` is `package main` and cannot be imported, so
nothing outside it can construct `newApp`. Reading the source is the only available instrument
for the last link in the chain. Its weakness is specific and stated in the file: it holds the
**shape** of the wiring, not its behaviour. It cannot tell a correct `buildSocial` from a stub.
What it holds is that the mount is **wired at all**, which is the entire content of the defect.

---

## 8. Measurements

Every number measured here. Baseline taken by `git stash`-ing `main.go` **and** removing the
new files, so it is a true `5b28213` measurement rather than a partial one.

| | master `5b28213` | after |
|---|---|---|
| `go build ./...` | 0 | **0** |
| `go vet ./...` | 0 | **0** |
| `internal/auth` passes / skips | 70 / 18 | **70 / 18** |
| `internal/oauth` passes / skips | 121 / 12 | **121 / 12** |
| `internal/httpapi` passes / skips | 489 / 169 | **501** / 169 |
| `cmd/identity` passes / skips | 21 / 10 | **23** / 10 |
| `golangci-lint` (these 4 packages) | 37 | **36** |

### Skips — counted, not assumed

**209 skipped across the four packages. Every one is `TEST_DATABASE_URL` unset.** The counts
are identical before and after, so this packet neither added nor removed a skip.

**No integration test ran.** Docker was not started for this packet. That specifically means:

- `internal/oauth/store_test.go` — **the only coverage of the real `connected_accounts` SQL**,
  including the unique-index violation that `oauth.Store` turns into `ErrAlreadyLinked`. My
  `TestAFailedCreateLeavesNoConnectedAccount` asserts the error **propagates**; it does not
  prove the real store produces it.
- `internal/auth/integration_test.go` — the real-transaction tests. My transaction assertions
  compare the **querier identity** each write was handed (`markerQuerier{"transaction"}` vs
  `{"reader"}`), which proves the writes share a transaction *seam*. It does not prove the
  database rolls back.
- `internal/httpapi`'s 169 — admin, apikeys, mfa, oidc, recovery, tenancy route integration.

**The social tests in all three commits are entirely unit-tier.** `fakeUnitOfWork` cannot roll
back, by its own comment in `service_test.go`; the tests that need real rollback live in the
integration suite. **Nothing in this packet has been run against a real Postgres.** A reviewer
should treat that as the open item.

### golangci-lint

36 issues in these four packages, down from 37. **None is in a file this packet added or
touched.** It found one real defect while being run — an ineffectual assignment to a clamped
offset in `withinWindow`, left over from a draft where the offset was never read — and that is
fixed. The remaining 36 are pre-existing (`unused` on dead helpers in the integration tier,
which is what a skipped suite leaves behind). The delta of 1 is my file, net of the fix.

---

## 9. Mutation tests

Every mutation was **verified present in the file by `grep` before the run**, and every
restore was confirmed by **`diff` against a pre-mutation copy — not by exit status.**

### `internal/httpapi` tripwire

| # | Mutation | Verified | Result | Caught by |
|---|---|---|---|---|
| 1 | delete the callback route registration | `grep` → 1 line left | **exit 1** | 2 tests |
| 2 | delete the `registerSocialRoutes(r)` call | `grep -c` → 0 | **exit 1** | 2 tests |
| 3 | make `Lookup` distinguish known-but-unconfigured from unknown | `grep` → present | **exit 1** | 3 tests |
| restored | — | `diff` **IDENTICAL**, `grep -c` → 0 | **exit 0** | |

### `internal/auth` — the takeover

| # | Mutation | Verified | Result | Caught by |
|---|---|---|---|---|
| 4 | question 4 **links** the colliding identity instead of refusing | `grep` → present | **exit 1** | `TestTheAddressCollisionRefusesRatherThanLinks`, `TestTheFourOutcomes/address_already_belongs` |
| 5 | re-consent link branch **also mints a session** | `grep` → present | **exit 1** | `TestRelinkingYourOwnIdentity…` (1 test) |
| 6 | fresh-link branch **also mints a session** | `grep` → present | **exit 1** | `TestLinkingReturnsNoSession…`, `TestTheAddressCollisionRefusalIsOnly…` (2 tests) |
| restored | — | `diff` **IDENTICAL**, `grep -c "THE MUTATION"` → 0 | **exit 0** | |

### `cmd/identity` tripwire

| # | Mutation | Verified | Result | Caught by |
|---|---|---|---|---|
| A | **delete the `WithSocial` append** — the `c1fc199` defect, reproduced | `grep` → 0 calls | **exit 1** | 2 tests |
| B | call `WithSocial`, append to a **discarded local slice** | `grep` → `discarded` | **exit 1** | 1 test |
| C | move the mount **outside** the `authSvc` guard | `grep` → `socialMounted` | **exit 1** | 1 test |
| restored | — | `diff` **IDENTICAL**, test file `diff` unchanged | **exit 0** | |

---

## 10. Two findings about my own work

**1. My first takeover mutation was the wrong mutation, and it proved nothing.**
Mutation 4 was originally applied by replacing `createAndSignIn` with a call to `link` — which
is question **5**'s branch, not question **4**'s. `TestTheAddressCollisionRefusesRatherThanLinks`
**passed** against it. The mutation that actually performs the takeover is returning `link` with
`LinkTo` set to the *colliding* user, which is what #4 in the table above is. Recorded because
a mutation recipe that was never the right mutation is indistinguishable from one that was
never run.

**2. The re-consent link branch has one observer; the fresh-link branch has two.**
Mutation 5 was caught by exactly one test; mutation 6 by two. The re-consent branch is exercised
by `TestRelinkingYourOwnIdentityRewritesTheCredentialAndMintsNothing` and nothing else — its
`wantSession: false` assertion in the outcomes table goes through the **fresh-link** branch,
because that fixture seeds no existing row. The property **is** asserted on both paths, so this
is a thin spot rather than a gap. It is the kind of thing worth knowing before someone deletes
the test that happens to be holding it.

Two assertions were wrong before they were right, both caught by `go vet` and by the tests:

- The `Lookup` test first asserted the two errors were **byte-identical**. That is wrong —
  `Lookup` wraps the sentinel with the caller's own name, and requiring no diagnostic would mean
  deleting the one useful thing about the message. Rewritten to substitute the name out and
  compare what remains.
- The sealing test first called the `callback` helper, which **overwrites** `client.tokens` on
  every call, and then asserted on plaintexts that had never been sent. Fixed with a
  `signInWith` helper, and the constraint is documented on both.

---

## 11. What I did not do

**No integration test ran.** 209 skips, all `TEST_DATABASE_URL`. Stated in §8 with what each
skip costs. This is the largest gap and it is not a gap I can close without Docker.

**The `oauth_provider` migration check is scoped to `00008`.** A later migration adding a
provider would not be seen. Applying migrations are never edited here, so the path does not go
stale — but a *later* enum change would. Narrower than it looks; stated rather than hidden.

**No `social_connections` disconnect route, and no unlink.** Out of scope — the packet is about
mounting and testing what exists. Worth noting that `claims_test.go:495` injects a
`/v1/auth/oauth/{provider}/disconnect` path as a *drift* fixture, so a future packet adding
disconnect has a test shape waiting.

**No OpenAPI change.** `openapi/v1.yaml` already declares both operations under the
`social-login` tag (`README.md:1741`), and the drift walks see them. Nothing to add.

**`README.md`'s "Social login is not built" section is already corrected** (`README.md:1730-1745`),
and its claim checks pass. No doc edit needed — though note the README's current text describes
the surface as mounted while it was not, which is a **second instance of the same failure mode**
in prose. Flagged, not edited: §8 says leave the surrounding surface alone, and a README rewrite
deserves its own packet.

**`DECISIONS.md` D11 does not exist.** `internal/auth/social.go:36` and
`internal/httpapi/oauth.go:23` both say the takeover trade-off "is recorded as DECISIONS.md
D11". `DECISIONS.md` ends at **D10** and contains **zero** occurrences of `D11`. Two source
comments point at a decision record that was never written. The trade-off is fully argued in
`social.go`'s file header, so **no security content is missing** — but the pointer is stale.
Left for a documentation packet rather than fixed inline here.

**No refactor of the surrounding auth surface.** Per §8. The auth gate (§5) is reported, not
changed.

**No containers, images or volumes started.** Nothing to clean up. I did not run `docker prune`.

---

## 12. Findings outside the packet, for the manager

1. **`registerSocialRoutes` IS called** (`auth.go:195`) — the packet's §3 premise is wrong,
   and its `git log` was scoped to one file. Conclusion unaffected; cause corrected. (§3)
2. **The social routes are gated on `auth` as well as on a provider** (`auth.go:125` returns
   before `auth.go:195`). Correct behaviour, incomplete comments in two places. (§5)
3. **`DECISIONS.md` D11 does not exist**; two comments cite it. (§11)
4. **`README.md:1730-1745` says the surface is mounted while it was not** — a prose instance
   of the same gate-that-is-green-about-the-wrong-thing failure. (§11)
5. **`store_test.go` is the only coverage of the real `connected_accounts` SQL** and it is
   skipped here. Combined with this packet making the surface reachable for the first time,
   the first real sign-in will exercise SQL no test in this packet ran. Worth a database-backed
   pass before the surface is enabled in a deployment.

---

## 13. What I would do next

1. **Run the integration tier against a real Postgres.** Highest value by a wide margin: the
   surface is now reachable for the first time, and `connected_accounts` has never been written
   by a test that ran.
2. **Write `DECISIONS.md` D11**, so the two comments pointing at it land on a real record.
3. **Correct the two comments about the auth gate** — a two-line change, in its own packet.
4. **Add the re-consent branch as a table row** in `TestTheFourOutcomes…`, which would give it
   a second observer and close the thin spot in §10.

---

## 14. Checklist

- [x] Committed to `worker/identity-social-01`. Not pushed, not merged.
- [x] Three commits, each worth a reviewer's slot. No filler, no scaffolds, no commit messages
      describing intent.
- [x] Every command bounded by `timeout`.
- [x] Skips named and counted: **209**, all `TEST_DATABASE_URL`, identical before and after.
- [x] Every "fixed" claim has before/after measurement (§8) and a mutation proof (§9).
- [x] This report exists and is committed.
- [x] Findings outside the packet named and specific (§12).
- [x] No container, image or volume left running. `docker prune` never run.
- [x] Additive only. Nothing existing was removed or reshaped; `main.go` gains 137 lines and
      changes nothing.
