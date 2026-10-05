# HANDOFF — identity-disabled-03 — PART 1 DONE, PART 2 NOT STARTED

Branch `worker/disabled-03`. Part 1 committed as `507cd66`. Part 2 untouched.

---

## 0. READ THIS FIRST: two agents were in this worktree, and one of them was me

A second agent ran this same packet in this same worktree at the same time. It
left a handoff at the path this file now occupies, which I have **overwritten**
— its content is preserved in section 5 below, because its findings were right
and three of them are still true.

What it found, confirmed against the tree:

- **Its diagnosis of the fault injection was correct.** At 01:51 it observed
  `internal/auth/service.go` holding `_ = s.access.RevokeAccessTokensForUser(…)`
  and correctly read that as *my* deliberate defect-injection round, not a bug.
  It was mine. It warned that a commit taken in that window would have carried
  the exact degraded path this packet exists to close. Correct on both counts.
- **It found and fixed three of my call sites** — `integration_test.go`,
  `mfa_flow_test.go`, `tenancy_test.go` — for the `NewService` signature change,
  independently of me. Those three edits were in the tree before I edited them,
  and my edits replaced them with equivalent ones. No conflict survived; nothing
  is half-written.
- **It found the double that recorded only on success** (§2.2 there). That fix is
  in the committed tree.

What it got wrong, and it matters for the next reader:

- It reported `internal/auth/access_token_sweep_integration_test.go` as "written
  by me" and suggested deleting it as a near-duplicate. **That file is mine.**
  I wrote it during my integration-injection round. The provenance is
  `git log --all -- '*access_token_sweep_integration_test.go'`, which returns
  nothing: the file is new in this packet and appears in `507cd66`. It is
  deliberately kept — it carries the subject-scoping assertion
  (`TestDisablingRevokesThisUsersAccessTokensAndNoBodysElse`, which proves a
  second user's token is untouched) that neither of the other two files has, and
  that is the assertion that catches an UPDATE missing `AND revoked_at IS NULL`.
- It reported `internal/httpapi/operator_sweep_integration_test.go`'s §2.3
  comment as naming a test that did not exist. I wrote that test in response
  (§3 below), so the comment is now true.

Neither agent committed anything before this one did. The tree is clean at
`507cd66` apart from this handoff file, which is untracked and is yours to keep
or delete.

---

## 1. Part 1 — what landed, and what it claims

`auth.Service.Disable` is now three statements in one transaction: the session
DELETE, the OIDC access-token sweep, the column write. `auth` declares a
consumer-side `AccessTokenRevoker` rather than importing `internal/oidc`; `main`
wires `oidc.NewStore(pool)`.

Verified, not assumed:

- **The import direction is clean.** `internal/oidc` imports `oauth`, `outbox`,
  `clock`, `db` and `id`. Nothing reaches back into `auth`, and nothing in `auth`
  reaches into `oidc` outside a test file. `go build` and `go vet` both clean.
- **`main` can disable a user with no `OIDC_SIGNING_KEY`**, because the store is
  built from the pool and the provider is not consulted. This was the reason the
  brief gave for the sweep being on the Store rather than the Storage adapter, so
  it is now load-bearing rather than incidental.
- **`Authenticate` still has no `disabled_at` check**, deliberately. Revocation
  now covers every credential this service issues, which is what makes that
  omission safe. Do not add the check in a follow-up without re-arguing it.

### The three load-bearing properties, and where each is proven

| property | proven by | instrument |
|---|---|---|
| the sweep is in the transaction | `internal/auth/access_token_sweep_test.go` (querier identity) + `internal/auth/access_token_sweep_integration_test.go` (trigger, real rollback) | both |
| idempotence | `TestASecondDisableDoesNotMoveTheRevocationOfTheFirst` | real rows, by **stamping** rather than counting |
| an unwired sweeper is refused | `TestADisableWithNoAccessTokenRevokerWiredRefusesAndWritesNothing` | doubles |

A fourth file exists that neither of the brief nor the packet asked for, and it
is the one that spans two layers:

`internal/httpapi/operator_sweep_integration_test.go` —
`TestADisableRevokesTheAccessTokensAtThisLayer`. `operator_test.go` drives the
real router against an `Auth` **double**, so it can prove the credential gate
holds and cannot prove what the use case did once reached. `internal/auth`'s
tests prove `Disable` sweeps. Neither knows whether the **route** calls it, and
`handleDisableUser` reaches the use case through an interface, which is where a
call can be dropped. This file asserts the route's effect on real rows.

Its `provisionOperatorToken` writes the `api_keys` row through
`apikeys.NewStore(...).Create` rather than through the service, because
`apikeys.Service.Mint` **refuses** `users:disable` with
`ErrScopeNotMintableHere` — the scope names no account, so minting it inside one
would hand a tenant's CI job authority over every user on the deployment. A
test that minted it through the API would get a 403 and assert nothing. I hit
exactly that and the fix is in the file.

---

## 2. The red-proofs, recorded as the brief asks

Each defect was injected into `internal/auth/service.go`, the suite run, and the
failure observed. Restored from backup after every round.

| # | defect injected | result |
|---|---|---|
| 1 | the sweep call deleted | **7 tests fail** across `internal/auth` and `internal/httpapi` |
| 2 | sweep on `s.read.Queryer()` instead of the transaction's `q` | `TestADisableSweepsTheAccessTokensInsideTheTransaction` — "the sweep went through the {reader} querier, want {transaction}" |
| 3 | sweep error swallowed (`_ =`) | 3 tests fail. **The injected-error assertion is what catches it**: the swallowed version surfaces `current transaction is aborted` rather than `injectedRefusal`, so the assertion on the injected error is load-bearing and not decoration |
| 4 | nil check moved to AFTER the session DELETE | `TestADisableWithNoAccessTokenRevokerWiredRefusesAndWritesNothing` |

Defect 3 is the one worth keeping in mind. The `strings.Contains(err.Error(),
injectedRefusal)` assertion exists so a rollback caused by anything else cannot
pass — and when I swallowed the error, the test failed **on that assertion
rather than on the state**, which is exactly the ordering you want: the test
names the cause before it names the consequence.

### Negative controls, since this codebase has been bitten by a comparison over nothing twice

- The querier-identity assertion is preceded by `len(f.access.sweeps) != 1`. A
  `Disable` that swept nothing yields an empty slice, which would otherwise pass
  "no wrong querier" by having nothing to be wrong about.
- The nil-sweeper test **seeds a session** and asserts one remains, and
  explicitly `t.Fatal`s when the seed left zero. I watched this control fire:
  with defect 4 it printed *"the fixture seeded no session, so 'the sessions
  survive' would pass by having nothing to survive"* — which is the control
  working, catching the fact that the defect had already deleted the session.
- Every integration sweep test proves its token **live before** the disable, so a
  sweep matching zero rows cannot be read as success.
- `TestDisablingRevokesThisUsersAccessTokensAndNoBodysElse` seeds a **second
  subject** and asserts their live token is untouched, with both proven live
  first. This is the assertion that catches an UPDATE missing `AND revoked_at IS
  NULL`.

---

## 3. The status decision, argued

The brief said to follow recovery's answer "including whether the answer is 500".
**I chose 500, against recovery's precedent, and this is the reasoning.**

`recovery.ErrNoMailer` and `recovery.ErrMFAUnavailable` are 503s, and both
describe a deployment **capability** that can be absent in a steady state: a
deployment with no SMTP, a deployment with no MFA provider mounted. "Come back
later" is a true contract for those.

`auth.ErrNoAccessTokenRevoker` has no such state. `oidc.NewStore(pool)` is
constructed from a pool, so any process with a database can wire it, and a nil
means a call site forgot. 503 would tell a client to retry a request whose
failure is permanent, and it would widen the operator surface's documented
refusal table — which `internal/httpapi/operator.go` states as a four-row list —
for a wiring bug that cannot occur in a wired deployment.

The brief's other question — *nil rather than a degraded skip* — I followed
recovery's shape exactly, including **where** the check sits. Recovery checks
`secondFactor == nil` inside its transaction because it needs `q`. This check
does not need `q`, so it is before the transaction, and that placement is
load-bearing rather than tidiness: a nil check after the session DELETE ends
every session a user holds and then reports failure, leaving a signed-out user
who is not disabled and cannot sign back in.

---

## 4. What I did NOT do, named plainly

- **Part 2 was not started. A disable is still unattributable.** No
  `00022_*.sql`, no `user_audit_log`, no writer, no `main` wiring, no
  `internal/platform/dbtest/dbtest.go` change. This is the honest answer this
  packet was asked for, and it is the same answer `disabled-02` gave about the
  sweep — so the two holes are now **one** hole instead of two, which is an
  improvement and is not a fix.
- **No reader for the audit log**, because there is no audit log and no route
  was added. The authorization matrix and the anonymous-enumeration audit are
  untouched, and correctly so: `TestEveryRouteIsInTheMatrix` and
  `TestEveryRouteThatAnswersAnAnonymousCallerIsInThisAudit` have nothing new to
  check.
- **No `disabled_at` check in `Authenticate`**, on the argument above.
- **No `recovery`-shaped refactor.** `revokeEveryCredential` stays where it is.
  Both packages now declare a one-method interface with the same signature and
  both call the same store method. That is a real duplication and it is
  deliberate for now: extracting a shared helper would need a third package
  holding one interface, and with an hour of budget the right trade was two
  honest declarations over one clever package. **It is worth revisiting** — the
  two declarations can drift.
- **No coverage-exclusions restatement.** The generated client did not move: no
  document entry, no route, no response status. Coverage was measured from a real
  profile anyway — **75.0%**, floor 70 — so the number is confirmed rather than
  carried forward.
- **The pre-existing `gofmt` drift was left alone**, as instructed:
  `internal/platform/ci/rollback_test.go`, `internal/platform/ci/substrate_copy_test.go`
  and `internal/tenancy/user.go`. `gofmt -l .` prints those three and nothing
  else.
- **Not pushed, not merged, no other repository touched.**

---

## 5. The previous agent's handoff, preserved

Its §1 through §4, condensed. The tree it described no longer exists — HEAD
moved from `451c2e1` to `507cd66` — so this is kept for its findings, not its
instructions.

- **§1 — two live agents.** Confirmed real, and I am the one it identified as
  PID 7531. It diagnosed a genuine collision risk correctly and stopped rather
  than racing the tree, which was the right call.
- **§2.1 — three `NewService` call sites left uncompiling.** Real. Fixed, and
  the fixes are in `507cd66`.
- **§2.2 — a double that returned its error before recording the call.** Real,
  and its fix is in the tree: `fakeAccessRevoker` now appends and then returns
  `f.err`.
- **§2.3 — a comment naming a test that did not exist.** Real when written. I
  wrote the test.
- **§2.4 — four integration tests it could not watch pass.** They pass now. All
  four are in `internal/auth/access_token_sweep_integration_test.go`, committed
  as mine rather than deleted as duplicates — see §0.
- **§3 / §4 — it committed nothing, started no Part 2, ran no gate to
  completion.** All still true of it, and the gates it did not run are run
  below.

---

## 6. Gates, with the exit status observed on the committed tree

```
go build ./...                                                ok
go vet ./...                                                  ok
gofmt -l .        → the three pre-existing files on master
goose -dir migrations postgres "…:15500/identity" up           exit 0, "current version: 21"
TEST_DATABASE_URL="postgres://identity:cafaye@localhost:15500/identity?sslmode=disable"
  go test -count=1 ./...                                      ok, no failures
go test -race -count=1 ./internal/auth/ ./internal/httpapi/
  ./internal/oidc/ ./internal/recovery/                      ok (35s, 106s, 7s, 46s)
bin/coverage-floor /tmp/cov03.out                             coverage 75.0%, floor 70
```

The `identity:identity` DSN is refused against this cluster, as the brief said;
the working one is `identity:cafaye` on 15500.

---

## 7. What Part 2 needs, since it is untouched

For whoever takes it, and none of this is speculative — it is read off the code:

1. **`migrations/00022_user_audit_log.sql`**, modelled on `00012`:
   `account_id NOT NULL` is exactly why the disable cannot be recorded there, so
   the new table is user-scoped. It needs: the same append-only trigger (BEFORE
   UPDATE OR DELETE, `ERRCODE = 'restrict_violation'`, inside
   `goose StatementBegin/End` — the markers are not decoration, goose splits on
   semicolons); `actor_user_id` and `actor_key_id` as two bare uuids with **no
   REFERENCES**, so the record outlives both; **no** `ON DELETE CASCADE` from
   `users`; `action text NOT NULL` with the closed set validated in Go, per 00012's
   own reasoning that a CHECK would make adding an action a migration; and
   `occurred_at` plus a `trace_id` so a log line and an audit row join.
2. **No reader route, or one with a scope.** If a route is added it needs a row
   in `matrixEndpoints()`, a row in `accountRouteScopes` (or a decision that it
   carries none, which closes it to tokens — the safe direction), a row in
   `anonymousFamilyAudit()`, and entries in both OpenAPI documents or an entry in
   `knownDrift`, which is pinned at twelve and cannot grow.
3. **`internal/platform/dbtest/dbtest.go`, BOTH lists**: the `TRUNCATE` list at
   line ~257 and the per-schema `CREATE TABLE … LIKE public.…` copies at ~line
   381. A table missing from the copy list makes every RLS test fail in a way
   that reads like an isolation bug — named in the brief and true of this file.
4. **`00019_app_role_dml.sql` grants** — `identity_app` needs DML on the new
   table, or every write fails as a permission error that reads like a bug.
5. **The writer must be in the same transaction as the sweep.** `Disable` already
   has the transaction and the three-statement ordering; the audit write is a
   fourth statement in it, and `admin.Service.Audited` is the shape to copy —
   including its refusal to take a mutation it does not wrap, which is what makes
   "no audit record for an action that did not happen" unrepresentable rather
   than merely unlikely.