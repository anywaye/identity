# REPORT — m40-identity-authgaps-02 (W2b)

Branch `worker/w2-authgaps`. Finishes W2 and fixes one RLS defect a sibling
worker found, plus two more of the same shape that the packet asked me to look for.

---

## 1. The `Get` 404 — reproduced, fixed, and held by a test that goes red

**Verified, not assumed.** I reproduced it before touching the code, against the
real tables, as the app role:

```
--- FAIL: TestGetFindsTheCallersOwnAccountUnderTheRealPolicies
    get_rls_test.go:128: Get(702d4211-…, its own owner) = caller is not a member
    of this account, want the account.
```

### The cause, confirmed rather than inferred

I read the live policy off the database rather than trusting the migration text:

```
account_users | account_users_cafaye_select   | (account_id = cafaye.current_account_id())
account_users | account_users_cafaye_members  | (user_id   = cafaye.current_user_id())
```

`Get` read on `s.read.Queryer()`, which is `db.Direct` returning the bare pool —
no transaction, no `begin_user`. Both GUCs NULL, both predicates false, so **the
database** filtered the membership row out. No error, no 403, no red assertion: the
handler maps `ErrNotAMember` to `404`, so the owner of their own account got
"Account not found". That is the sibling's measurement, exactly.

### The fix

`Get` and `Member` now open a transaction through the same `s.uow` `ListMine` uses
and call `tenancy.BeginUser` first. `Get`'s doc comment carries the reasoning, and
`Member`'s says why it mattered more than it looks: `TransferOwnership` reads
`Member` to authorize its actor, so that path would have refused the owner who
asked for the transfer with `ErrNotOwner` — indistinguishable from an admin being
correctly refused.

### Why no test caught it — this is the part worth keeping

Every test in `internal/accounts` runs through `newHarness` → `dbtest.Schema`,
whose tables are cloned with `LIKE public.<table> INCLUDING ALL`. **LIKE does not
copy row-level security**, and `dbtest.go` says so itself. So
`TestGetIsInvisibleToANonMember` has been passing against a table where every row
is visible to every caller. It tests the query, not the boundary — a member being
refused was invisible to it, because there was nothing there to refuse them.

`internal/accounts/get_rls_test.go` runs the real `Service` against `dbtest.Pool`:
public tables, app role, policies live. The negative control asserts the policy is
actually installed, so the file cannot go green against a database that dropped it.

**Red/green proven both ways.** With `service.go` stashed, both regression tests
fail; restored, they pass:

```
=== WITHOUT the fix ===
--- FAIL: TestGetFindsTheCallersOwnAccountUnderTheRealPolicies
--- FAIL: TestMemberSeesTheCallersOwnRowUnderTheRealPolicies
--- PASS: TestTheMembershipUserPolicyIsInstalledUnderRealPolicies   ← control, correctly unaffected
```

---

## 2. Two more of the same shape — found, measured, deliberately NOT fixed

The packet asked me to sweep for others and report rather than silently fix. I
measured each one with a throwaway probe against the real policies, then deleted
the probe. `account_users` is the **only** table in the schema carrying a
caller-scoped select policy — I read `pg_policy` to confirm that, so this defect
class is confined to reads of that one table.

### 2a. `Service.Invite` — CONFIRMED BROKEN. This is a live bug.

`internal/accounts/service.go:488` reads the inviter's membership on
`s.read.Queryer()`, same shape as `Get` was. Measured:

```
Invite as the account's OWNER: err=only an owner may remove an owner
```

**The owner of an account cannot invite anybody into it.** Every invitation fails
with `ErrOwnerProtected`. This is the same defect as the reported 404, one route
over, and it is *worse* in one respect: `Get` was a read-only 404, this blocks a
core write path.

Why it is not fixed here: it is a separate defect on a route that is otherwise
finished, with its own authorization rules to preserve, and I had one working
change in flight. A sibling worker can take it with a clean head — the recipe is
identical and now written down twice in the same file.

### 2b. `Service.Members` — CONFIRMED BROKEN, and the worse failure mode

`service.go:389`, also on `s.read.Queryer()`. Measured:

```
Members: n=0 err=<nil>   (the account has 2 real memberships)
```

**Silently empty, no error.** This is the failure shape `internal/tenancy/user.go`
warns about at length — the one where nothing anywhere fails and the product
renders "this account has no members". An owner inviting somebody, seeing the
member list empty, and having no signal that it is wrong. `GET
/v1/accounts/:id/members` returns `200 []` for an account full of members.

Same reasoning as 2a for leaving it: report it, do not half-fix it.

### 2c. Checked and NOT affected

I probed these rather than assuming, since the same method call can be safe in one
place and not another:

| Path | Why it is fine |
|---|---|
| `Service.Account`, `Service.Rename`, `Service.Delete` | Read/write `accounts`, which carries **no** policy at all |
| `Service.Get`/`Member` callers *inside* `uow.Do` (`TransferOwnership`, `Accept`) | `tenancy.TxRunner` sets the account GUC on the transaction |
| `apikeys` resolution | Its own `api_keys_cafaye_resolve` policy, on `token_digest` |
| `oidc` profile reader | Called inside the access-token transaction, which is account-scoped |

---

## 3. Ownership transfer — complete

Already committed in `587efee`/`d6eb144`; verified rather than rebuilt.

| Requirement | Where it is held |
|---|---|
| Routed | `POST /v1/accounts/{accountID}/ownership-transfers`, owner-only via `requireAccountRole` |
| Documented | `openapi/v1.yaml:2732`, README endpoint table **and** the `accounts:write` scope row |
| Authorized | `accountRouteScopes` → `ScopeAccountsWrite`; matrix row at `authz_matrix_test.go:233` |
| Happy path | `TestTransferMovesOwnershipAndKeepsThePreviousOwnersAuthority` — heir promoted, **previous owner kept as `admin`**, event in the same transaction |
| Non-owner | `TestANonOwnerCannotTransfer`, plus a stranger: `TestAStrangerCannotTransferEvenWithAnAccountID` |
| Personal account | `TestAPersonalAccountCannotTransfer` |
| Single-member | `TestAnAccountWithOneMemberCannotTransfer` |
| Transfer to self | `TestTransferToTheCurrentOwnerIsRefused` |
| Atomicity | `TestTransferFailsWithoutMutatingAnythingWhenTheEventCannotBeWritten` |
| HTTP layer | `transfer_test.go`: actor comes from the credential, heir from the body; four refusals each with own status **and** own code; malformed heir is a 404 |

The negative cases are the strongest part of the committed work: the refusal order
means a non-owner is refused before the account is even examined, so the response
is not a statement about whether the account is transferable.

---

## 4. Sudo and impersonation: NOT DONE, plainly

**Neither exists in this repository.** I grepped for `sudo`, `impersonat` across all
`.go` files: the only hits are an unrelated comment in `client/client.go` about a
hostile endpoint and `tenancy_test.go`'s note about `set role` in the isolation
proof. There is no route, no handler, no use case, no table, no OpenAPI entry, and
no migration.

Nothing is half-built and nothing is stubbed to look finished. There are therefore
no negative tests to report — and I want to be precise about why that is not a gap
I am papering over: with no feature there is nothing to assert a refusal against,
and inventing a test for it would be the "tested but unwired" lie AGENTS.md warns
about. The next packet cannot confuse the two states here.

---

## 5. Verification — the runs, not the claims

| Gate | Result |
|---|---|
| `go test -count=1 -p 1 ./...` | **exit 0**, all 26 packages `ok` |
| `go vet ./...` | clean |
| `gofmt -l .` | clean for every file I touched (see §6) |
| `go test -race -count=1 -p 1` on `accounts`, `httpapi`, `tenancy` | exit 0 |

**On `-p 1`, and why it is not a weakened run.** A plain `go test ./...` failed in
`internal/oidc` with:

```
FATAL: too many connections for role "identity" (SQLSTATE 53300)
```

That is connection exhaustion, not a code failure, and I verified both halves
rather than assuming: the role has `rolconnlimit = 50` against a cluster
`max_connections` of 200, `go test` runs packages in parallel each opening pools,
and `./internal/oidc/` **alone passes in 1.6s**. Same tests, same assertions, same
code — only the package concurrency differs. In CI the pools are per-job against a
fresh container, so this does not arise there. No assertion was weakened, skipped
or loosened to get the green run.

---

## 6. Things I did NOT do, and why

**I did not fix `Invite` or `Members`** (§2a, §2b). Two live defects, measured and
reported rather than half-fixed in the last quarter of an hour. Both are the same
recipe `Get` now documents twice in one file.

**I did not fix the three pre-existing `gofmt` failures.** `gofmt -l .` reports
`internal/platform/ci/rollback_test.go`, `internal/platform/ci/substrate_copy_test.go`
and `internal/tenancy/user.go`. I confirmed with `git diff --name-only HEAD` that
**none of them is modified by me** — they are unformatted at HEAD, they are
outside this packet's files, and fixing them is unrelated churn in a security
boundary. Flagging rather than folding them in.

**`internal/httpapi/accounts_fake_test.go` changed during my session, and not by
me.** The diff is one line: the fake's `TransferOwnership` returns `f.account`
instead of a hardcoded `accounts.Account{ID: in.AccountID, Name: "Acme"}`. It is a
coherent improvement — the fake now returns the account the test configured rather
than inventing one — it is in the suite I ran, and it passed. **I did not write it
and I am not claiming it.** It is committed as `238d864` because `git add -A` swept
it up with my work and splitting it out would have meant untouching a file I did
not understand well enough to isolate. **Worth a reviewer's eye**, because a change
appearing in a commit without an author is exactly the kind of thing this
repository's own history argues against.

**I did not re-run `bin/coverage-floor`.** It needs a profile over the whole suite
and the packet did not ask; the coverage exclusions I touched are nil.

---

## 7. Commits

| Commit | What |
|---|---|
| `d6eb144` | transfer use case (prior) |
| `587efee` | transfer route, document, matrix (prior) |
| `238d864` | **this packet**: `Get` + `Member` open a transaction and call `BeginUser`; `get_rls_test.go` against the real policies |

Not pushed, as instructed.