# REPORT — m41-identity-invitemembers-01 (W7)

Branch `worker/w7-invite-members`. Takes the two RLS defects
`REPORT-w2-authgaps-02.md` §2 measured and deliberately left, fixes both, and
adds the proof the previous packet's report says was missing for them.

---

## 1. Both defects: CONFIRMED, independently, before anything changed

The prior report is a hypothesis, so I re-measured both. The shape to look for
is a read on `store.Queryer()` rather than a transaction that calls
`cafaye.begin_user` — and `account_users` is the only table in this schema with a
caller-scoped select policy, so I read that off the live database rather than
trusting the report's table:

```
$ psql … -c "select polname, polcmd, pg_get_expr(polqual, polrelid) … "
account_users_cafaye_insert | (with check only)                                    | a
account_users_cafaye_delete | account_id = (SELECT cafaye.current_account_id())    | d
account_users_cafaye_members| user_id   = (SELECT cafaye.current_user_id())       | r   ← 00018
account_users_cafaye_select | account_id = (SELECT cafaye.current_account_id())    | r   ← 00016
account_users_cafaye_update | account_id = (SELECT cafaye.current_account_id())    | w
```

Five policies: four keyed on `account_id`, one on the caller. Two permissive
`select` policies are OR-ed, so a caller standing in an account sees all of its
membership rows, and a caller who has not chosen an account sees their own.

The measurement was a **test written first and run against the unmodified
service**, not a throwaway probe — that is §3.

| | Reported by W2b | Measured here, before the fix |
|---|---|---|
| `Invite` (§2a) | `err=only an owner may remove an owner` | `Invite by the account's own owner = only an owner may remove an owner, want a pending invitation` |
| `Members` (§2b) | `n=0 err=<nil>` | `Members listed 0 rows, want 3 — the account has an owner, an admin and a member` |

Both reproduce exactly. The two causes are also two different halves of the
boundary, which is why they do not get the same fix:

- **`Invite`** reads the *inviter's* membership — `s.store.Member(ctx,
  s.read.Queryer(), in.AccountID, in.InvitedBy)` at `service.go:488`. That row is
  admitted only by the **caller** policy, so it needs `begin_user`.
- **`Members`** lists an account's rows — `s.store.Members(ctx,
  s.read.Queryer(), accountID)` at `service.go:389`. Those rows are admitted by the
  **account** policy, so `begin_user` cannot help: no amount of naming the caller
  puts an account on the transaction. It needs `begin_account`.

`Invite` is the worse of the two by consequence — it blocks a write path, and the
owner of an account cannot invite anybody into it — and `Members` is the worse by
shape, because nothing fails at all: `GET /v1/accounts/:id/members` answers
`200 []` for an account full of members, and a product renders that as truth.

---

## 2. The fixes, and the shape each one took

### 2a. `Invite` — read the inviter through `Member`

One line, plus the comment that says why:

```go
inviter, err := s.Member(ctx, in.AccountID, in.InvitedBy)
```

`Member` already opens a transaction and calls `tenancy.BeginUser` — the previous
packet fixed it and left the reasoning on it. Calling it rather than repeating
the transaction here is the point: **there is one method that reads a membership
for a caller, it knows the GUC has to be named on a transaction, and every caller
of it inherits both.** A fifth hand-written transaction would have been a fifth
place to forget.

The error mapping is untouched: `ErrNotAMember` is still `ErrOwnerProtected`, and
everything else is still wrapped. That mapping is what made the bug hard to read
from the outside — "only an owner may remove an owner", about removing an owner,
in response to an invitation.

**The owner restriction is still decided, and still from the membership.** The
test asserts all four cases against the live policies, and two of them are there
because a fix that made the inviter visible *by not looking at it* would
over-correct:

| Inviter | Role offered | Answer |
|---|---|---|
| owner | member | 201 — the defect |
| admin | admin | `ErrRoleNotInvitable` |
| member | member | `ErrOwnerProtected` |
| stranger | member | `ErrOwnerProtected` |

**My first draft of that table was wrong and the test caught it.** I asserted
`ErrRoleNotInvitable` for a *member* inviting an admin; the member is refused one
hop earlier, by `!inviter.Role.AtLeast(RoleAdmin)` → `ErrOwnerProtected`, and
`ErrRoleNotInvitable` is the admin-invites-admin case. `TestOnlyAnOwnerMayInviteAnAdmin`
in `service_test.go` says so and I should have read it first.

### 2b. `Members` — a transaction, and a refusal when there is nothing to scope it by

```go
scoped, ok := tenancy.AccountFrom(ctx)
if !ok { … ErrNoIdentity … }
if scoped != accountID { … ErrNoIdentity … }
// then
s.uow.Do(ctx, func(ctx, q) error { rows, err := s.store.Members(ctx, q, accountID); … })
```

Three decisions in there, and the second is the one worth arguing about.

**The identity comes from the CONTEXT, through `tenancy.TxRunner`, not from the
argument.** `requireAccountRole` is the only place in this service that puts an
account on a context (`internal/httpapi/accounts.go:397`), and it does so *after*
a membership read has established the account is the caller's. So the identity
this read runs under is an established fact rather than the caller's argument.

The alternative — `tenancy.BeginAccount(ctx, q, accountID)`, naming the account
from the method's own parameter — would be one line shorter and is what I first
reached for. **It is wrong here, and `scope.go`'s "WHY begin_account IS CALLED
HERE AND NOWHERE ELSE" is why**: `Members` authorizes nothing at all (its doc
comment says so and means it — authorization is `requireAccountRole`'s job), so
handing the policy an account id straight from a method argument would grant the
read of any account's member list to any caller able to name one. The context is
only set where a membership check approved the account, and that check is the
whole reason this fix does not widen anything.

**The refusal is not decoration.** A context that names nothing, or names a
different account, leaves the same two questions in the query and no predicate
true — so the answer is `[]`, and an empty member list is a real answer as far as
any caller can tell. That is this defect, not a hypothetical one: fixed without
the refusal, the instance is gone and the class stays. `tenancy.BeginUser` refuses
the nil caller for exactly this reason ("a membership read with no membership to
find is not a thing anybody meant to ask for"), so this is the same rule about
the other half of the identity.

The sentinel is `tenancy.ErrNoIdentity`, which `writeTenancyError` does not
recognise, so it falls to `default: unexpected(w, r, o.logger, err)` — a **500
with a trace id**, logged. That is the right answer for a route reached without
the middleware meant to have authorized it, and it matches `requireAccountRole`'s
own rule ("a lookup that FAILS is a 500 and not a 403").

**No new sentinel, no new error mapping, no new route, no document entry.** The
two refusals are a 500, which is what the surface already did with an error it
did not recognise.

---

## 3. The proof: red first, and a control for each policy

`internal/accounts/invite_members_rls_test.go`, against `dbtest.Pool` — the
public tables, the app login role, the policies live. This is the only
arrangement in which "a member being refused" is observable at all: every other
test in the package runs on a schema cloned with `LIKE … INCLUDING ALL`, and LIKE
does not copy row-level security, so those tests have been asserting against a
table where **every row is visible to every caller**. That is why
`TestOnlyAnOwnerMayInviteAnAdmin` was green while the owner could not invite
anybody — it tests the query, not the boundary.

The harness is a third one (`newRealAccountHarness`) because this file needs the
pool **and** the account seam, which `newRealPolicyHarness` deliberately does not
wire:

| harness | pool | runner |
|---|---|---|
| `newHarness` (service_test.go) | `dbtest.Schema` | `db.TxRunner` |
| `newRealPolicyHarness` (get_rls_test.go) | `dbtest.Pool` | `db.TxRunner` |
| `newRealAccountHarness` (this file) | `dbtest.Pool` | `tenancy.TxRunner` — the production wiring, `cmd/identity/main.go:414` |

### Red, against the unmodified service

```
--- FAIL: TestInviteFindsTheInviterUnderTheRealPolicies (0.01s)
      invite_members_rls_test.go:119: Invite by the account's own owner = only an owner may
      remove an owner, want a pending invitation. …
--- FAIL: TestMembersListsEveryRowOfTheAccountUnderTheRealPolicies (0.02s)
      invite_members_rls_test.go:187: Members listed 0 rows, want 3 …
--- FAIL: TestMembersRefusesWithoutItsOwnAccountRatherThanAnsweringEmpty (0.03s)
      (both subtests)
--- PASS: TestGetFindsTheCallersOwnAccountUnderTheRealPolicies          ← prior packet, unaffected
--- PASS: TestMemberSeesTheCallersOwnRowUnderTheRealPolicies            ← prior packet, unaffected
--- PASS: TestTheMembershipUserPolicyIsInstalledUnderRealPolicies        ← control, correctly unaffected
--- PASS: TestTheAccountSelectPolicyIsInstalledUnderRealPolicies        ← control, correctly unaffected
```

The two prior-packet tests and the two controls passing while the three new ones
fail is the shape that matters: the new tests fail **for this defect** and not for
anything the packet before it left in the tree.

### Green, with the fix

All seven pass. The four cases in the `Invite` table above are asserted inside
the first one, so the rule that was bypassed is asserted as well as the one that
was broken.

### A control per policy, and why there are two

`get_rls_test.go` has a control for `account_users_cafaye_members`, which is the
policy `Invite` depends on. **This file adds one for `account_users_cafaye_select`**
— the account policy, which is what `Members` depends on. Without it, a database
where 00016's select policy had been dropped would let the count assertion pass
by showing every row in the table: "this test passed" must not be able to mean
"the boundary was not there".

The two controls are independent of the two fixes by construction: the count test
passes a *valid* account on the context, so it fails on the missing transaction
rather than on the refusal, and the refusal test passes no account at all, so it
fails on the missing refusal rather than on the transaction. Neither can stand in
for the other.

---

## 4. Verification — the runs, not the claims

| Gate | Result |
|---|---|
| `bin/prime` (`go mod download && go build ./... && go test -count=1 -p 4 ./...`) | **exit 0**, all 26 packages `ok` |
| skips in the run | **0** (`TEST_DATABASE_URL` exported, so the anti-skip guards were live) |
| `go vet ./...` | clean |
| `gofmt -l .` | clean for every file I touched (see §5) |
| `golangci-lint run ./internal/accounts/...` | one issue, pre-existing and not mine (`accounts_test.go:155`, QF1001) |
| `go test -race -count=1 -p 2` on `accounts`, `httpapi`, `tenancy` | exit 0 |
| `internal/accounts`, verbose | 69 tests, **0 skips** |

`internal/httpapi` is the package I most expected to break and it does not: both
callers of `Members` (`handleGetAccount`, `handleListMembers`) sit behind
`requireAccountRole`, which is what puts the account on the context the refusal
now requires. `authz_matrix_test.go` drives the real service against a real
database and passes.

---

## 5. Things I did NOT do, and why

**I did not touch `httpapi`.** The refusal needed no new sentinel and no new
mapping precisely because `writeTenancyError`'s `default` is already the right
answer. No route was added or changed, so nothing in the OpenAPI documents, the
endpoint table, `accountRouteScopes`, the authorization matrix or
`anonymousFamilyAudit` moved.

**I did not fix the three pre-existing `gofmt` failures.**
`gofmt -l .` reports `internal/platform/ci/rollback_test.go`,
`internal/platform/ci/substrate_copy_test.go` and `internal/tenancy/user.go`.
`git diff --name-only HEAD` lists none of them: they are unformatted at HEAD,
they are outside this packet's files, and fixing them is unrelated churn in a
security boundary. Flagging rather than folding in, as W2b did.

**I did not run `bin/coverage-floor`.** It needs a profile over the whole suite
and the packet did not ask for it. The exclusions are untouched. Saying so rather
than implying a number I did not measure.

**I did not add a session/api-key question to `Members`.** The use case takes no
credential and never has; `requireAccountRole` decides who is asking and this
method authorizes nobody. Adding a check here would give the service a second
answer to a question the middleware already answered once.

**I did not convert the rest of the package to `dbtest.Pool`.** The other twenty-
odd tests in `service_test.go` still run against a schema with no policies, and
several of them (`TestGetIsInvisibleToANonMember` among them) are testing the
query rather than the boundary. That is a real gap and it is not mine to close in
this packet; §6 says what I know about it.

---

## 6. Two things about the previous packet a reviewer should know

Neither is mine and I am not claiming either. Both came out of writing this fix.

**1. The `Get`/`Member` fix was never written in CHANGELOG.md, and it is not in
the commit the report names.** `REPORT-w2-authgaps-02.md` §7 lists `238d864` as
"`Get` + `Member` open a transaction and call `BeginUser`; `get_rls_test.go`".
`git show 238d864 --stat` says otherwise: that commit adds
`internal/accounts/get_rls_test.go` and **nothing else**. The service change
landed in `ee5dda4`, whose message is about the transfer handler's tests
(`git log -S 'naming the caller for the account read' -- internal/accounts/service.go`
names `ee5dda4` and no other commit). So the fix is in the branch and works —
I have read it and this packet builds on it — but the commit a reviewer would
look at for it does not contain it.

The CHANGELOG consequence is real: `grep begin_user CHANGELOG.md` finds only
`ListMine` (packet identity-caller-scope). My entry is the first the class has
had, and it says so and covers all four use cases rather than pretending the
other two were always fine.

**2. `TestGetIsInvisibleToANonMember` is a test of the query, not the boundary,
and it is green.** `get_rls_test.go`'s header says this about the package as a
whole; I am restating it as a live item because I hit it while writing this
file. It runs on `dbtest.Schema`, where no policy exists, so "a non-member cannot
read this account" is asserted against a table where any caller can read any
row. The assertion passes because the query is right. It would pass identically
if `account_users` had no row-level security at all — which is exactly the state
`dbtest.Schema` puts it in.

I did not change it: the fix for that is either converting those cases to
`dbtest.Pool` or deleting them in favour of `get_rls_test.go`, and the second is
a claim about another packet's test that deserves its own commit.

---

## 7. Commits

| Commit | What |
|---|---|
| *(this one)* | `Invite` reads the inviter through `Member`; `Members` opens a transaction through `tenancy.TxRunner` and refuses a context that does not name its own account; `invite_members_rls_test.go` against the real policies, red first; `transfer_test.go`'s fixture puts the account on its context; CHANGELOG |

One commit, because the two halves are one change: the same table, the same
missing-transaction recipe, and a test file that would not make sense split in
two. The branch is `worker/w7-invite-members`, not pushed, as instructed.

### The one test I had to change, and why

`transfer_test.go`'s `otherOwner` helper called `h.svc.Members(t.Context(),
account.ID)` — the use case directly, outside any request, so with no account on
the context. It now wraps the context in `tenancy.WithAccount`, which is what
`requireAccountRole` does for a real request. That is the whole change; the
helper is a fixture reading an account it just built, and the refusal is the new
contract it has to honour. It was the only call site in the repository affected,
and the failure was loud rather than silent — which is the refusal working.