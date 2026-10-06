package accounts

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/tenancy"
)

// `Get` UNDER THE REAL POLICIES, and the reason this file exists separately from
// service_test.go.
//
// # THE GAP THIS FILE CLOSES
//
// Every other test in this package runs through `newHarness`, and that harness
// opens `dbtest.Schema` — a private schema whose tables are cloned with
// `LIKE public.<table> INCLUDING ALL`. LIKE copies columns, defaults, CHECKs and
// indexes. IT DOES NOT COPY ROW-LEVEL SECURITY, and dbtest.go says so itself:
// the clones "carry no row-level security … so there is no policy to grant and
// nothing here is a second copy of the boundary."
//
// Which means every assertion in service_test.go about membership visibility ran
// with NO POLICY AT ALL. `TestGetIsInvisibleToANonMember` passed against a table
// where every row is visible to every caller — which is a test of the query, not
// of the boundary. A member being refused was invisible to it, because there
// was nothing there to refuse them.
//
// # WHAT THAT HID
//
// migrations/00018 adds a fifth policy to `account_users`. The first four are on
// `account_id`; the fifth is on the caller:
//
//	account_users_cafaye_members  for select  using (user_id = cafaye.current_user_id())
//
// A caller who has not chosen an account has no `current_account_id()`, so the
// four account policies hide the row. The fifth is what lets a caller see their
// OWN memberships, and it is only in force once `cafaye.begin_user` has been
// called ON THE SAME TRANSACTION.
//
// `ListMine` opens a transaction and calls `tenancy.BeginUser` first, so its
// predicate is satisfied. `Get` read on `s.read.Queryer()` — a bare pooled
// connection, no transaction, no GUC — so every predicate was false, the
// membership row was filtered out by the DATABASE rather than refused by any
// assertion anywhere, and the handler rendered that as `404 Account not found`
// for the owner of their own account.
//
// # LISTMINE IS THE THIRD USE CASE WITH THE SAME SHAPE, AND IT IS HERE FOR THE SAME REASON
//
// `ListMine` answers "which accounts is THIS PERSON in", so it is scoped by the
// CALLER — `account_users_cafaye_members` (00018) — and it opens a transaction
// and calls `tenancy.BeginUser` first, exactly as `Get` does. The copy in
// service_test.go ran on `dbtest.Schema`, so it passed against a table with no
// policy at all: the query's own `where au.user_id = $1` did the scoping, and
// the test could not tell a correct query from a missing `BeginUser`. On
// `dbtest.Pool` the two are distinguishable — drop the `BeginUser` and the
// policy filters every row, so a user who owns an account is told they belong
// to none, which is the defect 90c6bea fixed and the reason this test exists.
//
// # WHY THE HARNESS IS DUPLICATED RATHER THAN PARAMETERISED
//
// It differs from `newHarness` in exactly one thing — `dbtest.Pool` for
// `dbtest.Schema` — and that one thing is the entire subject of this file.
// Parameterising the helper would make the difference a boolean at every call
// site, and a reader would have to know which value means "the policies are on".

// newRealPolicyHarness is newHarness against the tables whose policies are live.
func newRealPolicyHarness(t *testing.T) *harness {
	t.Helper()

	pool := dbtest.Pool(t)
	clk := clock.NewFake(time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC))
	events := &recordedEvents{}
	revokes := &recordedRevocations{}
	store := NewStore(pool)

	return &harness{
		store:   store,
		events:  events,
		revokes: revokes,
		clock:   clk,
		q:       pool,
		pool:    pool,
		svc: NewService(
			db.TxRunner{Pool: pool},
			store,
			events,
			revokes,
			clk,
			db.Direct{Pool: pool},
		),
	}
}

// uniqueAccountName is `dbtest.UniqueEmail` reduced to something `Slugify` can
// actually keep.
//
// The account slug is unique, and Slugify truncates it at 63 characters. A long
// test name plus a full unique address is longer than that, so the random tail —
// the only part that differs between runs — falls off the end and every run of
// this file collides on the same slug. This is the trap AGENTS.md records for the
// authorization matrix's fixtures ("names its accounts with a counter and not with
// the test path"), met here for the same reason.
func uniqueAccountName(t *testing.T, prefix string) string {
	t.Helper()

	local, _, _ := strings.Cut(dbtest.UniqueEmail(t), "@")
	// The local part is `<testname>-<12 hex bytes>`, and the 12 hex bytes are the
	// only part that differs between runs. Keeping just those, rather than the
	// whole address, is what makes the name short enough for the slug to hold.
	if len(local) < 13 {
		t.Fatalf("UniqueEmail returned %q, which has no %d-byte tail to keep", local, 12)
	}
	return prefix + "-" + local[len(local)-12:]
}

// TestGetFindsTheCallersOwnAccountUnderTheRealPolicies is the regression test for
// the 404. It goes red on the unfixed code with ErrNotAMember for the owner of
// their own account — exactly the 404 a browser saw.
//
// It asserts three things, and the third is what stops a future "fix" that
// over-corrects into reading the membership outside any scope at all:
//
//  1. a member CAN read their own account — the defect,
//  2. the role it returns is the role really in the table,
//  3. a stranger still cannot, so the fix did not become "turn the policy off".
func TestGetFindsTheCallersOwnAccountUnderTheRealPolicies(t *testing.T) {
	h := newRealPolicyHarness(t)
	member := addUser(t, h.q)
	account := h.owned(t, uniqueAccountName(t, "real-policies"), member)

	got, role, err := h.svc.Get(t.Context(), account.ID, member)
	if err != nil {
		t.Fatalf("Get(%s, its own owner) = %v, want the account. account_users carries "+
			"`account_users_cafaye_members` (00018), which filters on "+
			"`user_id = cafaye.current_user_id()`, so a read that has not called "+
			"tenancy.BeginUser ON ITS OWN TRANSACTION cannot see its own membership row: "+
			"the database filters it and the handler renders that as a 404.",
			account.ID, err)
	}
	if got.ID != account.ID {
		t.Errorf("Get returned account %s, want %s", got.ID, account.ID)
	}
	if role != RoleOwner {
		t.Errorf("Get returned role %q, want %q", role, RoleOwner)
	}

	stranger := addUser(t, h.q)
	if _, _, err := h.svc.Get(t.Context(), account.ID, stranger); !errors.Is(err, ErrNotAMember) {
		t.Errorf("a non-member reading a real account = %v, want ErrNotAMember", err)
	}

	// A missing account is indistinguishable from one the caller is not in, and
	// that is a security property rather than a convenience: a 403 for "not a
	// member" and a 404 for "no such account" is an existence oracle for anybody
	// who can guess an id. This is the third assertion
	// TestGetIsInvisibleToANonMember carried, and it moves here because it is the
	// same property — the database filters the row and the service maps the miss
	// to the one error — and it is only MEANINGFUL under the real policies,
	// where "the row was filtered" and "the row is not there" are the same event.
	if _, _, err := h.svc.Get(t.Context(), id.MustNew(), member); !errors.Is(err, ErrNotAMember) {
		t.Errorf("reading a missing account = %v, want ErrNotAMember — it must be "+
			"indistinguishable from not being a member", err)
	}
}

// TestListMineIsScopedToTheCallerUnderTheRealPolicies is the regression test
// for the empty account list, and the reason this file is not only about `Get`
// and `Member`.
//
// `ListMine` is scoped by the CALLER — `account_users_cafaye_members` (00018,
// `user_id = cafaye.current_user_id()`) — so a read that has not called
// `tenancy.BeginUser` ON ITS OWN TRANSACTION returns nothing: the database
// filters every row out and the product renders "you are not a member of any
// account". It is the same defect `Get` had, on the one use case that answers
// "which accounts am I in" rather than "what is this account", and it was fixed
// in the same commit (90c6bea) — but the copy in service_test.go ran on
// `dbtest.Schema`, where there is no policy to be refused by, so it passed
// against a table where the query's own `where au.user_id = $1` did all the
// scoping and nothing was tested but the query.
//
// It asserts the list is the CALLER's and nobody else's, which is the property
// the scoping exists for: a query scoped by an account id from a request body
// is how one tenant's data reaches another's.
func TestListMineIsScopedToTheCallerUnderTheRealPolicies(t *testing.T) {
	h := newRealPolicyHarness(t)
	mine := addUser(t, h.q)
	theirs := addUser(t, h.q)

	h.owned(t, uniqueAccountName(t, "list-mine-one"), mine)
	h.owned(t, uniqueAccountName(t, "list-mine-two"), mine)
	theirsAccount := h.owned(t, uniqueAccountName(t, "list-mine-theirs"), theirs)

	got, err := h.svc.ListMine(t.Context(), mine)
	if err != nil {
		t.Fatalf("ListMine: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("ListMine returned %d accounts, want 2: %+v", len(got), got)
	}
	for _, m := range got {
		if m.Account.ID == theirsAccount.ID {
			t.Error("ListMine returned somebody else's account")
		}
		if m.Role != RoleOwner {
			t.Errorf("%q has role %q, want %q", m.Account.Name, m.Role, RoleOwner)
		}
	}
}

// TestMemberSeesTheCallersOwnRowUnderTheRealPolicies is the same predicate read
// directly rather than through `Get`, because the two take different paths and
// only one of them being wrong is still wrong.
//
// `Member` is what `TransferOwnership` reads to authorize its actor on an account
// nobody has stood in yet, and to prove the heir is already a member. With the
// same missing `BeginUser`, a transfer would refuse the owner who asked for it —
// the identical bug wearing a different hat, and one the use-case tests cannot see
// because they run without policies either.
func TestMemberSeesTheCallersOwnRowUnderTheRealPolicies(t *testing.T) {
	h := newRealPolicyHarness(t)
	mine := addUser(t, h.q)
	account := h.owned(t, uniqueAccountName(t, "member-read"), mine)

	if _, err := h.svc.Member(t.Context(), account.ID, mine); err != nil {
		t.Errorf("Member for the account's own owner = %v, want the row", err)
	}

	other := addRealMember(t, h, account.ID, RoleMember)
	if _, err := h.svc.Member(t.Context(), account.ID, other); err != nil {
		t.Errorf("Member for a second, real member = %v, want the row", err)
	}
}

// addRealMember is `harness.member`, and the difference is the whole point.
//
// An INSERT into account_users meets the ordinary `with check`, which demands an
// account identity — 00018's fifth policy is `for select` and nothing else, so
// naming the caller does not admit this row. The account therefore has to be
// named, which is why this opens its own transaction instead of leaning on a
// helper written for a schema with no policies on it.
func addRealMember(t *testing.T, h *harness, accountID id.UUID, role Role) id.UUID {
	t.Helper()

	uid := addUser(t, h.q)
	err := db.TxRunner{Pool: h.pool}.Do(t.Context(),
		func(ctx context.Context, q db.Querier) error {
			if err := tenancy.BeginAccount(ctx, q, accountID); err != nil {
				return err
			}
			_, err := h.store.AddMember(ctx, q, Membership{AccountID: accountID, UserID: uid, Role: role})
			return err
		})
	if err != nil {
		t.Fatalf("adding a %s under the real policies: %v", role, err)
	}
	return uid
}

// TestTheMembershipUserPolicyIsInstalledUnderRealPolicies is the control.
//
// Without it, every test in this file would ALSO pass against a database where
// the fifth policy had been dropped — so a regression in migrations/00018 would
// leave this file green and the 404 would come back with the next caller. "This
// test passed" must not be able to mean "the boundary was not there".
//
// It is deliberately not in internal/tenancy, which proves the policies for the
// SUBSTRATE's own temporary tables: this one proves the test above is measuring
// the policies on identity's real account_users.
func TestTheMembershipUserPolicyIsInstalledUnderRealPolicies(t *testing.T) {
	pool := dbtest.Pool(t)

	var qual string
	err := pool.QueryRow(t.Context(),
		`SELECT pg_get_expr(polqual, polrelid) FROM pg_policy
		  WHERE polrelid = 'account_users'::regclass
		    AND polname = 'account_users_cafaye_members'`,
	).Scan(&qual)
	if err != nil {
		t.Fatalf("reading the membership user policy: %v. Without it, every test in this "+
			"file passes for the wrong reason — the policy is their whole subject.", err)
	}
	if !strings.Contains(strings.ToLower(qual), "current_user_id") {
		t.Errorf("account_users_cafaye_members filters on %q, want a predicate naming "+
			"cafaye.current_user_id(). A policy that does not scope by the CALLER is a "+
			"different boundary, and the 404 this file exists for would be a different bug.",
			qual)
	}
}
