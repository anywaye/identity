package accounts

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/tenancy"
	"github.com/cafaye/identity/internal/users"
)

// `Invite` and `Members` UNDER THE REAL POLICIES, and the second file in this
// package that has to run against `dbtest.Pool`.
//
// # THE SAME GAP get_rls_test.go CLOSED, IN THE TWO PLACES IT WAS LEFT
//
// REPORT-w2-authgaps-02.md §2 measured two more instances of the defect `Get`
// and `Member` had — a read on `s.read.Queryer()`, a bare pooled connection with
// no transaction and therefore no GUC — and deliberately left them rather than
// half-fix two more at the end of a budget. This file is that fix's proof.
//
// The recipe, from that report's own measurements:
//
//	Invite as the account's OWNER: err=only an owner may remove an owner
//	Members: n=0 err=<nil>          (the account has 2 real memberships)
//
// The first is a core write path refused to the owner of their own account: the
// inviter's membership row was filtered out by the DATABASE rather than by any
// assertion, `ErrNotAMember` was mapped to `ErrOwnerProtected`, and every
// invitation in that account failed. The second is worse, because nothing fails
// at all — `GET /v1/accounts/:id/members` answers `200 []` for an account full
// of members, and a product renders that as truth.
//
// `account_users` is the only table in this schema carrying a caller-scoped
// select policy, so this is the last of the class: the report read `pg_policy`
// to confirm it, and this file's control asserts the policies it depends on so
// the claim cannot rot silently.
//
// # AND THE INVITE PRIVILEGE RULES, WHICH WERE GREEN FOR THE SAME REASON
//
// `TestOnlyAnOwnerMayInviteAnAdmin` asserted the invite privilege rules — an
// admin may invite a member, only an owner may invite an admin, a member may not
// invite anybody — and it passed on `dbtest.Schema`, where the inviter's
// membership read always succeeds because there is no policy to filter it. Two
// of its cases are the regression test above; the two SUCCESSES (an admin
// inviting a member, an owner inviting an admin) are unique, and a success is
// the assertion that most needs the boundary. It is here as
// `TestOnlyAnOwnerMayInviteAnAdminUnderTheRealPolicies`.
//
// # WHY THE HARNESS IS DUPLICATED A THIRD TIME, AND WHY IT IS NOT A COPY
//
// newHarness runs against `dbtest.Schema`, whose tables are cloned with `LIKE
// public.<table> INCLUDING ALL` — and LIKE does not copy row-level security, so
// there is no policy there to be refused by. Every test in service_test.go that
// exercises membership visibility has been running with no policy at all: it
// tests the query, not the boundary. newRealPolicyHarness (get_rls_test.go)
// fixed that for `Get` and `Member`; this file needs the same pool AND the
// account seam, which the other harness deliberately does not wire:
//
//   - `newHarness`         — dbtest.Schema, db.TxRunner
//   - `newRealPolicyHarness` — dbtest.Pool, db.TxRunner
//   - `newRealAccountHarness` — dbtest.Pool, tenancy.TxRunner
//
// The third is the production wiring (cmd/identity/main.go builds the service
// with `tenancy.TxRunner`), and `Members` cannot work without it: its rows are
// filtered by the ACCOUNT, not by the caller, so no amount of `BeginUser` names
// them. A boolean parameter would make a reader have to know which value means
// "the policies are on AND the account seam is installed".

// newRealAccountHarness is the production wiring against the tables whose
// policies are live.
func newRealAccountHarness(t *testing.T) *harness {
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
			tenancy.TxRunner{TxRunner: db.TxRunner{Pool: pool}},
			store,
			users.NewStore(pool),
			events,
			revokes,
			clk,
			db.Direct{Pool: pool},
			nil, // no mailer: these tests are about the RLS policies, not the email
		),
	}
}

// TestInviteFindsTheInviterUnderTheRealPolicies is the regression test for the
// owner who cannot invite anybody.
//
// It asserts four things, and the last three are what stops a "fix" that
// over-corrects into "the inviter's role is not checked any more":
//
//  1. the OWNER may invite a member — the defect,
//  2. an admin still may NOT hand out an admin,
//  3. a member may not invite anybody,
//  4. a stranger is refused with the same error a demoted caller gets.
func TestInviteFindsTheInviterUnderTheRealPolicies(t *testing.T) {
	h := newRealAccountHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, uniqueAccountName(t, "invite-rls"), owner)

	// The context carries the account because requireAccountRole put it there:
	// this is what a request to POST /v1/accounts/{id}/invitations actually
	// arrives with, and the invitation INSERT below meets account_invitations'
	// `with check` on that identity.
	ctx := tenancy.WithAccount(t.Context(), account.ID)

	invited, err := h.svc.Invite(ctx, InviteInput{
		AccountID: account.ID,
		Email:     dbtest.UniqueEmail(t),
		Role:      RoleMember,
		InvitedBy: owner,
	})
	if err != nil {
		t.Fatalf("Invite by the account's own owner = %v, want a pending invitation. "+
			"account_users carries `account_users_cafaye_members` (00018), which filters on "+
			"`user_id = cafaye.current_user_id()`, so a read that has not called "+
			"tenancy.BeginUser ON ITS OWN TRANSACTION cannot see the inviter's own row: the "+
			"database filters it and this maps ErrNotAMember to ErrOwnerProtected, which is "+
			"how the owner of an account came to be unable to invite anybody into it.",
			err)
	}
	if invited.Invitation.ID.IsZero() {
		t.Error("Invite returned an invitation with no id")
	}
	if invited.Token == "" {
		t.Error("Invite returned no token; the invitation could never be redeemed")
	}
	if invited.Invitation.Role != RoleMember {
		t.Errorf("Invite created a %q invitation, want %q", invited.Invitation.Role, RoleMember)
	}

	// (2) The owner restriction is read off the SAME membership row, so a fix
	// that made the inviter visible by not looking at it would over-correct
	// here: an admin would be able to clone themselves into a second admin.
	admin := addRealMember(t, h, account.ID, RoleAdmin)
	if _, err := h.svc.Invite(ctx, InviteInput{
		AccountID: account.ID,
		Email:     dbtest.UniqueEmail(t),
		Role:      RoleAdmin,
		InvitedBy: admin,
	}); !errors.Is(err, ErrRoleNotInvitable) {
		t.Errorf("an admin inviting an admin = %v, want ErrRoleNotInvitable — the rule is "+
			"about the INVITER, so it has to be decided from the membership this fix made "+
			"visible rather than skipped", err)
	}

	// (3) A member cannot invite anybody at all, which is a DIFFERENT refusal —
	// one hop earlier, and about the inviter's role rather than the role they
	// offered. It is here because it is the assertion most likely to be broken by
	// a fix that reads the inviter from anywhere but the membership table.
	plain := addRealMember(t, h, account.ID, RoleMember)
	if _, err := h.svc.Invite(ctx, InviteInput{
		AccountID: account.ID,
		Email:     dbtest.UniqueEmail(t),
		Role:      RoleMember,
		InvitedBy: plain,
	}); !errors.Is(err, ErrOwnerProtected) {
		t.Errorf("a member inviting a member = %v, want ErrOwnerProtected", err)
	}

	// (4) And a stranger is refused as one, rather than invited on a row the
	// policy happened to let through.
	stranger := addUser(t, h.q)
	if _, err := h.svc.Invite(ctx, InviteInput{
		AccountID: account.ID,
		Email:     dbtest.UniqueEmail(t),
		Role:      RoleMember,
		InvitedBy: stranger,
	}); !errors.Is(err, ErrOwnerProtected) {
		t.Errorf("a stranger inviting into an account = %v, want ErrOwnerProtected", err)
	}
}

// TestOnlyAnOwnerMayInviteAnAdminUnderTheRealPolicies is the invite privilege
// rules under the real policies, and the reason this file is not only the two
// regression tests above.
//
// The copy in service_test.go asserted these rules and passed on `dbtest.Schema`,
// where the inviter's membership read always succeeds because there is no policy
// to filter it — so it was green while the owner could not invite anybody, which
// is the defect the test above is the regression test for. Two of its cases (an
// admin inviting an admin, a member inviting anybody) are that test; the two
// SUCCESSES are unique, and a success is the assertion that most needs the
// boundary: it is the inviter's own row being visible to the caller policy and
// the invitation's `with check` being satisfied by the account identity, neither
// of which a policy-free schema can refuse.
//
// It runs against the production wiring (`newRealAccountHarness`), and the
// context carries the account because that is what `requireAccountRole` does for
// a real request: the invitation INSERT below meets `account_invitations`'s
// `with check` on that identity.
func TestOnlyAnOwnerMayInviteAnAdminUnderTheRealPolicies(t *testing.T) {
	h := newRealAccountHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, uniqueAccountName(t, "invite-admin-hierarchy"), owner)
	admin := addRealMember(t, h, account.ID, RoleAdmin)
	member := addRealMember(t, h, account.ID, RoleMember)

	ctx := tenancy.WithAccount(t.Context(), account.ID)

	// An admin inviting a member: allowed. The one asymmetry's permissive half.
	if _, err := h.svc.Invite(ctx, InviteInput{
		AccountID: account.ID, Email: dbtest.UniqueEmail(t), Role: RoleMember, InvitedBy: admin,
	}); err != nil {
		t.Errorf("an admin inviting a member = %v, want success", err)
	}

	// A member inviting anybody: refused, one hop earlier, about the inviter's
	// role rather than the role offered.
	if _, err := h.svc.Invite(ctx, InviteInput{
		AccountID: account.ID, Email: dbtest.UniqueEmail(t), Role: RoleMember, InvitedBy: member,
	}); !errors.Is(err, ErrOwnerProtected) {
		t.Errorf("a member inviting anybody = %v, want ErrOwnerProtected", err)
	}

	// An admin inviting an admin: refused. The privilege has to be granted by
	// somebody who already holds it, or an admin can clone themselves.
	_, err := h.svc.Invite(ctx, InviteInput{
		AccountID: account.ID, Email: dbtest.UniqueEmail(t), Role: RoleAdmin, InvitedBy: admin,
	})
	if !errors.Is(err, ErrRoleNotInvitable) {
		t.Errorf("an admin inviting an admin = %v, want ErrRoleNotInvitable", err)
	}

	// An owner inviting an admin: allowed. The one asymmetry's restrictive half.
	if _, err := h.svc.Invite(ctx, InviteInput{
		AccountID: account.ID, Email: dbtest.UniqueEmail(t), Role: RoleAdmin, InvitedBy: owner,
	}); err != nil {
		t.Errorf("an owner inviting an admin = %v, want success", err)
	}
}

// TestMembersListsEveryRowOfTheAccountUnderTheRealPolicies is the regression
// test for the empty member list.
//
// A count is the assertion rather than the contents because the failure has no
// error: `n=0 err=<nil>` is exactly what the report measured, and a test that
// only checked the error would have been green the whole time. The roles are
// then checked too, so a list of the right LENGTH from the wrong rows — three
// memberships of some other account, which a different mistake could produce —
// does not pass as the same thing.
func TestMembersListsEveryRowOfTheAccountUnderTheRealPolicies(t *testing.T) {
	h := newRealAccountHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, uniqueAccountName(t, "members-rls"), owner)
	admin := addRealMember(t, h, account.ID, RoleAdmin)
	plain := addRealMember(t, h, account.ID, RoleMember)

	members, err := h.svc.Members(tenancy.WithAccount(t.Context(), account.ID), account.ID)
	if err != nil {
		t.Fatalf("Members(%s) = %v, want the account's three memberships", account.ID, err)
	}

	if len(members) != 3 {
		t.Fatalf("Members listed %d rows, want 3 — the account has an owner, an admin and a "+
			"member. An EMPTY list here is the defect: account_users is scoped by "+
			"`account_id = cafaye.current_account_id()`, a read on a bare pooled connection has "+
			"set no account, so the database filtered every row and the caller was told this "+
			"account has nobody in it.", len(members))
	}

	roles := make(map[id.UUID]Role, len(members))
	for _, m := range members {
		if m.Account.ID != account.ID {
			t.Errorf("Members returned a membership of account %s, want %s", m.Account.ID, account.ID)
		}
		roles[m.UserID] = m.Role
	}
	for _, want := range []struct {
		user id.UUID
		role Role
	}{
		{owner, RoleOwner},
		{admin, RoleAdmin},
		{plain, RoleMember},
	} {
		if got := roles[want.user]; got != want.role {
			t.Errorf("member %s is listed as %q, want %q", want.user, got, want.role)
		}
	}
}

// TestMembersRefusesWithoutItsOwnAccountRatherThanAnsweringEmpty is the check on
// the fix rather than on the defect.
//
// `Members` now refuses a request that is not standing in the account it was
// asked about, and this is why that is a refusal and not a comment: the rows are
// filtered by the ACCOUNT, so a read that does not name one returns nothing, and
// nothing is indistinguishable from an account with no members. That is the
// same shape `tenancy.BeginUser` refuses the nil caller for — "a membership
// read with no membership to find is not a thing anybody meant to ask for" — and
// the HTTP layer renders an unrecognized error as a 500 with a trace id, which
// is the right answer for a route that was reached without its middleware.
func TestMembersRefusesWithoutItsOwnAccountRatherThanAnsweringEmpty(t *testing.T) {
	h := newRealAccountHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, uniqueAccountName(t, "members-scope"), owner)
	addRealMember(t, h, account.ID, RoleMember)

	t.Run("no account on the context", func(t *testing.T) {
		members, err := h.svc.Members(t.Context(), account.ID)
		if !errors.Is(err, tenancy.ErrNoIdentity) {
			t.Errorf("Members with no account on the context = %v, want a refusal naming the "+
				"missing identity. Answering %d rows instead is the silent failure this "+
				"defect already was: an empty member list is a real answer as far as any "+
				"caller can tell.", err, len(members))
		}
		if len(members) != 0 {
			t.Errorf("Members returned %d rows alongside an error, want none", len(members))
		}
	})

	t.Run("a different account on the context", func(t *testing.T) {
		elsewhere := addUser(t, h.q)
		other := h.owned(t, uniqueAccountName(t, "members-other"), elsewhere)

		members, err := h.svc.Members(tenancy.WithAccount(t.Context(), other.ID), account.ID)
		if !errors.Is(err, tenancy.ErrNoIdentity) {
			t.Errorf("Members(%s) while standing in %s = %v, want a refusal. The query is "+
				"scoped by both, so the mismatch answers neither one: it returns the other "+
				"account's rows filtered to this id, which is the empty list again.",
				account.ID, other.ID, err)
		}
		if len(members) != 0 {
			t.Errorf("Members returned %d rows alongside an error, want none", len(members))
		}
	})
}

// TestTheAccountSelectPolicyIsInstalledUnderRealPolicies is the control for
// TestMembersListsEveryRowOfTheAccountUnderTheRealPolicies.
//
// get_rls_test.go has one for `account_users_cafaye_members`, which is the
// policy `Invite` depends on. This is the OTHER one: `Members` is scoped by the
// account rather than by the caller, so a run against a database where 00016's
// select policy had been dropped would see every row of the table and this
// file's central assertion would be satisfied by the boundary being absent.
// "This test passed" must not be able to mean "the boundary was not there".
func TestTheAccountSelectPolicyIsInstalledUnderRealPolicies(t *testing.T) {
	pool := dbtest.Pool(t)

	var qual string
	err := pool.QueryRow(t.Context(),
		`SELECT pg_get_expr(polqual, polrelid) FROM pg_policy
		  WHERE polrelid = 'account_users'::regclass
		    AND polname = 'account_users_cafaye_select'`,
	).Scan(&qual)
	if err != nil {
		t.Fatalf("reading the membership account policy: %v. Without it, every account-scoped "+
			"test in this file passes for the wrong reason — the policy is their subject.",
			err)
	}
	if !strings.Contains(strings.ToLower(qual), "current_account_id") {
		t.Errorf("account_users_cafaye_select filters on %q, want a predicate naming "+
			"cafaye.current_account_id(). A policy that does not scope by the ACCOUNT is a "+
			"different boundary, and the empty member list this file exists for would be a "+
			"different bug.", qual)
	}
}

// TestTheCallerSelectPolicyIsInstalledUnderRealPolicies is the control for the
// two Invite tests, and it is here rather than only in get_rls_test.go because
// this file's Invite tests are the ones that would pass without it.
//
// `Invite` reads the inviter's membership through `Member`, which names the
// caller — so the read is admitted by `account_users_cafaye_members` (00018,
// `user_id = cafaye.current_user_id()`). Drop that policy and the read still
// succeeds, because a table with no policy on it shows every row to every
// caller: the inviter is found, the invitation is created, and both Invite tests
// above stay green while the boundary they depend on is gone. get_rls_test.go
// has a control for the same policy; this one is the same assertion repeated
// where it is load-bearing, so this file is self-contained — a reader does not
// have to know that another file's control is what stands between these tests and
// a database with no caller scope.
//
// The invitation WRITE's `with check` (`account_invitations_cafaye_insert`) is
// not controlled here. It is one of the five tables'
// `TestTenancyIdentityOwnsItsFiveTables` in internal/tenancy asserts, at the
// suite level, on every run — which is the right home for a property all five
// tables share.
func TestTheCallerSelectPolicyIsInstalledUnderRealPolicies(t *testing.T) {
	pool := dbtest.Pool(t)

	var qual string
	err := pool.QueryRow(t.Context(),
		`SELECT pg_get_expr(polqual, polrelid) FROM pg_policy
		  WHERE polrelid = 'account_users'::regclass
		    AND polname = 'account_users_cafaye_members'`,
	).Scan(&qual)
	if err != nil {
		t.Fatalf("reading the membership caller policy: %v. Without it, both Invite tests "+
			"in this file pass for the wrong reason — the policy is their subject.", err)
	}
	if !strings.Contains(strings.ToLower(qual), "current_user_id") {
		t.Errorf("account_users_cafaye_members filters on %q, want a predicate naming "+
			"cafaye.current_user_id(). A policy that does not scope by the CALLER lets the "+
			"inviter's row through for anybody, and the invite privilege rules this file "+
			"exists for would be enforced by a boundary that is not there.", qual)
	}
}
