package accounts

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/tenancy"
	"github.com/anywaye/identity/internal/users"
)


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
			nil,
		),
	}
}

func TestInviteFindsTheInviterUnderTheRealPolicies(t *testing.T) {
	h := newRealAccountHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, uniqueAccountName(t, "invite-rls"), owner)

	ctx := tenancy.WithAccount(t.Context(), account.ID)

	invited, err := h.svc.Invite(ctx, InviteInput{
		AccountID: account.ID,
		Email:     dbtest.UniqueEmail(t),
		Role:      RoleMember,
		InvitedBy: owner,
	})
	if err != nil {
		t.Fatalf("Invite by the account's own owner = %v, want a pending invitation. "+
			"account_users carries `account_users_anywaye_members` (00018), which filters on "+
			"`user_id = anywaye.current_user_id()`, so a read that has not called "+
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

	plain := addRealMember(t, h, account.ID, RoleMember)
	if _, err := h.svc.Invite(ctx, InviteInput{
		AccountID: account.ID,
		Email:     dbtest.UniqueEmail(t),
		Role:      RoleMember,
		InvitedBy: plain,
	}); !errors.Is(err, ErrOwnerProtected) {
		t.Errorf("a member inviting a member = %v, want ErrOwnerProtected", err)
	}

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

func TestOnlyAnOwnerMayInviteAnAdminUnderTheRealPolicies(t *testing.T) {
	h := newRealAccountHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, uniqueAccountName(t, "invite-admin-hierarchy"), owner)
	admin := addRealMember(t, h, account.ID, RoleAdmin)
	member := addRealMember(t, h, account.ID, RoleMember)

	ctx := tenancy.WithAccount(t.Context(), account.ID)

	if _, err := h.svc.Invite(ctx, InviteInput{
		AccountID: account.ID, Email: dbtest.UniqueEmail(t), Role: RoleMember, InvitedBy: admin,
	}); err != nil {
		t.Errorf("an admin inviting a member = %v, want success", err)
	}

	if _, err := h.svc.Invite(ctx, InviteInput{
		AccountID: account.ID, Email: dbtest.UniqueEmail(t), Role: RoleMember, InvitedBy: member,
	}); !errors.Is(err, ErrOwnerProtected) {
		t.Errorf("a member inviting anybody = %v, want ErrOwnerProtected", err)
	}

	_, err := h.svc.Invite(ctx, InviteInput{
		AccountID: account.ID, Email: dbtest.UniqueEmail(t), Role: RoleAdmin, InvitedBy: admin,
	})
	if !errors.Is(err, ErrRoleNotInvitable) {
		t.Errorf("an admin inviting an admin = %v, want ErrRoleNotInvitable", err)
	}

	if _, err := h.svc.Invite(ctx, InviteInput{
		AccountID: account.ID, Email: dbtest.UniqueEmail(t), Role: RoleAdmin, InvitedBy: owner,
	}); err != nil {
		t.Errorf("an owner inviting an admin = %v, want success", err)
	}
}

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
			"`account_id = anywaye.current_account_id()`, a read on a bare pooled connection has "+
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

func TestTheAccountSelectPolicyIsInstalledUnderRealPolicies(t *testing.T) {
	pool := dbtest.Pool(t)

	var qual string
	err := pool.QueryRow(t.Context(),
		`SELECT pg_get_expr(polqual, polrelid) FROM pg_policy
		  WHERE polrelid = 'account_users'::regclass
		    AND polname = 'account_users_anywaye_select'`,
	).Scan(&qual)
	if err != nil {
		t.Fatalf("reading the membership account policy: %v. Without it, every account-scoped "+
			"test in this file passes for the wrong reason — the policy is their subject.",
			err)
	}
	if !strings.Contains(strings.ToLower(qual), "current_account_id") {
		t.Errorf("account_users_anywaye_select filters on %q, want a predicate naming "+
			"anywaye.current_account_id(). A policy that does not scope by the ACCOUNT is a "+
			"different boundary, and the empty member list this file exists for would be a "+
			"different bug.", qual)
	}
}

func TestTheCallerSelectPolicyIsInstalledUnderRealPolicies(t *testing.T) {
	pool := dbtest.Pool(t)

	var qual string
	err := pool.QueryRow(t.Context(),
		`SELECT pg_get_expr(polqual, polrelid) FROM pg_policy
		  WHERE polrelid = 'account_users'::regclass
		    AND polname = 'account_users_anywaye_members'`,
	).Scan(&qual)
	if err != nil {
		t.Fatalf("reading the membership caller policy: %v. Without it, both Invite tests "+
			"in this file pass for the wrong reason — the policy is their subject.", err)
	}
	if !strings.Contains(strings.ToLower(qual), "current_user_id") {
		t.Errorf("account_users_anywaye_members filters on %q, want a predicate naming "+
			"anywaye.current_user_id(). A policy that does not scope by the CALLER lets the "+
			"inviter's row through for anybody, and the invite privilege rules this file "+
			"exists for would be enforced by a boundary that is not there.", qual)
	}
}
