package accounts

import (
	"context"
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
			users.NewStore(pool),
			events,
			revokes,
			clk,
			db.Direct{Pool: pool},
			nil,
		),
	}
}

func uniqueAccountName(t *testing.T, prefix string) string {
	t.Helper()

	local, _, _ := strings.Cut(dbtest.UniqueEmail(t), "@")
	if len(local) < 13 {
		t.Fatalf("UniqueEmail returned %q, which has no %d-byte tail to keep", local, 12)
	}
	return prefix + "-" + local[len(local)-12:]
}

func TestGetFindsTheCallersOwnAccountUnderTheRealPolicies(t *testing.T) {
	h := newRealPolicyHarness(t)
	member := addUser(t, h.q)
	account := h.owned(t, uniqueAccountName(t, "real-policies"), member)

	got, role, err := h.svc.Get(t.Context(), account.ID, member)
	if err != nil {
		t.Fatalf("Get(%s, its own owner) = %v, want the account. account_users carries "+
			"`account_users_anywaye_members` (00018), which filters on "+
			"`user_id = anywaye.current_user_id()`, so a read that has not called "+
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

	if _, _, err := h.svc.Get(t.Context(), id.MustNew(), member); !errors.Is(err, ErrNotAMember) {
		t.Errorf("reading a missing account = %v, want ErrNotAMember — it must be "+
			"indistinguishable from not being a member", err)
	}
}

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

func TestTheMembershipUserPolicyIsInstalledUnderRealPolicies(t *testing.T) {
	pool := dbtest.Pool(t)

	var qual string
	err := pool.QueryRow(t.Context(),
		`SELECT pg_get_expr(polqual, polrelid) FROM pg_policy
		  WHERE polrelid = 'account_users'::regclass
		    AND polname = 'account_users_anywaye_members'`,
	).Scan(&qual)
	if err != nil {
		t.Fatalf("reading the membership user policy: %v. Without it, every test in this "+
			"file passes for the wrong reason — the policy is their whole subject.", err)
	}
	if !strings.Contains(strings.ToLower(qual), "current_user_id") {
		t.Errorf("account_users_anywaye_members filters on %q, want a predicate naming "+
			"anywaye.current_user_id(). A policy that does not scope by the CALLER is a "+
			"different boundary, and the 404 this file exists for would be a different bug.",
			qual)
	}
}
