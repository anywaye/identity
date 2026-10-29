package accounts

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/anywaye/identity/internal/outbox"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/tenancy"
	"github.com/anywaye/identity/internal/users"
)


func TestLastOwnerProtectionUnderTheRealPolicies(t *testing.T) {
	t.Run("the only owner cannot demote themselves", func(t *testing.T) {
		h := newRealAccountHarness(t)
		owner := addUser(t, h.q)
		account := h.owned(t, uniqueAccountName(t, "sole-owner"), owner)
		addRealMember(t, h, account.ID, RoleMember)

		_, err := h.svc.ChangeRole(tenancy.WithAccount(t.Context(), account.ID), ChangeRoleInput{
			AccountID: account.ID, UserID: owner, Role: RoleMember, Actor: owner,
		})
		if !errors.Is(err, ErrSelfRoleChange) {
			t.Errorf("demoting the only owner = %v, want ErrSelfRoleChange", err)
		}
		assertRole(t, h, account.ID, owner, RoleOwner)
	})

	t.Run("the only owner cannot be removed", func(t *testing.T) {
		h := newRealAccountHarness(t)
		owner := addUser(t, h.q)
		account := h.owned(t, uniqueAccountName(t, "undeletable-owner"), owner)

		err := h.svc.RemoveMember(tenancy.WithAccount(t.Context(), account.ID), RemoveMemberInput{
			AccountID: account.ID, UserID: owner, Actor: owner,
		})
		if !errors.Is(err, ErrLastOwner) {
			t.Errorf("removing the only owner = %v, want ErrLastOwner", err)
		}
		assertRole(t, h, account.ID, owner, RoleOwner)
	})

	t.Run("one of two owners may step down", func(t *testing.T) {
		h := newRealAccountHarness(t)
		first := addUser(t, h.q)
		account := h.owned(t, uniqueAccountName(t, "two-owners"), first)
		second := addRealMember(t, h, account.ID, RoleOwner)

		updated, err := h.svc.ChangeRole(tenancy.WithAccount(t.Context(), account.ID), ChangeRoleInput{
			AccountID: account.ID, UserID: first, Role: RoleAdmin, Actor: first,
		})
		if err != nil {
			t.Fatalf("one of two owners stepping down: %v", err)
		}
		if updated.Role != RoleAdmin {
			t.Errorf("role = %q, want %q", updated.Role, RoleAdmin)
		}
		assertRole(t, h, account.ID, second, RoleOwner)
	})

	t.Run("a member can be promoted to owner, which adds one", func(t *testing.T) {
		h := newRealAccountHarness(t)
		owner := addUser(t, h.q)
		account := h.owned(t, uniqueAccountName(t, "promotion"), owner)
		successor := addRealMember(t, h, account.ID, RoleAdmin)

		if _, err := h.svc.ChangeRole(tenancy.WithAccount(t.Context(), account.ID), ChangeRoleInput{
			AccountID: account.ID, UserID: successor, Role: RoleOwner, Actor: owner,
		}); err != nil {
			t.Fatalf("promoting to owner: %v", err)
		}
		if _, err := h.svc.ChangeRole(tenancy.WithAccount(t.Context(), account.ID), ChangeRoleInput{
			AccountID: account.ID, UserID: owner, Role: RoleMember, Actor: successor,
		}); err != nil {
			t.Fatalf("the first owner stepping down: %v", err)
		}
		assertRole(t, h, account.ID, successor, RoleOwner)
	})
}

func TestRemoveMemberThroughTheServiceUnderTheRealPolicies(t *testing.T) {
	h := newRealAccountHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, uniqueAccountName(t, "departures"), owner)
	admin := addRealMember(t, h, account.ID, RoleAdmin)
	target := addRealMember(t, h, account.ID, RoleMember)
	ctx := tenancy.WithAccount(t.Context(), account.ID)

	if err := h.svc.RemoveMember(ctx, RemoveMemberInput{
		AccountID: account.ID, UserID: target, Actor: admin,
	}); err != nil {
		t.Errorf("an admin removing a member = %v, want success", err)
	}
	if _, err := h.svc.Member(t.Context(), account.ID, target); !errors.Is(err, ErrNotAMember) {
		t.Errorf("the member survived removal: %v", err)
	}

	err := h.svc.RemoveMember(ctx, RemoveMemberInput{
		AccountID: account.ID, UserID: owner, Actor: admin,
	})
	if !errors.Is(err, ErrOwnerProtected) {
		t.Errorf("an admin removing the owner = %v, want ErrOwnerProtected", err)
	}
	assertRole(t, h, account.ID, owner, RoleOwner)

	if err := h.svc.RemoveMember(ctx, RemoveMemberInput{
		AccountID: account.ID, UserID: admin, Actor: owner,
	}); err != nil {
		t.Errorf("an owner removing an admin = %v, want success", err)
	}
}

func TestRemoveMemberRevokesTheCredentialsTheyHeldUnderTheRealPolicies(t *testing.T) {
	h := newRealAccountHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, uniqueAccountName(t, "departures"), owner)
	target := addRealMember(t, h, account.ID, RoleMember)
	ctx := tenancy.WithAccount(t.Context(), account.ID)

	if err := h.svc.RemoveMember(ctx, RemoveMemberInput{
		AccountID: account.ID, UserID: target, Actor: owner,
	}); err != nil {
		t.Fatalf("removing: %v", err)
	}

	if h.revokes.count() != 1 {
		t.Fatalf("the removal swept credentials %d times, want 1", h.revokes.count())
	}
	got := h.revokes.calls[0]
	if got.accountID != account.ID {
		t.Errorf("the sweep was scoped to account %s, want %s", got.accountID, account.ID)
	}
	if got.userID != target {
		t.Errorf("the sweep was scoped to user %s, want the member who was removed %s", got.userID, target)
	}
	if !got.at.Equal(h.clock.Now()) {
		t.Errorf("the sweep ran at %s, want the service clock's %s", got.at, h.clock.Now())
	}

	before := h.revokes.count()
	if err := h.svc.RemoveMember(ctx, RemoveMemberInput{
		AccountID: account.ID, UserID: owner, Actor: addRealMember(t, h, account.ID, RoleAdmin),
	}); !errors.Is(err, ErrOwnerProtected) {
		t.Fatalf("an admin removing the owner = %v, want ErrOwnerProtected", err)
	}
	if h.revokes.count() != before {
		t.Error("a refused removal swept credentials anyway")
	}
}

func TestARemovalThatCannotSweepRollsBackUnderTheRealPolicies(t *testing.T) {
	h := newRealAccountHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, uniqueAccountName(t, "departures"), owner)
	target := addRealMember(t, h, account.ID, RoleMember)
	ctx := tenancy.WithAccount(t.Context(), account.ID)

	h.revokes.failWith = errors.New("the api_keys table is not reachable")
	if err := h.svc.RemoveMember(ctx, RemoveMemberInput{
		AccountID: account.ID, UserID: target, Actor: owner,
	}); err == nil {
		t.Fatal("a removal succeeded with a revoker that failed")
	}

	if _, err := h.svc.Member(t.Context(), account.ID, target); err != nil {
		t.Errorf("the membership was removed even though the sweep failed: %v", err)
	}
	for _, e := range h.events.appended {
		if e.Type == outbox.EventMemberRemoved {
			t.Error("identity.member.removed was announced for a removal that rolled back")
		}
	}
}

func TestARemovalWithNoRevokerStillRemovesTheMembershipUnderTheRealPolicies(t *testing.T) {
	h := newRealAccountHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, uniqueAccountName(t, "departures"), owner)
	target := addRealMember(t, h, account.ID, RoleMember)
	ctx := tenancy.WithAccount(t.Context(), account.ID)

	withoutSweep := NewService(
		tenancy.TxRunner{TxRunner: db.TxRunner{Pool: h.pool}},
		h.store,
		users.NewStore(h.pool),
		h.events,
		nil,
		h.clock,
		db.Direct{Pool: h.pool},
		nil,
	)
	if err := withoutSweep.RemoveMember(ctx, RemoveMemberInput{
		AccountID: account.ID, UserID: target, Actor: owner,
	}); err != nil {
		t.Fatalf("removing with no revoker wired: %v", err)
	}
	if _, err := withoutSweep.Member(t.Context(), account.ID, target); !errors.Is(err, ErrNotAMember) {
		t.Errorf("the membership survived a removal with no revoker: %v", err)
	}
}

func TestChangeRoleEmitsBothRolesUnderTheRealPolicies(t *testing.T) {
	h := newRealAccountHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, uniqueAccountName(t, "promotions"), owner)
	target := addRealMember(t, h, account.ID, RoleMember)
	ctx := tenancy.WithAccount(t.Context(), account.ID)

	if _, err := h.svc.ChangeRole(ctx, ChangeRoleInput{
		AccountID: account.ID, UserID: target, Role: RoleAdmin, Actor: owner,
	}); err != nil {
		t.Fatalf("ChangeRole: %v", err)
	}

	e := h.events.payloadFor(t, outbox.EventMemberRoleChanged)
	if want := account.ID.String(); e.Subject != want {
		t.Errorf("subject = %q, want the account id %q", e.Subject, want)
	}
	for _, want := range []string{`"previous_role":"member"`, `"role":"admin"`} {
		if !strings.Contains(string(e.Data), want) {
			t.Errorf("the payload %s does not contain %s", e.Data, want)
		}
	}
}

func TestRemoveMemberEmitsTheRoleTheyHeldUnderTheRealPolicies(t *testing.T) {
	h := newRealAccountHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, uniqueAccountName(t, "emitting"), owner)
	target := addRealMember(t, h, account.ID, RoleAdmin)
	ctx := tenancy.WithAccount(t.Context(), account.ID)

	if err := h.svc.RemoveMember(ctx, RemoveMemberInput{
		AccountID: account.ID, UserID: target, Actor: owner,
	}); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}

	e := h.events.payloadFor(t, outbox.EventMemberRemoved)
	if !strings.Contains(string(e.Data), `"role":"admin"`) {
		t.Errorf("the payload %s does not carry the role they held", e.Data)
	}
	if want := account.ID.String(); e.Subject != want {
		t.Errorf("subject = %q, want the account id %q", e.Subject, want)
	}
}

func TestProvisionUnderTheRealPolicies(t *testing.T) {
	h := newRealAccountHarness(t)
	email := dbtest.UniqueEmail(t)
	userID := addUserWithEmail(t, h.q, email)

	var account Account
	var membership Membership
	runner := tenancy.TxRunner{TxRunner: db.TxRunner{Pool: h.pool}}

	err := runner.Do(t.Context(), func(ctx context.Context, tx db.Querier) error {
		created, err := h.svc.Provision(ctx, tx, userID, email)
		if err != nil {
			return err
		}
		account = created

		if err := tenancy.BeginAccount(ctx, tx, created.ID); err != nil {
			return err
		}

		m, err := h.svc.AddOwner(ctx, tx, created.ID, userID)
		if err != nil {
			return err
		}
		membership = m
		return nil
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	if !account.Personal {
		t.Error("Provision made a team account")
	}
	if want := PersonalName(email); account.Name != want {
		t.Errorf("name = %q, want the email local part %q", account.Name, want)
	}
	if want := PersonalSlug(email, userID); account.Slug != want {
		t.Errorf("slug = %q, want %q", account.Slug, want)
	}
	if membership.Role != RoleOwner {
		t.Errorf("the membership's role is %q, want %q", membership.Role, RoleOwner)
	}
	h.events.only(t, outbox.EventAccountCreated)
}

func TestTwoPeopleWithTheSameLocalPartBothRegisterUnderTheRealPolicies(t *testing.T) {
	h := newRealAccountHarness(t)
	runner := tenancy.TxRunner{TxRunner: db.TxRunner{Pool: h.pool}}

	var createdIDs []id.UUID
	var wantUIDs []id.UUID
	var wantSlugs []string
	var wantNames []string
	for i := 0; i < 2; i++ {
		email := "kaka-" + dbtest.UniqueEmail(t)[len("kaka-"):]
		uid := addUserWithEmail(t, h.q, email)
		wantUIDs = append(wantUIDs, uid)
		wantSlugs = append(wantSlugs, PersonalSlug(email, uid))
		wantNames = append(wantNames, PersonalName(email))
		var created Account
		if err := runner.Do(t.Context(), func(ctx context.Context, tx db.Querier) error {
			c, err := h.svc.Provision(ctx, tx, uid, email)
			if err != nil {
				return err
			}
			created = c
			if err := tenancy.BeginAccount(ctx, tx, created.ID); err != nil {
				return err
			}
			_, err = h.svc.AddOwner(ctx, tx, created.ID, uid)
			return err
		}); err != nil {
			t.Fatalf("provisioning a personal account for %s: %v", email, err)
		}
		createdIDs = append(createdIDs, created.ID)
		if created.Slug != wantSlugs[i] {
			t.Errorf("provisioned slug %q, want PersonalSlug %q for user %s", created.Slug, wantSlugs[i], uid)
		}
		if created.Name != wantNames[i] {
			t.Errorf("provisioned name %q, want PersonalName %q", created.Name, wantNames[i])
		}
		if !created.Personal {
			t.Errorf("provisioned account %s is not marked personal", created.ID)
		}
	}

	if wantSlugs[0] == wantSlugs[1] {
		t.Fatalf("two users with the same local part produced the same slug %q — PersonalSlug is not unique per user", wantSlugs[0])
	}

	var personal int
	if err := h.q.QueryRow(t.Context(), `SELECT count(*) FROM accounts WHERE personal AND id = ANY($1)`, createdIDs).Scan(&personal); err != nil {
		t.Fatalf("counting: %v", err)
	}
	if personal != 2 {
		rows, _ := h.q.Query(t.Context(), `SELECT id, slug, personal, created_at FROM accounts WHERE id = ANY($1) ORDER BY created_at`, createdIDs)
		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var id, slug string
				var pers bool
				var at string
				_ = rows.Scan(&id, &slug, &pers, &at)
				t.Logf("personal row: id=%s slug=%q personal=%v created_at=%s", id, slug, pers, at)
			}
		}
		t.Errorf("%d personal accounts exist among the 2 just created, want 2 — the second registration collided on the slug", personal)
	}

	for i := range createdIDs {
		m, err := h.svc.Member(t.Context(), createdIDs[i], wantUIDs[i])
		if err != nil {
			t.Errorf("owner membership for account %s user %s: %v", createdIDs[i], wantUIDs[i], err)
			continue
		}
		if m.Role != RoleOwner {
			t.Errorf("account %s user %s role = %q, want %q", createdIDs[i], wantUIDs[i], m.Role, RoleOwner)
		}
	}
}
