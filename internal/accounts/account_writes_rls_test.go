package accounts

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cafaye/identity/internal/outbox"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/tenancy"
	"github.com/cafaye/identity/internal/users"
)

// The account-scoped WRITES under the real policies, and the fourth kind of test
// in this package that has to run against `dbtest.Pool`.
//
// # THE GAP THIS FILE CLOSES
//
// get_rls_test.go closed it for the caller-scoped READS (`Get`, `Member`,
// `ListMine`); invite_members_rls_test.go closed it for the account-scoped READ
// (`Members`) and the invite path. This file is the WRITES: `ChangeRole`,
// `RemoveMember`, and the registration pair `Provision`/`AddOwner`.
//
// Every one of them reads or writes `account_users` inside a transaction, and
// under the real policies that transaction has to carry the ACCOUNT identity —
// `tenancy.TxRunner` sets it from the request context, which is where
// `requireAccountRole` puts it after a membership read established the account
// is the caller's. The copies in service_test.go ran on `dbtest.Schema` through
// `newHarness`, whose `db.TxRunner` sets no identity and whose context carries
// no account. On a schema with no policies that is invisible: the reads match
// their rows and the writes meet their `with check` because there is no policy
// to refuse them. So those tests could not detect the identity being dropped —
// the one regression that would break every one of these use cases in
// production while leaving the suite green.
//
// # WHY THESE ARE NOT REDUNDANT WITH THE READ FILES
//
// A read that loses its identity answers the wrong thing (`[]`, a 404); a write
// that loses its identity is REFUSED — `account_users_cafaye_insert` and
// `_cafaye_update` are `with check (account_id = (select
// cafaye.current_account_id()))`, so the membership write meets SQLSTATE 42501
// and the use case fails. That is a loud failure, and it is the correct one, but
// it is a failure the Schema copies never produced: they ran with no `with
// check` to refuse them. So the writes were tested for their LOGIC (the
// last-owner count, the owner protection, the credential sweep) and never for
// their PREMISE — that the transaction they run in is standing in the account
// they name.
//
// # THE HARNESS IS THE PRODUCTION WIRING, SHARED
//
// These tests use `newRealAccountHarness` from invite_members_rls_test.go —
// `dbtest.Pool` plus `tenancy.TxRunner`, which is what `cmd/identity/main.go`
// builds the service with. It lives there rather than here because that file
// introduced it and this file is a second consumer of the same wiring, not a
// third copy of it. The context carries the account on every use-case call,
// because that is what a real request has by the time it reaches these use
// cases: `requireAccountRole` put it there.

// TestLastOwnerProtectionUnderTheRealPolicies is the last-owner invariant
// under the real policies, in every shape the Schema copy asserted.
//
// The invariant is service logic, but its ENFORCEMENT reads the membership
// table: `ChangeRole` reads the target and counts the owners, `RemoveMember`
// reads the target and the actor. Under the real policies those reads are
// admitted by `account_users_cafaye_select`, so the test now fails — with
// `ErrNotAMember`, not the invariant's own error — if the transaction stops
// carrying the account. That is the regression this file exists to catch, and
// it is invisible on `dbtest.Schema`, where the reads always succeed.
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
		// Now the original owner may step down: the account has two.
		if _, err := h.svc.ChangeRole(tenancy.WithAccount(t.Context(), account.ID), ChangeRoleInput{
			AccountID: account.ID, UserID: owner, Role: RoleMember, Actor: successor,
		}); err != nil {
			t.Fatalf("the first owner stepping down: %v", err)
		}
		assertRole(t, h, account.ID, successor, RoleOwner)
	})
}

// TestRemoveMemberThroughTheServiceUnderTheRealPolicies is the removal rules
// under the real policies: an admin may remove a member, the owner's membership
// is a different object, and an owner may remove a non-owner.
//
// The rules are decided from membership reads — the target's role and the
// actor's — so the test is in this file for the reason the last-owner invariant
// is: those reads need the account identity on the transaction, and a schema
// with no policies gives them to anybody.
func TestRemoveMemberThroughTheServiceUnderTheRealPolicies(t *testing.T) {
	h := newRealAccountHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, uniqueAccountName(t, "departures"), owner)
	admin := addRealMember(t, h, account.ID, RoleAdmin)
	target := addRealMember(t, h, account.ID, RoleMember)
	ctx := tenancy.WithAccount(t.Context(), account.ID)

	// An admin removing a member: allowed.
	if err := h.svc.RemoveMember(ctx, RemoveMemberInput{
		AccountID: account.ID, UserID: target, Actor: admin,
	}); err != nil {
		t.Errorf("an admin removing a member = %v, want success", err)
	}
	if _, err := h.svc.Member(t.Context(), account.ID, target); !errors.Is(err, ErrNotAMember) {
		t.Errorf("the member survived removal: %v", err)
	}

	// An admin removing the owner: refused, and the owner stays.
	err := h.svc.RemoveMember(ctx, RemoveMemberInput{
		AccountID: account.ID, UserID: owner, Actor: admin,
	})
	if !errors.Is(err, ErrOwnerProtected) {
		t.Errorf("an admin removing the owner = %v, want ErrOwnerProtected", err)
	}
	assertRole(t, h, account.ID, owner, RoleOwner)

	// An owner removing a non-owner: allowed, even when that owner is the last.
	if err := h.svc.RemoveMember(ctx, RemoveMemberInput{
		AccountID: account.ID, UserID: admin, Actor: owner,
	}); err != nil {
		t.Errorf("an owner removing an admin = %v, want success", err)
	}
}

// TestRemoveMemberRevokesTheCredentialsTheyHeldUnderTheRealPolicies is the
// offboarding sweep under the real policies.
//
// The sweep is a `CredentialRevoker` double here, so the RLS dependency is not
// the sweep itself but the removal that triggers it: `RemoveMember` reads the
// target and the actor before it deletes, and those reads need the account
// identity. The test's subject — a removal revokes the credentials the member
// held, in the same transaction — is the rule this package exists to enforce on
// internal/apikeys' behalf, and it is only meaningful when the removal it tests
// is the one the production wiring performs.
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
	// The same instant the removal and the event carry, so "when was this
	// credential withdrawn" and "when was this person removed" have one answer.
	if !got.at.Equal(h.clock.Now()) {
		t.Errorf("the sweep ran at %s, want the service clock's %s", got.at, h.clock.Now())
	}

	// A REFUSED removal sweeps nothing. An admin who cannot remove the owner must
	// not leave that owner's credentials revoked on the way to being told no — a
	// sweep outside the transaction's success path is a partial write.
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

// TestARemovalThatCannotSweepRollsBackUnderTheRealPolicies is the other
// direction of the same transaction under the real policies: a revoker that
// fails must take the whole removal with it.
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

	// The membership is back, and the event was not written: both writes were inside
	// the transaction the sweep's failure rolled back.
	if _, err := h.svc.Member(t.Context(), account.ID, target); err != nil {
		t.Errorf("the membership was removed even though the sweep failed: %v", err)
	}
	for _, e := range h.events.appended {
		if e.Type == outbox.EventMemberRemoved {
			t.Error("identity.member.removed was announced for a removal that rolled back")
		}
	}
}

// TestARemovalWithNoRevokerStillRemovesTheMembershipUnderTheRealPolicies: the
// sweep may be nil — a deployment with no api key table has no credentials to
// revoke — and the membership change must still happen.
func TestARemovalWithNoRevokerStillRemovesTheMembershipUnderTheRealPolicies(t *testing.T) {
	h := newRealAccountHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, uniqueAccountName(t, "departures"), owner)
	target := addRealMember(t, h, account.ID, RoleMember)
	ctx := tenancy.WithAccount(t.Context(), account.ID)

	// A service with no revoker, built the production way with a nil.
	withoutSweep := NewService(
		tenancy.TxRunner{TxRunner: db.TxRunner{Pool: h.pool}},
		h.store,
		users.NewStore(h.pool),
		h.events,
		nil,
		h.clock,
		db.Direct{Pool: h.pool},
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

// TestChangeRoleEmitsBothRolesUnderTheRealPolicies is the event shape under the
// real policies: core's catalog wants the old and the new role, because a
// consumer that only learns the new one cannot revoke what it previously
// granted.
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

// TestRemoveMemberEmitsTheRoleTheyHeldUnderTheRealPolicies is the removal
// event's role under the real policies.
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

// TestProvisionUnderTheRealPolicies is the registration write path under the
// real policies.
//
// `Provision` and `AddOwner` do not open their own transactions — they run
// inside the registration's — and the registration's transaction is where the
// account identity has to come from. The Schema copy opened a bare `db.TxRunner`
// and called them; on a schema with no policies the membership INSERT meets no
// `with check`, so the test passed without the identity that production has to
// set. Here the fixture does what `internal/auth.provisionTenancy` does:
// `tenancy.BeginAccount` on the same transaction, before `AddOwner`, because
// `begin_account` is transaction-local and the membership write is the
// account-scoped statement that needs it.
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

		// Begin as the account that was just created, for the same reason
		// `Create` and `internal/auth.provisionTenancy` do: the membership write
		// below is account-scoped and the account did not exist when the request
		// arrived. Without this the INSERT is refused with SQLSTATE 42501 under
		// the real policies.
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

// TestTwoPeopleWithTheSameLocalPartBothRegisterUnderTheRealPolicies is the
// personal-slug uniqueness under the real policies: two people whose email
// local parts are the same must both be able to register.
func TestTwoPeopleWithTheSameLocalPartBothRegisterUnderTheRealPolicies(t *testing.T) {
	dbtest.Reset(t)
	h := newRealAccountHarness(t)
	runner := tenancy.TxRunner{TxRunner: db.TxRunner{Pool: h.pool}}

	for i := 0; i < 2; i++ {
		email := "kaka-" + dbtest.UniqueEmail(t)[len("kaka-"):]
		uid := addUserWithEmail(t, h.q, email)
		if err := runner.Do(t.Context(), func(ctx context.Context, tx db.Querier) error {
			created, err := h.svc.Provision(ctx, tx, uid, email)
			if err != nil {
				return err
			}
			// The same reason TestProvisionUnderTheRealPolicies gives: the
			// membership write is account-scoped and the account is new.
			if err := tenancy.BeginAccount(ctx, tx, created.ID); err != nil {
				return err
			}
			_, err = h.svc.AddOwner(ctx, tx, created.ID, uid)
			return err
		}); err != nil {
			t.Fatalf("provisioning a personal account for %s: %v", email, err)
		}
	}

	var personal int
	if err := h.q.QueryRow(t.Context(), `SELECT count(*) FROM accounts WHERE personal`).Scan(&personal); err != nil {
		t.Fatalf("counting: %v", err)
	}
	if personal != 2 {
		t.Errorf("%d personal accounts exist, want 2 — the second registration collided on the slug", personal)
	}
}
