package accounts

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/tenancy"
)

func TestAcceptRedeemsAFreshInvitationUnderTheRealPolicies(t *testing.T) {
	h := newRealAccountHarness(t)
	owner := addUser(t, h.q)
	account := h.owned(t, uniqueAccountName(t, "accept-rls"), owner)

	invited, err := h.svc.Invite(tenancy.WithAccount(t.Context(), account.ID), InviteInput{
		AccountID: account.ID,
		Email:     dbtest.UniqueEmail(t),
		Role:      RoleMember,
		InvitedBy: owner,
	})
	if err != nil {
		t.Fatalf("Invite = %v, want a pending invitation", err)
	}

	invitee := addUser(t, h.q)

	membership, err := h.svc.Accept(t.Context(), AcceptInput{Token: invited.Token, User: invitee})
	if err != nil {
		t.Fatalf("Accept of a fresh invitation = %v, want a membership. "+
			"account_invitations carries only account policies, which demand an identity "+
			"this caller cannot have yet, so the lookup reads zero rows and the fresh "+
			"invitation 404s.", err)
	}
	if membership.AccountID != account.ID {
		t.Errorf("membership is in account %s, want %s", membership.AccountID, account.ID)
	}
	if membership.UserID != invitee {
		t.Errorf("membership is for user %s, want %s", membership.UserID, invitee)
	}
	if membership.Role != RoleMember {
		t.Errorf("membership role is %q, want %q", membership.Role, RoleMember)
	}

	if _, err := h.svc.Accept(t.Context(), AcceptInput{Token: invited.Token, User: invitee}); !errors.Is(err, ErrInvitationUsed) {
		t.Errorf("second Accept of the same token = %v, want ErrInvitationUsed", err)
	}
}

func TestAcceptKeepsItsDocumentedStatusesUnderTheRealPolicies(t *testing.T) {
	newInvitation := func(t *testing.T, h *harness, name string) (Account, Invited) {
		t.Helper()
		owner := addUser(t, h.q)
		account := h.owned(t, uniqueAccountName(t, name), owner)
		invited, err := h.svc.Invite(tenancy.WithAccount(t.Context(), account.ID), InviteInput{
			AccountID: account.ID,
			Email:     dbtest.UniqueEmail(t),
			Role:      RoleMember,
			InvitedBy: owner,
		})
		if err != nil {
			t.Fatalf("Invite = %v, want a pending invitation", err)
		}
		return account, invited
	}

	t.Run("a wrong token is not found", func(t *testing.T) {
		h := newRealAccountHarness(t)
		_, invited := newInvitation(t, h, "accept-wrong")
		_ = invited
		invitee := addUser(t, h.q)
		if _, err := h.svc.Accept(t.Context(), AcceptInput{Token: "definitely-not-the-token", User: invitee}); !errors.Is(err, ErrInvitationNotFound) {
			t.Errorf("Accept of a wrong token = %v, want ErrInvitationNotFound", err)
		}
	})

	t.Run("an expired invitation is expired", func(t *testing.T) {
		h := newRealAccountHarness(t)
		_, invited := newInvitation(t, h, "accept-expired")
		invitee := addUser(t, h.q)
		h.clock.Advance(8 * 24 * time.Hour)
		if _, err := h.svc.Accept(t.Context(), AcceptInput{Token: invited.Token, User: invitee}); !errors.Is(err, ErrInvitationExpired) {
			t.Errorf("Accept of an expired invitation = %v, want ErrInvitationExpired", err)
		}
	})

	t.Run("a revoked invitation is not found", func(t *testing.T) {
		h := newRealAccountHarness(t)
		account, invited := newInvitation(t, h, "accept-revoked")
		invitee := addUser(t, h.q)
		err := db.TxRunner{Pool: h.pool}.Do(t.Context(), func(ctx context.Context, q db.Querier) error {
			if err := tenancy.BeginAccount(ctx, q, account.ID); err != nil {
				return err
			}
			_, err := h.store.RevokePendingInvitation(ctx, q, account.ID, invited.Invitation.ID)
			return err
		})
		if err != nil {
			t.Fatalf("revoking the invitation: %v", err)
		}
		if _, err := h.svc.Accept(t.Context(), AcceptInput{Token: invited.Token, User: invitee}); !errors.Is(err, ErrInvitationNotFound) {
			t.Errorf("Accept of a revoked invitation = %v, want ErrInvitationNotFound", err)
		}
	})

	t.Run("a token joins its own account and no other", func(t *testing.T) {
		h := newRealAccountHarness(t)
		ownerA := addUser(t, h.q)
		accountA := h.owned(t, uniqueAccountName(t, "accept-tenant-a"), ownerA)
		ownerB := addUser(t, h.q)
		accountB := h.owned(t, uniqueAccountName(t, "accept-tenant-b"), ownerB)

		invited, err := h.svc.Invite(tenancy.WithAccount(t.Context(), accountA.ID), InviteInput{
			AccountID: accountA.ID,
			Email:     dbtest.UniqueEmail(t),
			Role:      RoleMember,
			InvitedBy: ownerA,
		})
		if err != nil {
			t.Fatalf("Invite = %v, want a pending invitation", err)
		}

		invitee := addUser(t, h.q)
		membership, err := h.svc.Accept(t.Context(), AcceptInput{Token: invited.Token, User: invitee})
		if err != nil {
			t.Fatalf("Accept = %v, want a membership in the inviting account", err)
		}
		if membership.AccountID != accountA.ID {
			t.Errorf("membership is in account %s, want %s", membership.AccountID, accountA.ID)
		}
		if _, err := h.svc.Member(tenancy.WithAccount(t.Context(), accountB.ID), accountB.ID, invitee); err == nil {
			t.Error("the invitee is a member of the account that never invited them: a token granted broader scope than its own invitation")
		}
	})
}
