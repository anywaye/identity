package accounts

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/tenancy"
)

// `Accept` UNDER THE REAL POLICIES: the redemption lookup has no account to
// run under, because the account is what the lookup is FOR.
//
// # THE DEFECT THIS PINS
//
// `account_invitations` is protected by migrations/00016's `protect_table`, so
// every account policy on it demands an identity — and `Service.Accept` reads
// the invitation through `InvitationByToken` on `s.read`, a bare pooled
// connection that carries none. The lookup reads zero rows, `ErrNoRows` becomes
// `ErrInvitationNotFound`, and `POST /v1/invitations/accept` answers 404 for a
// freshly issued invitation. The site-loop walk proved this live: the API and
// the email carried the same token, the member had a valid session, and the
// redemption still 404'd.
//
// HANDOFF-identity-isolation.md §4.1 records the paired fix this test demands:
// `cafaye.protect_credential_table('account_invitations', 'token_digest')` in a
// migration, plus `tenancy.BeginCredential` before the lookup on the Go side.
// Both halves or neither — the migration half alone reads the same zero rows.
//
// # WHY HERE AND NOT IN internal/tenancy
//
// The tenancy package proves the policy admits the row. This file proves the
// USE CASE goes through it: the redemption path, the single-use mark, and the
// documented statuses, all under the app role with the policies live. The copies
// in service_test.go run on `dbtest.Schema`, where LIKE copies no RLS — they
// pass with this wiring and would pass with no wiring at all.
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

	// The accept route carries no account — the token names it — so the
	// context carries none either. That absence is the whole subject: the
	// lookup must resolve by the presented digest, not by an identity the
	// caller cannot have yet.
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

	// The invitation is single-use: the same token redeemed again is refused,
	// and the refusal names reuse rather than absence.
	if _, err := h.svc.Accept(t.Context(), AcceptInput{Token: invited.Token, User: invitee}); !errors.Is(err, ErrInvitationUsed) {
		t.Errorf("second Accept of the same token = %v, want ErrInvitationUsed", err)
	}
}

// TestAcceptKeepsItsDocumentedStatusesUnderTheRealPolicies is the check on the
// fix rather than on the defect: once the lookup resolves, every documented
// status must still be the one the contract promises. Each of these is green
// today for the wrong reason — every token 404s when no token resolves — so
// they only become evidence together with the redemption above.
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
