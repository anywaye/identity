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
)


type transferFixture struct {
	account Account
	owner   id.UUID
	heir    id.UUID
}

func newTransferFixture(t *testing.T, h *harness) transferFixture {
	t.Helper()

	owner := addUser(t, h.q)
	account := h.owned(t, "Transferable-"+dbtest.UniqueEmail(t), owner)
	heir := h.member(t, account.ID, RoleMember)

	h.events.reset()

	return transferFixture{account: account, owner: owner, heir: heir}
}

func TestTransferMovesOwnershipAndKeepsThePreviousOwnersAuthority(t *testing.T) {
	h := newHarness(t)
	f := newTransferFixture(t, h)

	got, err := h.svc.TransferOwnership(t.Context(), TransferInput{
		AccountID: f.account.ID,
		ToUserID:  f.heir,
		Actor:     f.owner,
	})
	if err != nil {
		t.Fatalf("TransferOwnership: %v", err)
	}

	if got.NewOwner.Role != RoleOwner {
		t.Errorf("the heir's role is %q, want %q", got.NewOwner.Role, RoleOwner)
	}
	if got.PreviousOwner.Role != RoleAdmin {
		t.Errorf("the previous owner's role is %q, want %q — they keep their authority",
			got.PreviousOwner.Role, RoleAdmin)
	}
	if got.PreviousOwner.UserID != f.owner {
		t.Errorf("the previous owner is %s, want %s", got.PreviousOwner.UserID, f.owner)
	}

	assertRole(t, h, f.account.ID, f.heir, RoleOwner)
	assertRole(t, h, f.account.ID, f.owner, RoleAdmin)

	h.events.only(t, outbox.EventAccountOwnershipTransferred)

	e := h.events.payloadFor(t, outbox.EventAccountOwnershipTransferred)
	for _, want := range []string{f.heir.String(), f.owner.String(), f.account.ID.String()} {
		if !containsString(string(e.Data), want) {
			t.Errorf("the event data %s does not mention %s; both sides of the transfer have to be in it", e.Data, want)
		}
	}
}

func TestANonOwnerCannotTransfer(t *testing.T) {
	h := newHarness(t)
	f := newTransferFixture(t, h)

	for _, tt := range []struct {
		name  string
		actor Role
	}{
		{name: "an admin", actor: RoleAdmin},
		{name: "a member", actor: RoleMember},
	} {
		t.Run(tt.name, func(t *testing.T) {
			attacker := h.member(t, f.account.ID, tt.actor)

			_, err := h.svc.TransferOwnership(t.Context(), TransferInput{
				AccountID: f.account.ID,
				ToUserID:  f.heir,
				Actor:     attacker,
			})
			if !errors.Is(err, ErrNotOwner) {
				t.Fatalf("%s transferring = %v, want ErrNotOwner", tt.name, err)
			}

			assertRole(t, h, f.account.ID, f.heir, RoleMember)
			assertRole(t, h, f.account.ID, f.owner, RoleOwner)
		})
	}

	if got := h.events.types(); len(got) != 0 {
		t.Errorf("refused transfers emitted %v, want none", got)
	}
}

func TestAStrangerCannotTransferEvenWithAnAccountID(t *testing.T) {
	h := newHarness(t)
	f := newTransferFixture(t, h)
	other := h.owned(t, "Somebody-Else-"+dbtest.UniqueEmail(t), addUser(t, h.q))
	h.events.reset()

	stranger := otherOwner(t, h, other)

	_, err := h.svc.TransferOwnership(t.Context(), TransferInput{
		AccountID: f.account.ID,
		ToUserID:  f.heir,
		Actor:     stranger,
	})
	if !errors.Is(err, ErrNotOwner) {
		t.Fatalf("an owner of another account transferring = %v, want ErrNotOwner", err)
	}
	assertRole(t, h, f.account.ID, f.heir, RoleMember)
}

func TestAPersonalAccountCannotTransfer(t *testing.T) {
	h := newHarness(t)

	user := addUser(t, h.q)
	email := dbtest.UniqueEmail(t)
	runner := db.TxRunner{Pool: h.q.(db.Pool)}
	var personal Account
	if err := runner.Do(t.Context(), func(ctx context.Context, tx db.Querier) error {
		created, err := h.svc.Provision(ctx, tx, user, email)
		if err != nil {
			return err
		}
		if _, err := h.svc.AddOwner(ctx, tx, created.ID, user); err != nil {
			return err
		}
		personal = created
		return nil
	}); err != nil {
		t.Fatalf("provisioning a personal account: %v", err)
	}

	h.member(t, personal.ID, RoleMember)

	_, err := h.svc.TransferOwnership(t.Context(), TransferInput{
		AccountID: personal.ID,
		ToUserID:  addUser(t, h.q),
		Actor:     user,
	})
	if !errors.Is(err, ErrNotTransferable) {
		t.Fatalf("transferring a personal account = %v, want ErrNotTransferable", err)
	}
	assertRole(t, h, personal.ID, user, RoleOwner)
}

func TestAnAccountWithOneMemberCannotTransfer(t *testing.T) {
	h := newHarness(t)

	owner := addUser(t, h.q)
	account := h.owned(t, "Solo-"+dbtest.UniqueEmail(t), owner)
	stranger := addUser(t, h.q)

	_, err := h.svc.TransferOwnership(t.Context(), TransferInput{
		AccountID: account.ID,
		ToUserID:  stranger,
		Actor:     owner,
	})
	if !errors.Is(err, ErrNotTransferable) {
		t.Fatalf("transferring a one-member account = %v, want ErrNotTransferable", err)
	}

	if _, err := h.svc.Member(t.Context(), account.ID, stranger); !errors.Is(err, ErrNotAMember) {
		t.Errorf("the named stranger is %v, want ErrNotAMember — naming somebody is not admitting them", err)
	}
	assertRole(t, h, account.ID, owner, RoleOwner)
}

func TestTransferToTheCurrentOwnerIsRefused(t *testing.T) {
	h := newHarness(t)
	f := newTransferFixture(t, h)

	_, err := h.svc.TransferOwnership(t.Context(), TransferInput{
		AccountID: f.account.ID,
		ToUserID:  f.owner,
		Actor:     f.owner,
	})
	if !errors.Is(err, ErrTransferToSelf) {
		t.Fatalf("transferring to oneself = %v, want ErrTransferToSelf", err)
	}
	assertRole(t, h, f.account.ID, f.owner, RoleOwner)
}

func TestTransferFailsWithoutMutatingAnythingWhenTheEventCannotBeWritten(t *testing.T) {
	h := newHarness(t)
	f := newTransferFixture(t, h)
	h.events.failWith = errors.New("outbox is down")

	_, err := h.svc.TransferOwnership(t.Context(), TransferInput{
		AccountID: f.account.ID,
		ToUserID:  f.heir,
		Actor:     f.owner,
	})
	if err == nil {
		t.Fatal("TransferOwnership succeeded with a failing outbox; the event is part of the fact")
	}

	assertRole(t, h, f.account.ID, f.heir, RoleMember)
	assertRole(t, h, f.account.ID, f.owner, RoleOwner)
}

func otherOwner(t *testing.T, h *harness, account Account) id.UUID {
	t.Helper()

	members, err := h.svc.Members(tenancy.WithAccount(t.Context(), account.ID), account.ID)
	if err != nil {
		t.Fatalf("Members: %v", err)
	}
	for _, m := range members {
		if m.Role == RoleOwner {
			return m.UserID
		}
	}
	t.Fatal("the fixture account has no owner")
	return id.UUID{}
}

func containsString(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}
