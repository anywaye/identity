package accounts

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cafaye/identity/internal/outbox"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
)

// Ownership transfer: the jumpstart `Account::Transfer` rules, expressed here.
//
// The four rules, in the order this file asserts them, because the ORDER IS THE
// ARGUMENT: who is asking is decided before what would be asked of the account,
// so a caller who is not the owner cannot learn whether the account is
// transferable at all.
//
//	caller is not the owner        ErrNotOwner        — a non-owner is refused,
//	                                                 and learns nothing further
//	account is personal            ErrNotTransferable — a personal account has
//	                                                 nobody to hand it to
//	fewer than two members         ErrNotTransferable — same shape, same reason
//	target is not a member        ErrNotAMember      — the membership write is
//	                                                 the only thing that could
//	                                                 create one, and this does not
//
// The first two refusals being 403-and-422 rather than one error is the point.
// "You are not the owner" is about the CALLER; "this account has nobody to hand
// it to" is about the ACCOUNT. An admin asking is answered 403 whether or not
// the account could have been transferred, which means the response is not a
// statement about the account.

// transferFixture is an owned team account plus a second member, which is the
// only shape a transfer can happen in at all.
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

	// The fixture's own create wrote an identity.account.created. Every event
	// assertion below is about the transfer, so the setup's is cleared first.
	h.events.reset()

	return transferFixture{account: account, owner: owner, heir: heir}
}

// TestTransferMovesOwnershipAndKeepsThePreviousOwnersAuthority is the happy
// path, and it asserts the THREE things a transfer is, because each of them is a
// different rule from the reference and a partial implementation satisfies two
// of them:
//
//  1. the heir holds the owner role,
//  2. the previous owner KEEPS their authority — jumpstart's "previous owner
//     roles are unchanged", which in a total order means admin, and
//  3. it happened in one transaction: both rows, and the event, together.
//
// The previous owner becoming `admin` rather than `member` is the whole of what
// jumpstart's comment "Previous owner roles are unchanged" means here, and it is
// not the same as `member`: an owner demoted to member would lose the ability to
// rename the account, invite members and remove them, on the day they handed the
// thing over. The rule that keeps them an admin is the one that makes
// transferring reversible — an heir who turns out to be unavailable is a
// problem, and a previous owner who can no longer administer the account cannot
// fix it.
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

	// Read back through the service rather than trusting the returned rows: the
	// rows are what the use case says it wrote, and the point is what is in the
	// database.
	assertRole(t, h, f.account.ID, f.heir, RoleOwner)
	assertRole(t, h, f.account.ID, f.owner, RoleAdmin)

	// The event names BOTH sides, and both of them are in one event rather than
	// two role-change events. "Who runs this account now" is one fact with two
	// halves; a consumer that received two `role_changed` events could interleave
	// them with anything else and reconstruct a state that never existed — an
	// account with two owners, or with none.
	h.events.only(t, outbox.EventAccountOwnershipTransferred)

	e := h.events.payloadFor(t, outbox.EventAccountOwnershipTransferred)
	for _, want := range []string{f.heir.String(), f.owner.String(), f.account.ID.String()} {
		if !containsString(string(e.Data), want) {
			t.Errorf("the event data %s does not mention %s; both sides of the transfer have to be in it", e.Data, want)
		}
	}
}

// TestANonOwnerCannotTransfer is the first negative case, and it is the one a
// hand-written fake would let you get wrong: with a fake store that always says
// "caller is the owner", an implementation that forgets to check passes every
// happy-path test.
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

			// Nothing moved. A refused transfer that had promoted somebody first
			// and then failed the owner check would leave an account with two
			// owners, which no later request can repair.
			assertRole(t, h, f.account.ID, f.heir, RoleMember)
			assertRole(t, h, f.account.ID, f.owner, RoleOwner)
		})
	}

	if got := h.events.types(); len(got) != 0 {
		t.Errorf("refused transfers emitted %v, want none", got)
	}
}

// TestAStrangerCannotTransferEvenWithAnAccountID answers a different question
// from the one above: the caller may hold the owner role in ANOTHER account, and
// the id in the path is theirs to choose. Ownership is per-account, so the check
// is on this account's membership and nothing else.
func TestAStrangerCannotTransferEvenWithAnAccountID(t *testing.T) {
	h := newHarness(t)
	f := newTransferFixture(t, h)
	other := h.owned(t, "Somebody-Else-"+dbtest.UniqueEmail(t), addUser(t, h.q))
	h.events.reset()

	// The owner of a DIFFERENT account, attempting it against f's account. The
	// id in the path is theirs to choose, which is the whole of what this case is.
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

// TestAPersonalAccountCannotTransfer is the second of jumpstart's three rules,
// and it is a refusal rather than a special case: a personal account belongs to
// the user a registration created it for, so there is nobody for them to hand it
// to, and an implementation that let them would produce an account whose owner
// is not the person it exists for.
func TestAPersonalAccountCannotTransfer(t *testing.T) {
	h := newHarness(t)

	// Provision through the registration path so `personal` is genuinely true
	// rather than set by a fixture.
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

	// A second member, so the refusal is provably about `personal` and not about
	// the member count. Without this the test would pass for the wrong reason.
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

// TestAnAccountWithOneMemberCannotTransfer is the third rule, and it exists
// because transferring is the only way an owner gives the account away: with
// one member there is nobody to give it to, and a transfer to a non-member is
// how an account would acquire an owner nobody chose.
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

	// And the stranger did NOT become a member by being named. A transfer that
	// created the target's membership would be an invitation with none of an
	// invitation's properties: no consent, no expiry, no way to refuse.
	if _, err := h.svc.Member(t.Context(), account.ID, stranger); !errors.Is(err, ErrNotAMember) {
		t.Errorf("the named stranger is %v, want ErrNotAMember — naming somebody is not admitting them", err)
	}
	assertRole(t, h, account.ID, owner, RoleOwner)
}

// TestTransferToTheCurrentOwnerIsRefused closes the loop on the two-member rule:
// an account with two members whose owner names THEMSELVES is transfer-shaped
// and semantically empty, and it is refused rather than answered 200 with the
// previous owner demoted — because that would take the only owner away from the
// only person who asked for it.
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

// TestTransferFailsWithoutMutatingAnythingWhenTheEventCannotBeWritten is the
// transaction test, and it is in this direction specifically: a service that
// rolled everything back would pass every happy-path test in this file perfectly.
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

// otherOwner reads the single owner of an account the fixture already built.
func otherOwner(t *testing.T, h *harness, account Account) id.UUID {
	t.Helper()

	members, err := h.svc.Members(t.Context(), account.ID)
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
