package recovery

// PACKET identity-disabled-01: RECOVERY MUST NOT BE THE WAY BACK IN.
//
// # WHY THIS FILE IS SEPARATE AND WHY IT IS THE MOST IMPORTANT ONE
//
// Everything else in this packet closes a DOOR. This file closes the one route
// that exists specifically to let somebody who cannot get in, get in.
//
// Password reset proves control of a mailbox. That is real evidence — it is how a
// user who has lost their password recovers. It is ALSO the one credential an
// attacker with a stolen or previously-read mailbox can present, and after a
// disable that is exactly what we are defending against. So:
//
//	MINTING REFUSES. A disabled account is sent nothing, and the answer is
//	                  byte-identical to the answer for an address with no account.
//	REDEMPTION REFUSES. A LIVE token for a disabled user redeems nothing, and the
//	                  answer is the shape of a token that never existed.
//
// # THE TWO REFUSALS HAVE DIFFERENT SHAPES, AND BOTH ARE THE EXISTING ONE
//
// MINT answers 202 with a constant body for every address. A disabled account gets
// that, not a 403 and not a 202 that is somehow slower. Anything else is an
// enumeration oracle: `POST /v1/password-resets` reaches strangers with no
// credential, so "disabled" would publish a list of disabled accounts to anyone
// posting a list of addresses. This is the rule identity-27 learned the hard way
// and D9 records.
//
// REDEMPTION answers 404 — the shape of a token that never existed. The token IS
// the credential on that route, so a caller who presents it is either the owner or
// whoever took the link, and neither of them should learn that a person turned
// this account off. The honest sentence for the OWNER is on the login they will
// hit next, which names the state in 403 to somebody who has proved their
// password. That is why the two answers differ and why neither is the other's.
//
// # AND THE TOKEN IS NOT SPENT
//
// A refusal that consumed the token would be a second, irreversible decision made
// by an operator who did not make it: re-enable would then leave the user with a
// link that no longer works and no session, which is indistinguishable from a
// service that lost their state. Leaving it live costs nothing while the account
// is disabled, because every redemption below refuses, and it makes re-enabling
// mean what it says.

import (
	"context"
	"errors"
	"testing"

	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/sessions"
)

// disable and enable turn the concept's two directions on for these tests.
//
// They go through the real `users.Store` rather than a raw UPDATE so that the
// column's semantics — the instant written, the NULL on the way back — are the
// production ones. There is deliberately no use of `auth.Service.Disable` here:
// this package has no dependency on internal/auth and taking one for a test would
// put an edge between two packages where there is not one in production. The
// session revocation is internal/auth's business and is tested there.
func (h *harness) disable(userID id.UUID) {
	h.t.Helper()
	if err := h.users.Disable(h.t.Context(), h.pool, userID, h.now()); err != nil {
		h.t.Fatalf("disabling the account: %v", err)
	}
}

func (h *harness) enable(userID id.UUID) {
	h.t.Helper()
	if err := h.users.Enable(h.t.Context(), h.pool, userID); err != nil {
		h.t.Fatalf("enabling the account: %v", err)
	}
}

// mintEmailChangeTarget produces a SECOND-side email-change token by hand.
//
// It exists so the LAST step of the change is reachable in a test at all. In
// production that token is only ever minted by ConfirmEmailChangeCurrent, which
// the disable now refuses — so a test asserting only the middle step would pass
// against an implementation that never checked the last one, and would be testing
// a step nothing can reach. Seeding it directly is what makes the last assertion
// about the code rather than about reachability.
func (h *harness) mintEmailChangeTarget(userID id.UUID, target string) (string, error) {
	h.t.Helper()

	token, digest, err := sessions.NewToken()
	if err != nil {
		return "", err
	}

	var rowID id.UUID
	err = db.TxRunner{Pool: h.pool}.Do(h.t.Context(), func(ctx context.Context, q db.Querier) error {
		created, err := NewStore(h.pool).Create(ctx, q, NewToken{
			UserID:      userID,
			Purpose:     PurposeEmailChange,
			Digest:      digest,
			TargetEmail: target,
			CreatedAt:   h.now(),
			ExpiresAt:   h.now().Add(EmailChangeTTL),
		})
		if err != nil {
			return err
		}
		rowID = created.ID
		return nil
	})
	if err != nil {
		return "", err
	}

	// The seeded row has the digest in `token_digest`; the second side is addressed
	// by `target_token_digest`. Moving it across is what `MintTarget` does, and
	// doing it through the store keeps the columns honest.
	err = db.TxRunner{Pool: h.pool}.Do(h.t.Context(), func(ctx context.Context, q db.Querier) error {
		_, err := NewStore(h.pool).MintTarget(ctx, q, rowID, digest, h.now())
		return err
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

// The mint refuses, and the refusal is INVISIBLE.
//
// Both halves are asserted and they are different halves: nothing is MINTED (no
// row) and nothing is SENT (no message), and the second is the one a test that
// only counted rows would miss.
func TestAPasswordResetIsNotMintedForADisabledAccount(t *testing.T) {
	h := newHarness(t, true)
	who := h.register(dbtest.UniqueEmail(t), "correct horse battery")
	h.disable(who.id)

	before := h.mailer.count()
	if err := h.svc.RequestPasswordReset(h.t.Context(), who.email); err != nil {
		t.Fatalf("RequestPasswordReset on a disabled account = %v, want nil: the route's answer "+
			"must not depend on the row's state, or it is an enumeration oracle", err)
	}

	if got := h.mailer.count() - before; got != 0 {
		t.Errorf("%d messages were sent to a disabled account, want 0: a reset link is the way "+
			"back in past an administrator's decision", got)
	}
	if got := h.tokenRowCount(who.id, PurposePasswordReset); got != 0 {
		t.Errorf("%d reset token rows exist for a disabled account, want 0", got)
	}
}

// The address confirmation mint, for the same reason and on the same shape.
//
// It is a separate test rather than another case in the table above because it is
// a separate route with its own census row, and the census in
// `internal/httpapi/anonymous_enumeration_test.go` requires each route to be
// answered individually.
func TestAnEmailVerificationIsNotMintedForADisabledAccount(t *testing.T) {
	h := newHarness(t, true)
	who := h.register(dbtest.UniqueEmail(t), "correct horse battery")
	h.disable(who.id)

	before := h.mailer.count()
	if err := h.svc.RequestVerification(h.t.Context(), who.email); err != nil {
		t.Fatalf("RequestVerification on a disabled account = %v, want nil", err)
	}

	if got := h.mailer.count() - before; got != 0 {
		t.Errorf("%d messages were sent to a disabled account, want 0", got)
	}
	if got := h.tokenRowCount(who.id, PurposeVerifyEmail); got != 0 {
		t.Errorf("%d verification token rows exist for a disabled account, want 0", got)
	}
}

// THE ANSWER IS THE SAME ONE AN UNREGISTERED ADDRESS GETS.
//
// This is the assertion that makes the previous two safe rather than merely
// quiet: a disabled account and an address nobody has must be indistinguishable at
// the response, and "indistinguishable" is asserted by running both and comparing
// what the service did — no message either way, no row either way.
func TestADisabledAccountAndAnUnregisteredAddressAreIndistinguishableToTheMint(t *testing.T) {
	h := newHarness(t, true)
	disabled := h.register(dbtest.UniqueEmail(t), "correct horse battery")
	h.disable(disabled.id)
	unknown := dbtest.UniqueEmail(t)

	if err := h.svc.RequestPasswordReset(h.t.Context(), disabled.email); err != nil {
		t.Fatalf("RequestPasswordReset for a disabled account = %v, want nil", err)
	}
	if err := h.svc.RequestPasswordReset(h.t.Context(), unknown); err != nil {
		t.Fatalf("RequestPasswordReset for an unregistered address = %v, want nil", err)
	}

	if got := h.mailer.count(); got != 0 {
		t.Errorf("%d messages were sent across both addresses, want 0 — the disabled account and "+
			"the address nobody has must cost the same and say the same, or the difference is a "+
			"list of disabled accounts for anyone posting a list of addresses", got)
	}
}

// REDEMPTION REFUSES, and this is the one that matters most: the token was LIVE.
//
// The mint is refused above, but a token minted BEFORE the disable is still a
// perfectly good token with a real expiry, and it is in a real inbox. An operator
// who disables an account thirty seconds after a reset link went out cannot
// unsend it, so this is the window the packet has to close.
func TestALiveResetTokenRedeemsNothingForADisabledAccount(t *testing.T) {
	h := newHarness(t, true)
	who := h.register(dbtest.UniqueEmail(t), "correct horse battery")

	// Minted while the account is perfectly healthy.
	if err := h.svc.RequestPasswordReset(h.t.Context(), who.email); err != nil {
		t.Fatalf("RequestPasswordReset before the disable: %v", err)
	}
	token := tokenFrom(t, h.mailer.last(t))
	sentBefore := h.mailer.count()

	// …and then somebody turns the account off, link already in flight.
	h.disable(who.id)

	_, err := h.svc.RedeemPasswordReset(h.t.Context(), RedeemPasswordResetInput{
		Token:    token,
		Password: "a brand new correct horse battery",
	})

	if !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("RedeemPasswordReset for a disabled account = %v, want ErrTokenNotFound — the "+
			"shape of a token that never existed, which is the only shape that tells a holder of a "+
			"stolen link nothing about the account's state", err)
	}

	// The password did not move. This is the assertion a test that only checked the
	// error would miss, and it is the whole of the packet's fourth requirement.
	//
	// It is asserted from BOTH sides on purpose: the new password must not verify,
	// and the OLD one must. A test that only checked the first would pass against a
	// store that cleared `password_digest` to something no password matches, which
	// reads as "the password did not change" and is actually an account nobody can
	// ever sign in to again.
	stored, err := h.users.ByID(h.t.Context(), h.pool, who.id)
	if err != nil {
		t.Fatalf("reading back the user: %v", err)
	}
	if testHasher().Verify(stored.PasswordDigest, "a brand new correct horse battery") {
		t.Error("the password was changed by a reset for a disabled account: recovery became the " +
			"way back in past an administrator's decision")
	}
	if !testHasher().Verify(stored.PasswordDigest, "correct horse battery") {
		t.Error("the original password no longer verifies, so the reset did something other than " +
			"refuse — and the assertion above would have passed for the wrong reason")
	}
	if got := h.mailer.count(); got != sentBefore {
		t.Errorf("%d messages were sent during the redemption, want %d", got, sentBefore)
	}
}

// AND THE TOKEN IS NOT SPENT, because re-enabling has to mean what it says.
func TestARefusedRedemptionDoesNotSpendTheToken(t *testing.T) {
	h := newHarness(t, true)
	who := h.register(dbtest.UniqueEmail(t), "correct horse battery")

	if err := h.svc.RequestPasswordReset(h.t.Context(), who.email); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	token := tokenFrom(t, h.mailer.last(t))
	tokenID := h.newestTokenID(who.id, PurposePasswordReset)

	h.disable(who.id)
	if _, err := h.svc.RedeemPasswordReset(h.t.Context(), RedeemPasswordResetInput{
		Token: token, Password: "a brand new correct horse battery",
	}); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("RedeemPasswordReset = %v, want ErrTokenNotFound", err)
	}

	row := h.storedTokenRow(tokenID)
	if row["spent_at"] != nil {
		t.Errorf("spent_at = %v after a refused redemption, want NULL: an operator who disabled an "+
			"account did not also decide to invalidate the link already in the owner's inbox, and "+
			"spending it would make re-enabling leave them unable to get back in", row["spent_at"])
	}

	// The consequence, asserted rather than left as a claim about the row: once the
	// account is enabled again, that same link works. Which is what "re-enable"
	// has to mean if it is going to be the honest inverse of "disable".
	h.enable(who.id)
	if _, err := h.svc.RedeemPasswordReset(h.t.Context(), RedeemPasswordResetInput{
		Token: token, Password: "a brand new correct horse battery",
	}); err != nil {
		t.Errorf("RedeemPasswordReset after re-enabling = %v, want success: the refusal did not "+
			"spend the token, so lifting the disable restores the flow the user started", err)
	}
}

// The verification redemption refuses on the same shape, and it is worth a test of
// its own because it is a different route with its own census row and because it
// is the ONE redemption that grants nothing in the first place — so "refusing it"
// is about consistency and about not writing a fact about an account somebody has
// decided does not exist right now.
func TestALiveVerificationTokenRedeemsNothingForADisabledAccount(t *testing.T) {
	h := newHarness(t, true)
	who := h.register(dbtest.UniqueEmail(t), "correct horse battery")

	if err := h.svc.RequestVerification(h.t.Context(), who.email); err != nil {
		t.Fatalf("RequestVerification: %v", err)
	}
	token := tokenFrom(t, h.mailer.last(t))

	h.disable(who.id)

	err := h.svc.RedeemVerification(h.t.Context(), RedeemVerificationInput{Token: token})
	if !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("RedeemVerification for a disabled account = %v, want ErrTokenNotFound", err)
	}

	stored, err := h.users.ByID(h.t.Context(), h.pool, who.id)
	if err != nil {
		t.Fatalf("reading back the user: %v", err)
	}
	if stored.IsVerified() {
		t.Error("the address was marked verified by a disabled account's token")
	}
}

// THE EMAIL CHANGE, and it is the one whose two halves are easy to forget.
//
// A change mints its FIRST token while the caller is signed in, and its SECOND
// token when that first is confirmed. A disable between those two points must stop
// the second mint as well, or the flow's remaining half is live with nothing able
// to answer it — and worse, the second mint is the one that writes a row and sends
// a message.
//
// RequestEmailChange itself is session-gated and a disabled user holds no session,
// so it is unreachable rather than refused; this file asserts the two reachable
// halves.
func TestNeitherHalfOfAnEmailChangeRunsForADisabledAccount(t *testing.T) {
	h := newHarness(t, true)
	who := h.register(dbtest.UniqueEmail(t), "correct horse battery")
	newAddress := dbtest.UniqueEmail(t)

	if _, err := h.svc.RequestEmailChange(h.t.Context(), RequestEmailChangeInput{
		UserID: who.id, Email: newAddress,
	}); err != nil {
		t.Fatalf("RequestEmailChange before the disable: %v", err)
	}
	first := tokenFrom(t, h.mailer.last(t))

	// The account is turned off with the first token sitting in the owner's inbox.
	h.disable(who.id)

	sentBefore := h.mailer.count()
	if _, err := h.svc.ConfirmEmailChangeCurrent(h.t.Context(), ConfirmEmailChangeCurrentInput{
		Token: first,
	}); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("ConfirmEmailChangeCurrent for a disabled account = %v, want ErrTokenNotFound: "+
			"this is the step that MINTS the second token, so letting it run would put a live "+
			"credential in play for an account nobody may use", err)
	}
	if got := h.mailer.count(); got != sentBefore {
		t.Errorf("%d messages were sent during the confirmation, want %d", got, sentBefore)
	}

	// And the final step refuses too, for a token this harness never minted. That
	// half is normally unreachable for a disabled account precisely because the
	// second token is never minted; asserting it is the negative control on that
	// reasoning, because a test that only checked the first half would pass against
	// an implementation that simply forgot the ordering.
	target, err := h.mintEmailChangeTarget(who.id, newAddress)
	if err != nil {
		t.Fatalf("seeding a second-side token so the last step is reachable at all: %v", err)
	}
	if _, err := h.svc.ConfirmEmailChangeNew(h.t.Context(), ConfirmEmailChangeNewInput{
		Token: target,
	}); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("ConfirmEmailChangeNew for a disabled account = %v, want ErrTokenNotFound", err)
	}

	stored, err := h.users.ByID(h.t.Context(), h.pool, who.id)
	if err != nil {
		t.Fatalf("reading back the user: %v", err)
	}
	if stored.Email != who.email {
		t.Errorf("the address moved to %q on a disabled account, want it unchanged at %q",
			stored.Email, who.email)
	}
}

// A DISABLED ACCOUNT CANNOT START A SESSION LINK MINT.
//
// It cannot REDEEM one either, and that half is the NEXT PACKET: the redeem route
// does not exist yet, so there is nothing to refuse today. This test exists so the
// gap is written down where a reader of the mint will look rather than only in a
// handoff document nobody opens, and it is a test rather than a comment because a
// comment asserting an absence is not a thing anybody re-checks.
func TestASessionLinkIsNotMintedForADisabledAccount(t *testing.T) {
	h := newHarness(t, true)
	who := h.register(dbtest.UniqueEmail(t), "correct horse battery")
	h.disable(who.id)

	_, err := h.svc.MintSessionLink(h.t.Context(), MintSessionLinkInput{UserID: who.id})
	if !errors.Is(err, ErrSubjectDisabled) {
		t.Fatalf("MintSessionLink for a disabled account = %v, want ErrSubjectDisabled", err)
	}
	if got := h.tokenRowCount(who.id, PurposeSessionLink); got != 0 {
		t.Errorf("%d session link rows exist for a disabled account, want 0", got)
	}
}

// AND THE REFUSAL IS NAMED, SO A CALLER BEHIND A MACHINE CREDENTIAL CAN TELL IT
// FROM A 404.
//
// This surface is the opposite of the self-service ones and the difference is the
// credential: `POST /v1/session-links` requires a scoped api key holding
// `sessions:write`, so the caller is an operator with authority over somebody
// else's account and there is no stranger to protect. D12 is the ruling: an
// unknown subject is a 404 here and a 202 on every self-service route, for exactly
// that reason. "That subject is disabled" is the same kind of answer for the same
// kind of caller.
func TestTheSubjectDisabledRefusalIsItsOwnErrorAndNotA404(t *testing.T) {
	h := newHarness(t, true)
	who := h.register(dbtest.UniqueEmail(t), "correct horse battery")

	if _, err := h.svc.MintSessionLink(h.t.Context(), MintSessionLinkInput{UserID: who.id}); err != nil {
		t.Fatalf("MintSessionLink for an enabled account = %v, want a link", err)
	}

	h.disable(who.id)
	_, err := h.svc.MintSessionLink(h.t.Context(), MintSessionLinkInput{UserID: who.id})

	if errors.Is(err, ErrSubjectNotFound) {
		t.Error("a disabled subject answered 404's error: on a machine-credential surface that " +
			"tells an operator the user does not exist, which is false and which they can act on")
	}
	if !errors.Is(err, ErrSubjectDisabled) {
		t.Errorf("MintSessionLink = %v, want ErrSubjectDisabled", err)
	}
}
