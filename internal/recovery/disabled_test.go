package recovery


import (
	"context"
	"errors"
	"testing"

	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/sessions"
)

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

	err = db.TxRunner{Pool: h.pool}.Do(h.t.Context(), func(ctx context.Context, q db.Querier) error {
		_, err := NewStore(h.pool).MintTarget(ctx, q, rowID, digest, h.now())
		return err
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

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

func TestALiveResetTokenRedeemsNothingForADisabledAccount(t *testing.T) {
	h := newHarness(t, true)
	who := h.register(dbtest.UniqueEmail(t), "correct horse battery")

	if err := h.svc.RequestPasswordReset(h.t.Context(), who.email); err != nil {
		t.Fatalf("RequestPasswordReset before the disable: %v", err)
	}
	token := tokenFrom(t, h.mailer.last(t))
	sentBefore := h.mailer.count()

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

	h.enable(who.id)
	if _, err := h.svc.RedeemPasswordReset(h.t.Context(), RedeemPasswordResetInput{
		Token: token, Password: "a brand new correct horse battery",
	}); err != nil {
		t.Errorf("RedeemPasswordReset after re-enabling = %v, want success: the refusal did not "+
			"spend the token, so lifting the disable restores the flow the user started", err)
	}
}

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
