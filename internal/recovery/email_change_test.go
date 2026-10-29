package recovery

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/platform/id"

	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/sessions"
)


func TestAnEmailChangeNeedsBothAddressesConfirmed(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()
	target := dbtest.UniqueEmail(t)

	change, err := h.svc.RequestEmailChange(t.Context(), RequestEmailChangeInput{
		UserID: who.id, Email: target,
	})
	if err != nil {
		t.Fatalf("RequestEmailChange: %v", err)
	}
	if change.CurrentEmail != who.email || change.NewEmail != target {
		t.Errorf("the change = %+v, want %q -> %q", change, who.email, target)
	}

	first := h.mailer.last(t)
	if first.To != who.email {
		t.Fatalf("the first message went to %q, want the CURRENT address %q", first.To, who.email)
	}
	current := tokenFrom(t, first)

	assertEmailIs(t, h, who, who.email)
	if h.hasTargetDigest(h.newestTokenID(who.id, PurposeEmailChange)) {
		t.Error("a target token exists before the current address was confirmed")
	}

	if _, err := h.svc.ConfirmEmailChangeCurrent(t.Context(), ConfirmEmailChangeCurrentInput{
		Token: current,
	}); err != nil {
		t.Fatalf("ConfirmEmailChangeCurrent: %v", err)
	}

	second := h.mailer.last(t)
	if second.To != target {
		t.Errorf("the second message went to %q, want the NEW address %q", second.To, target)
	}
	next := tokenFrom(t, second)
	if next == current {
		t.Error("the new-address token is the one already spent on the current address")
	}

	assertEmailIs(t, h, who, who.email)

	if _, err := h.svc.ConfirmEmailChangeNew(t.Context(), ConfirmEmailChangeNewInput{
		Token: next,
	}); err != nil {
		t.Fatalf("ConfirmEmailChangeNew: %v", err)
	}

	assertEmailIs(t, h, who, target)
	assertEmailAvailable(t, h, who.email)
}

func TestTheNewAddressTokenIsMintedOnlyAfterTheCurrentAddressIsConfirmed(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()
	rowID := h.requestEmailChange(t, who, dbtest.UniqueEmail(t))

	if h.hasTargetDigest(rowID) {
		t.Error("a target token exists immediately after the request")
	}
	if _, err := h.pool.Exec(t.Context(),
		`UPDATE recovery_tokens SET target_token_digest = $2 WHERE id = $1`,
		rowID, sessions.Digest("written by hand")); err == nil {
		t.Error("the database accepted a target token before the current address was confirmed")
	}

	token := tokenFrom(t, h.mailer.last(t))
	if _, err := h.svc.ConfirmEmailChangeCurrent(t.Context(), ConfirmEmailChangeCurrentInput{
		Token: token,
	}); err != nil {
		t.Fatalf("ConfirmEmailChangeCurrent: %v", err)
	}
	if !h.hasTargetDigest(rowID) {
		t.Error("no target token exists after the current address was confirmed")
	}
}

func TestAChangeDoesNotApplyFromTheCurrentAddressTokenAlone(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()
	target := dbtest.UniqueEmail(t)
	h.requestEmailChange(t, who, target)
	current := tokenFrom(t, h.mailer.last(t))

	if _, err := h.svc.ConfirmEmailChangeNew(t.Context(), ConfirmEmailChangeNewInput{
		Token: current,
	}); err == nil {
		t.Fatal("the current-address token moved the address on its own")
	}
	assertEmailIs(t, h, who, who.email)
}

func TestAChangeDoesNotApplyFromTheNewAddressTokenAlone(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()
	target := dbtest.UniqueEmail(t)
	h.requestEmailChange(t, who, target)

	h.svc.ConfirmEmailChangeCurrent(t.Context(), ConfirmEmailChangeCurrentInput{
		Token: tokenFrom(t, h.mailer.last(t)),
	})
	next := tokenFrom(t, h.mailer.last(t))

	if _, err := h.svc.ConfirmEmailChangeNew(t.Context(), ConfirmEmailChangeNewInput{Token: next}); err != nil {
		t.Fatalf("ConfirmEmailChangeNew: %v", err)
	}
	if _, err := h.svc.ConfirmEmailChangeNew(t.Context(), ConfirmEmailChangeNewInput{Token: next}); err == nil {
		t.Fatal("the new-address token was accepted twice")
	}
	assertEmailIs(t, h, who, target)
}

func TestAnExpiredEmailChangeTokenIsRefusedOnBothHalves(t *testing.T) {
	t.Run("the current-address half", func(t *testing.T) {
		h := newHarness(t, true)
		who := h.registerSimple()
		h.requestEmailChange(t, who, dbtest.UniqueEmail(t))
		current := tokenFrom(t, h.mailer.last(t))

		h.clk.Advance(EmailChangeTTL + time.Second)
		if _, err := h.svc.ConfirmEmailChangeCurrent(t.Context(), ConfirmEmailChangeCurrentInput{
			Token: current,
		}); err == nil {
			t.Fatal("an expired current-address token was accepted")
		}
		if got := h.mailer.count(); got != 1 {
			t.Errorf("%d messages; a refused token mailed the new address anyway", got)
		}
	})

	t.Run("the new-address half", func(t *testing.T) {
		h := newHarness(t, true)
		who := h.registerSimple()
		h.requestEmailChange(t, who, dbtest.UniqueEmail(t))
		h.svc.ConfirmEmailChangeCurrent(t.Context(), ConfirmEmailChangeCurrentInput{
			Token: tokenFrom(t, h.mailer.last(t)),
		})
		next := tokenFrom(t, h.mailer.last(t))

		h.clk.Advance(EmailChangeTTL + time.Second)
		if _, err := h.svc.ConfirmEmailChangeNew(t.Context(), ConfirmEmailChangeNewInput{Token: next}); err == nil {
			t.Fatal("an expired new-address token was accepted")
		}
		assertEmailIs(t, h, who, who.email)
	})
}

func TestAChangeClearsTheVerificationAndEndsEveryCredential(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()

	h.requestVerification(t, who)
	if err := h.svc.RedeemVerification(t.Context(), RedeemVerificationInput{
		Token: tokenFrom(t, h.mailer.last(t)),
	}); err != nil {
		t.Fatalf("RedeemVerification: %v", err)
	}
	assertVerified(t, h, who)

	target := dbtest.UniqueEmail(t)
	h.requestEmailChange(t, who, target)
	h.svc.ConfirmEmailChangeCurrent(t.Context(), ConfirmEmailChangeCurrentInput{
		Token: tokenFrom(t, h.mailer.last(t)),
	})
	if _, err := h.svc.ConfirmEmailChangeNew(t.Context(), ConfirmEmailChangeNewInput{
		Token: tokenFrom(t, h.mailer.last(t)),
	}); err != nil {
		t.Fatalf("ConfirmEmailChangeNew: %v", err)
	}

	assertNotVerified(t, h, who)
	if got := h.sessionsFor(who.id); got != 0 {
		t.Errorf("%d sessions survived an email change, want 0", got)
	}
	if _, swept := h.access.swept(who.id); !swept {
		t.Error("an email change revoked no access tokens")
	}
}

func TestAnEmailChangeToAnAddressSomebodyElseHasIsRefusedTwice(t *testing.T) {
	t.Run("at the request", func(t *testing.T) {
		h := newHarness(t, true)
		who := h.registerSimple()
		taken := h.registerSimple()

		_, err := h.svc.RequestEmailChange(t.Context(), RequestEmailChangeInput{
			UserID: who.id, Email: taken.email,
		})
		if !errors.Is(err, ErrEmailTaken) {
			t.Errorf("RequestEmailChange to a registered address = %v, want ErrEmailTaken", err)
		}
		if got := h.mailer.count(); got != 0 {
			t.Errorf("%d messages were sent for a change that could never apply", got)
		}
	})

	t.Run("at the confirmation", func(t *testing.T) {
		h := newHarness(t, true)
		who := h.registerSimple()
		target := dbtest.UniqueEmail(t)
		h.requestEmailChange(t, who, target)
		h.svc.ConfirmEmailChangeCurrent(t.Context(), ConfirmEmailChangeCurrentInput{
			Token: tokenFrom(t, h.mailer.last(t)),
		})
		next := tokenFrom(t, h.mailer.last(t))

		if _, err := h.users.Create(t.Context(), h.pool, dbCreate(target)); err != nil {
			t.Fatalf("registering the address mid-change: %v", err)
		}

		if _, err := h.svc.ConfirmEmailChangeNew(t.Context(), ConfirmEmailChangeNewInput{Token: next}); !errors.Is(err, ErrEmailTaken) {
			t.Errorf("ConfirmEmailChangeNew onto a registered address = %v, want ErrEmailTaken", err)
		}
		assertEmailIs(t, h, who, who.email)
	})
}

func TestAnEmailChangeToTheCurrentAddressIsRefused(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()

	for _, address := range []string{who.email, "  " + strings.ToUpper(who.email) + " "} {
		_, err := h.svc.RequestEmailChange(t.Context(), RequestEmailChangeInput{
			UserID: who.id, Email: address,
		})
		if !errors.Is(err, ErrSameAddress) {
			t.Errorf("RequestEmailChange(%q) = %v, want ErrSameAddress", address, err)
		}
	}
	if got := h.mailer.count(); got != 0 {
		t.Errorf("%d messages were sent for a change that describes no move", got)
	}
}

func TestAnEmailChangeTokenIsNotAResetOrAVerificationToken(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()
	h.requestEmailChange(t, who, dbtest.UniqueEmail(t))
	change := tokenFrom(t, h.mailer.last(t))

	if err := h.svc.RedeemVerification(t.Context(), RedeemVerificationInput{Token: change}); err == nil {
		t.Error("an email change token was accepted by the verification redemption")
	}
	h.clk.Advance(RequestWindow + time.Second)
	reset := h.requestReset(t, who)
	if _, err := h.svc.ConfirmEmailChangeCurrent(t.Context(),
		ConfirmEmailChangeCurrentInput{Token: reset}); err == nil {
		t.Error("a password reset token was accepted as an email change confirmation")
	}
	assertNotVerified(t, h, who)
	assertPasswordIs(t, h, who, "correct horse battery staple")
}


func (h *harness) requestEmailChange(t *testing.T, who account, target string) id.UUID {
	t.Helper()
	if _, err := h.svc.RequestEmailChange(t.Context(), RequestEmailChangeInput{
		UserID: who.id, Email: target,
	}); err != nil {
		t.Fatalf("RequestEmailChange: %v", err)
	}
	return h.newestTokenID(who.id, PurposeEmailChange)
}

func assertEmailIs(t *testing.T, h *harness, who account, want string) {
	t.Helper()
	var got string
	if err := h.pool.QueryRow(t.Context(),
		`SELECT email FROM users WHERE id = $1`, who.id).Scan(&got); err != nil {
		t.Fatalf("reading the address: %v", err)
	}
	if got != want {
		t.Errorf("the account's address is %q, want %q", got, want)
	}
}

func assertEmailAvailable(t *testing.T, h *harness, email string) {
	t.Helper()
	var n int
	if err := h.pool.QueryRow(t.Context(),
		`SELECT count(*) FROM users WHERE email = $1`, email).Scan(&n); err != nil {
		t.Fatalf("counting users at %q: %v", email, err)
	}
	if n != 0 {
		t.Errorf("%d accounts still hold %q; the old address was not freed", n, email)
	}
}
