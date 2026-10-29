package recovery

import (
	"testing"
	"time"

	"github.com/anywaye/identity/internal/platform/dbtest"
)


func TestAVerificationProvesTheAddressAndNothingElse(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()
	assertNotVerified(t, h, who)

	token := h.requestVerification(t, who)
	if got := h.mailer.last(t).To; got != who.email {
		t.Errorf("the verification went to %q, want the account's own address %q", got, who.email)
	}

	sessionsBefore := h.sessionsFor(who.id)
	if err := h.svc.RedeemVerification(t.Context(), RedeemVerificationInput{Token: token}); err != nil {
		t.Fatalf("RedeemVerification: %v", err)
	}

	assertVerified(t, h, who)

	if got := h.sessionsFor(who.id); got != sessionsBefore {
		t.Errorf("%d sessions after a verification, want %d: verifying an address is not a "+
			"security change", got, sessionsBefore)
	}
	if _, swept := h.access.swept(who.id); swept {
		t.Error("a verification revoked the account's access tokens")
	}

	var seen int
	if err := h.pool.QueryRow(t.Context(),
		`SELECT count(*) FROM outbox_events WHERE type = 'identity.user.email_verified' AND subject = $1`,
		who.id.String()).Scan(&seen); err != nil {
		t.Fatalf("counting the verification event: %v", err)
	}
	if seen != 1 {
		t.Errorf("%d identity.user.email_verified events after one verification, want 1", seen)
	}
}

func TestAReusedVerificationTokenIsRefused(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()

	token := h.requestVerification(t, who)
	if err := h.svc.RedeemVerification(t.Context(), RedeemVerificationInput{Token: token}); err != nil {
		t.Fatalf("the first redemption: %v", err)
	}
	if err := h.svc.RedeemVerification(t.Context(), RedeemVerificationInput{Token: token}); err == nil {
		t.Fatal("a verification token was accepted twice")
	}

	var at *time.Time
	if err := h.pool.QueryRow(t.Context(),
		`SELECT email_verified_at FROM users WHERE id = $1`, who.id).Scan(&at); err != nil {
		t.Fatalf("reading the verification state: %v", err)
	}
	if !at.Equal(h.now()) {
		t.Errorf("verified at %s, want %s: a replay moved the instant", at, h.now())
	}
}

func TestAnExpiredVerificationTokenIsRefused(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()

	token := h.requestVerification(t, who)
	h.clk.Advance(VerifyEmailTTL + time.Second)

	if err := h.svc.RedeemVerification(t.Context(), RedeemVerificationInput{Token: token}); err == nil {
		t.Fatal("an expired verification token was accepted")
	}
	assertNotVerified(t, h, who)
}

func TestAVerificationRequestForAVerifiedAddressIsNotDistinguished(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()

	token := h.requestVerification(t, who)
	if err := h.svc.RedeemVerification(t.Context(), RedeemVerificationInput{Token: token}); err != nil {
		t.Fatalf("RedeemVerification: %v", err)
	}
	firstProof := h.now()

	h.clk.Advance(RequestWindow + time.Second)

	if err := h.svc.RequestVerification(t.Context(), who.email); err != nil {
		t.Errorf("RequestVerification on a verified account = %v, want nil: a proved address "+
			"must not be a distinguishable case", err)
	}
	if got := h.mailer.count(); got != 2 {
		t.Errorf("%d messages after a second request on a verified account, want 2: the request "+
			"is treated exactly as it is for an unverified account", got)
	}

	if err := h.svc.RedeemVerification(t.Context(), RedeemVerificationInput{
		Token: tokenFrom(t, h.mailer.last(t)),
	}); err != nil {
		t.Fatalf("redeeming the second verification: %v", err)
	}
	var at *time.Time
	if err := h.pool.QueryRow(t.Context(),
		`SELECT email_verified_at FROM users WHERE id = $1`, who.id).Scan(&at); err != nil {
		t.Fatalf("reading the verification state: %v", err)
	}
	if at == nil || !at.Equal(firstProof) {
		t.Errorf("email_verified_at = %v, want the first proof at %s", at, firstProof)
	}
}

func TestAVerificationRequestForAnUnknownAddressIsSilent(t *testing.T) {
	h := newHarness(t, true)

	if err := h.svc.RequestVerification(t.Context(), dbtest.UniqueEmail(t)); err != nil {
		t.Fatalf("RequestVerification for an unknown address = %v, want nil", err)
	}
	if got := h.mailer.count(); got != 0 {
		t.Errorf("%d messages for an address with no account", got)
	}
	if got := countRows(t, h, `SELECT count(*) FROM recovery_tokens`); got != 0 {
		t.Errorf("%d rows for an address with no account", got)
	}
}

func TestAVerificationRequestInsideTheWindowSendsNothing(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()

	if err := h.svc.RequestVerification(t.Context(), who.email); err != nil {
		t.Fatalf("the first request: %v", err)
	}
	for range 10 {
		h.clk.Advance(time.Second)
		if err := h.svc.RequestVerification(t.Context(), who.email); err != nil {
			t.Fatalf("a request inside the window: %v", err)
		}
	}
	if got := h.mailer.count(); got != 1 {
		t.Errorf("%d verification messages after 11 requests inside the window, want 1", got)
	}
}

func TestVerificationStatusIsA200WithABooleanRatherThanAnError(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()

	before, err := h.svc.VerificationStatus(t.Context(), who.id)
	if err != nil {
		t.Fatalf("VerificationStatus before verifying: %v", err)
	}
	if before.Verified || before.VerifiedAt != nil || before.Email != who.email {
		t.Errorf("before: %+v, want unverified at %q", before, who.email)
	}

	h.requestVerification(t, who)
	if err := h.svc.RedeemVerification(t.Context(), RedeemVerificationInput{
		Token: tokenFrom(t, h.mailer.last(t)),
	}); err != nil {
		t.Fatalf("RedeemVerification: %v", err)
	}

	after, err := h.svc.VerificationStatus(t.Context(), who.id)
	if err != nil {
		t.Fatalf("VerificationStatus after verifying: %v", err)
	}
	if !after.Verified || after.VerifiedAt == nil || !after.VerifiedAt.Equal(h.now()) {
		t.Errorf("after: %+v, want verified at %s", after, h.now())
	}
}


func (h *harness) requestVerification(t *testing.T, who account) string {
	t.Helper()
	if err := h.svc.RequestVerification(t.Context(), who.email); err != nil {
		t.Fatalf("RequestVerification: %v", err)
	}
	return tokenFrom(t, h.mailer.last(t))
}
