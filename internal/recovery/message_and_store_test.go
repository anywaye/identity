package recovery

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/sessions"
)


func TestNoSubjectCarriesAToken(t *testing.T) {
	const token = "Zz3vK7mXpR2tY8wB4cN6dF0gH1jK5lM9oP3qS7uV2wX4yZ8"

	for kind := range messageBodies {
		t.Run(string(kind), func(t *testing.T) {
			t.Parallel()

			message, err := messageFor(kind, messageData{
				To: "kaka@example.com", Email: "kaka@example.com",
				Target: "new@example.com", Token: token, Expiry: issuedAt().Add(time.Hour),
			})
			if err != nil {
				t.Fatalf("messageFor(%s): %v", kind, err)
			}
			if strings.Contains(message.Subject, token) {
				t.Errorf("the %s subject carries the token: %q", kind, message.Subject)
			}
			if !strings.Contains(message.Body, token) {
				t.Errorf("the %s body does not carry its token; a user cannot enter a code "+
					"that was never in the message:\n%s", kind, message.Body)
			}
			if strings.Contains(message.Body, "{{") {
				t.Errorf("the %s body has an unsubstituted placeholder in it:\n%s", kind, message.Body)
			}
		})
	}
}

func TestEveryMessageNamesTheAddressAndTheDeadline(t *testing.T) {
	for kind := range messageBodies {
		t.Run(string(kind), func(t *testing.T) {
			t.Parallel()

			expiry := issuedAt().Add(EmailChangeTTL)
			message, err := messageFor(kind, messageData{
				To: "kaka@example.com", Email: "kaka@example.com",
				Target: "new@example.com", Token: "a-token", Expiry: expiry,
			})
			if err != nil {
				t.Fatalf("messageFor(%s): %v", kind, err)
			}
			if !strings.Contains(message.Body, "kaka@example.com") {
				t.Errorf("the %s body does not name the account's address:\n%s", kind, message.Body)
			}
			if !strings.Contains(message.Body, expiry.UTC().Format(time.RFC1123)) {
				t.Errorf("the %s body does not carry a deadline a reader can place:\n%s", kind, message.Body)
			}
		})
	}
}

func TestAMessageWithNoTokenIsRefused(t *testing.T) {
	for kind := range messageBodies {
		if _, err := messageFor(kind, messageData{Email: "kaka@example.com"}); err == nil {
			t.Errorf("messageFor(%s) rendered a body with no token in it", kind)
		}
	}
}

func TestAMessageKindWithNoBodyIsRefusedRatherThanRenderedEmpty(t *testing.T) {
	if _, err := messageFor(messageKind("not_a_kind"), messageData{Token: "a-token"}); err == nil {
		t.Fatal("an unknown message kind rendered")
	}
}

func TestAnEmailChangeBodyNamesTheNewAddress(t *testing.T) {
	message, err := messageFor(messageChangeNew, messageData{
		Email: "kaka@example.com", Target: "new@example.com",
		Token: "a-token", Expiry: issuedAt().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("messageFor: %v", err)
	}
	if !strings.Contains(message.Body, "new@example.com") {
		t.Errorf("the new-address body does not name the new address:\n%s", message.Body)
	}
}

func TestThePurposesAreAClosedSetThatTheSchemaAgreesWith(t *testing.T) {
	want := map[Purpose]bool{
		PurposePasswordReset: true,
		PurposeVerifyEmail:   true,
		PurposeEmailChange:   true,
		PurposeSessionLink:   true,
	}
	for _, p := range allPurposes() {
		if !want[p] {
			t.Errorf("%q is in allPurposes but not in the set this test pins; either the "+
				"purpose does not exist or this test was not told about it", p)
		}
		delete(want, p)
	}
	if len(want) != 0 {
		t.Errorf("the pinned set has %d purposes this file no longer declares: %v", len(want), want)
	}
}

func TestEveryPurposeIsMailedHereOrDeclaredCallerDelivered(t *testing.T) {
	for _, p := range allPurposes() {
		_, hasBody := messageBodies[purposeMessageKind(p)]
		_, declaredElsewhere := callerDeliveredPurposes[p]
		if hasBody == declaredElsewhere {
			t.Errorf("%q is either renderable here and also declared caller-delivered, or "+
				"neither; every purpose is exactly one of the two, and `callerDeliveredPurposes` "+
				"must not name a flow this package sends", p)
		}
	}

	for p, who := range callerDeliveredPurposes {
		if who == "" {
			t.Errorf("%q is declared caller-delivered with nobody named as the deliverer", p)
		}
	}
}

func purposeMessageKind(p Purpose) messageKind {
	if p == PurposeEmailChange {
		return messageChangeFirst
	}
	return messageKind(p)
}

func TestTheSchemaRefusesAnUnknownPurpose(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()

	_, digest, err := sessions.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}

	if _, err := h.pool.Exec(t.Context(), `
		INSERT INTO recovery_tokens (user_id, purpose, token_digest, created_at, expires_at)
		VALUES ($1, 'sign_their_will', $2, $3, $4)`,
		who.id, digest, h.now(), h.now().Add(time.Hour)); err == nil {
		t.Error("the database accepted a purpose this build does not implement")
	}
}

func TestTheSchemaRefusesATokenWhoseExpiryIsItsOwnCreation(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()

	_, digest, err := sessions.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}

	if _, err := h.pool.Exec(t.Context(), `
		INSERT INTO recovery_tokens (user_id, purpose, token_digest, created_at, expires_at)
		VALUES ($1, 'password_reset', $2, $3, $3)`,
		who.id, digest, h.now()); err == nil {
		t.Error("the database accepted a token that expires the instant it was created")
	}
}

func TestTheSchemaRefusesATargetOnAFlowThatDoesNotMoveAddresses(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()

	_, digest, err := sessions.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}

	if _, err := h.pool.Exec(t.Context(), `
		INSERT INTO recovery_tokens (user_id, purpose, token_digest, target_email, created_at, expires_at)
		VALUES ($1, 'password_reset', $2, 'attacker@example.com', $3, $4)`,
		who.id, digest, h.now(), h.now().Add(time.Hour)); err == nil {
		t.Error("the database accepted a password reset token carrying a target address")
	}

	if _, err := h.pool.Exec(t.Context(), `
		INSERT INTO recovery_tokens (user_id, purpose, token_digest, created_at, expires_at)
		VALUES ($1, 'email_change', $2, $3, $4)`,
		who.id, digest, h.now(), h.now().Add(time.Hour)); err == nil {
		t.Error("the database accepted an email change token with no target address")
	}
}

func TestTokensAreGoneWithTheirUser(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()
	h.requestReset(t, who)

	rowID := h.newestTokenID(who.id, PurposePasswordReset)
	if got := countRows(t, h, `SELECT count(*) FROM recovery_tokens WHERE id = $1`, rowID); got != 1 {
		t.Fatalf("%d rows before the user is deleted, want 1", got)
	}
	if _, err := h.pool.Exec(t.Context(), `DELETE FROM users WHERE id = $1`, who.id); err != nil {
		t.Fatalf("deleting the user: %v", err)
	}
	if got := countRows(t, h, `SELECT count(*) FROM recovery_tokens WHERE id = $1`, rowID); got != 0 {
		t.Errorf("the token survived its user: %d rows remain", got)
	}
}

func TestOneTokenSpentOnceUnderConcurrency(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()
	token := h.requestReset(t, who)

	const racers = 8
	results := make(chan error, racers)
	start := make(chan struct{})

	for range racers {
		go func() {
			<-start
			_, err := h.svc.RedeemPasswordReset(t.Context(), RedeemPasswordResetInput{
				Token: token, Password: "one of these will win",
			})
			results <- err
		}()
	}
	close(start)

	won := 0
	for range racers {
		if err := <-results; err == nil {
			won++
		}
	}
	if won != 1 {
		t.Errorf("%d of %d concurrent redemptions of one token succeeded, want exactly 1", won, racers)
	}
	assertPasswordIs(t, h, who, "one of these will win")
}

func TestTheStoredDigestIsTheOnlyCredential(t *testing.T) {
	h := newHarness(t, true)
	who := h.registerSimple()

	token, digest, err := sessions.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	created, err := NewStore(h.pool).Create(t.Context(), h.pool, NewToken{
		UserID: who.id, Purpose: PurposePasswordReset,
		Digest: digest, CreatedAt: h.now(), ExpiresAt: h.now().Add(PasswordResetTTL),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	row := h.storedTokenRow(created.ID)
	if got := row["token_digest"]; got != digest {
		t.Errorf("token_digest = %v, want the digest the store was handed", got)
	}

	for _, garbage := range []string{"", " ", "not-a-token", token, token[:20], strings.Repeat("x", 4096)} {
		got := sessions.Digest(garbage)
		if len(got) != 64 {
			t.Errorf("Digest(%d bytes) is %d characters, want 64", len(garbage), len(got))
		}
	}
	if sessions.Digest(token) != digest {
		t.Error("Digest is not a function of its input; the lookup could not be an indexed equality")
	}

	if _, err := NewStore(h.pool).Live(t.Context(), h.pool, digest, PurposePasswordReset, h.now()); err != nil {
		t.Fatalf("Live on a fresh token: %v", err)
	}
	if _, err := NewStore(h.pool).Live(t.Context(), h.pool, digest, PurposeVerifyEmail, h.now()); !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("Live for the wrong purpose = %v, want ErrTokenNotFound", err)
	}
}
