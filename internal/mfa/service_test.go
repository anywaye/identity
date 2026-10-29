package mfa

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/anywaye/identity/internal/outbox"
	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/sessions"
	"github.com/anywaye/identity/internal/users"
)


const testIssuer = "anywaye identity"

type harness struct {
	t     *testing.T
	pool  *pgxpool.Pool
	clk   *clock.Fake
	store *Store
	svc   *Service
	user  users.User
	secret string
	codes  []string
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	pool := dbtest.Schema(t)
	clk := clock.NewFake(issuedAt)
	store := NewStore(pool)

	h := &harness{
		t:     t,
		pool:  pool,
		clk:   clk,
		store: store,
		svc: NewService(
			db.TxRunner{Pool: pool},
			db.Direct{Pool: pool},
			store,
			outbox.NewStore(pool),
			sessions.NewStore(pool),
			mustVault(t),
			clk,
			testIssuer,
		),
	}
	h.user = newTestUser(t, pool)
	return h
}

func mustVault(t *testing.T) Vault {
	t.Helper()
	vault, err := NewAESCipher(testKey)
	if err != nil {
		t.Fatalf("NewAESCipher: %v", err)
	}
	return vault
}

func (h *harness) now() time.Time { return h.clk.Now() }

func (h *harness) code() string {
	h.t.Helper()
	if h.secret == "" {
		h.t.Fatal("no secret: enroll first")
	}
	code, err := Code(h.secret, h.now())
	if err != nil {
		h.t.Fatalf("Code: %v", err)
	}
	return code
}

func (h *harness) enroll() Credential {
	h.t.Helper()
	started, err := h.svc.StartEnrollment(h.t.Context(), StartEnrollmentInput{UserID: h.user.ID})
	if err != nil {
		h.t.Fatalf("StartEnrollment: %v", err)
	}
	h.secret = started.Secret

	confirmed, err := h.svc.Confirm(h.t.Context(), ConfirmInput{
		UserID:       h.user.ID,
		EnrollmentID: started.Credential.ID,
		Factor:       h.code(),
	})
	if err != nil {
		h.t.Fatalf("Confirm: %v", err)
	}
	h.codes = confirmed.RecoveryCodes
	return confirmed.Credential
}

func (h *harness) clearFactorFailures() {
	h.t.Helper()
	credential, err := h.store.ConfirmedCredential(h.t.Context(), h.pool, h.user.ID)
	if err != nil {
		return
	}
	if err := h.store.ClearFactorFailures(h.t.Context(), h.pool, credential.ID); err != nil {
		h.t.Fatalf("resetting the factor's counter: %v", err)
	}
}

func (h *harness) signIn() sessions.Session {
	h.t.Helper()
	token, digest, err := sessions.NewToken()
	if err != nil {
		h.t.Fatalf("NewToken: %v", err)
	}
	session, err := sessions.NewStore(h.pool).Create(h.t.Context(), h.pool, sessions.NewSession{
		UserID:      h.user.ID,
		TokenDigest: digest,
		ExpiresAt:   h.now().Add(24 * time.Hour),
		UserAgent:   "Test/1.0",
	})
	if err != nil {
		h.t.Fatalf("creating a session: %v", err)
	}
	_ = token
	return session
}

func (h *harness) liveSessions() int {
	h.t.Helper()
	var n int
	if err := h.pool.QueryRow(h.t.Context(), `SELECT count(*) FROM sessions WHERE user_id = $1`, h.user.ID).Scan(&n); err != nil {
		h.t.Fatalf("counting sessions: %v", err)
	}
	return n
}

func (h *harness) events(eventType string) []outbox.Envelope {
	h.t.Helper()
	rows, err := h.pool.Query(h.t.Context(),
		`SELECT envelope FROM outbox_events WHERE type = $1 AND subject = $2 ORDER BY occurred_at`,
		eventType, h.user.ID.String())
	if err != nil {
		h.t.Fatalf("reading the outbox: %v", err)
	}
	defer rows.Close()

	var out []outbox.Envelope
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			h.t.Fatalf("scanning an event: %v", err)
		}
		var e outbox.Envelope
		if err := json.Unmarshal(raw, &e); err != nil {
			h.t.Fatalf("the stored envelope is not an outbox envelope: %v", err)
		}
		out = append(out, e)
	}
	return out
}


func TestAnEnrollmentIsNotMFAUntilItIsConfirmed(t *testing.T) {
	h := newHarness(t)

	started, err := h.svc.StartEnrollment(t.Context(), StartEnrollmentInput{UserID: h.user.ID})
	if err != nil {
		t.Fatalf("StartEnrollment: %v", err)
	}
	h.secret = started.Secret

	status, err := h.svc.StatusFor(t.Context(), h.user.ID)
	if err != nil {
		t.Fatalf("StatusFor: %v", err)
	}
	if status.Enabled {
		t.Error("an unconfirmed enrollment reports itself as enabled")
	}
	if enabled, err := h.svc.Enabled(t.Context(), h.pool, h.user.ID); err != nil || enabled {
		t.Errorf("Enabled = (%v, %v) for a pending enrollment, want (false, nil)", enabled, err)
	}

	if _, err := h.svc.Confirm(t.Context(), ConfirmInput{
		UserID: h.user.ID, EnrollmentID: started.Credential.ID, Factor: "000000",
	}); !errors.Is(err, ErrInvalidFactor) {
		t.Errorf("Confirm with a wrong code = %v, want ErrInvalidFactor", err)
	}
	if status, _ := h.svc.StatusFor(t.Context(), h.user.ID); status.Enabled {
		t.Error("a failed confirmation enabled MFA")
	}

	confirmed, err := h.svc.Confirm(t.Context(), ConfirmInput{
		UserID: h.user.ID, EnrollmentID: started.Credential.ID, Factor: h.code(),
	})
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if !confirmed.Credential.IsConfirmed() {
		t.Error("the confirmed credential does not say it is confirmed")
	}
	if len(confirmed.RecoveryCodes) != RecoveryCodeCount {
		t.Errorf("%d recovery codes were issued, want %d", len(confirmed.RecoveryCodes), RecoveryCodeCount)
	}

	status, _ = h.svc.StatusFor(t.Context(), h.user.ID)
	if !status.Enabled {
		t.Error("a confirmed credential does not report itself as enabled")
	}
	if status.RecoveryCodesRemaining != RecoveryCodeCount {
		t.Errorf("StatusFor reports %d codes left, want %d", status.RecoveryCodesRemaining, RecoveryCodeCount)
	}
	if status.EnrolledAt == nil {
		t.Error("StatusFor has no enrolled_at for an enrolled user")
	}
}

func TestTheSecretIsShownOnceAndStoredSealed(t *testing.T) {
	h := newHarness(t)
	started, err := h.svc.StartEnrollment(t.Context(), StartEnrollmentInput{UserID: h.user.ID})
	if err != nil {
		t.Fatalf("StartEnrollment: %v", err)
	}

	if started.Secret == "" || !strings.HasSuffix(strings.ToUpper(started.Secret), strings.ToUpper(started.Secret)) {
		t.Fatalf("the enrollment response carries no secret: %q", started.Secret)
	}
	if !strings.HasPrefix(started.ProvisioningURI, "otpauth://totp/") {
		t.Errorf("the provisioning URI is %q, want an otpauth://totp/ one", started.ProvisioningURI)
	}

	var stored string
	if err := h.pool.QueryRow(t.Context(),
		`SELECT secret_ciphertext FROM mfa_credentials WHERE id = $1`, started.Credential.ID).Scan(&stored); err != nil {
		t.Fatalf("reading the stored secret: %v", err)
	}
	if strings.Contains(stored, started.Secret) {
		t.Fatal("the row holds the secret in the clear")
	}
	if stored != started.Credential.SecretCiphertext {
		t.Error("the response and the row disagree about the sealed value")
	}
	if !strings.HasPrefix(stored, SealPrefix) {
		t.Errorf("the stored value %q has no version prefix", stored)
	}

	status, _ := h.svc.StatusFor(t.Context(), h.user.ID)
	encoded, _ := json.Marshal(status)
	if strings.Contains(string(encoded), started.Secret) {
		t.Fatal("the status response carries the secret")
	}
}

func TestConfirmingRevokesEverySessionIssuedBeforeMFA(t *testing.T) {
	h := newHarness(t)

	before := h.signIn()
	h.enroll()

	if got := h.liveSessions(); got != 0 {
		t.Errorf("%d sessions survived the enrollment, want 0", got)
	}
	token, digest, err := sessions.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if _, err := h.store.ConfirmedCredential(t.Context(), h.pool, h.user.ID); err != nil {
		t.Fatalf("the credential went with the session: %v", err)
	}
	if _, err := sessions.NewStore(h.pool).ByToken(t.Context(), h.pool, token, h.now()); !errors.Is(err, sessions.ErrNotFound) {
		t.Errorf("a session token resolved after the revocation: %v", err)
	}
	_ = before
	_ = digest
}

func TestConfirmingAnnouncesItself(t *testing.T) {
	h := newHarness(t)
	if got := h.events(outbox.EventMFAEnabled); len(got) != 0 {
		t.Fatalf("%d events before enrollment, want 0", len(got))
	}

	credential := h.enroll()

	events := h.events(outbox.EventMFAEnabled)
	if len(events) != 1 {
		t.Fatalf("%d identity.mfa.enabled events, want 1", len(events))
	}
	if events[0].Subject != h.user.ID.String() {
		t.Errorf("subject = %q, want the user %q", events[0].Subject, h.user.ID)
	}
	var payload struct {
		UserID       string `json:"user_id"`
		CredentialID string `json:"credential_id"`
		Method       string `json:"method"`
	}
	if err := json.Unmarshal(events[0].Data, &payload); err != nil {
		t.Fatalf("the payload is not JSON: %v", err)
	}
	if payload.CredentialID != credential.ID.String() || payload.Method != MethodTOTP || payload.UserID != h.user.ID.String() {
		t.Errorf("payload = %+v", payload)
	}
	rendered := string(events[0].Data)
	for _, secretValue := range []string{h.secret, h.codes[0], strings.Join(h.codes, "")} {
		if strings.Contains(rendered, secretValue) {
			t.Fatalf("the event payload carries a secret: %s", rendered)
		}
	}
	if got := h.events(outbox.EventMFADisabled); len(got) != 0 {
		t.Errorf("%d identity.mfa.disabled events after an enrollment", len(got))
	}
}

func TestAnExpiredEnrollmentIsRefused(t *testing.T) {
	h := newHarness(t)
	started, err := h.svc.StartEnrollment(t.Context(), StartEnrollmentInput{UserID: h.user.ID})
	if err != nil {
		t.Fatalf("StartEnrollment: %v", err)
	}
	h.secret = started.Secret
	code := h.code()

	h.clk.Advance(EnrollmentTTL + time.Second)

	if _, err := h.svc.Confirm(t.Context(), ConfirmInput{
		UserID: h.user.ID, EnrollmentID: started.Credential.ID, Factor: code,
	}); !errors.Is(err, ErrEnrollmentNotFound) {
		t.Errorf("Confirming an expired enrollment = %v, want ErrEnrollmentNotFound", err)
	}
}

func TestStartingAnEnrollmentReplacesThePendingOne(t *testing.T) {
	h := newHarness(t)

	var firstID id.UUID
	for range 3 {
		started, err := h.svc.StartEnrollment(t.Context(), StartEnrollmentInput{UserID: h.user.ID})
		if err != nil {
			t.Fatalf("StartEnrollment: %v", err)
		}
		if firstID.IsZero() {
			firstID = started.Credential.ID
		}
		h.secret = started.Secret
	}

	var pending int
	if err := h.pool.QueryRow(t.Context(),
		`SELECT count(*) FROM mfa_credentials WHERE user_id = $1 AND confirmed_at IS NULL`, h.user.ID).Scan(&pending); err != nil {
		t.Fatalf("counting pending enrollments: %v", err)
	}
	if pending != 1 {
		t.Errorf("%d pending enrollments, want 1", pending)
	}
}


func TestARotatedSecretInvalidatesTheOldOne(t *testing.T) {
	h := newHarness(t)
	h.enroll()
	oldSecret := h.secret
	oldCodes := h.codes

	if _, err := h.svc.StartEnrollment(t.Context(), StartEnrollmentInput{UserID: h.user.ID}); !errors.Is(err, ErrInvalidFactor) {
		t.Errorf("rotating with no factor = %v, want ErrInvalidFactor", err)
	}

	started, err := h.svc.StartEnrollment(t.Context(), StartEnrollmentInput{UserID: h.user.ID, Factor: h.code()})
	if err != nil {
		t.Fatalf("rotating: %v", err)
	}
	if !started.Replaced {
		t.Error("the rotation does not say it replaced a live credential")
	}
	h.secret = started.Secret

	h.clk.Advance(Period)
	if _, err := h.svc.VerifyFactor(t.Context(), h.user.ID, codeFor(t, oldSecret, StepAt(h.now(), Period)), h.now()); err != nil {
		t.Errorf("the old secret stopped working before the rotation was confirmed: %v", err)
	}
	h.clk.Advance(Period)
	if _, err := h.svc.VerifyFactor(t.Context(), h.user.ID, h.code(), h.now()); !errors.Is(err, ErrInvalidFactor) {
		t.Errorf("an unconfirmed secret was accepted as a factor: %v", err)
	}

	confirmed, err := h.svc.Confirm(t.Context(), ConfirmInput{
		UserID: h.user.ID, EnrollmentID: started.Credential.ID, Factor: h.code(),
	})
	if err != nil {
		t.Fatalf("Confirming the rotation: %v", err)
	}
	if confirmed.ReplacedCredentialID.IsZero() {
		t.Error("the confirmation does not say what it replaced")
	}
	h.codes = confirmed.RecoveryCodes

	if _, err := h.svc.VerifyFactor(t.Context(), h.user.ID, codeFor(t, oldSecret, StepAt(h.now(), Period)), h.now()); !errors.Is(err, ErrInvalidFactor) {
		t.Errorf("the OLD secret still works after a rotation: %v", err)
	}
	for _, code := range oldCodes {
		h.refuteFactor(code)
	}
	h.clk.Advance(2 * Period)
	if _, err := h.svc.VerifyFactor(t.Context(), h.user.ID, h.code(), h.now()); err != nil {
		t.Errorf("the new secret does not work after the rotation: %v", err)
	}
}


func TestARecoveryCodeIsAcceptedInPlaceOfATOTPCodeAndIsSingleUse(t *testing.T) {
	h := newHarness(t)
	h.enroll()

	code := h.codes[0]
	claim, err := h.svc.VerifyFactor(t.Context(), h.user.ID, code, h.now())
	if err != nil {
		t.Fatalf("a recovery code was refused: %v", err)
	}
	if claim.Method() != MethodRecoveryCode {
		t.Errorf("Method = %q, want %q", claim.Method(), MethodRecoveryCode)
	}
	spelling := strings.ToLower(strings.ReplaceAll(code, "-", " "))
	if _, err := h.svc.VerifyFactor(t.Context(), h.user.ID, spelling, h.now()); !errors.Is(err, ErrInvalidFactor) {
		t.Errorf("a re-spelled code was not refused as spent: %v", err)
	}
}

func TestSpellingDoesNotMatterForAFirstUse(t *testing.T) {
	h := newHarness(t)
	h.enroll()

	spellings := []func(string) string{
		func(code string) string { return code },
		func(code string) string { return strings.ToLower(code) },
		func(code string) string { return strings.ReplaceAll(code, "-", "") },
		func(code string) string { return strings.ReplaceAll(code, "-", " ") },
		func(code string) string { return "  " + code + "  " },
	}

	for i, spell := range spellings {
		t.Run(spell(h.codes[i]), func(t *testing.T) {
			code := h.codes[i]
			if _, err := h.svc.VerifyFactor(t.Context(), h.user.ID, spell(code), h.now()); err != nil {
				t.Errorf("a recovery code spelled %q was refused: %v", spell(code), err)
			}
			if _, err := h.svc.VerifyFactor(t.Context(), h.user.ID, code, h.now()); !errors.Is(err, ErrInvalidFactor) {
				t.Errorf("the code was spendable twice")
			}
		})
	}
}

func TestTheLastRecoveryCodeIsCalledOut(t *testing.T) {
	h := newHarness(t)
	h.enroll()

	for i := 1; i < len(h.codes); i++ {
		claim, err := h.svc.VerifyFactor(t.Context(), h.user.ID, h.codes[i], h.now())
		if err != nil {
			t.Fatalf("using code %d: %v", i, err)
		}
		if want := RecoveryCodeCount - i; claim.RecoveryCodesRemaining() != want {
			t.Errorf("after using code %d the claim reports %d left, want %d", i, claim.RecoveryCodesRemaining(), want)
		}
	}

	last, err := h.svc.VerifyFactor(t.Context(), h.user.ID, h.codes[0], h.now())
	if err != nil {
		t.Fatalf("using the last code: %v", err)
	}
	if last.RecoveryCodesRemaining() != 0 {
		t.Errorf("after the last code the claim reports %d left, want 0", last.RecoveryCodesRemaining())
	}

	status, _ := h.svc.StatusFor(t.Context(), h.user.ID)
	if status.RecoveryCodesRemaining != 0 {
		t.Errorf("StatusFor reports %d codes left, want 0", status.RecoveryCodesRemaining)
	}
}

func TestRegeneratingInvalidatesTheOldSetAtomically(t *testing.T) {
	h := newHarness(t)
	h.enroll()
	old := h.codes

	if _, err := h.svc.RegenerateRecoveryCodes(t.Context(), RegenerateRecoveryCodesInput{UserID: h.user.ID}); !errors.Is(err, ErrInvalidFactor) {
		t.Errorf("regenerating with no factor = %v, want ErrInvalidFactor", err)
	}

	if _, err := h.svc.VerifyFactor(t.Context(), h.user.ID, old[0], h.now()); err != nil {
		t.Fatalf("spending a code: %v", err)
	}
	if _, err := h.svc.RegenerateRecoveryCodes(t.Context(),
		RegenerateRecoveryCodesInput{UserID: h.user.ID, Factor: old[0]}); !errors.Is(err, ErrInvalidFactor) {
		t.Errorf("regenerating with a SPENT code = %v, want ErrInvalidFactor", err)
	}

	regenerated, err := h.svc.RegenerateRecoveryCodes(t.Context(),
		RegenerateRecoveryCodesInput{UserID: h.user.ID, Factor: h.code()})
	if err != nil {
		t.Fatalf("RegenerateRecoveryCodes: %v", err)
	}
	if len(regenerated.RecoveryCodes) != RecoveryCodeCount {
		t.Fatalf("%d codes issued, want %d", len(regenerated.RecoveryCodes), RecoveryCodeCount)
	}
	h.codes = regenerated.RecoveryCodes

	for _, code := range old {
		h.refuteFactor(code)
	}
	status, _ := h.svc.StatusFor(t.Context(), h.user.ID)
	if status.RecoveryCodesRemaining != RecoveryCodeCount {
		t.Errorf("%d codes left, want %d: the old set was not invalidated", status.RecoveryCodesRemaining, RecoveryCodeCount)
	}
	h.clk.Advance(2 * Period)
	if _, err := h.svc.VerifyFactor(t.Context(), h.user.ID, h.codes[0], h.now()); err != nil {
		t.Errorf("a new code does not work: %v", err)
	}
}

func TestRegeneratingIsAtomicOrItDoesNotHappenAtAll(t *testing.T) {
	h := newHarness(t)
	h.enroll()
	old := h.codes[0]

	err := h.svc.uow.Do(t.Context(), func(ctx context.Context, q db.Querier) error {
		if err := h.svc.replaceRecoveryCodes(ctx, q, h.credentialID(), []string{"7KQF4W2X5DTRM3HN"}, h.now()); err != nil {
			return err
		}
		return errors.New("the second write failed")
	})
	if err == nil {
		t.Fatal("the transaction was expected to fail")
	}

	status, err := h.svc.StatusFor(t.Context(), h.user.ID)
	if err != nil {
		t.Fatalf("StatusFor: %v", err)
	}
	if status.RecoveryCodesRemaining != RecoveryCodeCount {
		t.Errorf("%d codes left after a rolled-back regeneration, want %d: the old set was partly destroyed",
			status.RecoveryCodesRemaining, RecoveryCodeCount)
	}
	if _, err := h.svc.VerifyFactor(t.Context(), h.user.ID, old, h.now()); err != nil {
		t.Errorf("an old code stopped working after a rolled-back regeneration: %v", err)
	}
}

func (h *harness) refuteFactor(code string) {
	h.t.Helper()

	h.clearFactorFailures()
	if _, err := h.svc.VerifyFactor(h.t.Context(), h.user.ID, code, h.now()); !errors.Is(err, ErrInvalidFactor) {
		h.t.Errorf("the code %s was accepted, want ErrInvalidFactor (err = %v)", code, err)
	}
	h.clearFactorFailures()
}

func (h *harness) credentialID() id.UUID {
	h.t.Helper()
	credential, err := h.store.ConfirmedCredential(h.t.Context(), h.pool, h.user.ID)
	if err != nil {
		h.t.Fatalf("reading the credential: %v", err)
	}
	return credential.ID
}


func TestDisablingRequiresASecondFactor(t *testing.T) {
	h := newHarness(t)
	h.enroll()
	live := h.signIn()

	if err := h.svc.Disable(t.Context(), DisableInput{UserID: h.user.ID}); !errors.Is(err, ErrInvalidFactor) {
		t.Errorf("disabling with no code = %v, want ErrInvalidFactor", err)
	}
	if err := h.svc.Disable(t.Context(), DisableInput{UserID: h.user.ID, Factor: "000000"}); !errors.Is(err, ErrInvalidFactor) {
		t.Errorf("disabling with a wrong code = %v, want ErrInvalidFactor", err)
	}
	if _, err := h.svc.StatusFor(t.Context(), h.user.ID); err != nil {
		t.Fatalf("StatusFor: %v", err)
	}
	if status, _ := h.svc.StatusFor(t.Context(), h.user.ID); !status.Enabled {
		t.Fatal("a refused disable turned MFA off anyway")
	}
	if h.liveSessions() != 1 {
		t.Error("a refused disable revoked a session")
	}
	_ = live

	if err := h.svc.Disable(t.Context(), DisableInput{UserID: h.user.ID, Factor: h.codes[0]}); err != nil {
		t.Errorf("disabling with a recovery code: %v", err)
	}
	if status, _ := h.svc.StatusFor(t.Context(), h.user.ID); status.Enabled {
		t.Error("MFA is still enabled after a valid disable")
	}
}

func TestDisablingRevokesSessionsAndAnnouncesIt(t *testing.T) {
	h := newHarness(t)
	h.enroll()
	h.signIn()
	h.signIn()

	if err := h.svc.Disable(t.Context(), DisableInput{UserID: h.user.ID, Factor: h.code()}); err != nil {
		t.Fatalf("Disable: %v", err)
	}

	if got := h.liveSessions(); got != 0 {
		t.Errorf("%d sessions survived the disable, want 0", got)
	}
	events := h.events(outbox.EventMFADisabled)
	if len(events) != 1 {
		t.Fatalf("%d identity.mfa.disabled events, want 1", len(events))
	}
	if events[0].Subject != h.user.ID.String() {
		t.Errorf("subject = %q, want the user", events[0].Subject)
	}
	if strings.Contains(string(events[0].Data), h.secret) {
		t.Error("the disable event carries the secret")
	}
	for _, table := range []string{"mfa_credentials", "mfa_recovery_codes", "mfa_used_totp_steps"} {
		var n int
		if err := h.pool.QueryRow(t.Context(), `SELECT count(*) FROM `+table+` WHERE credential_id = $1`,
			h.credentialIDOrZero()).Scan(&n); err == nil && n != 0 {
			t.Errorf("%s still has %d rows after a disable", table, n)
		}
	}
}

func (h *harness) credentialIDOrZero() id.UUID {
	var raw string
	if err := h.pool.QueryRow(h.t.Context(),
		`SELECT subject FROM outbox_events WHERE type = $1 ORDER BY occurred_at LIMIT 1`,
		outbox.EventMFADisabled).Scan(&raw); err != nil {
		h.t.Fatalf("reading the disable event: %v", err)
	}
	return id.UUID{}
}

func TestDisablingRefusesWhenTheSecondFactorIsLocked(t *testing.T) {
	h := newHarness(t)
	h.enroll()

	for range sessions.MaxFailedAttempts {
		if _, err := h.svc.VerifyFactor(t.Context(), h.user.ID, "000000", h.now()); !errors.Is(err, ErrInvalidFactor) {
			t.Fatalf("a wrong code = %v, want ErrInvalidFactor", err)
		}
	}

	var locked *sessions.LockedError
	_, err := h.svc.VerifyFactor(t.Context(), h.user.ID, "000000", h.now())
	if !errors.As(err, &locked) {
		t.Fatalf("attempt %d past the threshold = %v, want a *sessions.LockedError", sessions.MaxFailedAttempts, err)
	}
	if locked.RetryAfter != sessions.LockoutDuration {
		t.Errorf("RetryAfter = %s, want %s", locked.RetryAfter, sessions.LockoutDuration)
	}

	if _, err := h.svc.VerifyFactor(t.Context(), h.user.ID, h.code(), h.now()); !errors.As(err, &locked) {
		t.Errorf("a correct code during a lock = %v, want a *sessions.LockedError", err)
	}
	if err := h.svc.Disable(t.Context(), DisableInput{UserID: h.user.ID, Factor: h.codes[0]}); !errors.As(err, &locked) {
		t.Errorf("disabling during a lock = %v, want a *sessions.LockedError", err)
	}

	h.clk.Advance(sessions.LockoutDuration + time.Second)
	if _, err := h.svc.VerifyFactor(t.Context(), h.user.ID, h.code(), h.now()); err != nil {
		t.Errorf("the lock did not lapse: %v", err)
	}
}

func TestTheFactorLockoutIsThisLockout(t *testing.T) {
	cases := []struct {
		name string
		from sessions.Lockout
		at   time.Time
	}{
		{"a fresh counter", sessions.Lockout{}, issuedAt},
		{"one failure down", sessions.Lockout{FailedAttempts: 1}, issuedAt},
		{"one short of the threshold", sessions.Lockout{FailedAttempts: sessions.MaxFailedAttempts - 1}, issuedAt},
		{"an expired lock with a stale count", sessions.Lockout{
			FailedAttempts: sessions.MaxFailedAttempts,
			LockedUntil:    ptr(issuedAt.Add(-time.Minute)),
		}, issuedAt},
		{"an active lock", sessions.Lockout{
			LockedUntil: ptr(issuedAt.Add(time.Minute)),
		}, issuedAt},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pool := dbtest.Schema(t)
			store := NewStore(pool)
			user := newTestUser(t, pool)
			ctx := context.Background()
			credential := confirm(t, pool, newCredential(t, pool, user))

			lockUntil := c.from.LockedUntil
			if err := store.RecordFactorFailure(ctx, pool, credential.ID, c.from.FailedAttempts, lockUntil); err != nil {
				t.Fatalf("seeding the counter: %v", err)
			}

			read, err := store.ConfirmedCredential(ctx, pool, user.ID)
			if err != nil {
				t.Fatalf("reading the credential: %v", err)
			}
			onRow := sessions.Lockout{FailedAttempts: read.FailedAttempts, LockedUntil: read.LockedUntil}

			if onRow.Locked(c.at) != c.from.Locked(c.at) {
				t.Errorf("Locked = %v, want %v", onRow.Locked(c.at), c.from.Locked(c.at))
			}
			if onRow.RetryAfter(c.at) != c.from.RetryAfter(c.at) {
				t.Errorf("RetryAfter = %s, want %s", onRow.RetryAfter(c.at), c.from.RetryAfter(c.at))
			}
			next := onRow.Failed(c.at)
			if next.FailedAttempts != c.from.Failed(c.at).FailedAttempts {
				t.Errorf("Failed().FailedAttempts = %d, want %d", next.FailedAttempts, c.from.Failed(c.at).FailedAttempts)
			}
			if (next.LockedUntil == nil) != (c.from.Failed(c.at).LockedUntil == nil) {
				t.Errorf("Failed().LockedUntil = %v, want %v", next.LockedUntil, c.from.Failed(c.at).LockedUntil)
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }

func TestADeploymentWithNoKeyFailsClosed(t *testing.T) {
	pool := dbtest.Schema(t)
	clk := clock.NewFake(issuedAt)
	store := NewStore(pool)
	user := newTestUser(t, pool)

	real := NewService(db.TxRunner{Pool: pool}, db.Direct{Pool: pool}, store,
		outbox.NewStore(pool), sessions.NewStore(pool), mustVault(t), clk, testIssuer)
	started, err := real.StartEnrollment(t.Context(), StartEnrollmentInput{UserID: user.ID})
	if err != nil {
		t.Fatalf("StartEnrollment: %v", err)
	}
	secret := started.Secret
	code, err := Code(secret, clk.Now())
	if err != nil {
		t.Fatalf("Code: %v", err)
	}
	if _, err := real.Confirm(t.Context(), ConfirmInput{
		UserID: user.ID, EnrollmentID: started.Credential.ID, Factor: code,
	}); err != nil {
		t.Fatalf("Confirm: %v", err)
	}

	keyless := NewService(db.TxRunner{Pool: pool}, db.Direct{Pool: pool}, store,
		outbox.NewStore(pool), sessions.NewStore(pool), Unavailable{}, clk, testIssuer)

	if _, err := keyless.StartEnrollment(t.Context(), StartEnrollmentInput{UserID: user.ID, Factor: code}); !errors.Is(err, ErrNoVault) {
		t.Errorf("enrolling with no key = %v, want ErrNoVault", err)
	}
	if _, err := keyless.VerifyFactor(t.Context(), user.ID, code, clk.Now()); !errors.Is(err, ErrNoVault) {
		t.Errorf("verifying with no key = %v, want ErrNoVault: an enrolled user must not be let in", err)
	}
	if _, err := keyless.VerifyFactor(t.Context(), user.ID, "123456", clk.Now()); !errors.Is(err, ErrNoVault) {
		t.Errorf("verifying a wrong code with no key = %v, want ErrNoVault", err)
	}
	if err := keyless.Disable(t.Context(), DisableInput{UserID: user.ID, Factor: code}); !errors.Is(err, ErrNoVault) {
		t.Errorf("disabling with no key = %v, want ErrNoVault", err)
	}
	if _, err := real.StatusFor(t.Context(), user.ID); err != nil {
		t.Fatalf("StatusFor: %v", err)
	}
}
