package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/mfa"
)

const (
	canarySecret   = "CANARYSECRETCANARYSECRETCANARYSE"
	canaryCode     = "424242"
	canaryRecovery = "CNRY-SCRT-CODE-RTRY"
)

func TestNoSecretReachesTheLogs(t *testing.T) {
	s := newCanaryServer(t)


	secret := canarySecret
	code := canaryCode
	if !mfa.IsRecoveryCode(canaryRecovery) {
		t.Fatalf("the recovery canary %q is not shaped like a recovery code, so the test would pass for the wrong reason", canaryRecovery)
	}
	if len(secret) != 32 {
		t.Fatalf("the secret canary is %d characters, want 32", len(secret))
	}
	if _, err := mfa.Code(secret, s.clock.Now()); err != nil {
		t.Fatalf("the secret canary is not a usable TOTP secret: %v", err)
	}


	created := sendWith(t, s.handler, http.MethodPost, "/v1/mfa/enrollments", s.token, "", `{}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("POST /v1/mfa/enrollments = %d; body: %s", created.Code, created.Body)
	}
	var started struct {
		EnrollmentID    string `json:"enrollment_id"`
		Secret          string `json:"secret"`
		ProvisioningURI string `json:"provisioning_uri"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &started); err != nil {
		t.Fatalf("the enrollment body is not JSON: %v", err)
	}
	if started.Secret == "" || started.ProvisioningURI == "" {
		t.Fatal("the enrollment response carries no secret or URI")
	}
	if !strings.Contains(started.ProvisioningURI, started.Secret) {
		t.Fatalf("the provisioning URI %q does not contain the secret %q, so the URI assertions below prove nothing",
			started.ProvisioningURI, started.Secret)
	}

	serviceSecret, serviceURI := started.Secret, started.ProvisioningURI
	if !strings.HasPrefix(serviceURI, "otpauth://") {
		t.Fatalf("the provisioning URI is %q, want an otpauth:// one", serviceURI)
	}

	realCode := mustTOTPCode(t, serviceSecret, s.clock.Now())
	confirmed := s.post(t, "/v1/mfa/enrollments/"+started.EnrollmentID+"/confirm", s.token,
		`{"code":"`+realCode+`"}`)
	if confirmed.Code != http.StatusOK {
		t.Fatalf("confirm = %d, want 200; body: %s", confirmed.Code, confirmed.Body)
	}
	var confirmedBody confirmedEnrollmentResponse
	if err := json.Unmarshal(confirmed.Body.Bytes(), &confirmedBody); err != nil {
		t.Fatalf("the confirmation body is not JSON: %v", err)
	}
	if len(confirmedBody.RecoveryCodes) == 0 {
		t.Fatal("the confirmation issued no recovery codes, so the recovery paths never ran")
	}
	serviceRecovery := confirmedBody.RecoveryCodes[0]

	challenge := s.challenge(t, s.email)
	finished := s.finish(t, challenge.Challenge, mustTOTPCode(t, serviceSecret, s.clock.Now()))
	if finished.Code != http.StatusOK {
		t.Fatalf("POST /v1/session/mfa = %d, want 200; body: %s", finished.Code, finished.Body)
	}

	challenge = s.challenge(t, s.email)
	spent := s.finish(t, challenge.Challenge, serviceRecovery)
	if spent.Code != http.StatusOK {
		t.Fatalf("spending a recovery code = %d, want 200; body: %s", spent.Code, spent.Body)
	}

	s.challenge(t, s.email)
	wrong := s.finish(t, s.challenge(t, s.email).Challenge, canaryCode)
	if wrong.Code == http.StatusOK {
		t.Fatal("the canary code was accepted as a code, so the flow did not exercise a refusal")
	}

	if _, err := s.owner.Exec(t.Context(), `DROP TABLE mfa_used_totp_steps`); err != nil {
		t.Fatalf("dropping mfa_used_totp_steps: %v", err)
	}
	if rec := s.finish(t, s.challenge(t, s.email).Challenge, mustTOTPCode(t, serviceSecret, s.clock.Now())); rec.Code != http.StatusInternalServerError {
		t.Fatalf("the store failure = %d, want 500; body: %s", rec.Code, rec.Body)
	}


	logs := s.logs.rendered()
	if strings.TrimSpace(logs) == "" {
		t.Fatal("nothing was logged at all, so the absence assertions below would pass vacuously. " +
			"The store failure above is the request that should have logged, so an empty log means the harness is wrong.")
	}


	forbidden := []string{
		serviceSecret,
		serviceURI,
		serviceRecovery,
		strings.ReplaceAll(serviceRecovery, "-", ""),
		strings.ToLower(serviceRecovery),
		canarySecret,
		canaryRecovery,
		code,
		"otpauth://",
		"secret=",
	}

	for _, value := range forbidden {
		if value == "" {
			continue
		}
		if strings.Contains(logs, value) {
			t.Errorf("the rendered logs contain %q, which is a secret or a container for one.\nRendered logs:\n%s", value, logs)
		}
	}

	for _, word := range []string{"secret", "code", "otpauth"} {
		if strings.Contains(strings.ToLower(logs), word) {
			t.Errorf("the rendered logs mention %q, which is the vocabulary of a secret even with no value attached.\nRendered logs:\n%s",
				word, logs)
		}
	}
}

func TestTheCanaryIsNotVacuous(t *testing.T) {
	if len(canarySecret) != 32 {
		t.Errorf("canarySecret is %d characters, want 32", len(canarySecret))
	}
	if _, err := mfa.Code(canarySecret, issuedAtForTest()); err != nil {
		t.Errorf("canarySecret is not usable as a TOTP secret: %v", err)
	}

	if !mfa.IsRecoveryCode(canaryRecovery) {
		t.Errorf("canaryRecovery %q is not a recovery code this service accepts", canaryRecovery)
	}
	if mfa.RecoveryDigest(canaryRecovery) != mfa.RecoveryDigest(strings.ToLower(canaryRecovery)) {
		t.Error("canaryRecovery's digest is not case-stable, so it would not match a log line in either case")
	}

	if len(canaryCode) != 6 {
		t.Errorf("canaryCode is %d characters, want 6", len(canaryCode))
	}
	for _, r := range canaryCode {
		if r < '0' || r > '9' {
			t.Fatalf("canaryCode contains %q, so it is not a six-digit code", r)
		}
	}
}

func issuedAtForTest() time.Time {
	return time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
}
