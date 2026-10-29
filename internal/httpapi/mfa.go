package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/anywaye/identity/internal/auth"
	"github.com/anywaye/identity/internal/mfa"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/sessions"
)


const enrollmentIDParam = "enrollmentID"

// MFA is the second-factor use cases the routes need.
//
// Declared here, at the consumer, for the same reason Auth and Tenancy are: the
// handlers are testable against a double and this file has no dependency on the
// use cases' internals.
//
// The split into two interfaces is not tidiness. MANAGE is the surface that can
// read and write a secret — enrollment, rotation, recovery codes, disabling — and
// it is what a deployment with no MFA_ENCRYPTION_KEY must NOT have, because a user
// must not be talked into enrolling a factor this process could not later verify.
// CHALLENGE is what the login path needs, and it works without a key: mfa.Enabled
// needs no secret, so a keyless process still knows which of its users have a
// second factor and still refuses them rather than waving them through.
type MFA interface {
	StatusFor(ctx context.Context, userID id.UUID) (mfa.Status, error)
}

type MFAManage interface {
	MFA
	StartEnrollment(ctx context.Context, in mfa.StartEnrollmentInput) (mfa.StartedEnrollment, error)
	Confirm(ctx context.Context, in mfa.ConfirmInput) (mfa.ConfirmedEnrollment, error)
	RegenerateRecoveryCodes(ctx context.Context, in mfa.RegenerateRecoveryCodesInput) (mfa.RegeneratedRecoveryCodes, error)
	Disable(ctx context.Context, in mfa.DisableInput) error
}

// WithMFA mounts the second-factor management surface.
//
// It is an Option for the reason WithAuth and WithOIDC are: a process with no
// MFA_ENCRYPTION_KEY has nothing to seal a secret with, and that process must
// still answer /healthz and must still refuse a second-factor login. The routes
// are absent rather than present-and-failing.
func WithMFA(m MFAManage) Option {
	return func(o *options) {
		if m != nil {
			o.mfa = m
		}
	}
}



func (o options) registerMFARoutes(r chiRouter) {
	if o.mfa == nil {
		return
	}
	r.Get("/v1/mfa", o.sessionCredentialOnly(o.handleMFAStatus))
	r.Post("/v1/mfa/enrollments", o.sessionCredentialOnly(o.handleStartEnrollment))
	r.Post("/v1/mfa/enrollments/{enrollmentID}/confirm", o.sessionCredentialOnly(o.handleConfirmEnrollment))
	r.Post("/v1/mfa/recovery-codes", o.sessionCredentialOnly(o.handleRegenerateRecoveryCodes))
	r.Delete("/v1/mfa", o.sessionCredentialOnly(o.handleDisableMFA))
}


type mfaStatusResponse struct {
	Enabled bool `json:"enabled"`
	Method                 string     `json:"method,omitempty"`
	EnrolledAt             *time.Time `json:"enrolled_at,omitempty"`
	RecoveryCodesRemaining *int       `json:"recovery_codes_remaining,omitempty"`
}

type startEnrollmentRequest struct {
	Code string `json:"code,omitempty"`
}

type startedEnrollmentResponse struct {
	EnrollmentID    string    `json:"enrollment_id"`
	Secret          string    `json:"secret"`
	ProvisioningURI string    `json:"provisioning_uri"`
	Method          string    `json:"method"`
	Digits          int       `json:"digits"`
	PeriodSeconds   int       `json:"period_seconds"`
	Algorithm       string    `json:"algorithm"`
	ExpiresAt       time.Time `json:"expires_at"`
	Replaced        bool      `json:"replaced"`
}

type confirmEnrollmentRequest struct {
	Code string `json:"code"`
}

type confirmedEnrollmentResponse struct {
	Enabled                bool      `json:"enabled"`
	Method                 string    `json:"method"`
	EnrolledAt             time.Time `json:"enrolled_at"`
	RecoveryCodes          []string  `json:"recovery_codes"`
	ReplacedExistingSecret bool      `json:"replaced_existing_secret"`
}

type factorRequest struct {
	Code string `json:"code"`
}

type recoveryCodesResponse struct {
	RecoveryCodes          []string  `json:"recovery_codes"`
	IssuedAt               time.Time `json:"issued_at"`
	RecoveryCodesRemaining int       `json:"recovery_codes_remaining"`
}


func (o options) handleMFAStatus(w http.ResponseWriter, r *http.Request) {
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	status, err := o.mfa.StatusFor(r.Context(), user.ID)
	if err != nil {
		unexpected(w, r, o.logger, err)
		return
	}

	response := mfaStatusResponse{Enabled: status.Enabled, Method: status.Method, EnrolledAt: status.EnrolledAt}
	if status.Enabled {
		remaining := status.RecoveryCodesRemaining
		response.RecoveryCodesRemaining = &remaining
	}
	writeJSON(w, http.StatusOK, response)
}

func (o options) handleStartEnrollment(w http.ResponseWriter, r *http.Request) {
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	var body *startEnrollmentRequest
	if !decodeBody(w, r, &body) {
		return
	}

	started, err := o.mfa.StartEnrollment(r.Context(), mfa.StartEnrollmentInput{
		UserID: user.ID,
		Factor: body.Code,
	})
	if err != nil {
		o.writeMFAError(w, r, err)
		return
	}

	writeJSON(w, http.StatusCreated, startedEnrollmentResponse{
		EnrollmentID:    started.Credential.ID.String(),
		Secret:          started.Secret,
		ProvisioningURI: started.ProvisioningURI,
		Method:          started.Credential.Method,
		Digits:          started.Credential.Digits,
		PeriodSeconds:   started.Credential.PeriodSeconds,
		Algorithm:       started.Credential.Algorithm,
		ExpiresAt:       *started.Credential.ExpiresAt,
		Replaced:        started.Replaced,
	})
}

func (o options) handleConfirmEnrollment(w http.ResponseWriter, r *http.Request) {
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	enrollmentID, ok := enrollmentIDFrom(r)
	if !ok {
		notFound(w, r)
		return
	}

	var body *confirmEnrollmentRequest
	if !decodeBody(w, r, &body) {
		return
	}
	if body.Code == "" {
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the request has an invalid field").
			withFieldErrors([]FieldError{{Field: "code", Code: mfa.CodeRequired}}))
		return
	}

	confirmed, err := o.mfa.Confirm(r.Context(), mfa.ConfirmInput{
		UserID:       user.ID,
		EnrollmentID: enrollmentID,
		Factor:       body.Code,
	})
	if err != nil {
		o.writeMFAError(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, confirmedEnrollmentResponse{
		Enabled:                true,
		Method:                 confirmed.Credential.Method,
		EnrolledAt:             *confirmed.Credential.ConfirmedAt,
		RecoveryCodes:          confirmed.RecoveryCodes,
		ReplacedExistingSecret: !confirmed.ReplacedCredentialID.IsZero(),
	})
}

func (o options) handleRegenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	var body *factorRequest
	if !decodeBody(w, r, &body) {
		return
	}

	regenerated, err := o.mfa.RegenerateRecoveryCodes(r.Context(), mfa.RegenerateRecoveryCodesInput{
		UserID: user.ID,
		Factor: body.Code,
	})
	if err != nil {
		o.writeMFAError(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, recoveryCodesResponse{
		RecoveryCodes:          regenerated.RecoveryCodes,
		IssuedAt:               regenerated.IssuedAt,
		RecoveryCodesRemaining: RecoveryCodeCount,
	})
}

func (o options) handleDisableMFA(w http.ResponseWriter, r *http.Request) {
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	var body *factorRequest
	if !decodeBody(w, r, &body) {
		return
	}

	if err := o.mfa.Disable(r.Context(), mfa.DisableInput{UserID: user.ID, Factor: body.Code}); err != nil {
		o.writeMFAError(w, r, err)
		return
	}
	o.clearSessionCookie(w)
	noContent(w)
}

// RecoveryCodeCount mirrors mfa.RecoveryCodeCount for the response body. It is a
// constant rather than a value read back from the service because the count of a
// freshly issued set IS the constant, and a client rendering "you now have N codes"
// wants N rather than a round trip to learn it.
const RecoveryCodeCount = mfa.RecoveryCodeCount

func enrollmentIDFrom(r *http.Request) (id.UUID, bool) {
	parsed, err := id.Parse(chi.URLParam(r, enrollmentIDParam))
	if err != nil || parsed.IsZero() {
		return id.UUID{}, false
	}
	return parsed, true
}


// MFAChallengeCookieName is where the challenge token lives in a browser.
//
// __Host- again, for the reason the session cookie uses it: Secure, Path=/, no
// Domain, so a sibling origin cannot write or overwrite it. A challenge token in a
// cookie an attacker can set is a challenge they can answer.
//
// The request id is NOT in the name, unlike the OIDC login page's state cookie:
// there is one login per browser, not one per product, so there is nothing to
// disambiguate and a per-request name would leave cookies behind.
const MFAChallengeCookieName = "__Host-mfa-challenge"

type completeSecondFactorRequest struct {
	Challenge string `json:"challenge,omitempty"`
	Code      string `json:"code"`
}

func presentedChallenge(r *http.Request, body *completeSecondFactorRequest) string {
	if body != nil && body.Challenge != "" {
		return body.Challenge
	}
	if cookie, err := r.Cookie(MFAChallengeCookieName); err == nil {
		return cookie.Value
	}
	return ""
}

func (o options) handleCompleteSecondFactor(w http.ResponseWriter, r *http.Request) {
	var body *completeSecondFactorRequest
	if !decodeBody(w, r, &body) {
		return
	}

	challenge := presentedChallenge(r, body)
	if challenge == "" {
		unauthorized(w, r)
		return
	}

	result, err := o.auth.CompleteSecondFactor(r.Context(), auth.CompleteSecondFactorInput{
		ChallengeToken: challenge,
		Code:           body.Code,
	})
	if err != nil {
		o.writeMFAError(w, r, err)
		return
	}

	o.clearMFAChallengeCookie(w)
	o.setSessionCookie(w, result.Token, result.ExpiresAt)
	writeJSON(w, http.StatusOK, sessionResponse{Token: result.Token, ExpiresAt: result.ExpiresAt})
}

func (o options) setMFAChallengeCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     MFAChallengeCookieName,
		Value:    token,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  expiresAt,
	})
}

func (o options) clearMFAChallengeCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     MFAChallengeCookieName,
		Value:    "",
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}


func (o options) writeMFAError(w http.ResponseWriter, r *http.Request, err error) {
	var (
		locked   *sessions.LockedError
		fieldErr *mfa.FieldError
	)

	switch {
	case errors.Is(err, sessions.ErrNotFound), errors.Is(err, mfa.ErrEnrollmentNotFound),
		errors.Is(err, mfa.ErrChallengeNotFound):
		problemFor(w, r, http.StatusNotFound, CodeNotFound,
			"no pending multi-factor enrollment or sign-in challenge matches that")

	case errors.Is(err, mfa.ErrNotEnabled):
		problemFor(w, r, http.StatusConflict, CodeConflict,
			"multi-factor authentication is not enabled for this account")

	case errors.Is(err, mfa.ErrInvalidFactor), errors.Is(err, auth.ErrInvalidCredentials),
		errors.Is(err, auth.ErrUnauthenticated):
		unauthorized(w, r)

	case errors.As(err, &locked):
		seconds := retryAfterSeconds(locked.RetryAfter)
		w.Header().Set(RetryAfterHeader, seconds)
		problemFor(w, r, http.StatusLocked, CodeAccountLocked,
			"too many failed second-factor attempts for this account; retry after "+seconds+" seconds")

	case errors.Is(err, mfa.ErrNoVault):
		problemFor(w, r, http.StatusServiceUnavailable, CodeServiceUnavailable,
			"this deployment cannot verify a second factor; MFA_ENCRYPTION_KEY is not configured")

	case errors.As(err, &fieldErr):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the request has an invalid field").
			withFieldErrors([]FieldError{{Field: fieldErr.Field, Code: fieldErr.Code}}))

	default:
		unexpected(w, r, o.logger, err)
	}
}

var (
	_ MFAManage = (*mfa.Service)(nil)
	_ MFA       = (*mfa.Service)(nil)
)

var _ = fmt.Sprintf
