package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/recovery"
	"github.com/anywaye/identity/internal/users"
)


// Recovery is the part of recovery.Service the v1 routes need.
//
// Declared here, at the consumer, for the reason Auth and MFA are: the handlers
// are testable against a programmable double, and this file has no dependency on
// the use cases' internals. Every method takes an id or a clock-free input, so
// there is no way for a handler to reach past an authorization decision into a
// query it wrote itself.
type Recovery interface {
	RequestPasswordReset(ctx context.Context, email string) error
	RedeemPasswordReset(ctx context.Context, in recovery.RedeemPasswordResetInput) (recovery.RedeemPasswordResult, error)
	RequestVerification(ctx context.Context, email string) error
	RedeemVerification(ctx context.Context, in recovery.RedeemVerificationInput) error
	VerificationStatus(ctx context.Context, userID id.UUID) (recovery.Verification, error)
	RequestEmailChange(ctx context.Context, in recovery.RequestEmailChangeInput) (recovery.EmailChange, error)
	ConfirmEmailChangeCurrent(ctx context.Context, in recovery.ConfirmEmailChangeCurrentInput) (recovery.EmailChange, error)
	ConfirmEmailChangeNew(ctx context.Context, in recovery.ConfirmEmailChangeNewInput) (users.User, error)

	MintSessionLink(ctx context.Context, in recovery.MintSessionLinkInput) (recovery.SessionLink, error)

	RedeemSessionLink(ctx context.Context, in recovery.RedeemSessionLinkInput) (recovery.RedeemedSession, error)
}

// WithRecovery mounts the recovery surface.
//
// It is an Option for the reason every other service here is one: with no
// DATABASE_URL there is no recovery_tokens table, and that process must still answer
// /healthz. The routes are absent rather than present-and-500.
//
// IT IS NOT CONDITIONAL ON A MAILER. A deployment that cannot deliver answers 503
// on the routes that need to send one, with a sentence saying why — for the reason
// the login's second step is mounted without MFA_ENCRYPTION_KEY: a 404 here would
// tell a product this service has never heard of password recovery, which is the
// one answer that is both false and useless.
func WithRecovery(r Recovery) Option {
	return func(o *options) {
		if r != nil {
			o.recovery = r
		}
	}
}

func (o options) registerRecoveryRoutes(r chiRouter) {
	if o.recovery == nil {
		return
	}
	r.Post("/v1/password-resets", o.rateLimit("/v1/password-resets", o.sessionCredentialOnly(o.handleRequestPasswordReset)))
	r.Post("/v1/password-resets/confirm", o.sessionCredentialOnly(o.handleRedeemPasswordReset))
	r.Post("/v1/email-verifications", o.rateLimit("/v1/email-verifications", o.sessionCredentialOnly(o.handleRequestVerification)))
	r.Post("/v1/email-verifications/confirm", o.sessionCredentialOnly(o.handleRedeemVerification))
	r.Get("/v1/email-verification", o.sessionCredentialOnly(o.handleVerificationStatus))
	r.Post("/v1/email-changes", o.sessionCredentialOnly(o.handleRequestEmailChange))
	r.Post("/v1/email-changes/current-address", o.sessionCredentialOnly(o.handleConfirmEmailChangeCurrent))
	r.Post("/v1/email-changes/new-address", o.sessionCredentialOnly(o.handleConfirmEmailChangeNew))
}


type acceptedResponse struct {
	Status string `json:"status"`
}

func accepted() acceptedResponse { return acceptedResponse{Status: "accepted"} }

type emailRequest struct {
	Email string `json:"email"`
}

type tokenRequest struct {
	Token string `json:"token"`
}

type passwordResetRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

type verificationStatusResponse struct {
	Email string `json:"email"`
	EmailVerified   bool       `json:"email_verified"`
	EmailVerifiedAt *time.Time `json:"email_verified_at,omitempty"`
}

type emailChangeResponse struct {
	CurrentEmail string    `json:"current_email"`
	NewEmail     string    `json:"new_email"`
	ExpiresAt    time.Time `json:"expires_at"`
	EmailVerified *bool `json:"email_verified,omitempty"`
}


func (o options) handleRequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var body *emailRequest
	if !decodeBody(w, r, &body) {
		return
	}
	if err := o.recovery.RequestPasswordReset(r.Context(), body.Email); err != nil {
		o.writeRecoveryError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, accepted())
}

func (o options) handleRedeemPasswordReset(w http.ResponseWriter, r *http.Request) {
	var body *passwordResetRequest
	if !decodeBody(w, r, &body) {
		return
	}
	if _, err := o.recovery.RedeemPasswordReset(r.Context(), recovery.RedeemPasswordResetInput{
		Token:    body.Token,
		Password: body.Password,
	}); err != nil {
		o.writeRecoveryError(w, r, err)
		return
	}
	o.clearSessionCookie(w)
	noContent(w)
}

func (o options) handleRequestVerification(w http.ResponseWriter, r *http.Request) {
	var body *emailRequest
	if !decodeBody(w, r, &body) {
		return
	}
	if err := o.recovery.RequestVerification(r.Context(), body.Email); err != nil {
		o.writeRecoveryError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, accepted())
}

func (o options) handleRedeemVerification(w http.ResponseWriter, r *http.Request) {
	var body *tokenRequest
	if !decodeBody(w, r, &body) {
		return
	}
	if err := o.recovery.RedeemVerification(r.Context(), recovery.RedeemVerificationInput{
		Token: body.Token,
	}); err != nil {
		o.writeRecoveryError(w, r, err)
		return
	}
	noContent(w)
}

func (o options) handleVerificationStatus(w http.ResponseWriter, r *http.Request) {
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	status, err := o.recovery.VerificationStatus(r.Context(), user.ID)
	if err != nil {
		o.writeRecoveryError(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, verificationStatusResponse{
		Email:           status.Email,
		EmailVerified:   status.Verified,
		EmailVerifiedAt: status.VerifiedAt,
	})
}

func (o options) handleRequestEmailChange(w http.ResponseWriter, r *http.Request) {
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	var body *emailRequest
	if !decodeBody(w, r, &body) {
		return
	}

	change, err := o.recovery.RequestEmailChange(r.Context(), recovery.RequestEmailChangeInput{
		UserID: user.ID,
		Email:  body.Email,
	})
	if err != nil {
		o.writeRecoveryError(w, r, err)
		return
	}

	writeJSON(w, http.StatusCreated, emailChangeResponse{
		CurrentEmail: change.CurrentEmail,
		NewEmail:     change.NewEmail,
		ExpiresAt:    change.ExpiresAt,
	})
}

func (o options) handleConfirmEmailChangeCurrent(w http.ResponseWriter, r *http.Request) {
	var body *tokenRequest
	if !decodeBody(w, r, &body) {
		return
	}
	if _, err := o.recovery.ConfirmEmailChangeCurrent(r.Context(), recovery.ConfirmEmailChangeCurrentInput{
		Token: body.Token,
	}); err != nil {
		o.writeRecoveryError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, accepted())
}

func (o options) handleConfirmEmailChangeNew(w http.ResponseWriter, r *http.Request) {
	var body *tokenRequest
	if !decodeBody(w, r, &body) {
		return
	}

	updated, err := o.recovery.ConfirmEmailChangeNew(r.Context(), recovery.ConfirmEmailChangeNewInput{
		Token: body.Token,
	})
	if err != nil {
		o.writeRecoveryError(w, r, err)
		return
	}

	o.clearSessionCookie(w)

	verified := updated.IsVerified()
	writeJSON(w, http.StatusOK, emailChangeResponse{
		CurrentEmail:  updated.Email,
		NewEmail:      updated.Email,
		EmailVerified: &verified,
	})
}


func (o options) writeRecoveryError(w http.ResponseWriter, r *http.Request, err error) {
	var fieldErr *users.FieldError

	switch {
	case errors.Is(err, recovery.ErrTokenNotFound):
		problemFor(w, r, http.StatusNotFound, CodeNotFound,
			"no such link, or it has already been used")

	case errors.Is(err, recovery.ErrNoMailer):
		problemFor(w, r, http.StatusServiceUnavailable, CodeServiceUnavailable,
			"this deployment cannot send email, so it cannot send that link")

	case errors.Is(err, recovery.ErrEmailTaken):
		problemFor(w, r, http.StatusConflict, CodeConflict,
			"an account already exists for that email address")

	case errors.Is(err, recovery.ErrSameAddress):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("that is already the address on this account").
			withFieldErrors([]FieldError{{Field: "email", Code: "already_current"}}))

	case errors.As(err, &fieldErr):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the request has an invalid field").
			withFieldErrors([]FieldError{{Field: fieldErr.Field, Code: fieldErr.Code}}))

	default:
		unexpected(w, r, o.logger, err)
	}
}

var _ Recovery = (*recovery.Service)(nil)
