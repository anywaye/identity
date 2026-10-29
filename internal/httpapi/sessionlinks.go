package httpapi


import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/anywaye/identity/internal/apikeys"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/recovery"
	"github.com/anywaye/identity/internal/users"
)

func (o options) registerSessionLinkRoutes(r chiRouter) {
	r.Post("/v1/session-links", o.requireSessionLinkMint(o.handleMintSessionLink))

	r.Post("/v1/session-links/redeem", o.sessionCredentialOnly(o.handleRedeemSessionLink))
}

func (o options) requireSessionLinkMint(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !o.isAPIKeyRequest(r) {
			problemFor(w, r, http.StatusForbidden, CodeForbidden,
				"this route mints a credential for a named subject, which is a delegation and not "+
					"something a person does to themselves. It is reachable by a scoped api key holding "+
					"the "+apikeys.ScopeSessionsWrite+" scope; a browser session may not use it")
			return
		}

		caller, err := o.apiKeyCaller.Authenticate(r.Context(), o.presentedAPIKey(r), o.clk.Now())
		if err != nil || caller.Key.ID.IsZero() {
			unauthorized(w, r)
			return
		}

		if required := scopeRequiredBy(r); !caller.Key.Allows(required) {
			problemFor(w, r, http.StatusForbidden, CodeForbidden,
				"this api key does not carry the "+required+" scope")
			return
		}

		next(w, r)
	}
}


type mintSessionLinkRequest struct {
	UserID string `json:"user_id"`
	Email string `json:"email"`
	Window *int64 `json:"expires_in"`
}

type sessionLinkResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}


func (o options) handleMintSessionLink(w http.ResponseWriter, r *http.Request) {
	var body *mintSessionLinkRequest
	if !decodeBody(w, r, &body) {
		return
	}

	in := recovery.MintSessionLinkInput{}
	if body.Email != "" {
		in.Email = body.Email
	} else {
		userID, err := id.Parse(body.UserID)
		if err != nil || userID.IsZero() {
			writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
				withDetail("user_id must be the id of a user this service has, or email must name one").
				withFieldErrors([]FieldError{{Field: "user_id", Code: "invalid_format"}}))
			return
		}
		in.UserID = userID
	}
	if body.Window != nil {
		in.Window = time.Duration(*body.Window) * time.Second
	}

	link, err := o.recovery.MintSessionLink(r.Context(), in)
	if err != nil {
		o.writeSessionLinkError(w, r, err)
		return
	}

	writeJSON(w, http.StatusCreated, sessionLinkResponse{Token: link.Token, ExpiresAt: link.ExpiresAt})
}


type redeemSessionLinkRequest struct {
	Token string `json:"token"`
}

func (o options) handleRedeemSessionLink(w http.ResponseWriter, r *http.Request) {
	var body *redeemSessionLinkRequest
	if !decodeBody(w, r, &body) {
		return
	}

	if strings.TrimSpace(body.Token) == "" {
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the request has an invalid field").
			withFieldErrors([]FieldError{{Field: "token", Code: "required"}}))
		return
	}

	session, err := o.recovery.RedeemSessionLink(r.Context(), recovery.RedeemSessionLinkInput{
		Token:     body.Token,
		UserAgent: r.UserAgent(),
		IP:        remoteIP(r),
	})
	if err != nil {
		o.writeSessionLinkRedeemError(w, r, err)
		return
	}

	o.setSessionCookie(w, session.Token, session.ExpiresAt)
	writeJSON(w, http.StatusOK, sessionResponse{Token: session.Token, ExpiresAt: session.ExpiresAt})
}

func (o options) writeSessionLinkRedeemError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, recovery.ErrTokenNotFound):
		problemFor(w, r, http.StatusNotFound, CodeNotFound,
			"no such link, or it has already been used")

	case errors.Is(err, recovery.ErrMFAUnavailable):
		problemFor(w, r, http.StatusServiceUnavailable, CodeServiceUnavailable,
			"this deployment cannot say whether an account has a second factor, so it redeems no links")

	default:
		unexpected(w, r, o.logger, err)
	}
}

func (o options) writeSessionLinkError(w http.ResponseWriter, r *http.Request, err error) {
	var fieldErr *users.FieldError

	switch {
	case errors.Is(err, recovery.ErrSubjectNotFound):
		problemFor(w, r, http.StatusNotFound, CodeNotFound,
			"no user with that id exists on this deployment")

	case errors.Is(err, recovery.ErrSubjectDisabled):
		problemFor(w, r, http.StatusForbidden, CodeForbidden,
			"that account is disabled and cannot be given a session")

	case errors.Is(err, recovery.ErrSubjectHasSecondFactor):
		problemFor(w, r, http.StatusConflict, CodeConflict,
			"that account has a second factor, which a session link cannot answer. "+
				"A delegated link is not a way around a second step")

	case errors.Is(err, recovery.ErrMFAUnavailable):
		problemFor(w, r, http.StatusServiceUnavailable, CodeServiceUnavailable,
			"this deployment cannot say whether an account has a second factor, so it mints no links")

	case errors.As(err, &fieldErr):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the request has an invalid field").
			withFieldErrors([]FieldError{{Field: fieldErr.Field, Code: fieldErr.Code}}))

	default:
		unexpected(w, r, o.logger, err)
	}
}

