package httpapi

import (
	"net/http"
	"regexp"
	"time"

	"github.com/anywaye/identity/internal/platform/id"
)


type mintSessionTokenRequest struct {
	AccountID string `json:"account_id"`
	Audience  string `json:"audience"`
}

type mintedSessionTokenResponse struct {
	Token string `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

const (
	codeTokenFieldRequired = "required"
	codeTokenFieldInvalid  = "invalid"
)

var sessionTokenAudiencePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

func (o options) registerSessionTokenRoutes(r chiRouter) {
	r.Post("/v1/session/tokens", o.sessionCredentialOnly(o.handleMintSessionToken))
}

func (o options) handleMintSessionToken(w http.ResponseWriter, r *http.Request) {
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	var body *mintSessionTokenRequest
	if !decodeBody(w, r, &body) {
		return
	}

	if body.AccountID == "" {
		o.refuseSessionTokenField(w, r, "account_id", codeTokenFieldRequired)
		return
	}
	accountID, err := id.Parse(body.AccountID)
	if err != nil {
		o.refuseSessionTokenField(w, r, "account_id", codeTokenFieldInvalid)
		return
	}

	if !sessionTokenAudiencePattern.MatchString(body.Audience) {
		o.refuseSessionTokenField(w, r, "audience", codeTokenFieldInvalid)
		return
	}

	if _, _, err := o.tenancy.Get(r.Context(), accountID, user.ID); err != nil {
		o.writeTenancyError(w, r, err)
		return
	}

	minted, err := o.oidc.MintAccountToken(user.ID, accountID, body.Audience, o.clk.Now())
	if err != nil {
		unexpected(w, r, o.logger, err)
		return
	}

	writeJSON(w, http.StatusOK, mintedSessionTokenResponse{Token: minted.Token, ExpiresAt: minted.ExpiresAt})
}

func (o options) refuseSessionTokenField(w http.ResponseWriter, r *http.Request, field, code string) {
	writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
		withDetail("the request has an invalid field").
		withFieldErrors([]FieldError{{Field: field, Code: code}}))
}
