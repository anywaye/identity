package httpapi

import (
	"net/http"
	"regexp"
	"time"

	"github.com/cafaye/identity/internal/platform/id"
)

// POST /v1/session/tokens — the session-to-token exchange.
//
// ## The problem this endpoint was built to solve, stated plainly
//
// Some services scope by ONE account and verify RS256 tokens off this provider's
// JWKS: billing is the first, and its `Processor`-side verifier requires a
// singular `account_id` claim. Identity's profile-scope access tokens carry
// `accounts`, an ARRAY, and the reason is on the record in `internal/oidc/
// profiles.go`: a person is a member of a personal account and usually several
// team accounts, and a token carrying one of them arbitrarily would be wrong for
// all the others. Both sides were self-consistent and incompatible, and the
// consequence — recorded in billing's `REPORT-billing-21-authorization` as a
// DECISION NEEDED — was that a real user's request to `/v1` was answered 401.
//
// The resolution this endpoint implements is the one the record calls the
// smallest that cannot be wrong: the ACCOUNT IS NAMED BY A PARTY THAT IS ALLOWED
// TO NAME IT. A server-side caller (a product's own backend, holding the user's
// session) says which account its user is acting in; identity verifies the
// membership and signs a token that names that one account. Nothing anywhere
// picks `accounts[0]`, nothing guesses "whichever the client meant", and the
// account a request is scoped to is chosen once, explicitly, by the party whose
// user it is.
//
// ## Session-only, and the middleware is the reason
//
// The route is wrapped in `sessionCredentialOnly`, so a scoped api key is
// refused with the 403 the rest of the session surface answers: a credential
// bound to one account minting a token that asserts a HUMAN's identity is a
// machine credential impersonating its owner, which is the privilege escalation
// the credential surface's own comment warns about. A session can mint one
// because a session already IS the human's proof.
//
// ## What the endpoint does not do
//
// It does not read any account-scoped row, refresh, or revoke: the token it
// mints is short-lived by construction (`oidc.AccountTokenTTL`), verifiable
// without calling identity, and dies with the session's own expiry at the
// longest. Revocation is the session's, which the session surface already owns.

// mintSessionTokenRequest is the body of POST /v1/session/tokens.
type mintSessionTokenRequest struct {
	AccountID string `json:"account_id"`
	Audience  string `json:"audience"`
}

// mintedSessionTokenResponse is the answer, and it is 200 rather than 201
// because nothing durable was created: there is no row, so there is no Location
// to point at, and RFC 6749's token endpoint answers 200 for the same reason. A
// 201 would be a promise of a resource that a follow-up GET cannot find.
type mintedSessionTokenResponse struct {
	// Token is the compact JWS, signed with the key the JWKS publishes.
	Token string `json:"token"`
	// ExpiresAt is the token's `exp`, told to the caller so it can schedule the
	// re-mint without parsing what it is about to hand on.
	ExpiresAt time.Time `json:"expires_at"`
}

// The field codes this surface answers with. Two, and not a package-wide
// vocabulary, because these are the only two things that can be wrong with a
// two-field body: something is missing or something is not the shape it claims.
const (
	codeTokenFieldRequired = "required"
	codeTokenFieldInvalid  = "invalid"
)

// sessionTokenAudiencePattern is the shape of an audience this platform's
// services answer to: a service name — `billing`, `darkroom`, `muse` — lowercase,
// starting with a letter, digits and hyphens after. It is a SHAPE and not a
// closed list on purpose: identity does not hold the fleet's service roster, and
// a list here would be a second roster that goes stale the day a service is
// renamed. The receiver is the authority on its own audience — billing pins
// `BILLING_IDENTITY_AUDIENCE` and refuses anything else — which is the same
// division of labour as the `iss` claim.
var sessionTokenAudiencePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

// registerSessionTokenRoutes mounts the exchange.
//
// Mounted by `registerRoutes` only when BOTH a provider (to sign with) and a
// tenancy service (to verify the named account against) exist, which is the rule
// every conditional surface here follows: a deployment that cannot mint answers
// 404, not a 500 on every request.
func (o options) registerSessionTokenRoutes(r chiRouter) {
	r.Post("/v1/session/tokens", o.sessionCredentialOnly(o.handleMintSessionToken))
}

// handleMintSessionToken exchanges the caller's session for one account-scoped
// access token.
//
//	POST /v1/session/tokens  {account_id, audience}  →  200 {token, expires_at}
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
		// A body field that cannot name any account is 422 and not the 404 an
		// unknown-but-well-formed id gets: the difference between "that is not an
		// id" and "that id is not one of yours" is a fact about the request, not
		// about somebody else's rows, and only the second has to be
		// indistinguishable from absence.
		o.refuseSessionTokenField(w, r, "account_id", codeTokenFieldInvalid)
		return
	}

	if !sessionTokenAudiencePattern.MatchString(body.Audience) {
		o.refuseSessionTokenField(w, r, "audience", codeTokenFieldInvalid)
		return
	}

	// The membership check, and the whole of the authorization decision. A
	// non-member and a non-existent account are one answer — the tenancy layer's
	// `ErrNotFound`/`ErrNotAMember` both map to the 404 sentence that says nothing
	// — because the caller must not be able to walk account ids by minting.
	if _, _, err := o.tenancy.Get(r.Context(), accountID, user.ID); err != nil {
		o.writeTenancyError(w, r, err)
		return
	}

	minted, err := o.oidc.MintAccountToken(user.ID, accountID, body.Audience, o.clk.Now())
	if err != nil {
		// The provider was built without a key or the signer refused, both of
		// which are deployment faults no caller can act on.
		unexpected(w, r, o.logger, err)
		return
	}

	writeJSON(w, http.StatusOK, mintedSessionTokenResponse{Token: minted.Token, ExpiresAt: minted.ExpiresAt})
}

// refuseSessionTokenField is one field error in the shape the rest of this
// surface uses: 422, one detail sentence, the field and code named.
func (o options) refuseSessionTokenField(w http.ResponseWriter, r *http.Request, field, code string) {
	writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
		withDetail("the request has an invalid field").
		withFieldErrors([]FieldError{{Field: field, Code: code}}))
}
