package httpapi

// THE SESSION LINK: TWO ROUTES, TWO CREDENTIAL KINDS, AND NOTHING BETWEEN THEM.
//
//	POST /v1/session-links          {user_id, expires_in?}  scoped api key, sessions:write
//	POST /v1/session-links/redeem   {token}                   PUBLIC — the link IS the credential
//
// Only the first is mounted by this commit; the second arrives with its own tests
// in the next one, and nothing here describes a route that is not served.
//
// # WHY THE MINT IS A MACHINE CREDENTIAL AND NOT A SESSION
//
// A browser session is a person acting as themselves. A mint asks this service to
// put a credential in front of somebody ELSE's browser, which is a different act
// with a different blast radius: the subject is named in the body and is not
// necessarily the caller. That is the vocabulary's `sessions:write`, and it is the
// first scope in this service whose route turns an opaque value into an
// authenticated browser session — see apikeys' block comment for why the mint route
// refuses a session outright and why the redemption cannot be reached by a token at
// all.
//
// The refusal is 403 and not 401 for the same reason `requireAdminToken` answers
// 403: a session IS authenticated, so a 401 would send a client hunting a login
// problem that does not exist. The middleware runs OUTSIDE the handler chain rather
// than inside it, so "no session may mint" is a property of the surface and not of
// whatever the handler remembered — the reason is on `requireSessionLinkMint`.
//
// THE REDEMPTION IS PUBLIC, AND THAT IS NOT A HOLE
//
// The redemption takes no credential beyond the link itself, exactly as
// `POST /v1/session/mfa` takes a challenge. The link is 256 bits of entropy with a
// ten-minute window and one use, it is delivered by the caller over a channel the
// caller owns, and guessing one is not a search anybody can run. Every refusal it
// can give is the SHAPE of an unknown token, so a stranger holding a dead link
// learns nothing about the account it was for.

import (
	"errors"
	"net/http"
	"time"

	"github.com/cafaye/identity/internal/apikeys"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/recovery"
	"github.com/cafaye/identity/internal/users"
)

// registerSessionLinkRoutes mounts the mint.
//
// THE REDEMPTION IS NOT HERE YET, and the route table is deliberately not extended
// with a placeholder: a route mounted against a use case that does not exist would
// be a 500 in production and a row in four tables claiming a capability this
// deployment cannot serve. It arrives in this packet's next commit, with its own
// tests, and `TestTheCommitWalkSeesTheSessionLinkSurface` is what makes the day it
// lands a day the walks notice.
//
// IT IS CALLED UNCONDITIONALLY from registerRoutes and it takes NO OPTION, which is
// the point of the whole arrangement: both routes need a database and nothing else,
// and a conditional surface is one more field for `options`, one more entry somebody
// must remember to add to `router_walk_test.go`'s list, and one more way for a walk
// of the router to read a smaller service than the one that runs. There is nothing
// here that can be configured away, so there is nothing here to be conditional
// about — the routes are present with a database and absent without one, which is
// the rule every other surface here follows for the same reason.
func (o options) registerSessionLinkRoutes(r chiRouter) {
	// The MINT. Token-only, and the scope check is here rather than in the handler
	// so that a route added next to it inherits it by being wrapped.
	r.Post("/v1/session-links", o.requireSessionLinkMint(o.handleMintSessionLink))
}

// requireSessionLinkMint is the mint's credential gate: a scoped api key holding
// `sessions:write`, and nothing else.
//
// TWO CHECKS IN ONE MIDDLEWARE, and the order is the argument:
//
//  1. IS THIS A TOKEN? A session is refused with 403. This runs FIRST so that a
//     browser session is refused before its scope is consulted — a session carries
//     no scopes at all, so checking them would be reading a field that is empty by
//     construction and answering "this credential lacks sessions:write" for a
//     credential that has no scopes to lack.
//  2. DOES IT HOLD THE SCOPE? 403 again, naming the scope, because the caller is
//     authenticated and the missing thing is authority rather than identity.
//
// IT IS A SEPARATE FUNCTION RATHER THAN A REUSE OF `requireAdminToken` because the
// two surfaces are not the same: the admin surface requires a token AND an account
// role, and this one requires a token AND a scope, with no account anywhere in its
// path. Reusing the admin middleware and bolting a scope check beside it would give
// one function two names and make "which rule protects the mint" a question about
// call order.
//
// IT RUNS OUTSIDE THE HANDLER for the reason on `requireAdminToken`: wrapped inside
// a handler, the property is whatever that handler remembered, and the route added
// next is the one without it.
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
			// An unusable token is the same 401 an unknown credential gets, for the
			// reason every other route in this service answers "who are you" one way.
			unauthorized(w, r)
			return
		}

		// THE SCOPE COMES OUT OF THE TABLE, not out of a constant written here. That is
		// the difference between a declaration and a description: `accountRouteScopes`
		// is walked by `TestEveryScopeIsEnforcedOnItsRoutes` against the vocabulary, so
		// deleting the row fails that test AND closes this route to tokens — the scope
		// gate and the vocabulary are the same fact read twice rather than two facts
		// that can disagree. `Allows("")` is false for every granted set, so a route
		// nobody declared a scope for is closed rather than open.
		if required := scopeRequiredBy(r); !caller.Key.Allows(required) {
			problemFor(w, r, http.StatusForbidden, CodeForbidden,
				"this api key does not carry the "+required+" scope")
			return
		}

		next(w, r)
	}
}

// ---------------------------------------------------------------------------
// request and response shapes
// ---------------------------------------------------------------------------

// mintSessionLinkRequest is the body of POST /v1/session-links.
//
// Window is SECONDS as a number, for the reason `apiKeysRequest.ExpiresIn` is: RFC
// 6749's token response calls this value `expires_in` and a client that has to
// parse a Go duration string to configure a token has been given a decision.
// `expires_in` and a pointer rather than a plain int so that ABSENT and ZERO are
// different answers — absent takes the default window, and zero is a field the
// caller filled in with a number this service refuses. Collapsing them would make
// `{"window": 0}` silently mean "ten minutes".
type mintSessionLinkRequest struct {
	UserID string `json:"user_id"`
	// Window is the requested lifetime in seconds. Absent means
	// recovery.SessionLinkTTL; a value over recovery.MaxSessionLinkTTL is a 422 and
	// never a clamp.
	Window *int64 `json:"expires_in"`
}

// sessionLinkResponse is the 201 from the mint, and it is the same shape the other
// three token routes answer with: the value and the instant it dies.
//
// THE TOKEN IS RENDERED ONCE. It is in this body and nowhere else in this service —
// not in the cookie, not in a header, not in a log line — and the row behind it
// holds only the digest. That is the same contract `POST /v1/password-resets/
// confirm`'s sibling routes and `POST /v1/accounts/:id/invitations` keep, and a
// client that loses it mints another.
type sessionLinkResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ---------------------------------------------------------------------------
// handlers
// ---------------------------------------------------------------------------

// handleMintSessionLink writes one link row for a named subject.
//
//	POST /v1/session-links  {user_id, expires_in?}  →  201 {token, expires_at}
//
// THE SUBJECT IS NAMED BY THE CALLER AND IS NOT THE CALLER, which is the whole
// reason this route needs a machine credential: the caller already holds one, so
// there is nothing here a person's own session could add. The caller's OWN scopes
// do not limit WHICH subject may be named — there is no scope for "mint for your
// own account" and there will not be one, because the authority that matters is the
// grant on the token and a second dimension would be a second decision to make
// twice for the same capability.
func (o options) handleMintSessionLink(w http.ResponseWriter, r *http.Request) {
	var body *mintSessionLinkRequest
	if !decodeBody(w, r, &body) {
		return
	}

	// Parsed here rather than in the use case so a malformed id is a 422 naming a
	// field the caller can point at, rather than a 500 from a parse inside a
	// transaction. The nil uuid is refused for the reason accountIDFrom refuses it:
	// it is a value no row can have, and a store that treated it as a wildcard would
	// mint for an arbitrary subject.
	userID, err := id.Parse(body.UserID)
	if err != nil || userID.IsZero() {
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("user_id must be the id of a user this service has").
			withFieldErrors([]FieldError{{Field: "user_id", Code: "invalid_format"}}))
		return
	}

	in := recovery.MintSessionLinkInput{UserID: userID}
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

// ---------------------------------------------------------------------------
// error mapping
// ---------------------------------------------------------------------------

// writeSessionLinkError maps the mint's refusals onto problem documents.
//
// FIVE ANSWERS, and each is chosen rather than defaulted:
//
//	ErrSubjectNotFound       404  a named user id that is not there. This is the
//	                              ONE place in this service where a subject that
//	                              does not exist gets a status that says so, and it
//	                              is safe HERE ONLY because the route is behind a
//	                              credential holding `sessions:write`: there is no
//	                              anonymous stranger to protect, and a caller asking
//	                              for a user who is not there is entitled to be
//	                              told. The self-service flows answer 202 to an
//	                              unknown address for exactly the opposite reason —
//	                              they have no credential, so "no such account" would
//	                              be a free enumeration oracle. See DECISIONS.md D12.
//	ErrSubjectDisabled       403  the subject has been turned off by a person. Same
//	                              argument as ErrSubjectNotFound and the same
//	                              credential behind it: there is no stranger here,
//	                              so naming the state is free — and a 404 would send
//	                              an operator looking for a user id that is not
//	                              missing. NOT the redemption's answer: on that
//	                              route the token IS the credential, so the caller
//	                              may be whoever took the link. See DECISIONS.md D13.
//	ErrSubjectHasSecond…     409  the subject has a second factor and a link cannot
//	                              answer a challenge. A distinct status and a
//	                              sentence that names the reason, because the caller
//	                              has a real decision to make (do not delegate to
//	                              this account) and a 404 would send them looking for
//	                              a broken subject.
//	ErrMFAUnavailable        503  this deployment cannot say whether anybody has a
//	                              second factor, so it mints nothing. Same shape as
//	                              ErrNoMailer's 503: a deployment problem the caller
//	                              can act on by not depending on this.
//	*users.FieldError        422  the request is not acceptable, per field.
//
// IT IS A SEPARATE FUNCTION RATHER THAN AN ARM IN `writeRecoveryError` for the
// reason `writeAdminError` is separate: the two surfaces answer different questions,
// and adding these arms to the recovery mapper would give the anonymous flows
// mappings for cases they cannot produce.
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

// THE REDEMPTION IS MOUNTED BY `registerSessionLinkRoutes` IN THE NEXT COMMIT, and
// the interface assertion that proves it is here when it lands rather than above.
