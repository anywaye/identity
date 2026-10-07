package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/otel/trace"

	"github.com/cafaye/identity/internal/auth"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/signup"
	"github.com/cafaye/identity/internal/telemetry"
	"github.com/cafaye/identity/internal/users"
)

const (
	// SessionCookieName carries the session token to a browser.
	//
	// The __Host- prefix is not decoration. It is a contract the browser
	// enforces: a cookie with this name is accepted only if it is Secure, has
	// Path=/, and carries no Domain attribute. That makes it impossible for a
	// subdomain or a plain-HTTP sibling origin to set or overwrite the session
	// cookie — the two cookie-fixation vectors a `session` cookie leaves open.
	SessionCookieName = "__Host-session"

	// RetryAfterHeader carries the lockout window in seconds, so a client can wait
	// correctly without parsing the problem document.
	RetryAfterHeader = "Retry-After"

	// maxRequestBody caps an accepted request body.
	//
	// A registration is an address (≤320 bytes) and a password (≤1024), so a
	// legitimate body is under 2 KB and 4 KB leaves generous room for encoding
	// overhead. The cap is a DoS control: without it an unauthenticated caller
	// chooses how many bytes this service reads and parses per request, and how
	// much of them reaches the JSON decoder.
	maxRequestBody = 4 << 10
)

// Auth is the part of auth.Service the v1 routes need. It is an interface
// declared here, at the consumer, so the handlers can be tested against a
// programmable double and so the HTTP layer has no dependency on the use cases'
// internals.
type Auth interface {
	Register(ctx context.Context, in auth.RegisterInput) (auth.RegisteredUser, error)
	Login(ctx context.Context, in auth.LoginInput) (auth.LoginResult, error)
	Authenticate(ctx context.Context, token string) (users.User, error)
	Logout(ctx context.Context, token string) error
	// ListSessions and RevokeSession are "sign out of one of these", and they take
	// the CREDENTIAL rather than a user id. That is deliberate and it is the
	// reason they are on this interface: a method whose signature accepts a user id
	// hands every caller the ability to name somebody else's account, and the day
	// one handler reads that id out of a URL instead of out of a session the
	// boundary is a habit. Here the service resolves the caller and asks only about
	// the resolved caller's rows.
	//
	// RevokeSession's ErrSessionNotFound covers "not yours" and "does not exist"
	// together, which is why the two are one method rather than one method plus a
	// lookup.
	ListSessions(ctx context.Context, token string) ([]auth.Session, error)
	RevokeSession(ctx context.Context, token string, sessionID id.UUID) error
	// CompleteSecondFactor is the rest of a login for an account with a second
	// factor, and it is on this interface rather than on a separate one because it
	// IS the rest of Login: the two halves share the session store and the
	// transaction, and splitting them would be an invitation to mint a session in
	// one and not the other.
	CompleteSecondFactor(ctx context.Context, in auth.CompleteSecondFactorInput) (auth.LoginResult, error)

	// Disable and Enable are the operator surface's two use cases, and they are on
	// THIS interface rather than on a new one because they are what auth.Service
	// already has: a disable is not a column write, it is a column write plus the
	// revocation of every session the account holds, in one transaction, and that
	// transaction belongs to the package that owns "which sessions may exist".
	//
	// Their AUTHORIZATION is not here and must not be: it is the route's, because the
	// scope a caller needs is `users:disable` and no account role reaches it. A
	// handler cannot be the only thing standing between a tenant and a colleague in
	// another tenant.
	//
	// BOTH TAKE AN INPUT STRUCT RATHER THAN A USER ID AND A CLOCK, and disabled-04 is
	// why. Each writes a row naming the operator who asked, so the use case has to be
	// TOLD who asked — and `Disable(ctx, userID, at)` had nowhere to put two actor
	// ids and a trace id. Passing them positionally would have put a uuid beside the
	// subject's uuid with nothing in the signature to say which was which, which is
	// the one mistake this signature is now shaped to make impossible: an audit row
	// blaming the subject for their own disable is worse than no row at all.
	Disable(ctx context.Context, in auth.DisableInput) error
	Enable(ctx context.Context, in auth.EnableInput) error

	// UpdateDisplayName is the write half of /v1/me, and it is on this interface
	// for the reason Disable and Enable are: the handler resolves the caller
	// through Authenticate and then writes the one column the profile screen
	// owns, and the use case that owns that write is auth.Service's.
	//
	// name is a POINTER, and nil is the clearing case: an empty display name and
	// no display name are the same state, and the two ways of asking for it —
	// an empty string and an omitted one — both arrive here as nil.
	UpdateDisplayName(ctx context.Context, userID id.UUID, name *string) error

	// UpdateTheme is the write half of /v1/me's second field, and it is on this
	// interface for the reason UpdateDisplayName is.
	//
	// theme is a POINTER, and nil is the clearing case: a cleared theme and a
	// never-set one are the same state (the key is absent from the document),
	// and both an omitted field and an explicit one arrive here as nil — the
	// same pointer's job as the name's, and the same omission semantics.
	UpdateTheme(ctx context.Context, userID id.UUID, theme *string) error
}

// WithAuth mounts the v1 routes.
//
// It is an Option rather than a constructor argument because the probes are the
// service's floor: a process with no DATABASE_URL has no auth service, and that
// process must still answer /healthz. Routes are simply absent when it is not
// given, so a misconfiguration shows up as a 404 rather than as a stack of 500s.
func WithAuth(a Auth) Option {
	return func(o *options) {
		if a != nil {
			o.auth = a
		}
	}
}

// userResponse is the public projection of a user.
//
// It is a dedicated type rather than the domain struct, so a digest cannot reach
// a response body by being added to one. TestRegisterHappyPath asserts the
// rendered shape, which is the check that actually matters.
//
// display_name is omitempty on purpose, and the omission is the backwards-
// compatibility promise: a client written against the two-field response cannot
// tell a user with no name from a user whose name this service has never heard
// of, because the field is simply not there. A null would be a third answer to
// "what is this person called", and the two answers the service has are "this"
// and "nothing".
//
// theme is omitempty for the same reason, and the reasoning is the reference's
// own: the system theme is what a user who never chose one has, so "no theme"
// and "the system theme" are one state with one representation. A null would
// be a second representation of it, and the answers the service has are
// "light", "dark" and "nothing".
type userResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	// DisplayName is present only when the user has one. See above.
	DisplayName *string `json:"display_name,omitempty"`
	// Theme is present only when the user has chosen one. See above.
	Theme *string `json:"theme,omitempty"`
}

// sessionResponse is the API surface of a login.
//
// The token is here as well as in the cookie, deliberately: a cookie is a browser
// mechanism and an API client cannot use one, and core's conventions are explicit
// that "no cookies for API traffic" is a rule about API clients, not a reason for
// the browser surface to exist. They are the same value for the same session.
type sessionResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// challengeResponse is the 202 from POST /v1/session for an account with a second
// factor.
//
// NO `token` FIELD, and that is the point rather than an omission. A client that
// reads `token` finds nothing, and the only way to get one is to present a code.
// The field is not present-and-empty either, because an empty field invites a
// client to treat "the field exists" as "the login is complete".
type challengeResponse struct {
	MFARequired bool      `json:"mfa_required"`
	Challenge   string    `json:"challenge"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// registerRequest is the body of POST /v1/users.
//
// Website is the honeypot field. It is not a field any human fills in: the sign-in
// form (rendered by parlor, not by this service — see DECISIONS.md D10) carries it
// hidden, so a person never sees it and never types into it. A bot fills every field
// it finds, including this one. A populated value therefore means the submission did
// not come from the form, and it is refused before the use case is called — before
// any row exists.
//
// IT IS DELIBERATELY ABSENT FROM THE OPENAPI DOCUMENT. The schema in openapi/v1.yaml
// is the contract for API clients, and a honeypot that is documented is a honeypot
// the next bot skips. The field is accepted here so the form can send it (empty) and
// so a bot's populated value is refused with the same generic 422 a validation
// failure gets, rather than with an "unknown field" that names the trap.
//
// Timestamp and Signature are the signed pair, and they follow the SAME
// discipline: accepted here so the form can send them, absent from the OpenAPI
// document so a bot reading the contract does not learn that the pair is the
// second check. A submission that carries a populated honeypot OR a bad pair is
// refused with the SAME generic 422 — a bot must not learn which check caught
// it, and the two refusals are byte-identical.
type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	// Website is the honeypot. See the type's comment for why it is here and why it
	// is not in the OpenAPI document.
	Website string `json:"website"`
	// Timestamp and Signature are the signed pair the form carries. See the
	// type's comment for why they are here and why they are not in the OpenAPI
	// document.
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
}

// loginRequest is the body of POST /v1/session.
type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// updateMeRequest is the body of PATCH /v1/me.
//
// display_name is a plain string, and an omitted one decodes as the empty
// string — which clears. That is the behaviour the display-name packet shipped
// and the OpenAPI document describes, and it is frozen now: a client written
// against it depends on an omitted name clearing.
//
// theme is a POINTER so an omitted field is distinguishable from a present
// one — and an omitted theme CLEARS, the same semantics display_name has.
// The two fields cannot have two omission rules, and the sibling's rule is the
// frozen one: a caller who reaches PATCH /v1/me is saying "this is my profile
// now", and a field they did not send returns to its zero state. The system
// theme — the reference's theme.blank? — is that zero state, and it is
// reached by omission because an absence, not a value, is what blank means in
// a JSON document.
//
// A present theme validates against the closed set — "light" or "dark" — and
// anything else is the 422 field error writeAuthError and the registration
// surface already produce.
type updateMeRequest struct {
	DisplayName string `json:"display_name"`
	// Theme is a pointer so an omitted field is distinguishable from an empty
	// one. See above.
	Theme *string `json:"theme"`
}

// registerRoutes mounts the v1 surface on r.
func (o options) registerRoutes(r chiRouter) {
	if o.auth == nil {
		return
	}

	// THE TWO UNAUTHENTICATED AUTH ROUTES, each behind the request-rate
	// limiter. The limiter is keyed on the client address and the route
	// pattern, never the account being attempted, so the 429 it answers is
	// identical for every account — existing or not. See ratelimit.go for
	// why the refusal comes AFTER the handler's work.
	r.Post("/v1/users", o.rateLimit("/v1/users", o.handleRegister))
	r.Post("/v1/session", o.rateLimit("/v1/session", o.handleLogin))
	// SESSION-ONLY, and it has to be said out loud rather than left to fall out of
	// the lookup: a token presented here resolves to no session, Logout treats an
	// unknown token as a success because logging out twice is not an error, and the
	// caller is answered 204 — "your session was revoked" — when nothing was. The
	// token still works afterwards, so nothing is compromised; but a client that
	// believed the 204 would think its credential was gone. There is no scope for
	// the session surface at all: a token cannot mint, read or revoke a browser
	// session.
	r.Delete("/v1/session", o.sessionCredentialOnly(o.handleLogout))
	r.Get("/v1/me", o.handleMe)
	// THE WRITE HALF, mounted beside the read and deliberately NOT wrapped in
	// sessionCredentialOnly: the gate is the credential itself, exactly as it is
	// on GET. A scoped api key is not a session, so Authenticate refuses it with
	// the same 401 a never-issued token gets — and that is the honest answer,
	// because a machine credential has no business naming a human and there is
	// no scope that would let one try.
	r.Patch("/v1/me", o.handleUpdateMe)

	// THE LISTING AND THE SINGLE REVOCATION, and the plural is deliberate:
	// `DELETE /v1/session` above is the caller's own current session and takes no
	// id, because the id of the session you are using is the one you already have.
	// These two are the rest of the surface — "which devices am I signed in on"
	// and "end that one" — and they are session-only for the same reason the route
	// above is: a scoped api key cannot enumerate or revoke browser sessions, and
	// `sessionCredentialOnly` is a middleware so the property belongs to the
	// surface rather than to whatever the handlers remembered.
	//
	// They are mounted HERE, on the auth routes, and not under registerTenancyRoutes,
	// which is the whole tenancy registrar. A session belongs to a USER and not to
	// an account: one person is in as many accounts as they like, so there is no
	// account whose tenancy would mean "the sessions this caller may act on". The
	// same argument the operator surface's rows in accountRouteScopes make, and the
	// consequence here is that these two routes are absent from accountRouteScopes
	// deliberately — a row there would be a scope gating nothing, which
	// TestEveryScopeIsEnforcedOnItsRoutes exists to catch. They carry no scope at
	// all, and a scoped token is refused by the middleware above rather than by a
	// scope check.
	r.Get("/v1/sessions", o.sessionCredentialOnly(o.handleListSessions))
	r.Delete("/v1/sessions/{sessionID}", o.sessionCredentialOnly(o.handleRevokeSession))

	// The other half of `/v1/me`, and it is a separate registrar because it is
	// conditional on something the rest of this function is not: the deletion use
	// case. `GET /v1/me` is mounted wherever there is an auth service, which is
	// every deployment forever. This one is mounted where the stores and the
	// credential sweep were built, so a misconfigured deployment answers 404 rather
	// than 500 — the same rule as every other surface on this router.
	//
	// MOUNTED HERE AND NOT IN registerTenancyRoutes because its subject is a person
	// rather than one of their memberships (DECISIONS.md D14), and
	// `TestEveryMountedRouteIsAnAccountRoute` refuses a non-account path in the
	// tenancy registrar for the same reason.
	o.registerDeletionRoute(r)

	// THE SECOND STEP OF A LOGIN, mounted beside the first and deliberately NOT
	// gated on the MFA management routes' condition.
	//
	// A deployment with no MFA_ENCRYPTION_KEY has users who enrolled elsewhere, and
	// those users must reach this route and be refused at their second factor. A 404
	// here would say this service has never heard of MFA, and a client that believed
	// it would be free to treat the absence of a challenge as the absence of a
	// requirement — which is the bypass, expressed as a routing decision.
	// The login's second step is NOT a session surface in the sense above: it takes
	// a challenge token rather than a credential, and a challenge is not a session
	// and cannot be replayed. A scoped token presenting one gets the same 403 as
	// every other non-session credential, because the answer to a challenge is a
	// browser session and a machine holding one has no use for it.
	r.Post("/v1/session/mfa", o.sessionCredentialOnly(o.handleCompleteSecondFactor))

	// The account routes need both services: a session to resolve the caller from
	// and a tenancy service to resolve their role in it. With only one of the two
	// they are not mounted at all, which is the same rule as above — a
	// misconfiguration should be a 404, not a 500 on every request.
	if o.tenancy != nil {
		o.registerTenancyRoutes(r)
	}

	// The MFA management surface needs a key, which is why it is a separate Option
	// from the challenge route above: absent without one, and absent rather than
	// present-and-500.
	o.registerMFARoutes(r)

	// The OIDC protocol surface needs a session to render its login page and a
	// key to sign with. Both are the auth service's, so it hangs off the same
	// condition rather than a second one.
	if o.oidc != nil {
		o.registerOIDCRoutes(r)
	}

	// The introspection surface. Not account-scoped and not conditional on the OIDC
	// provider, because it introspects an OPAQUE first-party credential and has
	// nothing to do with the JWT one: the provider's own introspection is still a
	// refusal, and a deployment with a database and no signing key still answers
	// this one. Absent without WithIntrospection, for the reason every other route
	// is: a misconfiguration is a 404, not a 500.
	o.registerIntrospectionRoute(r)

	// And the recovery surface, for the same reason: it needs a database and no
	// key, and it is the last thing in this registrar because it is the only one
	// whose routes are reachable with no credential at all.
	o.registerRecoveryRoutes(r)

	// And the social-login surface, which is also reachable with no credential and
	// for the same reason: a browser arrives at the callback holding nothing but
	// the state cookie this service set. It is absent unless a provider is
	// configured, which is a NORMAL state here rather than a broken one — this is
	// the one surface a deployment can leave off on purpose.
	o.registerSocialRoutes(r)

	// And the session-link mint: a machine credential holding `sessions:write`
	// mints a single-use token for a named subject, which that subject's browser
	// redeems into a session. It needs the same one thing the recovery surface needs
	// — a database — and it has its own registrar so the surface has a name a reader
	// can go looking for. It is NOT conditional on a mailer and never will be: the
	// caller delivers the link, so a deployment that cannot send email can still mint
	// one, and gating this on a mailer would refuse a capability that does not need
	// it.
	o.registerSessionLinkRoutes(r)

	// And the operator surface: a machine credential holding `users:disable` turns a
	// user's account off, and back on. It hangs off `auth` — the use cases are
	// `auth.Service.Disable` and `.Enable` — so it needs nothing this registrar does
	// not already have, and it has its own registrar for the same reason every other
	// surface does: a name a reader can go looking for.
	o.registerOperatorRoutes(r)
}

// chiRouter is the slice of *chi.Mux these routes need. Naming it keeps the
// option struct from importing chi for one method.
//
// It is an INTERFACE rather than a concrete *chi.Mux for one reason beyond
// tidiness, and the reason is observability: every route registered through it is
// wrapped by `traced`, so a route registered by any of the seven register*
// functions gets its `http.route` recorded without that function having to know
// telemetry exists. A handler list that somebody has to remember to extend is a
// list that will be missed exactly once, and the miss is a span with no route on
// it — invisible in a trace view, wrong in a metric, and green in every test that
// does not walk the routes.
//
// A decorator rather than a chi `Use` middleware, and the reason is measured in
// telemetry.go: chi fills RoutePattern in on the request it routes to, and
// neither an outer middleware nor a `Use` middleware ever sees it. Only the
// matched handler does.
type chiRouter interface {
	Post(pattern string, h http.HandlerFunc)
	Delete(pattern string, h http.HandlerFunc)
	Get(pattern string, h http.HandlerFunc)
	Patch(pattern string, h http.HandlerFunc)
}

// traced wraps a route handler so the span carries the route TEMPLATE.
//
// This is the one place in the service that knows the difference between a route
// and a path, and it is a decorator rather than a middleware for the reason given
// on chiRouter: a pattern has one value per endpoint and a path has one per
// request, and only chi — at the moment it matches — can tell them apart.
func traced(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// ONLY the route. The method is recorded by telemetryMiddleware, outside
		// the router, so that a 404 and a 405 carry it too — those never reach a
		// route handler, and a 404 whose span says nothing about what was asked
		// for is a request an operator cannot search for.
		span := trace.SpanFromContext(r.Context())
		telemetry.Record(span, map[string]any{"http.route": routeTemplate(r)})
		h(w, r)
	}
}

// tracedRouter decorates a chiRouter so every route registered through it is
// wrapped by `traced`.
//
// The decorator is here rather than at each of the seven register* call sites for
// the reason given on chiRouter, and it is a POINTER receiver because of one
// specific thing: a fault injection went the wrong way and the fix belongs here.
//
// Changing `traced` to record `r.URL.Path` instead of the template made every
// observability test in this package PASS, and that is the finding. A test that
// drives a handful of fixed requests cannot tell a template from a path when the
// requests it drives have no path parameters in them: for `GET /healthz` the
// template and the path are the same string. The tests assert the positive case
// (`http.route` == "/healthz") and the negative case (a 404 carries no route),
// and neither can distinguish the two implementations for a request whose path IS
// its template.
//
// So `patterns` records the templates as they are registered, and
// TestTheRouteTableIsWhatTheRouterServes drives a PARAMETERISED template. That
// is the only request shape on which the property is testable at all, and it is
// the shape that actually occurs in production: every one of the routes with a
// `{parameter}` in it is a route whose path and template differ on every request
// but the first.
type tracedRouter struct {
	chiRouter

	// patterns is the route table, in registration order.
	patterns []string
}

func (t *tracedRouter) Get(pattern string, h http.HandlerFunc) {
	t.patterns = append(t.patterns, pattern)
	t.chiRouter.Get(pattern, traced(h))
}

func (t *tracedRouter) Post(pattern string, h http.HandlerFunc) {
	t.patterns = append(t.patterns, pattern)
	t.chiRouter.Post(pattern, traced(h))
}

func (t *tracedRouter) Patch(pattern string, h http.HandlerFunc) {
	t.patterns = append(t.patterns, pattern)
	t.chiRouter.Patch(pattern, traced(h))
}

func (t *tracedRouter) Delete(pattern string, h http.HandlerFunc) {
	t.patterns = append(t.patterns, pattern)
	t.chiRouter.Delete(pattern, traced(h))
}

// handleRegister creates an account.
//
//	POST /v1/users  {email, password}  →  201 {id, email}
func (o options) handleRegister(w http.ResponseWriter, r *http.Request) {
	var body *registerRequest
	if !decodeBody(w, r, &body) {
		return
	}

	// THE HONEYPOT, checked before the use case is called. A bot that gets a row in
	// the database has won, even if the row is later deleted: the address is now
	// taken, and the 409 of DECISIONS.md D9 is a disclosure a stranger can read. So
	// the refusal is here, at the handler, before auth.Register is called — not
	// inside the use case, where a future caller could bypass it.
	//
	// The check is on the raw value, untrimmed. A human who never saw the field
	// sends nothing at all — the form renders it empty and nobody types into a
	// hidden input — so any non-empty value, whitespace included, is a bot. Trimming
	// would let a whitespace-only submission through, and the form sends exactly
	// the empty string, so there is no legitimate value to protect.
	if body.Website != "" {
		// The detail is generic on purpose. Naming the field would tell a bot which
		// one is the trap, and the refusal is indistinguishable from any other
		// validation failure — which is the point.
		problemFor(w, r, http.StatusUnprocessableEntity, CodeValidationFailed,
			"the request has an invalid field")
		return
	}

	// THE SIGNED TIMESTAMP, checked after the honeypot and before the use case is
	// called — for the reason the honeypot is: a bot that gets a row in the
	// database has won. The pair is verified in constant time inside
	// signup.Service (hmac.Equal), the age window is enforced there too, and
	// EVERY rejection is the same generic 422 the honeypot gives — a forged
	// signature, an instant submission, an expired one and a future one are
	// four answers a bot must not be able to tell apart.
	//
	// The check is conditional on the service being wired, which in a running
	// process it always is: SIGNUP_SIGNING_KEY is required at boot, so a process
	// that can serve POST /v1/users can always verify the pair. The condition
	// is the same fail-closed shape every other surface has — a test that
	// builds a router without the signup service gets a register route that
	// does not verify, which is the honest state for "this router was not wired
	// with the key" rather than a silent skip in production.
	if o.signup != nil {
		if !o.signup.Verify(signup.Pair{Timestamp: body.Timestamp, Signature: body.Signature}, o.clk.Now()) {
			problemFor(w, r, http.StatusUnprocessableEntity, CodeValidationFailed,
				"the request has an invalid field")
			return
		}
	}

	created, err := o.auth.Register(r.Context(), auth.RegisterInput{
		Email:    body.Email,
		Password: body.Password,
	})
	if err != nil {
		o.writeAuthError(w, r, err)
		return
	}

	writeJSON(w, http.StatusCreated, userResponse{ID: created.ID.String(), Email: created.Email})
}

// handleLogin authenticates and starts a session, OR hands back a challenge.
//
//	POST /v1/session  {email, password}
//	  →  200 {token, expires_at}                     + the session cookie
//	  →  202 {mfa_required, challenge, expires_at}    + the challenge cookie
//
// TWO RESPONSES FROM ONE ENDPOINT, and the split is the security property.
//
// THE 202 BRANCH MINTS NO SESSION AND SETS NO SESSION COOKIE. The credentials were
// correct and the authentication is not finished, which is what 202 means: the
// request was accepted for processing rather than fulfilled. The cookie that is
// set on this branch is the CHALLENGE cookie, which authenticates nothing — and it
// is set before the body, for the same reason the session cookie is.
//
// The cookie is set at all for an API client as well as a browser, because the
// challenge token is in the body and the API client can carry it in its own
// Authorization header on the next call. The cookie is the browser's convenience;
// it is not the credential's only home, and nothing trusts it in preference to the
// value the use case already checked.
func (o options) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body *loginRequest
	if !decodeBody(w, r, &body) {
		return
	}

	result, err := o.auth.Login(r.Context(), auth.LoginInput{
		Email:     body.Email,
		Password:  body.Password,
		UserAgent: r.UserAgent(),
		IP:        remoteIP(r),
	})
	if err != nil {
		o.writeAuthError(w, r, err)
		return
	}

	if result.MFARequired {
		o.writeChallenge(w, r, result)
		return
	}

	// The cookie is set before the body so that a client which crashes mid-write
	// is still left signed out rather than holding a token it never saw.
	o.setSessionCookie(w, result.Token, result.ExpiresAt)
	writeJSON(w, http.StatusOK, sessionResponse{Token: result.Token, ExpiresAt: result.ExpiresAt})
}

// writeChallenge answers a login that needs a second factor.
//
// It cannot fall through to the session response, and that is why it is a separate
// function rather than an if inside one: there is no field of LoginResult on this
// branch from which a session could be obtained, because LoginResult.Token is the
// empty string here.
func (o options) writeChallenge(w http.ResponseWriter, r *http.Request, result auth.LoginResult) {
	if result.Challenge == nil || result.Challenge.Token == "" {
		// Said out loud rather than rendered as an empty 202. A 202 with no
		// challenge token would leave a client in a state it cannot finish and
		// cannot diagnose, which is the one outcome worse than a 500.
		unexpected(w, r, o.logger, errNoChallengeToken)
		return
	}

	o.setMFAChallengeCookie(w, result.Challenge.Token, result.Challenge.ExpiresAt)
	writeJSON(w, http.StatusAccepted, challengeResponse{
		MFARequired: true,
		Challenge:   result.Challenge.Token,
		ExpiresAt:   result.Challenge.ExpiresAt,
	})
}

// errNoChallengeToken is what writeChallenge reports when the use case says a
// second factor is required and hands back nothing to present one against.
var errNoChallengeToken = errors.New("a login reported that a second factor is required but returned no challenge")

// handleLogout revokes the current session.
//
//	DELETE /v1/session  →  204, cookie cleared
func (o options) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := o.presentedToken(r)
	if token == "" {
		// No credential means no session to revoke. 401 rather than 204: a 204
		// would tell a client its request succeeded when nothing happened.
		unauthorized(w, r)
		return
	}

	if err := o.auth.Logout(r.Context(), token); err != nil {
		// A token that no longer resolves is still cleared client-side. A stale
		// cookie is the common case, and leaving it in place means the user
		// clicks "sign out" again and nothing appears to happen.
		if errors.Is(err, auth.ErrUnauthenticated) {
			o.clearSessionCookie(w)
			unauthorized(w, r)
			return
		}
		unexpected(w, r, o.logger, err)
		return
	}

	o.clearSessionCookie(w)
	noContent(w)
}

// handleMe returns the authenticated user.
//
//	GET /v1/me  →  200 {id, email, display_name?, theme?}
func (o options) handleMe(w http.ResponseWriter, r *http.Request) {
	token := o.presentedToken(r)
	if token == "" {
		unauthorized(w, r)
		return
	}

	user, err := o.auth.Authenticate(r.Context(), token)
	if err != nil {
		if errors.Is(err, auth.ErrUnauthenticated) {
			unauthorized(w, r)
			return
		}
		unexpected(w, r, o.logger, err)
		return
	}

	writeJSON(w, http.StatusOK, userResponse{
		ID:          user.ID.String(),
		Email:       user.Email,
		DisplayName: user.DisplayName,
		Theme:       user.Preferences.Theme,
	})
}

// handleUpdateMe sets the caller's display name and/or theme.
//
//	PATCH /v1/me  {display_name, theme?}  →  200 {id, email, display_name?, theme?}
//
// THE ORDER IS THE SECURITY PROPERTY, and it is the same one handleMe has: the
// credential is resolved BEFORE the body is read, so a stranger never reaches
// the code that writes. A body parsed first and a refusal after it would still
// be a refusal — but the refusal would be reachable by anybody, and the parse
// would be work done for nothing on every anonymous request.
//
// AN OMITTED FIELD CLEARS, for both fields, and that is the route's one
// omission rule: display_name's clear-on-omission is frozen by the display-name
// packet and its OpenAPI document, and the theme adopts it rather than
// inventing a second semantics on the same route. A present theme validates
// against the closed set — "light" or "dark" — and the refusal is the same
// 422 field error display_name's is. The system theme is reached by omission:
// the reference's theme.blank? is an absence, not a value.
//
// THE RULES ARE ENFORCED HERE, in the handler, because this is where a refusal
// is a 422 naming the field rather than a 500 from a database constraint — the
// rules themselves are users.ValidateDisplayName's and users.ValidateTheme's,
// and the handler is where they are applied to a request. The store does not
// re-check them, for the reason every other store method gives: the table's
// surface does not define the rules.
func (o options) handleUpdateMe(w http.ResponseWriter, r *http.Request) {
	token := o.presentedToken(r)
	if token == "" {
		unauthorized(w, r)
		return
	}

	user, err := o.auth.Authenticate(r.Context(), token)
	if err != nil {
		if errors.Is(err, auth.ErrUnauthenticated) {
			unauthorized(w, r)
			return
		}
		unexpected(w, r, o.logger, err)
		return
	}

	var body *updateMeRequest
	if !decodeBody(w, r, &body) {
		return
	}

	name := strings.TrimSpace(body.DisplayName)
	if err := users.ValidateDisplayName(name); err != nil {
		var fe *users.FieldError
		if !errors.As(err, &fe) {
			unexpected(w, r, o.logger, err)
			return
		}
		// A 422 with errors[] is core's shape for "the request was understood and
		// is not acceptable" — the same document writeAuthError writes for a
		// refused registration, so the two surfaces cannot drift apart.
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the request has an invalid field").
			withFieldErrors([]FieldError{{Field: fe.Field, Code: fe.Code}}))
		return
	}

	// nil clears and non-nil sets, which is the whole of the pointer's job —
	// see users.UpdateName for why the two are one state.
	var set *string
	if name != "" {
		set = &name
	}

	// An omitted theme is the clearing case, the same semantics the name has —
	// see updateMeRequest for why the two fields share one omission rule.
	var theme *string
	if body.Theme != nil {
		if err := users.ValidateTheme(*body.Theme); err != nil {
			var fe *users.FieldError
			if !errors.As(err, &fe) {
				unexpected(w, r, o.logger, err)
				return
			}
			// The same 422 shape display_name's refusal gets, for the reason
			// above: one document for "understood and not acceptable", so the
			// two fields on this route cannot drift apart.
			writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
				withDetail("the request has an invalid field").
				withFieldErrors([]FieldError{{Field: fe.Field, Code: fe.Code}}))
			return
		}
		theme = body.Theme
	}

	if err := o.auth.UpdateDisplayName(r.Context(), user.ID, set); err != nil {
		unexpected(w, r, o.logger, err)
		return
	}

	// The theme is written after the name, and always: an omitted theme is a
	// clearing, so there is no case where this route writes one column and not
	// the other.
	if err := o.auth.UpdateTheme(r.Context(), user.ID, theme); err != nil {
		unexpected(w, r, o.logger, err)
		return
	}

	// The response carries the values that were just written rather than the
	// ones the pre-update read had, so a client that rendered from the
	// response cannot be shown a stale value on the request that changed it.
	writeJSON(w, http.StatusOK, userResponse{ID: user.ID.String(), Email: user.Email, DisplayName: set, Theme: theme})
}

// sessionListItem is one entry of GET /v1/sessions.
//
// # NOTHING HERE IS A CREDENTIAL, AND THAT IS THE PROPERTY OF THIS TYPE
//
// There is no `token` field and no field derived from one. The row behind it holds
// a SHA-256 digest, so the list cannot leak the token itself — and the digest is
// NOT rendered either, on the reasoning client/errors.go gives for a different
// table: a value that is one SHA-256 away from a live credential is a credential
// for anybody holding the database, and a response body is a worse place for it
// than a row nobody reads. So the id is here and nothing derived from the
// credential is.
//
// A dedicated type rather than `auth.Session` or `sessions.Session`, for the same
// reason `userResponse` is not `users.User`: a field cannot reach a body by being
// added to a domain struct. Two of the four types above could each gain a field
// that renders a credential, and neither would fail a test.
//
// `current` is the field a client needs and cannot compute: which of these is the
// session this request arrived on. Without it a UI has to compare the browser's
// cookie against a list it cannot see into, which means asking the user which one
// is this one.
type sessionListItem struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	UserAgent string    `json:"user_agent"`
	// IP is a string rather than a nullable struct so the field is absent-by-empty
	// on the wire: a session created through a client that sent no address has no
	// IP, and `null` in a field a UI renders as "last seen from" is a thing every
	// caller has to special-case. Same reasoning as the empty user agent.
	IP      string `json:"ip"`
	Current bool   `json:"current"`
}

// sessionListResponse is the 200 from GET /v1/sessions.
//
// AN OBJECT WITH A NAMED FIELD, NOT A BARE ARRAY. `GET /v1/accounts` answers a bare
// array because it predates this and changing it would break a generated client;
// the difference it buys is the room to add `total` or a cursor later without a
// second breaking change, and a list that is going to grow a `next_cursor` — as
// this one will, once a user has enough devices for the response to be worth
// paging — should not start as the shape that cannot grow.
type sessionListResponse struct {
	Sessions []sessionListItem `json:"sessions"`
}

// handleListSessions returns the caller's live sessions.
//
//	GET /v1/sessions  →  200 {sessions: [{id, created_at, expires_at, user_agent, ip, current}]}
//
// The caller is resolved from the credential and the use case asks about that
// user's rows, so there is no user id anywhere in this handler to get wrong. The
// one thing worth naming is the 401: a dead or unknown token is a 401 and not an
// empty list, because an empty list is a client concluding its session is fine.
func (o options) handleListSessions(w http.ResponseWriter, r *http.Request) {
	token := o.presentedToken(r)
	if token == "" {
		unauthorized(w, r)
		return
	}

	list, err := o.auth.ListSessions(r.Context(), token)
	if err != nil {
		if errors.Is(err, auth.ErrUnauthenticated) {
			unauthorized(w, r)
			return
		}
		unexpected(w, r, o.logger, err)
		return
	}

	// The non-nil slice, so a user with no live sessions gets `[]` and not `null`.
	// It matters more here than on the account list for a reason that is about the
	// question being asked: "where am I signed in" has the ordinary answer "nowhere
	// you are still using", and a client that has to handle null to render it is a
	// client that will eventually render it wrong.
	items := make([]sessionListItem, 0, len(list))
	for _, s := range list {
		items = append(items, sessionListItem{
			ID:        s.ID.String(),
			CreatedAt: s.CreatedAt,
			ExpiresAt: s.ExpiresAt,
			UserAgent: s.UserAgent,
			IP:        ipString(s.IP),
			Current:   s.Current,
		})
	}

	writeJSON(w, http.StatusOK, sessionListResponse{Sessions: items})
}

// ipString renders a recorded address, or "" for a session that never had one.
func ipString(addr *netip.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

// sessionIDParam is the chi URL parameter naming the session being revoked.
//
// A CONSTANT FOR THE REASON keyIDParam IS ONE: the name appears in the route
// pattern and in the handler, and two spellings of it is two chances to read the
// wrong one — which on this route is a handler reading no parameter at all and
// revoking something it chose itself.
const sessionIDParam = "sessionID"

// handleRevokeSession revokes one of the caller's own sessions.
//
//	DELETE /v1/sessions/{sessionID}  →  204
//	                                 404 no such session of yours
//
// # THE 404 IS THE TENANT BOUNDARY
//
// There is no ownership check in this handler and there is deliberately no way to
// add one: the use case resolves the caller from the credential and the DELETE
// carries the owner in its predicate (`Store.RevokeOneForUser`). A handler that
// read the id, asked "is this mine" and then deleted would be the same boundary
// with a window in it.
//
// A session id belonging to somebody else is the SAME 404 as one that does not
// exist, and that is the whole disclosure decision. The caller is authenticated, so
// they cannot use this route to learn about accounts they are not in — but a 403
// against a 404 would let any signed-in user probe whether a given session id is
// live anywhere in this deployment, which is a question about another person's
// credential answered to a stranger.
//
// # A MALFORMED ID IS A 404 AND NOT A 422
//
// On the reasoning accountIDFrom gives: the path is part of a resource's identity,
// so "this is not an id this service issued" has to be the same answer as "this id
// is one this service issued and it is not yours". A 422 would be a distinct,
// observable answer to a probe over the same space of strings.
//
// # NO COOKIE IS CLEARED, EVEN WHEN THE REVOKED SESSION IS THIS ONE
//
// That is the consequence `Service.RevokeSession` documents, and it is stated in
// the response rather than performed here. Clearing the cookie from this handler
// would clear it whenever the id in the path happened to be the caller's current
// session — which the handler cannot know, because `Authenticate` resolves a token
// to a user and does not say which session row it came from. `DELETE /v1/session`
// is the route that clears the cookie, it already does, and a client that wants
// "and sign me out here too" calls it. Guessing wrong in the other direction is
// worse: clearing a browser's cookie for a session the caller did not revoke logs
// them out of the device they are using to end a session on another one.
func (o options) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	token := o.presentedToken(r)
	if token == "" {
		unauthorized(w, r)
		return
	}

	sessionID, ok := sessionIDFrom(r)
	if !ok {
		notFound(w, r)
		return
	}

	if err := o.auth.RevokeSession(r.Context(), token, sessionID); err != nil {
		switch {
		case errors.Is(err, auth.ErrUnauthenticated):
			unauthorized(w, r)
		case errors.Is(err, auth.ErrSessionNotFound):
			notFound(w, r)
		default:
			unexpected(w, r, o.logger, err)
		}
		return
	}

	noContent(w)
}

// sessionIDFrom reads and parses the session id in the path, on the same terms as
// accountIDFrom: a malformed id and the nil uuid are both "not a session of yours".
func sessionIDFrom(r *http.Request) (id.UUID, bool) {
	parsed, err := id.Parse(chi.URLParam(r, sessionIDParam))
	if err != nil || parsed.IsZero() {
		return id.UUID{}, false
	}
	return parsed, true
}

// presentedToken returns the credential the request is making, preferring an
// explicit Authorization header over the cookie.
//
// The preference is not a detail. A client holding both — a browser session plus
// an API token it pasted in — has said which one it means, and answering from the
// cookie would make the result depend on invisible browser state.
func (o options) presentedToken(r *http.Request) string {
	if token := bearerToken(r); token != "" {
		return token
	}
	return cookieToken(r)
}

// bearerToken extracts a token from an Authorization header, or "".
//
// The scheme is compared case-insensitively because RFC 7235 says it is
// case-insensitive, and a client sending "bearer" is not an attacker. Anything
// else — a bare token, a Basic header, an empty bearer — is not a credential this
// service accepts, and treating an unrecognised header as "no credential" keeps
// every malformed case on one path.
func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	const prefix = "Bearer "

	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}

// cookieToken reads the session cookie, or "".
func cookieToken(r *http.Request) string {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// setSessionCookie writes the hardened session cookie.
func (o options) setSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/", // required by the __Host- prefix
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  expiresAt,
	})
}

// clearSessionCookie expires the session cookie.
//
// Every attribute is repeated from the setting cookie. A deletion has to match
// the original on name, domain and path or the browser treats it as a different
// cookie and the stale one survives — the precise bug that makes "sign out" appear
// to do nothing.
func (o options) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

// remoteIP extracts the client address from RemoteAddr, or nil.
//
// It is recorded, never trusted: nothing in this service makes an authorization
// decision on it, and a proxy in front of the service means it is the proxy's
// address anyway. An unparseable value is nil rather than an error, because
// failing a login over a malformed header would be a denial of service anyone
// could trigger.
func remoteIP(r *http.Request) *netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return nil
	}
	return &addr
}

// decodeBody reads a JSON request body into dst, writing a problem and returning
// false if it cannot.
//
// dst must be a pointer to a pointer. That is not a quirk: decoding the literal
// `null` into a struct succeeds and leaves it zeroed, so a body of `null` would
// otherwise be indistinguishable from `{}` and would sail through to the service
// as a request with no email and no password.
//
// Four failure modes are separated, because they mean different things to a
// client and collapsing them produces unhelpful errors:
//
//	too large        413  the caller sent more than this endpoint accepts
//	not JSON         400  malformed syntax, which core scopes to 400
//	not an object    400  syntactically valid JSON of the wrong shape
//	unknown field    422  syntactically fine, semantically not what we accept
func decodeBody[T any](w http.ResponseWriter, r *http.Request, dst **T) bool {
	// Limited at the reader, so an oversized body is refused as it arrives rather
	// than after it has been buffered.
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	decoder := json.NewDecoder(r.Body)
	// An unknown field is a typo, usually. Silently dropping "emial" creates an
	// account with an address the caller did not choose and an error that points
	// at nothing.
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		var syntax *json.SyntaxError
		var unmarshalType *json.UnmarshalTypeError

		switch {
		case bodyTooLarge(err):
			problemFor(w, r, http.StatusRequestEntityTooLarge, CodePayloadTooLarge,
				fmt.Sprintf("the request body is larger than the %d bytes this endpoint accepts", maxRequestBody))
		case errors.As(err, &syntax),
			errors.As(err, &unmarshalType),
			errors.Is(err, io.EOF),
			errors.Is(err, io.ErrUnexpectedEOF):
			// io.ErrUnexpectedEOF is a truncated body, which Decode reports rather
			// than a SyntaxError. Both are malformed syntax, and core reserves 400
			// for exactly this.
			problemFor(w, r, http.StatusBadRequest, CodeInvalidJSON,
				"the request body is not a JSON object this endpoint accepts")
		default:
			// Unknown field, trailing data, and a value of the wrong JSON type all
			// land here: the JSON parsed, and what it says is not acceptable.
			problemFor(w, r, http.StatusUnprocessableEntity, CodeValidationFailed,
				"the request body has a field this endpoint does not accept")
		}
		return false
	}

	// `null` decodes without error and leaves the target nil. It is valid JSON and
	// not a request body, so it is a 400 rather than a validation failure.
	if *dst == nil {
		problemFor(w, r, http.StatusBadRequest, CodeInvalidJSON,
			"the request body must be a JSON object, not null")
		return false
	}

	return true
}

// writeAuthError maps a use-case error onto the response.
//
// The 401 for a refused login is deliberately one fixed sentence. Varying it per
// case is how a login endpoint becomes an account-enumeration oracle.
func (o options) writeAuthError(w http.ResponseWriter, r *http.Request, err error) {
	var locked *auth.LockedError
	var disabled *auth.DisabledError
	var unverified *auth.EmailNotVerifiedError
	var fieldErr *users.FieldError

	switch {
	case errors.As(err, &disabled):
		// 403 forbidden, and the reason this leaks nothing while the 423 below
		// leaks a little: the use case reaches this only AFTER the password has been
		// verified. A caller told their account is disabled has already proved they
		// hold the credential, so they already knew the account existed.
		//
		// 403 rather than 423 because 423 in this service means "locked, retry at",
		// carries a Retry-After, and every client that knows the code renders it as a
		// countdown. This account is not coming back at any time, so a Retry-After
		// would be a promise nothing keeps — and reusing the lockout's status is the
		// conflation migrations/00021's first three lines exist to prevent.
		//
		// `forbidden` rather than a new code: core's reserved list already names
		// this case ("understood the request, refuses to authorize it"), and a code
		// invented for something core describes is a code somebody has to reconcile
		// later. `account_locked` earns its own because 423 is a status core has no
		// name for.
		//
		// The sentence is FIXED. A detail that varied by reason would vary by
		// account state, which is the enumeration oracle this check is positioned to
		// avoid.
		problemFor(w, r, http.StatusForbidden, CodeForbidden,
			"this account is disabled; contact the person or organisation that administers it")

	case errors.As(err, &unverified):
		// 403 forbidden, anchored AFTER the password for the same reason the
		// disabled check above is: the use case reaches this only after the
		// credential has been verified, so a caller told their address is
		// unverified has already proved they hold the credential and already
		// knew the account existed. A refusal placed before the password is a
		// one-request existence oracle for every unverified account on the
		// service.
		//
		// Its own code rather than `forbidden` because the two 403s have
		// different remedies: a disabled account needs an administrator, an
		// unverified one needs the user to click a link. And it deliberately
		// does not share the lockout's 423 or its sentence — see
		// CodeEmailNotVerified and DECISIONS.md D13.
		problemFor(w, r, http.StatusForbidden, CodeEmailNotVerified,
			"this account's email address is not verified; verify it before signing in")

	case errors.As(err, &locked):
		// The window goes in the Retry-After header, which is where RFC 9110 puts
		// it, and in the detail sentence so a human reading the response can act on
		// it.
		//
		// It is deliberately NOT an entry in errors[]: core scopes that array to
		// 422 and describes it as per-field request failures. "retry_after" is not
		// a field of the request, and smuggling it in there would make every
		// client that renders errors[] as a form summary show a field the user
		// never typed.
		seconds := retryAfterSeconds(locked.RetryAfter)
		w.Header().Set(RetryAfterHeader, seconds)
		problemFor(w, r, http.StatusLocked, CodeAccountLocked,
			"too many failed sign-in attempts for this account; retry after "+seconds+" seconds")

	case errors.Is(err, auth.ErrInvalidCredentials), errors.Is(err, auth.ErrUnauthenticated):
		unauthorized(w, r)

	case errors.Is(err, users.ErrEmailTaken):
		problemFor(w, r, http.StatusConflict, CodeConflict,
			"an account already exists for that email address")

	case errors.As(err, &fieldErr):
		// A 422 with errors[] is core's shape for "the request was understood and
		// is not acceptable". Exactly one field failed here, because the handlers
		// stop at the first.
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the request has an invalid field").
			withFieldErrors([]FieldError{{Field: fieldErr.Field, Code: fieldErr.Code}}))

	default:
		unexpected(w, r, o.logger, err)
	}
}

// retryAfterSeconds renders a duration in whole seconds, rounding up and clamping
// at zero.
//
// Rounding up rather than truncating means the client waits at least as long as
// told; truncating would tell it to retry 0.7 seconds early and get another 423,
// which is a loop the client owns and the server caused. RFC 9110 defines
// Retry-After in seconds.
func retryAfterSeconds(d time.Duration) string {
	if d <= 0 {
		return "0"
	}
	seconds := int64(d / time.Second)
	if d%time.Second != 0 {
		seconds++
	}
	return fmt.Sprintf("%d", seconds)
}
