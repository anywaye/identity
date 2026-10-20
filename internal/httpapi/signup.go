package httpapi

// THE SIGNUP TIMESTAMP: THE MINT THE FORM CARRIES, AND THE CHECK THAT READS IT.
//
//	POST /v1/signup-timestamp  →  200 {timestamp, signature}   PUBLIC, unauthenticated
//
// # WHY IDENTITY MINTS AND THE CLIENT CANNOT SIGN
//
// The signed timestamp is the second half of signup bot defense (the honeypot is
// the first — see registerRequest's comment). A bot that leaves the trap empty
// sails through the honeypot; the timestamp is what stops it. The pair is an
// HMAC-SHA256 over the timestamp, keyed with a server secret (SIGNUP_SIGNING_KEY)
// that only identity holds. The client cannot sign anything — identity mints the
// pair and hands it out, and the same secret verifies it on submission. Without
// the secret there is nothing to verify against, and a forged timestamp is
// indistinguishable from a real one; that is why the variable is REQUIRED at
// boot rather than optional like the feature keys. See
// REPORT-identity-spamprotection-01 for the per-secret argument against
// reusing one of the four existing secrets, and internal/config for the boot
// refusal when it is absent.
//
// # THE ENDPOINT IS DELIBERATELY OPEN, AND THAT IS A DECISION WITH A REASON
//
// There is no rate limit here, and the reason is the cost-benefit: a signed
// timestamp costs one HMAC-SHA256 (nanoseconds, no storage, no state), while a
// rate limit costs a dependency this repository does not have and a state
// machine it does not need. The pair is a BEARER CREDENTIAL with a one-hour
// window — a captured pair dies on its own, and a bot that mints a million of
// them has a million credentials that all expire. The protection is the
// signature and the window, not the mint's availability. A future packet that
// adds a rate limit is adding a dependency for a problem the window already
// solves; this one does not.
//
// # THE WIRE SHAPE IS A UNIX INTEGER, AND THAT IS THE SIGNED-VALUE REQUIREMENT
//
// The timestamp is a Unix integer on the wire, not an RFC 3339 string. The
// OpenAPI's existing style renders instants as RFC 3339 (via time.Time), but
// those are UNSIGNED values where any valid rendering is fine. A SIGNED value
// has a stronger requirement: the signature is over the exact bytes of the
// message, so the message must have exactly ONE canonical form. A Unix integer
// has one (the decimal string, and JSON numbers are exact well within int64);
// an RFC 3339 string has several (fractional seconds or not, `Z` or `+00:00`),
// and a client that normalised the rendering would present a different message
// than the one that was signed. The canonical form is the whole of the
// signature's security, so it wins over the style preference.
//
// # CLOCK SKEW IS NOT A QUESTION HERE
//
// Mint and verify run on the SAME server's clock (internal/platform/clock is
// the seam that hands one instant to both). There is no second source of truth
// to consult and no skew to correct: the 2 s floor already covers the instant
// a bot submits, and the 1 h ceiling is measured on the same clock the mint
// used. Inventing a second clock would be inventing a second thing to be wrong.

import (
	"net/http"
	"time"

	"github.com/cafaye/identity/internal/signup"
)

// Signup is the part of signup.Service the v1 routes need.
//
// Declared here, at the consumer, for the reason Auth and Recovery are: the
// handlers are testable against a programmable double, and this file has no
// dependency on the use cases' internals. Both methods take the instant as a
// parameter rather than reading one, so a test can move time exactly — the
// same seam every other use case in this service reads through.
type Signup interface {
	// Mint returns a fresh pair for now.
	Mint(now time.Time) signup.Pair
	// Verify reports whether pair is a pair this key minted, inside the age
	// window, at now. Every rejection is a plain false with no branch naming
	// its cause.
	Verify(pair signup.Pair, now time.Time) bool
}

// WithSignup mounts the signup timestamp surface.
//
// It is an Option for the reason every other service here is one. The signup
// service is built from SIGNUP_SIGNING_KEY, which is REQUIRED at boot — so in
// a running process this is always set and the mint route is always mounted.
// The Option exists so a test can build a router without it, and so the
// registrar's early return is the same fail-closed shape every other surface
// has: a process that cannot mint a timestamp does not serve a route that
// pretends to.
func WithSignup(s Signup) Option {
	return func(o *options) {
		if s != nil {
			o.signup = s
		}
	}
}

// registerSignupRoutes mounts the mint.
//
// IT IS CALLED UNCONDITIONALLY from registerRoutes and it takes NO OPTION,
// which is the point of the whole arrangement: the signup service needs a key
// and nothing else, and a key is the one secret a boot cannot go without. There
// is nothing here that can be configured away, so there is nothing here to be
// conditional about — the route is present with the service and absent without
// it, which is the rule every other surface here follows for the same reason.
func (o options) registerSignupRoutes(r chiRouter) {
	// THE FAIL-CLOSED GUARD, and it is the same shape every other surface here
	// has: no service, no route. A router built without the signup service
	// (every test that is not about the mint) serves no mint route, so the
	// route's presence is a fact about the wiring rather than a constant —
	// which is what lets TestTheClaimWalkSeesNothingWhenTheServicesAreAbsent
	// hold the whole options struct to that property.
	if o.signup == nil {
		return
	}

	// THE MINT. Public and unauthenticated, exactly as POST /v1/users is: the
	// form (rendered by parlor, not by this service — DECISIONS.md D10) asks
	// for a fresh pair before it renders, and a browser arriving at the form
	// holds nothing but the address it was sent to. The pair is the only thing
	// the endpoint hands out, and it is a bearer credential with a one-hour
	// window rather than a secret.
	//
	// Behind the request-rate limiter, like every other unauthenticated route
	// on this surface: the mint costs one HMAC and answers the same to
	// everybody, but a loop that mints in a burst is a burden the launch does
	// not need to carry.
	r.Post("/v1/signup-timestamp", o.rateLimit("/v1/signup-timestamp", o.handleMintSignupTimestamp))
}

// ---------------------------------------------------------------------------
// handlers
// ---------------------------------------------------------------------------

// handleMintSignupTimestamp hands out a fresh pair.
//
//	POST /v1/signup-timestamp  →  200 {timestamp, signature}
//
// The 200 IS signup.Pair ITSELF, rendered as JSON. The same two fields travel
// back on POST /v1/users, and one type for both directions is the whole of
// the point — a minted pair and a presented pair cannot be told apart by
// anything but their values, so there is no "minted" flag for a forger to set
// and no second type to drift from the first.
//
// # IT TAKES NO BODY AND NO CREDENTIAL, AND THAT IS THE CONTRACT
//
// The request carries nothing: no email, no account, no identifier of any kind.
// The response carries nothing but the pair. There is no state to enumerate, no
// row to look up, and no way for the response to differ between two callers —
// which is what makes the endpoint safe to leave open (see the file header's
// rate-limit argument). A deployment that wants to know who minted a pair can
// read the trace id off the span, the same way it reads every other request.
//
// # THE PAIR IS RENDERED ONCE AND IS A BEARER CREDENTIAL
//
// The signature is in this body and nowhere else in this service — not in a
// header, not in a log line, not in a cookie. The client holds it and presents
// it on POST /v1/users, where the same secret verifies it. A client that loses
// it mints another; a deployment that leaks it has leaked a one-hour credential
// for one form submission, which is the whole of the blast radius.
func (o options) handleMintSignupTimestamp(w http.ResponseWriter, r *http.Request) {
	pair := o.signup.Mint(o.clk.Now())
	writeJSON(w, http.StatusOK, pair)
}
