package httpapi


import (
	"net/http"
	"time"

	"github.com/anywaye/identity/internal/signup"
)

// Signup is the part of signup.Service the v1 routes need.
//
// Declared here, at the consumer, for the reason Auth and Recovery are: the
// handlers are testable against a programmable double, and this file has no
// dependency on the use cases' internals. Both methods take the instant as a
// parameter rather than reading one, so a test can move time exactly — the
// same seam every other use case in this service reads through.
type Signup interface {
	Mint(now time.Time) signup.Pair
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

func (o options) registerSignupRoutes(r chiRouter) {
	if o.signup == nil {
		return
	}

	r.Post("/v1/signup-timestamp", o.rateLimit("/v1/signup-timestamp", o.handleMintSignupTimestamp))
}


func (o options) handleMintSignupTimestamp(w http.ResponseWriter, r *http.Request) {
	pair := o.signup.Mint(o.clk.Now())
	writeJSON(w, http.StatusOK, pair)
}
