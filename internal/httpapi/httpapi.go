// Package httpapi wires the identity service's HTTP surface.
//
// The scaffold exposes only the two endpoints every service in the platform
// must have: liveness (/healthz) and readiness (/readyz). Auth routes land in
// later packets.
package httpapi

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/ratelimit"
)

// DefaultReadinessTimeout bounds a single readiness probe so a hung
// dependency cannot pin the orchestrator's health check open.
const DefaultReadinessTimeout = 2 * time.Second

// Check is a named dependency that readiness probes. Name is reported in the
// readiness response so an operator can see what failed.
type Check struct {
	Name string
	Ping func(ctx context.Context) error
}

type options struct {
	logger           *slog.Logger
	readinessTimeout time.Duration
	// clk is the service's clock, and it exists because the HTTP layer has to pass
	// an INSTANT to the stores rather than let them read one.
	//
	// The alternative — time.Now() at the call site — is how a credential ends up
	// judged against a different second than the one its row was written with, and
	// it is untestable: a suite cannot age a token out without sleeping. Every use
	// case in this service reads time through internal/platform/clock, and this is
	// the seam that lets the HTTP layer do the same.
	clk     clock.Clock
	auth    Auth
	tenancy Tenancy
	// deletion ends a person's own account. Absent means the route is not mounted,
	// which is the same rule every other conditional surface here follows: a
	// deployment that cannot delete an account should answer 404 rather than 500,
	// because "this service cannot do that" and "this service is broken" are
	// different facts and only one of them is true.
	//
	// IT IS SEPARATE FROM `auth` BECAUSE IT IS A SEPARATE SERVICE with its own
	// dependencies — the tenancy stores and the credential sweep — and hanging it
	// off the auth routes would mount `DELETE /v1/me` whenever a login is
	// possible, which is every deployment, whether or not those were built.
	deletion Deletion
	// apiKeyCaller resolves a scoped token to its caller. Absent means the account
	// routes are session-only and a token presented to one is refused.
	apiKeyCaller APIKeyCaller
	// introspector serves POST /v1/introspections. Absent means the route is not
	// mounted.
	introspector Introspector
	// apiKeys is the scoped-token surface. It is separate from oidcClients because
	// it is a different credential with a different lifetime and a different
	// storage, and a deployment with one configured and not the other is a real one:
	// a first-party machine credential has no key to sign with.
	apiKeys     APIKeys
	oidc        OIDC
	oidcClients OIDCClients
	// mfa is the MANAGEMENT surface — the routes that read and write a TOTP secret.
	// It needs MFA_ENCRYPTION_KEY and is absent without it.
	//
	// The login's second step is NOT here: it goes through Auth, because
	// auth.Service is where a session is minted. See the note in mfa.go.
	mfa MFAManage
	// admin is the ADMIN surface: revoking invitations and reading the immutable
	// audit trail. It is token-only (see requireAdminToken) and absent without it,
	// like every other optional surface here.
	admin Admin
	// recovery is the ACCOUNT-RECOVERY surface: password reset, address
	// verification and email change. It is absent without a database, like every
	// other surface here, and it is deliberately NOT conditional on a mailer: a
	// deployment that cannot deliver answers 503 on the routes that send one, which
	// is the same shape as the login's second step answering 503 with no MFA key.
	// A 404 here would tell a product this service has never heard of password
	// recovery, and that is the one answer that is both false and useless.
	recovery Recovery
	// signup is the SIGNUP TIMESTAMP surface: the mint the form carries and the
	// check that reads it. It is absent without a key, like every other surface
	// here — but the key is REQUIRED at boot, so a running process always has
	// it and the mint route is always mounted. The Option exists so a test can
	// build a router without it, and so the registrar's early return is the
	// same fail-closed shape every other surface has.
	signup Signup
	// social is the SOCIAL LOGIN surface: the configured OAuth providers and the
	// use case that finishes a round trip. It is absent without a provider, and it
	// is the only surface here whose absence is not a misconfiguration — a
	// deployment that wants password sign-in only configures no provider and never
	// sees these routes. That is the same "absent rather than present-and-500" rule
	// every other optional surface follows, and this one earns it: mounting the
	// routes with no credentials would send people to a provider this process
	// cannot exchange a code with.
	social Social

	// agents is the AGENT surface: the claim route that binds a principal to an
	// account. It is absent without a database, like every other surface here, and
	// it is deliberately NOT conditional on anything else — there is no key and no
	// mailer a claim needs, because the caller delivers the link themselves.
	//
	// It is mounted from registerTenancyRoutes rather than from registerRoutes, for
	// the reason the admin surface is: a claim is an action on an ACCOUNT, so it is
	// account-scoped, so it belongs in the registrar the two route walks read.
	agents Agents

	// rateLimiter bounds what one client address can do on the unauthenticated
	// auth surface. It is wired UNCONDITIONALLY by main from cfg.RateLimit,
	// because the surface it protects is the one a security review looks at
	// first and an unconfigured deployment must not be an unprotected one —
	// the limits have defaults. The Option exists so a test can build a
	// router with a limiter tuned to what it is asserting.
	rateLimiter *ratelimit.Limiter

	// panicOnRoute is a TEST seam: a route pattern that is registered with a
	// handler which panics, so a test can reach the recovery path and the 500 it
	// writes without a database.
	//
	// It replaces a ROUTE and not the router, and that distinction is the whole
	// reason this exists in this shape. The first version of it swapped out the
	// entire mux, which meant the request never passed through chi, never got a
	// route template, and produced a 500 on a span with no route on it — a test
	// asserting a service that is not the one that ships. Replacing one route
	// keeps the span, the template, the recovery and the status exactly as they
	// are in production, and changes only which handler the route points at.
	//
	// Empty in every real process, and it is an empty string rather than a nil
	// handler so the production path has no branch to get wrong.
	panicOnRoute string

	// parameterizedRoute is a second TEST seam, and its reason is the fault
	// injection described on tracedRouter: a suite of fixed requests cannot tell
	// a route template from a concrete path, because for a request with no path
	// parameters the two are the same string. A parameterised pattern is the only
	// request shape on which the distinction is observable at all, and the
	// distinction is the whole of the cardinality guarantee.
	//
	// Empty in every real process.
	parameterizedRoute string
}

// Option customises the handler built by New.
type Option func(*options)

// WithLogger sets the logger used to report probe failures.
func WithLogger(logger *slog.Logger) Option {
	return func(o *options) {
		if logger != nil {
			o.logger = logger
		}
	}
}

// WithReadinessTimeout overrides how long a probe may take before it is
// treated as unavailable.
func WithReadinessTimeout(d time.Duration) Option {
	return func(o *options) {
		if d > 0 {
			o.readinessTimeout = d
		}
	}
}

// WithClock sets the instant the HTTP layer hands to the stores.
//
// It is only interesting to a test, and it is here rather than a package variable
// for the reason every other dependency is: a mutable global clock is a way for
// one test to age another test's credential. The default is the real clock.
func WithClock(c clock.Clock) Option {
	return func(o *options) {
		if c != nil {
			o.clk = c
		}
	}
}

// WithRateLimiter sets the request-rate limiter for the unauthenticated auth
// surface.
//
// main wires it unconditionally from cfg.RateLimit, so a running process
// always has one; the Option exists so a test can build a router with a
// limiter tuned to what it is asserting — a low limit for the red-then-green
// proof, a window the test can advance for the reset.
func WithRateLimiter(l *ratelimit.Limiter) Option {
	return func(o *options) {
		if l != nil {
			o.rateLimiter = l
		}
	}
}

// New builds the service router. With no checks there is nothing to probe, so
// readiness succeeds with "deps":"none" — the shape v0 ships in, before
// DATABASE_URL exists. With no Auth there are no /v1 routes at all, so a process
// without a database still serves its probes and nothing else.
func New(checks []Check, opts ...Option) http.Handler {
	o := options{
		logger:           slog.New(slog.DiscardHandler),
		readinessTimeout: DefaultReadinessTimeout,
		// The real clock, and it is a value rather than a package variable so two
		// servers in one test binary cannot age each other's credentials.
		clk: clock.System{},
	}
	for _, opt := range opts {
		opt(&o)
	}

	// Outermost first, and the order is a dependency chain rather than a
	// preference:
	//
	//	telemetry  the span must exist before anything can record a status on it
	//	trace id   the id must exist before the panic handler can quote it
	//	recovery   inside the trace, so the 500 it writes is on a span
	//
	// Recovery is inside telemetry rather than outside it because a panic
	// recovered above the span would write its 500 with no span carrying the
	// status — a request that failed with nothing in the trace view saying so,
	// which is the one request an operator most wants to find.
	//
	// The test seam sits INSIDE all of them, not outside: a handler that panics
	// must still get a span, a trace id and a recovery, or the observability
	// tests would be asserting about a request that never went through the chain.
	return telemetryMiddleware(traceMiddleware(recoverPanics(o.logger, newMux(checks, o))))
}

// newMux is the router, without the two middlewares, so that a test which has to
// enumerate the routes can walk the tree this assembles rather than a second
// assembly of the same routes written out in a test.
//
// The alternative is a test that calls registerRoutes itself, and that is a
// second list of what a deployed process mounts — the exact thing the tripwire in
// openapi_drift_test.go exists to refuse. This is the whole of the change: the
// wiring below is the wiring that was inline, and New is the only caller.
// routeTable is the pattern list the last-built router recorded, and it is what
// the route-template canary reads.
//
// A package variable rather than a return value because newMux is called by
// New, whose signature is a published contract of this package — the option
// struct, not a route table. It is written by every build and read only by tests,
// and the test that reads it builds its own router, so nothing outside the test
// binary ever observes it.
//
// It exists because of the fault injection described on tracedRouter: with only
// per-request assertions, a service recording the concrete path instead of the
// template passed every observability test. The route table is what makes the
// distinction observable.
//
// IT IS MUTEX-GUARDED, and that is a fix rather than decoration. An unguarded
// package variable written by every router build is a data race the moment two
// tests build routers concurrently, which this package does in dozens of
// `t.Parallel` subtests: `go test -race` reported a WRITE/WRITE on this line from
// two goroutines both in newMux, and the failures were whichever test happened to
// be running — 52 to 64 failing tests on a clean checkout, varying per run. The
// rule that caught it is AGENTS.md's own: no globals, no init-time state. A global
// is not a convenience here; it is the defect.
//
// Readers go through recordedRouteTable, which returns a COPY under the lock. A
// slice returned under a read lock is still a race — the header is copied but the
// backing array is not — and the one caller ranges over it after releasing.
var (
	routeTableMu sync.RWMutex
	routeTable   []string
)

// recordedRouteTable is the pattern list the last-built router recorded.
func recordedRouteTable() []string {
	routeTableMu.RLock()
	defer routeTableMu.RUnlock()
	return append([]string(nil), routeTable...)
}

func newMux(checks []Check, o options) *chi.Mux {
	mux := chi.NewRouter()
	mux.NotFound(notFound)
	mux.MethodNotAllowed(methodNotAllowed)

	// EVERY route goes through tracedRouter, including the two probes. That is the
	// point of the decorator: a route registered directly on the mux would get a
	// span with no route on it, and the probes are exactly the routes an operator
	// filters by when a service looks idle.
	//
	// `r` is the traced view; `mux` is the real router underneath. The two names
	// are here because the authorization-matrix walk in router_walk_test.go needs
	// the undecorated tree to enumerate the routes, and a walk that saw a
	// decorator's wrapper would count a route twice.
	r := &tracedRouter{chiRouter: mux}
	r.Get("/healthz", handleHealthz)
	r.Get("/readyz", o.handleReadyz(checks))
	if o.panicOnRoute != "" {
		// Through `r`, not `mux`, so the test's route is traced like every other.
		// A test-only route that skipped the decorator would make the 500's span
		// look like a production one while missing the route, which is the exact
		// false negative the seam is supposed to avoid.
		r.Get(o.panicOnRoute, func(http.ResponseWriter, *http.Request) {
			panic("the handler panicked")
		})
	}
	if o.parameterizedRoute != "" {
		r.Get(o.parameterizedRoute, func(w http.ResponseWriter, r *http.Request) {
			// A 404 is the honest answer for a route with no service behind it,
			// and it is what the test needs: the span still records the route
			// template, because the template is recorded by the decorator BEFORE
			// the handler runs. That ordering is the point — a service that
			// recorded the route only on a 2xx would lose it on every error, and
			// the errors are the requests an operator is looking at.
			notFound(w, r)
		})
	}
	// The well-known documents are registered before the /v1 and /oidc routes
	// because they are reachable without a session, a database or a signing key
	// being configured, and a process with no DATABASE_URL should still be able
	// to answer a probe for its own metadata.
	o.registerOIDCWellKnownRoutes(r)
	o.registerRoutes(r)
	// The signup timestamp mint, mounted here rather than inside registerRoutes
	// for the reason the probes are: it is a PUBLIC endpoint that needs no
	// database and no session — only the signup service, which is built from a
	// key that is required at boot. registerRoutes returns early when there is
	// no auth service (no DATABASE_URL), and a process with a key but no
	// database would then serve no mint route for a form that cannot exist
	// there anyway. The registrar's own early return is the fail-closed shape:
	// no key, no route.
	o.registerSignupRoutes(r)
	routeTableMu.Lock()
	routeTable = r.patterns
	routeTableMu.Unlock()
	return mux
}

// HealthResponse is the /healthz body. Liveness answers whether this process
// is running, never whether its dependencies are healthy.
type HealthResponse struct {
	Status string `json:"status"`
}

// ReadyResponse is the /readyz body. Deps lists the dependencies that were
// probed ("none" when there are none) and Status is "ok" or "unavailable".
type ReadyResponse struct {
	Status string `json:"status"`
	Deps   string `json:"deps"`
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, HealthResponse{Status: "ok"})
}

func (o options) handleReadyz(checks []Check) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(checks) == 0 {
			writeJSON(w, http.StatusOK, ReadyResponse{Status: "ok", Deps: "none"})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), o.readinessTimeout)
		defer cancel()

		var failed []string
		for _, check := range checks {
			if err := probe(ctx, check); err != nil {
				failed = append(failed, check.Name)
				o.logger.Warn("readiness probe failed", "dep", check.Name, "error", err)
			}
		}

		// The response names the dependencies that were checked; the underlying
		// error stays in the log so nothing internal leaks to anonymous callers.
		deps := joinNames(checks)
		if len(failed) > 0 {
			writeJSON(w, http.StatusServiceUnavailable, ReadyResponse{Status: "unavailable", Deps: deps})
			return
		}
		writeJSON(w, http.StatusOK, ReadyResponse{Status: "ok", Deps: deps})
	}
}

// notFound and methodNotAllowed are problem documents like every other non-2xx
// response, per core's error envelope. A bespoke JSON body here is how a client
// ends up with two error shapes to parse.
func notFound(w http.ResponseWriter, r *http.Request) {
	problemFor(w, r, http.StatusNotFound, CodeNotFound, "no route matches this request")
}

func methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	problemFor(w, r, http.StatusMethodNotAllowed, CodeMethodNotAllowed,
		"this route does not implement the request's method")
}

// probe runs one readiness check. A panicking dependency is a failed probe,
// not a dead process: the net/http recover would otherwise close the
// connection and leave the orchestrator guessing.
func probe(ctx context.Context, check Check) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("probe panicked: %v", r)
		}
	}()

	return check.Ping(ctx)
}

func joinNames(checks []Check) string {
	names := make([]string, 0, len(checks))
	for _, check := range checks {
		names = append(names, check.Name)
	}
	return strings.Join(names, ",")
}
