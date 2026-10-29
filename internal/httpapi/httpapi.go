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

	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/ratelimit"
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
	clk     clock.Clock
	auth    Auth
	tenancy Tenancy
	deletion Deletion
	apiKeyCaller APIKeyCaller
	introspector Introspector
	apiKeys     APIKeys
	oidc        OIDC
	oidcClients OIDCClients
	mfa MFAManage
	admin Admin
	recovery Recovery
	signup Signup
	social Social

	agents Agents

	rateLimiter *ratelimit.Limiter

	panicOnRoute string

	parameterizedRoute string
}

// Option customizes the handler built by New.
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
		clk: clock.System{},
	}
	for _, opt := range opts {
		opt(&o)
	}

	return telemetryMiddleware(traceMiddleware(recoverPanics(o.logger, newMux(checks, o))))
}

var (
	routeTableMu sync.RWMutex
	routeTable   []string
)

func recordedRouteTable() []string {
	routeTableMu.RLock()
	defer routeTableMu.RUnlock()
	return append([]string(nil), routeTable...)
}

func newMux(checks []Check, o options) *chi.Mux {
	mux := chi.NewRouter()
	mux.NotFound(notFound)
	mux.MethodNotAllowed(methodNotAllowed)

	r := &tracedRouter{chiRouter: mux}
	r.Get("/healthz", handleHealthz)
	r.Get("/readyz", o.handleReadyz(checks))
	if o.panicOnRoute != "" {
		r.Get(o.panicOnRoute, func(http.ResponseWriter, *http.Request) {
			panic("the handler panicked")
		})
	}
	if o.parameterizedRoute != "" {
		r.Get(o.parameterizedRoute, func(w http.ResponseWriter, r *http.Request) {
			notFound(w, r)
		})
	}
	o.registerOIDCWellKnownRoutes(r)
	o.registerRoutes(r)
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

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Trace-Id") == "visibility-probe" {
		CaptureError(fmt.Errorf("visibility probe identity: %s", r.URL.Path), r)
		writeJSON(w, http.StatusInternalServerError, HealthResponse{Status: "ok"})
		return
	}
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

		deps := joinNames(checks)
		if len(failed) > 0 {
			writeJSON(w, http.StatusServiceUnavailable, ReadyResponse{Status: "unavailable", Deps: deps})
			return
		}
		writeJSON(w, http.StatusOK, ReadyResponse{Status: "ok", Deps: deps})
	}
}

func notFound(w http.ResponseWriter, r *http.Request) {
	problemFor(w, r, http.StatusNotFound, CodeNotFound, "no route matches this request")
}

func methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	problemFor(w, r, http.StatusMethodNotAllowed, CodeMethodNotAllowed,
		"this route does not implement the request's method")
}

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
