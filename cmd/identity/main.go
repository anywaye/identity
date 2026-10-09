// Command identity runs the cafaye identity service.
//
// main stays thin on purpose: read the configuration, build the app, hand the
// process lifetime to the app. Everything testable lives in the app and in
// internal/.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	// acctboundary is internal/tenancy under a name that does not collide with
	// the `tenancy` local below, which is the accounts SERVICE. The distinction
	// matters to a reader: one is the database boundary, the other is the use
	// cases that sit inside it.
	acctboundary "github.com/cafaye/identity/internal/tenancy"

	"github.com/cafaye/identity/internal/accounts"
	"github.com/cafaye/identity/internal/agents"
	"github.com/cafaye/identity/internal/apikeys"
	"github.com/cafaye/identity/internal/auth"
	"github.com/cafaye/identity/internal/config"
	"github.com/cafaye/identity/internal/courier"
	"github.com/cafaye/identity/internal/deletion"
	"github.com/cafaye/identity/internal/httpapi"
	"github.com/cafaye/identity/internal/mfa"
	"github.com/cafaye/identity/internal/oauth"
	"github.com/cafaye/identity/internal/oidc"
	"github.com/cafaye/identity/internal/outbox"
	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/ratelimit"
	"github.com/cafaye/identity/internal/recovery"
	"github.com/cafaye/identity/internal/sessions"
	"github.com/cafaye/identity/internal/signup"
	"github.com/cafaye/identity/internal/telemetry"
	"github.com/cafaye/identity/internal/useraudit"
	"github.com/cafaye/identity/internal/users"
)

// shutdownTimeout is how long in-flight requests get to finish once a
// termination signal arrives.
const shutdownTimeout = 15 * time.Second

func main() {
	// `-healthcheck` is the container health probe, and it is a flag on this binary
	// rather than a `curl` in the compose file for one reason: the runtime image is
	// `gcr.io/distroless/static-debian12:nonroot`, which has no shell and no HTTP
	// client. The alternatives were a `build:` stanza that adds curl (a supply
	// chain in a security service's image) or no healthcheck at all.
	//
	// It matters more than a dev-loop convenience, because `docker compose up
	// --wait` is only as good as the health signals it waits on, and without this
	// it considers the service up the instant the process starts — which is before
	// the pools are built and long before /readyz would answer 200.
	//
	// It probes /readyz and not /healthz, because readiness is the one that
	// consults the database. A probe that reports healthy against a database that
	// is gone is a probe that reports a working service that answers 503 to
	// everybody.
	if len(os.Args) == 2 && os.Args[1] == "-healthcheck" {
		os.Exit(healthcheck())
	}

	if err := run(); err != nil {
		slog.Error("identity exited with an error", "error", err)
		os.Exit(1)
	}
}

// healthcheckTimeout bounds the probe. Short, because a compose healthcheck that
// takes thirty seconds to fail is a healthcheck whose interval is a lie, and this
// one runs every few seconds for the life of the container.
const healthcheckTimeout = 2 * time.Second

// healthcheck probes this process's own readiness endpoint and reports the result
// as an exit status. 0 healthy, 1 not.
//
// The address comes from PORT rather than being hardcoded, because a container
// started with a different PORT has to be probeable and a probe aimed at 8080
// would report a perfectly healthy service as dead.
func healthcheck() int {
	port := os.Getenv("PORT")
	if port == "" {
		port = config.DefaultPort
	}
	ctx, cancel := context.WithTimeout(context.Background(), healthcheckTimeout)
	defer cancel()

	// The response body is read and discarded rather than the connection simply
	// being closed: closing without draining means the server sees a broken pipe
	// on a request it already answered, which shows up in its own logs as an error
	// every few seconds forever.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+port+"/readyz", nil)
	if err != nil {
		return 1
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func run() error {
	cfg, err := config.Load(os.LookupEnv)
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.SlogLevel()}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Telemetry is installed BEFORE the app, so a span can exist for anything
	// that happens while the pools and the providers are being built — a boot
	// that takes ninety seconds because the database is slow is exactly the boot
	// an operator is watching for, and it is invisible without this.
	shutdownTelemetry, err := installTelemetry(ctx, logger)
	if err != nil {
		return err
	}
	defer func() {
		// A separate context: `ctx` is already cancelled by the time this runs,
		// because a SIGTERM is what usually got us here, and a cancelled context
		// cannot be used to wait for a flush. Bounded by the SDK's own timeout,
		// because a telemetry flush must not be able to hold up a shutdown.
		flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdownTelemetry(flushCtx); err != nil {
			logger.Warn("flushing telemetry on the way out failed", "error", err)
		}
	}()

	a, err := newApp(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer a.Close()

	if err := a.Listen(); err != nil {
		return err
	}

	logger.Info("starting identity", "addr", a.Addr(), "database", cfg.DatabaseURL != "")

	if err := a.Run(ctx); err != nil {
		return err
	}

	logger.Info("identity stopped")
	return nil
}

// installTelemetry starts OpenTelemetry, or stands the no-op up in its place.
//
// ONE LINE, AND ONLY ON THE DISABLED PATH. Silence is the contract there: a
// warning per export attempt fills the service's own log store with the fact that
// telemetry is off, which is how a self-hoster discovers that turning it off is
// not supported — the opposite of the intent. One line at startup is not spam,
// and it is the difference between "telemetry is off" and "telemetry is broken",
// which look identical from outside.
//
// The endpoint is logged WITH ITS QUERY AND FRAGMENT REMOVED. A bring-your-own
// backend puts its API key in the path or the query string, and a startup line
// that quoted the whole thing would write that key into the same log store the
// redaction boundary is trying to keep it out of.
//
// A configured endpoint that cannot be built is a BOOT FAILURE, not a silent
// no-op. "Telemetry is silently absent" and "telemetry is off" look identical
// from outside and only one of them is what anybody meant, so a service that
// starts happily and exports nowhere is the one that gets discovered a quarter
// later.
func installTelemetry(ctx context.Context, logger *slog.Logger) (telemetry.Shutdown, error) {
	lookup := os.Getenv
	shutdown, err := telemetry.Install(ctx, telemetry.Options{
		ServiceName: telemetry.ServiceName,
		Endpoint:    telemetry.Endpoint(lookup),
		Disabled:    !telemetry.Enabled(lookup),
		LookupEnv:   lookup,
	})
	if err != nil {
		return nil, err
	}

	if reason := telemetry.NoOpReason(lookup); reason != "" {
		logger.Info("telemetry is off", "reason", reason)
		return shutdown, nil
	}
	logger.Info("telemetry is on",
		"service", telemetry.ServiceName,
		"endpoint", redactEndpoint(telemetry.Endpoint(lookup)),
	)
	return shutdown, nil
}

// redactEndpoint is a hostname and a port, or nothing else. A bring-your-own
// backend's key lives in the path or the query string, and a self-hoster has to
// be able to confirm which backend their service is pointed at without that key
// landing in a log store.
func redactEndpoint(endpoint string) string {
	if index := strings.IndexAny(endpoint, "?#"); index >= 0 {
		return endpoint[:index]
	}
	return endpoint
}

// app owns the process's HTTP server and, when a database is configured, the
// connection pool behind the readiness probe.
type app struct {
	cfg      config.Config
	logger   *slog.Logger
	pool     *pgxpool.Pool
	srv      *http.Server
	listener net.Listener
	timeout  time.Duration

	// outboxPublisher is the bus connection the publisher loop drains the
	// outbox through, or nil when this deployment has no broker (NATS_URL
	// unset). It is closed on shutdown. The loop itself is tied to the
	// process's context and returns on its cancellation; Close may race the
	// loop's final pass, which is safe because a closed connection fails the
	// publish and the batch is released rather than committed.
	outboxPublisher *outbox.NATSPublisher
}

// newApp wires the service together. With no DATABASE_URL it builds no pool,
// registers no readiness dependency, and mounts no /v1 routes — the v0 default,
// where the process serves its probes and nothing else. With one, it builds the
// pools, the stores and the use cases, and mounts the auth surface.
func newApp(ctx context.Context, cfg config.Config, logger *slog.Logger) (*app, error) {
	var pool *pgxpool.Pool
	checks := make([]httpapi.Check, 0, 1)

	if cfg.DatabaseURL != "" {
		p, err := db.Open(ctx, cfg.DatabaseURL, db.DefaultOptions())
		if err != nil {
			return nil, fmt.Errorf("opening database pool: %w", err)
		}
		pool = p
		checks = append(checks, httpapi.Check{Name: db.CheckName, Ping: pool.Ping})
	}

	opts := []httpapi.Option{httpapi.WithLogger(logger)}

	// THE SIGNUP TIMESTAMP SURFACE, and it is the one option here that is
	// UNCONDITIONAL: it needs no database, no pool and no feature flag, only the
	// key — and the key is the one secret a boot cannot go without, so a process
	// that can serve anything can mint a pair. It is mounted beside
	// registerRoutes in newMux for the same reason the probes are: a deployment
	// with no DATABASE_URL has no signup form to defend, but the mint costs one
	// HMAC, answers the same to everybody, and a pair from it is a credential
	// this deployment's POST /v1/users would refuse anyway (it is not mounted
	// there). The verify on POST /v1/users is wired by the same option: a
	// process that can register can verify, because both need nothing but this
	// key.
	opts = append(opts, httpapi.WithSignup(signup.New(cfg.SignupSigningKeyValue)))

	// THE REQUEST-RATE LIMITER for the unauthenticated auth surface, wired
	// UNCONDITIONALLY. It is not a feature block in the sense OIDC, MFA,
	// courier and OAuth are: those are absent when unconfigured, because they
	// belong to features a deployment may not have turned on. This one is
	// present by default, because the surface it protects is the one a
	// customer's security review looks at first and an unconfigured
	// deployment must not be an unprotected one — every limit has a default
	// (internal/config). The key is the client address and the route
	// pattern, never the account being attempted, so the 429 is identical
	// for every account.
	//
	// The store is in-process for launch: one replica is what the launch
	// has, and an in-process counter has no fail-open question. What a
	// shared store would need later is recorded in the packet report, not
	// built now.
	opts = append(opts, httpapi.WithRateLimiter(ratelimit.New(clock.System{}, map[string]ratelimit.Limit{
		"/v1/users":               {Max: cfg.RateLimit.Signup, Window: cfg.RateLimit.Window},
		"/v1/session":             {Max: cfg.RateLimit.Signin, Window: cfg.RateLimit.Window},
		"/v1/signup-timestamp":    {Max: cfg.RateLimit.SignupTimestamp, Window: cfg.RateLimit.Window},
		"/v1/password-resets":     {Max: cfg.RateLimit.Recovery, Window: cfg.RateLimit.Window},
		"/v1/email-verifications": {Max: cfg.RateLimit.Recovery, Window: cfg.RateLimit.Window},
	})))

	// ONE HASHER FOR THE WHOLE PROCESS, and it is built here rather than inside
	// buildAuth because two surfaces need one: a password reset hashes a new
	// password through the same code a registration does, and the constructor
	// derives an argon2id digest for the login's timing equaliser — so a second
	// Hasher would derive a second dummy digest and cost a hundred milliseconds of
	// memory-hard work at boot for nothing.
	hasher := users.NewHasher()

	// One outbox store for the whole process: the use cases below write events
	// through it inside their transactions, and the publisher loop newApp
	// starts drains the same table through it. It is created here rather than
	// inside buildAuth so the loop and the writers share one object — two stores
	// over one table would be two things to keep configured identically, and
	// the loop is the one consumer that has to see every row the writers commit.
	var events *outbox.Store
	if pool != nil {
		events = outbox.NewStore(pool)
	}

	authSvc, tenancy, secondFactor, deletionSvc, mfaUsable, err := buildAuth(cfg, pool, hasher, logger, events)
	if err != nil {
		return nil, err
	}
	if authSvc != nil {
		machineCredentials, err := buildAPIKeys(cfg, pool, tenancy, logger, events)
		if err != nil {
			return nil, err
		}

		opts = append(opts,
			httpapi.WithAuth(authSvc),
			httpapi.WithTenancy(tenancy),
			httpapi.WithDeletion(deletionSvc),
			// The agent surface. It needs a database and nothing else, and it is
			// mounted here rather than gated on any key or mailer for the reason
			// the recovery surface is: a claim is a capability this service has,
			// and a 404 on it would tell a product identity has never heard of
			// agents. The caller delivers the claim link themselves, so there is
			// no mailer to be unavailable.
			httpapi.WithAgents(agents.NewService(pool)),
			// The login's second step rides on WithAuth, because auth.Service is what
			// mints the session behind it. Only the MANAGEMENT routes are conditional,
			// and only on a usable key: such a process must not be able to enroll a
			// factor it could never verify, while still refusing the users who enrolled
			// elsewhere. Mounting both, or neither, is a bypass in one direction or
			// the other.
		)
		if mfaUsable {
			opts = append(opts, httpapi.WithMFA(secondFactor))
		}
		// The recovery surface. It is mounted unconditionally inside this branch —
		// not gated on a mailer — because a 404 on /v1/password-resets would tell a
		// product this service has never heard of password recovery, which is both
		// false and useless. A deployment that cannot send a message answers 503 on
		// the routes that need one, with a sentence saying so.
		recoverySvc, err := buildRecovery(cfg, pool, hasher, secondFactor, logger, events)
		if err != nil {
			return nil, err
		}
		if recoverySvc != nil {
			opts = append(opts, httpapi.WithRecovery(recoverySvc))
		}
		// The social-login surface, and this is the ONLY call site WithSocial has ever
		// had. Its absence is why the surface was unreachable on master: the two
		// routes were written, registerSocialRoutes was called from registerRoutes,
		// and `options.social` was nil in every process, so the registrar returned
		// before registering anything and a deployment with OAUTH_* configured served
		// a 404 for a feature it had been given credentials for.
		//
		// IT IS INSIDE THIS BRANCH rather than beside it because a social sign-in
		// creates a user row, provisions a personal account and mints a session — all
		// through auth.Service. A process with no DATABASE_URL has none of that, and a
		// mounted start route there would send a browser to a provider and answer 404
		// on the way back. registerRoutes gates the same way, at auth.go:125, so the
		// absence and the gate agree.
		//
		// `social == nil` IS THE NORMAL CASE and is not an error: every OAUTH_* variable
		// is optional and an untouched deployment arrives here with none of them set.
		// That is the state this service ships in, and the absence of these two routes
		// is the documented shape of it — a clean 404 rather than a redirect to a
		// provider the deployment cannot authenticate with.
		social, err := buildSocial(cfg, pool, authSvc, logger)
		if err != nil {
			return nil, err
		}
		if social != nil {
			opts = append(opts, httpapi.WithSocial(social))
		}
		if machineCredentials != nil {
			// Four options from one service, and each is a different capability rather
			// than a different spelling of the same one: the management surface
			// (mint/list/revoke), resolving a presented token to its caller so the
			// account routes accept one, and the introspection surface a resource
			// server asks because the token is opaque and carries no claims of its
			// own. WithAPIKeyCaller is what makes the scope gate reachable at all —
			// without it every account route is session-only.
			opts = append(opts,
				httpapi.WithAPIKeys(machineCredentials),
				httpapi.WithAPIKeyCaller(machineCredentials),
				httpapi.WithIntrospection(machineCredentials),
			)
		}
	} else {
		// Said out loud, because a process serving probes and no auth surface is a
		// valid configuration and a surprising one.
		logger.Warn("no DATABASE_URL configured; the /v1 auth routes are not mounted")
	}

	provider, clients, err := buildOIDC(cfg, pool, logger, events)
	if err != nil {
		return nil, err
	}
	switch {
	case provider == nil && cfg.OIDCEnabled():
		// The opposite surprise: keys are configured and there is nowhere to keep
		// the registrations, so the provider would sign tokens for clients that
		// cannot be registered or revoked.
		logger.Warn("OIDC is configured but there is no DATABASE_URL; the OIDC surface is not mounted")
	case provider != nil:
		opts = append(opts, httpapi.WithOIDC(provider), httpapi.WithOIDCClients(clients))
	}

	handler := httpapi.New(checks, opts...)

	a := &app{
		cfg:    cfg,
		logger: logger,
		pool:   pool,
		srv: &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
		},
		timeout: shutdownTimeout,
	}

	// THE OUTBOX PUBLISHER LOOP — the one piece of process wiring that is not an
	// HTTP surface. It moves committed events from outbox_events onto the bus,
	// and it runs until the process's context is done.
	//
	// IT IS CONDITIONAL ON NATS_URL, and the condition is the whole of this
	// deployment's bus wiring. Unset is the shipped state and not an error: the
	// table, the loop and the Publisher interface exist, and a deployment that
	// has not wired a broker accumulates rows in outbox_events — the honest
	// shape of "not started yet", because the rows are the promise and they
	// drain the moment a broker is configured. Set is the new path: a real NATS
	// publisher over JetStream, and the loop in a goroutine tied to the
	// process's shutdown context — the same ctx the HTTP server drains on, so a
	// SIGTERM stops both.
	//
	// A broker that is DOWN when this runs is not a boot failure: the publisher
	// connects with RetryOnFailedConnect, so the loop starts, every publish
	// fails, the rows stay claimable, and they drain when the broker returns.
	// What fails the boot is a NATS_URL that does not parse — a typo belongs at
	// boot, where an operator reads it, not at the first event, where nobody
	// does.
	//
	// THE SECOND CONDITION IS THE POOL, and without it this branch would build
	// a loop whose claimer is a nil store: NATS_URL set and DATABASE_URL unset
	// is a misconfiguration, and a nil *Store panics on the first Claim, which
	// in a goroutine takes the whole process down. There is no outbox table to
	// drain without a pool, so the loop does not start — the same honest
	// accumulation as the no-broker case, and the boot log says which of the
	// two it is.
	if cfg.NATSEnabled() && events != nil {
		publisher, err := outbox.NewNATSPublisher(cfg.NATSURL)
		if err != nil {
			return nil, fmt.Errorf("building the NATS publisher: %w", err)
		}
		a.outboxPublisher = publisher

		loop := outbox.NewService(events, publisher, logger, 0)
		go func() {
			// Run returns nil on a clean shutdown and logs its own retries, so
			// the only thing to report is an unexpected exit — which for this
			// loop means the process is shutting down anyway.
			if err := loop.Run(ctx); err != nil {
				logger.Error("the outbox publisher loop exited", "error", err)
			}
		}()

		logger.Info("the outbox publisher is running", "broker", cfg.NATSURL)
	} else if !cfg.NATSEnabled() {
		logger.Info("NATS_URL is not set; the outbox publisher is not started, and " +
			"events will accumulate in outbox_events until a broker is configured")
	} else {
		logger.Warn("NATS_URL is set but DATABASE_URL is not; there is no outbox " +
			"table to drain, so the publisher loop is not started")
	}

	return a, nil
}

// buildAuth assembles the use cases over a pool, or returns nil when there is no
// pool to build them on.
//
// It takes the outbox store as a parameter rather than making its own: one
// store, shared, because it is stateless apart from its pool and two of them
// would be two objects that have to be configured identically — and because
// the publisher loop newApp starts claims from the SAME table, so the store
// that writes the events and the store that drains them must be one object.
//
// The publisher loop itself is wired by newApp, not here: what is started, and
// under what condition, is a fact about the deployment's NATS_URL and belongs
// at the top level of the process's assembly. When NATS_URL is unset no
// publisher exists and no loop runs — events accumulate in outbox_events, which
// is the honest state for a deployment that has not wired a broker: the rows
// are the promise, and they drain the moment one is configured.
//
// It returns the MFA use cases alongside the auth ones because auth.Login cannot
// work without them: a correct password must not mint a session for an account
// that has a second factor, and the only way to know is to ask.
// The fourth return is mfaUsable: whether this deployment can encrypt and decrypt a
// TOTP secret, which is exactly whether the MANAGEMENT routes may be mounted.
func buildAuth(
	cfg config.Config, pool *pgxpool.Pool, hasher *users.Hasher, logger *slog.Logger,
	events *outbox.Store,
) (*auth.Service, *accounts.Service, *mfa.Service, *deletion.Service, bool, error) {
	if pool == nil {
		return nil, nil, nil, nil, false, nil
	}

	// events is non-nil here: newApp creates it beside the pool and hands the
	// same store to every use case below and to the publisher loop.

	// The api key store, built BEFORE tenancy and handed to it. The dependency runs
	// backwards from the rest of this file and the reason is a security rule rather
	// than a convenience: removing a member from an account revokes the machine
	// credentials they held in it, in the same transaction as the membership delete,
	// and accounts.Service can only do that with a revoker to call. It is an
	// interface declared in accounts and satisfied here, so neither package imports
	// the other.
	//
	// One store, two services: apikeys.Service below takes the same *Store, so the
	// table has a single owner in this process and there is no second object to
	// configure identically.
	apiKeyStore := apikeys.NewStore(pool)

	// Tenancy is built first because registration needs it: a new user gets a
	// personal account, and both writes are one transaction. The order of these
	// two blocks is the dependency order, which is the reason they share a
	// function rather than being two independent builders in newApp.
	accountStore := accounts.NewStore(pool)

	// The invitation mailer, built beside the tenancy service it feeds and
	// passed into it. It is nil when this deployment has no mail path — a
	// supported state, not a broken one: the invitation is created and no mail
	// is claimed, and the 201 does not say an email was on its way. When the
	// deployment can send, it is built from the same resolved configuration
	// the recovery mailer uses, and config.Load has already refused to boot a
	// deployment that cannot say where invitation links go.
	invitationMailer, err := buildInvitationMailer(cfg, logger)
	if err != nil {
		return nil, nil, nil, nil, false, err
	}

	tenancy := accounts.NewService(
		acctboundary.TxRunner{TxRunner: db.TxRunner{Pool: pool}},
		accountStore,
		users.NewStore(pool),
		events,
		apiKeyStore,
		clock.System{},
		db.Direct{Pool: pool},
		invitationMailer,
	)

	// THE DELETION SERVICE, and it is built HERE rather than on its own because it
	// needs the three things this function has already made: the pool, the account
	// store (shared, not a second one over the same table) and the outbox.
	//
	// `acctboundary.TxRunner` and not `db.TxRunner`, for the reason it is the one
	// tenancy uses: it installs the account identity from the request context
	// before the callback runs. `internal/deletion` re-installs the USER identity
	// itself, because its transaction has no account — but the runner is still the
	// right seam, so a request that arrives carrying an account is not left with a
	// transaction standing in nobody's account.
	//
	// The credential sweeper is built from the SAME two stores the rest of the
	// process uses, and its constructor REFUSES a half-wired pair rather than
	// returning a sweeper that ends sessions and leaves every access token
	// standing. There is no fallback and no `Unavailable{}` here: a deployment
	// that cannot sweep cannot delete, and `DELETE /v1/me` is then not mounted at
	// all — a 404, which is a fact about the deployment rather than an error in a
	// user's request.
	credentialSweep, err := deletion.NewSweeper(sessions.NewStore(pool), oidc.NewStore(pool))
	if err != nil {
		return nil, nil, nil, nil, false, err
	}
	deletionSvc := deletion.NewService(
		acctboundary.TxRunner{TxRunner: db.TxRunner{Pool: pool}},
		users.NewStore(pool),
		accountStore,
		credentialSweep,
		events,
	)

	// The second factor is built before auth for the reason the comment above says:
	// auth takes it as a required dependency, so it has to exist before NewService
	// is called.
	//
	// NO MFA_ENCRYPTION_KEY means the vault is mfa.Unavailable{}, never nil. Every
	// path that reads or writes a secret fails with ErrNoVault, and the ENROLLMENT
	// ROUTES ARE NOT MOUNTED — a user must not be talked into enrolling a factor
	// this process could not later verify.
	//
	// The login path still works and still creates a challenge for users who
	// enrolled elsewhere, because mfa.Enabled needs no key. That is the fail-closed
	// direction: such a user is refused rather than let in on their password.
	// A wrong key is a startup failure and not a warning: an operator who
	// configured a 16-byte key believes they have 128 bits of entropy protecting
	// every second factor on the platform, and they do not.
	vault, err := buildMFASecret(cfg, logger)
	if err != nil {
		return nil, nil, nil, nil, false, err
	}
	_, mfaUsable := vault.(mfa.Unavailable)
	mfaUsable = !mfaUsable
	secondFactor := mfa.NewService(
		acctboundary.TxRunner{TxRunner: db.TxRunner{Pool: pool}},
		db.Direct{Pool: pool},
		mfa.NewStore(pool),
		events,
		sessions.NewStore(pool),
		vault,
		clock.System{},
		cfg.MFAIssuer(),
	)
	if mfaUsable {
		logger.Info("multi-factor authentication is available",
			"issuer", cfg.MFAIssuer(),
			"period_seconds", int(mfa.Period.Seconds()),
			"digits", mfa.Digits,
			"skew_steps", mfa.SkewSteps,
			"recovery_codes", mfa.RecoveryCodeCount,
		)
	} else {
		logger.Warn("MFA_ENCRYPTION_KEY is not configured; the MFA management routes are not mounted " +
			"and this process cannot verify a second factor for anybody")
	}

	authSvc := auth.NewService(
		// Registration's user row, personal account, owner membership and two
		// events; login's session and cleared failure counter; and the
		// second-factor login's session, challenge consumption and two cleared
		// counters, are each one transaction.
		acctboundary.TxRunner{TxRunner: db.TxRunner{Pool: pool}},
		// Everything else is a single statement and does not need one.
		db.Direct{Pool: pool},
		users.NewStore(pool),
		sessions.NewStore(pool),
		events,
		tenancy,
		secondFactor,
		// oidc.Store rather than the storage adapter, and for recovery's exact
		// reason: this is one UPDATE over `oidc_access_tokens` that needs no signing
		// key, and `users:disable` has to be able to end a user's JWTs on a
		// deployment where the OIDC provider is not mounted at all. A deployment
		// with no OIDC_SIGNING_KEY still has the table, and a disable that could
		// not reach it would answer 500 to an operator holding a valid key.
		//
		// IT IS NOT AN OPTIONAL ARGUMENT, and `auth.ErrNoAccessTokenRevoker` is
		// what a nil here would produce at the first disable rather than at boot.
		// See that error for why the degraded "revoked the sessions, left the
		// tokens" is not on the table.
		oidc.NewStore(pool),
		// The user_audit_log writer. IT IS NOT AN OPTIONAL ARGUMENT, and
		// `auth.ErrNoUserAuditRecorder` is what a nil here would produce at the first
		// disable rather than at boot — the same wiring argument as the revoker above,
		// and the same answer: a disable that revokes and does not record is the gap
		// disabled-04 exists to close, so degrading into it is not on the table.
		//
		// `*useraudit.Store` satisfies `auth.UserAuditRecorder` by signature, taking
		// the transaction's querier rather than its own pool — which is what puts the
		// audit row in the SAME transaction as the revocations and the column write
		// rather than beside them.
		useraudit.NewStore(pool),
		// Built once by newApp and shared with the recovery surface, because the
		// constructor derives a dummy digest in the login's timing equaliser and a
		// second Hasher would derive a second one for the same purpose.
		hasher,
		// The real clock. Every window in the service reads time through this, which
		// is what lets a test move time exactly.
		clock.System{},
		auth.DefaultSessionTTL,
		// The sign-in verification gate, from cfg. It is OFF BY DEFAULT (parity
		// with the reference this fleet matches); a deployment that wants
		// confirmation-gated sign-in sets REQUIRE_EMAIL_VERIFICATION.
		cfg.RequireEmailVerification,
	)

	return authSvc, tenancy, secondFactor, deletionSvc, mfaUsable, nil
}

// buildRecovery assembles the account-recovery use cases: password reset, address
// verification and email change.
//
// # THE MAILER IS courier's, AND `Unavailable{}` IS ONLY FOR A DEPLOYMENT THAT HAS
// NOT CONFIGURED IT
//
// `buildMailer` returns one of two things, and the difference is the whole of this
// function's mailer wiring:
//
//	configured    a courier.RecoveryMailer, which speaks POST /v1/messages
//	absent        recovery.Unavailable{}, which fails every send with ErrNoMailer
//
// The absent case is a SUPPORTED DEPLOYMENT rather than a gap: a local stack with
// no courier, or one where mail has not been turned on. It is loud in the log
// because a 404 on `/v1/password-resets` would tell a product this service has
// never heard of password recovery, which is both false and useless — so the routes
// stay mounted and answer 503 with a sentence naming the problem. The shape is the
// one `buildMFASecret`'s absent key already produces, and for the same reason: a
// user told "try later" retries forever and an operator told `internal` goes
// looking for a database problem that is not there.
//
// # NEITHER ALTERNATIVE WAS AVAILABLE
//
// A LOGGER was the alternative that was weighed and refused, and the reason is
// unchanged from when the seam was declared: every message this service sends
// contains a live credential until it is spent, and a reset token in an operator's
// log aggregator is a reset token anybody who can read the logs can redeem. The
// flows would work in every test and in a staging stack, and the first production
// deployment would be the first time a real user found their password reset had
// been written to a log file.
//
// # AND `Unavailable{}` IS STILL HERE FOR A REASON
//
// It is not reachable by accident and it is not dead: it is what a deployment with
// no `COURIER_TOKEN` mounts, and `TestAMailerIsCouriersOrUnavailableAndNothing
// Else` holds that the two are the only possibilities. It is the fail-loud design
// the seam was written for — every path that needs a message answers 503 rather
// than dropping one — and that is worth keeping for a deployment that has not
// finished the configuration rather than deleting.
//
// buildSocial assembles the social-login dependency, and its return type is
// httpapi.Social so that "nothing to mount" is a nil of the interface the router
// takes — the same shape buildRecovery's and buildOIDC's callers already handle.
//
// # A NIL RETURN IS THE SHIPPED STATE, NOT A MISCONFIGURATION
//
// Every OAUTH_* variable is optional. A deployment that sets none of them arrives
// here with `cfg.OAuth.Enabled()` false and gets (nil, nil), and the two routes are
// absent — a clean 404 rather than a redirect to a provider the deployment cannot
// authenticate with. That is the rule `httpapi.WithSocial` states and it is
// enforced by returning an UNTYPED nil: `WithSocial` guards on `if s != nil`, so a
// typed nil pointer inside the interface would defeat the guard and mount routes
// with nothing behind them. `httpapi.NewSocial` is where that nil is produced.
//
// # WHY EACH UNCONFIGURED PIECE IS ITS OWN CONDITION
//
// `pool == nil` and `authSvc == nil` are checked separately rather than combined,
// because they are different misconfigurations with different fixes and this
// function returns no error for either. They are both NORMAL: `config.Load` accepts
// a process with no DATABASE_URL, and newApp warns about it a few lines above.
// A combined condition would be shorter and would lose the ability to say which.
//
// # AND WHY A BROKEN CONFIGURATION IS A STARTUP FAILURE
//
// Every error below is a FAILURE and not a warning, and the distinction is the same
// one buildRecovery and buildOIDC draw. A key that does not decode to 32 bytes, a
// base URL that cannot produce a callback, or half a provider's credentials are all
// things an operator can fix before serving traffic, and every one of them would
// otherwise present as a support call from a person whose sign-in button does
// nothing. config.Load has already refused the obviously broken combinations by
// calling oauth.Settings.Validate; what reaches here is what that could not check
// without constructing the objects.
func buildSocial(
	cfg config.Config, pool *pgxpool.Pool, authSvc *auth.Service, logger *slog.Logger,
) (httpapi.Social, error) {
	if !cfg.OAuthEnabled() {
		// Nothing configured. The shipped state, and not a failure: every OAUTH_*
		// variable is optional and an untouched deployment arrives here.
		return nil, nil
	}
	if pool == nil || authSvc == nil {
		// Said out loud, and it is reachable: buildSocial takes both as arguments
		// rather than reading them from newApp's closure, so a future caller outside
		// the `if authSvc != nil` branch gets a log line naming the cause rather than
		// a nil dereference at boot. The current caller does not, and saying so is
		// what makes this branch's unreachability a fact rather than a hope.
		logger.Warn("OAuth is configured but there is no DATABASE_URL or no auth service; " +
			"the social-login surface is not mounted")
		return nil, nil
	}

	key, err := cfg.OAuth.Key()
	if err != nil {
		return nil, fmt.Errorf("loading the OAuth token encryption key: %w", err)
	}
	cipher, err := oauth.NewCipher(key)
	if err != nil {
		// A wrong key length is a startup failure for the reason NewCipher gives: an
		// operator who configured a 16-byte key believes they have 128 bits of
		// entropy protecting every provider credential on the platform, and they do
		// not. The tokens are already in the database sealed under whatever key was
		// there, so starting anyway would mean writing new rows this process cannot
		// read back.
		return nil, fmt.Errorf("building the OAuth token cipher: %w", err)
	}

	// The registry is built from the SAME base URL the settings carry, and the
	// client is given the same one, because the redirect_uri sent with the exchange
	// has to byte-match the one the authorize step offered. Two values would produce a
	// callback URL nothing is listening on, and the provider refuses the mismatch
	// without saying which of the two URLs was wrong.
	registry, err := oauth.NewRegistry(cfg.OAuth.RedirectBaseURL, cfg.OAuth.Providers()...)
	if err != nil {
		return nil, fmt.Errorf("building the OAuth provider registry: %w", err)
	}

	service := auth.NewSocialService(
		// The ordinary auth service, not a copy. Every write a social callback makes
		// goes through its transaction runner, its session store and its tenancy
		// provisioner, so a user minted by a provider round trip is a user the rest of
		// the service cannot tell apart from one registered with a password — which is
		// the point of not duplicating any of it here.
		authSvc,
		// The SAME registry object the router resolves providers through. NewSocial
		// takes both halves and hands this one to each; two registries would be a start
		// route that redirects to a provider the callback then 404s for, which is a 404
		// a person sees halfway through a sign-in.
		registry,
		oauth.NewClient(oauth.ClientOptions{RedirectBaseURL: cfg.OAuth.RedirectBaseURL}),
		oauth.NewStore(pool),
		cipher,
	)

	// The operator cannot see which providers came up otherwise — oauth.Registry.Names
	// exists for this log line and nothing else. A missing secret and a broken route
	// look identical from outside the process, and this is the only place they do not.
	logger.Info("social login is mounted",
		"providers", strings.Join(registry.Names(), ","),
		"redirect_base", cfg.OAuth.RedirectBaseURL,
	)

	// NewSocial returns an UNTYPED nil when the registry is empty, which is the shape
	// WithSocial's `if s != nil` guard needs. The `Enabled()` check above has already
	// established at least one provider, so this is belt and braces — and it is the
	// kind of belt that is load-bearing, because a typed nil here would mount two
	// routes with nothing behind them and panic on the first request.
	return httpapi.NewSocial(registry, service), nil
}

// buildRecovery is the account-recovery service, and it takes the second factor as a
// parameter rather than being handed it.
//
// The reason is the session link: `MintSessionLink` must be able to refuse a subject
// who has enrolled one, and a recovery service that could not ask would mint a link
// for such a subject on the assumption that nobody has one. So the dependency is
// explicit at the call site, and `buildAuth`'s `secondFactor` is what satisfies it.
func buildRecovery(
	cfg config.Config, pool *pgxpool.Pool, hasher *users.Hasher,
	secondFactor recovery.SecondFactorState, logger *slog.Logger,
	events *outbox.Store,
) (*recovery.Service, error) {
	if pool == nil {
		return nil, nil
	}

	mailer, err := buildMailer(cfg, logger)
	if err != nil {
		// A courier block that is PRESENT and unreadable is a startup failure, and
		// `config.Load` has already refused the obviously broken ones. This is the
		// remaining case, and it fails startup rather than warning because a
		// deployment that believes it can send mail and cannot is worse than one
		// that refuses to start: the first person to find out is a user waiting on
		// a password reset that was never sent.
		return nil, fmt.Errorf("building the mailer: %w", err)
	}

	service := recovery.NewService(
		// A spent token and the state it changes are one transaction, so every
		// redemption runs on the runner rather than on a bare querier.
		acctboundary.TxRunner{TxRunner: db.TxRunner{Pool: pool}},
		// Everything else is a single statement: the lookup that decides whether
		// the account exists, the cooldown read, and the resolution of a presented
		// token.
		db.Direct{Pool: pool},
		recovery.NewStore(pool),
		users.NewStore(pool),
		sessions.NewStore(pool),
		// oidc.Store rather than the storage adapter, and deliberately: this is one
		// UPDATE over oidc_access_tokens that needs no signing key, and a password
		// reset has to be able to end a user's JWTs on a deployment where the OIDC
		// provider is not mounted at all.
		oidc.NewStore(pool),
		events,
		mailer,
		hasher,
		clock.System{},
		// `mfa.Service` itself, and NOT nil and not a stub. A deployment with no
		// MFA_ENCRYPTION_KEY still builds one — with an Unavailable vault — because
		// `Enabled` needs no key: it is a lookup on `mfa_credentials`, and refusing
		// every link in such a deployment would be exactly backwards, since those are
		// the deployments where an enrolment somebody made elsewhere is most likely to
		// exist.
		secondFactor,
	)

	return service, nil
}

// buildMailer returns the Mailer this deployment has: courier's, or a refusing one.
//
// # THE SERVICE CREDENTIAL, AND WHY IT IS A BEARER TOKEN
//
// courier's document declares `security: [bearerAuth: [messages:write]]` and says
// identity is the only issuer, so this service presents
// `Authorization: Bearer <COURIER_TOKEN>` and nothing else. The alternatives were
// weighed:
//
//   - A SHARED SECRET on a header of our own. courier's
//     `CourierWeb.Plugs.IngestToken` does this, and its moduledoc gives the reason
//     it is right THERE: the callers are three services holding a Sentry DSN and
//     there is no identity service in that path to mint one. There IS one in this
//     path, and that plug is wired to a different route — a header courier's
//     `:authenticated` pipeline does not read produces a request that is still a
//     401.
//   - A USER'S SESSION OR API KEY. Both are a person's credential, and the
//     `account_id` courier takes from the principal is the tenancy of the mail.
//     Attributing the platform's password resets to whichever user happened to
//     trigger one would put a stranger's recovery in somebody else's tenant.
//
// # AND THE TOKEN IS NEVER LOGGED, WHICH IS WHY THE STARTUP LINE NAMES NOTHING
//
// The credential lives inside a closure in `internal/courier` and the line below
// reports the base URL, which is not a secret and is the thing an operator has to be
// able to confirm. `%#v` prints an exported struct field by value and does not
// consult `String()`, so a `token` field on the client would be a leak no method
// could intercept; `TestTheClientNeverPrintsACredential` drives a real request
// against a server that echoes the credential back and sweeps every formatting verb
// for it.

// buildInvitationMailer builds the invitation mailer, or nil when this deployment
// has no mail path.
//
// IT IS NIL RATHER THAN A REFUSING IMPLEMENTATION, and that is the difference from
// recovery's mailer. A deployment with no mail path still has a tenancy feature:
// the invitation is created, the token is returned to the admin, and no mail is
// claimed. The refusing shape exists for recovery because its routes are mounted
// and answer 503; the invite route answers 201 with a token the admin can give
// the invitee by hand, which is the better answer for a deployment that cannot
// send.
//
// THE TEMPLATE IS config.Load's RESOLVED value, for the reason buildMailer's
// templates are: a caller that re-resolved it here would be a second answer to
// "where does this link point". And config.Load has already refused to boot when
// the variable is unset or broken, so a deployment that reaches this function
// with a mail path has a template courier will accept.
// THE RETURN TYPE IS accounts.InvitationMailer, AND THAT IS WHAT MAKES THE NIL
// ABOVE AN UNTYPED ONE. A nil *courier.InvitationMailer stored in the
// interface NewService takes compares non-nil, so Invite's `s.mailer != nil`
// guard passes and SendInvitation runs on a nil receiver — the 2026-10-08
// panic on a stack with no mail path. The same shape buildSocial's return
// already has, for the same guard in WithSocial.
func buildInvitationMailer(cfg config.Config, logger *slog.Logger) (accounts.InvitationMailer, error) {
	if !cfg.CourierEnabled() {
		return nil, nil
	}

	client, err := courier.New(courier.Config{
		BaseURL: cfg.CourierBaseURL,
		Token:   cfg.CourierTokenValue,
	})
	if err != nil {
		return nil, fmt.Errorf("building the courier client: %w", err)
	}
	mailer, err := courier.NewInvitationMailer(courier.InvitationMailerConfig{
		Client:       client,
		LinkTemplate: cfg.InvitationLinkTemplate,
		Logger:       logger,
	})
	if err != nil {
		return nil, fmt.Errorf("building the invitation mailer: %w", err)
	}

	// ONE LINE, and what it does not say matches the recovery mailer's: it does
	// not say the invitation was sent. courier's `/readyz` says courier's
	// database answers; a send is where a misconfigured provider is found.
	logger.Info("invitations can be emailed through courier",
		"link_template", cfg.InvitationLinkTemplate,
	)
	return mailer, nil
}

func buildMailer(cfg config.Config, logger *slog.Logger) (recovery.Mailer, error) {
	if !cfg.CourierEnabled() {
		logger.Warn("account recovery is mounted, but this deployment cannot send email. " +
			"Set COURIER_BASE_URL, COURIER_TOKEN and at least one link template to enable " +
			"it: PASSWORD_RESET_LINK_TEMPLATE for the screen that redeems a reset, " +
			"EMAIL_VERIFICATION_LINK_TEMPLATE for the one that redeems an address " +
			"confirmation, or RECOVERY_LINK_TEMPLATE to apply to every purpose. Until " +
			"then POST /v1/password-resets answers 503.")
		return recovery.Unavailable{}, nil
	}

	client, err := courier.New(courier.Config{
		BaseURL: cfg.CourierBaseURL,
		Token:   cfg.CourierTokenValue,
	})
	if err != nil {
		return nil, fmt.Errorf("building the courier client: %w", err)
	}
	// The RESOLVED templates are passed straight through, and this is the only place
	// in the process that hands them to the adapter. A caller that re-applied the
	// default here would be a second answer to "where does this link point", and the
	// two would drift the first time somebody added a purpose.
	mailer, err := courier.NewRecoveryMailer(courier.RecoveryMailerConfig{
		Client:        client,
		LinkTemplates: cfg.LinkTemplates,
		Logger:        logger,
	})
	if err != nil {
		return nil, fmt.Errorf("building the courier mailer: %w", err)
	}

	// THE LINE, AND WHAT IT DOES NOT SAY. It does not say mail will be sent.
	// courier's `/readyz` is outside every pipeline and answers for courier's
	// DATABASE; it does not say courier can deliver, because courier's adapter check
	// is scoped to production. A green readiness probe and this line together are
	// "courier is reachable", and a send is where a misconfigured provider is
	// found. An operator who reads "mail is wired" as "mail is being sent" has been
	// told something this process cannot support.
	//
	// ONE ATTRIBUTE PER PURPOSE, and not one shared `link_template`, because the
	// purposes point at different screens and an operator confirming one value has
	// confirmed nothing about the other. `LinkTemplatePurposes` sorts them, so the
	// line is the same on every restart and two log excerpts diff.
	attrs := []any{
		"courier", cfg.CourierBaseURL,
		"send_timeout", courier.DefaultTimeout,
		"probe_timeout", courier.DefaultProbeTimeout,
	}
	for _, purpose := range cfg.LinkTemplatePurposes() {
		attrs = append(attrs, "link_template."+string(purpose), cfg.LinkTemplateFor(purpose))
	}
	logger.Info("account recovery can send email through courier", attrs...)

	// WHAT IS DELIVERABLE, said out loud. All four of `internal/recovery`'s
	// messages have a courier type: the password reset onto `password_reset`,
	// the address verification onto `welcome` — whose words are true for an
	// account that has never proved an address — and the two halves of an EMAIL
	// CHANGE onto the two types courier built for them (`20373bf`, packet m70):
	// the current-address half, which is the only warning an account owner gets
	// that somebody is moving their address, carries the confirmation link, and
	// the new-address half carries the previous address and no link. See
	// internal/courier's RecoveryMailer for why a wrong notice would have been
	// worse than a refusal, and for the mapping in full.
	logger.Info("account recovery can send all four messages through courier: " +
		"password reset, address verification, and both halves of an email change")

	// THE SHARED-DEFAULT WARNING, which is the one that closes identity-24's finding
	// from the operator's side rather than the test's.
	//
	// A deployment with only `RECOVERY_LINK_TEMPLATE` still boots — that is the
	// compatibility promise and `internal/config` is where it is made — but its
	// address-verification link points wherever its one template says, which for the
	// configuration this shape was introduced to replace is the password reset
	// screen. A verification token presented there is a 404. Nothing else in the
	// process can see it: the mail renders, the send succeeds, the token redeems at
	// its own endpoint, and the reader is the only one who finds out.
	warnSharedLinkTemplates(cfg, logger)

	return mailer, nil
}

// warnSharedLinkTemplates says which purposes resolve to the shared default, and
// names the variable that would give each one its own.
//
// IT NAMES THE VARIABLES RATHER THAN DESCRIBING THE MIGRATION, because
// `TestAnUnconfiguredDeploymentIsLoudAtStartup` exists for the same reason: an
// operator told "consider configuring the links separately" has been told a symptom,
// and the variable names are the whole of the difference between that and a fix.
//
// THE CHECK IS ON THE RESOLVED VALUE rather than on "was the variable set", so what
// it says — these purposes resolve to RECOVERY_LINK_TEMPLATE — stays true for a
// deployment that set both variables to the same string. A warning that is
// occasionally redundant is a better trade than one that is occasionally wrong about
// a state it describes as fact.
func warnSharedLinkTemplates(cfg config.Config, logger *slog.Logger) {
	shared := cfg.LinkPurposesUsingTheDefault()
	if len(shared) == 0 {
		return
	}

	purposes := make([]string, 0, len(shared))
	variables := make([]string, 0, len(shared))
	for _, purpose := range shared {
		purposes = append(purposes, string(purpose))
		if variable, ok := config.LinkTemplateVariable(purpose); ok {
			variables = append(variables, variable)
		}
	}
	logger.Warn("RECOVERY_LINK_TEMPLATE is the link for every purpose with no variable " +
		"of its own, and it is currently the link for: " + strings.Join(purposes, ", ") + ". " +
		"If that template is the password reset screen then an address confirmation " +
		"or an email-change confirmation lands the reader on a screen that answers " +
		"404 for the token it carries. " +
		"Set " + strings.Join(variables, " and ") + " to say where each kind of link goes.")
}

// buildAPIKeys assembles the scoped-token use cases, or returns nil when this
// process cannot have them.
//
// THE ONE CONDITION is a pool, and it is the same one auth needs — a table with no
// process writing to it is not a capability, it is a 500 waiting for the first
// request. So this is called from inside the `authSvc != nil` branch and never
// decides anything of its own.
//
// It takes NO CONFIGURATION, and that is worth a line because every other surface
// in this file does. An api key is not a secret this deployment generates and has
// to keep: it is a random value whose only stored form is a SHA-256 of it, and
// there is no key to load, no key to rotate and no key to lose. The costs of
// having a signing key configured for the OIDC provider — a startup failure on a
// wrong one, a trust anchor that changes on a restart — do not exist here, which
// is one of the reasons this credential is a row lookup rather than a JWT.
//
// The outbox store is the one newApp made, the same object buildAuth and
// buildOIDC receive and the publisher loop drains through: one store over one
// table, because the store is stateless apart from its pool and a second one
// would be a second thing to keep configured identically — and because the loop
// is the one consumer that has to see every row the writers commit.
func buildAPIKeys(
	cfg config.Config,
	pool *pgxpool.Pool,
	tenancy *accounts.Service,
	logger *slog.Logger,
	events *outbox.Store,
) (*apikeys.Service, error) {
	if pool == nil || tenancy == nil {
		return nil, nil
	}

	service := apikeys.NewService(
		acctboundary.TxRunner{TxRunner: db.TxRunner{Pool: pool}},
		acctboundary.CredentialResolver{TxRunner: db.TxRunner{Pool: pool}},
		db.Direct{Pool: pool},
		apikeys.NewStore(pool),
		events,
		tenancy,
		users.NewStore(pool),
		clock.System{},
	)

	// The startup line is the same one MFA gets, and for the same reason: an
	// operator who does not know a capability is mounted will discover it from a
	// 404, and one who believes it is mounted when it is not will discover it from
	// a 404 too. The scopes are in the line because they are the vocabulary a
	// consumer has to match against, and a list that changes with a release belongs
	// in the log at boot rather than in a document somebody has to find.
	logger.Info("scoped api tokens are mounted",
		"prefix", apikeys.Prefix,
		"secret_bytes", apikeys.SecretBytes,
		"scopes", strings.Join(apikeys.AllScopes(), " "),
		"default_ttl", apikeys.DefaultTTL,
		"max_ttl", apikeys.MaxTTL,
	)

	return service, nil
}

// buildMFASecret returns the vault for the configured key, or mfa.Unavailable{}.
//
// Three outcomes, and the third is a startup failure rather than a warning:
//
//	key absent   Unavailable{} — a deployment that has not turned MFA on
//	key present  a real AES-256-GCM vault
//	key wrong    an error
//
// It is NEVER generated at boot. A generated key would mean every restart
// invalidates every enrolled user's secret, and a restart is not something anybody
// decides to do — which is the same rule AGENTS.md states for OIDC_SIGNING_KEY.
func buildMFASecret(cfg config.Config, logger *slog.Logger) (mfa.Vault, error) {
	key, err := cfg.MFAEncryptionKey()
	switch {
	case errors.Is(err, config.ErrNoMFAEncryptionKey):
		logger.Warn("MFA_ENCRYPTION_KEY is not set")
		return mfa.Unavailable{}, nil
	case err != nil:
		return nil, fmt.Errorf("reading MFA_ENCRYPTION_KEY: %w", err)
	}

	vault, err := mfa.NewAESCipher(key)
	if err != nil {
		return nil, fmt.Errorf("building the MFA encryption key: %w", err)
	}
	return vault, nil
}

// buildOIDC assembles the OpenID Connect provider, or returns nils when this
// process is not one.
//
// Three conditions, and all three are required. A signing key with no database has
// nowhere to keep a registration, so the provider could sign tokens for clients
// that can never be registered or revoked. A database with no key cannot sign. And
// no issuer means the provider is not configured at all, which is the legitimate
// deployment — a courier, or a local stack that has no key yet.
//
// The order inside is the dependency order: the key, because the storage adapter
// needs it to publish the key set; the storage, because the provider needs it for
// every protocol decision; then the provider and the registration use cases,
// which share the one store.
func buildOIDC(cfg config.Config, pool *pgxpool.Pool, logger *slog.Logger, events *outbox.Store) (*oidc.Provider, *oidc.Service, error) {
	if !cfg.OIDCEnabled() || pool == nil {
		return nil, nil, nil
	}

	key, err := oidc.LoadSigningKey(cfg.OIDCSigningKey, cfg.OIDCKeyID)
	if err != nil {
		// A startup failure, not a warning. The alternative is a provider that
		// signs with a key it invented, publishes a document nobody has cached and
		// rotates its own trust anchor on every restart.
		return nil, nil, fmt.Errorf("loading the OIDC signing key: %w", err)
	}

	store := oidc.NewStore(pool)
	storage := oidc.NewStorage(store, oidc.NewProfileReader(), oauth.NewStore(pool),
		key, clock.System{}, db.Direct{Pool: pool}, oidc.PathLogin)

	provider, err := oidc.NewProvider(oidc.Config{
		Issuer:        cfg.OIDCIssuer,
		SigningKey:    key,
		AllowInsecure: cfg.OIDCAllowInsecure,
		LoginUIURL:    cfg.OIDCLoginUIURL,
	}, storage)
	if err != nil {
		return nil, nil, fmt.Errorf("building the OIDC provider: %w", err)
	}

	// The outbox store is newApp's, the same object every other writer and the
	// publisher loop use: one store over one table, because the store is
	// stateless apart from its pool and a second one would be a second thing to
	// keep configured identically.
	clients := oidc.NewService(
		acctboundary.TxRunner{TxRunner: db.TxRunner{Pool: pool}},
		store,
		events,
		storage,
		clock.System{},
		db.Direct{Pool: pool},
	)

	// THE LOGIN UI IS IN THIS LINE AND NOT OPTIONAL, because it is the one setting
	// an operator has to change when this packet lands and the one nothing else in
	// the process can see is wrong. A browser that is redirected to an address with
	// no sign-in form on it gets an error page from another service; a browser that
	// is redirected to a form for the wrong deployment authenticates into the wrong
	// one. Neither is visible in a health check, and both are the kind of thing
	// that is found by a user.
	logger.Info("the OIDC provider is mounted",
		"issuer", provider.Issuer(),
		"key_id", key.ID(),
		"authorize", oidc.PathAuthorize,
		"login_ui", cfg.OIDCLoginUIURL,
	)

	return provider, clients, nil
}

// Listen binds the socket. It is separate from Run so the address is known —
// and reported — before the first request is served.
func (a *app) Listen() error {
	listener, err := net.Listen("tcp", a.cfg.Addr())
	if err != nil {
		return fmt.Errorf("listening on %s: %w", a.cfg.Addr(), err)
	}
	a.listener = listener
	return nil
}

// Addr is the bound address, empty until Listen succeeds.
func (a *app) Addr() string {
	if a.listener == nil {
		return ""
	}
	return a.listener.Addr().String()
}

// Run serves until ctx is cancelled (SIGTERM, SIGINT, or a test's context),
// then drains in-flight requests before returning.
func (a *app) Run(ctx context.Context) error {
	if a.listener == nil {
		return errors.New("Run called before Listen")
	}

	serveErr := make(chan error, 1)
	go func() {
		a.logger.Info("listening", "addr", a.Addr())
		serveErr <- a.srv.Serve(a.listener)
	}()

	select {
	case err := <-serveErr:
		return a.serveResult(err)
	case <-ctx.Done():
		a.logger.Info("shutdown requested", "in_flight_drain", a.timeout)
	}

	// Shutdown gets a fresh context: the cancelled one cannot be used to wait.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()

	if err := a.srv.Shutdown(shutdownCtx); err != nil {
		// Drain deadline blown: drop the connections rather than hang.
		_ = a.srv.Close()
		return fmt.Errorf("graceful shutdown: %w", err)
	}

	return a.serveResult(<-serveErr)
}

// Close releases the connection pool and the outbox publisher's bus connection.
func (a *app) Close() error {
	if a.outboxPublisher != nil {
		a.outboxPublisher.Close()
	}
	if a.pool == nil {
		return nil
	}
	a.pool.Close()
	return nil
}

// serveResult normalises http.ErrServerClosed, which is how Serve reports a
// server stopped by Shutdown rather than a failure.
func (a *app) serveResult(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
