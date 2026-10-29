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
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	acctboundary "github.com/anywaye/identity/internal/tenancy"

	"github.com/anywaye/identity/internal/accounts"
	"github.com/anywaye/identity/internal/agents"
	"github.com/anywaye/identity/internal/apikeys"
	"github.com/anywaye/identity/internal/auth"
	"github.com/anywaye/identity/internal/config"
	"github.com/anywaye/identity/internal/courier"
	"github.com/anywaye/identity/internal/deletion"
	"github.com/anywaye/identity/internal/httpapi"
	"github.com/anywaye/identity/internal/mfa"
	"github.com/anywaye/identity/internal/migrate"
	"github.com/anywaye/identity/internal/oauth"
	"github.com/anywaye/identity/internal/oidc"
	"github.com/anywaye/identity/internal/outbox"
	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/ratelimit"
	"github.com/anywaye/identity/internal/recovery"
	"github.com/anywaye/identity/internal/sessions"
	"github.com/anywaye/identity/internal/signup"
	"github.com/anywaye/identity/internal/telemetry"
	"github.com/anywaye/identity/internal/useraudit"
	"github.com/anywaye/identity/internal/users"

	"github.com/anywaye/identity/migrations"
)

const shutdownTimeout = 15 * time.Second

func main() {
	if len(os.Args) == 2 && os.Args[1] == "-healthcheck" {
		os.Exit(healthcheck())
	}

	command, err := subcommand(os.Args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "identity: %v\n", err)
		os.Exit(2)
	}

	switch command {
	case commandMigrate:
		if err := runMigrate(context.Background(), os.Getenv("DATABASE_URL"), os.Stderr); err != nil {
			fmt.Fprintf(os.Stderr, "identity migrate: %v\n", err)
			os.Exit(1)
		}
	default:
		if err := run(); err != nil {
			slog.Error("identity exited with an error", "error", err)
			os.Exit(1)
		}
	}
}

const (
	commandServe   = "serve"
	commandMigrate = "migrate"
)

func subcommand(args []string) (string, error) {
	if len(args) == 0 {
		return commandServe, nil
	}
	if len(args) > 1 {
		switch args[1] {
		case commandMigrate:
			return commandMigrate, nil
		case commandServe:
			return commandServe, nil
		}
		if !strings.HasPrefix(args[1], "-") {
			return "", fmt.Errorf("unknown command %q; want %q, %q or -healthcheck", args[1], commandServe, commandMigrate)
		}
	}
	if filepath.Base(args[0]) == commandMigrate {
		return commandMigrate, nil
	}
	return commandServe, nil
}

func runMigrate(ctx context.Context, dsn string, out io.Writer) error {
	logger := slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelInfo}))
	logger.Info("applying the embedded migrations", "command", commandMigrate)

	applied, err := migrate.Run(ctx, dsn, migrations.FS, logger)
	if err != nil {
		return err
	}
	if len(applied) == 0 {
		logger.Info("already at the embedded schema; nothing to apply")
		return nil
	}
	logger.Info("migrations applied", "count", len(applied), "last", applied[len(applied)-1])
	return nil
}

const healthcheckTimeout = 2 * time.Second

func healthcheck() int {
	port := os.Getenv("PORT")
	if port == "" {
		port = config.DefaultPort
	}
	ctx, cancel := context.WithTimeout(context.Background(), healthcheckTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+port+"/readyz", nil)
	if err != nil {
		return 1
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
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

	shutdownTelemetry, err := installTelemetry(ctx, logger)
	httpapi.InitErrorReporting()
	if err != nil {
		return err
	}
	defer func() {
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
	defer func() {
		if err := a.Close(); err != nil {
			logger.Warn("closing the app on the way out failed", "error", err)
		}
	}()

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

func redactEndpoint(endpoint string) string {
	if index := strings.IndexAny(endpoint, "?#"); index >= 0 {
		return endpoint[:index]
	}
	return endpoint
}

type app struct {
	cfg      config.Config
	logger   *slog.Logger
	pool     *pgxpool.Pool
	srv      *http.Server
	listener net.Listener
	timeout  time.Duration

	outboxPublisher *outbox.NATSPublisher
}

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

	opts = append(opts, httpapi.WithSignup(signup.New(cfg.SignupSigningKeyValue)))

	opts = append(opts, httpapi.WithRateLimiter(ratelimit.New(clock.System{}, map[string]ratelimit.Limit{
		"/v1/users":               {Max: cfg.RateLimit.Signup, Window: cfg.RateLimit.Window},
		"/v1/session":             {Max: cfg.RateLimit.Signin, Window: cfg.RateLimit.Window},
		"/v1/signup-timestamp":    {Max: cfg.RateLimit.SignupTimestamp, Window: cfg.RateLimit.Window},
		"/v1/password-resets":     {Max: cfg.RateLimit.Recovery, Window: cfg.RateLimit.Window},
		"/v1/email-verifications": {Max: cfg.RateLimit.Recovery, Window: cfg.RateLimit.Window},
		"/v1/agents": {Max: cfg.RateLimit.AgentRegister, Window: cfg.RateLimit.Window},
	})))

	hasher := users.NewHasher()

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
			httpapi.WithAgents(agents.NewService(pool, agents.WithClaimUI(cfg.AgentClaimUIURL))),
		)
		if mfaUsable {
			opts = append(opts, httpapi.WithMFA(secondFactor))
		}
		recoverySvc, err := buildRecovery(cfg, pool, hasher, secondFactor, logger, events)
		if err != nil {
			return nil, err
		}
		if recoverySvc != nil {
			opts = append(opts, httpapi.WithRecovery(recoverySvc))
		}
		social, err := buildSocial(cfg, pool, authSvc, logger)
		if err != nil {
			return nil, err
		}
		if social != nil {
			opts = append(opts, httpapi.WithSocial(social))
		}
		if machineCredentials != nil {
			opts = append(opts,
				httpapi.WithAPIKeys(machineCredentials),
				httpapi.WithAPIKeyCaller(machineCredentials),
				httpapi.WithIntrospection(machineCredentials),
			)
		}
	} else {
		logger.Warn("no DATABASE_URL configured; the /v1 auth routes are not mounted")
	}

	provider, clients, err := buildOIDC(cfg, pool, logger, events)
	if err != nil {
		return nil, err
	}
	switch {
	case provider == nil && cfg.OIDCEnabled():
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

	if cfg.NATSEnabled() && events != nil {
		publisher, err := outbox.NewNATSPublisher(cfg.NATSURL, logger)
		if err != nil {
			return nil, fmt.Errorf("building the NATS publisher: %w", err)
		}
		a.outboxPublisher = publisher

		loop := outbox.NewService(events, publisher, logger, 0)
		go func() {
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

func buildAuth(
	cfg config.Config, pool *pgxpool.Pool, hasher *users.Hasher, logger *slog.Logger,
	events *outbox.Store,
) (*auth.Service, *accounts.Service, *mfa.Service, *deletion.Service, bool, error) {
	if pool == nil {
		return nil, nil, nil, nil, false, nil
	}


	apiKeyStore := apikeys.NewStore(pool)

	accountStore := accounts.NewStore(pool)

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
		acctboundary.TxRunner{TxRunner: db.TxRunner{Pool: pool}},
		db.Direct{Pool: pool},
		users.NewStore(pool),
		sessions.NewStore(pool),
		events,
		tenancy,
		secondFactor,
		oidc.NewStore(pool),
		useraudit.NewStore(pool),
		hasher,
		clock.System{},
		auth.DefaultSessionTTL,
		cfg.RequireEmailVerification,
	)

	return authSvc, tenancy, secondFactor, deletionSvc, mfaUsable, nil
}

func buildSocial(
	cfg config.Config, pool *pgxpool.Pool, authSvc *auth.Service, logger *slog.Logger,
) (httpapi.Social, error) {
	if !cfg.OAuthEnabled() {
		return nil, nil
	}
	if pool == nil || authSvc == nil {
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
		return nil, fmt.Errorf("building the OAuth token cipher: %w", err)
	}

	registry, err := oauth.NewRegistry(cfg.OAuth.RedirectBaseURL, cfg.OAuth.Providers()...)
	if err != nil {
		return nil, fmt.Errorf("building the OAuth provider registry: %w", err)
	}

	service := auth.NewSocialService(
		authSvc,
		registry,
		oauth.NewClient(oauth.ClientOptions{RedirectBaseURL: cfg.OAuth.RedirectBaseURL}),
		oauth.NewStore(pool),
		cipher,
	)

	logger.Info("social login is mounted",
		"providers", strings.Join(registry.Names(), ","),
		"redirect_base", cfg.OAuth.RedirectBaseURL,
	)

	return httpapi.NewSocial(registry, service), nil
}

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
		return nil, fmt.Errorf("building the mailer: %w", err)
	}

	service := recovery.NewService(
		acctboundary.TxRunner{TxRunner: db.TxRunner{Pool: pool}},
		db.Direct{Pool: pool},
		recovery.NewStore(pool),
		users.NewStore(pool),
		sessions.NewStore(pool),
		oidc.NewStore(pool),
		events,
		mailer,
		hasher,
		clock.System{},
		secondFactor,
	)

	return service, nil
}


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
	mailer, err := courier.NewRecoveryMailer(courier.RecoveryMailerConfig{
		Client:        client,
		LinkTemplates: cfg.LinkTemplates,
		Logger:        logger,
	})
	if err != nil {
		return nil, fmt.Errorf("building the courier mailer: %w", err)
	}

	attrs := []any{
		"courier", cfg.CourierBaseURL,
		"send_timeout", courier.DefaultTimeout,
		"probe_timeout", courier.DefaultProbeTimeout,
	}
	for _, purpose := range cfg.LinkTemplatePurposes() {
		attrs = append(attrs, "link_template."+string(purpose), cfg.LinkTemplateFor(purpose))
	}
	logger.Info("account recovery can send email through courier", attrs...)

	logger.Info("account recovery can send all four messages through courier: " +
		"password reset, address verification, and both halves of an email change")

	warnSharedLinkTemplates(cfg, logger)

	return mailer, nil
}

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

	logger.Info("scoped api tokens are mounted",
		"prefix", apikeys.Prefix,
		"secret_bytes", apikeys.SecretBytes,
		"scopes", strings.Join(apikeys.AllScopes(), " "),
		"default_ttl", apikeys.DefaultTTL,
		"max_ttl", apikeys.MaxTTL,
	)

	return service, nil
}

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

func buildOIDC(cfg config.Config, pool *pgxpool.Pool, logger *slog.Logger, events *outbox.Store) (*oidc.Provider, *oidc.Service, error) {
	if !cfg.OIDCEnabled() || pool == nil {
		return nil, nil, nil
	}

	key, err := oidc.LoadSigningKey(cfg.OIDCSigningKey, cfg.OIDCKeyID)
	if err != nil {
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

	clients := oidc.NewService(
		acctboundary.TxRunner{TxRunner: db.TxRunner{Pool: pool}},
		store,
		events,
		storage,
		clock.System{},
		db.Direct{Pool: pool},
	)

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
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", a.cfg.Addr())
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

// Run serves until ctx is canceled (SIGTERM, SIGINT, or a test's context),
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

	shutdownCtx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()

	if err := a.srv.Shutdown(shutdownCtx); err != nil {
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

func (a *app) serveResult(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
