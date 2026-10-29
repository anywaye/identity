package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/anywaye/identity/internal/oauth"
	"github.com/anywaye/identity/internal/oidc"
	"github.com/anywaye/identity/internal/recovery"
)

const (
	DefaultPort = "8080"
	DefaultLogLevel = "info"

	minPort = 1
	maxPort = 65535
)

// Lookup mirrors os.LookupEnv: it returns the value for key and whether the
// key was present. Injecting it keeps Load testable without mutating the
// process environment.
type Lookup func(key string) (string, bool)

var (
	ErrInvalidPort        = errors.New("invalid PORT")
	ErrInvalidLogLevel    = errors.New("invalid LOG_LEVEL")
	ErrInvalidDatabaseURL = errors.New("invalid DATABASE_URL")

	ErrInvalidOIDC = errors.New("invalid OIDC configuration")

	ErrInsecureOIDCIssuer = errors.New("OIDC_ISSUER is http")

	ErrInvalidMFA = errors.New("invalid MFA_ENCRYPTION_KEY")

	ErrNoMFAEncryptionKey = errors.New("MFA_ENCRYPTION_KEY is not configured")

	ErrInvalidCourier = errors.New("invalid courier configuration")

	ErrInvalidOAuth = errors.New("invalid OAuth configuration")

	ErrNoCourierToken = errors.New("COURIER_TOKEN is not configured")

	ErrNoSignupSigningKey = errors.New("SIGNUP_SIGNING_KEY is not configured")

	ErrInvalidSignupSigningKey = errors.New("invalid SIGNUP_SIGNING_KEY")

	ErrInvalidRateLimit = errors.New("invalid RATE_LIMIT_* configuration")
)

// DefaultMFAIssuer is what an authenticator app displays next to the entry when
// MFA_ISSUER is unset.
//
// "anywaye identity", with a space rather than a hyphen, because that is what a
// person reads in a phone's authenticator next to the six digits and the clock.
// It is also what the provisioning URI's issuer parameter carries, so changing it
// changes what every future enrollment shows and nothing about the credentials
// already confirmed.
const DefaultMFAIssuer = "anywaye identity"

// Config is the fully validated service configuration.
type Config struct {
	Port string
	DatabaseURL string
	LogLevel string

	OIDCIssuer     string
	OIDCSigningKey string
	OIDCKeyID      string
	OIDCAllowInsecure bool

	OIDCLoginUIURL string

	AgentClaimUIURL string

	MFAEncryptionKeyValue []byte

	MFAIssuerLabel string

	CourierBaseURL    string
	CourierTokenValue string

	LinkTemplates map[recovery.Purpose]string

	DefaultLinkTemplate string

	InvitationLinkTemplate string

	OAuth oauth.Settings

	SignupSigningKeyValue []byte

	NATSURL string

	RateLimit RateLimit

	RequireEmailVerification bool
}

// RateLimit is the per-route request-rate limit block.
//
// It is a struct and not five loose fields because the five travel together:
// one window shared by every route on the surface, and a limit per route. A
// deployment that tunes one route's limit understands the window it is tuned
// against, and a deployment that changes the window changes it for every
// route at once — which is the honest shape of "how long is a minute of
// abuse".
type RateLimit struct {
	Window time.Duration
	Signup int
	Signin int
	SignupTimestamp int
	Recovery int
	AgentRegister int
}

const (
	OAuthRedirectBaseURLVar = "OAUTH_REDIRECT_BASE_URL"
	OAuthEncryptionKeyVar = "OAUTH_ENCRYPTION_KEY"
	OAuthGoogleClientIDVar     = "OAUTH_GOOGLE_CLIENT_ID"
	OAuthGoogleClientSecretVar = "OAUTH_GOOGLE_CLIENT_SECRET"
	OAuthGitHubClientIDVar     = "OAUTH_GITHUB_CLIENT_ID"
	OAuthGitHubClientSecretVar = "OAUTH_GITHUB_CLIENT_SECRET"
	OAuthMicrosoftClientIDVar     = "OAUTH_MICROSOFT_CLIENT_ID"
	OAuthMicrosoftClientSecretVar = "OAUTH_MICROSOFT_CLIENT_SECRET"
	OAuthAppleClientIDVar = "OAUTH_APPLE_CLIENT_ID"
	OAuthAppleTeamIDVar = "OAUTH_APPLE_TEAM_ID"
	OAuthAppleKeyIDVar = "OAUTH_APPLE_KEY_ID"
	OAuthApplePrivateKeyVar = "OAUTH_APPLE_PRIVATE_KEY"

	OAuthGoogleAuthorizeURLVar    = "OAUTH_GOOGLE_AUTHORIZE_URL"
	OAuthGoogleTokenURLVar        = "OAUTH_GOOGLE_TOKEN_URL"
	OAuthGoogleUserInfoURLVar     = "OAUTH_GOOGLE_USERINFO_URL"
	OAuthGitHubAuthorizeURLVar    = "OAUTH_GITHUB_AUTHORIZE_URL"
	OAuthGitHubTokenURLVar        = "OAUTH_GITHUB_TOKEN_URL"
	OAuthGitHubUserInfoURLVar     = "OAUTH_GITHUB_USERINFO_URL"
	OAuthGitHubEmailsURLVar       = "OAUTH_GITHUB_EMAILS_URL"
	OAuthMicrosoftAuthorizeURLVar = "OAUTH_MICROSOFT_AUTHORIZE_URL"
	OAuthMicrosoftTokenURLVar     = "OAUTH_MICROSOFT_TOKEN_URL"
	OAuthMicrosoftUserInfoURLVar  = "OAUTH_MICROSOFT_USERINFO_URL"
	OAuthAppleAuthorizeURLVar = "OAUTH_APPLE_AUTHORIZE_URL"
	OAuthAppleTokenURLVar     = "OAUTH_APPLE_TOKEN_URL"

	NATSURLVar = "NATS_URL"

	RateLimitWindowVar          = "RATE_LIMIT_WINDOW"
	RateLimitSignupVar          = "RATE_LIMIT_SIGNUP"
	RateLimitSigninVar          = "RATE_LIMIT_SIGNIN"
	RateLimitSignupTimestampVar = "RATE_LIMIT_SIGNUP_TIMESTAMP"
	RateLimitAgentRegisterVar   = "RATE_LIMIT_AGENT_REGISTER"
	RateLimitRecoveryVar        = "RATE_LIMIT_RECOVERY"

	RequireEmailVerificationVar = "REQUIRE_EMAIL_VERIFICATION"
)

var oauthEndpointVars = []struct {
	provider string
	field    string
	variable string
	assign   func(*oauth.Settings, string)
}{
	{
		provider: oauth.ProviderGoogle,
		field:    "AuthorizeURL",
		variable: OAuthGoogleAuthorizeURLVar,
		assign:   func(s *oauth.Settings, v string) { s.Google.Endpoints.AuthorizeURL = v },
	},
	{
		provider: oauth.ProviderGoogle,
		field:    "TokenURL",
		variable: OAuthGoogleTokenURLVar,
		assign:   func(s *oauth.Settings, v string) { s.Google.Endpoints.TokenURL = v },
	},
	{
		provider: oauth.ProviderGoogle,
		field:    "UserInfoURL",
		variable: OAuthGoogleUserInfoURLVar,
		assign:   func(s *oauth.Settings, v string) { s.Google.Endpoints.UserInfoURL = v },
	},
	{
		provider: oauth.ProviderGitHub,
		field:    "AuthorizeURL",
		variable: OAuthGitHubAuthorizeURLVar,
		assign:   func(s *oauth.Settings, v string) { s.GitHub.Endpoints.AuthorizeURL = v },
	},
	{
		provider: oauth.ProviderGitHub,
		field:    "TokenURL",
		variable: OAuthGitHubTokenURLVar,
		assign:   func(s *oauth.Settings, v string) { s.GitHub.Endpoints.TokenURL = v },
	},
	{
		provider: oauth.ProviderGitHub,
		field:    "UserInfoURL",
		variable: OAuthGitHubUserInfoURLVar,
		assign:   func(s *oauth.Settings, v string) { s.GitHub.Endpoints.UserInfoURL = v },
	},
	{
		provider: oauth.ProviderGitHub,
		field:    "EmailsURL",
		variable: OAuthGitHubEmailsURLVar,
		assign:   func(s *oauth.Settings, v string) { s.GitHub.Endpoints.EmailsURL = v },
	},
	{
		provider: oauth.ProviderMicrosoft,
		field:    "AuthorizeURL",
		variable: OAuthMicrosoftAuthorizeURLVar,
		assign:   func(s *oauth.Settings, v string) { s.Microsoft.Endpoints.AuthorizeURL = v },
	},
	{
		provider: oauth.ProviderMicrosoft,
		field:    "TokenURL",
		variable: OAuthMicrosoftTokenURLVar,
		assign:   func(s *oauth.Settings, v string) { s.Microsoft.Endpoints.TokenURL = v },
	},
	{
		provider: oauth.ProviderMicrosoft,
		field:    "UserInfoURL",
		variable: OAuthMicrosoftUserInfoURLVar,
		assign:   func(s *oauth.Settings, v string) { s.Microsoft.Endpoints.UserInfoURL = v },
	},
	{
		provider: oauth.ProviderApple,
		field:    "AuthorizeURL",
		variable: OAuthAppleAuthorizeURLVar,
		assign:   func(s *oauth.Settings, v string) { s.Apple.Endpoints.AuthorizeURL = v },
	},
	{
		provider: oauth.ProviderApple,
		field:    "TokenURL",
		variable: OAuthAppleTokenURLVar,
		assign:   func(s *oauth.Settings, v string) { s.Apple.Endpoints.TokenURL = v },
	},
}

// MFAEncryptionKey returns the configured key, or ErrNoMFAEncryptionKey.
//
// The decoding is base64url and then a length check, and BOTH failures are startup
// errors. The length check belongs here rather than at the cipher because an
// operator who pasted a 16-byte key has configured half the entropy they think they
// have, and quietly stretching it would hide that until the day it matters.
func (c Config) MFAEncryptionKey() ([]byte, error) {
	if len(c.MFAEncryptionKeyValue) == 0 {
		return nil, ErrNoMFAEncryptionKey
	}
	if len(c.MFAEncryptionKeyValue) != 32 {
		return nil, fmt.Errorf("%w: it decodes to %d bytes, want exactly 32",
			ErrInvalidMFA, len(c.MFAEncryptionKeyValue))
	}
	return c.MFAEncryptionKeyValue, nil
}

// MFAIssuer is the label an authenticator app displays next to the entry.
//
// The default is applied HERE as well as in Load, so a Config written as a literal —
// in a test, or in a one-off tool — still names something. An authenticator app
// showing a blank account is a support ticket, and Load is not the only way to
// build a Config.
func (c Config) MFAIssuer() string {
	if c.MFAIssuerLabel == "" {
		return DefaultMFAIssuer
	}
	return c.MFAIssuerLabel
}

// MFAEncryptionKeyConfigured reports whether this deployment has a usable key,
// without revealing anything about it. main uses it to decide whether to mount the
// MFA management routes.
func (c Config) MFAEncryptionKeyConfigured() bool {
	return len(c.MFAEncryptionKeyValue) == 32
}

// OIDCEnabled reports whether the OIDC surface is configured.
//
// One boolean rather than three checks at every use, because the decision is
// genuinely one thing: either this process is an OpenID Connect provider or it is
// not. A process with an unset OIDC_ISSUER serves its /v1 surface and its probes
// and nothing else, and the routes are absent rather than present-and-500 — the
// same rule WithAuth and WithTenancy already follow for a missing DATABASE_URL.
//
// IT DOES NOT CHECK OIDCLoginUIURL, and that is not an oversight: a Config from
// Load with the three above set and the login UI unset never exists, because
// loadOIDC refuses it. A Config built as a literal can, and `buildOIDC` hands
// that one to oidc.NewProvider, which refuses it too — so the check a caller
// would want is a construction failure rather than a second boolean here.
func (c Config) OIDCEnabled() bool {
	return c.OIDCIssuer != "" && c.OIDCSigningKey != "" && c.OIDCKeyID != ""
}

// CourierToken returns the service credential, or ErrNoCourierToken.
//
// The split sentinel matters at the one place it is used: `main` treats "absent"
// as a deployment with no mail path and mounts `recovery.Unavailable{}`, and treats
// "present and unreadable" as a startup failure. Those are opposite behaviors and
// an operator who cannot tell them apart from the log has been told nothing.
func (c Config) CourierToken() (string, error) {
	if c.CourierTokenValue == "" {
		return "", ErrNoCourierToken
	}
	return c.CourierTokenValue, nil
}

// CourierEnabled reports whether this deployment can send a message.
//
// One boolean rather than a pile of checks at the use site, because the decision is
// one thing — either this process has a mail path or it does not — and a caller
// that checked the fields itself could get a combination this service does not
// allow.
//
// THE TEMPLATE CHECK IS `len(LinkTemplates) > 0` AND NOT "every purpose has one",
// and the difference is deliberate. `Load` refuses a courier block that does not
// resolve a template for every purpose it can configure one for, so a Config from
// `Load` with a base URL and a token has a complete set — and the completeness of
// anything else is enforced where the links are rendered, in
// `courier.NewRecoveryMailer`, which refuses a purpose with no template rather than
// substituting another purpose's.
func (c Config) CourierEnabled() bool {
	return c.CourierBaseURL != "" && c.CourierTokenValue != "" &&
		len(c.LinkTemplates) > 0 && c.InvitationLinkTemplate != ""
}

// LinkTemplateFor reports the template a purpose resolved to, or "" for a purpose
// this deployment configured nothing for.
//
// It exists so a caller reads the RESOLVED value — the one that will actually be
// rendered — rather than reaching for the default and applying the fallback itself,
// which is how a second, subtly different answer to "where does this link point"
// gets written.
func (c Config) LinkTemplateFor(purpose recovery.Purpose) string {
	return c.LinkTemplates[purpose]
}

// LinkTemplateVariable names the environment variable that configures a purpose's
// link.
//
// IT IS EXPORTED FOR THE DRIFT CHECK and not for convenience. `internal/courier`
// knows which messages it can deliver and this package knows which variables name
// them, and nothing in the type system joins the two — so a purpose with a variable
// nobody renders, and a message with no variable at all, are both reachable by
// editing one map. `internal/courier`'s test walks both directions through this
// function, which is cheaper and less fragile than either side reading the other's
// source.
func LinkTemplateVariable(purpose recovery.Purpose) (string, bool) {
	variable, ok := linkTemplateVariables[purpose]
	return variable, ok
}

// LinkTemplatePurposes lists the purposes this deployment has a link for, in a
// stable order.
//
// A map's iteration order is random, so a startup log built from one would print a
// different line order on every restart and a diff of two log excerpts would be
// meaningless.
func (c Config) LinkTemplatePurposes() []recovery.Purpose {
	purposes := make([]recovery.Purpose, 0, len(c.LinkTemplates))
	for purpose := range c.LinkTemplates {
		purposes = append(purposes, purpose)
	}
	slices.Sort(purposes)
	return purposes
}

// LinkPurposesUsingTheDefault reports the purposes whose link came from
// RECOVERY_LINK_TEMPLATE rather than from a variable of their own.
//
// # WHAT THE CALLER DOES WITH IT, AND WHY IT IS A QUERY AND NOT A FIELD
//
// `buildMailer` warns when this is not empty, because an unmigrated deployment's
// verification link points at its reset screen and nothing else in the process can
// see that. The comparison is on the VALUE rather than on "was the variable set",
// so what the warning says — "these purposes resolve to RECOVERY_LINK_TEMPLATE" —
// stays true for a deployment that set both variables to the same string. A warning
// that is occasionally redundant is a better trade than one that is occasionally
// wrong about a state it is describing as fact.
func (c Config) LinkPurposesUsingTheDefault() []recovery.Purpose {
	if c.DefaultLinkTemplate == "" {
		return nil
	}
	var shared []recovery.Purpose
	for _, purpose := range c.LinkTemplatePurposes() {
		if c.LinkTemplates[purpose] == c.DefaultLinkTemplate {
			shared = append(shared, purpose)
		}
	}
	return shared
}

// SignupSigningKey returns the configured key, or ErrNoSignupSigningKey.
//
// The split sentinel matters for the same reason ErrNoMFAEncryptionKey is
// distinct from ErrInvalidMFA: the two lead to different places. Here, though,
// BOTH are startup failures — the distinction is only in the message an
// operator reads. "Not configured" names the variable to set; "invalid" names
// the value to fix. A caller that cannot tell them apart has been told one
// thing when the fix is the other.
func (c Config) SignupSigningKey() ([]byte, error) {
	if len(c.SignupSigningKeyValue) == 0 {
		return nil, ErrNoSignupSigningKey
	}
	if len(c.SignupSigningKeyValue) != 32 {
		return nil, fmt.Errorf("%w: it decodes to %d bytes, want exactly 32",
			ErrInvalidSignupSigningKey, len(c.SignupSigningKeyValue))
	}
	return c.SignupSigningKeyValue, nil
}

// Load reads the environment through lookup and returns a validated Config.
//
// A nil lookup means "no environment": the defaults apply. Values that are
// present but invalid are errors rather than silent fallbacks, so a typo in a
// deployment manifests as a startup failure and not as surprising behavior.
func Load(lookup Lookup) (Config, error) {
	if lookup == nil {
		lookup = func(string) (string, bool) { return "", false }
	}

	cfg := Config{
		Port:        DefaultPort,
		LogLevel:    DefaultLogLevel,
		DatabaseURL: lookupValue(lookup, "DATABASE_URL"),
	}

	if port, ok := lookup("PORT"); ok {
		cfg.Port = port
	}
	if err := cfg.validatePort(); err != nil {
		return Config{}, err
	}

	if level, ok := lookup("LOG_LEVEL"); ok {
		cfg.LogLevel = strings.ToLower(strings.TrimSpace(level))
	}
	if err := cfg.validateLogLevel(); err != nil {
		return Config{}, err
	}

	if err := cfg.validateDatabaseURL(); err != nil {
		return Config{}, err
	}

	cfg.NATSURL = lookupValue(lookup, NATSURLVar)

	if err := cfg.loadOIDC(lookup); err != nil {
		return Config{}, err
	}

	if err := cfg.loadMFA(lookup); err != nil {
		return Config{}, err
	}

	if err := cfg.loadCourier(lookup); err != nil {
		return Config{}, err
	}

	if err := cfg.loadOAuth(lookup); err != nil {
		return Config{}, err
	}

	if err := cfg.loadRateLimit(lookup); err != nil {
		return Config{}, err
	}

	if err := cfg.loadAgentClaimUI(lookup); err != nil {
		return Config{}, err
	}

	if _, ok := lookup(RequireEmailVerificationVar); ok {
		switch strings.ToLower(strings.TrimSpace(lookupValue(lookup, RequireEmailVerificationVar))) {
		case "true", "1", "yes":
			cfg.RequireEmailVerification = true
		case "false", "0", "no", "":
		default:
			return Config{}, fmt.Errorf("%s is %q, want true or false",
				RequireEmailVerificationVar, lookupValue(lookup, RequireEmailVerificationVar))
		}
	}

	if err := cfg.loadSignupSigningKey(lookup); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// OAuthEnabled reports whether the social-login routes should be mounted.
//
// It asks the Settings rather than re-deriving "is there a provider", for the reason
// the whole OAuth field is a value and not six strings: the answer to "is this
// deployment offering social sign-in" belongs to the package that knows what a
// provider is. A Config built as a literal with a half-configured provider still
// answers false here, and `Load` — which validates — is what keeps that from being a
// state a real process can reach.
func (c Config) OAuthEnabled() bool { return c.OAuth.Enabled() }

// NATSEnabled reports whether the outbox publisher loop should run.
//
// One boolean rather than a check at the use site, because the decision is one
// thing — either this process has a bus or it does not — and the answer is
// load-bearing in both directions: set means the loop runs and events leave the
// table, unset means they accumulate in it. A caller that checked the field
// itself could get that combination wrong in a way that reads as a feature.
func (c Config) NATSEnabled() bool { return c.NATSURL != "" }

func (c *Config) loadOAuth(lookup Lookup) error {
	appleInputs := oauth.AppleSecretInputs{
		ServicesID: lookupValue(lookup, OAuthAppleClientIDVar),
		TeamID:     lookupValue(lookup, OAuthAppleTeamIDVar),
		KeyID:      lookupValue(lookup, OAuthAppleKeyIDVar),
		PrivateKey: lookupValue(lookup, OAuthApplePrivateKeyVar),
	}
	appleSecret, err := oauth.MintAppleClientSecret(appleInputs)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidOAuth, err)
	}

	c.OAuth = oauth.Settings{
		RedirectBaseURL: lookupValue(lookup, OAuthRedirectBaseURLVar),
		EncryptionKey:   lookupValue(lookup, OAuthEncryptionKeyVar),
		Google: oauth.ProviderSettings{
			ClientID:     lookupValue(lookup, OAuthGoogleClientIDVar),
			ClientSecret: lookupValue(lookup, OAuthGoogleClientSecretVar),
		},
		GitHub: oauth.ProviderSettings{
			ClientID:     lookupValue(lookup, OAuthGitHubClientIDVar),
			ClientSecret: lookupValue(lookup, OAuthGitHubClientSecretVar),
		},
		Microsoft: oauth.ProviderSettings{
			ClientID:     lookupValue(lookup, OAuthMicrosoftClientIDVar),
			ClientSecret: lookupValue(lookup, OAuthMicrosoftClientSecretVar),
		},
		Apple: oauth.ProviderSettings{
			ClientID:     appleInputs.ServicesID,
			ClientSecret: appleSecret,
		},
	}
	for _, v := range oauthEndpointVars {
		v.assign(&c.OAuth, lookupValue(lookup, v.variable))
	}

	if err := c.OAuth.Validate(); err != nil {
		if variable := oauthEndpointVariable(err); variable != "" {
			return fmt.Errorf("%w: %s: %w", ErrInvalidOAuth, variable, err)
		}
		return fmt.Errorf("%w: %w", ErrInvalidOAuth, err)
	}
	return nil
}

func oauthEndpointVariable(err error) string {
	var endpointErr *oauth.EndpointError
	if !errors.As(err, &endpointErr) {
		return ""
	}
	for _, v := range oauthEndpointVars {
		if v.provider == endpointErr.Provider && v.field == endpointErr.Field {
			return v.variable
		}
	}
	return ""
}

func (c *Config) loadMFA(lookup Lookup) error {
	c.MFAIssuerLabel = DefaultMFAIssuer
	if issuer := lookupValue(lookup, "MFA_ISSUER"); issuer != "" {
		c.MFAIssuerLabel = issuer
	}

	encoded := lookupValue(lookup, "MFA_ENCRYPTION_KEY")
	if encoded == "" {
		return nil
	}

	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("%w: it is not base64url: %w", ErrInvalidMFA, err)
	}
	c.MFAEncryptionKeyValue = decoded
	return nil
}

const defaultLinkTemplateVariable = "RECOVERY_LINK_TEMPLATE"

var linkTemplateVariables = map[recovery.Purpose]string{
	recovery.PurposePasswordReset: "PASSWORD_RESET_LINK_TEMPLATE",
	recovery.PurposeVerifyEmail:   "EMAIL_VERIFICATION_LINK_TEMPLATE",
	recovery.PurposeEmailChange:   "EMAIL_CHANGE_LINK_TEMPLATE",
}

func (c *Config) loadCourier(lookup Lookup) error {
	baseURL := lookupValue(lookup, "COURIER_BASE_URL")
	token := lookupValue(lookup, "COURIER_TOKEN")

	present := 0
	for _, value := range []string{baseURL, token} {
		if value != "" {
			present++
		}
	}
	if present == 0 {
		if configured, variable := anyLinkTemplateConfigured(lookup); configured {
			return fmt.Errorf("%w: %s is set but COURIER_BASE_URL and COURIER_TOKEN are "+
				"not, so the link has nowhere to go: a deployment with a link template "+
				"and no mail path believes it can send, and every route that needs to "+
				"will answer 503", ErrInvalidCourier, variable)
		}
		return nil
	}
	if present != 2 {
		return fmt.Errorf("%w: COURIER_BASE_URL and COURIER_TOKEN must both be set, or "+
			"neither of them: a base URL with no credential sends every message as an "+
			"anonymous caller and courier answers 401", ErrInvalidCourier)
	}

	if err := validateMailBaseURL(baseURL); err != nil {
		return err
	}
	templates, err := resolveLinkTemplates(lookup)
	if err != nil {
		return err
	}
	invitationTemplate, err := resolveInvitationLinkTemplate(lookup)
	if err != nil {
		return err
	}

	c.CourierBaseURL = baseURL
	c.CourierTokenValue = token
	c.LinkTemplates = templates
	c.DefaultLinkTemplate = lookupValue(lookup, defaultLinkTemplateVariable)
	c.InvitationLinkTemplate = invitationTemplate
	return nil
}

const (
	defaultRateLimitWindow          = time.Minute
	defaultRateLimitSignup          = 10
	defaultRateLimitSignin          = 20
	defaultRateLimitSignupTimestamp = 30
	defaultRateLimitRecovery        = 5
	defaultRateLimitAgentRegister   = 5
)

func (c *Config) loadRateLimit(lookup Lookup) error {
	c.RateLimit = RateLimit{
		Window:          defaultRateLimitWindow,
		Signup:          defaultRateLimitSignup,
		Signin:          defaultRateLimitSignin,
		SignupTimestamp: defaultRateLimitSignupTimestamp,
		Recovery:        defaultRateLimitRecovery,
		AgentRegister:   defaultRateLimitAgentRegister,
	}

	if err := c.loadRateLimitDuration(lookup, RateLimitWindowVar, &c.RateLimit.Window); err != nil {
		return err
	}
	if err := c.loadRateLimitCount(lookup, RateLimitSignupVar, &c.RateLimit.Signup); err != nil {
		return err
	}
	if err := c.loadRateLimitCount(lookup, RateLimitSigninVar, &c.RateLimit.Signin); err != nil {
		return err
	}
	if err := c.loadRateLimitCount(lookup, RateLimitSignupTimestampVar, &c.RateLimit.SignupTimestamp); err != nil {
		return err
	}
	if err := c.loadRateLimitCount(lookup, RateLimitAgentRegisterVar, &c.RateLimit.AgentRegister); err != nil {
		return err
	}
	return c.loadRateLimitCount(lookup, RateLimitRecoveryVar, &c.RateLimit.Recovery)
}

// AgentClaimUIURLVar is the variable naming the claim screen base.
const AgentClaimUIURLVar = "AGENT_CLAIM_UI_URL"

// ErrInvalidAgentClaimUI means the claim screen base is present and is not an
// address a browser can be sent to with a 256-bit link on it.
var ErrInvalidAgentClaimUI = errors.New("invalid AGENT_CLAIM_UI_URL")

func (c *Config) loadAgentClaimUI(lookup Lookup) error {
	raw := strings.TrimSpace(lookupValue(lookup, AgentClaimUIURLVar))
	c.AgentClaimUIURL = raw
	if raw == "" {
		return nil
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: it is not a URL: %w", ErrInvalidAgentClaimUI, err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("%w: its scheme is %q, want http or https", ErrInvalidAgentClaimUI, parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%w: it has no host, so there is nowhere to open a claim link", ErrInvalidAgentClaimUI)
	}
	if parsed.RawQuery != "" {
		return fmt.Errorf("%w: it carries a query (%q); the claim link path is appended to a clean "+
			"base, and a configured query would travel in every claim URL. Put a path, not a query, in the base",
			ErrInvalidAgentClaimUI, parsed.RawQuery)
	}
	if parsed.Fragment != "" {
		return fmt.Errorf("%w: it carries a fragment, which is not sent to a server", ErrInvalidAgentClaimUI)
	}
	if parsed.User != nil {
		return fmt.Errorf("%w: it has a userinfo section, so the host in it is not the host it resolves to", ErrInvalidAgentClaimUI)
	}
	return nil
}

func (c *Config) loadRateLimitDuration(lookup Lookup, variable string, target *time.Duration) error {
	value := lookupValue(lookup, variable)
	if value == "" {
		return nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("%w: %s is %q, want a duration like \"1m\" or \"30s\"",
			ErrInvalidRateLimit, variable, value)
	}
	if d <= 0 {
		return fmt.Errorf("%w: %s is %q, want a positive duration",
			ErrInvalidRateLimit, variable, value)
	}
	*target = d
	return nil
}

func (c *Config) loadRateLimitCount(lookup Lookup, variable string, target *int) error {
	value := lookupValue(lookup, variable)
	if value == "" {
		return nil
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return fmt.Errorf("%w: %s is %q, want a whole number",
			ErrInvalidRateLimit, variable, value)
	}
	if n <= 0 {
		return fmt.Errorf("%w: %s is %d, want a positive number (0 is not unlimited)",
			ErrInvalidRateLimit, variable, n)
	}
	*target = n
	return nil
}

const invitationLinkTemplateVariable = "INVITATION_LINK_TEMPLATE"

func resolveInvitationLinkTemplate(lookup Lookup) (string, error) {
	variable := invitationLinkTemplateVariable
	raw := lookupValue(lookup, variable)
	if raw == "" {
		return "", fmt.Errorf("%w: %s is not set, and a deployment that can send mail "+
			"needs it: every invitation is mailed with a link to the accept "+
			"screen, and without this variable each one would be mailed with "+
			"nothing to click. Set %s to the screen that redeems an invitation",
			ErrInvalidCourier, variable, variable)
	}
	if err := validateLinkTemplate(variable, raw); err != nil {
		return "", err
	}
	return raw, nil
}

func anyLinkTemplateConfigured(lookup Lookup) (bool, string) {
	if value := lookupValue(lookup, defaultLinkTemplateVariable); value != "" {
		return true, defaultLinkTemplateVariable
	}
	if value := lookupValue(lookup, invitationLinkTemplateVariable); value != "" {
		return true, invitationLinkTemplateVariable
	}
	for _, variable := range sortedLinkTemplateVariables() {
		if value := lookupValue(lookup, variable); value != "" {
			return true, variable
		}
	}
	return false, ""
}

func sortedLinkTemplateVariables() []string {
	variables := make([]string, 0, len(linkTemplateVariables))
	for _, variable := range linkTemplateVariables {
		variables = append(variables, variable)
	}
	slices.Sort(variables)
	return variables
}

func sortedPurposes(table map[recovery.Purpose]string) []recovery.Purpose {
	purposes := make([]recovery.Purpose, 0, len(table))
	for purpose := range table {
		purposes = append(purposes, purpose)
	}
	slices.Sort(purposes)
	return purposes
}

func resolveLinkTemplates(lookup Lookup) (map[recovery.Purpose]string, error) {
	defaultTemplate := lookupValue(lookup, defaultLinkTemplateVariable)
	if defaultTemplate != "" {
		if err := validateLinkTemplate(defaultLinkTemplateVariable, defaultTemplate); err != nil {
			return nil, err
		}
	}

	configured := 0
	for _, variable := range sortedLinkTemplateVariables() {
		if lookupValue(lookup, variable) != "" {
			configured++
		}
	}
	if configured == 0 && defaultTemplate == "" {
		return nil, fmt.Errorf("%w: a deployment that can send mail needs at least one link "+
			"template: set %s to the screen that redeems a password reset, %s to the "+
			"screen that redeems an address confirmation, %s to the screen that redeems "+
			"an email-change confirmation, or %s to apply to every purpose. Without one "+
			"a message arrives with nothing to click",
			ErrInvalidCourier,
			linkTemplateVariables[recovery.PurposePasswordReset],
			linkTemplateVariables[recovery.PurposeVerifyEmail],
			linkTemplateVariables[recovery.PurposeEmailChange],
			defaultLinkTemplateVariable)
	}

	out := make(map[recovery.Purpose]string, len(linkTemplateVariables))
	for _, purpose := range sortedPurposes(linkTemplateVariables) {
		variable := linkTemplateVariables[purpose]
		value := lookupValue(lookup, variable)
		if value != "" {
			if err := validateLinkTemplate(variable, value); err != nil {
				return nil, err
			}
			out[purpose] = value
			continue
		}
		if defaultTemplate == "" {
			return nil, fmt.Errorf("%w: %s is not set and neither is %s, so a %s link has "+
				"nowhere to point and the mail would carry a button that goes nowhere. "+
				"Set %s to the screen that redeems one, or set %s to apply to every "+
				"purpose", ErrInvalidCourier, variable, defaultLinkTemplateVariable,
				purpose, variable, defaultLinkTemplateVariable)
		}
		out[purpose] = defaultTemplate
	}
	return out, nil
}

func validateMailBaseURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("%w: COURIER_BASE_URL is not a URL: %w", ErrInvalidCourier, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%w: COURIER_BASE_URL scheme is %q, want http or https",
			ErrInvalidCourier, parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%w: COURIER_BASE_URL has no host", ErrInvalidCourier)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%w: COURIER_BASE_URL has a query or a fragment", ErrInvalidCourier)
	}
	return nil
}

func validateLinkTemplate(variable, raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("%w: %s is empty", ErrInvalidCourier, variable)
	}
	if !strings.Contains(trimmed, recoveryTokenPlaceholder) {
		return fmt.Errorf("%w: %s has no %s in it, so a link would carry no token and the "+
			"reader would reach a screen with nothing to redeem", ErrInvalidCourier,
			variable, recoveryTokenPlaceholder)
	}
	probe := strings.ReplaceAll(trimmed, recoveryTokenPlaceholder, "6f5d4c3b-2a19-4e8f-9c07-1b2d3e4f5061")
	parsed, err := url.Parse(probe)
	if err != nil {
		return fmt.Errorf("%w: %s is not a URL: %w", ErrInvalidCourier, variable, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%w: %s scheme is %q, want http or https",
			ErrInvalidCourier, variable, parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%w: %s has no host", ErrInvalidCourier, variable)
	}
	if parsed.Fragment != "" {
		return fmt.Errorf("%w: %s has a fragment; a mail client "+
			"does not send one to a server", ErrInvalidCourier, variable)
	}
	if parsed.User != nil {
		return fmt.Errorf("%w: %s has a userinfo section", ErrInvalidCourier, variable)
	}
	return nil
}

const recoveryTokenPlaceholder = "{token}"

func (c *Config) loadOIDC(lookup Lookup) error {
	issuer := lookupValue(lookup, "OIDC_ISSUER")
	key := lookupValue(lookup, "OIDC_SIGNING_KEY")
	keyID := lookupValue(lookup, "OIDC_SIGNING_KEY_ID")
	loginUI := lookupValue(lookup, oidc.LoginUIEnvVar)

	present := 0
	for _, value := range []string{issuer, key, keyID} {
		if value != "" {
			present++
		}
	}
	switch {
	case present == 0:
		if _, ok := lookup("OIDC_ALLOW_INSECURE"); ok && lookupValue(lookup, "OIDC_ALLOW_INSECURE") != "" {
			return fmt.Errorf("%w: OIDC_ALLOW_INSECURE is set but there is no OIDC_ISSUER to apply it to", ErrInvalidOIDC)
		}
		if loginUI != "" {
			return fmt.Errorf("%w: %s is set but there is no OIDC_ISSUER, OIDC_SIGNING_KEY and "+
				"OIDC_SIGNING_KEY_ID for it to apply to", ErrInvalidOIDC, oidc.LoginUIEnvVar)
		}
		return nil
	case present != 3:
		return fmt.Errorf("%w: OIDC_ISSUER, OIDC_SIGNING_KEY and OIDC_SIGNING_KEY_ID must all be set, or none of them", ErrInvalidOIDC)
	}

	if err := oidc.ValidateLoginUIURL(loginUI); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrInvalidOIDC, oidc.LoginUIEnvVar, err)
	}

	parsed, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("%w: OIDC_ISSUER is not a URL: %w", ErrInvalidOIDC, err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("%w: OIDC_ISSUER scheme is %q, want https", ErrInvalidOIDC, parsed.Scheme)
	}

	allowInsecure := false
	if _, ok := lookup("OIDC_ALLOW_INSECURE"); ok {
		value := lookupValue(lookup, "OIDC_ALLOW_INSECURE")
		switch strings.ToLower(value) {
		case "true", "1", "yes":
			allowInsecure = true
		case "false", "0", "no", "":
		default:
			return fmt.Errorf("%w: OIDC_ALLOW_INSECURE is %q, want true or false", ErrInvalidOIDC, value)
		}
	}
	if parsed.Scheme == "http" && !allowInsecure {
		return fmt.Errorf("%w: set OIDC_ALLOW_INSECURE=true to use it; every verifier on the platform fetches the "+
			"JWKS over this scheme, so an http issuer is only safe on localhost", ErrInsecureOIDCIssuer)
	}

	c.OIDCIssuer = strings.TrimSuffix(issuer, "/")
	c.OIDCSigningKey = key
	c.OIDCKeyID = keyID
	c.OIDCAllowInsecure = allowInsecure
	c.OIDCLoginUIURL = loginUI
	return nil
}

func (c *Config) loadSignupSigningKey(lookup Lookup) error {
	encoded := lookupValue(lookup, "SIGNUP_SIGNING_KEY")
	if encoded == "" {
		return ErrNoSignupSigningKey
	}

	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("%w: it is not base64url: %w", ErrInvalidSignupSigningKey, err)
	}
	if len(decoded) != 32 {
		return fmt.Errorf("%w: it decodes to %d bytes, want exactly 32",
			ErrInvalidSignupSigningKey, len(decoded))
	}
	c.SignupSigningKeyValue = decoded
	return nil
}

// Addr is the address the HTTP server listens on.
func (c Config) Addr() string {
	return ":" + c.Port
}

// SlogLevel maps the configured LOG_LEVEL onto a slog level.
func (c Config) SlogLevel() slog.Level {
	var level slog.Level
	if err := level.UnmarshalText([]byte(c.LogLevel)); err != nil {
		return slog.LevelInfo
	}
	return level
}

func (c Config) validatePort() error {
	port, err := strconv.Atoi(c.Port)
	if err != nil {
		return fmt.Errorf("%w: %q is not a number", ErrInvalidPort, c.Port)
	}
	if port < minPort || port > maxPort {
		return fmt.Errorf("%w: %d is outside %d-%d", ErrInvalidPort, port, minPort, maxPort)
	}
	return nil
}

func (c Config) validateLogLevel() error {
	var level slog.Level
	if err := level.UnmarshalText([]byte(c.LogLevel)); err != nil {
		return fmt.Errorf("%w: %q is not one of debug, info, warn, error", ErrInvalidLogLevel, c.LogLevel)
	}
	return nil
}

func (c Config) validateDatabaseURL() error {
	if c.DatabaseURL == "" {
		return nil
	}
	parsed, err := url.Parse(c.DatabaseURL)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidDatabaseURL, err)
	}
	if parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" {
		return fmt.Errorf("%w: scheme %q is not postgres", ErrInvalidDatabaseURL, parsed.Scheme)
	}
	return nil
}

func lookupValue(lookup Lookup, key string) string {
	value, _ := lookup(key)
	return strings.TrimSpace(value)
}
