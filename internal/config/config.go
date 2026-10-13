// Package config loads the service configuration from the environment.
//
// Configuration is read once at startup and never mutated afterwards: the
// Config value is the single source of truth threaded through the process.
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

	"github.com/cafaye/identity/internal/oauth"
	"github.com/cafaye/identity/internal/oidc"
	"github.com/cafaye/identity/internal/recovery"
)

const (
	// DefaultPort is used when PORT is unset.
	DefaultPort = "8080"
	// DefaultLogLevel is used when LOG_LEVEL is unset.
	DefaultLogLevel = "info"

	minPort = 1
	maxPort = 65535
)

// Lookup mirrors os.LookupEnv: it returns the value for key and whether the
// key was present. Injecting it keeps Load testable without mutating the
// process environment.
type Lookup func(key string) (string, bool)

// Errors returned by Load. They are wrapped with context, so callers should
// match them with errors.Is.
var (
	ErrInvalidPort        = errors.New("invalid PORT")
	ErrInvalidLogLevel    = errors.New("invalid LOG_LEVEL")
	ErrInvalidDatabaseURL = errors.New("invalid DATABASE_URL")

	// ErrInvalidOIDC means the OIDC configuration is present and incomplete, or
	// present and unreadable. It is a startup failure rather than a degraded mode
	// for the reason the whole block is: a provider with an issuer and no key can
	// sign nothing, and one with a key and no issuer has no `iss` to put in a
	// token. Both would otherwise be discovered as a 500 by the first user to try
	// to sign in.
	ErrInvalidOIDC = errors.New("invalid OIDC configuration")

	// ErrInsecureOIDCIssuer means the issuer is http and OIDC_ALLOW_INSECURE was
	// not set. It is its own sentinel so an operator reading a startup log is told
	// the one thing they have to do, rather than being told their configuration is
	// invalid.
	ErrInsecureOIDCIssuer = errors.New("OIDC_ISSUER is http")

	// ErrInvalidMFA means MFA_ENCRYPTION_KEY is present and unreadable. A startup
	// failure rather than a degraded mode, for the reason the OIDC block is: a
	// deployment whose key does not decode cannot seal a TOTP secret, so every
	// enrolled user would be locked out at their second factor — and would find
	// out at login, in front of somebody who thought they had a second factor.
	ErrInvalidMFA = errors.New("invalid MFA_ENCRYPTION_KEY")

	// ErrNoMFAEncryptionKey means MFA_ENCRYPTION_KEY is not set at all, which is a
	// supported state: a deployment with no second factor. It is a distinct
	// sentinel from ErrInvalidMFA because the two lead to completely different
	// places — one starts up, the other mounts a reduced surface and logs why.
	ErrNoMFAEncryptionKey = errors.New("MFA_ENCRYPTION_KEY is not configured")

	// ErrInvalidCourier means the courier block is present and unreadable: a base
	// URL that is not one, or a link template that cannot produce a working link for
	// the purpose it was configured for — including a purpose with no template at
	// all. A startup failure rather than a degraded mode, for the reason the OIDC and
	// MFA blocks are — a deployment whose mail configuration is wrong cannot send a
	// password reset or an address confirmation, and it would find out from a user
	// who never got one, in front of somebody waiting on a link.
	ErrInvalidCourier = errors.New("invalid courier configuration")

	// ErrInvalidOAuth means the social-login block is present and incomplete: a
	// provider with a client id and no secret, or a deployment that configured a
	// redirect base without an encryption key. The startup-failure rule is the
	// courier one — a half-configured OAuth provider produces callbacks that fail
	// at the provider, in front of a user who was told the button would work,
	// rather than at boot where an operator could see it.
	//
	// The rules themselves belong to oauth.Settings.Validate and are not
	// restated here; a second copy is a second thing to forget to update. Every
	// message this produces names a variable, because Validate's do and the
	// alternative sends an operator looking through six variables instead of one.
	ErrInvalidOAuth = errors.New("invalid OAuth configuration")

	// ErrNoCourierToken means COURIER_TOKEN is not set at all, which is a
	// SUPPORTED state: a deployment with no mail path. It is a distinct sentinel
	// from ErrInvalidCourier for the same reason ErrNoMFAEncryptionKey is distinct
	// from ErrInvalidMFA — one starts up and mounts a reduced surface, the other
	// refuses to start, and conflating them would either refuse to boot a
	// legitimate deployment or silently boot a broken one.
	ErrNoCourierToken = errors.New("COURIER_TOKEN is not configured")

	// ErrNoSignupSigningKey means SIGNUP_SIGNING_KEY is not set at all. Unlike
	// every other sentinel above this is a STARTUP FAILURE rather than a
	// supported state, and the difference is the reason it exists: spam
	// protection is not a feature a deployment enables or skips. A process
	// without the key would boot, serve its /v1 surface, and verify nothing —
	// a signup form with no defense, discovered by a bot rather than by a boot
	// log. The check must not vanish where a feature is not configured, so
	// there is no configuration in which this process starts without it.
	ErrNoSignupSigningKey = errors.New("SIGNUP_SIGNING_KEY is not configured")

	// ErrInvalidSignupSigningKey means SIGNUP_SIGNING_KEY is present and
	// unreadable: not base64url, or not 32 bytes once decoded. A startup
	// failure for the reason ErrInvalidMFA is — an operator who pasted a
	// 16-byte key has configured half the entropy they think they have, and a
	// timestamp signed under a short key is a timestamp anybody can forge.
	ErrInvalidSignupSigningKey = errors.New("invalid SIGNUP_SIGNING_KEY")

	// ErrInvalidRateLimit means a RATE_LIMIT_* variable is present and
	// unparseable, or parses to a non-positive number. A startup failure rather
	// than a fallback, for the reason the whole config package follows: a
	// deployment that believes it has a limit and has one that does not exist
	// is worse than one that refuses to start. The zero case is the one that
	// reads as harsh — "I set 0 and the process would not boot" — and it is
	// the point: 0 means "unlimited" everywhere else in computing, and this
	// service does not offer unlimited on the auth surface. A typo for 0 is a
	// typo the operator should meet at boot, not a silent disabling of the
	// only control that bounds a spray.
	ErrInvalidRateLimit = errors.New("invalid RATE_LIMIT_* configuration")
)

// DefaultMFAIssuer is what an authenticator app displays next to the entry when
// MFA_ISSUER is unset.
//
// "cafaye identity", with a space rather than a hyphen, because that is what a
// person reads in a phone's authenticator next to the six digits and the clock.
// It is also what the provisioning URI's issuer parameter carries, so changing it
// changes what every future enrollment shows and nothing about the credentials
// already confirmed.
const DefaultMFAIssuer = "cafaye identity"

// Config is the fully validated service configuration.
type Config struct {
	// Port is the TCP port the HTTP server binds to.
	Port string
	// DatabaseURL is the Postgres connection string. Empty means "no database
	// configured", which is valid in v0 and makes readiness checks a no-op.
	DatabaseURL string
	// LogLevel is one of debug, info, warn, error.
	LogLevel string

	// The OIDC provider's configuration. All three are required together or not
	// at all; see OIDCEnabled.
	//
	// OIDCSigningKey is a PEM-encoded RSA private key, read from the
	// environment rather than from a file so that the secret is whatever the
	// deployment's secret store already is. It is never logged and never
	// rendered in a response.
	OIDCIssuer     string
	OIDCSigningKey string
	OIDCKeyID      string
	// OIDCAllowInsecure permits an http issuer. It exists for `localhost` and for
	// a compose stack, and it is a field rather than a behavior because "this
	// deployment is local" is a fact about the deployment and guessing it from
	// the hostname would be a security decision made by a string match.
	OIDCAllowInsecure bool

	// OIDCLoginUIURL is where a browser goes to authenticate. `identity` renders no
	// HTML, so the sign-in form is a page in another service and this is its
	// address. It is REQUIRED whenever the three variables above are configured,
	// and there is no default: see internal/oidc/loginui.go for why a provider that
	// cannot send a browser anywhere to sign in is a startup failure rather than a
	// degraded mode, and why a compiled-in default would couple two services that
	// share no release train.
	OIDCLoginUIURL string

	// AgentClaimUIURL is where a HUMAN opens the claim link a registered agent is
	// handed (the `/agents/claim/[token]` screen on the website). It is the agent
	// flow's mirror of OIDCLoginUIURL and for the same structural reason: identity
	// renders no HTML, the screen is another repository's, and a registration that
	// produced no URL would mint a principal nobody can finish claiming. It is read
	// into the agents service (WithClaimUI) and the registration route refuses with
	// 503 rather than minting an unclaimable agent when it is empty. Validated with
	// the same shape rules as the login UI, and it is required only for the agent
	// registration surface rather than at boot, so a deployment that has not turned
	// agents on is not a startup failure. See agents.ClaimUIBaseEnvVar.
	AgentClaimUIURL string

	// MFAEncryptionKeyValue is the raw key a TOTP secret is sealed under, decoded
	// from MFA_ENCRYPTION_KEY. Empty means "this deployment has no second factor",
	// which is a supported state and reduces the surface rather than failing.
	MFAEncryptionKeyValue []byte

	// MFAIssuerLabel is what an authenticator app displays. It is NOT a secret, and
	// changing it is harmless to every credential already confirmed.
	MFAIssuerLabel string

	// The courier block: the platform's mail service, and the only thing that can
	// deliver a recovery message.
	//
	// ALL OF IT IS REQUIRED TOGETHER OR NONE OF IT, for the same all-or-nothing
	// reason the OIDC block is. A base URL with no credential would send every
	// request as an anonymous caller, and courier's answer to that is a 401 on a
	// mail egress; a credential with no base URL is a secret with nowhere to go; and
	// a link template is what turns a token into a link a person can follow, so
	// without one a "sent" reset mail would arrive with nothing to click.
	//
	// The token is never logged and never rendered, and it is read from the
	// environment rather than a file so the secret is whatever the deployment's
	// secret store already is.
	CourierBaseURL    string
	CourierTokenValue string

	// LinkTemplates is where each PURPOSE's link points, resolved at Load: a
	// purpose with a variable of its own gets it, and a purpose without one gets
	// DefaultLinkTemplate.
	//
	// IT IS PER PURPOSE RATHER THAN ONE TEMPLATE FOR EVERYTHING, and the reason is
	// that the two purposes want different SCREENS. A password reset and an address
	// confirmation are finished on different pages of a product, and a link that
	// points at the wrong one is a mail that renders perfectly and sends the reader
	// somewhere useless: a verification token presented to the reset screen is a
	// 404. So a deployment says where each one goes.
	//
	// THE KEY IS `recovery.Purpose` AND NOT A STRING, so that a purpose cannot be
	// misspelled into a template nothing reads. It is the one place this package
	// names a recovery concept, and the dependency runs the right way: `recovery` is
	// a cafaye concept, `internal/courier` is the platform adapter that implements
	// its seam, and neither of them imports this package.
	LinkTemplates map[recovery.Purpose]string

	// DefaultLinkTemplate is the value of RECOVERY_LINK_TEMPLATE, kept separately
	// because it is a different QUESTION from LinkTemplates and the startup log
	// needs the answer to both: what each purpose resolved to, and which of them
	// resolved to the shared default rather than to a variable of their own.
	//
	// IT IS WHAT MAKES EVERY DEPLOYMENT CONFIGURED BEFORE THIS CHANGE STILL BOOT.
	// An unmigrated deployment's verification link therefore still points at
	// whatever its one template says, which is the defect this exists to let a
	// deployment fix — and `buildMailer` says so in a warning rather than leaving an
	// operator to discover it from a user.
	DefaultLinkTemplate string

	// InvitationLinkTemplate is the value of INVITATION_LINK_TEMPLATE, and it is
	// REQUIRED whenever the courier block is wired — see loadCourier.
	//
	// IT IS NOT A RECOVERY PURPOSE AND MUST NOT BECOME ONE: the recovery
	// machinery is keyed by `recovery.Purpose`, a closed set of two, and an
	// invitation is an accounts concept — its token is an invitation token and
	// its screen is the product's accept route. The per-purpose link machinery
	// covers password_reset and verify_email because those are the purposes
	// recovery can deliver; an invitation is delivered here, by this service,
	// because the accept link is built from a token only this process holds.
	//
	// IT HAS NO DEFAULT AND FALLS BACK TO NOTHING, which is the difference from
	// the recovery templates and the whole reason it is a separate variable.
	// The recovery default exists because every deployment in existence already
	// has RECOVERY_LINK_TEMPLATE set; no such promise exists for invitations,
	// because no deployment has ever had a working invite-by-email path to
	// break. And the failure direction is the one identity-24 fixed: an
	// invitation link inheriting the reset template is a mail whose button
	// leads to a screen that cannot redeem it. So a deployment that can send
	// mail and cannot say where invitation links go refuses to start, naming
	// the variable, rather than discovering it at a user's first invite.
	InvitationLinkTemplate string

	// OAuth is the social-login block, read as one `oauth.Settings` rather than as
	// six fields.
	//
	// IT IS A VALUE AND NOT SIX STRINGS because the rules about which combinations
	// make sense belong to the package that consumes them: "a provider needs a base
	// URL and a token key", "half a provider's credentials is a mistake and never an
	// intention" and "an absent provider is a supported state" are all
	// oauth.Settings.Validate, and re-expressing them here would be a second
	// implementation to keep in step with the first. This package reads the
	// environment into the struct and calls Validate.
	//
	// The dependency runs one way: internal/oauth does not import internal/config.
	OAuth oauth.Settings

	// SignupSigningKeyValue is the raw key a signup timestamp is signed and
	// verified under, decoded from SIGNUP_SIGNING_KEY.
	//
	// IT IS ALWAYS PRESENT in a Config that Load accepts, and that is the whole
	// of this field's contract: the one secret this service cannot boot without,
	// because the signed timestamp is the second half of signup bot defense and
	// a deployment that could turn it off would be a deployment whose signup
	// form is undefended. It is read from the environment rather than a file so
	// the secret is whatever the deployment's secret store already is, it is
	// never logged, and it is never rendered in a response.
	//
	// It is 32 bytes because that is the HMAC-SHA256 key length, and a shorter
	// one is refused at Load rather than stretched — the same rule
	// MFA_ENCRYPTION_KEY follows, for the same reason: quietly stretching a
	// short key hides a typo until the day the entropy matters.
	SignupSigningKeyValue []byte

	// NATSURL is the broker the outbox publisher publishes to. Empty means "no
	// broker wired yet", which is a supported state and not an error: the
	// outbox table, the loop and the Publisher interface all exist, and a
	// deployment that has not wired a broker accumulates rows in outbox_events
	// until it does. It is read from the environment rather than from a file
	// because it is a deployment address and not a secret — nothing about it is
	// credential material, and an operator has to be able to read it back off
	// the boot log to confirm which broker their events are going to.
	NATSURL string

	// RateLimit is the request-rate limit block for the unauthenticated auth
	// surface. It is NOT a feature block in the sense OIDC, MFA, courier and
	// OAuth are: those are absent when unconfigured, because they belong to a
	// features a deployment may not have turned on. This one is present by
	// default, because the surface it protects is the one a customer's security
	// review looks at first and an unconfigured deployment must not be an
	// unprotected one.
	//
	// THE LIMITS HAVE DEFAULTS, AND A CONFIGURED ZERO IS A STARTUP ERROR. The
	// two rules together are the whole of the block's contract: a deployment
	// that sets nothing gets the defaults and is protected, and a deployment
	// that sets a limit to 0 — almost certainly a typo for "unlimited", which
	// this service does not offer — fails the boot rather than silently
	// disabling the one control that stands between the auth surface and a
	// spray. See loadRateLimit for the per-variable rules.
	RateLimit RateLimit

	// RequireEmailVerification gates sign-in on a proved address, and it is
	// OFF BY DEFAULT.
	//
	// # WHY OFF IS THE DEFAULT, AND IT IS PARITY
	//
	// The reference this fleet matches — Jumpstart Pro — uses
	// `has_secure_password` and does NOT use Devise's `:confirmable`, so an
	// unverified address can sign in there. Gating sign-in on verification
	// would be a deviation from parity, and a worker who flipped the default
	// would have broken the thing the fleet exists to match. So the default is
	// off, and the behavior is pinned by a test so a successor cannot flip it
	// by accident.
	//
	// # WHAT THE FLAG IS FOR
	//
	// The risk it exists to let an operator close: an address nobody has
	// proved can hold a session. A deployment that wants confirmation-gated
	// sign-in — because it sells to a regulated market, or because it has been
	// through an incident — sets one variable and gets a documented, tested
	// gate. Nobody who does not set it sees any change.
	//
	// # THE REFUSAL IS AFTER THE PASSWORD, AND THAT IS THE SECURITY PROPERTY
	//
	// The check lives in auth's startLogin, after the password is verified, so
	// a caller who is refused has already proved they hold the credential and
	// already knew the account existed. A refusal placed before the password is
	// a one-request existence oracle for every unverified account on the
	// service. See DECISIONS.md D13 for the same ruling on the disabled flag,
	// which is the precedent for how carefully these refusals are told apart.
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
	// Window is how long a limit lasts. One window for every route, because
	// the routes are one surface and a per-route window would be five things
	// to reason about where one suffices.
	Window time.Duration
	// Signup bounds POST /v1/users.
	Signup int
	// Signin bounds POST /v1/session.
	Signin int
	// SignupTimestamp bounds POST /v1/signup-timestamp.
	SignupTimestamp int
	// Recovery bounds the two anonymous recovery request routes,
	// POST /v1/password-resets and POST /v1/email-verifications. One limit
	// for both because they are the same shape — an address in, a message
	// out — and a deployment that mails one mails the other.
	Recovery int
	// AgentRegister bounds POST /v1/agents, the unauthenticated self-registration
	// a fresh agent calls once per lifetime. It is tighter than Signup by default
	// (5 against 10) because each registration mints a bearer token and a claim
	// link rather than a bare user row, so a spent request is worth more to an
	// abuser and worth less to a legitimate agent — nobody registers an agent on a
	// loop. One window shared with the rest of the surface, as every limit here is.
	AgentRegister int
}

// The social-login environment variables, named in one place.
//
// They are a const block rather than scattered string literals because the failure
// message for a half-configured provider has to name the variable the operator has
// to set, and a literal repeated in two places is a literal that gets one of them
// wrong. Every one of them is OPTIONAL: absent is a deployment that has not turned
// social login on, which is the state this service ships in.
const (
	// OAuthRedirectBaseURLVar is this service's public base URL. Callback URLs are
	// built from it and from nothing else — never from a Host header.
	OAuthRedirectBaseURLVar = "OAUTH_REDIRECT_BASE_URL"
	// OAuthEncryptionKeyVar is standard base64 of 32 raw bytes, which is what
	// `head -c 32 /dev/urandom | base64` prints.
	OAuthEncryptionKeyVar = "OAUTH_ENCRYPTION_KEY"
	// OAuthGoogleClientIDVar and OAuthGoogleClientSecretVar are the Google pair.
	OAuthGoogleClientIDVar     = "OAUTH_GOOGLE_CLIENT_ID"
	OAuthGoogleClientSecretVar = "OAUTH_GOOGLE_CLIENT_SECRET"
	// OAuthGitHubClientIDVar and OAuthGitHubClientSecretVar are the GitHub pair.
	OAuthGitHubClientIDVar     = "OAUTH_GITHUB_CLIENT_ID"
	OAuthGitHubClientSecretVar = "OAUTH_GITHUB_CLIENT_SECRET"
	// OAuthMicrosoftClientIDVar and OAuthMicrosoftClientSecretVar are the
	// Microsoft pair.
	OAuthMicrosoftClientIDVar     = "OAUTH_MICROSOFT_CLIENT_ID"
	OAuthMicrosoftClientSecretVar = "OAUTH_MICROSOFT_CLIENT_SECRET"
	// OAuthAppleClientIDVar is Apple's Services ID — the OAuth client id, and
	// the `sub` of the client_secret this service signs.
	OAuthAppleClientIDVar = "OAUTH_APPLE_CLIENT_ID"
	// OAuthAppleTeamIDVar is the Apple Developer Team ID — the `iss` of that
	// secret.
	OAuthAppleTeamIDVar = "OAUTH_APPLE_TEAM_ID"
	// OAuthAppleKeyIDVar is the platform key's id — the `kid` of that secret's
	// header.
	OAuthAppleKeyIDVar = "OAUTH_APPLE_KEY_ID"
	// OAuthApplePrivateKeyVar is the .p8 PEM contents of the platform key —
	// what the secret is signed with.
	OAuthApplePrivateKeyVar = "OAUTH_APPLE_PRIVATE_KEY"

	// The endpoint overrides. Every one is OPTIONAL and every one defaults to the
	// provider's real endpoint, which is defined once in internal/oauth/endpoints.go
	// — this package never writes one of those URLs, so a default cannot drift from
	// the variable that overrides it.
	//
	// THEY EXIST so a deployment can point the whole sign-in flow at a server it
	// controls. A test in this repository can already do that by building a Provider
	// literal (internal/platform/oauthtest), but a real process cannot, and a
	// deployment that cannot try a flow against its own IdP before pointing at
	// Google finds out about a wrong redirect base from a person who cannot sign
	// in.
	//
	// Which values are refused is oauth.Settings.Validate's rule and not this
	// package's: absent is the default, and present-but-undialable fails startup
	// naming the variable below.
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
	// OAuthAppleAuthorizeURLVar and OAuthAppleTokenURLVar are Apple's two
	// overridable endpoints, following the same pattern as the other three
	// providers.
	//
	// There is deliberately NO OAUTH_APPLE_JWKS_URL. The JWKS document is the
	// TRUST ROOT for Apple's id_token — the one provider whose identity this
	// service verifies against a published key rather than reads from a
	// userinfo call — and a deployment that could point it anywhere could point
	// it at a key document of its own, and then the id_token it verifies would
	// be one the deployment signed itself: a complete authentication bypass. The
	// authorize and token URLs carry no such power, because an id_token returned
	// by whichever token endpoint is still verified against the PINNED Apple
	// JWKS before a single claim is read. So Apple's key document is the one
	// endpoint this service refuses to let a deployment choose.
	//
	// There is no OAUTH_APPLE_USERINFO_URL because Apple has no userinfo
	// endpoint, and no OAUTH_APPLE_EMAILS_URL because the id_token carries the
	// address. Both absences are the provider's shape, not an oversight.
	OAuthAppleAuthorizeURLVar = "OAUTH_APPLE_AUTHORIZE_URL"
	OAuthAppleTokenURLVar     = "OAUTH_APPLE_TOKEN_URL"

	// NATSURLVar is the broker the outbox publisher publishes to. It is OPTIONAL
	// and its absence is a supported state rather than an error: a deployment
	// that has not wired a broker accumulates events in outbox_events, which is
	// the honest shape of "not started yet" — the rows are the promise, and they
	// drain the moment a broker is configured. See Config.NATSURL.
	NATSURLVar = "NATS_URL"

	// The request-rate limit variables. Every one is OPTIONAL and every one
	// has a DEFAULT, which is the difference between this block and every
	// other feature block in this file: absent is not "feature off", it is
	// "the default limit applies", because the surface these protect is the
	// one a security review looks at first and an unconfigured deployment
	// must not be an unprotected one.
	//
	// A PRESENT VALUE THAT DOES NOT PARSE, OR PARSES TO A NON-POSITIVE NUMBER,
	// IS A STARTUP ERROR. The zero case is the rule that reads as harsh and is
	// the reason this block exists: 0 means "unlimited" everywhere else, and
	// this service does not offer unlimited on the auth surface. See
	// ErrInvalidRateLimit.
	//
	// The per-route numbers and their reasons are in the README's operator
	// table, because a number without its reason is a default nobody revisits.
	RateLimitWindowVar          = "RATE_LIMIT_WINDOW"
	RateLimitSignupVar          = "RATE_LIMIT_SIGNUP"
	RateLimitSigninVar          = "RATE_LIMIT_SIGNIN"
	RateLimitSignupTimestampVar = "RATE_LIMIT_SIGNUP_TIMESTAMP"
	RateLimitAgentRegisterVar   = "RATE_LIMIT_AGENT_REGISTER"
	RateLimitRecoveryVar        = "RATE_LIMIT_RECOVERY"

	// RequireEmailVerificationVar gates sign-in on a proved address. It is a
	// BOOL and it is OFF BY DEFAULT, because the reference this fleet matches
	// does not gate sign-in on verification and the default must preserve
	// parity. See Config.RequireEmailVerification for the whole of it.
	RequireEmailVerificationVar = "REQUIRE_EMAIL_VERIFICATION"
)

// oauthEndpointVars is the per-endpoint table: which variable sets which provider's
// which endpoint.
//
// IT IS USED TWICE and that is why it is one table rather than seven reads. It
// READS the block, and it NAMES the variable in a refusal — oauth refuses an
// endpoint by provider and struct field because it does not know what a variable
// is called, and pattern-matching its error message on prose is how a rename
// becomes a message that names the wrong variable.
//
// `TestEveryOAuthEndpointHasAVariableAndEveryVariableHasAnEndpoint` walks it in
// both directions against the two definitions in internal/oauth: a field a provider
// has and no variable sets it is a deployment that cannot do the thing, and a
// variable with no field behind it is one that sets nothing while reading as if it
// did.
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

	// Read unconditionally, like DatabaseURL: absent is the supported state, and
	// the one place that decides what absent means is the boot wiring in
	// cmd/identity, not a default here.
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

	// The agent claim screen base. Read unconditionally (absent is the supported
	// state — a deployment that has not turned agents on — never a default), and
	// validated when present so a typo is a startup failure rather than a
	// registration that 503s its first real agent.
	if err := cfg.loadAgentClaimUI(lookup); err != nil {
		return Config{}, err
	}

	// THE SIGN-IN VERIFICATION GATE, parsed here rather than in a loader of its
	// own because it is one variable and one line of logic, and a function for
	// either would be a second place to look for a fact about the auth surface.
	// Absent is false — parity with the reference, pinned by a test. Present
	// and unreadable is a startup failure, the rule every other variable here
	// follows: a deployment that believes it has the gate on and does not is
	// the worse of the two states.
	if _, ok := lookup(RequireEmailVerificationVar); ok {
		switch strings.ToLower(strings.TrimSpace(lookupValue(lookup, RequireEmailVerificationVar))) {
		case "true", "1", "yes":
			cfg.RequireEmailVerification = true
		case "false", "0", "no", "":
		default:
			// A plain error and not a sentinel, because no caller matches on
			// this one with errors.Is — a bool flag has no downstream decision
			// to make, and the message names the variable, which is the whole
			// of the fix. The startup-failure rule is unchanged: a deployment
			// that believes it has the gate on and does not is the worse of the
			// two states.
			return Config{}, fmt.Errorf("%s is %q, want true or false",
				RequireEmailVerificationVar, lookupValue(lookup, RequireEmailVerificationVar))
		}
	}

	// THE ONE UNCONDITIONAL SECRET, checked last so that a deployment with
	// several things wrong reports the feature blocks first: each of those
	// has its own variable to fix, and an operator who fixes them one at a
	// time should meet them in the order the boot log prints them. This one
	// has no feature to be configured or skipped — it is either there or
	// the process does not start — so there is no earlier check it could
	// mask that an operator would rather see first.
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

// loadOAuth reads the social-login block.
//
// TEN CREDENTIAL VARIABLES, TWELVE ENDPOINT OVERRIDES AND FOUR PROVIDERS, and the
// rules are oauth.Settings.Validate's rather than this function's:
//
//   - a provider with one half of its credentials is a STARTUP FAILURE, not a
//     disabled provider. A "Continue with Google" button that 404s because a secret
//     went missing is a support call that should have been a failed deploy.
//   - a provider with both halves needs a redirect base URL and a token encryption
//     key, because a callback with nowhere to arrive and a token with nowhere to be
//     sealed are both useless rather than degraded.
//   - a key that does not decode is a startup failure EVEN WHEN NO PROVIDER IS
//     CONFIGURED, and this is the one rule that reads as harsh. It is the same rule
//     MFA_ENCRYPTION_KEY follows (loadMFA), for the same reason: a deployment whose
//     key is wrong should find out at boot rather than at the first social sign-in,
//     in front of a person who cannot sign in.
//   - NO BLOCK AT ALL is a supported state. This is the one optional surface whose
//     absence is a decision rather than a gap, and refusing to boot without it would
//     mean this service could not be deployed password-only.
//
// APPLE IS THE ONE PROVIDER WHOSE SECRET IS DERIVED RATHER THAN READ. Its
// client_secret is an ES256 JWT this service signs, minted here from the four
// OAUTH_APPLE_* inputs by oauth.MintAppleClientSecret — once, at startup, and
// cached, because the secret is valid for months and there is no rotation
// machinery. The minted secret lands in Settings.Apple.ClientSecret, so the
// exchange path needs no change. A half-configured set of the four inputs is
// refused by the helper as ErrIncompleteProvider, the existing rule unchanged.
func (c *Config) loadOAuth(lookup Lookup) error {
	appleInputs := oauth.AppleSecretInputs{
		ServicesID: lookupValue(lookup, OAuthAppleClientIDVar),
		TeamID:     lookupValue(lookup, OAuthAppleTeamIDVar),
		KeyID:      lookupValue(lookup, OAuthAppleKeyIDVar),
		PrivateKey: lookupValue(lookup, OAuthApplePrivateKeyVar),
	}
	appleSecret, err := oauth.MintAppleClientSecret(appleInputs)
	if err != nil {
		// Both sentinels are preserved: ErrInvalidOAuth says the block is
		// broken, and the inner one says WHICH rule — a half-configured Apple
		// is ErrIncompleteProvider, the same answer the other three providers
		// get, and an operator reading it goes looking for the same kind of
		// missing variable.
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
		// Every message this produces names a variable, because Validate's do and
		// the alternative — "invalid oauth settings" — sends an operator looking
		// through six variables instead of at one. An endpoint refusal arrives as
		// the provider and the struct field, because internal/oauth does not know
		// what a variable is called, so the table turns it back into one here.
		if variable := oauthEndpointVariable(err); variable != "" {
			return fmt.Errorf("%w: %s: %w", ErrInvalidOAuth, variable, err)
		}
		return fmt.Errorf("%w: %w", ErrInvalidOAuth, err)
	}
	return nil
}

// oauthEndpointVariable returns the environment variable that sets the endpoint an
// *oauth.EndpointError refused, or "" when the refusal was not about one.
//
// The empty answer is not a case anything can reach — the table covers every field
// both providers have — and it is handled rather than assumed precisely because it
// cannot be: a variable that names nothing is the same shape as a variable that was
// renamed, and this is the one place that would turn a rename into a boot log
// pointing at the wrong name.
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

// The asymmetry with the OIDC block above is deliberate and is the whole of this
// function: OIDC's three variables are all-or-nothing because a provider with an
// issuer and no key is a broken provider, whereas MFA's single variable has a
// SUPPORTED absent state — a deployment that has not turned a second factor on.
//
// That is the only thing absent means here. Present-but-unreadable is still a
// startup failure, because a deployment that believes it has a key and has one
// that does not decode would lock every enrolled user out at their second factor
// and tell nobody why.
//
// MFA_ISSUER is the exception to "absent is supported": absent means the default
// label, because it is a display string and not a secret, and a default is what a
// display string wants.
func (c *Config) loadMFA(lookup Lookup) error {
	c.MFAIssuerLabel = DefaultMFAIssuer
	if issuer := lookupValue(lookup, "MFA_ISSUER"); issuer != "" {
		c.MFAIssuerLabel = issuer
	}

	encoded := lookupValue(lookup, "MFA_ENCRYPTION_KEY")
	if encoded == "" {
		return nil
	}

	// base64url, no padding — the same shape as every other secret this service
	// takes, so an operator pasting from the same secret store as
	// OIDC_SIGNING_KEY does not have to think about it.
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("%w: it is not base64url: %w", ErrInvalidMFA, err)
	}
	c.MFAEncryptionKeyValue = decoded
	return nil
}

// defaultLinkTemplateVariable is the one link template a deployment configured
// before there were per-purpose ones, and it is the DEFAULT for every purpose that
// has no variable of its own.
//
// # WHY THE DEFAULT EXISTS, AND WHAT IT COSTS
//
// Every deployment in existence has this variable set and nothing else, and this
// repository does not get to break their boots to fix a bug that only exists
// because the bug predates the fix. So it is honored, and an unmigrated
// deployment's address-verification link keeps pointing wherever its single
// template says — which, for the configuration this shape was introduced to
// replace, is the password reset screen.
//
// # THE ALTERNATIVES, because the honest cost above deserves the argument
//
//	DERIVE A VERIFICATION PATH FROM THE RESET ONE, by replacing the last path
//	segment or appending a convention. Rejected: it is the platform choosing a
//	product's URL, which is the exact thing `LinkTemplate` exists to avoid, and it
//	is wrong for every product whose verify screen is not spelled the way identity
//	guessed. It would also make the defect INVISIBLE in a way this one is not.
//
//	REQUIRE `EMAIL_VERIFICATION_LINK_TEMPLATE`. Rejected: it breaks every
//	installation at boot, which is the failure mode the packet exists to rule out.
//
// So: a default, a warning at startup naming what is still shared, and one more
// variable for a deployment to set.
const defaultLinkTemplateVariable = "RECOVERY_LINK_TEMPLATE"

// linkTemplateVariables is the per-purpose table: which variable names which
// purpose's link.
//
// IT IS THE COMPLETE SET OF PURPOSES A DEPLOYMENT CAN PUT A LINK IN. `email_change`
// is in it because courier has carried both address-change types since `20373bf`
// and this adapter now delivers both halves: the current-address half carries the
// confirmation link, and that link has to point somewhere. The new-address half
// carries no link and so needs no variable of its own — but the purpose is one,
// and the variable configures the half that has one.
//
// `internal/courier`'s `TestEveryPurposeThisAdapterCanDeliverHasAVariableToConfigureItsLink`
// is what holds this set against the adapter's own, in both directions.
var linkTemplateVariables = map[recovery.Purpose]string{
	recovery.PurposePasswordReset: "PASSWORD_RESET_LINK_TEMPLATE",
	recovery.PurposeVerifyEmail:   "EMAIL_VERIFICATION_LINK_TEMPLATE",
	recovery.PurposeEmailChange:   "EMAIL_CHANGE_LINK_TEMPLATE",
}

// loadCourier reads and validates the courier block.
//
// IT MIRRORS `loadOIDC`'s all-or-nothing rule and for the same reason: variables
// that only make sense together, and a partial block is a deployment that believes
// it can send mail.
//
// Absent is supported. Everything unset is a process with no mail path, which is a
// legitimate deployment — a local stack, or one where courier is not deployed yet —
// and it mounts `recovery.Unavailable{}` so every route that needs a message answers
// 503 with a sentence saying why.
//
// The base URL is checked HERE rather than by the courier client. That is the whole
// point of loading it at boot: a URL that does not parse is a typo, and a typo found
// by the first user's password reset is a typo found in front of somebody who cannot
// sign in.
func (c *Config) loadCourier(lookup Lookup) error {
	baseURL := lookupValue(lookup, "COURIER_BASE_URL")
	token := lookupValue(lookup, "COURIER_TOKEN")

	// THE TWO CREDENTIALS ARE ALL-OR-NOTHING WITH EACH OTHER, and the link templates
	// are all-or-nothing WITH THEM. Counting over the block as a whole is what makes
	// that one rule rather than two, and a rule an operator can hold in their head is
	// the point: either this process has a mail path or it does not.
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

// Rate-limit defaults. Every one is a bound on abuse, not a guarantee against a
// burst, and the window is fixed rather than sliding — see internal/ratelimit for
// what that costs and why it is accepted.
const (
	defaultRateLimitWindow          = time.Minute
	defaultRateLimitSignup          = 10
	defaultRateLimitSignin          = 20
	defaultRateLimitSignupTimestamp = 30
	defaultRateLimitRecovery        = 5
	defaultRateLimitAgentRegister   = 5
)

// loadRateLimit reads and validates the request-rate limit block.
//
// THE DEFAULTS ARE THE POINT. Every other feature block in this file is absent
// when unconfigured, because they belong to features a deployment may not have
// turned on. This one is present by default, because the surface it protects is
// the one a customer's security review looks at first and an unconfigured
// deployment must not be an unprotected one.
//
// A PRESENT VALUE THAT DOES NOT PARSE, OR PARSES TO A NON-POSITIVE NUMBER, IS A
// STARTUP ERROR. The zero case is the rule that reads as harsh and is the reason
// this block exists: 0 means "unlimited" everywhere else, and this service does
// not offer unlimited on the auth surface. See ErrInvalidRateLimit.
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

// loadAgentClaimUI reads and validates the claim screen base.
//
// OPTIONAL RATHER THAN REQUIRED AT BOOT, and that is the difference from
// OIDCLoginUIURL: the claim screen belongs to the agent surface, which a
// deployment may not have turned on, and failing every boot over a feature nobody
// enabled would be the over-reach OIDC's own comment warns about. What is NOT
// optional is VALIDATION: a base that is present and unusable (a bad scheme, a
// query, a fragment, a userinfo) is refused here, so the failure is a startup
// error an operator reads rather than a 503 a user hits.
//
// THE SHAPE RULES ARE OIDC's, restated because they are the same class of
// redirect target: http/https, a host, and NO query (a preserved query would put a
// string this service did not write beside a claim link), NO fragment (never sent
// to a server) and NO userinfo (the host would not be the host it resolves to).
// See internal/oidc.ValidateLoginUIURL for the argument in full.
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

// loadRateLimitDuration reads a duration variable, defaulting when absent.
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

// loadRateLimitCount reads a count variable, defaulting when absent.
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

// invitationLinkTemplateVariable names the one link an invitation's accept
// screen is reached by.
//
// IT IS A CONSTANT RATHER THAN A LITERAL AT THE CALL SITE for the reason
// defaultLinkTemplateVariable is: a variable an operator types has to be spelled
// the same in the environment, the refusal, and the compose file, and a second
// spelling is a second thing to drift.
const invitationLinkTemplateVariable = "INVITATION_LINK_TEMPLATE"

// resolveInvitationLinkTemplate reads and validates the invitation link.
//
// IT IS REQUIRED WHENEVER THE COURIER BLOCK IS WIRED, and that is the whole
// rule. The invite route is mounted unconditionally — it is part of the
// tenancy surface, not a conditional one — so a deployment with a mail path
// and no invitation template is not a legitimate steady state: it is a
// deployment whose invite path fails at send time, on every invite, with a 500
// that names nothing actionable. Failing at boot costs one log line naming
// the variable; failing at invite time costs an admin who cannot invite
// anybody and cannot tell why from the response.
//
// THE VALIDATION IS validateLinkTemplate's, applied here rather than delegated,
// for the reason validateMailBaseURL gives: this service must refuse to start
// on a broken link whether or not a courier client is built.
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

// anyLinkTemplateConfigured reports whether any link variable is set, and which one
// was seen.
//
// THE ORDER IS NOT MAP ORDER, because the variable named in a startup log has to be
// the same one on every restart: an operator reading "PASSWORD_RESET_LINK_TEMPLATE
// is set but…" on Tuesday and "EMAIL_VERIFICATION_LINK_TEMPLATE" on Wednesday has
// been told two different things about the same mistake.
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

// sortedLinkTemplateVariables lists the per-purpose variables in name order, so
// every message built from this table is the same on every run.
func sortedLinkTemplateVariables() []string {
	variables := make([]string, 0, len(linkTemplateVariables))
	for _, variable := range linkTemplateVariables {
		variables = append(variables, variable)
	}
	slices.Sort(variables)
	return variables
}

// sortedPurposes lists a purpose-keyed table's purposes in name order, for the same
// reason `sortedLinkTemplateVariables` does: a refusal has to name the same variable
// on every run.
func sortedPurposes(table map[recovery.Purpose]string) []recovery.Purpose {
	purposes := make([]recovery.Purpose, 0, len(table))
	for purpose := range table {
		purposes = append(purposes, purpose)
	}
	slices.Sort(purposes)
	return purposes
}

// resolveLinkTemplates turns the three link variables into one template per purpose.
//
// # THE REFUSALS, AND WHY EACH IS THE FAILURE DIRECTION
//
//	no template anywhere      a deployment that can send mail cannot say where a
//	                         link goes, so every message would arrive with nothing
//	                         to click.
//	a purpose with neither    a deployment has said where the reset link goes and
//	                         nothing about the verification one. Falling back to
//	                         another purpose's template IS THE DEFECT: the mail
//	                         renders, every test passes, and the button leads to a
//	                         404 for the reader.
//	a template that will not  checked against a SUBSTITUTED copy, because `{token}`
//	                         is not a legal URI character and validating the template
//	                         as written would let through a shape courier's
//	                         `format: uri` rejects once the real token is in it.
//
// # THE DEFAULT IS VALIDATED EVEN WHEN NOTHING FALLS BACK TO IT
//
// A variable that is present but unreadable is a startup failure everywhere else in
// this package, and this one is no different: an operator who set
// `RECOVERY_LINK_TEMPLATE` to something broken has a typo, and finding it at boot
// costs one log line while finding it later costs an afternoon.
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

// validateMailBaseURL refuses a courier address that is not one.
//
// IT IS DUPLICATED RATHER THAN CALLED because the rule is identity's at boot and
// `internal/courier`'s at construction, and the two must be true independently: this
// service should refuse to start on a bad URL whether or not a courier client is
// built, and the client should refuse to exist on one whether or not something else
// validated it. `TestTheBootRulesAndTheClientRulesAgree` holds them in step.
//
// THE MESSAGE NAMES BOTH SCHEMES THE CODE ACCEPTS, which is a fix rather than a
// style preference. It used to say "want https" directly above a line that accepts
// http, and above a test that requires `http://localhost:4003` to boot — so it told
// an operator that a scheme this service starts up with is one it rejects.
// `TestAnInsecureLinkTemplateIsDescribedAsThoughHTTPSWereTheOnlyOneAccepted` holds
// it there.
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
		// A base URL with a query is a base URL somebody is about to concatenate a
		// path onto, and the result is a request whose query this service did not
		// write.
		return fmt.Errorf("%w: COURIER_BASE_URL has a query or a fragment", ErrInvalidCourier)
	}
	return nil
}

// validateLinkTemplate refuses a template that cannot produce a link a person can
// follow.
//
// IT TAKES THE VARIABLE NAME and names it in every refusal, which is why it is a
// parameter and not a constant: a deployment sets up to three of these, and "the
// link template is invalid" makes an operator diff three values against a rule they
// have to remember.
//
// THE REFUSALS ARE `internal/courier`'s, duplicated for the reason
// `validateMailBaseURL` gives — this service must refuse to start on a broken link
// whether or not a courier client is built — and they are applied PER PURPOSE rather
// than once. One template used to be validated once, which meant a single validation
// covered every message by accident of there being one template.
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
		// A fragment is not sent to a server, so a token in one reaches a browser
		// and never the screen that redeems it.
		return fmt.Errorf("%w: %s has a fragment; a mail client "+
			"does not send one to a server", ErrInvalidCourier, variable)
	}
	if parsed.User != nil {
		return fmt.Errorf("%w: %s has a userinfo section", ErrInvalidCourier, variable)
	}
	return nil
}

// recoveryTokenPlaceholder is the marker a link template must contain.
//
// IT IS DECLARED HERE AND NOT IMPORTED FROM `internal/courier` because the
// dependency runs the other way: `internal/courier` implements
// `recovery.Mailer` and this package is the service's configuration. Duplicating one
// constant is cheaper than an import that inverts the layering, and
// `TestTheBootPlaceholderIsCouriersPlaceholder` holds the two in step.
const recoveryTokenPlaceholder = "{token}"

// loadOIDC reads and validates the OIDC block.
//
// The rule is all-or-nothing, and it is a startup failure rather than a fallback
// in every direction:
//
//   - an issuer with no key, or a key with no issuer, or a key with no id. A
//     provider with an issuer and no key can sign nothing; one with a key and no
//     issuer has no `iss` to put in a token; one with no key id publishes a
//     document whose `kid` a verifier cannot match against a token header.
//   - a login UI with no block to apply it to, and a block with no login UI. The
//     second is the one this function grew a rule for, and it is the same shape as
//     the first three: a provider that publishes a working discovery document and
//     then cannot complete a single authorization flow is a broken provider, and
//     the only place anybody finds out is a user at a product's sign-in button.
//     `internal/oidc` owns the rule and this function CALLS it rather than
//     restating it, so a change to what counts as a usable login UI is a change in
//     one place.
//   - an http issuer without OIDC_ALLOW_INSECURE. Every verifier on the platform
//     compares `iss` for equality and fetches the JWKS over the same scheme, so
//     an http issuer in production is a token nobody can verify and a key
//     document nobody will fetch over a channel that protects it.
//
// Absent is the supported state: no issuer and no key is a process that is not an
// OpenID Connect provider, and that is a legitimate deployment — a courier, or a
// local stack that has no key yet.
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
			// Asking for an insecure issuer with nothing to apply it to is a
			// configuration mistake, not a no-op: the variable was written for a
			// deployment that has an issuer and does not.
			return fmt.Errorf("%w: OIDC_ALLOW_INSECURE is set but there is no OIDC_ISSUER to apply it to", ErrInvalidOIDC)
		}
		if loginUI != "" {
			// The same argument, for the same variable-shape: a login UI with nothing
			// to authenticate is a setting an operator changed and nothing reads.
			return fmt.Errorf("%w: %s is set but there is no OIDC_ISSUER, OIDC_SIGNING_KEY and "+
				"OIDC_SIGNING_KEY_ID for it to apply to", ErrInvalidOIDC, oidc.LoginUIEnvVar)
		}
		return nil
	case present != 3:
		return fmt.Errorf("%w: OIDC_ISSUER, OIDC_SIGNING_KEY and OIDC_SIGNING_KEY_ID must all be set, or none of them", ErrInvalidOIDC)
	}

	// The boot-time half of the login UI rule, and the refusal an operator reads
	// names the variable they have to set.
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

// loadSignupSigningKey reads and validates SIGNUP_SIGNING_KEY.
//
// # WHY ABSENT IS A STARTUP FAILURE HERE AND NOWHERE ELSE
//
// Every other secret in this package has a supported absent state, because
// every other secret belongs to a feature a deployment may not have turned on:
// no MFA_ENCRYPTION_KEY means no second factor, no COURIER_TOKEN means no mail
// path, no OIDC_* means the process is not a provider. SIGNUP_SIGNING_KEY
// belongs to no feature. It is the second half of signup bot defense, and a
// deployment that could boot without it would be a deployment whose signup
// form is undefended — silently, because the honeypot still refuses the bots
// that fill every field and the timestamp check is the only thing that stops
// the ones that do not.
//
// So the rule is the OIDC block's all-or-nothing with the "or nothing" branch
// removed: present and readable, or the process does not start. The message
// names the variable, because that is the whole of the fix.
//
// # THE SHAPE IS MFA'S
//
// base64url without padding, exactly 32 bytes — the same as MFA_ENCRYPTION_KEY,
// so an operator pasting from the same secret store does not have to think
// about it, and a value that does not decode to 32 bytes is a startup failure
// rather than a stretch, for the same reason: an operator who configured a
// 16-byte key believes they have 128 bits of entropy, and they do not.
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
