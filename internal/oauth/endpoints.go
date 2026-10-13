package oauth

import (
	"errors"
	"fmt"
	"net/url"
)

// # THE ENDPOINTS, IN ONE PLACE, AS CONSTANTS
//
// They are named constants rather than literals inside Google() and GitHub()
// because there is now a second way to state one — an environment variable — and
// two spellings of Google's authorize URL is one of them wrong within a release.
// The override struct below is the only other way in, and an unset field in it
// means "the constant", not "nothing".
//
// They are pinned rather than discovered from
// https://accounts.google.com/.well-known/openid-configuration, and making them
// configurable has not changed that argument: identity is an OIDC *provider*, and a
// service that hard-codes its own RPs to what it resolves at boot is a service whose
// behavior depends on what a third party served it that morning. What these
// variables change is who the deployment trusts, not what it trusts by default.
const (
	// GoogleAuthorizeURL is where the browser is sent to obtain a code.
	GoogleAuthorizeURL = "https://accounts.google.com/o/oauth2/v2/auth"
	// GoogleTokenURL exchanges that code for a token.
	GoogleTokenURL = "https://oauth2.googleapis.com/token"
	// GoogleUserInfoURL is called with the access token to learn who the user is.
	GoogleUserInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"

	// GitHubAuthorizeURL is where the browser is sent to obtain a code.
	GitHubAuthorizeURL = "https://github.com/login/oauth/authorize"
	// GitHubTokenURL exchanges that code for a token.
	GitHubTokenURL = "https://github.com/login/oauth/access_token"
	// GitHubUserInfoURL is GitHub's /user, which is the identity call.
	GitHubUserInfoURL = "https://api.github.com/user"
	// GitHubEmailsURL is the documented way to get an address whose visibility on
	// /user is private.
	GitHubEmailsURL = "https://api.github.com/user/emails?per_page=100"

	// MicrosoftAuthorizeURL is where the browser is sent to obtain a code.
	//
	// The `common` tenant rather than a specific one: this service signs in
	// personal Microsoft accounts and work/school accounts alike, and a tenant
	// pinned at build time would be a deployment choice this service has no
	// business making. The same reasoning as Google's and GitHub's pinned
	// endpoints — identity is an OIDC provider, and a service that discovers
	// its own RPs at boot is a service whose behavior depends on what a third
	// party served it that morning.
	MicrosoftAuthorizeURL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
	// MicrosoftTokenURL exchanges that code for a token.
	MicrosoftTokenURL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
	// MicrosoftUserInfoURL is called with the access token to learn who the user
	// is. It is Microsoft Graph's OIDC userinfo endpoint, which returns the
	// same `sub`/`email`/`email_verified` shape Google's does.
	MicrosoftUserInfoURL = "https://graph.microsoft.com/oidc/userinfo"

	// AppleAuthorizeURL is where the browser is sent to obtain a code.
	//
	// The same argument as the other three providers' pinned endpoints: identity
	// is an OIDC *provider*, and a service that discovers its own RPs at boot is
	// a service whose behavior depends on what a third party served it that
	// morning.
	AppleAuthorizeURL = "https://appleid.apple.com/auth/authorize"
	// AppleTokenURL exchanges that code for a token.
	//
	// It is also the `aud` of the client_secret this service signs for Apple,
	// which is why the minted secret and this constant cannot drift: both are
	// Apple's identity, stated in apple.go and here.
	AppleTokenURL = "https://appleid.apple.com/auth/token"
	// AppleJWKSURL is where Apple publishes the public keys an id_token's
	// signature is verified against. Apple has no userinfo endpoint, so this is
	// the only place the identity's authenticity is checked — see apple.go.
	AppleJWKSURL = "https://appleid.apple.com/auth/keys"
)

// ErrInvalidEndpoint means an endpoint override is a value this service cannot
// dial.
//
// It is a startup failure and NEVER a fallback to the default, and that direction
// is the whole rule: a deployer who set OAUTH_GOOGLE_TOKEN_URL and received
// Google's real token endpoint has a sign-in flow pointing somewhere they did not
// choose, working, against a third party, holding this service's client secret —
// and no way to find out. The same rule the encryption key and the redirect base
// URL already follow, applied to the one setting whose wrong value is still a
// working service.
var ErrInvalidEndpoint = errors.New("oauth endpoint override is not a usable url")

// EndpointError says WHICH override was refused, and why.
//
// It is a typed error rather than a formatted sentence because the package that
// knows the environment variable names is not this one: internal/config reads the
// environment and names OAUTH_GOOGLE_TOKEN_URL, and doing that from here would mean
// either writing those names twice or pattern-matching on prose. So the refusal
// travels as the provider and the struct field, and config turns that into a
// variable name.
type EndpointError struct {
	// Provider is the provider name: "google" or "github".
	Provider string
	// Field is the ProviderEndpoints field that was refused.
	Field string
	// Reason says what is wrong with the value.
	Reason error
}

func (e *EndpointError) Error() string {
	return fmt.Sprintf("the %s endpoint override %s is not usable: %v", e.Provider, e.Field, e.Reason)
}

// Unwrap exposes both ErrInvalidEndpoint and the underlying reason, so
// errors.Is finds the sentinel through this wrapper and errors.As still reaches a
// reason worth naming.
func (e *EndpointError) Unwrap() []error {
	return []error{ErrInvalidEndpoint, e.Reason}
}

// ProviderEndpoints is one provider's endpoint overrides from the environment.
//
// AN EMPTY FIELD MEANS "use the default", never "no endpoint". The defaults are
// what a deployment runs when it says nothing, and blanking one would be a provider
// this service cannot complete a sign-in with — which is a startup error rather
// than a field an override may empty.
type ProviderEndpoints struct {
	AuthorizeURL string
	TokenURL     string
	UserInfoURL  string
	EmailsURL    string
}

// endpointOverride is one endpoint as the validation and the assignment walk it.
//
// The three funcs are mechanical and are here so that ONE list names every endpoint
// this package knows how to override. A fourth endpoint added to ProviderEndpoints
// and not to this list would be a field no environment variable could set and no
// test would catch, which is the exact shape of the drift this repository keeps
// writing checks about.
type endpointOverride struct {
	// field is the ProviderEndpoints field name, and is what an EndpointError
	// reports and what internal/config maps to a variable name.
	field string
	// value is what the deployment set, empty for "use the default".
	value string
	// get reads the endpoint off a provider definition, which is how a refusal
	// knows whether this provider has an endpoint of this kind at all.
	get func(Provider) string
	// set writes an override onto a provider definition.
	set func(*Provider, string)
}

// overrides lists every endpoint a deployment can override on one provider.
func (e ProviderEndpoints) overrides() []endpointOverride {
	return []endpointOverride{
		{
			field: "AuthorizeURL",
			value: e.AuthorizeURL,
			get:   func(p Provider) string { return p.AuthorizeURL },
			set:   func(p *Provider, v string) { p.AuthorizeURL = v },
		},
		{
			field: "TokenURL",
			value: e.TokenURL,
			get:   func(p Provider) string { return p.TokenURL },
			set:   func(p *Provider, v string) { p.TokenURL = v },
		},
		{
			field: "UserInfoURL",
			value: e.UserInfoURL,
			get:   func(p Provider) string { return p.UserInfoURL },
			set:   func(p *Provider, v string) { p.UserInfoURL = v },
		},
		{
			field: "EmailsURL",
			value: e.EmailsURL,
			get:   func(p Provider) string { return p.EmailsURL },
			set:   func(p *Provider, v string) { p.EmailsURL = v },
		},
	}
}

// applyTo overlays this deployment's overrides onto a provider definition.
//
// It runs at STARTUP, on the value Settings.Providers built, and nothing mutates a
// Provider afterwards. There is no path by which a request, a header or a query
// parameter reaches this: which endpoint this service dials is deployment
// configuration, and a caller who could choose it would be choosing where an
// outbound call carrying an authorization code goes.
func (e ProviderEndpoints) applyTo(p *Provider) {
	for _, o := range e.overrides() {
		if o.value != "" {
			o.set(p, o.value)
		}
	}
}

// validate refuses an override this service could not dial.
//
// CHECKED WHENEVER PRESENT, and independently of whether the provider has
// credentials: a value that is wrong today is wrong the day somebody adds the
// credentials, and the deployer is the only person who can fix it. This is the
// encryption key's rule, for the same reason.
func (e ProviderEndpoints) validate(name string) error {
	definition, known := providerByName(name)
	if !known {
		// Unreachable from Settings, whose table holds only known names. Returned
		// rather than panicked on: a provider added to that table and not to the
		// constructors should be a failed deploy, not a crash on the first sign-in.
		return &EndpointError{Provider: name, Field: "AuthorizeURL", Reason: errors.New("this service has no definition for that provider")}
	}

	for _, o := range e.overrides() {
		if o.value == "" {
			continue
		}
		if err := validateEndpointURL(o.value); err != nil {
			return &EndpointError{Provider: name, Field: o.field, Reason: err}
		}
		// An override for an endpoint this provider does not have is a setting that
		// does nothing, and the deployer who made it cannot see that. Google's
		// /user/emails is the case that exists today: the provider returns its
		// address on the identity call, so there is no second call to point
		// anywhere.
		if o.get(definition) == "" {
			return &EndpointError{
				Provider: name,
				Field:    o.field,
				Reason:   errors.New("this provider has no such endpoint to override"),
			}
		}
	}
	return nil
}

// validateEndpointURL refuses a value that is not an address this service could
// send an HTTP request to.
//
// A QUERY IS ALLOWED and a fragment is not, and the difference is the whole
// reasoning: GitHub's own emails endpoint is
// `https://api.github.com/user/emails?per_page=100`, so refusing a query would
// refuse the default this service ships with. A fragment is the opposite — it is
// never sent to a server, so an override carrying one is silently a different URL
// from the one the deployer wrote, which is precisely the failure a present-but-
// wrong value is supposed to become a startup failure over.
func validateEndpointURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("it does not parse: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("scheme %q is not http or https", parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("it has no host")
	}
	if parsed.Fragment != "" {
		return fmt.Errorf("it carries a fragment, which is never sent to a server")
	}
	return nil
}
