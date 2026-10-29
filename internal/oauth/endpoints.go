package oauth

import (
	"errors"
	"fmt"
	"net/url"
)

const (
	GoogleAuthorizeURL = "https://accounts.google.com/o/oauth2/v2/auth"
	GoogleTokenURL = "https://oauth2.googleapis.com/token"
	GoogleUserInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"

	GitHubAuthorizeURL = "https://github.com/login/oauth/authorize"
	GitHubTokenURL = "https://github.com/login/oauth/access_token"
	GitHubUserInfoURL = "https://api.github.com/user"
	GitHubEmailsURL = "https://api.github.com/user/emails?per_page=100"

	MicrosoftAuthorizeURL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
	MicrosoftTokenURL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
	MicrosoftUserInfoURL = "https://graph.microsoft.com/oidc/userinfo"

	AppleAuthorizeURL = "https://appleid.apple.com/auth/authorize"
	AppleTokenURL = "https://appleid.apple.com/auth/token"
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
	Provider string
	Field string
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

type endpointOverride struct {
	field string
	value string
	get func(Provider) string
	set func(*Provider, string)
}

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

func (e ProviderEndpoints) applyTo(p *Provider) {
	for _, o := range e.overrides() {
		if o.value != "" {
			o.set(p, o.value)
		}
	}
}

func (e ProviderEndpoints) validate(name string) error {
	definition, known := providerByName(name)
	if !known {
		return &EndpointError{Provider: name, Field: "AuthorizeURL", Reason: errors.New("this service has no definition for that provider")}
	}

	for _, o := range e.overrides() {
		if o.value == "" {
			continue
		}
		if err := validateEndpointURL(o.value); err != nil {
			return &EndpointError{Provider: name, Field: o.field, Reason: err}
		}
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
