package oauth

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"golang.org/x/oauth2"
)

const (
	ProviderGoogle = "google"
	ProviderGitHub = "github"
	ProviderMicrosoft = "microsoft"
	ProviderApple = "apple"
)

var knownProviders = []string{ProviderGoogle, ProviderGitHub, ProviderMicrosoft, ProviderApple}

var (
	ErrUnknownProvider = errors.New("unknown oauth provider")

	ErrIncompleteProvider = errors.New("oauth provider is half-configured")

	ErrInvalidRedirectBaseURL = errors.New("invalid oauth redirect base url")
)

// Provider is one configured OAuth 2.0 authorization-code provider.
//
// The endpoints are fields rather than constants because that is what lets a test
// point the whole flow at an httptest server. In production they come from
// Google() and GitHub(), with this deployment's endpoint overrides applied once at
// startup, and nothing mutates them after that.
type Provider struct {
	Name string
	ClientID     string
	ClientSecret string
	Scopes []string
	AuthorizeURL string
	TokenURL string
	UserInfoURL string
	EmailsURL string
	JWKSURL string
	ExtraAuthorizeOptions []oauth2.AuthCodeOption
}

// Google returns the provider definition with this service's endpoint choices.
//
// The endpoints are pinned rather than discovered from
// https://accounts.google.com/.well-known/openid-configuration: identity is an
// OIDC *provider*, and a service that hard-codes its own RPs to what it resolves
// at boot is a service whose behavior depends on what a third party served it
// that morning. Apple's and Microsoft's endpoints arrive the same way when those
// packets land. What they are is in endpoints.go, next to the overrides that can
// replace them.
func Google() Provider {
	return Provider{
		Name:         ProviderGoogle,
		Scopes:       []string{"openid", "email", "profile"},
		AuthorizeURL: GoogleAuthorizeURL,
		TokenURL:     GoogleTokenURL,
		UserInfoURL:  GoogleUserInfoURL,
		ExtraAuthorizeOptions: []oauth2.AuthCodeOption{oauth2.AccessTypeOffline},
	}
}

// GitHub returns the provider definition with this service's endpoint choices.
func GitHub() Provider {
	return Provider{
		Name:         ProviderGitHub,
		Scopes:       []string{"read:user", "user:email"},
		AuthorizeURL: GitHubAuthorizeURL,
		TokenURL:     GitHubTokenURL,
		UserInfoURL:  GitHubUserInfoURL,
		EmailsURL:    GitHubEmailsURL,
	}
}

// Microsoft returns the provider definition with this service's endpoint choices.
//
// The scopes are the Microsoft identity platform's v2.0 ones, and `offline_access`
// is here for the reason Google's access_type=offline is: without it the token
// endpoint issues no refresh token, and the stored credential dies an hour later
// with nothing to renew it.
//
// There is no EmailsURL because Microsoft's userinfo endpoint returns the
// address on the identity call, the way Google's does — the second call is
// GitHub's workaround for a provider whose identity endpoint will not always
// carry one.
func Microsoft() Provider {
	return Provider{
		Name:         ProviderMicrosoft,
		Scopes:       []string{"openid", "email", "profile", "offline_access"},
		AuthorizeURL: MicrosoftAuthorizeURL,
		TokenURL:     MicrosoftTokenURL,
		UserInfoURL:  MicrosoftUserInfoURL,
	}
}

// Apple returns the provider definition with this service's endpoint choices.
//
// The scopes are `openid email` and NOTHING ELSE, and the absence of `name` is
// the load-bearing part. Apple requires a POST callback (response_mode
// form_post) only when the `name` scope is requested; the honest scope here is
// openid email, because the name is not available on later authorizations
// anyway — Apple sends it once, on the first consent, and only to a form_post
// callback. Requesting it would mean a second, POST callback route and a name
// this service could display once and never again. So the callback stays a GET
// and the existing route is unchanged.
//
// There is no UserInfoURL because Apple has no userinfo endpoint: the identity
// comes from the id_token, verified against JWKSURL. The client_secret is not
// set here either — it is minted at startup from the four environment inputs
// (see MintAppleClientSecret) and dropped into the ClientSecret field by
// Settings.Providers, so the exchange path needs no change.
func Apple() Provider {
	return Provider{
		Name:         ProviderApple,
		Scopes:       []string{"openid", "email"},
		AuthorizeURL: AppleAuthorizeURL,
		TokenURL:     AppleTokenURL,
		JWKSURL:      AppleJWKSURL,
	}
}

func providerByName(name string) (Provider, bool) {
	switch name {
	case ProviderGoogle:
		return Google(), true
	case ProviderGitHub:
		return GitHub(), true
	case ProviderMicrosoft:
		return Microsoft(), true
	case ProviderApple:
		return Apple(), true
	default:
		return Provider{}, false
	}
}

// AuthCodeURL builds the URL the browser is redirected to.
//
// Every parameter here is required by the flow, and two of them are the CSRF
// defense: `state` goes into a cookie this service reads back, and
// `redirect_uri` must byte-match the callback URL registered with the provider or
// the exchange is refused. prompt/response_type/scope are the provider's own
// requirements.
func (p Provider) AuthCodeURL(state, redirectURI string) string {
	conf := p.oauth2Config()
	conf.RedirectURL = redirectURI

	return conf.AuthCodeURL(state, p.ExtraAuthorizeOptions...)
}

func (p Provider) oauth2Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Scopes:       p.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  p.AuthorizeURL,
			TokenURL: p.TokenURL,
		},
	}
}

// RedirectURI is the callback URL this provider must send the browser back to.
//
// It is derived from the configured base rather than taken from the request: a
// Host header an attacker chose must not become part of an OAuth redirect_uri, or
// the code is delivered to wherever they asked.
//
// The path it appends is not served by anything today, and the value is the same
// one the exchange sends: Client.Exchange calls this with the same base, so the
// authorize step and the token step cannot disagree about it. When the surface
// mounts, the route it names has to be this one — a callback at any other path is
// a second redirect_uri, and one that is not the configured one is refused by the
// provider without saying which of the two was wrong.
func (p Provider) RedirectURI(baseURL string) string {
	return strings.TrimSuffix(baseURL, "/") + "/v1/auth/oauth/" + p.Name + "/callback"
}

// Registry is the set of providers this deployment will accept, keyed by name.
//
// It holds only providers that are fully configured. A name that is absent is a
// 404 whether it is nonsense ("netflix") or a real provider this deployment has no
// credentials for, and that is on purpose: an unauthenticated endpoint that
// distinguishes those two is a way to enumerate a deployment's configuration.
type Registry struct {
	byName map[string]Provider
	redirectBase string
}

// NewRegistry returns a Registry over providers, built from baseURL.
//
// Providers with no credentials are dropped rather than stored as broken entries.
// The returned error is only about baseURL, which every caller needs.
//
// Unwired: no route constructs a Registry today, and Empty is the flag the
// not-yet-written mount would consult to decide whether to serve social login at
// all. It is the honest shape for the decision — absent rather than 404-per-provider
// — and it is untested against a real process until something mounts it.
func NewRegistry(baseURL string, providers ...Provider) (*Registry, error) {
	if err := validateRedirectBase(baseURL); err != nil {
		return nil, err
	}

	byName := make(map[string]Provider, len(providers))
	for _, p := range providers {
		if p.ClientID == "" || p.ClientSecret == "" {
			continue
		}
		byName[p.Name] = p
	}

	return &Registry{byName: byName, redirectBase: baseURL}, nil
}

// Lookup returns the provider with this name.
//
// A name that is well-formed but not configured is the same miss as a name that
// does not exist: ErrUnknownProvider either way.
func (r *Registry) Lookup(name string) (Provider, error) {
	p, ok := r.byName[name]
	if !ok {
		return Provider{}, fmt.Errorf("%w: %q", ErrUnknownProvider, name)
	}
	return p, nil
}

// RedirectBase is the configured public base URL.
func (r *Registry) RedirectBase() string { return r.redirectBase }

// Names returns the configured provider names, sorted. It exists for a startup log
// line: an operator who cannot see which providers came up has no way to tell a
// missing secret from a broken route.
func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.byName))
	for name := range r.byName {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Empty reports whether no provider is configured. The process mounts the OAuth
// routes only when this is false, so a deployment with no credentials serves a
// clean 404 rather than a redirect to a provider it cannot authenticate with.
func (r *Registry) Empty() bool { return len(r.byName) == 0 }

func validateRedirectBase(baseURL string) error {
	if baseURL == "" {
		return fmt.Errorf("%w: it is empty", ErrInvalidRedirectBaseURL)
	}

	parsed, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRedirectBaseURL, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%w: scheme %q is not http or https", ErrInvalidRedirectBaseURL, parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%w: it has no host", ErrInvalidRedirectBaseURL)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%w: it carries a query or fragment", ErrInvalidRedirectBaseURL)
	}
	return nil
}
