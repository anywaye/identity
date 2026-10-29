package httpapi


import (
	"context"

	"github.com/anywaye/identity/internal/auth"
	"github.com/anywaye/identity/internal/oauth"
)

type socialWiring struct {
	registry *oauth.Registry
	service  *auth.SocialService
}

var _ Social = (*socialWiring)(nil)

// NewSocial assembles the social-login dependency, or returns nil when this
// deployment has not turned social login on.
//
// # NIL IS A SUPPORTED ANSWER AND NOT A FAILURE
//
// A nil return here is the whole of the rule WithSocial's own comment states: the
// routes are ABSENT when no provider is configured, so a deployment with no OAuth
// client credentials serves a clean 404 rather than a redirect to a provider it
// cannot authenticate with. Returning a value whose `Empty()` is true would
// mount the routes and answer 404 per provider instead, which is a different
// service — one that advertises a feature it cannot complete — and it is the
// answer the packet for this surface refused to give.
//
// The nil is an UNTYPED nil interface, which is the only shape that works here:
// `WithSocial` guards on `if s != nil`, so a `(*socialWiring)(nil)` returned
// inside a `Social` would be non-nil as an interface, would be stored in
// `options.social`, would defeat the guard, and would panic on the first
// `Lookup`. Every `return nil` in this file is a literal nil for that reason and
// the rule is the reason this constructor exists instead of a bare struct
// literal at the call site.
//
// The three refusals are deliberately DIFFERENT conditions with the same answer,
// and they are named rather than collapsed, because they are three different
// misconfigurations and an operator reading a log needs to tell them apart:
//
//   - registry == nil — `oauth.NewRegistry` returned an error. `Empty()` on a nil
//     *Registry dereferences it, so this check is load-bearing and not tidiness.
//   - registry.Empty() — credentials are absent. This is the state this service
//     SHIPS in: every OAUTH_* variable is optional, so an untouched deployment
//     arrives here and correctly serves no social routes.
//   - service == nil — there is no use case. A `cmd` wiring mistake rather than a
//     configuration, and a nil check turns it into "routes absent" rather than a
//     dereference on the first callback.
func NewSocial(registry *oauth.Registry, service *auth.SocialService) Social {
	if registry == nil || registry.Empty() || service == nil {
		return nil
	}
	return &socialWiring{registry: registry, service: service}
}

// Lookup resolves the provider named in the URL, through the same registry the
// use case resolves through.
func (s *socialWiring) Lookup(provider string) (oauth.Provider, error) {
	return s.registry.Lookup(provider)
}

// RedirectBase is the configured public base URL.
//
// IT IS THE REGISTRY'S AND NOT A REQUEST'S, and that is the whole of
// oauth.Provider.RedirectURI's rule arriving here: a Host header an attacker
// chose must never become part of a redirect_uri, or the authorization code is
// delivered wherever they asked.
func (s *socialWiring) RedirectBase() string { return s.registry.RedirectBase() }

// Callback finishes the round trip.
//
// The delegation is the point: the use case is where the account-takeover
// decision lives (internal/auth/social.go), and an adapter that reimplemented any
// part of it would be a second implementation of a security decision in the HTTP
// layer, which is the one layer that has no business making one. This method
// adds nothing and must stay that way.
func (s *socialWiring) Callback(ctx context.Context, in auth.SocialCallbackInput) (auth.LoginResult, error) {
	return s.service.Callback(ctx, in)
}
