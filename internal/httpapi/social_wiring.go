package httpapi

// THE PRODUCTION SOCIAL WIRING: the one value in this repository that satisfies
// `Social`.
//
// # WHY AN ADAPTER AND NOT A THIRD METHOD ON oauth.Registry
//
// `Social` needs three methods. `*oauth.Registry` has two of them — `Lookup` and
// `RedirectBase`, both at internal/oauth/provider.go:205 and :214 — and the third,
// `Callback`, is `auth.SocialService`'s. The obvious repair is to add
// `func (r *Registry) Callback(ctx, in auth.SocialCallbackInput) (auth.LoginResult, error)`
// beside the other two, and it is not possible, because it would be a package
// cycle: `internal/auth` imports `internal/oauth` for `oauth.Provider`,
// `oauth.Tokens`, `oauth.Identity`, `oauth.Account` and `oauth.StoredTokens`, so
// `internal/oauth` cannot import `internal/auth` to name the argument and the
// result. `Registry` cannot name the type that finishes the round trip.
//
// So the seam has to be assembled where both packages are visible. This file is
// that place, and it is here rather than in `cmd/identity` for one concrete
// reason: a type declared in `cmd` cannot be named by a test, so the wiring this
// file performs — that a real registry and a real use case together satisfy the
// interface the router mounts on — would be reachable only by starting a process.
// This package already imports both `internal/auth` and `internal/oauth` (oauth.go
// does, for `Social`'s own signatures), so nothing new is imported to hold the
// value that makes the surface reachable.
//
// # ONE REGISTRY, PASSED TWICE, ON PURPOSE
//
// `NewSocial` takes the registry as well as the service, because
// `auth.SocialService` takes its own registry and nothing forces them to be the
// same object. Two of them would be a service that resolves a provider the
// router cannot, or the reverse, and the failure is not a crash: it is a start
// route that redirects to a provider the callback then answers 404 for, which is
// a 404 a person sees halfway through a sign-in. So this file does not accept two
// registries — it accepts one and gives it to both halves.

import (
	"context"

	"github.com/cafaye/identity/internal/auth"
	"github.com/cafaye/identity/internal/oauth"
)

// socialWiring is the adapter. UNEXPORTED, and the constructor below is the only
// way to build one, because the one field pairing that matters — the registry the
// router resolves through and the registry the use case resolves through being
// the same object — is established in the constructor rather than at six call
// sites that can each get it wrong.
type socialWiring struct {
	registry *oauth.Registry
	service  *auth.SocialService
}

// The compile-time half of the argument in this file's header. Without this line
// nothing stops a rename of `Social`'s third method from turning this adapter
// into a type that satisfies nothing, and the failure would arrive as a
// confusing `cannot use ... as httpapi.Social` at the one call site in
// cmd/identity rather than here, where the whole of the reason exists.
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
