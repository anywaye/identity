package httpapi


import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/anywaye/identity/internal/auth"
	"github.com/anywaye/identity/internal/oauth"
	"github.com/anywaye/identity/internal/users"
)

const (
	socialLoginPrefix = "/v1/auth/oauth"

	OAuthStateCookieName = "__Host-oauth-state"

	OAuthLinkCookieName = "__Host-oauth-link"

	OAuthStateTTL = 10 * time.Minute

	oauthLinkCookieValue = "1"
)

// Social is this surface's dependency: the configured providers, and the use case
// that finishes a round trip.
//
// One interface rather than two because a deployment that can build the redirect but
// not finish it — or the reverse — is a half-mounted flow that fails at the browser
// with a 404 on the callback, and the two halves are constructed together from one
// `oauth.Settings`.
type Social interface {
	Lookup(provider string) (oauth.Provider, error)
	RedirectBase() string
	Callback(ctx context.Context, in auth.SocialCallbackInput) (auth.LoginResult, error)
}

// WithSocial mounts the social-login routes.
//
// It is an Option for the reason WithAuth is: the routes are ABSENT when no provider
// is configured, so a deployment with no OAuth client credentials serves a clean 404
// rather than a redirect to a provider it cannot authenticate with. Every other
// optional surface in this service follows the same rule, and the one that does not
// — the recovery surface — says in its own comment why it differs.
func WithSocial(s Social) Option {
	return func(o *options) {
		if s != nil {
			o.social = s
		}
	}
}

func (o options) registerSocialRoutes(r chiRouter) {
	if o.social == nil {
		return
	}
	r.Get(socialLoginPrefix+"/{provider}", o.handleSocialStart)
	r.Get(socialLoginPrefix+"/{provider}/callback", o.handleSocialCallback)
}

type socialLinkedResponse struct {
	Provider string `json:"linked_provider"`
}

func (o options) handleSocialStart(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "provider")

	provider, err := o.social.Lookup(name)
	if err != nil {
		notFound(w, r)
		return
	}

	state, err := oauth.NewState(provider.Name)
	if err != nil {
		unexpected(w, r, o.logger, err)
		return
	}

	o.setOAuthStateCookie(w, state, o.linkingAs(r))

	o.oauthRedirect(w, provider.AuthCodeURL(state, provider.RedirectURI(o.social.RedirectBase())))
}

func (o options) linkingAs(r *http.Request) bool {
	if o.auth == nil {
		return false
	}
	token := o.presentedToken(r)
	if token == "" {
		return false
	}
	user, err := o.auth.Authenticate(r.Context(), token)
	return err == nil && !user.ID.IsZero()
}

func (o options) handleSocialCallback(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "provider")

	provider, err := o.social.Lookup(name)
	if err != nil {
		notFound(w, r)
		return
	}

	if !oauth.VerifyState(provider.Name, readCookie(r, OAuthStateCookieName), r.URL.Query().Get("state")) {
		o.clearOAuthStateCookies(w)
		problemFor(w, r, http.StatusBadRequest, CodeInvalidRequest,
			"this social sign-in did not start in this browser, so it cannot be finished here")
		return
	}
	o.clearOAuthStateCookies(w)

	if reason := r.URL.Query().Get("error"); reason != "" {
		problemFor(w, r, http.StatusBadRequest, CodeInvalidRequest,
			"the oauth provider did not return an authorization code")
		return
	}

	owner, ok := o.linkTarget(w, r)
	if !ok {
		return
	}

	result, err := o.social.Callback(r.Context(), auth.SocialCallbackInput{
		Provider:  provider.Name,
		Code:      r.URL.Query().Get("code"),
		LinkTo:    owner,
		UserAgent: r.UserAgent(),
		IP:        remoteIP(r),
	})
	if err != nil {
		o.writeSocialError(w, r, err)
		return
	}

	if !owner.ID.IsZero() {
		writeJSON(w, http.StatusOK, socialLinkedResponse{Provider: provider.Name})
		return
	}

	if result.MFARequired {
		o.writeChallenge(w, r, result)
		return
	}

	if result.Token == "" {
		unexpected(w, r, o.logger, errNoChallengeToken)
		return
	}

	o.setSessionCookie(w, result.Token, result.ExpiresAt)
	writeJSON(w, http.StatusOK, sessionResponse{Token: result.Token, ExpiresAt: result.ExpiresAt})
}

func (o options) linkTarget(w http.ResponseWriter, r *http.Request) (users.User, bool) {
	if readCookie(r, OAuthLinkCookieName) == "" {
		return users.User{}, true
	}
	if o.auth == nil {
		notFound(w, r)
		return users.User{}, false
	}

	user, err := o.auth.Authenticate(r.Context(), o.presentedToken(r))
	if err != nil {
		unauthorized(w, r)
		return users.User{}, false
	}
	return user, true
}

func (o options) writeSocialError(w http.ResponseWriter, r *http.Request, err error) {
	var fieldErr *users.FieldError

	switch {
	case errors.Is(err, oauth.ErrUnknownProvider):
		notFound(w, r)

	case errors.Is(err, oauth.ErrCodeRefused):
		problemFor(w, r, http.StatusBadRequest, CodeInvalidRequest,
			"the oauth provider refused the authorization code")

	case errors.Is(err, oauth.ErrNoEmail):
		problemFor(w, r, http.StatusBadRequest, CodeInvalidRequest,
			"the oauth provider did not return a verified email address this service will accept")

	case errors.Is(err, oauth.ErrAlreadyLinked):
		problemFor(w, r, http.StatusConflict, CodeConflict,
			"that oauth account is already linked to a different user")

	case errors.Is(err, auth.ErrSocialEmailInUse):
		problemFor(w, r, http.StatusConflict, CodeConflict,
			"an account already exists for the email address that oauth account reports, "+
				"so this sign-in was refused rather than linked. Sign in with that account instead")

	case errors.Is(err, users.ErrEmailTaken):
		problemFor(w, r, http.StatusConflict, CodeConflict,
			"an account already exists for that email address")

	case errors.Is(err, oauth.ErrProviderUnavailable):
		o.logger.Warn("an oauth provider could not be reached", "provider", chi.URLParam(r, "provider"), "error", err)
		problemFor(w, r, http.StatusBadGateway, CodeServiceUnavailable,
			"the oauth provider could not be reached")

	case errors.Is(err, auth.ErrUnauthenticated):
		unauthorized(w, r)

	case errors.As(err, &fieldErr):
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the provider reported an address this service will not store").
			withFieldErrors([]FieldError{{Field: fieldErr.Field, Code: fieldErr.Code}}))

	default:
		unexpected(w, r, o.logger, err)
	}
}

func (o options) setOAuthStateCookie(w http.ResponseWriter, state string, linking bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     OAuthStateCookieName,
		Value:    state,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(OAuthStateTTL.Seconds()),
		Expires:  time.Now().Add(OAuthStateTTL),
	})

	if linking {
		http.SetCookie(w, &http.Cookie{
			Name:     OAuthLinkCookieName,
			Value:    oauthLinkCookieValue,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(OAuthStateTTL.Seconds()),
			Expires:  time.Now().Add(OAuthStateTTL),
		})
	}
}

func (o options) clearOAuthStateCookies(w http.ResponseWriter) {
	for _, name := range []string{OAuthStateCookieName, OAuthLinkCookieName} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
			Expires:  time.Unix(0, 0),
		})
	}
}

func readCookie(r *http.Request, name string) string {
	cookie, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func (o options) oauthRedirect(w http.ResponseWriter, location string) {
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusFound)
}
