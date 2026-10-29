package httpapi


import (
	"context"

	"github.com/anywaye/identity/internal/auth"
	"github.com/anywaye/identity/internal/oauth"
)

type fakeSocial struct {
	base string

	requested []string

	callbackErr error
}

func newFakeSocial() *fakeSocial {
	return &fakeSocial{base: "https://identity.test"}
}

func (f *fakeSocial) Lookup(provider string) (oauth.Provider, error) {
	f.requested = append(f.requested, provider)
	if provider != oauth.Google().Name {
		return oauth.Provider{}, auth.ErrSocialNoProviders
	}
	return oauth.Google(), nil
}

func (f *fakeSocial) RedirectBase() string { return f.base }

func (f *fakeSocial) Callback(_ context.Context, in auth.SocialCallbackInput) (auth.LoginResult, error) {
	f.requested = append(f.requested, in.Provider)
	return auth.LoginResult{}, f.callbackErr
}
