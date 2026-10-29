package auth


import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"

	"github.com/anywaye/identity/internal/oauth"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/users"
)

func newFixtureWithEmailVerificationRequired() *fixture {
	f := newFixture()
	f.svc = NewService(
		f.uow,
		f.reader,
		f.users,
		f.sessions,
		f.events,
		f.tenancy,
		f.mfa,
		f.access,
		f.audit,
		users.NewHasherWithParams(&argon2id.Params{
			Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
		}),
		f.clock,
		24*time.Hour,
		true,
	)
	return f
}

func (f *fixture) verify(t *testing.T, userID id.UUID) {
	t.Helper()

	at := f.clock.Now()
	u, ok := f.users.byID[userID]
	if !ok {
		t.Fatalf("verifying a user: no such id %s", userID)
	}
	u.EmailVerifiedAt = &at
	f.users.byID[userID] = u
	f.users.byEmail[u.Email] = u
}

func TestAnUnverifiedAccountSignsInWhenTheFlagIsOff(t *testing.T) {
	t.Parallel()

	f := newFixture()
	u := f.register(t, "kaka@example.com", "correct horse battery staple")

	result, err := f.svc.Login(context.Background(), LoginInput{
		Email:    u.Email,
		Password: "correct horse battery staple",
	})
	if err != nil {
		t.Fatalf("Login with the flag off = %v, want success: the default is parity "+
			"with the reference, and an unverified address signs in there", err)
	}
	if result.Token == "" {
		t.Error("LoginResult.Token is empty; a parity login mints a session")
	}
	if len(f.sessions.minted) != 1 {
		t.Errorf("%d sessions were minted, want 1", len(f.sessions.minted))
	}
}

func TestLoginRefusesAnUnverifiedAccountWhenTheFlagIsOn(t *testing.T) {
	t.Parallel()

	f := newFixtureWithEmailVerificationRequired()
	u := f.register(t, "kaka@example.com", "correct horse battery staple")

	result, err := f.svc.Login(context.Background(), LoginInput{
		Email:    u.Email,
		Password: "correct horse battery staple",
	})

	var unverified *EmailNotVerifiedError
	if !errors.As(err, &unverified) {
		t.Fatalf("Login on an unverified account with the flag on = %v, want a *EmailNotVerifiedError", err)
	}
	if errors.Is(err, ErrInvalidCredentials) {
		t.Error("the gate answered ErrInvalidCredentials; the password was correct and " +
			"the caller must be told the address is unverified, not that the credential is wrong")
	}

	if result.Token != "" || result.MFARequired || result.Challenge != nil || !result.ExpiresAt.IsZero() {
		t.Errorf("LoginResult = %+v, want every field zero: a refused login mints nothing", result)
	}
	if len(f.sessions.minted) != 0 {
		t.Errorf("%d sessions were minted for a refused login, want 0", len(f.sessions.minted))
	}
}

func TestAnUnverifiedLoginWithTheWrongPasswordIsRefusedExactlyAsAnyOther(t *testing.T) {
	t.Parallel()

	f := newFixtureWithEmailVerificationRequired()
	u := f.register(t, "kaka@example.com", "correct horse battery staple")

	_, err := f.svc.Login(context.Background(), LoginInput{
		Email:    u.Email,
		Password: "wrong password",
	})

	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("a wrong password against an unverified account = %v, want ErrInvalidCredentials: "+
			"the gate is after the password, so a stranger never learns the verification state", err)
	}

	var unverified *EmailNotVerifiedError
	if errors.As(err, &unverified) {
		t.Error("the gate fired before the password was verified; that ordering is a " +
			"one-request existence oracle for every unverified account")
	}

	if got := f.users.byID[u.ID].FailedLoginAttempts; got != 1 {
		t.Errorf("FailedLoginAttempts = %d after one wrong password, want 1", got)
	}
}

func TestAVerifiedAccountSignsInWhenTheFlagIsOn(t *testing.T) {
	t.Parallel()

	f := newFixtureWithEmailVerificationRequired()
	u := f.register(t, "kaka@example.com", "correct horse battery staple")
	f.verify(t, u.ID)

	result, err := f.svc.Login(context.Background(), LoginInput{
		Email:    u.Email,
		Password: "correct horse battery staple",
	})
	if err != nil {
		t.Fatalf("Login for a verified account with the flag on = %v, want success", err)
	}
	if result.Token == "" {
		t.Error("LoginResult.Token is empty; a verified account signs in")
	}
	if len(f.sessions.minted) != 1 {
		t.Errorf("%d sessions were minted, want 1", len(f.sessions.minted))
	}
}

func TestASocialCallbackForAnUnverifiedAccountMintsNothingWhenTheFlagIsOn(t *testing.T) {
	t.Parallel()

	a := newFixtureWithEmailVerificationRequired()
	f := &socialFixture{
		t:        t,
		auth:     a,
		registry: newFakeSocialRegistry(oauth.ProviderGoogle, oauth.ProviderGitHub),
		client:   &fakeExchanger{},
		store:    newFakeAccounts(),
		sealer:   &fakeSealer{},
	}
	f.svc = NewSocialService(a.svc, f.registry, f.client, f.store, f.sealer)

	owner := f.linkOwner("kaka@example.com")
	if _, err := f.link(oauth.ProviderGoogle, "code-1", "google-uid-1", owner.Email, owner); err != nil {
		t.Fatalf("seeding the connected account: %v", err)
	}

	result, err := f.callback(oauth.ProviderGoogle, "code-2", "google-uid-1", owner.Email)

	var unverified *EmailNotVerifiedError
	if !errors.As(err, &unverified) {
		t.Fatalf("Callback for an unverified account with the flag on = %v, want a *EmailNotVerifiedError", err)
	}
	if result.Token != "" || result.MFARequired || result.Challenge != nil {
		t.Errorf("LoginResult = %+v, want nothing: the callback mints nothing", result)
	}
	if len(f.auth.sessions.minted) != 0 {
		t.Errorf("%d sessions were minted by the social callback, want 0", len(f.auth.sessions.minted))
	}
}
