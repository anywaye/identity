package auth


import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/oauth"
	"github.com/anywaye/identity/internal/users"
)

func TestLoginRefusesADisabledAccountWithItsOwnError(t *testing.T) {
	t.Parallel()

	f := newFixture()
	u := f.register(t, "kaka@example.com", "correct horse battery staple")
	f.disable(t, u.ID)

	result, err := f.svc.Login(context.Background(), LoginInput{
		Email:    u.Email,
		Password: "correct horse battery staple",
	})

	var disabled *users.DisabledError
	if !errors.As(err, &disabled) {
		t.Fatalf("Login on a disabled account = %v, want a *users.DisabledError", err)
	}

	if errors.Is(err, ErrInvalidCredentials) {
		t.Error("a disabled login answered ErrInvalidCredentials; the person proved the " +
			"password and must be told the account is disabled")
	}

	if result.Token != "" || result.MFARequired || result.Challenge != nil || !result.ExpiresAt.IsZero() {
		t.Errorf("LoginResult = %+v, want every field zero: a refused login mints nothing", result)
	}
	if len(f.sessions.minted) != 0 {
		t.Errorf("%d sessions were minted for a disabled login, want 0", len(f.sessions.minted))
	}

	if cleared := f.users.byID[u.ID].FailedLoginAttempts; cleared != 0 {
		t.Errorf("FailedLoginAttempts = %d after a disabled login, want 0: the password "+
			"was correct and the account state decided the answer", cleared)
	}
	if f.users.cleared != 0 {
		t.Errorf("ClearFailures ran %d times on a refused login, want 0", f.users.cleared)
	}
}

func TestADisabledLoginWithTheWrongPasswordIsRefusedExactlyAsAnyOther(t *testing.T) {
	t.Parallel()

	f := newFixture()
	u := f.register(t, "kaka@example.com", "correct horse battery staple")
	f.disable(t, u.ID)

	for attempt := 1; attempt <= 3; attempt++ {
		_, err := f.svc.Login(context.Background(), LoginInput{
			Email:    u.Email,
			Password: "not the password at all",
		})
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: Login with a wrong password on a disabled account = %v, "+
				"want ErrInvalidCredentials — a different error here is an existence oracle "+
				"reachable in one request", attempt, err)
		}
	}

	if got := f.users.byID[u.ID].FailedLoginAttempts; got != 3 {
		t.Errorf("FailedLoginAttempts = %d after three wrong passwords, want 3: a disabled "+
			"account is still under brute-force protection", got)
	}
	if len(f.sessions.minted) != 0 {
		t.Errorf("%d sessions were minted, want 0", len(f.sessions.minted))
	}
}

func TestReEnablingRestoresThePasswordDoor(t *testing.T) {
	t.Parallel()

	f := newFixture()
	u := f.register(t, "kaka@example.com", "correct horse battery staple")
	password := "correct horse battery staple"

	f.disable(t, u.ID)
	if _, err := f.svc.Login(context.Background(), LoginInput{Email: u.Email, Password: password}); err == nil {
		t.Fatal("Login on a disabled account succeeded")
	}

	f.enable(t, u.ID)

	result, err := f.svc.Login(context.Background(), LoginInput{Email: u.Email, Password: password})
	if err != nil {
		t.Fatalf("Login after re-enabling = %v, want the door open again", err)
	}
	if result.Token == "" {
		t.Error("Login after re-enabling returned no token, want a session")
	}
	if len(f.sessions.minted) != 1 {
		t.Errorf("%d sessions minted across the whole test, want exactly 1 — the one after re-enabling", len(f.sessions.minted))
	}
}

func TestALockedAccountIsStill423AndNeverTheDisabledRefusal(t *testing.T) {
	t.Parallel()

	f := newFixture()
	u := f.register(t, "kaka@example.com", "correct horse battery staple")
	f.users.RecordFailedLogin(context.Background(), f.uow.querier, u.ID, 0, ptr(start.Add(time.Minute)))

	_, err := f.svc.Login(context.Background(), LoginInput{
		Email:    u.Email,
		Password: "correct horse battery staple",
	})

	var locked *LockedError
	if !errors.As(err, &locked) {
		t.Fatalf("Login on a locked account = %v, want a *LockedError", err)
	}

	var disabled *users.DisabledError
	if errors.As(err, &disabled) {
		t.Error("a LOCKED account answered the DISABLED refusal; the two states are " +
			"different concepts and must not share a response")
	}
}

func TestALockedAndDisabledAccountAnswers423NotTheDisabledRefusal(t *testing.T) {
	t.Parallel()

	f := newFixture()
	u := f.register(t, "kaka@example.com", "correct horse battery staple")
	f.disable(t, u.ID)
	f.users.RecordFailedLogin(context.Background(), f.uow.querier, u.ID, 0, ptr(start.Add(time.Minute)))

	_, err := f.svc.Login(context.Background(), LoginInput{
		Email:    u.Email,
		Password: "correct horse battery staple",
	})

	var locked *LockedError
	if !errors.As(err, &locked) {
		t.Fatalf("Login on a locked AND disabled account = %v, want a *LockedError", err)
	}
}

func TestADisabledAccountWithASecondFactorIsRefusedBeforeTheChallenge(t *testing.T) {
	t.Parallel()

	f := newFixture()
	u := f.register(t, "kaka@example.com", "correct horse battery staple")
	f.mfa.enabled[u.ID] = true
	f.disable(t, u.ID)

	result, err := f.svc.Login(context.Background(), LoginInput{
		Email:    u.Email,
		Password: "correct horse battery staple",
	})

	var disabled *users.DisabledError
	if !errors.As(err, &disabled) {
		t.Fatalf("Login on a disabled MFA account = %v, want a *users.DisabledError", err)
	}
	if result.MFARequired || result.Challenge != nil {
		t.Errorf("LoginResult = %+v, want no challenge: the disable is answered before the "+
			"second factor is asked for", result)
	}
	if len(f.mfa.challenges) != 0 {
		t.Errorf("%d challenges were created for a disabled login, want 0", len(f.mfa.challenges))
	}
}

func TestASocialCallbackForADisabledAccountMintsNothing(t *testing.T) {
	t.Parallel()

	f := newSocialFixtureWithBothProviders(t)

	owner := f.linkOwner("kaka@example.com")
	if _, err := f.link(oauth.ProviderGoogle, "code-1", "google-uid-1", owner.Email, owner); err != nil {
		t.Fatalf("seeding the connected account: %v", err)
	}
	f.auth.disable(t, owner.ID)

	result, err := f.callback(oauth.ProviderGoogle, "code-2", "google-uid-1", owner.Email)

	var disabled *users.DisabledError
	if !errors.As(err, &disabled) {
		t.Fatalf("Callback for a disabled account = %v, want a *users.DisabledError", err)
	}
	if result.Token != "" || result.MFARequired || result.Challenge != nil {
		t.Errorf("LoginResult = %+v, want nothing: the callback mints nothing", result)
	}
	if len(f.auth.sessions.minted) != 0 {
		t.Errorf("%d sessions were minted by the social callback, want 0", len(f.auth.sessions.minted))
	}
}

func TestCompletingASecondFactorForAnAccountDisabledMidwayMintsNoSession(t *testing.T) {
	t.Parallel()

	f := newFixture()
	u := f.register(t, "kaka@example.com", "correct horse battery staple")
	f.mfa.enabled[u.ID] = true
	f.mfa.claim = f.mfa.claimFor(u.ID)

	challenge, err := f.svc.Login(context.Background(), LoginInput{
		Email:    u.Email,
		Password: "correct horse battery staple",
	})
	if err != nil {
		t.Fatalf("the first half of the login: %v", err)
	}
	if challenge.Challenge == nil {
		t.Fatal("the first half minted a session instead of a challenge; this test " +
			"needs a challenge token to present")
	}

	f.disable(t, u.ID)

	result, err := f.svc.CompleteSecondFactor(context.Background(), CompleteSecondFactorInput{
		ChallengeToken: challenge.Challenge.Token,
		Code:           "000000",
	})

	var disabled *users.DisabledError
	if !errors.As(err, &disabled) {
		t.Fatalf("CompleteSecondFactor on an account disabled midway = %v, want a *users.DisabledError", err)
	}
	if result.Token != "" {
		t.Error("CompleteSecondFactor returned a token for a disabled account")
	}
	if len(f.sessions.minted) != 0 {
		t.Errorf("%d sessions were minted, want 0", len(f.sessions.minted))
	}
}

func TestADisabledUserHoldsNoSessionAndPresentingOneIsRefused(t *testing.T) {
	t.Parallel()

	f := newFixture()
	u := f.register(t, "kaka@example.com", "correct horse battery staple")

	live, err := f.svc.Login(context.Background(), LoginInput{
		Email:    u.Email,
		Password: "correct horse battery staple",
	})
	if err != nil {
		t.Fatalf("the login before the disable: %v", err)
	}

	if _, err := f.svc.Authenticate(context.Background(), live.Token); err != nil {
		t.Fatalf("the live session does not authenticate before the disable: %v", err)
	}

	f.disable(t, u.ID)

	if _, err := f.svc.Authenticate(context.Background(), live.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("presenting a live session for a disabled user = %v, want ErrUnauthenticated", err)
	}
}
