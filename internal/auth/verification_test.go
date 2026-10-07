package auth

// PACKET identity-w69-authsurface, B4: THE SIGN-IN VERIFICATION GATE IS A CHOICE,
// AND THE DEFAULT IS PARITY.
//
// # WHAT THIS FILE PROVES, AND WHY EACH TEST IS HERE
//
// REQUIRE_EMAIL_VERIFICATION is OFF BY DEFAULT, and that default is not an
// oversight: the reference this fleet matches — Jumpstart Pro — uses
// `has_secure_password` and does NOT use Devise's `:confirmable`, so an
// unverified address can sign in there. Gating sign-in on verification would
// be a deviation from parity, so the flag exists for the deployment that
// wants it and changes nothing for the deployment that does not.
//
// The five tests below are the contract:
//
//  1. OFF (the default): an unverified account signs in. This is the parity
//     behaviour, PINNED — a successor must not be able to flip the default by
//     accident.
//  2. ON: an unverified account is refused with its own error, and mints
//     nothing.
//  3. ON, wrong password: the answer is ErrInvalidCredentials, exactly as it
//     would be for a verified account. The gate is AFTER the password, so a
//     stranger who has not proved the credential never learns the account's
//     verification state — the ordering is the security property, and this is
//     the test that holds it.
//  4. ON, verified account: the flag does not break the login it was not
//     written to refuse.
//  5. ON, social callback: the gate covers the door that has no password. It
//     lives in startLogin rather than Login for exactly this reason — see the
//     startLogin comment in service.go — and this test is what makes that
//     coverage a fact about the code rather than about somebody's memory.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"

	"github.com/cafaye/identity/internal/oauth"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/users"
)

// newFixtureWithEmailVerificationRequired is newFixture with the gate ON.
//
// It rebuilds the service from the fixture's own doubles rather than adding a
// parameter to newFixture, because newFixture is called from everywhere and a
// parameter every call site passed the same value for would be noise — the
// same reason newFixtureWithoutAccessRevoker exists as a sibling.
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

// verify marks the user's address as proved, the way users.Store.MarkEmailVerified
// does after a confirmation link is redeemed.
//
// It pokes the double's maps directly, the way seedSession pokes the sessions
// double: the property under test is what startLogin answers, and driving a
// whole redemption flow to set up a verified user would test the redemption
// rather than the gate.
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

// 1. THE DEFAULT IS PARITY, AND IT IS PINNED.
//
// An unverified account signs in when the flag is off — which is every
// deployment that has not set the variable. The assertion is the whole
// LoginResult rather than the error's absence, so a future default flip fails
// here on the token, the session and the error at once.
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

// 2. THE GATE, ON: AN UNVERIFIED ACCOUNT IS REFUSED, AND MINTS NOTHING.
//
// The refusal is its own error rather than ErrInvalidCredentials because the
// caller proved the password — the same ruling the disabled flag has, and for
// the same reason: a 401 would send a person who typed the right password
// round a reset loop that cannot help them.
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

	// Nothing that authenticates anything came back, asserted over the whole
	// struct so a future field cannot be the one that leaks.
	if result.Token != "" || result.MFARequired || result.Challenge != nil || !result.ExpiresAt.IsZero() {
		t.Errorf("LoginResult = %+v, want every field zero: a refused login mints nothing", result)
	}
	if len(f.sessions.minted) != 0 {
		t.Errorf("%d sessions were minted for a refused login, want 0", len(f.sessions.minted))
	}
}

// 3. THE ORDERING IS THE ENUMERATION REASONING, so it is a test and not a comment.
//
// A wrong password against an unverified account must be indistinguishable from
// a wrong password against a verified one — ErrInvalidCredentials, the same
// value, from the same path — because that is the answer a stranger gets, and
// it is the only answer that keeps this gate from becoming an existence oracle
// for every unverified account on the service. The gate sits after the
// password; this test is what holds it there.
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

	// The failure is counted, because the lockout keeps working on an
	// unverified account — the gate refuses the login, it does not grant the
	// account immunity from brute-force protection.
	if got := f.users.byID[u.ID].FailedLoginAttempts; got != 1 {
		t.Errorf("FailedLoginAttempts = %d after one wrong password, want 1", got)
	}
}

// 4. THE FLAG DOES NOT BREAK THE LOGIN IT WAS NOT WRITTEN TO REFUSE.
//
// A verified account signs in with the gate on. Without this test the gate
// could be moved above the password check — or worse, refuse every login — and
// tests 2 and 3 would still pass, because neither of them signs in
// successfully.
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

// 5. THE SOCIAL CALLBACK IS THE SAME DOOR, AND startLogin IS WHY.
//
// internal/auth/social.go resolves a provider identity to a local user and
// then calls startLogin — with no password anywhere in the request. A gate
// written in Login would leave that door open, and the defect would stay
// invisible because a social sign-in for an unverified account WORKS: it
// mints a session, tests are green, and nothing says the deployment's
// confirmation requirement was bypassed. The enumeration argument does not
// transfer, and the reason is a fact about the provider: the caller has
// already proved control of a provider account whose address this service
// believes, so they already know the local account exists.
func TestASocialCallbackForAnUnverifiedAccountMintsNothingWhenTheFlagIsOn(t *testing.T) {
	t.Parallel()

	// A social fixture whose auth service has the gate ON, built as one struct
	// literal rather than by mutating newSocialFixtureWithBothProviders: the
	// auth service is constructed from its doubles, so swapping the doubles
	// afterwards would leave the service holding the fixture's ORIGINAL empty
	// users double — and the callback's user lookup would miss every account
	// the test seeded.
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

	// The connected account exists BEFORE the gate matters, which is the case
	// that counts: signInAs is the path a provider identity already linked
	// takes, and it is the one that ends at startLogin with a user row in
	// hand. An account that had never used the provider would be refused
	// earlier for having no connected account at all, which proves nothing
	// about this door.
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
