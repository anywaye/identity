package auth

// PACKET identity-disabled-01, DOOR ONE: THE PASSWORD DOOR.
//
// # THE REFUSAL SHAPE IS A DECISION AND THIS FILE IS WHERE IT WAS MADE
//
// The lockout answers **423 account_locked** with a `Retry-After`, and that answer
// leaks the account's existence — DECISIONS.md D9 names the leak, measures it, and
// keeps it. Disabled could have copied that answer and it would have been a
// mistake, for two independent reasons.
//
// THE STATUS IS NOT 423. A 423 in this service means "locked, retry at" and every
// client that knows the code renders it as a countdown. A disabled account is not
// coming back at any time, so a `Retry-After` on it is a promise nothing will keep
// and a countdown that ends in a second refusal. It is also the exact
// conflation migrations/00021's first three lines exist to prevent: one column
// that means "a person turned this off, indefinitely" and one that means "five
// wrong passwords, fifteen minutes, and then it is fine again" must never share a
// status, because a client that cannot tell them apart tells a user the wrong one.
//
// IT IS **403 forbidden**, which is core's own reserved name for exactly this
// case: the credential was good and the request is refused. No new problem code is
// invented for it, which is the cheaper half of the decision and the reason: core
// owns that list (see the "codes this service adds" block in openapi/v1.yaml) and
// a code invented for a case core already names is a code that has to be
// reconciled later. `account_locked` earns its own because 423 is a status core has
// no name for; this does not.
//
// # AND IT LEAKS NOTHING, WHICH IS WHY NAMING THE STATE IS FREE HERE
//
// The lockout's 423 leaks because the lock is checked BEFORE the password, so a
// stranger reads it after six unauthenticated requests. **This check is AFTER the
// password has been verified.** A caller who receives "this account is disabled"
// has already proved they hold the right password — at which point they already
// know the account exists, so the answer is not an enumeration oracle and not a
// weaker one.
//
// So this is strictly BETTER than the house's existing lockout answer rather than a
// departure from it, and it is the reason the honest sentence survives: a user who
// typed the right password into a login form is not an attacker, and telling them
// "invalid email or password" when their password is correct is a support call
// that cannot be closed. The ordering is the whole argument, and
// TestADisabledLoginIsRefusedAndOnlyAfterThePasswordIsVerified exists because the
// ordering is the part a future edit would break silently.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/oauth"
	"github.com/cafaye/identity/internal/users"
)

// A disabled account is refused, and the refusal names the state.
//
// It is one test rather than a table because there is exactly one shape to prove
// and three properties to hold on it: the error is a *DisabledError, the session
// mint was never reached, and the failure counter was left where a locked-out
// login would leave it rather than being credited or penalized by a state the
// caller cannot act on.
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

	// Not ErrInvalidCredentials, and that is the decision rather than an accident:
	// the caller proved the password, and a 401 would send them round the reset
	// loop that cannot help them.
	if errors.Is(err, ErrInvalidCredentials) {
		t.Error("a disabled login answered ErrInvalidCredentials; the person proved the " +
			"password and must be told the account is disabled")
	}

	// Nothing that authenticates anything came back. LoginResult has no field that
	// can carry a token here, and this asserts the whole struct rather than one
	// field so a future field cannot be the one that leaks.
	if result.Token != "" || result.MFARequired || result.Challenge != nil || !result.ExpiresAt.IsZero() {
		t.Errorf("LoginResult = %+v, want every field zero: a refused login mints nothing", result)
	}
	if len(f.sessions.minted) != 0 {
		t.Errorf("%d sessions were minted for a disabled login, want 0", len(f.sessions.minted))
	}

	// The failure counter is untouched. A wrong password still counts, and this
	// login was not a wrong password — crediting it would let five wrong ones plus
	// one right one reset the run.
	if cleared := f.users.byID[u.ID].FailedLoginAttempts; cleared != 0 {
		t.Errorf("FailedLoginAttempts = %d after a disabled login, want 0: the password "+
			"was correct and the account state decided the answer", cleared)
	}
	if f.users.cleared != 0 {
		t.Errorf("ClearFailures ran %d times on a refused login, want 0", f.users.cleared)
	}
}

// THE ORDERING IS THE ENUMERATION REASONING, so it is a test and not a comment.
//
// A wrong password against a disabled account must be indistinguishable from a
// wrong password against an active one — ErrInvalidCredentials, the same value,
// from the same path — because that is the answer a stranger gets and it is the
// only answer that keeps this door from becoming an existence oracle for accounts
// an attacker did not create.
//
// The counter is asserted too, because "indistinguishable" that also meant "the
// disabled account is exempt from brute-force protection" would be a different
// feature. The lockout keeps working on a disabled account; it simply never gets
// the chance to be the reason the login ends.
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

// RE-ENABLE IS PART OF WHAT THIS PACKET SHIPS, and this is the test that keeps the
// concept honest rather than a one-way door.
//
// An irreversible disable is a different feature and needs its own name: this one
// is a state an operator can lift, and the state lifting has to restore the doors
// rather than leaving an account that is technically enabled and permanently
// unable to sign in.
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

// A LOCKED ACCOUNT STILL ANSWERS 423, because a lock is not a disable and the two
// statuses must not start agreeing.
//
// The table runs both states through the same call so that a future edit which
// moved the disabled check ABOVE the locked one — which would silently take the
// lockout's Retry-After away and leave a user waiting out a window that no longer
// exists — fails here rather than in a support ticket.
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

// BOTH AT ONCE IS STILL 423, and the reason is the order the doors are checked in.
//
// The lock is a policy that expires; the disable is a decision that does not. When
// both are true the honest answer is the one with a Retry-After in it, because
// that is the one whose window will actually close — and a caller told "disabled"
// when the account is merely locked would have no reason to come back in fifteen
// minutes and would instead go and ask an administrator to do something that was
// never needed.
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

// A DISABLED ACCOUNT WITH A SECOND FACTOR NEVER GETS A CHALLENGE.
//
// This is the shape of the mistake the whole package comment is about: a 202 with
// a challenge in it is a login that has been HALF-finished, and the half that is
// missing is the one the disabled state answers. Handing out a challenge would put
// a credential on the wire for an account that is not going to be let in, and the
// challenge is a real one — it is spent, it is time-boxed, and it is exactly the
// thing an attacker with a disabled account's password would want to hold.
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

// THE SOCIAL CALLBACK IS THE SAME DOOR, AND startLogin IS WHY.
//
// internal/auth/social.go resolves a provider identity to a local user and then
// calls startLogin — the same function the password path calls, and the one place
// in this package that mints a session without a password having been verified.
// Putting the check there rather than in Login is what makes the social door
// covered without a second edit that could be forgotten, and this test is what
// holds that: it drives the callback with a real connected account for a disabled
// user and asserts nothing came back.
//
// The enumeration argument does not transfer, and the reason is a fact about the
// provider rather than about this check: the caller has already proved control of
// a provider account whose address this service believes (internal/oauth refuses
// an unverified address), so they already know the local account exists.
func TestASocialCallbackForADisabledAccountMintsNothing(t *testing.T) {
	t.Parallel()

	f := newSocialFixtureWithBothProviders(t)

	// The connected account exists BEFORE the disable, which is the case that
	// matters: signInAs is the path a provider identity already linked takes, and
	// it is the one that ends at startLogin with a user row in hand. A disabled
	// account that had never used the provider would be refused earlier for
	// having no connected account at all, which proves nothing about this door.
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

// A disabled user cannot turn a LIVE CHALLENGE INTO A SESSION, which is the one
// door the disabled check in startLogin does NOT cover.
//
// startLogin creates a challenge; CompleteSecondFactor turns one into a session
// and is reached by a token the caller holds rather than by a user row. A user who
// was disabled between the two halves of their own login is exactly the window
// this closes, and it is a real one: ten minutes is long enough for an
// administrator to act inside it.
//
// The check is inside the same transaction that creates the session, so a refusal
// rolls the session back rather than minting one and apologizing.
func TestCompletingASecondFactorForAnAccountDisabledMidwayMintsNoSession(t *testing.T) {
	t.Parallel()

	f := newFixture()
	u := f.register(t, "kaka@example.com", "correct horse battery staple")
	f.mfa.enabled[u.ID] = true
	// The claim must name THIS user. VerifyChallenge hands back whatever `claim`
	// holds and CompleteSecondFactor mints the session for claim.UserID(), so
	// without this the test would disable one account and refuse-check another.
	f.mfa.claim = f.mfa.claimFor(u.ID)

	// First half: a correct password on an enabled account, which is the only way
	// to obtain a challenge at all.
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

	// And now somebody turns the account off, mid-login.
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

// A DISABLED USER HOLDS NO SESSION, and this is the test that says what the
// same-transaction revocation buys.
//
// The revocation is why this passes without a check in Authenticate: the row is
// gone, so the lookup misses for a reason the caller cannot distinguish from a
// token that never existed. If somebody made the revocation a soft flag instead,
// THIS is the test that fails — and it would fail at the login too, because a
// soft flag on the session is the shape this packet's migration header argues
// against when it says sessions are revoked by DELETE.
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

	// It works. Asserted, because a test that only checks the refusal passes just
	// as well against a token that was never valid.
	if _, err := f.svc.Authenticate(context.Background(), live.Token); err != nil {
		t.Fatalf("the live session does not authenticate before the disable: %v", err)
	}

	f.disable(t, u.ID)

	if _, err := f.svc.Authenticate(context.Background(), live.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("presenting a live session for a disabled user = %v, want ErrUnauthenticated", err)
	}
}
