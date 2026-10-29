package oidc

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/platform/id"
)


func (f storeFixture) newAuthRequest(t *testing.T, client Client, expiresAt time.Time) AuthRequest {
	t.Helper()

	request, err := f.store.CreateAuthRequest(f.ctx, f.q(), NewAuthRequest{
		ClientRowID:         client.ID,
		RedirectURI:         "https://app.example.com/cb",
		State:               "state-abc",
		Nonce:               "nonce-abc",
		ResponseType:        "code",
		ResponseMode:        "",
		Scopes:              []string{"accounts", "email", "openid"},
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		LoginHint:           "someone@example.com",
		CreatedAt:           storeTestNow,
		ExpiresAt:           expiresAt,
	})
	if err != nil {
		t.Fatalf("CreateAuthRequest: %v", err)
	}
	return request
}

func TestStoreAuthRequestRoundTrip(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)
	client := f.mustCreateClient(t, f.account, f.owner)
	request := f.newAuthRequest(t, client, storeTestNow.Add(AuthRequestTTL))

	if request.Subject != nil || request.AuthTime != nil {
		t.Error("a fresh request already has a subject; the user has not logged in yet")
	}
	if request.ClientID != client.ClientID {
		t.Errorf("the request carries client_id %q, want %q", request.ClientID, client.ClientID)
	}
	if request.ClientName != "Anytalk" {
		t.Errorf("the login page would show %q, want the registration's name", request.ClientName)
	}

	loaded, err := f.store.AuthRequestByID(f.ctx, f.q(), request.ID, storeTestNow)
	if err != nil {
		t.Fatalf("AuthRequestByID: %v", err)
	}
	if loaded.RedirectURI != request.RedirectURI {
		t.Errorf("redirect_uri = %q, want %q", loaded.RedirectURI, request.RedirectURI)
	}
	if loaded.CodeChallenge != request.CodeChallenge {
		t.Error("the code challenge did not survive the round trip")
	}
}

func TestStoreAuthRequestRefusesAnExpiredOne(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)
	client := f.mustCreateClient(t, f.account, f.owner)

	created, err := f.store.CreateAuthRequest(f.ctx, f.q(), NewAuthRequest{
		ClientRowID:         client.ID,
		RedirectURI:         "https://app.example.com/cb",
		State:               "state-abc",
		Nonce:               "nonce-abc",
		ResponseType:        "code",
		Scopes:              []string{"openid"},
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		CreatedAt:           storeTestNow.Add(-time.Hour),
		ExpiresAt:           storeTestNow.Add(-time.Second),
	})
	if err != nil {
		t.Fatalf("CreateAuthRequest: %v", err)
	}

	if _, err := f.store.AuthRequestByID(f.ctx, f.q(), created.ID, storeTestNow); !errors.Is(err, ErrAuthRequestNotFound) {
		t.Errorf("AuthRequestByID on an expired request = %v, want ErrAuthRequestNotFound", err)
	}
	if _, err := f.store.AuthRequestByID(f.ctx, f.q(), id.MustNew(), storeTestNow); !errors.Is(err, ErrAuthRequestNotFound) {
		t.Errorf("AuthRequestByID on an unknown id = %v, want ErrAuthRequestNotFound", err)
	}
}

func TestStoreCompleteAuthRequestIsOnceOnly(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)
	client := f.mustCreateClient(t, f.account, f.owner)
	request := f.newAuthRequest(t, client, storeTestNow.Add(AuthRequestTTL))
	_, other := f.seedAccount(t, "completer")

	if err := f.store.CompleteAuthRequest(f.ctx, f.q(), request.ID, f.owner, storeTestNow); err != nil {
		t.Fatalf("CompleteAuthRequest: %v", err)
	}

	loaded, err := f.store.AuthRequestByID(f.ctx, f.q(), request.ID, storeTestNow)
	if err != nil {
		t.Fatalf("AuthRequestByID: %v", err)
	}
	if loaded.Subject == nil || *loaded.Subject != f.owner {
		t.Errorf("subject = %v, want %s", loaded.Subject, f.owner)
	}
	if loaded.AuthTime == nil || !loaded.AuthTime.Equal(storeTestNow) {
		t.Errorf("auth_time = %v, want the injected instant", loaded.AuthTime)
	}

	if err := f.store.CompleteAuthRequest(f.ctx, f.q(), request.ID, other, storeTestNow.Add(time.Minute)); !errors.Is(err, ErrAuthRequestNotFound) {
		t.Errorf("the second CompleteAuthRequest = %v, want a refusal", err)
	}
	after, err := f.store.AuthRequestByID(f.ctx, f.q(), request.ID, storeTestNow)
	if err != nil {
		t.Fatalf("AuthRequestByID: %v", err)
	}
	if *after.Subject != f.owner {
		t.Error("a second completion re-pointed the request at another user")
	}
}

func TestStoreAuthCodeIsRedeemableExactlyOnce(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)
	client := f.mustCreateClient(t, f.account, f.owner)
	request := f.newAuthRequest(t, client, storeTestNow.Add(AuthRequestTTL))

	if err := f.store.CompleteAuthRequest(f.ctx, f.q(), request.ID, f.owner, storeTestNow); err != nil {
		t.Fatalf("CompleteAuthRequest: %v", err)
	}
	if err := f.store.SaveAuthCode(f.ctx, f.q(), request.ID, SecretDigest("the-code"), storeTestNow.Add(time.Minute)); err != nil {
		t.Fatalf("SaveAuthCode: %v", err)
	}

	redeemed, err := f.store.ConsumeAuthCode(f.ctx, f.q(), SecretDigest("the-code"), storeTestNow.Add(30*time.Second))
	if err != nil {
		t.Fatalf("ConsumeAuthCode: %v", err)
	}
	if redeemed.ID != request.ID {
		t.Errorf("redeemed request %s, want %s", redeemed.ID, request.ID)
	}
	if redeemed.RedirectURI != request.RedirectURI || redeemed.CodeChallenge != request.CodeChallenge {
		t.Error("the redeemed request lost the fields the token exchange needs")
	}
	if len(redeemed.Scopes) != len(request.Scopes) {
		t.Errorf("scopes = %v, want %v", redeemed.Scopes, request.Scopes)
	}

	if _, err := f.store.ConsumeAuthCode(f.ctx, f.q(), SecretDigest("the-code"), storeTestNow.Add(31*time.Second)); !errors.Is(err, ErrNoAuthCode) {
		t.Errorf("the second ConsumeAuthCode = %v, want ErrNoAuthCode", err)
	}
	if _, err := f.store.ConsumeAuthCode(f.ctx, f.q(), SecretDigest("never-issued"), storeTestNow); !errors.Is(err, ErrNoAuthCode) {
		t.Errorf("ConsumeAuthCode for an unknown code = %v, want ErrNoAuthCode", err)
	}
}

func TestStoreExpiredAuthCodeIsNotRedeemable(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)
	client := f.mustCreateClient(t, f.account, f.owner)
	request := f.newAuthRequest(t, client, storeTestNow.Add(AuthRequestTTL))

	if err := f.store.SaveAuthCode(f.ctx, f.q(), request.ID, SecretDigest("the-code"), storeTestNow.Add(time.Minute)); err != nil {
		t.Fatalf("SaveAuthCode: %v", err)
	}

	if _, err := f.store.ConsumeAuthCode(f.ctx, f.q(), SecretDigest("the-code"), storeTestNow.Add(2*time.Minute)); !errors.Is(err, ErrNoAuthCode) {
		t.Errorf("ConsumeAuthCode after expiry = %v, want ErrNoAuthCode", err)
	}
}

func TestStoreAuthCodeCannotBeRedeemedTwiceConcurrently(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)
	client := f.mustCreateClient(t, f.account, f.owner)
	request := f.newAuthRequest(t, client, storeTestNow.Add(AuthRequestTTL))
	if err := f.store.SaveAuthCode(f.ctx, f.q(), request.ID, SecretDigest("the-code"), storeTestNow.Add(time.Minute)); err != nil {
		t.Fatalf("SaveAuthCode: %v", err)
	}

	const racers = 8
	var (
		start     sync.WaitGroup
		done      sync.WaitGroup
		mu        sync.Mutex
		succeeded int
	)
	start.Add(1)
	for i := 0; i < racers; i++ {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			_, err := f.store.ConsumeAuthCode(f.ctx, f.q(), SecretDigest("the-code"), storeTestNow.Add(30*time.Second))
			if err == nil {
				mu.Lock()
				succeeded++
				mu.Unlock()
			}
		}()
	}
	start.Done()
	done.Wait()

	if succeeded != 1 {
		t.Errorf("%d of %d concurrent redemptions succeeded, want exactly 1", succeeded, racers)
	}
}

func TestStoreSaveAuthCodeRefusesASecond(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)
	client := f.mustCreateClient(t, f.account, f.owner)
	request := f.newAuthRequest(t, client, storeTestNow.Add(AuthRequestTTL))

	if err := f.store.SaveAuthCode(f.ctx, f.q(), request.ID, SecretDigest("first"), storeTestNow.Add(time.Minute)); err != nil {
		t.Fatalf("the first SaveAuthCode: %v", err)
	}
	if err := f.store.SaveAuthCode(f.ctx, f.q(), request.ID, SecretDigest("second"), storeTestNow.Add(time.Minute)); !errors.Is(err, ErrNoAuthCode) {
		t.Errorf("the second SaveAuthCode = %v, want ErrNoAuthCode", err)
	}
	if _, err := f.store.ConsumeAuthCode(f.ctx, f.q(), SecretDigest("first"), storeTestNow); err != nil {
		t.Errorf("the first code is not redeemable: %v", err)
	}
}

func TestStoreRefusesAPlainCodeChallenge(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)
	client := f.mustCreateClient(t, f.account, f.owner)

	_, err := f.store.CreateAuthRequest(f.ctx, f.q(), NewAuthRequest{
		ClientRowID:         client.ID,
		RedirectURI:         "https://app.example.com/cb",
		State:               "state-abc",
		Nonce:               "nonce-abc",
		ResponseType:        "code",
		Scopes:              []string{"openid"},
		CodeChallenge:       "plain-verifier",
		CodeChallengeMethod: "plain",
		CreatedAt:           storeTestNow,
		ExpiresAt:           storeTestNow.Add(AuthRequestTTL),
	})
	if err == nil {
		t.Fatal("CreateAuthRequest accepted code_challenge_method plain")
	}
}

func TestStoreDeleteAuthRequestIsIdempotent(t *testing.T) {
	t.Parallel()

	f := newStoreFixture(t)
	client := f.mustCreateClient(t, f.account, f.owner)
	request := f.newAuthRequest(t, client, storeTestNow.Add(AuthRequestTTL))

	if err := f.store.DeleteAuthRequest(f.ctx, f.q(), request.ID); err != nil {
		t.Fatalf("the first DeleteAuthRequest: %v", err)
	}
	if err := f.store.DeleteAuthRequest(f.ctx, f.q(), request.ID); err != nil {
		t.Errorf("the second DeleteAuthRequest = %v, want nil", err)
	}
	if _, err := f.store.AuthRequestByID(f.ctx, f.q(), request.ID, storeTestNow); !errors.Is(err, ErrAuthRequestNotFound) {
		t.Errorf("AuthRequestByID after a delete = %v, want ErrAuthRequestNotFound", err)
	}
}
