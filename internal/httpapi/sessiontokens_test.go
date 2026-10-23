package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/accounts"
	"github.com/anywaye/identity/internal/oidc"
	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/id"
)

// The session-to-token exchange, endpoint by endpoint.
//
// The claim set itself (iss, aud, account_id, the signature) is the provider's
// and is asserted in `internal/oidc/mint_test.go`. What is asserted HERE is the
// authorization decision this layer owns: which account is allowed to be named,
// what a refusal looks like, and which credentials may reach the route at all.
// The double is `fakeOIDC`, which records every call, so "nothing was minted"
// is a check that can actually fail.
type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

func sessionTokenRouter(t *testing.T, tenancy Tenancy, provider OIDC, now time.Time) (http.Handler, *fakeAuth) {
	t.Helper()

	auth := newFakeAuth()
	return New(nil,
		WithAuth(auth),
		WithTenancy(tenancy),
		WithOIDC(provider),
		WithClock(fixedClock{now: now}),
	), auth
}

func TestMintSessionTokenMintsForTheAccountTheCallerNamed(t *testing.T) {
	accountID := id.MustNew()
	tenancy := newFakeTenancy()
	tenancy.role = accounts.RoleMember
	provider := newFakeOIDC()
	now := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)

	handler, auth := sessionTokenRouter(t, tenancy, provider, now)
	rec := requestAs(t, handler, auth.token, http.MethodPost, "/v1/session/tokens",
		`{"account_id":"`+accountID.String()+`","audience":"billing"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	var body mintedSessionTokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not the exchange's response: %v\n%s", err, rec.Body)
	}
	if body.Token != "fake-minted-token" {
		t.Errorf("token = %q, want the provider's own", body.Token)
	}
	if want := now.Add(oidc.AccountTokenTTL); !body.ExpiresAt.Equal(want) {
		t.Errorf("expires_at = %s, want %s — the provider's expiry, through the service's clock", body.ExpiresAt, want)
	}

	// The whole of the decision: the subject is the session's user, the account
	// is the one the BODY named, and the instant is the service clock's.
	if len(provider.minted) != 1 {
		t.Fatalf("the provider was asked %d times, want 1", len(provider.minted))
	}
	request := provider.minted[0]
	if request.subject != auth.user.ID {
		t.Errorf("subject = %s, want the session's user %s", request.subject, auth.user.ID)
	}
	if request.accountID != accountID {
		t.Errorf("account = %s, want the account the body named %s", request.accountID, accountID)
	}
	if request.audience != "billing" {
		t.Errorf("audience = %q, want billing", request.audience)
	}
	if !request.at.Equal(now) {
		t.Errorf("minted at %s, want %s", request.at, now)
	}
}

// A caller who is not a member of the account they named gets the tenancy
// layer's one absence sentence, and NOTHING is signed. The second half is the
// half that matters: a 404 that still minted would be a lockout with a
// credential attached.
func TestMintSessionTokenIsAbsentForAnAccountTheCallerIsNotIn(t *testing.T) {
	tenancy := newFakeTenancy()
	tenancy.getErr = accounts.ErrNotAMember
	provider := newFakeOIDC()

	handler, auth := sessionTokenRouter(t, tenancy, provider, testInstant)
	rec := requestAs(t, handler, auth.token, http.MethodPost, "/v1/session/tokens",
		`{"account_id":"`+id.MustNew().String()+`","audience":"billing"}`)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", rec.Code, rec.Body)
	}
	if code := decodeProblem(t, rec).Code; code != CodeNotFound {
		t.Errorf("code = %q, want %q", code, CodeNotFound)
	}
	if len(provider.minted) != 0 {
		t.Errorf("a refused exchange minted %d token(s); the refusal must come before the signature", len(provider.minted))
	}
}

// Table of the shapes that are wrong before any store is consulted: a missing
// field, an account id that cannot name anything, an audience that is not a
// service name. Each is a 422 naming its own field, and none of them mints.
func TestMintSessionTokenFieldRefusals(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantField string
		wantCode  string
	}{
		{
			name:      "no account_id",
			body:      `{"audience":"billing"}`,
			wantField: "account_id",
			wantCode:  codeTokenFieldRequired,
		},
		{
			name:      "an account_id that is not an id",
			body:      `{"account_id":"not-a-uuid","audience":"billing"}`,
			wantField: "account_id",
			wantCode:  codeTokenFieldInvalid,
		},
		{
			name:      "no audience",
			body:      `{"account_id":"` + id.MustNew().String() + `"}`,
			wantField: "audience",
			wantCode:  codeTokenFieldInvalid,
		},
		{
			// Uppercase, spaces, a path: none of them is a service name, and a
			// receiver pinning its own audience will never match one.
			name:      "an audience that is not a service name",
			body:      `{"account_id":"` + id.MustNew().String() + `","audience":"https://billing.anywaye.com"}`,
			wantField: "audience",
			wantCode:  codeTokenFieldInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := newFakeOIDC()
			handler, auth := sessionTokenRouter(t, newFakeTenancy(), provider, testInstant)

			rec := requestAs(t, handler, auth.token, http.MethodPost, "/v1/session/tokens", tt.body)

			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422; body: %s", rec.Code, rec.Body)
			}
			problem := decodeProblem(t, rec)
			if len(problem.Errors) != 1 || problem.Errors[0].Field != tt.wantField || problem.Errors[0].Code != tt.wantCode {
				t.Errorf("field errors = %+v, want one %s/%s", problem.Errors, tt.wantField, tt.wantCode)
			}
			if len(provider.minted) != 0 {
				t.Errorf("a refused body minted %d token(s)", len(provider.minted))
			}
		})
	}
}

// A scoped api key is refused by the same middleware every session surface
// uses. THIS IS THE ESCALATION GUARD: a machine credential bound to one account
// must not be able to mint a token that asserts a human's identity.
func TestMintSessionTokenRefusesAnAPIKey(t *testing.T) {
	provider := newFakeOIDC()
	handler, _ := sessionTokenRouter(t, newFakeTenancy(), provider, testInstant)

	rec := requestAs(t, handler, "anywaye_scoped_token_value", http.MethodPost, "/v1/session/tokens",
		`{"account_id":"`+id.MustNew().String()+`","audience":"billing"}`)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body: %s", rec.Code, rec.Body)
	}
	if len(provider.minted) != 0 {
		t.Errorf("an api key minted %d token(s)", len(provider.minted))
	}
}

// A signer failure is this service's own fault and is a 500, not a refusal the
// caller could act on. The provider double makes it expressible.
func TestMintSessionTokenRefusesWithoutASigner(t *testing.T) {
	provider := newFakeOIDC()
	provider.mintErr = errors.New("the signing key is gone")

	handler, auth := sessionTokenRouter(t, newFakeTenancy(), provider, testInstant)
	rec := requestAs(t, handler, auth.token, http.MethodPost, "/v1/session/tokens",
		`{"account_id":"`+id.MustNew().String()+`","audience":"billing"}`)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body)
	}
}

// Without a provider the route is not mounted, which is the rule every
// conditional surface here follows: a deployment that cannot mint says so with
// a 404 rather than with a 500 on every request.
func TestMintSessionTokenIsAbsentWithoutAProvider(t *testing.T) {
	auth := newFakeAuth()
	handler := New(nil, WithAuth(auth), WithTenancy(newFakeTenancy()))

	rec := requestAs(t, handler, auth.token, http.MethodPost, "/v1/session/tokens",
		`{"account_id":"`+id.MustNew().String()+`","audience":"billing"}`)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", rec.Code, rec.Body)
	}
}

// clock.System satisfies the interface the route reads its instant from; this
// line fails to compile if the option stops accepting it.
var _ clock.Clock = clock.System{}
