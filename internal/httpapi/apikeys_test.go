package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/accounts"
	"github.com/anywaye/identity/internal/apikeys"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/users"
)


const fakeKeyPrefix = apikeys.Prefix

const (
	apiKeySecret = fakeKeyPrefix + "TESTONLYnotArealcredentialTESTONLYnotArealcredential"
)

type fakeAPIKeys struct {
	mu sync.Mutex

	issued apikeys.IssuedKey
	list   []apikeys.Key

	mintErr   error
	listErr   error
	revokeErr error

	minted  []apikeys.MintInput
	revoked []apikeys.RevokeInput
	listed  []id.UUID
}

func newFakeAPIKeys() *fakeAPIKeys {
	var accountID, userID, keyID id.UUID
	accountID[0], userID[0], keyID[0] = 0x11, 0x22, 0x33

	created := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	return &fakeAPIKeys{
		issued: apikeys.IssuedKey{
			Key: apikeys.Key{
				ID: keyID, AccountID: accountID, UserID: userID,
				Name:      "ci-deploy",
				Scopes:    []string{apikeys.ScopeAccountsRead},
				CreatedAt: created,
				ExpiresAt: created.AddDate(0, 3, 0),
			},
			Token: fakeKeyPrefix + "Zq3vK7mXpR2tY8wB4cN6dF0gH1jK5lM9oP3qS7uV2wX4yZ8",
		},
	}
}

func (f *fakeAPIKeys) Mint(_ context.Context, in apikeys.MintInput) (apikeys.IssuedKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.mintErr != nil {
		return apikeys.IssuedKey{}, f.mintErr
	}
	f.minted = append(f.minted, in)
	return f.issued, nil
}

func (f *fakeAPIKeys) List(_ context.Context, accountID id.UUID) ([]apikeys.Key, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	f.listed = append(f.listed, accountID)
	return f.list, nil
}

func (f *fakeAPIKeys) Revoke(_ context.Context, in apikeys.RevokeInput) (apikeys.Key, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revokeErr != nil {
		return apikeys.Key{}, f.revokeErr
	}
	f.revoked = append(f.revoked, in)
	return apikeys.Key{ID: in.KeyID, AccountID: in.AccountID}, nil
}


func TestMintAPIKeyReturnsTheSecretOnce(t *testing.T) {
	t.Parallel()

	f := newFakeAPIKeys()
	auth := newFakeAuth()
	handler := New(nil, WithAuth(auth), WithTenancy(apiKeyTenancy()), WithAPIKeys(f))

	rec := apiKeyPost(t, handler, apiKeyPath(f.issued.Key.AccountID), auth.token,
		`{"name":"ci-deploy","scopes":["accounts:read"]}`)

	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /v1/accounts/:id/api-keys = %d, want 201; body: %s", rec.Code, rec.Body)
	}
	if got, want := rec.Header().Get("Content-Type"), "application/json; charset=utf-8"; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}

	var body issuedAPIKeyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not JSON: %v\n%s", err, rec.Body)
	}

	if body.Token != f.issued.Token {
		t.Errorf("token = %q, want the issued value", body.Token)
	}

	if body.ID != f.issued.Key.ID.String() {
		t.Errorf("id = %q, want %q", body.ID, f.issued.Key.ID)
	}
	rendered := rec.Body.String()
	if strings.Contains(rendered, f.issued.Key.TokenDigest) && f.issued.Key.TokenDigest != "" {
		t.Errorf("the response carries the row's digest: %s", rendered)
	}
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if _, present := raw["last_used_at"]; present {
		t.Error("last_used_at is present on a token that has never been used")
	}
	for _, forbidden := range []string{"token_digest", "digest", "secret"} {
		if _, present := raw[forbidden]; present {
			t.Errorf("the response has a %q field", forbidden)
		}
	}

	listed := apiKeyGet(t, handler, apiKeyPath(f.issued.Key.AccountID), auth.token)
	if listed.Code != http.StatusOK {
		t.Fatalf("GET /v1/accounts/:id/api-keys = %d, want 200; body: %s", listed.Code, listed.Body)
	}
	if strings.Contains(listed.Body.String(), f.issued.Token) {
		t.Errorf("the list returns the secret: %s", listed.Body)
	}
}

func TestTheListCarriesNoSecretUnderAnyName(t *testing.T) {
	t.Parallel()

	f := newFakeAPIKeys()
	revokedAt := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	reason := "rotated"
	f.list = []apikeys.Key{
		{ID: id.MustNew(), Name: "live", Scopes: []string{apikeys.ScopeAccountsRead},
			CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)},
		{ID: id.MustNew(), Name: "gone", Scopes: []string{apikeys.ScopeAccountsWrite},
			CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
			RevokedAt: &revokedAt, RevokeReason: &reason},
	}

	auth := newFakeAuth()
	handler := New(nil, WithAuth(auth), WithTenancy(apiKeyTenancy()), WithAPIKeys(f))
	rec := apiKeyGet(t, handler, apiKeyPath(id.MustNew()), auth.token)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), f.issued.Token) {
		t.Errorf("the list body contains the issued secret: %s", rec.Body)
	}
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if strings.Contains(line, fakeKeyPrefix) {
			t.Errorf("the list body carries a token-shaped value: %s", line)
		}
	}
}

func TestTheListIsAnArrayNotNull(t *testing.T) {
	t.Parallel()

	f := newFakeAPIKeys()
	auth := newFakeAuth()
	handler := New(nil, WithAuth(auth), WithTenancy(apiKeyTenancy()), WithAPIKeys(f))
	rec := apiKeyGet(t, handler, apiKeyPath(id.MustNew()), auth.token)

	if got, want := strings.TrimSpace(rec.Body.String()), "[]"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestTheScopesSurviveTheWire(t *testing.T) {
	t.Parallel()

	f := newFakeAPIKeys()
	f.issued.Key.Scopes = []string{apikeys.ScopeAccountsRead, apikeys.ScopeAccountsWrite}
	auth := newFakeAuth()
	handler := New(nil, WithAuth(auth), WithTenancy(apiKeyTenancy()), WithAPIKeys(f))

	rec := apiKeyPost(t, handler, apiKeyPath(f.issued.Key.AccountID), auth.token,
		`{"name":"ci-deploy","scopes":["accounts:read","accounts:write"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST = %d, want 201; body: %s", rec.Code, rec.Body)
	}

	var body issuedAPIKeyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if len(body.Scopes) != 2 ||
		body.Scopes[0] != apikeys.ScopeAccountsRead ||
		body.Scopes[1] != apikeys.ScopeAccountsWrite {
		t.Errorf("scopes = %v, want the two granted values in order", body.Scopes)
	}
}

func TestMintTakesTheAccountFromThePathAndTheUserFromTheSession(t *testing.T) {
	t.Parallel()

	f := newFakeAPIKeys()
	auth := newFakeAuth()
	handler := New(nil, WithAuth(auth), WithTenancy(apiKeyTenancy()), WithAPIKeys(f))

	accountInPath := id.MustNew()
	rec := apiKeyPost(t, handler, apiKeyPath(accountInPath), auth.token,
		`{"name":"ci","scopes":["accounts:read"],`+
			`"account_id":"`+id.MustNew().String()+`","user_id":"`+id.MustNew().String()+`"}`)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a body naming its own account = %d, want 422; body: %s", rec.Code, rec.Body)
	}
	p := decodeProblem(t, rec)
	if p.Code != CodeValidationFailed {
		t.Errorf("code = %q, want %q", p.Code, CodeValidationFailed)
	}
	if !strings.Contains(p.Detail, "does not accept") {
		t.Errorf("the detail does not say what is wrong: %q", p.Detail)
	}
	if len(f.minted) != 0 {
		t.Error("the use case was reached at all")
	}

	rec = apiKeyPost(t, handler, apiKeyPath(accountInPath), auth.token,
		`{"name":"ci","scopes":["accounts:read"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST = %d, want 201; body: %s", rec.Code, rec.Body)
	}
	if len(f.minted) != 1 {
		t.Fatalf("the use case was called %d times, want 1", len(f.minted))
	}
	if f.minted[0].AccountID != accountInPath {
		t.Errorf("the use case was given account %s, want the path's %s", f.minted[0].AccountID, accountInPath)
	}
	if f.minted[0].MintedBy != auth.user.ID {
		t.Errorf("the use case was given user %s, want the session's %s", f.minted[0].MintedBy, auth.user.ID)
	}
}

func TestExpiresInIsSecondsAndOptional(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		body    string
		wantSet bool
		want    time.Duration
	}{
		{name: "omitted", body: `{"name":"ci","scopes":["accounts:read"]}`},
		{
			name: "thirty days", body: `{"name":"ci","scopes":["accounts:read"],"expires_in":2592000}`,
			wantSet: true, want: 30 * 24 * time.Hour,
		},
		{
			name: "negative", body: `{"name":"ci","scopes":["accounts:read"],"expires_in":-1}`,
			wantSet: true, want: -time.Second,
		},
		{
			name: "zero", body: `{"name":"ci","scopes":["accounts:read"],"expires_in":0}`,
			wantSet: true, want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFakeAPIKeys()
			auth := newFakeAuth()
			handler := New(nil, WithAuth(auth), WithTenancy(apiKeyTenancy()), WithAPIKeys(f))

			rec := apiKeyPost(t, handler, apiKeyPath(f.issued.Key.AccountID), auth.token, tt.body)
			if rec.Code != http.StatusCreated {
				t.Fatalf("POST = %d, want 201; body: %s", rec.Code, rec.Body)
			}
			if len(f.minted) != 1 {
				t.Fatalf("the use case was called %d times, want 1", len(f.minted))
			}
			got := f.minted[0].ExpiresIn
			if !tt.wantSet {
				if got != nil {
					t.Errorf("ExpiresIn = %v, want nil so the default applies", *got)
				}
				return
			}
			if got == nil {
				t.Fatal("ExpiresIn = nil, want the requested lifetime")
			}
			if *got != tt.want {
				t.Errorf("ExpiresIn = %s, want %s", *got, tt.want)
			}
		})
	}
}


func TestTheAPIKeyRoutesRequireAnOwner(t *testing.T) {
	t.Parallel()

	for _, role := range accounts.AllRoles() {
		t.Run(string(role), func(t *testing.T) {
			t.Parallel()

			tenancy := apiKeyTenancy()
			tenancy.role = role
			auth := newFakeAuth()
			handler := New(nil, WithAuth(auth), WithTenancy(tenancy), WithAPIKeys(newFakeAPIKeys()))

			rec := apiKeyGet(t, handler, apiKeyPath(id.MustNew()), auth.token)
			switch {
			case role.AtLeast(accounts.RoleOwner):
				if rec.Code != http.StatusOK {
					t.Errorf("an %s listing api keys = %d, want 200; body: %s", role, rec.Code, rec.Body)
				}
			default:
				if rec.Code != http.StatusForbidden {
					t.Errorf("a %s listing api keys = %d, want 403; body: %s", role, rec.Code, rec.Body)
				}
				if p := decodeProblem(t, rec); p.Code != CodeForbidden {
					t.Errorf("code = %q, want %q", p.Code, CodeForbidden)
				}
			}
		})
	}
}

func TestTheAPIKeyRoutesRefuseAnonymous(t *testing.T) {
	t.Parallel()

	keys := newFakeAPIKeys()
	handler := New(nil, WithAuth(newFakeAuth()), WithTenancy(apiKeyTenancy()), WithAPIKeys(keys))
	account := id.MustNew()

	for _, tt := range []struct {
		name   string
		method string
		path   string
	}{
		{"mint", http.MethodPost, "/v1/accounts/" + account.String() + "/api-keys"},
		{"list", http.MethodGet, "/v1/accounts/" + account.String() + "/api-keys"},
		{"revoke", http.MethodDelete, "/v1/accounts/" + account.String() + "/api-keys/" + id.MustNew().String()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rec := send(t, handler, tt.method, tt.path, "")
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%s %s anonymously = %d, want 401; body: %s", tt.method, tt.path, rec.Code, rec.Body)
			}
		})
	}
	if len(keys.minted) != 0 || len(keys.revoked) != 0 {
		t.Error("an unauthenticated request reached the use cases")
	}
}

func TestATokenCannotReachTheCredentialSurface(t *testing.T) {
	t.Parallel()

	for _, scope := range apikeys.AllScopes() {
		t.Run(scope, func(t *testing.T) {
			t.Parallel()

			keys := newFakeAPIKeys()
			auth := newFakeAuth()
			caller := newFakeAPIKeyCaller(auth.user, apikeys.Key{
				ID: id.MustNew(), AccountID: id.MustNew(), Scopes: []string{scope},
			})
			handler := New(nil,
				WithAuth(auth), WithTenancy(apiKeyTenancy()),
				WithAPIKeys(keys), WithAPIKeyCaller(caller),
			)
			account := caller.key.AccountID

			for _, tt := range []struct {
				name   string
				method string
				path   string
			}{
				{"mint", http.MethodPost, apiKeyPath(account)},
				{"list", http.MethodGet, apiKeyPath(account)},
				{"revoke", http.MethodDelete, apiKeyPath(account) + "/" + id.MustNew().String()},
			} {
				rec := apiKeySend(t, handler, tt.method, tt.path, apiKeySecret, `{}`)
				if rec.Code != http.StatusForbidden {
					t.Errorf("a token with %s reaching %s %s = %d, want 403; body: %s",
						scope, tt.method, tt.path, rec.Code, rec.Body)
				}
			}
			if len(keys.minted) != 0 || len(keys.revoked) != 0 {
				t.Errorf("a token with %s reached the use cases", scope)
			}
		})
	}
}

func TestEveryScopeIsEnforcedOnItsRoutes(t *testing.T) {
	t.Parallel()

	for route, scope := range accountRouteScopes {
		parts := strings.SplitN(route, " ", 2)
		if len(parts) != 2 {
			t.Errorf("the scope table's key %q is not a method and a path", route)
			continue
		}
		if !apikeys.IsSupportedScope(scope) {
			t.Errorf("route %s requires scope %q, which is not in the vocabulary", route, scope)
		}
	}

	used := make(map[string][]string, len(apikeys.AllScopes()))
	for route, scope := range accountRouteScopes {
		used[scope] = append(used[scope], route)
	}
	for _, scope := range apikeys.AllScopes() {
		if len(used[scope]) == 0 {
			t.Errorf("scope %q is in the vocabulary and is enforced on no route, "+
				"which is what a comment with a type looks like", scope)
		}
	}
}


func TestRevokeWorksWithAndWithoutABody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		body       string
		wantReason string
	}{
		{name: "no body at all"},
		{name: "an empty object", body: `{}`},
		{name: "a reason", body: `{"reason":"rotated"}`, wantReason: "rotated"},
		{name: "an empty reason", body: `{"reason":""}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFakeAPIKeys()
			auth := newFakeAuth()
			handler := New(nil, WithAuth(auth), WithTenancy(apiKeyTenancy()), WithAPIKeys(f))
			keyID := id.MustNew()

			rec := apiKeyDelete(t, handler,
				"/v1/accounts/"+f.issued.Key.AccountID.String()+"/api-keys/"+keyID.String(), auth.token, tt.body)
			if rec.Code != http.StatusNoContent {
				t.Fatalf("DELETE = %d, want 204; body: %s", rec.Code, rec.Body)
			}
			if rec.Body.Len() != 0 {
				t.Errorf("a 204 carried a body: %s", rec.Body)
			}
			if len(f.revoked) != 1 {
				t.Fatalf("the use case was called %d times, want 1", len(f.revoked))
			}
			if f.revoked[0].KeyID != keyID {
				t.Errorf("the use case was given key %s, want %s", f.revoked[0].KeyID, keyID)
			}
			if f.revoked[0].Reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", f.revoked[0].Reason, tt.wantReason)
			}
		})
	}
}

func TestRevokeRefusesAMalformedKeyId(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{"not-a-uuid", "123", "00000000-0000-0000-0000-000000000000", "%20"} {
		t.Run(bad, func(t *testing.T) {
			t.Parallel()

			f := newFakeAPIKeys()
			auth := newFakeAuth()
			handler := New(nil, WithAuth(auth), WithTenancy(apiKeyTenancy()), WithAPIKeys(f))

			rec := apiKeyDelete(t, handler,
				"/v1/accounts/"+f.issued.Key.AccountID.String()+"/api-keys/"+bad, auth.token, "")
			if rec.Code != http.StatusNotFound {
				t.Errorf("revoking %q = %d, want 404; body: %s", bad, rec.Code, rec.Body)
			}
			if len(f.revoked) != 0 {
				t.Error("a malformed id reached the use case")
			}
		})
	}
}


func TestAPIKeyErrorMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		give       error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "a member who is not an owner",
			give:       apikeys.ErrNotAuthorized,
			wantStatus: http.StatusForbidden, wantCode: CodeForbidden,
		},
		{
			name:       "a key that is not there",
			give:       apikeys.ErrNotFound,
			wantStatus: http.StatusNotFound, wantCode: CodeNotFound,
		},
		{
			name:       "already revoked",
			give:       apikeys.ErrAlreadyRevoked,
			wantStatus: http.StatusConflict, wantCode: CodeConflict,
		},
		{
			name:       "the name is taken by a live key",
			give:       apikeys.ErrNameTaken,
			wantStatus: http.StatusConflict, wantCode: CodeConflict,
		},
		{
			name:       "a bad field",
			give:       &apikeys.FieldError{Field: "scopes", Code: apikeys.CodeUnsupported},
			wantStatus: http.StatusUnprocessableEntity, wantCode: CodeValidationFailed,
		},
		{
			name:       "anything else is a 500",
			give:       errors.New("the database is on fire"),
			wantStatus: http.StatusInternalServerError, wantCode: CodeInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFakeAPIKeys()
			f.listErr = tt.give
			auth := newFakeAuth()
			logs := &recordingHandler{}
			handler := New(nil,
				WithAuth(auth), WithTenancy(apiKeyTenancy()), WithAPIKeys(f),
				WithLogger(slogLogger(logs)),
			)

			rec := apiKeyGet(t, handler, apiKeyPath(f.issued.Key.AccountID), auth.token)
			if rec.Code != tt.wantStatus {
				t.Fatalf("= %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body)
			}
			p := decodeProblem(t, rec)
			if p.Code != tt.wantCode {
				t.Errorf("code = %q, want %q", p.Code, tt.wantCode)
			}
			if p.TraceID == "" {
				t.Error("the problem carries no trace_id; support cannot start from it")
			}
			if rec.Header().Get(TraceHeader) != p.TraceID {
				t.Errorf("the header's trace id (%q) and the body's (%q) disagree",
					rec.Header().Get(TraceHeader), p.TraceID)
			}
		})
	}
}

func TestAnInternalFailureIsLoggedNotReturned(t *testing.T) {
	t.Parallel()

	f := newFakeAPIKeys()
	f.listErr = errors.New("pq: password authentication failed for user \"identity\" at 10.0.0.5")
	auth := newFakeAuth()
	logs := &recordingHandler{}
	handler := New(nil,
		WithAuth(auth), WithTenancy(apiKeyTenancy()), WithAPIKeys(f),
		WithLogger(slogLogger(logs)),
	)

	rec := apiKeyGet(t, handler, apiKeyPath(f.issued.Key.AccountID), auth.token)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("= %d, want 500", rec.Code)
	}

	p := decodeProblem(t, rec)
	for _, leak := range []string{"10.0.0.5", "password", "pq:"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("the 500 body leaks %q: %s", leak, rec.Body)
		}
		if strings.Contains(p.Detail, leak) {
			t.Errorf("the detail leaks %q: %s", leak, p.Detail)
		}
	}

	rendered := logs.rendered()
	if !strings.Contains(rendered, "10.0.0.5") {
		t.Errorf("the underlying error did not reach the log:\n%s", rendered)
	}
	if !strings.Contains(rendered, p.TraceID) {
		t.Errorf("the log line does not carry the trace id the caller was given:\n%s", rendered)
	}
}

func TestTheRoutesAreAbsentWithoutTheService(t *testing.T) {
	t.Parallel()

	auth := newFakeAuth()
	handler := New(nil, WithAuth(auth), WithTenancy(apiKeyTenancy()))
	account := id.MustNew()

	for _, path := range []string{"/v1/accounts/" + account.String() + "/api-keys"} {
		if rec := apiKeyGet(t, handler, path, auth.token); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s without the service = %d, want 404", path, rec.Code)
		}
	}
}


type fakeAPIKeyCaller struct {
	mu sync.Mutex

	key    apikeys.Key
	user   users.User
	role   accounts.Role
	err    error
	seen   []string
	sawNow time.Time
}

func newFakeAPIKeyCaller(user users.User, key apikeys.Key) *fakeAPIKeyCaller {
	return &fakeAPIKeyCaller{key: key, user: user, role: accounts.RoleOwner}
}

func (f *fakeAPIKeyCaller) Authenticate(_ context.Context, token string, now time.Time) (apikeys.Caller, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return apikeys.Caller{}, f.err
	}
	f.seen = append(f.seen, token)
	f.sawNow = now
	key := f.key
	key.Role = f.role
	return apikeys.Caller{User: f.user, Key: key, Role: f.role}, nil
}

func apiKeyPath(accountID id.UUID) string {
	return "/v1/accounts/" + accountID.String() + "/api-keys"
}

func apiKeyTenancy() *fakeTenancy {
	f := newFakeTenancy()
	f.role = accounts.RoleOwner
	f.account = accounts.Account{Name: "Acme", Slug: "acme"}
	return f
}

func apiKeyPost(t *testing.T, h http.Handler, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	return apiKeySend(t, h, http.MethodPost, path, token, body)
}

func apiKeyGet(t *testing.T, h http.Handler, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	return apiKeySend(t, h, http.MethodGet, path, token, "")
}

func apiKeyDelete(t *testing.T, h http.Handler, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	return apiKeySend(t, h, http.MethodDelete, path, token, body)
}

func apiKeySend(t *testing.T, h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

var _ = fmt.Sprintf
