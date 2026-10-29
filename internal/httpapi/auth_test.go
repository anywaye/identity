package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/auth"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/users"
)

func slogLogger(h slog.Handler) *slog.Logger { return slog.New(h) }

func decodeJSON(data []byte, v any) error { return json.Unmarshal(data, v) }

func parseUUIDish(s string) (string, error) {
	if len(s) != 36 {
		return "", errors.New("not 36 characters")
	}
	for i, r := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if r != '-' {
				return "", errors.New("dash in the wrong place")
			}
			continue
		}
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return "", errors.New("not lower-case hex")
		}
	}
	return s, nil
}


type fakeAuth struct {
	mu sync.Mutex

	user  users.User
	token string
	login auth.LoginResult

	registerErr error
	loginErr    error
	authErr     error
	logoutErr   error
	secondFactorErr error
	secondFactor auth.LoginResult
	disableErr error
	enableErr  error
	updateNameErr error

	registered []auth.RegisterInput
	loggedIn   []auth.LoginInput
	loggedOut  []string
	updatedDisplayNameFor []id.UUID
	updatedDisplayName    *string
	updateThemeErr  error
	updatedThemeFor []id.UUID
	updatedTheme    *string
	disableInputs []auth.DisableInput
	enableInputs  []auth.EnableInput
	searched      []searchCall
	searchResults []users.DirectoryEntry
	searchErr     error
	counts    users.UserCounts
	countsErr error
	disabled   []id.UUID
	disabledAt []time.Time
	enabled    []id.UUID
	completed []auth.CompleteSecondFactorInput
	lastAuthToken string

	sessions         []auth.Session
	listErr          error
	revokeSessionErr error
	listedAs         []string
	revokedSessions  []revokeSessionCall
}

func newFakeAuth() *fakeAuth {
	var uid id.UUID
	uid[0] = 0xab
	return &fakeAuth{
		user:  users.User{ID: uid, Email: "kaka@example.com"},
		token: "a-session-token",
		login: auth.LoginResult{
			User:      auth.RegisteredUser{ID: uid, Email: "kaka@example.com"},
			Token:     "a-session-token",
			ExpiresAt: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
		},
		secondFactor: auth.LoginResult{
			User:      auth.RegisteredUser{ID: uid, Email: "kaka@example.com"},
			Token:     "a-second-factor-token",
			ExpiresAt: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
		},
	}
}

func (f *fakeAuth) CompleteSecondFactor(_ context.Context, in auth.CompleteSecondFactorInput) (auth.LoginResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.completed = append(f.completed, in)
	if f.secondFactorErr != nil {
		return auth.LoginResult{}, f.secondFactorErr
	}
	return f.secondFactor, nil
}

func (f *fakeAuth) Register(_ context.Context, in auth.RegisterInput) (auth.RegisteredUser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.registered = append(f.registered, in)
	if f.registerErr != nil {
		return auth.RegisteredUser{}, f.registerErr
	}
	return auth.RegisteredUser{ID: f.user.ID, Email: f.user.Email}, nil
}

func (f *fakeAuth) Login(_ context.Context, in auth.LoginInput) (auth.LoginResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loggedIn = append(f.loggedIn, in)
	if f.loginErr != nil {
		return auth.LoginResult{}, f.loginErr
	}
	return f.login, nil
}

func (f *fakeAuth) Authenticate(_ context.Context, token string) (users.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastAuthToken = token
	if f.authErr != nil {
		return users.User{}, f.authErr
	}
	return f.user, nil
}

func (f *fakeAuth) Logout(_ context.Context, token string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loggedOut = append(f.loggedOut, token)
	return f.logoutErr
}

func (f *fakeAuth) ListSessions(_ context.Context, token string) ([]auth.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listedAs = append(f.listedAs, token)
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.sessions, nil
}

func (f *fakeAuth) RevokeSession(_ context.Context, token string, sessionID id.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokedSessions = append(f.revokedSessions, revokeSessionCall{token: token, sessionID: sessionID})
	return f.revokeSessionErr
}

type revokeSessionCall struct {
	token     string
	sessionID id.UUID
}

func (f *fakeAuth) Disable(_ context.Context, in auth.DisableInput) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disableInputs = append(f.disableInputs, in)
	f.disabled = append(f.disabled, in.UserID)
	f.disabledAt = append(f.disabledAt, in.At)
	return f.disableErr
}

func (f *fakeAuth) Enable(_ context.Context, in auth.EnableInput) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enableInputs = append(f.enableInputs, in)
	f.enabled = append(f.enabled, in.UserID)
	return f.enableErr
}

func (f *fakeAuth) UpdateDisplayName(_ context.Context, userID id.UUID, name *string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updatedDisplayNameFor = append(f.updatedDisplayNameFor, userID)
	f.updatedDisplayName = name
	return f.updateNameErr
}

func (f *fakeAuth) UpdateTheme(_ context.Context, userID id.UUID, theme *string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updatedThemeFor = append(f.updatedThemeFor, userID)
	f.updatedTheme = theme
	return f.updateThemeErr
}

func (f *fakeAuth) SearchUsers(_ context.Context, query string, limit int) ([]users.DirectoryEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.searched = append(f.searched, searchCall{query: query, limit: limit})
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	return f.searchResults, nil
}


func (f *fakeAuth) UserCounts(_ context.Context) (users.UserCounts, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.countsErr != nil {
		return users.UserCounts{}, f.countsErr
	}
	return f.counts, nil
}

type searchCall struct {
	query string
	limit int
}

func post(t *testing.T, h http.Handler, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	return send(t, h, http.MethodPost, target, body)
}

func send(t *testing.T, h http.Handler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()

	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequestWithContext(context.Background(), method, target, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeProblem(t *testing.T, rec *httptest.ResponseRecorder) Problem {
	t.Helper()

	if got, want := rec.Header().Get("Content-Type"), "application/problem+json"; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}
	var p Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("the body is not a problem document: %v\n%s", err, rec.Body)
	}
	return p
}


func TestRegisterHappyPath(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	rec := post(t, New(nil, WithAuth(f)), "/v1/users", `{"email":"kaka@example.com","password":"correct horse battery"}`)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", rec.Code, rec.Body)
	}
	if got, want := rec.Header().Get("Content-Type"), "application/json; charset=utf-8"; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}

	var body struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not JSON: %v\n%s", err, rec.Body)
	}
	if body.Email != "kaka@example.com" {
		t.Errorf("email = %q, want kaka@example.com", body.Email)
	}
	if body.ID != f.user.ID.String() {
		t.Errorf("id = %q, want %q", body.ID, f.user.ID)
	}

	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("the body is not a JSON object: %v", err)
	}
	if len(raw) != 2 {
		t.Errorf("the response has %d fields (%v), want exactly id and email", len(raw), raw)
	}
	for _, forbidden := range []string{"password", "digest", "password_digest", "locked_until", "failed_login_attempts"} {
		if _, present := raw[forbidden]; present {
			t.Errorf("the response carries %q", forbidden)
		}
	}
}

func TestRegisterDuplicateEmailIs409(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	f.registerErr = users.ErrEmailTaken

	rec := post(t, New(nil, WithAuth(f)), "/v1/users", `{"email":"kaka@example.com","password":"correct horse battery"}`)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body: %s", rec.Code, rec.Body)
	}
	p := decodeProblem(t, rec)
	if p.Code != CodeConflict {
		t.Errorf("code = %q, want %q", p.Code, CodeConflict)
	}
	if p.Type != errorTypeBase+CodeConflict {
		t.Errorf("type = %q, want %q", p.Type, errorTypeBase+CodeConflict)
	}
	if p.Status != http.StatusConflict {
		t.Errorf("body status = %d, want 409", p.Status)
	}
	if p.TraceID == "" {
		t.Error("trace_id is empty")
	}
}

func TestRegisterFieldErrorBecomes422WithErrorsArray(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		err       error
		wantField string
		wantCode  string
	}{
		{
			name:      "a short password",
			err:       &users.FieldError{Field: "password", Code: "too_short"},
			wantField: "password",
			wantCode:  "too_short",
		},
		{
			name:      "a malformed address",
			err:       &users.FieldError{Field: "email", Code: "invalid_format"},
			wantField: "email",
			wantCode:  "invalid_format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFakeAuth()
			f.registerErr = tt.err

			rec := post(t, New(nil, WithAuth(f)), "/v1/users",
				`{"email":"kaka@example.com","password":"correct horse battery"}`)

			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422; body: %s", rec.Code, rec.Body)
			}
			p := decodeProblem(t, rec)
			if p.Code != CodeValidationFailed {
				t.Errorf("code = %q, want %q", p.Code, CodeValidationFailed)
			}
			if p.Type != errorTypeBase+CodeValidationFailed {
				t.Errorf("type = %q, want %q", p.Type, errorTypeBase+CodeValidationFailed)
			}
			if len(p.Errors) != 1 {
				t.Fatalf("errors has %d entries, want 1: %+v", len(p.Errors), p.Errors)
			}
			if p.Errors[0].Field != tt.wantField || p.Errors[0].Code != tt.wantCode {
				t.Errorf("errors[0] = %+v, want %s/%s", p.Errors[0], tt.wantField, tt.wantCode)
			}

			if strings.Contains(rec.Body.String(), "correct horse") {
				t.Errorf("the 422 echoes the submitted password: %s", rec.Body)
			}
		})
	}
}

func TestRegisterMalformedJSONIs400(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{name: "truncated", body: `{"email":"kaka@example.com"`},
		{name: "not an object", body: `["kaka@example.com"]`},
		{name: "not JSON at all", body: `this is not json`},
		{name: "an empty body", body: ``},
		{name: "a JSON null", body: `null`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFakeAuth()
			rec := post(t, New(nil, WithAuth(f)), "/v1/users", tt.body)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body)
			}
			p := decodeProblem(t, rec)
			if p.Code != CodeInvalidJSON {
				t.Errorf("code = %q, want %q", p.Code, CodeInvalidJSON)
			}
			if p.Errors != nil {
				t.Errorf("errors = %v on a 400, want none; core scopes errors[] to 422", p.Errors)
			}
		})
	}
}

func TestRegisterRejectsAnOversizedBody(t *testing.T) {
	t.Parallel()

	huge := `{"email":"kaka@example.com","password":"` + strings.Repeat("a", maxRequestBody) + `"}`

	f := newFakeAuth()
	rec := post(t, New(nil, WithAuth(f)), "/v1/users", huge)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body: %s", rec.Code, rec.Body)
	}
	p := decodeProblem(t, rec)
	if p.Code != CodePayloadTooLarge {
		t.Errorf("code = %q, want %q", p.Code, CodePayloadTooLarge)
	}
	if f.hasRegistered() {
		t.Error("an oversized body reached the service")
	}
}

func TestRegisterUnknownFieldsAreRejected(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	rec := post(t, New(nil, WithAuth(f)), "/v1/users", `{"emial":"kaka@example.com","password":"correct horse battery"}`)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body: %s", rec.Code, rec.Body)
	}
	p := decodeProblem(t, rec)
	if p.Code != CodeValidationFailed {
		t.Errorf("code = %q, want %q", p.Code, CodeValidationFailed)
	}
}


func TestRegisterHoneypotFieldIsRefusedBeforeTheServiceIsCalled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		website string
	}{
		{name: "a filled honeypot", website: "http://spam.example.com"},
		{name: "a whitespace-only honeypot", website: "   "},
		{name: "a single character", website: "x"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFakeAuth()
			rec := post(t, New(nil, WithAuth(f)), "/v1/users",
				`{"email":"kaka@example.com","password":"correct horse battery","website":"`+tt.website+`"}`)

			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422; body: %s", rec.Code, rec.Body)
			}
			p := decodeProblem(t, rec)
			if p.Code != CodeValidationFailed {
				t.Errorf("code = %q, want %q", p.Code, CodeValidationFailed)
			}
			if strings.Contains(rec.Body.String(), "website") {
				t.Errorf("the 422 names the honeypot field: %s", rec.Body)
			}
			if f.hasRegistered() {
				t.Error("a populated honeypot reached the registration service")
			}
		})
	}
}

func TestRegisterEmptyHoneypotIsAccepted(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	rec := post(t, New(nil, WithAuth(f)), "/v1/users",
		`{"email":"kaka@example.com","password":"correct horse battery","website":""}`)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", rec.Code, rec.Body)
	}
	if !f.hasRegistered() {
		t.Error("an empty honeypot was refused")
	}
}


func TestLoginHappyPathSetsTheHostCookieAndReturnsTheToken(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	rec := post(t, New(nil, WithAuth(f)), "/v1/session", `{"email":"kaka@example.com","password":"correct horse battery"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	var body struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not JSON: %v\n%s", err, rec.Body)
	}
	if body.Token != f.login.Token {
		t.Errorf("token = %q, want %q", body.Token, f.login.Token)
	}
	if !body.ExpiresAt.Equal(f.login.ExpiresAt) {
		t.Errorf("expires_at = %s, want %s", body.ExpiresAt, f.login.ExpiresAt)
	}

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want exactly 1: %+v", len(cookies), cookies)
	}
	c := cookies[0]

	if c.Name != SessionCookieName {
		t.Errorf("cookie name = %q, want %q", c.Name, SessionCookieName)
	}
	if !strings.HasPrefix(c.Name, "__Host-") {
		t.Errorf("cookie name %q does not carry the __Host- prefix, so it is not origin-bound", c.Name)
	}
	if !c.Secure {
		t.Error("cookie is not Secure; a __Host- cookie without Secure is rejected by the browser")
	}
	if c.Path != "/" {
		t.Errorf("cookie Path = %q, want /", c.Path)
	}
	if c.Domain != "" {
		t.Errorf("cookie Domain = %q, want empty; a __Host- cookie with a Domain is rejected", c.Domain)
	}
	if !c.HttpOnly {
		t.Error("cookie is not HttpOnly, so a script can read the session token")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie SameSite = %v, want Lax", c.SameSite)
	}
	if c.Value != f.login.Token {
		t.Errorf("cookie value = %q, want the token %q", c.Value, f.login.Token)
	}
	if c.Expires.IsZero() {
		t.Error("cookie has no expiry, so it dies when the browser closes")
	}
}

func TestLoginRefusalIsGeneric(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
	}{
		{name: "wrong credentials", err: auth.ErrInvalidCredentials},
		{name: "an unknown account", err: auth.ErrInvalidCredentials},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFakeAuth()
			f.loginErr = tt.err

			rec := post(t, New(nil, WithAuth(f)), "/v1/session", `{"email":"kaka@example.com","password":"wrong"}`)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401; body: %s", rec.Code, rec.Body)
			}
			p := decodeProblem(t, rec)
			if p.Code != CodeUnauthorized {
				t.Errorf("code = %q, want %q", p.Code, CodeUnauthorized)
			}
			if strings.Contains(strings.ToLower(p.Detail), "no such") ||
				strings.Contains(strings.ToLower(p.Detail), "unknown") ||
				strings.Contains(strings.ToLower(p.Detail), "not found") {
				t.Errorf("detail %q reveals whether the account exists", p.Detail)
			}
			if cookies := rec.Result().Cookies(); len(cookies) != 0 {
				t.Errorf("a refused login set %d cookies", len(cookies))
			}
		})
	}
}

func TestLoginLockedIs423WithRetryAfter(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	f.loginErr = &auth.LockedError{RetryAfter: 7 * time.Minute}

	rec := post(t, New(nil, WithAuth(f)), "/v1/session", `{"email":"kaka@example.com","password":"correct horse battery"}`)

	if rec.Code != http.StatusLocked {
		t.Fatalf("status = %d, want 423; body: %s", rec.Code, rec.Body)
	}
	p := decodeProblem(t, rec)
	if p.Code != CodeAccountLocked {
		t.Errorf("code = %q, want %q", p.Code, CodeAccountLocked)
	}
	if p.Status != http.StatusLocked {
		t.Errorf("body status = %d, want 423", p.Status)
	}

	if got, want := rec.Header().Get(RetryAfterHeader), "420"; got != want {
		t.Errorf("%s = %q, want %q seconds", RetryAfterHeader, got, want)
	}
	if !strings.Contains(p.Detail, "420") {
		t.Errorf("detail %q does not say how long to wait", p.Detail)
	}
	if p.Errors != nil {
		t.Errorf("errors = %v on a 423, want none; core scopes errors[] to 422", p.Errors)
	}
	if cookies := rec.Result().Cookies(); len(cookies) != 0 {
		t.Errorf("a locked login set %d cookies", len(cookies))
	}
}

func TestRetryAfterSecondsRoundsUp(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give time.Duration
		want string
	}{
		{name: "exactly a minute", give: time.Minute, want: "60"},
		{name: "with a remainder rounds up", give: 90 * time.Second, want: "90"},
		{name: "a millisecond over a second", give: time.Second + time.Millisecond, want: "2"},
		{name: "a single second", give: time.Second, want: "1"},
		{name: "zero", give: 0, want: "0"},
		{name: "negative clamps to zero", give: -time.Minute, want: "0"},
		{name: "fifteen minutes", give: 15 * time.Minute, want: "900"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := retryAfterSeconds(tt.give); got != tt.want {
				t.Errorf("retryAfterSeconds(%s) = %q, want %q", tt.give, got, tt.want)
			}
		})
	}
}

func TestLoginRecordsRequestMetadata(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/session",
		strings.NewReader(`{"email":"kaka@example.com","password":"correct horse battery"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "integration-test/1.0")
	req.RemoteAddr = "203.0.113.7:54321"

	rec := httptest.NewRecorder()
	New(nil, WithAuth(f)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	inputs := f.loginInputs()
	if len(inputs) != 1 {
		t.Fatalf("Login was called %d times, want 1", len(inputs))
	}
	if inputs[0].UserAgent != "integration-test/1.0" {
		t.Errorf("UserAgent = %q, want the request's", inputs[0].UserAgent)
	}
	if inputs[0].IP == nil || inputs[0].IP.String() != "203.0.113.7" {
		t.Errorf("IP = %v, want 203.0.113.7 parsed from RemoteAddr", inputs[0].IP)
	}
}

func TestLoginToleratesAnUnparseableRemoteAddr(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/session",
		strings.NewReader(`{"email":"kaka@example.com","password":"correct horse battery"}`))
	req.RemoteAddr = "not-an-address"

	rec := httptest.NewRecorder()
	New(nil, WithAuth(f)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if inputs := f.loginInputs(); len(inputs) != 1 || inputs[0].IP != nil {
		t.Errorf("IP = %v, want nil for an unparseable RemoteAddr", inputs[0].IP)
	}
}


func TestMeAcceptsTheCookie(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/me", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "a-session-token"})

	rec := httptest.NewRecorder()
	New(nil, WithAuth(f)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	if len(body) != 2 {
		t.Errorf("the response has %d fields (%v), want exactly id and email", len(body), body)
	}
	if body["email"] != "kaka@example.com" {
		t.Errorf("email = %v, want kaka@example.com", body["email"])
	}
}

func TestMeAcceptsABearerToken(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/me", nil)
	req.Header.Set("Authorization", "Bearer a-session-token")

	rec := httptest.NewRecorder()
	New(nil, WithAuth(f)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}
}

func TestMeRejectsEveryMissingOrBrokenCredential(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prepare func(*http.Request)
	}{
		{name: "nothing at all", prepare: func(*http.Request) {}},
		{
			name: "an empty cookie",
			prepare: func(r *http.Request) {
				r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: ""})
			},
		},
		{
			name: "a cookie under the wrong name",
			prepare: func(r *http.Request) {
				r.AddCookie(&http.Cookie{Name: "session", Value: "a-session-token"})
			},
		},
		{
			name: "a bare Authorization header",
			prepare: func(r *http.Request) {
				r.Header.Set("Authorization", "a-session-token")
			},
		},
		{
			name: "the wrong scheme",
			prepare: func(r *http.Request) {
				r.Header.Set("Authorization", "Basic a-session-token")
			},
		},
		{
			name: "an empty bearer",
			prepare: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer ")
			},
		},
		{
			name: "a token the service rejects",
			prepare: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer never-issued")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFakeAuth()
			if strings.Contains(tt.name, "rejects") {
				f.authErr = auth.ErrUnauthenticated
			}

			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/me", nil)
			tt.prepare(req)

			rec := httptest.NewRecorder()
			New(nil, WithAuth(f)).ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401; body: %s", rec.Code, rec.Body)
			}
			p := decodeProblem(t, rec)
			if p.Code != CodeUnauthorized {
				t.Errorf("code = %q, want %q", p.Code, CodeUnauthorized)
			}
		})
	}
}

func TestMePrefersTheAuthorizationHeaderOverTheCookie(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/me", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "cookie-token"})
	req.Header.Set("Authorization", "Bearer header-token")

	rec := httptest.NewRecorder()
	New(nil, WithAuth(f)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if got := f.lastAuthenticatedToken(); got != "header-token" {
		t.Errorf("the service was given %q, want the header's header-token", got)
	}
}


func TestUpdateMeSetsTheDisplayName(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPatch, "/v1/me", strings.NewReader(`{"display_name":"Kaka"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "a-session-token"})

	rec := httptest.NewRecorder()
	New(nil, WithAuth(f)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	if body["display_name"] != "Kaka" {
		t.Errorf("display_name = %v, want Kaka", body["display_name"])
	}
	if body["email"] != "kaka@example.com" {
		t.Errorf("email = %v, want kaka@example.com", body["email"])
	}

	if len(f.updatedDisplayNameFor) != 1 || f.updatedDisplayNameFor[0] != f.user.ID {
		t.Errorf("UpdateDisplayName was called for %v, want the caller's id %s", f.updatedDisplayNameFor, f.user.ID)
	}
	if f.updatedDisplayName == nil || *f.updatedDisplayName != "Kaka" {
		t.Errorf("UpdateDisplayName was given %v, want Kaka", f.updatedDisplayName)
	}
}

func TestUpdateMeClearsTheDisplayNameWithAnEmptyString(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPatch, "/v1/me", strings.NewReader(`{"display_name":""}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "a-session-token"})

	rec := httptest.NewRecorder()
	New(nil, WithAuth(f)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	if _, present := body["display_name"]; present {
		t.Errorf("display_name is present in the response (%v), want it omitted when cleared", body["display_name"])
	}

	if len(f.updatedDisplayNameFor) != 1 {
		t.Fatalf("UpdateDisplayName was called %d times, want 1", len(f.updatedDisplayNameFor))
	}
	if f.updatedDisplayName != nil {
		t.Errorf("UpdateDisplayName was given %v, want nil (the clearing case)", *f.updatedDisplayName)
	}
}

func TestUpdateMeClearsTheDisplayNameWhenTheFieldIsOmitted(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPatch, "/v1/me", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "a-session-token"})

	rec := httptest.NewRecorder()
	New(nil, WithAuth(f)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	if _, present := body["display_name"]; present {
		t.Errorf("display_name is present in the response (%v), want it omitted when cleared", body["display_name"])
	}

	if len(f.updatedDisplayNameFor) != 1 {
		t.Fatalf("UpdateDisplayName was called %d times, want 1", len(f.updatedDisplayNameFor))
	}
	if f.updatedDisplayName != nil {
		t.Errorf("UpdateDisplayName was given %v, want nil (the clearing case)", *f.updatedDisplayName)
	}
}

func TestUpdateMeTrimsTheDisplayName(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPatch, "/v1/me", strings.NewReader(`{"display_name":"  Kaka  "}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "a-session-token"})

	rec := httptest.NewRecorder()
	New(nil, WithAuth(f)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	if f.updatedDisplayName == nil || *f.updatedDisplayName != "Kaka" {
		t.Errorf("UpdateDisplayName was given %v, want the trimmed Kaka", f.updatedDisplayName)
	}
}

func TestUpdateMeSetsTheTheme(t *testing.T) {
	t.Parallel()

	for _, want := range []string{"light", "dark"} {
		t.Run(want, func(t *testing.T) {
			t.Parallel()

			f := newFakeAuth()
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPatch, "/v1/me", strings.NewReader(`{"theme":"`+want+`"}`))
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "a-session-token"})

			rec := httptest.NewRecorder()
			New(nil, WithAuth(f)).ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
			}

			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("the body is not JSON: %v", err)
			}
			if body["theme"] != want {
				t.Errorf("theme = %v, want %s", body["theme"], want)
			}

			if len(f.updatedThemeFor) != 1 || f.updatedThemeFor[0] != f.user.ID {
				t.Errorf("UpdateTheme was called for %v, want the caller's id %s", f.updatedThemeFor, f.user.ID)
			}
			if f.updatedTheme == nil || *f.updatedTheme != want {
				t.Errorf("UpdateTheme was given %v, want %s", f.updatedTheme, want)
			}
		})
	}
}

func TestUpdateMeRejectsAnInvalidTheme(t *testing.T) {
	t.Parallel()

	for _, give := range []string{"", "blue", "system", "DARK", " dark "} {
		t.Run(give, func(t *testing.T) {
			t.Parallel()

			f := newFakeAuth()
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPatch, "/v1/me", strings.NewReader(`{"theme":"`+give+`"}`))
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "a-session-token"})

			rec := httptest.NewRecorder()
			New(nil, WithAuth(f)).ServeHTTP(rec, req)

			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422; body: %s", rec.Code, rec.Body)
			}
			p := decodeProblem(t, rec)
			if p.Code != CodeValidationFailed {
				t.Errorf("code = %q, want %q", p.Code, CodeValidationFailed)
			}
			if len(p.Errors) != 1 || p.Errors[0].Field != "theme" || p.Errors[0].Code != users.CodeInvalidFormat {
				t.Errorf("errors = %v, want one entry naming theme/%s", p.Errors, users.CodeInvalidFormat)
			}

			if len(f.updatedThemeFor) != 0 {
				t.Errorf("UpdateTheme was called %d times on a refused request, want 0", len(f.updatedThemeFor))
			}
			if len(f.updatedDisplayNameFor) != 0 {
				t.Errorf("UpdateDisplayName was called %d times on a refused request, want 0", len(f.updatedDisplayNameFor))
			}
		})
	}
}

func TestUpdateMeRejectsANonStringTheme(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPatch, "/v1/me", strings.NewReader(`{"theme":42}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "a-session-token"})

	rec := httptest.NewRecorder()
	New(nil, WithAuth(f)).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body)
	}
	p := decodeProblem(t, rec)
	if p.Code != CodeInvalidJSON {
		t.Errorf("code = %q, want %q", p.Code, CodeInvalidJSON)
	}
}

func TestUpdateMeClearsTheThemeWhenTheFieldIsOmitted(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	dark := "dark"
	f.user.Preferences.Theme = &dark

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPatch, "/v1/me", strings.NewReader(`{"display_name":"Kaka"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "a-session-token"})

	rec := httptest.NewRecorder()
	New(nil, WithAuth(f)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	if _, present := body["theme"]; present {
		t.Errorf("theme is present in the response (%v), want it omitted when cleared", body["theme"])
	}

	if len(f.updatedThemeFor) != 1 {
		t.Fatalf("UpdateTheme was called %d times, want 1", len(f.updatedThemeFor))
	}
	if f.updatedTheme != nil {
		t.Errorf("UpdateTheme was given %v, want nil (the clearing case)", *f.updatedTheme)
	}
}

func TestUpdateMeRejectsAnonymous(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPatch, "/v1/me", strings.NewReader(`{"display_name":"Kaka"}`))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	New(nil, WithAuth(f)).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body: %s", rec.Code, rec.Body)
	}
	p := decodeProblem(t, rec)
	if p.Code != CodeUnauthorized {
		t.Errorf("code = %q, want %q", p.Code, CodeUnauthorized)
	}
}

func TestUpdateMeRejectsOverLength(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	long := strings.Repeat("a", 65)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPatch, "/v1/me", strings.NewReader(`{"display_name":"`+long+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "a-session-token"})

	rec := httptest.NewRecorder()
	New(nil, WithAuth(f)).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body: %s", rec.Code, rec.Body)
	}
	p := decodeProblem(t, rec)
	if p.Code != CodeValidationFailed {
		t.Errorf("code = %q, want %q", p.Code, CodeValidationFailed)
	}
	if len(p.Errors) != 1 || p.Errors[0].Field != "display_name" {
		t.Errorf("errors = %v, want one entry naming display_name", p.Errors)
	}
}

func TestMeReturnsTheDisplayNameWhenSet(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	name := "Kaka"
	f.user.DisplayName = &name

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/me", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "a-session-token"})

	rec := httptest.NewRecorder()
	New(nil, WithAuth(f)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	if body["display_name"] != "Kaka" {
		t.Errorf("display_name = %v, want Kaka", body["display_name"])
	}
}

func TestMeOmitsTheDisplayNameWhenUnset(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/me", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "a-session-token"})

	rec := httptest.NewRecorder()
	New(nil, WithAuth(f)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	if _, present := body["display_name"]; present {
		t.Errorf("display_name is present in the response, want it omitted when unset")
	}
	if len(body) != 2 {
		t.Errorf("the response has %d fields (%v), want exactly id and email", len(body), body)
	}
}

func TestMeReturnsTheThemeWhenSet(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	dark := "dark"
	f.user.Preferences.Theme = &dark

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/me", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "a-session-token"})

	rec := httptest.NewRecorder()
	New(nil, WithAuth(f)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	if body["theme"] != "dark" {
		t.Errorf("theme = %v, want dark", body["theme"])
	}
}

func TestMeOmitsTheThemeWhenUnset(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/me", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "a-session-token"})

	rec := httptest.NewRecorder()
	New(nil, WithAuth(f)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	if _, present := body["theme"]; present {
		t.Errorf("theme is present in the response, want it omitted when unset")
	}
	if len(body) != 2 {
		t.Errorf("the response has %d fields (%v), want exactly id and email", len(body), body)
	}
}


func TestLogoutClearsTheCookieAndRevokes(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/v1/session", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "a-session-token"})

	rec := httptest.NewRecorder()
	New(nil, WithAuth(f)).ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", rec.Code, rec.Body)
	}
	if body := rec.Body.String(); body != "" {
		t.Errorf("a 204 has a body: %q", body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "" {
		t.Errorf("a 204 declares Content-Type %q, want none", ct)
	}

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1 clearing the session", len(cookies))
	}
	c := cookies[0]
	if c.Name != SessionCookieName {
		t.Errorf("cookie name = %q, want %q", c.Name, SessionCookieName)
	}
	if c.Value != "" {
		t.Errorf("cookie value = %q, want empty", c.Value)
	}
	if c.MaxAge >= 0 {
		t.Errorf("cookie MaxAge = %d, want negative so the browser deletes it", c.MaxAge)
	}
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		t.Errorf("the clearing cookie's attributes differ from the setting cookie's: %+v", c)
	}
}

func TestLogoutWorksForABearerClient(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/v1/session", nil)
	req.Header.Set("Authorization", "Bearer a-session-token")

	rec := httptest.NewRecorder()
	New(nil, WithAuth(f)).ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", rec.Code, rec.Body)
	}
	if got := f.lastLoggedOutToken(); got != "a-session-token" {
		t.Errorf("the service revoked %q, want a-session-token", got)
	}
}

func TestLogoutWithoutACredentialIs401(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	rec := send(t, New(nil, WithAuth(f)), http.MethodDelete, "/v1/session", "")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body: %s", rec.Code, rec.Body)
	}
	p := decodeProblem(t, rec)
	if p.Code != CodeUnauthorized {
		t.Errorf("code = %q, want %q", p.Code, CodeUnauthorized)
	}
}

func TestLogoutWithAStaleTokenStillClearsTheCookie(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	f.logoutErr = auth.ErrUnauthenticated

	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/v1/session", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "expired"})

	rec := httptest.NewRecorder()
	New(nil, WithAuth(f)).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body: %s", rec.Code, rec.Body)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge >= 0 {
		t.Errorf("the stale cookie was not cleared: %+v", cookies)
	}
}


func TestUnexpectedErrorsAre500WithTheCauseInTheLog(t *testing.T) {
	t.Parallel()

	logs := &recordingHandler{}
	logger := slogLogger(logs)

	f := newFakeAuth()
	f.loginErr = errors.New("dial tcp 10.0.0.5:5432: connection refused (password authentication failed for user identity)")

	rec := post(t, New(nil, WithAuth(f), WithLogger(logger)), "/v1/session", `{"email":"kaka@example.com","password":"correct horse battery"}`)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body)
	}
	p := decodeProblem(t, rec)
	if p.Code != CodeInternal {
		t.Errorf("code = %q, want %q", p.Code, CodeInternal)
	}
	if p.TraceID == "" {
		t.Error("trace_id is empty; support could not correlate this")
	}

	for _, secret := range []string{"10.0.0.5", "password", "refused", "dial tcp", "identity"} {
		if strings.Contains(strings.ToLower(rec.Body.String()), secret) {
			t.Errorf("the body leaks %q: %s", secret, rec.Body)
		}
	}

	entry := logs.find("request failed")
	if entry == "" {
		t.Fatalf("nothing was logged; got %d entries", logs.count())
	}
	if !strings.Contains(entry, "10.0.0.5") {
		t.Errorf("the log entry does not carry the cause: %s", entry)
	}
	if !strings.Contains(entry, p.TraceID) {
		t.Errorf("the log entry does not carry the trace id %q: %s", p.TraceID, entry)
	}
}

func TestPanicInAHandlerIs500(t *testing.T) {
	t.Parallel()

	logs := &recordingHandler{}
	h := New(nil, WithAuth(panickingAuth{}), WithLogger(slogLogger(logs)))

	rec := post(t, h, "/v1/users", `{"email":"kaka@example.com","password":"correct horse battery"}`)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "goroutine") || strings.Contains(rec.Body.String(), "panic") {
		t.Errorf("the body carries a stack trace: %s", rec.Body)
	}
	if logs.find("request failed") == "" {
		t.Error("the panic was not logged")
	}
}

func TestRegistrationStoreFailureIs500Not409(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	f.registerErr = errors.New("connection reset by peer")

	rec := post(t, New(nil, WithAuth(f)), "/v1/users", `{"email":"kaka@example.com","password":"correct horse battery"}`)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body)
	}
	p := decodeProblem(t, rec)
	if p.Code == CodeConflict {
		t.Error("a store failure was reported as a conflict; that tells a caller their address is taken")
	}
}

func TestAuthRoutesAreAbsentWithoutAnAuthService(t *testing.T) {
	t.Parallel()

	tests := []struct {
		method string
		target string
	}{
		{method: http.MethodPost, target: "/v1/users"},
		{method: http.MethodPost, target: "/v1/session"},
		{method: http.MethodDelete, target: "/v1/session"},
		{method: http.MethodGet, target: "/v1/me"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.target, func(t *testing.T) {
			t.Parallel()

			rec := send(t, New(nil), tt.method, tt.target, `{}`)

			if rec.Code != http.StatusNotFound {
				t.Errorf("status = %d, want 404 when no auth service is configured; body: %s", rec.Code, rec.Body)
			}
		})
	}
}

func TestWrongMethodsAreProblemJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		target string
	}{
		{name: "GET on register", method: http.MethodGet, target: "/v1/users"},
		{name: "PUT on login", method: http.MethodPut, target: "/v1/session"},
		{name: "POST on me", method: http.MethodPost, target: "/v1/me"},
		{name: "GET on logout", method: http.MethodGet, target: "/v1/session"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := send(t, New(nil, WithAuth(newFakeAuth())), tt.method, tt.target, `{}`)

			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d, want 405; body: %s", rec.Code, rec.Body)
			}
			p := decodeProblem(t, rec)
			if p.Code != CodeMethodNotAllowed {
				t.Errorf("code = %q, want %q", p.Code, CodeMethodNotAllowed)
			}
		})
	}
}

func TestUnknownRouteIsProblemJSON(t *testing.T) {
	t.Parallel()

	rec := send(t, New(nil), http.MethodGet, "/v1/nope", "")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", rec.Code, rec.Body)
	}
	p := decodeProblem(t, rec)
	if p.Code != CodeNotFound {
		t.Errorf("code = %q, want %q", p.Code, CodeNotFound)
	}
	if p.Instance != "/v1/nope" {
		t.Errorf("instance = %q, want /v1/nope", p.Instance)
	}
}

func TestProbesAreUnaffectedByTheV1Surface(t *testing.T) {
	t.Parallel()

	h := New(nil, WithAuth(newFakeAuth()))

	for _, target := range []string{"/healthz", "/readyz"} {
		rec := send(t, h, http.MethodGet, target, "")
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200; body: %s", target, rec.Code, rec.Body)
		}
		if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
			t.Errorf("GET %s Content-Type = %q, want application/json", target, got)
		}
	}
}


func (f *fakeAuth) hasRegistered() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.registered) > 0
}

func (f *fakeAuth) loginInputs() []auth.LoginInput {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]auth.LoginInput(nil), f.loggedIn...)
}

func (f *fakeAuth) lastLoggedOutToken() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.loggedOut) == 0 {
		return ""
	}
	return f.loggedOut[len(f.loggedOut)-1]
}

func (f *fakeAuth) lastAuthenticatedToken() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastAuthToken
}

type panickingAuth struct{}

func (panickingAuth) Register(context.Context, auth.RegisterInput) (auth.RegisteredUser, error) {
	panic("handler exploded")
}
func (panickingAuth) CompleteSecondFactor(context.Context, auth.CompleteSecondFactorInput) (auth.LoginResult, error) {
	panic("handler exploded")
}
func (panickingAuth) Login(context.Context, auth.LoginInput) (auth.LoginResult, error) {
	panic("handler exploded")
}
func (panickingAuth) Authenticate(context.Context, string) (users.User, error) {
	panic("handler exploded")
}
func (panickingAuth) Logout(context.Context, string) error {
	panic("handler exploded")
}
func (panickingAuth) ListSessions(context.Context, string) ([]auth.Session, error) {
	panic("handler exploded")
}
func (panickingAuth) RevokeSession(context.Context, string, id.UUID) error {
	panic("handler exploded")
}

func (panickingAuth) Disable(context.Context, auth.DisableInput) error {
	panic("handler exploded")
}
func (panickingAuth) Enable(context.Context, auth.EnableInput) error {
	panic("handler exploded")
}
func (panickingAuth) UpdateDisplayName(context.Context, id.UUID, *string) error {
	panic("handler exploded")
}
func (panickingAuth) UpdateTheme(context.Context, id.UUID, *string) error {
	panic("handler exploded")
}

func (panickingAuth) SearchUsers(context.Context, string, int) ([]users.DirectoryEntry, error) {
	panic("handler exploded")
}


func (panickingAuth) UserCounts(context.Context) (users.UserCounts, error) {
	panic("handler exploded")
}
