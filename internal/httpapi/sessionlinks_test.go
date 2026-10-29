package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/apikeys"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/recovery"
	"github.com/anywaye/identity/internal/users"
)


type sessionLinkFixture struct {
	handler http.Handler
	recovery *fakeRecovery
	subject   id.UUID
	keyHolder id.UUID
	apiKey        string
	strangerToken string
	session       string
}

func newSessionLinkFixture(t *testing.T, scopes ...string) *sessionLinkFixture {
	t.Helper()

	if len(scopes) == 0 {
		scopes = []string{apikeys.ScopeSessionsWrite}
	}
	return newSessionLinkFixtureWithGrant(t, scopes)
}

func newSessionLinkFixtureWithGrant(t *testing.T, scopes []string) *sessionLinkFixture {
	t.Helper()
	return newSessionLinkFixtureResolving(t, scopes, true)
}

func newSessionLinkFixtureResolving(t *testing.T, scopes []string, resolves bool) *sessionLinkFixture {
	t.Helper()

	auth := newFakeAuth()
	keyHolder := id.MustNew()
	caller := newFakeAPIKeyCaller(auth.user, apikeys.Key{
		ID:     id.MustNew(),
		UserID: keyHolder,
		AccountID: id.MustNew(),
		Scopes:    scopes,
	})
	if !resolves {
		caller.err = apikeys.ErrNotFound
	}
	rec := newFakeRecovery()

	return &sessionLinkFixture{
		handler: New(nil,
			WithAuth(auth),
			WithAPIKeyCaller(caller),
			WithRecovery(rec),
			WithLogger(slogLogger(&recordingHandler{})),
		),
		recovery:      rec,
		subject:       id.MustNew(),
		keyHolder:     keyHolder,
		apiKey:        apiKeySecret,
		strangerToken: scopedTokenForTheMatrix,
		session:       "a-session-token",
	}
}

func (f *sessionLinkFixture) mint(t *testing.T, body, credential string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/session-links", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func (f *sessionLinkFixture) happyBody() string {
	return `{"user_id":"` + f.subject.String() + `"}`
}


func TestAMintReturnsTheTokenAndTheInstantItDies(t *testing.T) {
	f := newSessionLinkFixture(t)

	rec := f.mint(t, f.happyBody(), f.apiKey)
	if rec.Code != http.StatusCreated {
		t.Fatalf("a token holding %s minting = %d, want 201; body: %s",
			apikeys.ScopeSessionsWrite, rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the 201 body is not JSON: %v", err)
	}
	if len(body) != 2 {
		t.Errorf("the 201 body carries %d field(s) (%v), want exactly token and expires_at. "+
			"Anything further is a fact about the subject, and this route publishes the "+
			"credential and its expiry and nothing else", len(body), body)
	}
	if body["token"] != "minted-by-the-use-case" {
		t.Errorf("token = %v, want the value the use case returned. A handler that rendered its "+
			"own value would be a second mint outside the transaction", body["token"])
	}
	if body["expires_at"] != "2026-10-01T12:10:00Z" {
		t.Errorf("expires_at = %v, want the instant the use case returned", body["expires_at"])
	}
}

func TestTheMintsSubjectIsTheOneTheBodyNames(t *testing.T) {
	f := newSessionLinkFixture(t)

	rec := f.mint(t, f.happyBody(), f.apiKey)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", rec.Code, rec.Body)
	}
	if len(f.recovery.mints) != 1 {
		t.Fatalf("the use case was called %d times, want once", len(f.recovery.mints))
	}
	if f.recovery.mints[0].UserID != f.subject {
		t.Errorf("the mint was asked for subject %s, want the one the body named (%s)",
			f.recovery.mints[0].UserID, f.subject)
	}
	if f.recovery.mints[0].UserID == f.keyHolder {
		t.Error("the mint was asked for the CALLER as its subject. The subject is named in the " +
			"body and is not the caller, which is the whole reason this route needs a scope " +
			"rather than a session")
	}
	if f.recovery.mints[0].Window != 0 {
		t.Errorf("an absent window reached the use case as %s, want 0 so the default applies",
			f.recovery.mints[0].Window)
	}
}

func TestTheWindowIsReadAsSecondsAndReachesTheUseCase(t *testing.T) {
	f := newSessionLinkFixture(t)

	rec := f.mint(t, `{"user_id":"`+f.subject.String()+`","expires_in":45}`, f.apiKey)
	if rec.Code != http.StatusCreated {
		t.Fatalf("a mint with a 45-second window = %d, want 201; body: %s", rec.Code, rec.Body)
	}
	if len(f.recovery.mints) != 1 {
		t.Fatalf("the use case was called %d times, want once", len(f.recovery.mints))
	}
	if got := f.recovery.mints[0].Window; got != 45*time.Second {
		t.Errorf("the window reached the use case as %s, want 45s", got)
	}
}

func TestAnAbsentWindowAndAZeroWindowAreDifferentRequests(t *testing.T) {
	f := newSessionLinkFixture(t)

	rec := f.mint(t, `{"user_id":"`+f.subject.String()+`","expires_in":0}`, f.apiKey)
	if rec.Code != http.StatusCreated {
		t.Fatalf("an explicit zero window = %d, want 201; body: %s", rec.Code, rec.Body)
	}
	if len(f.recovery.mints) != 1 {
		t.Fatalf("the use case was called %d times, want once", len(f.recovery.mints))
	}
	if got := f.recovery.mints[0].Window; got != 0 {
		t.Errorf("an explicit zero reached the use case as %s, want 0. The use case reads 0 as "+
			"'refuse this', and a handler that defaulted it would silently grant the default "+
			"window to a caller who asked for none", got)
	}
}


func TestTheMintRouteIsReachableByExactlyOneCredential(t *testing.T) {
	cases := []struct {
		name string
		credential string
		build func(t *testing.T) *sessionLinkFixture
		want  int
		wantCode string
		reached bool
	}{
		{
			name:       "a token holding sessions:write",
			credential: "apiKey",
			build:      func(t *testing.T) *sessionLinkFixture { return newSessionLinkFixture(t) },
			want:       http.StatusCreated,
			reached:    true,
		},
		{
			name:       "a browser session",
			credential: "session",
			build:      func(t *testing.T) *sessionLinkFixture { return newSessionLinkFixture(t) },
			want:       http.StatusForbidden,
			wantCode:   CodeForbidden,
		},
		{
			name:       "no credential",
			credential: "",
			build:      func(t *testing.T) *sessionLinkFixture { return newSessionLinkFixture(t) },
			want:       http.StatusForbidden,
			wantCode:   CodeForbidden,
		},
		{
			name:       "a token holding some other scope",
			credential: "apiKey",
			build: func(t *testing.T) *sessionLinkFixture {
				return newSessionLinkFixture(t, apikeys.ScopeAccountsRead, apikeys.ScopeAccountsWrite)
			},
			want:     http.StatusForbidden,
			wantCode: CodeForbidden,
		},
		{
			name:       "a token holding a scope that does not exist",
			credential: "apiKey",
			build: func(t *testing.T) *sessionLinkFixture {
				return newSessionLinkFixture(t, "invented:scope")
			},
			want:     http.StatusForbidden,
			wantCode: CodeForbidden,
		},
		{
			name:       "a token holding no scopes",
			credential: "apiKey",
			build: func(t *testing.T) *sessionLinkFixture {
				return newSessionLinkFixtureWithGrant(t, []string{})
			},
			want:     http.StatusForbidden,
			wantCode: CodeForbidden,
		},
		{
			name:       "a token that resolves to nothing",
			credential: "strangerToken",
			build: func(t *testing.T) *sessionLinkFixture {
				return newSessionLinkFixtureResolving(t, []string{apikeys.ScopeSessionsWrite}, false)
			},
			want:     http.StatusUnauthorized,
			wantCode: CodeUnauthorized,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.build(t)

			credential := f.apiKey
			switch tc.credential {
			case "session":
				credential = f.session
			case "strangerToken":
				credential = f.strangerToken
			case "":
				credential = ""
			}

			rec := f.mint(t, f.happyBody(), credential)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tc.want, rec.Body)
			}
			if rec.Code >= 400 {
				if got := decodeProblem(t, rec).Code; got != tc.wantCode {
					t.Errorf("code = %q, want %q", got, tc.wantCode)
				}
			}
			if rec.Code >= 400 && rec.Header().Get("Content-Type") != "application/problem+json" {
				t.Errorf("a %d carried Content-Type %q, want application/problem+json",
					rec.Code, rec.Header().Get("Content-Type"))
			}

			reached := len(f.recovery.mints) > 0
			if reached != tc.reached {
				if tc.reached {
					t.Error("the use case was never reached, so the 2xx is a refusal rather than a mint")
				} else {
					t.Errorf("the use case WAS reached and the route answered %d. A mint that "+
						"refuses after the insert has already written the credential the caller "+
						"was told it did not get", rec.Code)
				}
			}
		})
	}
}

func TestTheScopeRefusalNamesTheMissingScope(t *testing.T) {
	f := newSessionLinkFixture(t, apikeys.ScopeAccountsRead)

	rec := f.mint(t, f.happyBody(), f.apiKey)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), apikeys.ScopeSessionsWrite) {
		t.Errorf("the 403 does not name %s: %s", apikeys.ScopeSessionsWrite, rec.Body)
	}
}

func TestTheSessionRefusalNamesTheScopeATokenWouldNeed(t *testing.T) {
	f := newSessionLinkFixture(t)

	rec := f.mint(t, f.happyBody(), f.session)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a browser session minting = %d, want 403; body: %s", rec.Code, rec.Body)
	}
	problem := decodeProblem(t, rec)
	if !strings.Contains(problem.Detail, apikeys.ScopeSessionsWrite) {
		t.Errorf("the 403 does not name the scope a token would need: %q", problem.Detail)
	}
	if len(f.recovery.mints) != 0 {
		t.Error("a browser session reached the use case")
	}
}


func TestTheMintsRefusalsAreTheStatusesAndCodesThisServicePromises(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		want     int
		wantCode string
		wantDetail string
		notInDetail string
	}{
		{
			name:        "a subject that is not a user",
			err:         recovery.ErrSubjectNotFound,
			want:        http.StatusNotFound,
			wantCode:    CodeNotFound,
			wantDetail:  "no user with that id",
			notInDetail: "SELECT",
		},
		{
			name:        "a subject with a second factor",
			err:         recovery.ErrSubjectHasSecondFactor,
			want:        http.StatusConflict,
			wantCode:    CodeConflict,
			wantDetail:  "second factor",
			notInDetail: "mfa_credentials",
		},
		{
			name:        "a deployment that cannot ask about second factors",
			err:         recovery.ErrMFAUnavailable,
			want:        http.StatusServiceUnavailable,
			wantCode:    CodeServiceUnavailable,
			wantDetail:  "cannot say whether an account has a second factor",
			notInDetail: "SELECT",
		},
		{
			name:        "a wrapped refusal",
			err:         wrappedError{inner: recovery.ErrSubjectHasSecondFactor},
			want:        http.StatusConflict,
			wantCode:    CodeConflict,
			wantDetail:  "second factor",
			notInDetail: "wrapped",
		},
		{
			name:        "something else entirely",
			err:         errDatabaseWentAway,
			want:        http.StatusInternalServerError,
			wantCode:    CodeInternal,
			notInDetail: "10.0.0.5",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSessionLinkFixture(t)
			f.recovery.mintErr = tc.err

			rec := f.mint(t, f.happyBody(), f.apiKey)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tc.want, rec.Body)
			}
			problem := decodeProblem(t, rec)
			if problem.Code != tc.wantCode {
				t.Errorf("code = %q, want %q", problem.Code, tc.wantCode)
			}
			if problem.Status != tc.want {
				t.Errorf("the document's own status = %d, want %d", problem.Status, tc.want)
			}
			if tc.wantDetail != "" && !strings.Contains(problem.Detail, tc.wantDetail) {
				t.Errorf("detail = %q, want it to mention %q", problem.Detail, tc.wantDetail)
			}
			if tc.notInDetail != "" && strings.Contains(problem.Detail, tc.notInDetail) {
				t.Errorf("the detail leaked an internal fact: %q", problem.Detail)
			}
			if rec.Header().Get("Content-Type") != "application/problem+json" {
				t.Errorf("a %d is not application/problem+json", rec.Code)
			}
		})
	}
}

func TestTheMintsValidationRefusalCarriesTheFieldError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		code string
	}{
		{"a window over the ceiling", &users.FieldError{Field: "window", Code: users.CodeTooLong}, users.CodeTooLong},
		{"a negative window", &users.FieldError{Field: "window", Code: users.CodeInvalidFormat}, users.CodeInvalidFormat},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSessionLinkFixture(t)
			f.recovery.mintErr = tc.err

			rec := f.mint(t, f.happyBody(), f.apiKey)
			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422; body: %s", rec.Code, rec.Body)
			}
			problem := decodeProblem(t, rec)
			if len(problem.Errors) != 1 {
				t.Fatalf("errors[] has %d entries, want 1: %+v", len(problem.Errors), problem.Errors)
			}
			if problem.Errors[0].Field != "window" {
				t.Errorf("field = %q, want %q", problem.Errors[0].Field, "window")
			}
			if problem.Errors[0].Code != tc.code {
				t.Errorf("code = %q, want %q", problem.Errors[0].Code, tc.code)
			}
		})
	}
}

func TestAMalformedSubjectIsRefusedBeforeTheUseCase(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"not a uuid at all", `{"user_id":"kaka"}`},
		{"an empty string", `{"user_id":""}`},
		{"the field is absent", `{}`},
		{"the field is the wrong type", `{"user_id":42}`},
		{"the nil uuid", `{"user_id":"00000000-0000-0000-0000-000000000000"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSessionLinkFixture(t)

			rec := f.mint(t, tc.body, f.apiKey)
			if rec.Code != http.StatusUnprocessableEntity && rec.Code != http.StatusBadRequest {
				t.Fatalf("%s = %d, want 422 or 400; body: %s", tc.name, rec.Code, rec.Body)
			}
			if len(f.recovery.mints) != 0 {
				t.Errorf("%s reached the use case. A subject this service cannot parse must be "+
					"refused here, or a uuid parse inside the transaction decides who gets a link",
					tc.name)
			}
		})
	}
}

func TestTheMintsRefusalsCarryATraceID(t *testing.T) {
	f := newSessionLinkFixture(t)
	f.recovery.mintErr = recovery.ErrSubjectNotFound

	rec := f.mint(t, f.happyBody(), f.apiKey)
	problem := decodeProblem(t, rec)
	if problem.TraceID == "" {
		t.Error("the problem document carries no trace_id, so a caller cannot quote it")
	}
	if header := rec.Header().Get(TraceHeader); header != problem.TraceID {
		t.Errorf("the %s header is %q and the body's trace_id is %q. core requires them to be "+
			"the same value", TraceHeader, header, problem.TraceID)
	}
}

type wrappedError struct{ inner error }

func (e wrappedError) Error() string { return "recovery: " + e.inner.Error() }
func (e wrappedError) Unwrap() error { return e.inner }

var errDatabaseWentAway = wrappedError{inner: connectionRefused{}}

type connectionRefused struct{}

func (connectionRefused) Error() string { return "dial tcp 10.0.0.5:5432: connection refused" }
