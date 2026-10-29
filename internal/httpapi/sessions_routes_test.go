package httpapi


import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/apikeys"
	"github.com/anywaye/identity/internal/auth"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/sessions"
	"github.com/anywaye/identity/internal/users"
)

type sessionWorld struct {
	handler http.Handler
	auth    *fakeAuth
}

func newSessionWorld(t *testing.T) *sessionWorld {
	t.Helper()

	f := newFakeAuth()
	return &sessionWorld{handler: New(nil, WithAuth(f)), auth: f}
}

func (w *sessionWorld) signedIn(t *testing.T, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	return requestAs(t, w.handler, w.auth.token, method, target, "")
}


func TestListingASessionRendersEverythingButACredential(t *testing.T) {
	t.Parallel()

	w := newSessionWorld(t)
	ip := netip.MustParseAddr("203.0.113.7")
	w.auth.sessions = []auth.Session{{
		ID:        id.MustNew(),
		CreatedAt: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
		UserAgent: "Mozilla/5.0 (Macintosh)",
		IP:        &ip,
		Current:   true,
	}}

	rec := w.signedIn(t, http.MethodGet, "/v1/sessions")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/sessions = %d, want 200\nbody: %s", rec.Code, rec.Body)
	}

	if got, want := rec.Header().Get("Content-Type"), "application/json; charset=utf-8"; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not JSON: %v\n%s", err, rec.Body)
	}
	raw, ok := body["sessions"].([]any)
	if !ok {
		t.Fatalf("the body has no `sessions` array: %s", rec.Body)
	}
	if len(raw) != 1 {
		t.Fatalf("`sessions` has %d entries, want 1", len(raw))
	}
	entry, ok := raw[0].(map[string]any)
	if !ok {
		t.Fatalf("the entry is not an object: %v", raw[0])
	}

	for _, key := range []string{"id", "created_at", "expires_at", "user_agent", "ip", "current"} {
		if _, present := entry[key]; !present {
			t.Errorf("the entry has no %q: %s", key, rec.Body)
		}
	}

	for _, key := range []string{"token", "token_digest", "digest", "user_id", "user"} {
		if _, present := entry[key]; present {
			t.Errorf("the entry carries %q, which must never be rendered on a listing: %s", key, rec.Body)
		}
	}

	for _, secret := range []string{w.auth.token, sessions.Digest(w.auth.token)} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Errorf("the response body contains %q: %s", secret, rec.Body)
		}
	}
}

func TestAnEmptyListingIsAnEmptyArrayNotNull(t *testing.T) {
	t.Parallel()

	w := newSessionWorld(t)
	w.auth.sessions = nil

	rec := w.signedIn(t, http.MethodGet, "/v1/sessions")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/sessions = %d, want 200\nbody: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"sessions":[]`) {
		t.Errorf("body = %s, want an empty array rather than null. A client rendering this has "+
			"to carry a null check for a case that is entirely ordinary.", rec.Body)
	}
}

func TestTheListingPassesTheCredentialRatherThanAUserId(t *testing.T) {
	t.Parallel()

	w := newSessionWorld(t)
	w.signedIn(t, http.MethodGet, "/v1/sessions")

	if len(w.auth.listedAs) != 1 {
		t.Fatalf("ListSessions was called %d times, want once", len(w.auth.listedAs))
	}
	if got := w.auth.listedAs[0]; got != w.auth.token {
		t.Errorf("ListSessions was handed %q, want the cookie's %q", got, w.auth.token)
	}
}

func TestTheListingRefusesAnUnusableCredentialWith401(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		token string
		err   error
	}{
		{name: "no credential at all", token: "", err: auth.ErrUnauthenticated},
		{name: "one that does not resolve", token: "nonsense", err: auth.ErrUnauthenticated},
		{name: "an expired one, which the use case cannot tell from an unknown one", token: "stale", err: auth.ErrUnauthenticated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := newSessionWorld(t)
			w.auth.listErr = tt.err

			rec := requestAs(t, w.handler, tt.token, http.MethodGet, "/v1/sessions", "")
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("GET /v1/sessions = %d, want 401\nbody: %s", rec.Code, rec.Body)
			}
			if p := decodeProblem(t, rec); p.Code != CodeUnauthorized {
				t.Errorf("code = %q, want %q", p.Code, CodeUnauthorized)
			}
		})
	}
}

func TestAStoreFailureDuringTheListingIsA500(t *testing.T) {
	t.Parallel()

	w := newSessionWorld(t)
	w.auth.listErr = errors.New("connection refused")

	rec := w.signedIn(t, http.MethodGet, "/v1/sessions")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("GET /v1/sessions = %d, want 500\nbody: %s", rec.Code, rec.Body)
	}
}

func TestAScopedApiKeyCannotListSessions(t *testing.T) {
	t.Parallel()

	handler := New(nil,
		WithAuth(newFakeAuth()),
		WithAPIKeyCaller(newFakeAPIKeyCaller(users.User{ID: id.MustNew()}, apikeys.Key{ID: id.MustNew(), AccountID: id.MustNew()})),
	)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer anywaye_a-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET /v1/sessions with an api key = %d, want 403\nbody: %s", rec.Code, rec.Body)
	}
	if p := decodeProblem(t, rec); p.Code != CodeForbidden {
		t.Errorf("code = %q, want %q", p.Code, CodeForbidden)
	}
}


func TestRevokingASessionTakesTheIdFromThePathAndTheCredentialFromTheRequest(t *testing.T) {
	t.Parallel()

	w := newSessionWorld(t)
	target := id.MustNew()

	rec := w.signedIn(t, http.MethodDelete, "/v1/sessions/"+target.String())
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE /v1/sessions/%s = %d, want 204\nbody: %s", target, rec.Code, rec.Body)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("a 204 carries a body: %q", rec.Body)
	}

	if len(w.auth.revokedSessions) != 1 {
		t.Fatalf("RevokeSession was called %d times, want once", len(w.auth.revokedSessions))
	}
	call := w.auth.revokedSessions[0]
	if call.sessionID != target {
		t.Errorf("the use case was given session %s, want the path's %s", call.sessionID, target)
	}
	if call.token != w.auth.token {
		t.Errorf("the use case was handed %q, want the cookie's %q", call.token, w.auth.token)
	}
}

func TestRevokingASessionAnswers404ForEveryWayOfNotOwningIt(t *testing.T) {
	t.Parallel()

	real := id.MustNew()

	tests := []struct {
		name     string
		path     string
		err      error
		wantCode int
	}{
		{
			name: "a session that does not exist", path: "/v1/sessions/" + id.MustNew().String(),
			err: auth.ErrSessionNotFound, wantCode: http.StatusNotFound,
		},
		{
			name: "a session that belongs to somebody else", path: "/v1/sessions/" + real.String(),
			err: auth.ErrSessionNotFound, wantCode: http.StatusNotFound,
		},
		{
			name: "one already revoked", path: "/v1/sessions/" + real.String(),
			err: auth.ErrSessionNotFound, wantCode: http.StatusNotFound,
		},
		{
			name: "an id this service did not issue", path: "/v1/sessions/not-a-uuid",
			wantCode: http.StatusNotFound,
		},
		{
			name: "the nil uuid", path: "/v1/sessions/00000000-0000-0000-0000-000000000000",
			wantCode: http.StatusNotFound,
		},
		{name: "no credential at all", path: "/v1/sessions/" + real.String(), wantCode: http.StatusUnauthorized},
		{name: "a credential that does not resolve", path: "/v1/sessions/" + real.String(), wantCode: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := newSessionWorld(t)
			w.auth.revokeSessionErr = tt.err

			token := w.auth.token
			if tt.wantCode == http.StatusUnauthorized && tt.name != "no credential at all" {
				token = "never-issued"
				w.auth.revokeSessionErr = auth.ErrUnauthenticated
			}
			if tt.name == "no credential at all" {
				token = ""
			}

			rec := requestAs(t, w.handler, token, http.MethodDelete, tt.path, "")
			if rec.Code != tt.wantCode {
				t.Fatalf("DELETE %s = %d, want %d\nbody: %s", tt.path, rec.Code, tt.wantCode, rec.Body)
			}

			wantCode := CodeNotFound
			if tt.wantCode == http.StatusUnauthorized {
				wantCode = CodeUnauthorized
			}
			if p := decodeProblem(t, rec); p.Code != wantCode {
				t.Errorf("code = %q, want %q; body: %s", p.Code, wantCode, rec.Body)
			}

			if tt.name == "an id this service did not issue" || tt.name == "the nil uuid" {
				if len(w.auth.revokedSessions) != 0 {
					t.Errorf("the use case was called with a malformed id: %v", w.auth.revokedSessions)
				}
			}
		})
	}
}

func TestTheFourRefusalsAreOneDocument(t *testing.T) {
	t.Parallel()

	render := func(path string) string {
		w := newSessionWorld(t)
		w.auth.revokeSessionErr = auth.ErrSessionNotFound
		rec := requestAs(t, w.handler, w.auth.token, http.MethodDelete, path, "")

		var p Problem
		if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
			t.Fatalf("the body is not a problem document: %v\n%s", err, rec.Body)
		}
		p.TraceID = ""
		p.Instance = ""
		out, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("re-marshaling: %v", err)
		}
		return string(out)
	}

	want := render("/v1/sessions/" + id.MustNew().String())
	for _, path := range []string{
		"/v1/sessions/" + id.MustNew().String(),
		"/v1/sessions/not-a-uuid",
		"/v1/sessions/00000000-0000-0000-0000-000000000000",
	} {
		if got := render(path); got != want {
			t.Errorf("DELETE %s renders\n  %s\nDELETE (a missing session) renders\n  %s\n"+
				"They must be one document: a detail that varies with the reason is how a 404 "+
				"becomes an oracle for whether a session id is live anywhere in this deployment.",
				path, got, want)
		}
	}
}

func TestAStoreFailureDuringTheRevocationIsA500(t *testing.T) {
	t.Parallel()

	w := newSessionWorld(t)
	w.auth.revokeSessionErr = errors.New("connection refused")

	rec := w.signedIn(t, http.MethodDelete, "/v1/sessions/"+id.MustNew().String())
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("DELETE /v1/sessions/… = %d, want 500\nbody: %s", rec.Code, rec.Body)
	}
}

func TestAScopedApiKeyCannotRevokeASession(t *testing.T) {
	t.Parallel()

	handler := New(nil,
		WithAuth(newFakeAuth()),
		WithAPIKeyCaller(newFakeAPIKeyCaller(users.User{ID: id.MustNew()}, apikeys.Key{ID: id.MustNew(), AccountID: id.MustNew()})),
	)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/v1/sessions/"+id.MustNew().String(), nil)
	req.Header.Set("Authorization", "Bearer anywaye_a-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("DELETE /v1/sessions/… with an api key = %d, want 403\nbody: %s", rec.Code, rec.Body)
	}
}

func TestTheSessionRoutesAreNotTenancyRoutesAndDeclareNoScope(t *testing.T) {
	t.Parallel()

	for _, route := range []string{"GET /v1/sessions", "DELETE /v1/sessions/{sessionID}"} {
		if scope, declared := accountRouteScopes[route]; declared {
			t.Errorf("%s declares the scope %q in accountRouteScopes. These routes are "+
				"session-only and are refused to a scoped token by `sessionCredentialOnly`; a "+
				"scope row here gates nothing, which is what a comment with a type looks like.",
				route, scope)
		}
	}

	for _, route := range mountedAccountRoutes() {
		if strings.Contains(route, "/v1/sessions") {
			t.Errorf("%s is mounted by registerTenancyRoutes. A session belongs to a user, not to "+
				"an account, so there is no account in the path to scope it by.", route)
		}
	}
}

func TestRevokingASessionSetsNoCookie(t *testing.T) {
	t.Parallel()

	w := newSessionWorld(t)
	rec := w.signedIn(t, http.MethodDelete, "/v1/sessions/"+id.MustNew().String())
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE /v1/sessions/… = %d, want 204\nbody: %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Set-Cookie"); got != "" {
		t.Errorf("Set-Cookie = %q on a 204 from the single-session revoke. This route cannot "+
			"know whether the session it just ended is the one the request arrived on, and "+
			"clearing the cookie on a guess signs the caller out of the device they are using.", got)
	}
}

func TestTheSessionRoutesAcceptEitherCredentialSurface(t *testing.T) {
	t.Parallel()

	for _, via := range []string{"cookie", "header"} {
		t.Run(via, func(t *testing.T) {
			t.Parallel()

			w := newSessionWorld(t)

			var req *http.Request
			if via == "cookie" {
				req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/sessions", nil)
				req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: w.auth.token})
			} else {
				req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/sessions", nil)
				req.Header.Set("Authorization", "Bearer "+w.auth.token)
			}

			rec := httptest.NewRecorder()
			w.handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("GET /v1/sessions via the %s = %d, want 200\nbody: %s", via, rec.Code, rec.Body)
			}
			if len(w.auth.listedAs) != 1 || w.auth.listedAs[0] != w.auth.token {
				t.Errorf("via the %s the use case was handed %v, want [%s]", via, w.auth.listedAs, w.auth.token)
			}
		})
	}
}
