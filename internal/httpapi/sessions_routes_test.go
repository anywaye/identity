package httpapi

// GET /v1/sessions AND DELETE /v1/sessions/{id}, AT THE ROUTER.
//
// Three things are under test here and none of them is the status code, which is
// the cheapest thing to assert about a new route and the least likely to be the
// bug:
//
//  1. THE SHAPE. What a row carries and, more importantly, what it does not. A
//     listing that renders a credential is the failure this service cares about
//     most and the one a status-code assertion cannot see.
//  2. THE CREDENTIAL THE HANDLER RESOLVED. The double records the token each use
//     case was handed, so a handler that read the wrong surface — or read the body
//     — is visible.
//  3. THE ID THE HANDLER TOOK FROM THE PATH. Same reason. The 404 is asserted for
//     the four ways of being wrong because that is where a handler that reached for
//     the wrong chi parameter would pass everything else.
//
// The boundary itself — a caller cannot revoke somebody else's session — is proven
// twice more and neither is here: the statement's WHERE clause in
// `internal/sessions/store_listing_test.go`, and over HTTP against a real database
// in `sessions_routes_integration_test.go`. What this file holds is that the
// handler hands the use case a CREDENTIAL rather than a user id, because that is
// the half a database test cannot see: the handler could pass the right token to a
// service that ignored it.

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/apikeys"
	"github.com/cafaye/identity/internal/auth"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/sessions"
	"github.com/cafaye/identity/internal/users"
)

// sessionWorld is the fixture: a real router over the fake auth service.
type sessionWorld struct {
	handler http.Handler
	auth    *fakeAuth
}

func newSessionWorld(t *testing.T) *sessionWorld {
	t.Helper()

	f := newFakeAuth()
	return &sessionWorld{handler: New(nil, WithAuth(f)), auth: f}
}

// signedIn sends a request carrying the session cookie, which is the surface a
// browser uses and the one this route is about.
func (w *sessionWorld) signedIn(t *testing.T, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	return requestAs(t, w.handler, w.auth.token, method, target, "")
}

// ---------------------------------------------------------------------------
// GET /v1/sessions
// ---------------------------------------------------------------------------

// TestListingASessionRendersEverythingButACredential is the shape test, and it
// asserts ABSENCE by walking the decoded body rather than by reading the struct.
//
// A test that checked the Go type would pass against a handler whose type had the
// right fields while its JSON tags put a digest on the wire — and the whole claim
// here is about the wire. So the body is decoded into `map[string]any` and every
// key is looked at by name.
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

	// The fields a client needs. Asserted by name against the WIRE, not against
	// the Go struct, for the reason in this file's header.
	for _, key := range []string{"id", "created_at", "expires_at", "user_agent", "ip", "current"} {
		if _, present := entry[key]; !present {
			t.Errorf("the entry has no %q: %s", key, rec.Body)
		}
	}

	// And the fields it must not have. A digest is one SHA-256 away from a live
	// credential and the token itself is the credential; `user_id` is not a secret
	// but a listing that renders the owner of a row is a listing whose authority
	// for having asked is the caller's problem to prove.
	for _, key := range []string{"token", "token_digest", "digest", "user_id", "user"} {
		if _, present := entry[key]; present {
			t.Errorf("the entry carries %q, which must never be rendered on a listing: %s", key, rec.Body)
		}
	}

	// The whole body, swept: no substring of the credential appears anywhere, and
	// neither does anything that could have been derived from it.
	//
	// The field-by-field list above would pass against a field with a name nobody
	// thought of, carrying the same value; this is the assertion that would not.
	// The DIGEST is here as well as the token, and it is the more important of the
	// two: a value one SHA-256 away from a live credential is a credential for
	// anybody holding this log, and `Store` has it in hand on every read.
	//
	// The fixture's own value is `a-session-token` with no row behind it, so the
	// digest has to be computed rather than read — `sessions.Digest` is imported for
	// it, which also means this assertion cannot rot if the column is ever renamed.
	for _, secret := range []string{w.auth.token, sessions.Digest(w.auth.token)} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Errorf("the response body contains %q: %s", secret, rec.Body)
		}
	}
}

// TestAnEmptyListingIsAnEmptyArrayNotNull is a rendering contract, and the case it
// protects is ordinary: a user who has signed in once and whose session has since
// expired asks "where am I signed in" and gets `[]`.
func TestAnEmptyListingIsAnEmptyArrayNotNull(t *testing.T) {
	t.Parallel()

	w := newSessionWorld(t)
	w.auth.sessions = nil // the double returns nil rather than an empty slice

	rec := w.signedIn(t, http.MethodGet, "/v1/sessions")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/sessions = %d, want 200\nbody: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"sessions":[]`) {
		t.Errorf("body = %s, want an empty array rather than null. A client rendering this has "+
			"to carry a null check for a case that is entirely ordinary.", rec.Body)
	}
}

// TestTheListingPassesTheCredentialRatherThanAUserId is the boundary claim this
// file can make. The double records what it was handed, and the assertion is that
// it is the cookie's value — because the use case resolves the user from it and
// there is no other route to a user id.
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

// An unusable credential is a 401 and not an empty list. The distinction is the
// whole reason the route is worth having: a 200 with nothing in it tells a client
// its session is fine.
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

// A store failure is a 500, not a 200 with nothing in it. "The database was down"
// and "you have no sessions" are different facts and only one of them is a reason
// to show a user a list.
func TestAStoreFailureDuringTheListingIsA500(t *testing.T) {
	t.Parallel()

	w := newSessionWorld(t)
	w.auth.listErr = errors.New("connection refused")

	rec := w.signedIn(t, http.MethodGet, "/v1/sessions")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("GET /v1/sessions = %d, want 500\nbody: %s", rec.Code, rec.Body)
	}
}

// A SCOPED API KEY IS REFUSED, with 403 and not 401.
//
// The 403 is the same one `sessionCredentialOnly` gives every other session
// surface and the reason is on it: a session IS authenticated, so a 401 would send
// a client hunting a login problem that does not exist. This test is here because
// "a token cannot enumerate browser sessions" is a property of THIS surface that a
// reader would otherwise have to infer from a middleware it has to find.
func TestAScopedApiKeyCannotListSessions(t *testing.T) {
	t.Parallel()

	handler := New(nil,
		WithAuth(newFakeAuth()),
		WithAPIKeyCaller(newFakeAPIKeyCaller(users.User{ID: id.MustNew()}, apikeys.Key{ID: id.MustNew(), AccountID: id.MustNew()})),
	)

	req := httptest.NewRequest(http.MethodGet, "/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer cafaye_a-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET /v1/sessions with an api key = %d, want 403\nbody: %s", rec.Code, rec.Body)
	}
	if p := decodeProblem(t, rec); p.Code != CodeForbidden {
		t.Errorf("code = %q, want %q", p.Code, CodeForbidden)
	}
}

// ---------------------------------------------------------------------------
// DELETE /v1/sessions/{id}
// ---------------------------------------------------------------------------

// TestRevokingASessionTakesTheIdFromThePathAndTheCredentialFromTheRequest is the
// positive case, and it asserts BOTH inputs.
//
// One without the other is a real bug in each direction: a handler that took the
// session id from the cookie would revoke the caller's current session whatever the
// URL said, and one that took the credential from the body would have a body to
// parse on a route that needs none.
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

// The four ways of naming a session you cannot revoke, and the two ways of arriving
// without a credential.
//
// THE 404 IS THE SAME FOR ALL FOUR and that is the disclosure decision in one
// table: a 403 against a 404 would let any signed-in caller probe whether a given
// session id belongs to anybody. The malformed-id case is here for the reason
// accountIDFrom gives — a 422 would be a second, observable answer over the same
// space of strings.
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
			// The handler refuses before the use case is reached, so the double has
			// nothing to answer — which is itself the assertion: a malformed id must
			// not become a query.
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

			// A malformed id never reaches the use case. Asserted rather than
			// assumed, because the handler has three ways to get this right and a
			// wrong one is a query on caller-supplied text.
			if tt.name == "an id this service did not issue" || tt.name == "the nil uuid" {
				if len(w.auth.revokedSessions) != 0 {
					t.Errorf("the use case was called with a malformed id: %v", w.auth.revokedSessions)
				}
			}
		})
	}
}

// THE FOUR 404s ARE BYTE-FOR-BYTE THE SAME DOCUMENT.
//
// Asserted as bytes, because "the same code" is not the property: a detail string
// that varies with the reason is the enumeration oracle this route's 404 exists to
// avoid, and a test comparing only `p.Code` would pass against all four.
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
		// Two fields are cleared, and both for the same reason: they are the REQUEST
		// rather than the answer. `trace_id` is fresh per response and `instance` is
		// the path, so leaving them in would make every pair of documents differ and
		// the assertion vacuous.
		p.TraceID = ""
		p.Instance = ""
		out, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("re-marshalling: %v", err)
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

// A store failure is a 500 rather than a 404. The distinction matters in the
// direction that is easy to get backwards: answering 404 to a database failure
// would tell a caller their session is already gone, and a client that then clears
// its cookie has logged the user out because of a blip.
func TestAStoreFailureDuringTheRevocationIsA500(t *testing.T) {
	t.Parallel()

	w := newSessionWorld(t)
	w.auth.revokeSessionErr = errors.New("connection refused")

	rec := w.signedIn(t, http.MethodDelete, "/v1/sessions/"+id.MustNew().String())
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("DELETE /v1/sessions/… = %d, want 500\nbody: %s", rec.Code, rec.Body)
	}
}

// A scoped api key cannot revoke a browser session either, and the reason is the
// same as for the listing: it is a session surface, and `sessionCredentialOnly` is
// a middleware so the property belongs to the route rather than to the handlers.
func TestAScopedApiKeyCannotRevokeASession(t *testing.T) {
	t.Parallel()

	handler := New(nil,
		WithAuth(newFakeAuth()),
		WithAPIKeyCaller(newFakeAPIKeyCaller(users.User{ID: id.MustNew()}, apikeys.Key{ID: id.MustNew(), AccountID: id.MustNew()})),
	)

	req := httptest.NewRequest(http.MethodDelete, "/v1/sessions/"+id.MustNew().String(), nil)
	req.Header.Set("Authorization", "Bearer cafaye_a-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("DELETE /v1/sessions/… with an api key = %d, want 403\nbody: %s", rec.Code, rec.Body)
	}
}

// The two session routes are on the AUTH registrar and not on the tenancy one,
// which is a design claim rather than an accident and this is what holds it: a
// session belongs to a USER, and one person is in as many accounts as they like,
// so there is no account whose tenancy would mean "the sessions this caller may
// act on".
//
// It is also why these two are absent from `accountRouteScopes`. A row there would
// be a scope gating nothing, and TestEveryScopeIsEnforcedOnItsRoutes exists to
// catch exactly that. Asserted here in the negative because the matrix's
// completeness check only walks the tenancy registrar and would not notice either
// way.
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

	// And they are not mounted by the tenancy registrar, which is the other half:
	// mounted there, they would be inside TestEveryRouteIsInTheMatrix and would
	// have to invent an account to be scoped by.
	for _, route := range mountedAccountRoutes() {
		if strings.Contains(route, "/v1/sessions") {
			t.Errorf("%s is mounted by registerTenancyRoutes. A session belongs to a user, not to "+
				"an account, so there is no account in the path to scope it by.", route)
		}
	}
}

// The revocation clears NO cookie, and this is why that is a test.
//
// The tempting implementation is "if the id in the path is the caller's current
// session, clear the cookie too" — and the handler cannot know, because
// `Authenticate` resolves a token to a user and does not say which session row it
// came from. Guessing wrong in that direction signs the user out of the device they
// are using to end a session on another one. `DELETE /v1/session` is the route that
// clears the cookie, and it already does.
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

// The two routes answer the `__Host-session` cookie and the bearer header alike,
// because `presentedToken` is shared with every other session route — and the
// sharing is the claim: a second way to read the credential would be a second place
// for the preference between them to live.
func TestTheSessionRoutesAcceptEitherCredentialSurface(t *testing.T) {
	t.Parallel()

	for _, via := range []string{"cookie", "header"} {
		t.Run(via, func(t *testing.T) {
			t.Parallel()

			w := newSessionWorld(t)

			var req *http.Request
			if via == "cookie" {
				req = httptest.NewRequest(http.MethodGet, "/v1/sessions", nil)
				req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: w.auth.token})
			} else {
				req = httptest.NewRequest(http.MethodGet, "/v1/sessions", nil)
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
