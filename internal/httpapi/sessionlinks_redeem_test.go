package httpapi


import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/anywaye/identity/internal/apikeys"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/recovery"
	"github.com/anywaye/identity/internal/users"
)

func (f *sessionLinkFixture) redeem(t *testing.T, body, credential string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/session-links/redeem", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}


func TestARedemptionReturnsASessionAndTheSessionCookie(t *testing.T) {
	f := newSessionLinkFixture(t)

	rec := f.redeem(t, `{"token":"a-link-token"}`, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("redeeming a live link = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the 200 body is not JSON: %v", err)
	}
	if len(body) != 2 {
		t.Errorf("the 200 body carries %d field(s) (%v), want exactly token and expires_at. This "+
			"is the LOGIN's body, and anything further would be a second session shape for "+
			"clients to learn", len(body), body)
	}
	if body["token"] != "redeemed-by-the-use-case" {
		t.Errorf("token = %v, want the value the use case returned", body["token"])
	}

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("the redemption set %d cookies, want 1: a browser holding a link and no session "+
			"cookie has nothing to be signed in with", len(cookies))
	}
	if c := cookies[0]; c.Value != "redeemed-by-the-use-case" {
		t.Errorf("the cookie carries %q, want the same value as the body's token", c.Value)
	}
}

func TestTheRedemptionPassesTheTokenAndTheRequestContextToTheUseCase(t *testing.T) {
	f := newSessionLinkFixture(t)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/session-links/redeem",
		strings.NewReader(`{"token":"a-link-token"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "a-browser-that-names-itself")
	req.RemoteAddr = "203.0.113.7:54321"
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if len(f.recovery.linkRedeems) != 1 {
		t.Fatalf("the use case was called %d times, want once", len(f.recovery.linkRedeems))
	}
	in := f.recovery.linkRedeems[0]
	if in.Token != "a-link-token" {
		t.Errorf("the use case was handed token %q, want the one the body carried", in.Token)
	}
	if in.UserAgent != "a-browser-that-names-itself" {
		t.Errorf("UserAgent = %q, want the request's. It is evidence for an incident and a "+
			"delegated session that records none is an unexplained session", in.UserAgent)
	}
	if in.IP == nil || in.IP.String() != "203.0.113.7" {
		t.Errorf("IP = %v, want 203.0.113.7. Recorded, never trusted — and recorded on a "+
			"delegated session exactly as on a password one", in.IP)
	}
}


func TestARefusedRedemptionIsTheShapeOfAnUnknownToken(t *testing.T) {
	cases := []struct {
		name        string
		err         error
		want        int
		wantCode    string
		wantDetail  string
		notInDetail string
	}{
		{
			name:        "a token that never existed",
			err:         recovery.ErrTokenNotFound,
			want:        http.StatusNotFound,
			wantCode:    CodeNotFound,
			wantDetail:  "no such link",
			notInDetail: "session_link",
		},
		{
			name:        "a wrapped refusal",
			err:         wrappedError{inner: recovery.ErrTokenNotFound},
			want:        http.StatusNotFound,
			wantCode:    CodeNotFound,
			wantDetail:  "no such link",
			notInDetail: "wrapped",
		},
		{
			name:        "a deployment that cannot ask about second factors",
			err:         recovery.ErrMFAUnavailable,
			want:        http.StatusServiceUnavailable,
			wantCode:    CodeServiceUnavailable,
			wantDetail:  "second factor",
			notInDetail: "SELECT",
		},
		{
			name:        "the database fell over",
			err:         errDatabaseWentAway,
			want:        http.StatusInternalServerError,
			wantCode:    CodeInternal,
			notInDetail: "10.0.0.5",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSessionLinkFixture(t)
			f.recovery.linkRedeemErr = tc.err

			rec := f.redeem(t, `{"token":"a-link-token"}`, "")

			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tc.want, rec.Body)
			}
			problem := decodeProblem(t, rec)
			if problem.Code != tc.wantCode {
				t.Errorf("code = %q, want %q", problem.Code, tc.wantCode)
			}
			if problem.Status != tc.want {
				t.Errorf("the document's own status = %d, want %d: core says `code` is the "+
					"contract and `status` is advisory, so the two disagreeing is invisible to a "+
					"client that reads the code", problem.Status, tc.want)
			}
			if !strings.Contains(problem.Detail, tc.wantDetail) {
				t.Errorf("detail = %q, want it to mention %q", problem.Detail, tc.wantDetail)
			}
			if strings.Contains(problem.Detail, tc.notInDetail) {
				t.Errorf("the detail leaked an internal fact: %q", problem.Detail)
			}
			if rec.Header().Get("Content-Type") != "application/problem+json" {
				t.Errorf("a %d is not application/problem+json", rec.Code)
			}
			if len(rec.Result().Cookies()) != 0 {
				t.Errorf("a refusal set %d cookie(s): a %d that hands over a session is not a "+
					"refusal", len(rec.Result().Cookies()), rec.Code)
			}
		})
	}
}

func TestTheRedemptionRouteIsReachableByNoCredentialAndByASessionAndByNothingElse(t *testing.T) {
	cases := []struct {
		name       string
		credential string
		want       int
		wantCode   string
	}{
		{
			name: "anonymous — the link IS the credential",
			want: http.StatusOK,
		},
		{
			name:       "with a browser session",
			credential: "session",
			want:       http.StatusOK,
		},
		{
			name:       "with a scoped api key",
			credential: "apiKey",
			want:       http.StatusForbidden,
			wantCode:   CodeForbidden,
		},
		{
			name:       "with a token-shaped value that resolves to nothing",
			credential: "strangerToken",
			want:       http.StatusForbidden,
			wantCode:   CodeForbidden,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSessionLinkFixture(t)

			credential := f.apiKey
			switch tc.credential {
			case "session":
				credential = f.session
			case "strangerToken":
				credential = f.strangerToken
			case "":
				credential = ""
			}

			rec := f.redeem(t, `{"token":"a-link-token"}`, credential)

			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tc.want, rec.Body)
			}
			if tc.wantCode != "" {
				if got := decodeProblem(t, rec).Code; got != tc.wantCode {
					t.Errorf("code = %q, want %q", got, tc.wantCode)
				}
			}
			if tc.want >= 400 && len(f.recovery.linkRedeems) != 0 {
				t.Error("a scoped api key reached the use case. A machine credential that can turn " +
					"an opaque value into a browser session has no counterpart in this vocabulary")
			}
		})
	}
}

func TestARedemptionBodyWithNoTokenIsRefusedBeforeTheUseCase(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"the field is absent", `{}`},
		{"an empty string", `{"token":""}`},
		{"whitespace", `{"token":"   "}`},
		{"the field is the wrong type", `{"token":42}`},
		{"an unknown field beside it", `{"token":"abc","redirect":"https://elsewhere.example.com"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSessionLinkFixture(t)

			rec := f.redeem(t, tc.body, "")
			if rec.Code != http.StatusUnprocessableEntity && rec.Code != http.StatusBadRequest {
				t.Fatalf("%s = %d, want 422 or 400; body: %s", tc.name, rec.Code, rec.Body)
			}
			if len(f.recovery.linkRedeems) != 0 {
				t.Errorf("%s reached the use case. There is no row this token can be, so the "+
					"route must refuse it rather than hashing it and asking the table", tc.name)
			}
		})
	}
}


type sessionLinkMatrixEndpoint struct {
	name   string
	method string
	pattern string
	anonymous   int
	withSession int
	withToken   int
	body        string
}

func sessionLinkMatrixEndpoints() []sessionLinkMatrixEndpoint {
	return []sessionLinkMatrixEndpoint{
		{
			name: "mint a session link", method: http.MethodPost,
			pattern:     "/v1/session-links",
			anonymous:   http.StatusForbidden,
			withSession: http.StatusForbidden,
			withToken:   http.StatusCreated,
			body:        `{"user_id":"00000000-0000-0000-0000-000000000001"}`,
		},
		{
			name: "redeem a session link", method: http.MethodPost,
			pattern:     "/v1/session-links/redeem",
			anonymous:   http.StatusOK,
			withSession: http.StatusOK,
			withToken:   http.StatusForbidden,
			body:        `{"token":"a-token-that-is-not-one"}`,
		},
	}
}

func TestEverySessionLinkRouteIsInTheMatrix(t *testing.T) {
	mounted := mountedSessionLinkRoutes()
	if len(mounted) == 0 {
		t.Fatal("the walk found no session-link route, so every assertion below would pass " +
			"vacuously")
	}

	covered := make(map[string]bool, len(sessionLinkMatrixEndpoints()))
	for _, endpoint := range sessionLinkMatrixEndpoints() {
		covered[normalizeRoute(endpoint.method, endpoint.pattern)] = true
	}

	for _, route := range mounted {
		if !covered[route] {
			t.Errorf("route %s is mounted on the session-link surface but has no row in its "+
				"authorization matrix", route)
		}
	}
	if len(covered) > len(mounted) {
		t.Errorf("the session-link matrix has %d rows for %d mounted routes; it is asserting on "+
			"routes that do not exist", len(covered), len(mounted))
	}
}

func TestTheSessionLinkAuthorizationMatrix(t *testing.T) {
	for _, endpoint := range sessionLinkMatrixEndpoints() {
		t.Run(endpoint.name, func(t *testing.T) {
			for _, column := range []struct {
				name       string
				credential string
				want       int
			}{
				{name: "anonymous", credential: "", want: endpoint.anonymous},
				{name: "session", credential: "a-session-token", want: endpoint.withSession},
				{name: "scoped token", credential: scopedTokenForTheMatrix, want: endpoint.withToken},
			} {
				t.Run(column.name, func(t *testing.T) {
					f := newSessionLinkFixture(t)
					rec := sendWith(t, f.handler, endpoint.method, endpoint.pattern,
						column.credential, "", endpoint.body)

					if rec.Code != column.want {
						t.Fatalf("%s %s as %s = %d, want %d; body: %s",
							endpoint.method, endpoint.pattern, column.name, rec.Code, column.want, rec.Body)
					}
					if column.want >= 400 && len(f.recovery.linkRedeems) != 0 {
						t.Errorf("a refused %s reached the redemption use case", column.name)
					}
				})
			}
		})
	}
}

func mountedSessionLinkRoutes() []string {
	var found []string

	r := chi.NewRouter()
	options{
		auth:         newFakeAuth(),
		apiKeyCaller: newFakeAPIKeyCaller(users.User{}, apikeys.Key{ID: id.MustNew(), Scopes: []string{apikeys.ScopeSessionsWrite}}),
		recovery:     newFakeRecovery(),
	}.registerRoutes(r)

	_ = chi.Walk(r, func(method string, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		clean := normalizeRoute(method, route)
		if strings.HasPrefix(clean, "POST /v1/session-links") {
			found = append(found, clean)
		}
		return nil
	})

	sort.Strings(found)
	return found
}
