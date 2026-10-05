package httpapi

// THE REDEMPTION, AT THE ROUTER.
//
// # WHY THESE TESTS DRIVE A DOUBLE AND NOT A DATABASE
//
// Because what is under test here is TRANSLATION: a status, a body, and above all
// the cookie. `internal/recovery`'s own tests hold the spend, the refusals and the
// single-use property against real rows, and
// `sessionlinks_redeem_integration_test.go` here drives the whole thing over a real
// database. A double in this file is the right instrument for one question — "does
// the route hand back exactly what `sessionResponse` and `setSessionCookie` produce,
// and does it refuse without reaching the use case" — and a test that wanted the
// token lifecycle would be measuring the thing next door.
//
// # THE ONE CLAIM THAT CANNOT BE MADE HERE
//
// BYTE AGREEMENT WITH `POST /v1/session`. Both routes call the same two functions, and
// calling them is what makes them agree; a double cannot prove it, because a
// double's answer is whatever the test told it to be. The walk is therefore in the
// integration file, over the real router with real use cases, and this file asserts
// only that the redeem route CALLS what the login route calls — which is visible as
// the cookie and the body shape being produced at all.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/cafaye/identity/internal/apikeys"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/recovery"
	"github.com/cafaye/identity/internal/users"
)

// redeem posts a body to the redemption route with one credential.
func (f *sessionLinkFixture) redeem(t *testing.T, body, credential string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/v1/session-links/redeem", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

// ---------------------------------------------------------------------------
// the happy path
// ---------------------------------------------------------------------------

// TestARedemptionReturnsASessionAndTheSessionCookie is the route working, and the
// cookie is the assertion that matters: `sessionResponse` renders a body and
// `setSessionCookie` renders a cookie, and a redemption that returned only the body
// would have passed a body-only assertion.
//
// THE TOKEN IS THE USE CASE'S, asserted against a value the handler could not have
// invented: the double returns "redeemed-by-the-use-case", so a handler that
// generated its own credential — which is what "the route minted a session" would
// look like — is caught here rather than in production.
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

// TestTheRedemptionPassesTheTokenAndTheRequestContextToTheUseCase is the wiring.
//
// The UserAgent and IP are here because `POST /v1/session` records them on the
// session row and a delegated session that recorded LESS would be an incident
// timeline with a hole in it: nobody could tell afterwards whether the session that
// appeared out of nowhere came from a link. A delegation is not a reason to record
// less than a password.
func TestTheRedemptionPassesTheTokenAndTheRequestContextToTheUseCase(t *testing.T) {
	f := newSessionLinkFixture(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/session-links/redeem",
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

// ---------------------------------------------------------------------------
// the refusals
// ---------------------------------------------------------------------------

// TestARefusedRedemptionIsTheShapeOfAnUnknownToken is the mapping, and the reason
// it is one status is the reason the whole recovery section says it is: the token IS
// the credential on this route, so the caller is the subject or whoever took the
// link, and every refusal has to be the answer for a link they did not receive.
//
// ErrMFAUnavailable is the one row that is NOT that shape, and it is in the table
// because it must not be: "this deployment cannot say whether anybody has a second
// factor" is a fact about the server, true of every caller, and a 404 would hide a
// misconfiguration behind what looks like a very quiet attack.
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
			// The wrapped form, because that is what a real one looks like: `errors.Is`
			// has to do the work, so a mapper comparing by equality would pass this
			// suite and fail in production.
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
			// AND NO SESSION, which is the half a status cannot make: a handler that
			// wrote the session and then declined to answer has still given the user a
			// credential.
			if len(rec.Result().Cookies()) != 0 {
				t.Errorf("a refusal set %d cookie(s): a %d that hands over a session is not a "+
					"refusal", len(rec.Result().Cookies()), rec.Code)
			}
		})
	}
}

// TestTheRedemptionRouteIsReachableByNoCredentialAndByASessionAndByNothingElse is
// the credential shape of this route, which is the same three-column question the
// recovery matrix asks of its eight routes and a different question from the mint's.
//
// The redeem route is PUBLIC: the link is the credential, exactly as a challenge is
// on `POST /v1/session/mfa`. So a session is neither required nor refused, and a
// scoped api key IS refused — a machine credential that can turn an opaque value into
// a browser session is the takeover this service's scope vocabulary deliberately has
// no room for, which is why the mint's 403 is not repeated here and the other
// direction is taken instead.
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
			// A session is neither required nor refused, and that is a decision: a
			// caller holding a valid session and presenting no link is exactly the
			// hijacked-browser case, and a session in the header changes nothing about
			// whether the link is right.
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
			// A refusal is asserted by the use case being reached, because a scoped key
			// that reached the redemption would have a browser session in hand.
			if tc.want >= 400 && len(f.recovery.linkRedeems) != 0 {
				t.Error("a scoped api key reached the use case. A machine credential that can turn " +
					"an opaque value into a browser session has no counterpart in this vocabulary")
			}
		})
	}
}

// TestARedemptionBodyWithNoTokenIsRefusedBeforeTheUseCase is the route's own
// validation, checked both ways: a 422 and no call into the use case.
//
// An EMPTY token is in the table and is not a malformed string — it parses. It is a
// value no row can hold, and a store that treated it as a wildcard would resolve
// against every link in the table. The refusal here is also what keeps a 422 from
// being an oracle: it is the same answer for an empty token and for a whitespace one.
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

// ---------------------------------------------------------------------------
// the matrix for this surface
// ---------------------------------------------------------------------------

// sessionLinkMatrixEndpoint is one row of the session-link route table.
//
// IT IS A THIRD MATRIX RATHER THAN A ROW IN EITHER OF THE OTHER TWO, and the reason
// is that the two existing tables each have a shape this surface does not fit.
//
// `matrixEndpoints` is about ROLES in an ACCOUNT, and neither of these routes has an
// account anywhere in its path. `recoveryMatrixEndpoints` walks the four recovery
// prefixes, and `/v1/session-links` is not one of them — a row added there would be
// a claim about a route its own coverage walk cannot see, which is the shape of bug
// router_walk_test.go exists to catch.
//
// What this surface asks is the CREDENTIAL question, and the answer differs per
// route on the same path: the mint is token-only, the redemption is public, and the
// two share a prefix. That is worth its own table with its own router walk.
type sessionLinkMatrixEndpoint struct {
	name   string
	method string
	// pattern is spelled exactly as the router spells it, because the coverage check
	// compares it against a chi.Walk rather than against a string.
	pattern string
	// anonymous, withSession and withToken are the status each of the three
	// credentials receives.
	anonymous   int
	withSession int
	withToken   int
	body        string
}

// sessionLinkMatrixEndpoints is the table. Every route `registerSessionLinkRoutes`
// mounts appears here exactly once, and TestEverySessionLinkRouteIsInTheMatrix walks
// the router to prove it.
func sessionLinkMatrixEndpoints() []sessionLinkMatrixEndpoint {
	return []sessionLinkMatrixEndpoint{
		{
			// THE MINT. 403 for both non-token columns rather than 401 for the anonymous
			// one: this surface is token-only, so "you are not a scoped token" is a
			// statement about the surface and it is true of a stranger exactly as it is
			// of a signed-in person. `requireSessionLinkMint` decides on the
			// credential's SHAPE, which is the same decision its own row in the mint's
			// table makes.
			name: "mint a session link", method: http.MethodPost,
			pattern:     "/v1/session-links",
			anonymous:   http.StatusForbidden,
			withSession: http.StatusForbidden,
			withToken:   http.StatusCreated,
			body:        `{"user_id":"00000000-0000-0000-0000-000000000001"}`,
		},
		{
			// THE REDEMPTION. Anonymous is the success column, and that is the point:
			// the link IS the credential, so there is nothing else to present. The
			// session column agrees with it because a session changes nothing about
			// whether the link is right. The scoped-token column is the refusal, and it
			// is the one cell on this table that is a security boundary rather than a
			// shape: the mint can create the value this route turns into a session, and
			// a credential that could do both without leaving the machine would make
			// the mint's delegation check decorative.
			name: "redeem a session link", method: http.MethodPost,
			pattern:     "/v1/session-links/redeem",
			anonymous:   http.StatusOK,
			withSession: http.StatusOK,
			withToken:   http.StatusForbidden,
			body:        `{"token":"a-token-that-is-not-one"}`,
		},
	}
}

// TestEverySessionLinkRouteIsInTheMatrix is the completeness check, and it walks
// the ROUTER rather than trusting a restated list.
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

// TestTheSessionLinkAuthorizationMatrix is the suite, and the assertions per cell are
// the status AND whether the use case was reached.
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

// mountedSessionLinkRoutes is every route under `/v1/session-links`, read out of chi.
//
// THE OPTIONS LITERAL IS THE WHOLE OF THE WALK'S HONESSY, for the reason
// `router_walk_test.go` records at length: a registrar that returns early for a
// missing service leaves its routes out, and the check above would then be a check of
// a smaller service than the one that runs. `auth` and `apiKeyCaller` are set because
// the mint's middleware needs both, and `TestTheDriftWalkSeesTheSessionLinkSurface`
// is what keeps the other walks honest about the same surface.
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
