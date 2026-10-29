package client


import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anywaye/identity/client/generated"
)

const (
	socialGoogle = generated.StartSocialLoginParamsProviderGoogle
)

type socialServer struct {
	*httptest.Server

	status      int
	body        string
	location    string
	lastQuery   string
	lastPath    string
	requestSeen bool
}

func newSocialServer(t *testing.T, status int, body, location string) *socialServer {
	t.Helper()

	s := &socialServer{status: status, body: body, location: location}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requestSeen = true
		s.lastPath = r.URL.Path
		s.lastQuery = r.URL.RawQuery
		if s.location != "" {
			w.Header().Set("Location", s.location)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(s.status)
		_, _ = w.Write([]byte(s.body))
	}))
	t.Cleanup(s.Close)
	return s
}

func TestTheStartWrapperReturnsTheRedirectTargetAndNothingElse(t *testing.T) {
	const target = "https://accounts.google.com/o/oauth2/v2/auth?client_id=abc&state=xyz"

	server := newSocialServer(t, http.StatusFound, "", target)
	client := newTestClient(t, server.URL, fakeSessionToken)

	location, err := client.StartSocialLogin(context.Background(), socialGoogle)
	if err != nil {
		t.Fatalf("a 302 with a Location is the success this operation promises: %v", err)
	}
	if location != target {
		t.Errorf("the wrapper returned %q, want the Location header verbatim (%q)", location, target)
	}
	if server.lastPath != "/v1/auth/oauth/google" {
		t.Errorf("the request went to %q, want /v1/auth/oauth/google", server.lastPath)
	}
	if !server.requestSeen {
		t.Error("no request reached the server, so the assertions above compared nothing")
	}
}

func TestAStartRedirectWithNoLocationIsAFailureRatherThanAnEmptyString(t *testing.T) {
	server := newSocialServer(t, http.StatusFound, "", "")
	client := newTestClient(t, server.URL, fakeSessionToken)

	location, err := client.StartSocialLogin(context.Background(), socialGoogle)
	if err == nil {
		t.Fatalf("a 302 with no Location was returned as the success %q. The document "+
			"promises a Location, and a caller rendering a sign-in button from an empty "+
			"string would render a link to itself.", location)
	}
	var call *CallError
	if !errorsAs(err, &call) {
		t.Fatalf("expected a *CallError, got %T: %v", err, err)
	}
	if location != "" {
		t.Errorf("the wrapper returned %q alongside an error. A caller that checks the error "+
			"second and uses the value anyway would follow a URL the service did not give it.", location)
	}
}

func TestAnUnconfiguredProviderIsTheSame404AsOneThatDoesNotExist(t *testing.T) {
	const body = `{"type":"https://anywaye.com/problems/not_found","title":"Not found",` +
		`"status":404,"code":"not_found","detail":"no route","trace_id":"3f1c9a2e-7b4d-4c8e-9a1b-2d5e6f708192"}`

	server := newSocialServer(t, http.StatusNotFound, body, "")
	client := newTestClient(t, server.URL, fakeSessionToken)

	_, _, err := client.CompleteSocialLogin(context.Background(),
		generated.CompleteSocialLoginParamsProviderGoogle,
		&generated.CompleteSocialLoginParams{State: "a-state"})
	if err == nil {
		t.Fatal("a 404 was returned as a success")
	}

	var problem ProblemError
	if !errorsAs(err, &problem) {
		t.Fatalf("expected a client.ProblemError so the caller can read `code`, got %T: %v", err, err)
	}
	if problem.HTTPStatus() != http.StatusNotFound {
		t.Errorf("the problem carries status %d, want 404", problem.HTTPStatus())
	}
}

func TestTheClientDoesNotFollowARedirect(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Location", "https://accounts.google.com/o/oauth2/v2/auth?state=xyz")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, fakeSessionToken)

	location, err := client.StartSocialLogin(context.Background(), socialGoogle)
	if err != nil {
		t.Fatalf("a 302 with a Location is this operation's success: %v", err)
	}
	if !strings.HasPrefix(location, "https://accounts.google.com/") {
		t.Errorf("the wrapper returned %q, want the redirect target", location)
	}

	if _, err := client.GetCurrentUser(context.Background()); err == nil {
		t.Error("a 302 answered as a success on an operation whose success is JSON")
	}

	if requests != 2 {
		t.Errorf("this client made %d request(s) for two calls. It follows none of the "+
			"redirects it is handed: the 302 is data to return, and the Location carries a "+
			"third party's address rather than this service's.", requests)
	}
}

func TestTheCallbackWrapperTellsTheThreeSuccessShapesApart(t *testing.T) {
	const token = "0dN3aQ2vF8kLmXpR7sT1uWzYb4cE6hJ9gK2mP5rS8tV"

	for _, tc := range []struct {
		name       string
		status     int
		body       string
		wantToken  string
		wantLinked bool
		wantMFA    bool
	}{
		{
			name:      "a sign-in that finished",
			status:    http.StatusOK,
			body:      `{"token":"` + token + `","expires_at":"2026-10-30T12:00:00Z"}`,
			wantToken: token,
		},
		{
			name:       "a provider identity linked, no session minted",
			status:     http.StatusOK,
			body:       `{"linked_provider":"google"}`,
			wantLinked: true,
		},
		{
			name:    "an account with a second factor",
			status:  http.StatusAccepted,
			body:    `{"mfa_required":true,"challenge":"` + token + `","expires_at":"2026-10-30T12:10:00Z"}`,
			wantMFA: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := newSocialServer(t, tc.status, tc.body, "")
			client := newTestClient(t, server.URL, fakeSessionToken)

			session, linked, err := client.CompleteSocialLogin(context.Background(),
				generated.CompleteSocialLoginParamsProviderGoogle,
				&generated.CompleteSocialLoginParams{State: "a-state"})

			switch {
			case tc.wantMFA:
				var mfa *MFARequiredError
				if !errorsAs(err, &mfa) {
					t.Fatalf("a 202 must come back as an *MFARequiredError so the caller "+
						"handles it with errors.As exactly as it does for a password login; got %T: %v", err, err)
				}
				if mfa.Challenge.Challenge != token {
					t.Errorf("the challenge carried %q, want %q", mfa.Challenge.Challenge, token)
				}
				if session != nil || linked {
					t.Errorf("a 202 returned (session=%v, linked=%v). No session exists on this "+
						"path, and a caller that read one would be holding an unauthenticated "+
						"client.", session, linked)
				}

			case tc.wantLinked:
				if err != nil {
					t.Fatalf("the link path is a 200 and is not an error: %v", err)
				}
				if !linked || session != nil {
					t.Errorf("the link path returned (session=%v, linked=%v), want (nil, true). "+
						"Linking mints nothing, so a non-nil session here is a credential "+
						"caller has no right to hold.", session, linked)
				}

			default:
				if err != nil {
					t.Fatalf("a 200 Session is a success: %v", err)
				}
				if session == nil || session.Token != tc.wantToken {
					t.Fatalf("the sign-in path returned %v, want a session carrying the token", session)
				}
				if linked {
					t.Error("the sign-in path reported linked=true. Linking and signing in are " +
						"different outcomes and a caller must not be told both happened.")
				}
			}
		})
	}
}

func TestTheCallbackWrapperRefusesToGuessAtAShapeItDoesNotRecognise(t *testing.T) {
	server := newSocialServer(t, http.StatusOK, `{"expires_at":"2026-10-30T12:00:00Z"}`, "")
	client := newTestClient(t, server.URL, fakeSessionToken)

	session, linked, err := client.CompleteSocialLogin(context.Background(),
		generated.CompleteSocialLoginParamsProviderGoogle,
		&generated.CompleteSocialLoginParams{State: "a-state"})
	if err == nil {
		t.Fatalf("a 200 carrying neither a token nor a linked_provider returned as "+
			"(session=%v, linked=%v). The document promises exactly two 200 shapes and a "+
			"guess between them reports a completed sign-in that did not happen.", session, linked)
	}
	var call *CallError
	if !errorsAs(err, &call) {
		t.Fatalf("expected a *CallError, got %T: %v", err, err)
	}
	if session != nil {
		t.Errorf("a session was returned alongside the error (%v). A caller that checks the "+
			"error second would hold a credential for a sign-in that failed.", session)
	}
}

func TestAnEmailCollisionComesBackAsA409AndNotASession(t *testing.T) {
	const body = `{"type":"https://anywaye.com/problems/conflict","title":"Conflict","status":409,` +
		`"code":"conflict","detail":"an account already exists for the email address that ` +
		`oauth account reports, so this sign-in was refused rather than linked. Sign in ` +
		`with that account instead","trace_id":"3f1c9a2e-7b4d-4c8e-9a1b-2d5e6f708192"}`

	server := newSocialServer(t, http.StatusConflict, body, "")
	client := newTestClient(t, server.URL, fakeSessionToken)

	session, linked, err := client.CompleteSocialLogin(context.Background(),
		generated.CompleteSocialLoginParamsProviderGoogle,
		&generated.CompleteSocialLoginParams{State: "a-state"})
	if err == nil {
		t.Fatalf("a 409 was returned as a success (session=%v, linked=%v). This is the "+
			"email-collision refusal and reporting it as a completed sign-in is exactly "+
			"the account takeover the rule exists to prevent.", session, linked)
	}
	if session != nil {
		t.Errorf("a session was returned alongside the refusal: %v", session)
	}
	if linked {
		t.Error("linked=true on a 409. Nothing was linked; the sign-in was refused.")
	}

	var problem ProblemError
	if !errorsAs(err, &problem) {
		t.Fatalf("expected a client.ProblemError carrying `conflict`, got %T: %v", err, err)
	}
	if problem.HTTPStatus() != http.StatusConflict {
		t.Errorf("the problem carries status %d, want 409", problem.HTTPStatus())
	}
}
