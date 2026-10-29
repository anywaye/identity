package client


import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const sessionCredential = "0dN3aQ2vF8kLmXpR7sT1uWzYb4cE6hJ9gK2mP5rS8tV"

const apiCredential = "anywaye_Zq3vK7mXpR2tY8wB4cN6dF0gH1jK5lM9oP3qS7uV2wX4yZ8"

const jwtCredential = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
	"eyJzdWIiOiJhYjAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDAifQ." +
	"c2lnbmF0dXJlLWhlcmU"

func TestClassifyCredentialTellsTheThreeShapesApart(t *testing.T) {
	for _, tc := range []struct {
		name   string
		token  string
		want   CredentialKind
		reason string
	}{
		{
			name:  "a scoped api token is an api token",
			token: apiCredential,
			want:  KindAPIToken,
			reason: "the `anywaye_` prefix is identity's own discriminator, and " +
				"`internal/apikeys/apikeys.go` says it decides which table a value is " +
				"looked up in before any query runs",
		},
		{
			name:  "a session token is a session",
			token: sessionCredential,
			want:  KindSession,
			reason: "43 base64url characters with no prefix and no dots is the shape " +
				"identity's `Session.token` documents",
		},
		{
			name:  "a jws is a jwt",
			token: jwtCredential,
			want:  KindJWT,
			reason: "three base64url segments whose header decodes to a JSON object " +
				"carrying an `alg` — the other five services' service-to-service credential",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ClassifyCredential(tc.token)
			if err != nil {
				t.Fatalf("classification refused a credential it should accept: %v", err)
			}
			if got != tc.want {
				t.Errorf("classified %T, want %T.\n%s", got, tc.want, tc.reason)
			}
		})
	}
}

func TestClassifyCredentialIsNotFooledByTheSegmentCount(t *testing.T) {
	got, err := ClassifyCredential("one.two.three")
	if err != nil {
		t.Fatalf("classification refused: %v", err)
	}
	if got == KindJWT {
		t.Error("`one.two.three` was classified as a JWT.\n" +
			"The shape check is necessary and not sufficient, so the header segment is " +
			"decoded and parsed. A value that happens to contain dots is a session " +
			"credential far more often than it is a JWT.")
	}
}

func TestClassifyCredentialRefusesValuesThatCouldBreakAHeader(t *testing.T) {
	for _, tc := range []struct{ name, token string }{
		{"an empty value", ""},
		{"a carriage return", "abc\rdef"},
		{"a line feed", "abc\ndef"},
		{"a NUL", "abc\x00def"},
		{"a space", "abc def"},
		{"a tab", "abc\tdef"},
		{"a DEL", "abc\x7fdef"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ClassifyCredential(tc.token)
			if err == nil {
				t.Fatalf("%q was accepted.\n"+
					"CR, LF and NUL are header injection, and the other controls and the "+
					"space have no legitimate use in any of the three shapes. Refusing at "+
					"construction is worth more than a 401 from a service hours later.",
					tc.token)
			}
			if !errors.Is(err, ErrInvalidCredential) {
				t.Errorf("the refusal does not match ErrInvalidCredential, so a caller "+
					"cannot branch on it: %v", err)
			}
			if err != nil && strings.Contains(err.Error(), strings.TrimSpace(tc.token)) &&
				tc.token != "" {
				t.Errorf("the error message quotes the offending value: %v", err)
			}
		})
	}
}

func TestAttachCredentialPutsAnAPITokenInTheHeaderAndNotInACookie(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/me", nil)

	if err := AttachCredential(req, apiCredential); err != nil {
		t.Fatalf("attaching: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "Bearer "+apiCredential {
		t.Errorf("Authorization is %q, want the bearer header.\n"+
			"A scoped API token is accepted on the account-scoped routes through the "+
			"header; that is the surface it belongs on.", got)
	}

	if got := req.Header.Get("Cookie"); got != "" {
		t.Errorf("a scoped API token was put in a Cookie header: %q.\n"+
			"core reserves cookies for browser sessions, and a machine credential in a "+
			"cookie is one a browser attaches without the holder intending it. This is "+
			"the direction that has to be refused.", got)
	}
}

func TestAttachCredentialPutsASessionInBoth(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/me", nil)

	if err := AttachCredential(req, sessionCredential); err != nil {
		t.Fatalf("attaching: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "Bearer "+sessionCredential {
		t.Errorf("Authorization is %q, want the bearer header.\n"+
			"A session is a credential like any other and belongs in the header first; "+
			"identity prefers it when both are present.", got)
	}

	want := SessionCookieName + "=" + sessionCredential
	if got := req.Header.Get("Cookie"); got != want {
		t.Errorf("Cookie is %q, want %q.\n"+
			"THE `__Host-` PREFIX IS NOT COSMETIC: a browser enforces Secure, Path=/ and "+
			"no Domain on it, and that is what binds it to one origin. A cookie named "+
			"`session` instead would look authenticated and not be.",
			got, want)
	}
}

func TestAttachCredentialNeverOverwritesWhatTheCallerSet(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/me", nil)
	req.Header.Set("Authorization", "Bearer caller-supplied")
	req.Header.Set("Cookie", "__Host-session=caller-supplied")

	if err := AttachCredential(req, sessionCredential); err != nil {
		t.Fatalf("attaching: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "Bearer caller-supplied" {
		t.Errorf("Authorization became %q; a caller's own per-request header was overwritten.\n"+
			"The generated client applies the same rule to the same problem "+
			"(`checkForExistence`), and matching it means a caller who passes their own "+
			"credential per request gets theirs rather than a surprise about which of two "+
			"values won.", got)
	}
	if got := req.Header.Get("Cookie"); got != "__Host-session=caller-supplied" {
		t.Errorf("Cookie became %q; a caller's own cookie was overwritten.", got)
	}
}

func TestTheCredentialReachesTheWireAndTheServerSeesIt(t *testing.T) {
	for _, tc := range []struct {
		name       string
		token      string
		wantCookie bool
	}{
		{"a scoped api token", apiCredential, false},
		{"a session token", sessionCredential, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var (
				gotAuth   string
				gotCookie string
				gotPath   string
			)

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotAuth = r.Header.Get("Authorization")
				gotCookie = r.Header.Get("Cookie")
				gotPath = r.URL.Path

				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"ab000000-0000-0000-0000-000000000000",` +
					`"email":"someone@example.com"}`))
			}))
			defer server.Close()

			client, err := New(Options{BaseURL: server.URL, Token: tc.token})
			if err != nil {
				t.Fatalf("building a client: %v", err)
			}

			if _, err := client.GetCurrentUser(t.Context()); err != nil {
				t.Fatalf("GetCurrentUser: %v", err)
			}

			if gotAuth != "Bearer "+tc.token {
				t.Errorf("the server saw Authorization %q, want the credential.\n"+
					"This is the assertion that matters: the one above tests the helper, "+
					"this one tests that a request actually left the process.", gotAuth)
			}

			switch {
			case tc.wantCookie && gotCookie == "":
				t.Errorf("the server saw no Cookie header.\n" +
					"A session must also travel in `__Host-session`, because identity's " +
					"cookie surface is the browser's and the header is the fallback.")
			case !tc.wantCookie && gotCookie != "":
				t.Errorf("the server saw Cookie %q for a credential that must not travel "+
					"in one.", gotCookie)
			}

			if gotPath != "/v1/me" {
				t.Errorf("the request went to %q, want /v1/me.\n"+
					"The base URL is concatenated with the operation's path, so a base "+
					"URL keeping its trailing slash would produce `//v1/me` — which some "+
					"routers answer with a 404 and some silently accept.",
					gotPath)
			}
		})
	}
}

func TestAnAnonymousClientSendsNoCredential(t *testing.T) {
	var gotAuth, gotCookie string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCookie = r.Header.Get("Cookie")

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	client, err := New(Options{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("building an anonymous client: %v", err)
	}

	if client.HasCredential() {
		t.Error("HasCredential reports true for a client built with no token")
	}

	if _, err := client.Liveness(t.Context()); err != nil {
		t.Fatalf("Liveness: %v", err)
	}

	if gotAuth != "" || gotCookie != "" {
		t.Errorf("an anonymous client sent Authorization %q and Cookie %q.\n"+
			"`GET /healthz` is served to anybody, and a client that attached an empty "+
			"credential would send `Authorization: Bearer `, which is a malformed header "+
			"rather than an absent one.", gotAuth, gotCookie)
	}
}
