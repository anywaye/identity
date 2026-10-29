package httpapi

import (
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)


type recoveryMatrixEndpoint struct {
	name   string
	method string
	pattern string
	anonymous   int
	withSession int
	withToken   int
	body string
}

func recoveryMatrixEndpoints() []recoveryMatrixEndpoint {
	return []recoveryMatrixEndpoint{
		{
			name: "ask for a password-reset link", method: http.MethodPost,
			pattern:   "/v1/password-resets",
			anonymous: http.StatusAccepted, withSession: http.StatusAccepted, withToken: http.StatusForbidden,
			body: `{"email":"kaka@example.com"}`,
		},
		{
			name: "spend a reset link", method: http.MethodPost,
			pattern:   "/v1/password-resets/confirm",
			anonymous: http.StatusNoContent, withSession: http.StatusNoContent, withToken: http.StatusForbidden,
			body: `{"token":"a-token","password":"a completely new password"}`,
		},
		{
			name: "ask for a verification link", method: http.MethodPost,
			pattern:   "/v1/email-verifications",
			anonymous: http.StatusAccepted, withSession: http.StatusAccepted, withToken: http.StatusForbidden,
			body: `{"email":"kaka@example.com"}`,
		},
		{
			name: "spend a verification link", method: http.MethodPost,
			pattern:   "/v1/email-verifications/confirm",
			anonymous: http.StatusNoContent, withSession: http.StatusNoContent, withToken: http.StatusForbidden,
			body: `{"token":"a-token"}`,
		},
		{
			name: "read the verification status", method: http.MethodGet,
			pattern:   "/v1/email-verification",
			anonymous: http.StatusUnauthorized, withSession: http.StatusOK, withToken: http.StatusForbidden,
		},
		{
			name: "start an email change", method: http.MethodPost,
			pattern:   "/v1/email-changes",
			anonymous: http.StatusUnauthorized, withSession: http.StatusCreated, withToken: http.StatusForbidden,
			body: `{"email":"new-address@example.com"}`,
		},
		{
			name: "confirm the current address", method: http.MethodPost,
			pattern:   "/v1/email-changes/current-address",
			anonymous: http.StatusAccepted, withSession: http.StatusAccepted, withToken: http.StatusForbidden,
			body: `{"token":"a-token"}`,
		},
		{
			name: "confirm the new address", method: http.MethodPost,
			pattern:   "/v1/email-changes/new-address",
			anonymous: http.StatusOK, withSession: http.StatusOK, withToken: http.StatusForbidden,
			body: `{"token":"a-token"}`,
		},
	}
}

func TestTheRecoveryAuthorizationMatrix(t *testing.T) {
	for _, endpoint := range recoveryMatrixEndpoints() {
		t.Run(endpoint.name, func(t *testing.T) {
			for _, column := range []struct {
				name string
				credential string
				want       int
			}{
				{name: "anonymous", credential: "", want: endpoint.anonymous},
				{name: "session", credential: "a-session-token", want: endpoint.withSession},
				{name: "scoped token", credential: scopedTokenForTheMatrix, want: endpoint.withToken},
			} {
				t.Run(column.name, func(t *testing.T) {
					f := newFakeRecovery()
					rec := sendWith(t, recoveryServer(t, f, newFakeAuth()),
						endpoint.method, endpoint.pattern, column.credential, "", endpoint.body)

					if rec.Code != column.want {
						t.Fatalf("%s %s as %s = %d, want %d; body: %s",
							endpoint.method, endpoint.pattern, column.name, rec.Code, column.want, rec.Body)
					}

					if column.want < 300 {
						if ct := rec.Header().Get("Content-Type"); strings.HasPrefix(ct, "application/problem+json") {
							t.Errorf("a %d is carrying a problem document: %s", rec.Code, rec.Body)
						}
					} else if got := decodeProblem(t, rec).Code; got != CodeUnauthorized && got != CodeForbidden {
						t.Errorf("code = %q, want %q or %q", got, CodeUnauthorized, CodeForbidden)
					}

					switch {
					case column.want == http.StatusForbidden && f.touched():
						t.Error("the use case ran before the refusal; a scoped token must be turned " +
							"away by the middleware, not by a handler that has already minted a token")
					case column.name == "session" && endpoint.anonymous == http.StatusUnauthorized:
						if !f.touched() {
							t.Errorf("a session on %s did not reach the use case, so the %d is a "+
								"refusal rather than the answer", endpoint.pattern, column.want)
						}
					}
				})
			}
		})
	}
}

const scopedTokenForTheMatrix = "anywaye_" + "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"

func TestTheTwoSessionOnlyRoutesAreTheOnlyTwoThatRequireOne(t *testing.T) {
	var sessionOnly []string
	for _, endpoint := range recoveryMatrixEndpoints() {
		if endpoint.anonymous == http.StatusUnauthorized {
			sessionOnly = append(sessionOnly, endpoint.pattern)
		}
	}
	sort.Strings(sessionOnly)

	want := []string{"/v1/email-changes", "/v1/email-verification"}
	if len(sessionOnly) != len(want) {
		t.Fatalf("%d route(s) require a session (%v), want %d (%v)",
			len(sessionOnly), sessionOnly, len(want), want)
	}
	for i, pattern := range want {
		if sessionOnly[i] != pattern {
			t.Errorf("the session-only routes are %v, want %v", sessionOnly, want)
		}
	}
}

func TestNoRecoveryRouteAcceptsASessionInPlaceOfItsToken(t *testing.T) {
	redemptions := 0
	for _, endpoint := range recoveryMatrixEndpoints() {
		if endpoint.anonymous == http.StatusNotFound || endpoint.anonymous == http.StatusUnauthorized {
			continue
		}
		redemptions++

		f := newFakeRecovery()
		rec := sendWith(t, recoveryServer(t, f, newFakeAuth()),
			endpoint.method, endpoint.pattern, "", "", endpoint.body)
		if rec.Code != endpoint.anonymous {
			t.Errorf("%s %s with no credential at all = %d, want %d; body: %s",
				endpoint.method, endpoint.pattern, rec.Code, endpoint.anonymous, rec.Body)
		}
		if !f.touched() {
			t.Errorf("%s never reached the use case, so it is authenticating by something "+
				"other than the token in its own body", endpoint.pattern)
		}
	}
	if redemptions != 6 {
		t.Errorf("the table has %d routes that answer a no-credential caller with a success; "+
			"this packet has six. A route that changed which credential it requires belongs in "+
			"its own test with its own reason.", redemptions)
	}
}

func TestEveryRecoveryRouteIsInTheMatrix(t *testing.T) {
	mounted := mountedRecoveryRoutes()

	covered := make(map[string]bool, len(recoveryMatrixEndpoints()))
	for _, endpoint := range recoveryMatrixEndpoints() {
		covered[normalizeRoute(endpoint.method, endpoint.pattern)] = true
	}

	for _, route := range mounted {
		if !covered[route] {
			t.Errorf("route %s is mounted on the recovery surface but has no row in its "+
				"authorization matrix", route)
		}
	}
	if len(covered) > len(mounted) {
		t.Errorf("the recovery matrix has %d rows for %d mounted routes; it is asserting on "+
			"routes that do not exist", len(covered), len(mounted))
	}
}

func mountedRecoveryRoutes() []string {
	var found []string

	r := chi.NewRouter()
	opts := options{auth: newFakeAuth(), recovery: newFakeRecovery()}
	opts.registerRoutes(r)

	_ = chi.Walk(r, func(method string, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		clean := normalizeRoute(method, route)
		if isRecoverySurfaceRoute(clean) {
			found = append(found, clean)
		}
		return nil
	})

	sort.Strings(found)
	return found
}

func isRecoverySurfaceRoute(route string) bool {
	path := strings.TrimPrefix(route, strings.SplitN(route, " ", 2)[0]+" ")
	switch {
	case strings.HasPrefix(path, "/v1/password-resets"):
		return true
	case strings.HasPrefix(path, "/v1/email-verifications"):
		return true
	case strings.HasPrefix(path, "/v1/email-changes"):
		return true
	case path == "/v1/email-verification":
		return true
	default:
		return false
	}
}
