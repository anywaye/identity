package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/anywaye/identity/internal/mfa"
	"github.com/anywaye/identity/internal/platform/id"
)


type mfaMatrixEndpoint struct {
	name   string
	method string
	pattern string
	anonymous int
	authenticated int
	body func(t *testing.T, s *mfaServer) string
	path func(t *testing.T, s *mfaServer) string
}

func mfaMatrixEndpoints() []mfaMatrixEndpoint {
	return []mfaMatrixEndpoint{
		{
			name: "read the second-factor status", method: http.MethodGet,
			pattern: "/v1/mfa", anonymous: http.StatusUnauthorized, authenticated: http.StatusOK,
		},
		{
			name: "start an enrollment", method: http.MethodPost,
			pattern: "/v1/mfa/enrollments", anonymous: http.StatusUnauthorized, authenticated: http.StatusCreated,
			body: func(t *testing.T, s *mfaServer) string {
				return `{"code":"` + s.codeFor(t) + `"}`
			},
		},
		{
			name: "confirm an enrollment", method: http.MethodPost,
			pattern:   "/v1/mfa/enrollments/{enrollmentID}/confirm",
			anonymous: http.StatusUnauthorized, authenticated: http.StatusOK,
			path: func(t *testing.T, s *mfaServer) string {
				return "/v1/mfa/enrollments/" + s.pendingEnrollmentID(t) + "/confirm"
			},
			body: func(t *testing.T, s *mfaServer) string {
				return `{"code":"` + s.pendingEnrollmentCode(t) + `"}`
			},
		},
		{
			name: "regenerate the recovery codes", method: http.MethodPost,
			pattern: "/v1/mfa/recovery-codes", anonymous: http.StatusUnauthorized, authenticated: http.StatusOK,
			body: func(t *testing.T, s *mfaServer) string {
				return `{"code":"` + s.codeFor(t) + `"}`
			},
		},
		{
			name: "disable the second factor", method: http.MethodDelete,
			pattern: "/v1/mfa", anonymous: http.StatusUnauthorized, authenticated: http.StatusNoContent,
			body: func(t *testing.T, s *mfaServer) string {
				return `{"code":"` + s.codeFor(t) + `"}`
			},
		},
		{
			name: "complete a second factor", method: http.MethodPost,
			pattern: "/v1/session/mfa", anonymous: http.StatusUnauthorized, authenticated: http.StatusUnauthorized,
			body: func(*testing.T, *mfaServer) string { return `{"code":"123456"}` },
		},
	}
}

func TestTheMFAAuthorizationMatrix(t *testing.T) {
	for _, endpoint := range mfaMatrixEndpoints() {
		t.Run(endpoint.name, func(t *testing.T) {
			t.Run("anonymous", func(t *testing.T) {
				s := newMFAServer(t)
				email, _ := s.signUp(t)
				s.enrollAndConfirmFor(t, email, s.token)

				rec := s.send(t, endpoint, "", enrolledUser{})
				if rec.Code != endpoint.anonymous {
					t.Fatalf("%s %s as anonymous = %d, want %d; body: %s",
						endpoint.method, endpoint.pattern, rec.Code, endpoint.anonymous, rec.Body)
				}
				if got := decodeProblem(t, rec).Code; got != CodeUnauthorized {
					t.Errorf("code = %q, want %q", got, CodeUnauthorized)
				}
			})

			t.Run("authenticated", func(t *testing.T) {
				s := newMFAServer(t)
				email, _ := s.signUp(t)
				user := s.enrollAndConfirmFor(t, email, s.token)

				s.clock.Advance(mfa.Period + time.Second)

				rec := s.send(t, endpoint, s.token, user)
				if rec.Code != endpoint.authenticated {
					t.Fatalf("%s %s as an authenticated caller = %d, want %d; body: %s",
						endpoint.method, endpoint.pattern, rec.Code, endpoint.authenticated, rec.Body)
				}
			})
		})
	}
}

func TestEveryMFARouteIsInTheMatrix(t *testing.T) {
	mounted := mountedMFARoutes()

	covered := make(map[string]bool, len(mfaMatrixEndpoints()))
	for _, e := range mfaMatrixEndpoints() {
		covered[normalizeRoute(e.method, e.pattern)] = true
	}

	for _, route := range mounted {
		if !covered[route] {
			t.Errorf("route %s is mounted but has no row in the MFA authorization matrix", route)
		}
	}
	if len(covered) > len(mounted) {
		t.Errorf("the MFA matrix has %d rows for %d mounted routes; it is asserting on routes that do not exist",
			len(covered), len(mounted))
	}
}

func mountedMFARoutes() []string {
	var found []string

	r := chi.NewRouter()
	opts := options{auth: newFakeAuth(), mfa: newFakeMFAManage()}
	opts.registerRoutes(r)

	_ = chi.Walk(r, func(method string, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		clean := normalizeRoute(method, route)
		if isMFASurfaceRoute(clean) {
			found = append(found, clean)
		}
		return nil
	})

	sort.Strings(found)
	return found
}

func isMFASurfaceRoute(route string) bool {
	path := strings.TrimPrefix(route, strings.SplitN(route, " ", 2)[0]+" ")
	return strings.HasPrefix(path, "/v1/mfa") || path == "/v1/session/mfa"
}


func (s *mfaServer) send(t *testing.T, endpoint mfaMatrixEndpoint, token string, _ enrolledUser) *httptest.ResponseRecorder {
	t.Helper()

	path := endpoint.pattern
	if endpoint.path != nil {
		path = endpoint.path(t, s)
	}
	body := ""
	if endpoint.body != nil {
		body = endpoint.body(t, s)
	}
	return sendWith(t, s.handler, endpoint.method, path, token, "", body)
}

func (s *mfaServer) codeFor(t *testing.T) string {
	t.Helper()
	return s.user.code(t, s.clock.Now())
}

func (s *mfaServer) pendingEnrollmentID(t *testing.T) string {
	t.Helper()
	s.ensurePendingEnrollment(t)
	return s.pendingID
}

func (s *mfaServer) pendingEnrollmentCode(t *testing.T) string {
	t.Helper()
	s.ensurePendingEnrollment(t)
	return s.pendingCode
}

func (s *mfaServer) ensurePendingEnrollment(t *testing.T) {
	t.Helper()
	if s.pendingID != "" {
		return
	}

	s.clock.Advance(mfa.Period + time.Second)

	rec := s.post(t, "/v1/mfa/enrollments", s.token, `{"code":"`+s.codeFor(t)+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("creating the fixture's pending enrollment = %d; body: %s", rec.Code, rec.Body)
	}

	var body struct {
		EnrollmentID string `json:"enrollment_id"`
		Secret       string `json:"secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the enrollment body is not JSON: %v", err)
	}
	code, err := mfa.Code(body.Secret, s.clock.Now())
	if err != nil {
		t.Fatalf("mfa.Code: %v", err)
	}
	s.pendingID, s.pendingCode = body.EnrollmentID, code
}

type fakeMFAManage struct{}

func (fakeMFAManage) StatusFor(context.Context, id.UUID) (mfa.Status, error) {
	return mfa.Status{}, nil
}

func (fakeMFAManage) StartEnrollment(context.Context, mfa.StartEnrollmentInput) (mfa.StartedEnrollment, error) {
	return mfa.StartedEnrollment{}, nil
}

func (fakeMFAManage) Confirm(context.Context, mfa.ConfirmInput) (mfa.ConfirmedEnrollment, error) {
	return mfa.ConfirmedEnrollment{}, nil
}

func (fakeMFAManage) RegenerateRecoveryCodes(context.Context, mfa.RegenerateRecoveryCodesInput) (mfa.RegeneratedRecoveryCodes, error) {
	return mfa.RegeneratedRecoveryCodes{}, nil
}

func (fakeMFAManage) Disable(context.Context, mfa.DisableInput) error { return nil }

func newFakeMFAManage() MFAManage { return fakeMFAManage{} }
