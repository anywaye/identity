package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/apikeys"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/recovery"
	"github.com/anywaye/identity/internal/users"
)


type fakeRecovery struct {
	mu sync.Mutex

	resetErr     error
	redeemErr    error
	verifyErr    error
	statusErr    error
	statusOut    recovery.Verification
	changeErr    error
	changeOut    recovery.EmailChange
	confirmCurEr error
	confirmNewEr error
	confirmNewOu users.User

	resets    []string
	verifies  []string
	redeems   []recovery.RedeemPasswordResetInput
	confirmed []recovery.ConfirmEmailChangeNewInput
	statuses  []id.UUID
	mints []recovery.MintSessionLinkInput
	mintOut recovery.SessionLink
	mintErr error
	linkRedeems   []recovery.RedeemSessionLinkInput
	linkRedeemErr error
}

func newFakeRecovery() *fakeRecovery {
	return &fakeRecovery{
		statusOut: recovery.Verification{Email: "kaka@example.com"},
		changeOut: recovery.EmailChange{
			CurrentEmail: "kaka@example.com",
			NewEmail:     "new@example.com",
			ExpiresAt:    time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC),
		},
		confirmNewOu: users.User{
			ID:    id.UUID{0xab},
			Email: "new@example.com",
		},
	}
}

func (f *fakeRecovery) RequestPasswordReset(_ context.Context, email string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resets = append(f.resets, email)
	return f.resetErr
}

func (f *fakeRecovery) RedeemPasswordReset(_ context.Context, in recovery.RedeemPasswordResetInput) (recovery.RedeemPasswordResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.redeems = append(f.redeems, in)
	if f.redeemErr != nil {
		return recovery.RedeemPasswordResult{}, f.redeemErr
	}
	return recovery.RedeemPasswordResult{Email: "kaka@example.com"}, nil
}

func (f *fakeRecovery) RequestVerification(_ context.Context, email string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verifies = append(f.verifies, email)
	return f.verifyErr
}

func (f *fakeRecovery) RedeemVerification(_ context.Context, in recovery.RedeemVerificationInput) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verifies = append(f.verifies, in.Token)
	return f.verifyErr
}

func (f *fakeRecovery) VerificationStatus(_ context.Context, userID id.UUID) (recovery.Verification, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statuses = append(f.statuses, userID)
	return f.statusOut, f.statusErr
}

func (f *fakeRecovery) RequestEmailChange(_ context.Context, in recovery.RequestEmailChangeInput) (recovery.EmailChange, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.confirmed = append(f.confirmed, recovery.ConfirmEmailChangeNewInput{})
	if f.changeErr != nil {
		return recovery.EmailChange{}, f.changeErr
	}
	return f.changeOut, nil
}

func (f *fakeRecovery) ConfirmEmailChangeCurrent(_ context.Context, in recovery.ConfirmEmailChangeCurrentInput) (recovery.EmailChange, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verifies = append(f.verifies, in.Token)
	if f.confirmCurEr != nil {
		return recovery.EmailChange{}, f.confirmCurEr
	}
	return f.changeOut, nil
}

func (f *fakeRecovery) ConfirmEmailChangeNew(_ context.Context, in recovery.ConfirmEmailChangeNewInput) (users.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.confirmed = append(f.confirmed, in)
	if f.confirmNewEr != nil {
		return users.User{}, f.confirmNewEr
	}
	return f.confirmNewOu, nil
}

func (f *fakeRecovery) MintSessionLink(_ context.Context, in recovery.MintSessionLinkInput) (recovery.SessionLink, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mints = append(f.mints, in)
	if f.mintErr != nil {
		return recovery.SessionLink{}, f.mintErr
	}
	if f.mintOut.Token == "" {
		return recovery.SessionLink{
			Token:     "minted-by-the-use-case",
			ExpiresAt: time.Date(2026, 10, 1, 12, 10, 0, 0, time.UTC),
		}, nil
	}
	return f.mintOut, nil
}

func (f *fakeRecovery) RedeemSessionLink(_ context.Context, in recovery.RedeemSessionLinkInput) (recovery.RedeemedSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.linkRedeems = append(f.linkRedeems, in)
	if f.linkRedeemErr != nil {
		return recovery.RedeemedSession{}, f.linkRedeemErr
	}
	return recovery.RedeemedSession{
		Token:     "redeemed-by-the-use-case",
		ExpiresAt: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC),
	}, nil
}

func (f *fakeRecovery) touched() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.resets)+len(f.verifies)+len(f.redeems)+len(f.confirmed)+
		len(f.statuses)+len(f.mints)+len(f.linkRedeems) > 0
}

func recoveryServer(t *testing.T, f *fakeRecovery, auth Auth) http.Handler {
	t.Helper()
	return New(nil, WithAuth(auth), WithRecovery(f), WithLogger(slogLogger(&recordingHandler{})))
}


func TestTheRequestRoutesAnswer202WithAConstantBody(t *testing.T) {
	t.Parallel()

	for _, route := range []struct{ path, field string }{
		{path: "/v1/password-resets", field: "email"},
		{path: "/v1/email-verifications", field: "email"},
	} {
		t.Run(route.path, func(t *testing.T) {
			t.Parallel()

			rec := post(t, recoveryServer(t, newFakeRecovery(), newFakeAuth()), route.path,
				`{"`+route.field+`":"kaka@example.com"}`)

			if rec.Code != http.StatusAccepted {
				t.Fatalf("status = %d, want 202; body: %s", rec.Code, rec.Body)
			}
			if got, want := rec.Header().Get("Content-Type"), "application/json; charset=utf-8"; got != want {
				t.Errorf("Content-Type = %q, want %q", got, want)
			}

			var raw map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
				t.Fatalf("the body is not JSON: %v", err)
			}
			if len(raw) != 1 {
				t.Errorf("the body has %d fields (%v), want exactly `status`. This type is a constant "+
					"so that a client cannot tell a registered address from an unregistered one", len(raw), raw)
			}
			if raw["status"] != "accepted" {
				t.Errorf("status = %v, want %q", raw["status"], "accepted")
			}
			for _, forbidden := range []string{"email", "sent", "expires_at", "token", "verified"} {
				if _, present := raw[forbidden]; present {
					t.Errorf("the body carries %q, which differs between a registered address and "+
						"an unregistered one or says something a caller cannot act on", forbidden)
				}
			}
		})
	}
}

func TestTheRequestRoutesDoNotEchoTheAddressInARefusal(t *testing.T) {
	t.Parallel()

	f := newFakeRecovery()
	f.resetErr = &users.FieldError{Field: "email", Code: users.CodeInvalidFormat}
	rec := post(t, recoveryServer(t, f, newFakeAuth()), "/v1/password-resets",
		`{"email":"not-an-address"}`)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body: %s", rec.Code, rec.Body)
	}
	p := decodeProblem(t, rec)
	if p.Code != CodeValidationFailed {
		t.Errorf("code = %q, want %q", p.Code, CodeValidationFailed)
	}
	if len(p.Errors) != 1 || p.Errors[0].Field != "email" {
		t.Errorf("errors = %+v, want one entry naming email", p.Errors)
	}
}


func TestEveryRecoveryRefusalMapsToItsOwnStatus(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
		route string
		body  string
		token string
	}{
		{
			name: "a token that is not there", err: recovery.ErrTokenNotFound,
			wantStatus: http.StatusNotFound, wantCode: CodeNotFound,
			route: "/v1/password-resets/confirm", body: `{"token":"t","password":"correct horse battery"}`,
		},
		{
			name: "a deployment with no mailer", err: recovery.ErrNoMailer,
			wantStatus: http.StatusServiceUnavailable, wantCode: CodeServiceUnavailable,
			route: "/v1/password-resets", body: `{"email":"kaka@example.com"}`,
		},
		{
			name: "an address somebody else has", err: recovery.ErrEmailTaken,
			wantStatus: http.StatusConflict, wantCode: CodeConflict,
			route: "/v1/email-changes", body: `{"email":"new@example.com"}`, token: "a-session",
		},
		{
			name: "a change that describes no move", err: recovery.ErrSameAddress,
			wantStatus: http.StatusUnprocessableEntity, wantCode: CodeValidationFailed,
			route: "/v1/email-changes", body: `{"email":"kaka@example.com"}`, token: "a-session",
		},
		{
			name: "a field the use case refuses", err: &users.FieldError{Field: "password", Code: users.CodeTooShort},
			wantStatus: http.StatusUnprocessableEntity, wantCode: CodeValidationFailed,
			route: "/v1/password-resets/confirm", body: `{"token":"t","password":"short"}`,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFakeRecovery()
			switch tt.route {
			case "/v1/password-resets":
				f.resetErr = tt.err
			case "/v1/password-resets/confirm":
				f.redeemErr = tt.err
			case "/v1/email-verifications":
				f.verifyErr = tt.err
			case "/v1/email-changes":
				f.changeErr = tt.err
			case "/v1/email-changes/current-address":
				f.confirmCurEr = tt.err
			case "/v1/email-changes/new-address":
				f.confirmNewEr = tt.err
			}

			rec := sendWith(t, recoveryServer(t, f, newFakeAuth()), http.MethodPost,
				tt.route, tt.token, "", tt.body)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body)
			}
			p := decodeProblem(t, rec)
			if p.Code != tt.wantCode {
				t.Errorf("code = %q, want %q", p.Code, tt.wantCode)
			}
			if p.Detail == "" {
				t.Error("detail is empty; every refusal says something a caller can act on")
			}
			if p.TraceID == "" {
				t.Error("trace_id is empty")
			}
		})
	}
}

func TestTheTokenRefusalsAreOneAnswer(t *testing.T) {
	t.Parallel()

	routes := []struct {
		path  string
		body  string
		token string
		setup func(*fakeRecovery)
	}{
		{
			path:  "/v1/password-resets/confirm",
			body:  `{"token":"a-token","password":"correct horse battery"}`,
			setup: func(f *fakeRecovery) { f.redeemErr = recovery.ErrTokenNotFound },
		},
		{
			path:  "/v1/email-verifications/confirm",
			body:  `{"token":"a-token"}`,
			setup: func(f *fakeRecovery) { f.verifyErr = recovery.ErrTokenNotFound },
		},
		{
			path:  "/v1/email-changes/current-address",
			body:  `{"token":"a-token"}`,
			setup: func(f *fakeRecovery) { f.confirmCurEr = recovery.ErrTokenNotFound },
		},
		{
			path:  "/v1/email-changes/new-address",
			body:  `{"token":"a-token"}`,
			setup: func(f *fakeRecovery) { f.confirmNewEr = recovery.ErrTokenNotFound },
		},
	}

	var first *httptest.ResponseRecorder
	for _, route := range routes {
		f := newFakeRecovery()
		route.setup(f)
		rec := sendWith(t, recoveryServer(t, f, newFakeAuth()), http.MethodPost,
			route.path, "", "", route.body)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s = %d, want 404; body: %s", route.path, rec.Code, rec.Body)
		}
		if first == nil {
			first = rec
			continue
		}
		a, b := decodeProblem(t, first), decodeProblem(t, rec)
		if a.Code != b.Code || a.Title != b.Title || a.Detail != b.Detail || a.Status != b.Status {
			t.Errorf("%s answers %q/%q, and the first route answered %q/%q. Every redemption route "+
				"has to refuse a bad token identically, or a caller can tell which routes take tokens "+
				"worth guessing for",
				route.path, b.Code, b.Detail, a.Code, a.Detail)
		}
	}
}


func TestTheRecoveryRoutesAreAbsentWithoutTheService(t *testing.T) {
	t.Parallel()

	for _, route := range []struct{ method, path string }{
		{http.MethodPost, "/v1/password-resets"},
		{http.MethodPost, "/v1/password-resets/confirm"},
		{http.MethodPost, "/v1/email-verifications"},
		{http.MethodPost, "/v1/email-verifications/confirm"},
		{http.MethodGet, "/v1/email-verification"},
		{http.MethodPost, "/v1/email-changes"},
		{http.MethodPost, "/v1/email-changes/current-address"},
		{http.MethodPost, "/v1/email-changes/new-address"},
	} {
		rec := send(t, New(nil, WithAuth(newFakeAuth())), route.method, route.path, `{}`)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s with no recovery service = %d, want 404",
				route.method, route.path, rec.Code)
		}
	}
}

func TestAScopedAPIKeyIsRefusedEverywhereOnThisSurface(t *testing.T) {
	t.Parallel()

	for _, route := range []struct{ method, path, body string }{
		{http.MethodPost, "/v1/password-resets", `{"email":"kaka@example.com"}`},
		{http.MethodPost, "/v1/password-resets/confirm", `{"token":"t","password":"correct horse battery"}`},
		{http.MethodPost, "/v1/email-verifications", `{"email":"kaka@example.com"}`},
		{http.MethodPost, "/v1/email-verifications/confirm", `{"token":"t"}`},
		{http.MethodGet, "/v1/email-verification", ""},
		{http.MethodPost, "/v1/email-changes", `{"email":"new@example.com"}`},
		{http.MethodPost, "/v1/email-changes/current-address", `{"token":"t"}`},
		{http.MethodPost, "/v1/email-changes/new-address", `{"token":"t"}`},
	} {
		rec := sendWith(t, recoveryServer(t, newFakeRecovery(), newFakeAuth()),
			route.method, route.path, apikeys.Prefix+"a-token", "", route.body)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s with a scoped api key = %d, want 403; body: %s",
				route.method, route.path, rec.Code, rec.Body)
		}
		if got := decodeProblem(t, rec).Code; got != CodeForbidden {
			t.Errorf("%s %s: code = %q, want %q", route.method, route.path, got, CodeForbidden)
		}
	}
}

func TestTheSessionRoutesRefuseAnAnonymousCaller(t *testing.T) {
	t.Parallel()

	for _, route := range []struct{ method, path, body string }{
		{http.MethodGet, "/v1/email-verification", ""},
		{http.MethodPost, "/v1/email-changes", `{"email":"new@example.com"}`},
	} {
		rec := sendWith(t, recoveryServer(t, newFakeRecovery(), newFakeAuth()),
			route.method, route.path, "", "", route.body)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s with no credential = %d, want 401; body: %s",
				route.method, route.path, rec.Code, rec.Body)
		}
		if got := decodeProblem(t, rec).Code; got != CodeUnauthorized {
			t.Errorf("%s %s: code = %q, want %q", route.method, route.path, got, CodeUnauthorized)
		}
	}
}


func TestTheRedeemRoutesClearTheSessionCookie(t *testing.T) {
	t.Parallel()

	for _, route := range []struct{ path, body string }{
		{path: "/v1/password-resets/confirm", body: `{"token":"t","password":"correct horse battery"}`},
		{path: "/v1/email-changes/new-address", body: `{"token":"t"}`},
	} {
		f := newFakeRecovery()
		rec := sendWith(t, recoveryServer(t, f, newFakeAuth()), http.MethodPost,
			route.path, "a-session-token", "", route.body)

		cookie := cookieNamed(rec, SessionCookieName)
		if cookie == nil || cookie.MaxAge >= 0 {
			t.Errorf("%s did not clear the session cookie: %+v", route.path, cookie)
		}
	}
}

func TestTheEmailChangeResponseNamesBothAddressesAndSaysTheNewOneIsUnverified(t *testing.T) {
	t.Parallel()

	rec := sendWith(t, recoveryServer(t, newFakeRecovery(), newFakeAuth()),
		http.MethodPost, "/v1/email-changes", "a-session-token", "", `{"email":"new@example.com"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", rec.Code, rec.Body)
	}

	var body emailChangeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	if body.CurrentEmail != "kaka@example.com" || body.NewEmail != "new@example.com" {
		t.Errorf("the body names %q -> %q, want the old and the new address",
			body.CurrentEmail, body.NewEmail)
	}
	if body.ExpiresAt.IsZero() {
		t.Error("the body carries no deadline, so a client cannot say 'finish this within a day'")
	}
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("the body is not a JSON object: %v", err)
	}
	for _, forbidden := range []string{"token", "token_digest", "id", "user_id"} {
		if _, present := raw[forbidden]; present {
			t.Errorf("the 201 carries %q. The change is addressed by its mailed tokens, and a row id "+
				"here would be an identifier a client holds for no reason", forbidden)
		}
	}

	done := sendWith(t, recoveryServer(t, newFakeRecovery(), newFakeAuth()),
		http.MethodPost, "/v1/email-changes/new-address", "", "", `{"token":"t"}`)
	if done.Code != http.StatusOK {
		t.Fatalf("the completion = %d, want 200; body: %s", done.Code, done.Body)
	}
	var completed emailChangeResponse
	if err := json.Unmarshal(done.Body.Bytes(), &completed); err != nil {
		t.Fatalf("the completion body is not JSON: %v", err)
	}
	if completed.EmailVerified == nil {
		t.Fatal("the completion carries no email_verified. A client that renders 'your address is " +
			"verified' from a change would be wrong: the address was never proved")
	}
	if *completed.EmailVerified {
		t.Error("email_verified = true after a change; SetEmail clears the column and this disagrees")
	}
}

func TestTheVerificationStatusIsA200WithABoolean(t *testing.T) {
	t.Parallel()

	rec := sendWith(t, recoveryServer(t, newFakeRecovery(), newFakeAuth()),
		http.MethodGet, "/v1/email-verification", "a-session-token", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	var body verificationStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	if body.Email != "kaka@example.com" || body.EmailVerified {
		t.Errorf("body = %+v, want an unverified kaka@example.com", body)
	}
	if body.EmailVerifiedAt != nil {
		t.Errorf("email_verified_at = %v on an unverified account", body.EmailVerifiedAt)
	}

	f := newFakeRecovery()
	at := time.Date(2026, 10, 1, 11, 0, 0, 0, time.UTC)
	f.statusOut = recovery.Verification{Email: "kaka@example.com", Verified: true, VerifiedAt: &at}
	verified := sendWith(t, recoveryServer(t, f, newFakeAuth()),
		http.MethodGet, "/v1/email-verification", "a-session-token", "", "")
	var verifiedBody verificationStatusResponse
	if err := json.Unmarshal(verified.Body.Bytes(), &verifiedBody); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	if !verifiedBody.EmailVerified || verifiedBody.EmailVerifiedAt == nil ||
		!verifiedBody.EmailVerifiedAt.Equal(at) {
		t.Errorf("body = %+v, want verified at %s", verifiedBody, at)
	}
}

func TestTheStatusRouteNeverRendersADigest(t *testing.T) {
	t.Parallel()

	rec := sendWith(t, recoveryServer(t, newFakeRecovery(), newFakeAuth()),
		http.MethodGet, "/v1/email-verification", "a-session-token", "", "")

	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	for _, forbidden := range []string{
		"password", "password_digest", "digest", "failed_login_attempts",
		"locked_until", "created_at", "updated_at", "id",
	} {
		if _, present := raw[forbidden]; present {
			t.Errorf("the status carries %q", forbidden)
		}
	}
}

func TestARecoveryRouteWithTheWrongMethodIs405(t *testing.T) {
	t.Parallel()

	rec := sendWith(t, recoveryServer(t, newFakeRecovery(), newFakeAuth()),
		http.MethodDelete, "/v1/password-resets", "", "", `{}`)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405; body: %s", rec.Code, rec.Body)
	}
	if got := decodeProblem(t, rec).Code; got != CodeMethodNotAllowed {
		t.Errorf("code = %q, want %q", got, CodeMethodNotAllowed)
	}
}

func TestAnInternalFailureIsRefusedAndTheCauseStaysInTheLog(t *testing.T) {
	t.Parallel()

	logs := &recordingHandler{}
	f := newFakeRecovery()
	f.redeemErr = errors.New("dial tcp 10.0.0.5:5432: connection refused (password authentication failed for user identity)")
	handler := New(nil, WithAuth(newFakeAuth()), WithRecovery(f), WithLogger(slogLogger(logs)))

	rec := sendWith(t, handler, http.MethodPost, "/v1/password-resets/confirm", "", "",
		`{"token":"t","password":"correct horse battery"}`)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body)
	}
	p := decodeProblem(t, rec)
	if p.Code != CodeInternal {
		t.Errorf("code = %q, want %q", p.Code, CodeInternal)
	}
	for _, leak := range []string{"10.0.0.5", "5432", "dial tcp", "refused", "user identity"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("the body leaks %q: %s", leak, rec.Body)
		}
	}
	for _, leak := range []string{"10.0.0.5", "dial tcp", "refused", "password", "user identity"} {
		if strings.Contains(p.Detail, leak) {
			t.Errorf("the detail leaks %q: %s", leak, p.Detail)
		}
	}
	if entry := logs.find("request failed"); entry == "" {
		t.Error("nothing was logged, so an operator has nothing")
	} else if !strings.Contains(entry, p.TraceID) {
		t.Errorf("the log entry does not carry the trace id %q", p.TraceID)
	}
}

func TestTheTokenReachesTheUseCaseAndIsNeverEchoedBack(t *testing.T) {
	t.Parallel()

	f := newFakeRecovery()
	handler := recoveryServer(t, f, newFakeAuth())

	rec := sendWith(t, handler, http.MethodPost, "/v1/password-resets/confirm", "", "",
		`{"token":"the-token","password":"a brand new password"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", rec.Code, rec.Body)
	}
	if body := rec.Body.String(); body != "" {
		t.Errorf("a 204 has a body: %q", body)
	}
	if len(f.redeems) != 1 {
		t.Fatalf("the use case was called %d times, want 1", len(f.redeems))
	}
	if f.redeems[0].Token != "the-token" || f.redeems[0].Password != "a brand new password" {
		t.Errorf("the use case was handed %+v", f.redeems[0])
	}
	if strings.Contains(rec.Body.String(), "the-token") {
		t.Error("the response echoed the token")
	}
}

func TestAnEmptyTokenIsRefusedBeforeAnythingIsWritten(t *testing.T) {
	t.Parallel()

	f := newFakeRecovery()
	f.redeemErr = &users.FieldError{Field: "token", Code: users.CodeRequired}

	rec := sendWith(t, recoveryServer(t, f, newFakeAuth()), http.MethodPost,
		"/v1/password-resets/confirm", "", "", `{"token":"","password":"a brand new password"}`)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body: %s", rec.Code, rec.Body)
	}
	if len(f.redeems) != 1 || f.redeems[0].Token != "" {
		t.Errorf("the use case was handed %+v; the router must pass the value through rather than "+
			"inventing one", f.redeems)
	}
}

func TestAnUnparseableBodyIsRefusedBeforeTheUseCase(t *testing.T) {
	t.Parallel()

	f := newFakeRecovery()
	handler := recoveryServer(t, f, newFakeAuth())

	for _, body := range []string{`{"email":`, `not json`, `null`, `["kaka@example.com"]`} {
		rec := post(t, handler, "/v1/password-resets", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("a body of %q = %d, want 400; body: %s", body, rec.Code, rec.Body)
		}
	}
	if len(f.resets) != 0 {
		t.Errorf("the use case was called %d times for four unparseable bodies", len(f.resets))
	}
}
