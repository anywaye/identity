package httpapi


import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/auth"
)

func TestLoginDisabledIs403Forbidden(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	f.loginErr = &auth.DisabledError{}

	rec := post(t, New(nil, WithAuth(f)), "/v1/session",
		`{"email":"kaka@example.com","password":"correct horse battery"}`)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body: %s", rec.Code, rec.Body)
	}

	p := decodeProblem(t, rec)
	if p.Code != CodeForbidden {
		t.Errorf("code = %q, want %q — core's reserved name for this case, not a new one",
			p.Code, CodeForbidden)
	}
	if p.Status != http.StatusForbidden {
		t.Errorf("body status = %d, want 403", p.Status)
	}
	if p.TraceID == "" {
		t.Error("trace_id is absent; every problem carries it")
	}
}

func TestTheDisabledRefusalNamesTheStateInAFixedSentence(t *testing.T) {
	t.Parallel()

	problem := func() Problem {
		t.Helper()
		f := newFakeAuth()
		f.loginErr = &auth.DisabledError{}
		rec := post(t, New(nil, WithAuth(f)), "/v1/session",
			`{"email":"kaka@example.com","password":"correct horse battery"}`)
		return decodeProblem(t, rec)
	}

	first := problem()
	second := problem()

	if !strings.Contains(first.Detail, "disabled") {
		t.Errorf("detail %q does not say the account is disabled; a refusal that does not name "+
			"the state sends the owner of the account round a password-reset loop that cannot help",
			first.Detail)
	}
	if first.Detail != second.Detail {
		t.Errorf("two disabled refusals carried different detail sentences (%q and %q): a detail "+
			"that varies is a detail that leaks", first.Detail, second.Detail)
	}

	if first.Errors != nil {
		t.Errorf("errors = %v on a 403, want none", first.Errors)
	}
}

func TestTheDisabledRefusalCarriesNoRetryAfter(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	f.loginErr = &auth.DisabledError{}

	rec := post(t, New(nil, WithAuth(f)), "/v1/session",
		`{"email":"kaka@example.com","password":"correct horse battery"}`)

	if got := rec.Header().Get(RetryAfterHeader); got != "" {
		t.Errorf("%s = %q on a disabled login, want it absent: the account is not coming back at "+
			"any time, and a client that believed this header would poll a route whose answer "+
			"cannot change", RetryAfterHeader, got)
	}
}

func TestTheDisabledRefusalSetsNoSessionCookie(t *testing.T) {
	t.Parallel()

	f := newFakeAuth()
	f.loginErr = &auth.DisabledError{}

	rec := post(t, New(nil, WithAuth(f)), "/v1/session",
		`{"email":"kaka@example.com","password":"correct horse battery"}`)

	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookieName {
			t.Errorf("a disabled login set a %s cookie", SessionCookieName)
		}
	}
	if cookies := rec.Result().Cookies(); len(cookies) != 0 {
		t.Errorf("a disabled login set %d cookies, want none: %v", len(cookies), cookies)
	}
}

func TestTheTwoAccountStatesAnswerTwoDifferentStatuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "locked — temporary, so it carries a retry",
			err:        &auth.LockedError{RetryAfter: 7 * time.Minute},
			wantStatus: http.StatusLocked,
			wantCode:   CodeAccountLocked,
		},
		{
			name:       "disabled — indefinite, so it does not",
			err:        &auth.DisabledError{},
			wantStatus: http.StatusForbidden,
			wantCode:   CodeForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFakeAuth()
			f.loginErr = tt.err

			rec := post(t, New(nil, WithAuth(f)), "/v1/session",
				`{"email":"kaka@example.com","password":"correct horse battery"}`)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body)
			}
			if p := decodeProblem(t, rec); p.Code != tt.wantCode {
				t.Errorf("code = %q, want %q", p.Code, tt.wantCode)
			}
		})
	}
}

func TestAWrongPasswordIsStillGenericWhateverTheAccountsState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
	}{
		{name: "wrong credentials on an active account", err: auth.ErrInvalidCredentials},
		{name: "wrong credentials standing in for a disabled one", err: auth.ErrInvalidCredentials},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFakeAuth()
			f.loginErr = tt.err

			rec := post(t, New(nil, WithAuth(f)), "/v1/session",
				`{"email":"kaka@example.com","password":"not the right password"}`)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401; body: %s", rec.Code, rec.Body)
			}
			if p := decodeProblem(t, rec); p.Code != CodeUnauthorized {
				t.Errorf("code = %q, want %q", p.Code, CodeUnauthorized)
			}
		})
	}
}
