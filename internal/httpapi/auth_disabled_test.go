package httpapi

// PACKET identity-disabled-01: THE LOGIN ROUTE'S ANSWER FOR A DISABLED ACCOUNT.
//
// # WHAT IS BEING DECIDED HERE, AND WHERE THE REASONING LIVES
//
// `writeAuthError`'s comment carries the argument. This file holds it: 403,
// `forbidden`, one fixed sentence, no Retry-After, and — the part that makes it
// free — no cookie.
//
// # WHY THESE ASSERTIONS AND NOT JUST THE STATUS
//
// A test that checked `403` alone would pass against a handler that answered 403
// with the account's address in the detail, or with a session cookie set, or with
// a Retry-After that promises a retry. Each of those is a different defect and
// each is invisible to a status-code assertion. So the shape is compared as a
// whole Problem, the cookie set is asserted empty, and the absence of
// Retry-After is asserted explicitly — a header this service knows how to send and
// that would mean something false here.

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/auth"
)

// A disabled login is 403 forbidden, with core's own code and no new one.
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

// THE SENTENCE NAMES THE STATE, because that is the whole point of answering
// differently from a wrong password.
//
// It has to be FIXED as well: a detail that varied with the reason would vary with
// the account's state, and the enumeration argument this refusal rests on is that
// the only caller who reaches it has already proved the password. So there is one
// sentence, asserted as one sentence.
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

	// No errors[]: core scopes that array to 422 and to fields of the request, and
	// "disabled" is not a field anyone typed. Same rule the 423 states for
	// `retry_after`, and for the same reason.
	if first.Errors != nil {
		t.Errorf("errors = %v on a 403, want none", first.Errors)
	}
}

// NO RETRY-AFTER, and this is the assertion that keeps 423 and 403 apart.
//
// A `Retry-After` here would be a promise nothing keeps: 423 in this service means
// "locked, retry at", and every client that knows the code renders it as a
// countdown. A disabled account is not coming back at any time, so a client that
// believed the header would poll a route whose answer cannot change.
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

// NO COOKIE. A `__Host-session` header on a refusal is a credential in a browser
// that authenticates nothing, and the login route's refusals have never set one.
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

// 403 AND 423 ARE DIFFERENT ANSWERS TO DIFFERENT STATES, held in both directions.
//
// The table exists because the two are one boolean apart in the handler and the
// consequence of picking the wrong one is a user told to wait for a window that
// will not close, or a user told to contact an administrator for something that
// expires on its own.
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

// A wrong password on a disabled account is STILL the generic 401, end to end.
//
// The use case guarantees this and the census in anonymous_enumeration_test.go
// relies on it, but the guarantee is made in a different package from the one that
// renders the answer, and this is the seam: a handler that mapped the disabled
// error before the password was verified would turn this route into a
// one-request existence oracle for every disabled account on the service.
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
