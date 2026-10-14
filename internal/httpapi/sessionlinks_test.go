package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/apikeys"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/recovery"
	"github.com/cafaye/identity/internal/users"
)

// THE MINT, AT THE ROUTER.
//
// Every test here drives the REAL router through `requireSessionLinkMint` against a
// programmable `Recovery` double, so what is under test is the credential gate and
// the error mapping — the two things this commit adds — and not the store, which
// internal/recovery's own tests hold against a real database.
//
// The 403s are asserted TWICE each: once for the status and once for the use case
// not being reached. A mint that refuses after inserting has produced the right
// status code and a live credential.

// sessionLinkFixture is the mint's router: one recovery double, one router, and the
// credentials the callers below present.
type sessionLinkFixture struct {
	handler http.Handler
	// recovery is the double, so a test can read what reached the use case and what
	// it was told to answer.
	recovery *fakeRecovery
	// subject is the user id the body names on the happy path, and keyHolder is the
	// user id behind the token. They are different ids on purpose: the mint's whole
	// contract is that the subject comes from the body and not from the caller, and a
	// fixture where the two coincided could not tell a handler that got it right from
	// one that got it wrong by accident.
	subject   id.UUID
	keyHolder id.UUID
	// apiKey is a token-shaped value that resolves, session is a session that
	// resolves, and strangerToken is token-shaped and resolves to nothing.
	apiKey        string
	strangerToken string
	session       string
}

// newSessionLinkFixture builds a router whose api key holds the scopes named, and
// defaults to the scope under test when none are.
func newSessionLinkFixture(t *testing.T, scopes ...string) *sessionLinkFixture {
	t.Helper()

	if len(scopes) == 0 {
		scopes = []string{apikeys.ScopeSessionsWrite}
	}
	return newSessionLinkFixtureWithGrant(t, scopes)
}

// newSessionLinkFixtureWithGrant takes the grant verbatim, including an empty one.
//
// IT IS SEPARATE FROM `newSessionLinkFixture` FOR ONE REASON, and the reason is the
// empty grant: a variadic cannot say "no scopes" without also saying "use the
// default", and "a token holding nothing" is a case the scope check has to be tested
// against — `Allows("")` is false for every granted set, and a test that never asks
// with an empty slice has not checked that.
func newSessionLinkFixtureWithGrant(t *testing.T, scopes []string) *sessionLinkFixture {
	t.Helper()
	return newSessionLinkFixtureResolving(t, scopes, true)
}

// newSessionLinkFixtureResolving builds a fixture whose api-key store either
// resolves every presented token or resolves none.
//
// THE UNRESOLVING VARIANT EXISTS FOR ONE ROW OF ONE TABLE: a token-shaped value that
// belongs to no key. `fakeAPIKeyCaller` resolves whatever it is handed, which is right
// for every test that wants a credential and wrong for the one that wants the absence
// of one — and a fixture that cannot express "this credential does not exist" is a
// fixture where the 401 row has to be asserted some other way, which is how a 403
// would end up standing in for it.
func newSessionLinkFixtureResolving(t *testing.T, scopes []string, resolves bool) *sessionLinkFixture {
	t.Helper()

	auth := newFakeAuth()
	// The key's own user is a fresh id rather than `auth.user.ID`, so "the subject
	// came from the body" is a claim about two different values rather than about one
	// that happened to be the same in both places.
	keyHolder := id.MustNew()
	caller := newFakeAPIKeyCaller(auth.user, apikeys.Key{
		ID:     id.MustNew(),
		UserID: keyHolder,
		// The account id is deliberately one nothing else in this file knows. The mint
		// route has no account in its path and never consults it, so a test that
		// started passing because of a tenancy lookup would have had to invent one —
		// and it does not, which is the point of the assertion in
		// TestTheMintsSubjectIsTheOneTheBodyNames.
		AccountID: id.MustNew(),
		Scopes:    scopes,
	})
	if !resolves {
		caller.err = apikeys.ErrNotFound
	}
	rec := newFakeRecovery()

	return &sessionLinkFixture{
		handler: New(nil,
			WithAuth(auth),
			WithAPIKeyCaller(caller),
			WithRecovery(rec),
			WithLogger(slogLogger(&recordingHandler{})),
		),
		recovery:      rec,
		subject:       id.MustNew(),
		keyHolder:     keyHolder,
		apiKey:        apiKeySecret,
		strangerToken: scopedTokenForTheMatrix,
		session:       "a-session-token",
	}
}

// mint posts a body to the mint route with one credential.
func (f *sessionLinkFixture) mint(t *testing.T, body, credential string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/session-links", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

// happyBody is a body naming a real subject.
func (f *sessionLinkFixture) happyBody() string {
	return `{"user_id":"` + f.subject.String() + `"}`
}

// ---------------------------------------------------------------------------
// the happy path
// ---------------------------------------------------------------------------

// TestAMintReturnsTheTokenAndTheInstantItDies is the route working, and the body is
// compared as a decoded map rather than as bytes for the reason every other body
// assertion in this package is: the decoded form is what catches a field the handler
// never meant to add.
func TestAMintReturnsTheTokenAndTheInstantItDies(t *testing.T) {
	f := newSessionLinkFixture(t)

	rec := f.mint(t, f.happyBody(), f.apiKey)
	if rec.Code != http.StatusCreated {
		t.Fatalf("a token holding %s minting = %d, want 201; body: %s",
			apikeys.ScopeSessionsWrite, rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the 201 body is not JSON: %v", err)
	}
	// EXACTLY TWO FIELDS. A third one here would be a fact about the subject that this
	// service has no reason to publish, and the honest way to keep that true is to
	// have a test that fails on the arrival rather than on a reviewer noticing.
	if len(body) != 2 {
		t.Errorf("the 201 body carries %d field(s) (%v), want exactly token and expires_at. "+
			"Anything further is a fact about the subject, and this route publishes the "+
			"credential and its expiry and nothing else", len(body), body)
	}
	if body["token"] != "minted-by-the-use-case" {
		t.Errorf("token = %v, want the value the use case returned. A handler that rendered its "+
			"own value would be a second mint outside the transaction", body["token"])
	}
	if body["expires_at"] != "2026-10-01T12:10:00Z" {
		t.Errorf("expires_at = %v, want the instant the use case returned", body["expires_at"])
	}
}

// TestTheMintsSubjectIsTheOneTheBodyNames is the wiring rather than the status: the
// use case is asked for the subject in the body, and the route's own account
// context is nowhere in it.
//
// That second half is why the fixture gives the key an account id that nothing else
// knows. A handler that read the caller's account instead of the body — the mistake
// core's "tenancy comes from the credential, never from the request body" rule names
// — would pass every status assertion in this file while minting for somebody else.
func TestTheMintsSubjectIsTheOneTheBodyNames(t *testing.T) {
	f := newSessionLinkFixture(t)

	rec := f.mint(t, f.happyBody(), f.apiKey)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", rec.Code, rec.Body)
	}
	if len(f.recovery.mints) != 1 {
		t.Fatalf("the use case was called %d times, want once", len(f.recovery.mints))
	}
	if f.recovery.mints[0].UserID != f.subject {
		t.Errorf("the mint was asked for subject %s, want the one the body named (%s)",
			f.recovery.mints[0].UserID, f.subject)
	}
	if f.recovery.mints[0].UserID == f.keyHolder {
		t.Error("the mint was asked for the CALLER as its subject. The subject is named in the " +
			"body and is not the caller, which is the whole reason this route needs a scope " +
			"rather than a session")
	}
	if f.recovery.mints[0].Window != 0 {
		t.Errorf("an absent window reached the use case as %s, want 0 so the default applies",
			f.recovery.mints[0].Window)
	}
}

// TestTheWindowIsReadAsSecondsAndReachesTheUseCase: `expires_in` is a NUMBER OF
// SECONDS and this is where that claim is checked — a handler that passed the raw
// integer through as a duration would mint a link living 45 nanoseconds.
func TestTheWindowIsReadAsSecondsAndReachesTheUseCase(t *testing.T) {
	f := newSessionLinkFixture(t)

	rec := f.mint(t, `{"user_id":"`+f.subject.String()+`","expires_in":45}`, f.apiKey)
	if rec.Code != http.StatusCreated {
		t.Fatalf("a mint with a 45-second window = %d, want 201; body: %s", rec.Code, rec.Body)
	}
	if len(f.recovery.mints) != 1 {
		t.Fatalf("the use case was called %d times, want once", len(f.recovery.mints))
	}
	if got := f.recovery.mints[0].Window; got != 45*time.Second {
		t.Errorf("the window reached the use case as %s, want 45s", got)
	}
}

// TestAnAbsentWindowAndAZeroWindowAreDifferentRequests is the pointer's whole reason
// for being a pointer, and it is here because a `*int64` in a struct is not a
// declaration anybody re-reads.
//
// Zero means "a lifetime of zero seconds", which is a request this service refuses;
// absent means "no opinion, take the ten-minute default". Collapsing them would make
// a client that sends `{"expires_in": 0}` believe it asked for the default.
func TestAnAbsentWindowAndAZeroWindowAreDifferentRequests(t *testing.T) {
	f := newSessionLinkFixture(t)

	rec := f.mint(t, `{"user_id":"`+f.subject.String()+`","expires_in":0}`, f.apiKey)
	if rec.Code != http.StatusCreated {
		t.Fatalf("an explicit zero window = %d, want 201; body: %s", rec.Code, rec.Body)
	}
	if len(f.recovery.mints) != 1 {
		t.Fatalf("the use case was called %d times, want once", len(f.recovery.mints))
	}
	if got := f.recovery.mints[0].Window; got != 0 {
		t.Errorf("an explicit zero reached the use case as %s, want 0. The use case reads 0 as "+
			"'refuse this', and a handler that defaulted it would silently grant the default "+
			"window to a caller who asked for none", got)
	}
}

// ---------------------------------------------------------------------------
// the credential gate
// ---------------------------------------------------------------------------

// TestTheMintRouteIsReachableByExactlyOneCredential is the gate, as a table over the
// callers that exist.
//
// THE `reached` COLUMN IS THE ASSERTION AND THE STATUS IS THE FOOTNOTE. Every
// refusal below asserts that the use case was NOT called, because a mint that
// answered 403 after inserting has minted anyway — the status code is what a client
// sees and the row is what an attacker wanted.
func TestTheMintRouteIsReachableByExactlyOneCredential(t *testing.T) {
	cases := []struct {
		name string
		// credential names which of the fixture's three values the request presents.
		credential string
		// build assembles the router for this row. It is a FUNCTION rather than a
		// list of scopes because one row needs a grant the variadic default cannot
		// express — the empty one — and a conditional in the loop deciding that would
		// be where a row stops reading as a case.
		build func(t *testing.T) *sessionLinkFixture
		want  int
		// wantCode is asserted on every row, so a row cannot pass on the status alone.
		wantCode string
		// reached says whether the use case may be called at all.
		reached bool
	}{
		{
			name:       "a token holding sessions:write",
			credential: "apiKey",
			build:      func(t *testing.T) *sessionLinkFixture { return newSessionLinkFixture(t) },
			want:       http.StatusCreated,
			reached:    true,
		},
		{
			// THE 403 AND NOT 401 IS THE ASSERTION. A session is authenticated; a 401
			// would send a client looking for a login problem that does not exist. The
			// row exists because the admin surface's identical rule is asserted there,
			// and two surfaces mean two tests: a rule restated in one place is a rule
			// that quietly changes in the other.
			name:       "a browser session",
			credential: "session",
			build:      func(t *testing.T) *sessionLinkFixture { return newSessionLinkFixture(t) },
			want:       http.StatusForbidden,
			wantCode:   CodeForbidden,
		},
		{
			// NO CREDENTIAL AT ALL IS ALSO 403, not 401: this surface is token-only, so
			// "you are not a token" is a statement about the surface and it is true of a
			// stranger exactly as it is of a session.
			name:       "no credential",
			credential: "",
			build:      func(t *testing.T) *sessionLinkFixture { return newSessionLinkFixture(t) },
			want:       http.StatusForbidden,
			wantCode:   CodeForbidden,
		},
		{
			name:       "a token holding some other scope",
			credential: "apiKey",
			build: func(t *testing.T) *sessionLinkFixture {
				return newSessionLinkFixture(t, apikeys.ScopeAccountsRead, apikeys.ScopeAccountsWrite)
			},
			want:     http.StatusForbidden,
			wantCode: CodeForbidden,
		},
		{
			// The scope nobody in this service has a use for is not a route into this
			// one. `HasScope` is an exact match and this is what it buys.
			name:       "a token holding a scope that does not exist",
			credential: "apiKey",
			build: func(t *testing.T) *sessionLinkFixture {
				return newSessionLinkFixture(t, "invented:scope")
			},
			want:     http.StatusForbidden,
			wantCode: CodeForbidden,
		},
		{
			// THE EMPTY GRANT. A token with no scopes at all is refused here, and this is
			// the row that says the check is not `Allows("")`-by-accident: a caller
			// holding an empty slice reads as a credential that LACKS the scope rather
			// than as one that holds everything.
			name:       "a token holding no scopes",
			credential: "apiKey",
			build: func(t *testing.T) *sessionLinkFixture {
				return newSessionLinkFixtureWithGrant(t, []string{})
			},
			want:     http.StatusForbidden,
			wantCode: CodeForbidden,
		},
		{
			// A token-shaped value that resolves to no key. It is refused at the
			// authentication step, which is a 401 and not the surface's 403 — the
			// difference matters and is asserted rather than assumed: 403 means "your
			// credential cannot use this route", and this caller has no credential at
			// all.
			name:       "a token that resolves to nothing",
			credential: "strangerToken",
			build: func(t *testing.T) *sessionLinkFixture {
				return newSessionLinkFixtureResolving(t, []string{apikeys.ScopeSessionsWrite}, false)
			},
			want:     http.StatusUnauthorized,
			wantCode: CodeUnauthorized,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.build(t)

			credential := f.apiKey
			switch tc.credential {
			case "session":
				credential = f.session
			case "strangerToken":
				credential = f.strangerToken
			case "":
				credential = ""
			}

			rec := f.mint(t, f.happyBody(), credential)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tc.want, rec.Body)
			}
			// The code is asserted only where there IS a problem document. Checking it on the
			// 201 row would be checking a field of a body that has no problem in it.
			if rec.Code >= 400 {
				if got := decodeProblem(t, rec).Code; got != tc.wantCode {
					t.Errorf("code = %q, want %q", got, tc.wantCode)
				}
			}
			if rec.Code >= 400 && rec.Header().Get("Content-Type") != "application/problem+json" {
				t.Errorf("a %d carried Content-Type %q, want application/problem+json",
					rec.Code, rec.Header().Get("Content-Type"))
			}

			// The half of the assertion a status code cannot make.
			reached := len(f.recovery.mints) > 0
			if reached != tc.reached {
				if tc.reached {
					t.Error("the use case was never reached, so the 2xx is a refusal rather than a mint")
				} else {
					t.Errorf("the use case WAS reached and the route answered %d. A mint that "+
						"refuses after the insert has already written the credential the caller "+
						"was told it did not get", rec.Code)
				}
			}
		})
	}
}

// TestTheScopeRefusalNamesTheMissingScope is the whole of what a developer needs
// from the 403: which scope to add to the token they minted.
//
// It asserts the NAME rather than merely that there is a refusal, because a refusal
// that says "forbidden" without naming the scope sends somebody to the vocabulary
// table with no idea which row to look at.
func TestTheScopeRefusalNamesTheMissingScope(t *testing.T) {
	f := newSessionLinkFixture(t, apikeys.ScopeAccountsRead)

	rec := f.mint(t, f.happyBody(), f.apiKey)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), apikeys.ScopeSessionsWrite) {
		t.Errorf("the 403 does not name %s: %s", apikeys.ScopeSessionsWrite, rec.Body)
	}
}

// TestTheSessionRefusalNamesTheScopeATokenWouldNeed is the other 403, from the other
// check, asserted separately because a developer's browser getting this one needs to
// know it is not a login problem.
//
// The assertion is that the detail names the scope. "A browser session may not use
// it" on its own reads like an authentication failure, and the sentence a client
// renders is what tells an operator which grant they are missing.
func TestTheSessionRefusalNamesTheScopeATokenWouldNeed(t *testing.T) {
	f := newSessionLinkFixture(t)

	rec := f.mint(t, f.happyBody(), f.session)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a browser session minting = %d, want 403; body: %s", rec.Code, rec.Body)
	}
	problem := decodeProblem(t, rec)
	if !strings.Contains(problem.Detail, apikeys.ScopeSessionsWrite) {
		t.Errorf("the 403 does not name the scope a token would need: %q", problem.Detail)
	}
	if len(f.recovery.mints) != 0 {
		t.Error("a browser session reached the use case")
	}
}

// ---------------------------------------------------------------------------
// the refusals the use case returns
// ---------------------------------------------------------------------------

// TestTheMintsRefusalsAreTheStatusesAndCodesThisServicePromises is a TABLE over the
// refusals `MintSessionLink` can return, because the mapping is a contract with
// clients: a caller that sees 404 knows the subject is not there, 409 knows to stop
// delegating to an account with a second factor, and 503 knows this deployment cannot
// mint at all right now.
//
// THE UNEXPECTED CASE IS IN THE TABLE too, and it is the row that matters: a
// database failure must be a 500 with the cause in the log and nothing in the body.
func TestTheMintsRefusalsAreTheStatusesAndCodesThisServicePromises(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		want     int
		wantCode string
		// wantDetail names a substring the sentence must carry, because a status and a
		// code are not enough for a caller to act on.
		wantDetail string
		// notInDetail is a substring the sentence must NOT carry: an internal error
		// message rendered to a caller is the leak `unexpected` exists to prevent, and
		// it is asserted rather than trusted.
		notInDetail string
	}{
		{
			name:        "a subject that is not a user",
			err:         recovery.ErrSubjectNotFound,
			want:        http.StatusNotFound,
			wantCode:    CodeNotFound,
			wantDetail:  "no user with that id",
			notInDetail: "SELECT",
		},
		{
			name:        "a subject with a second factor",
			err:         recovery.ErrSubjectHasSecondFactor,
			want:        http.StatusConflict,
			wantCode:    CodeConflict,
			wantDetail:  "second factor",
			notInDetail: "mfa_credentials",
		},
		{
			name:        "a deployment that cannot ask about second factors",
			err:         recovery.ErrMFAUnavailable,
			want:        http.StatusServiceUnavailable,
			wantCode:    CodeServiceUnavailable,
			wantDetail:  "cannot say whether an account has a second factor",
			notInDetail: "SELECT",
		},
		{
			// A WRAPPED sentinel, which is what a real one looks like: `errors.Is` has
			// to do the work, so a mapper comparing the error by string would fail here
			// and one comparing it by equality would too.
			name:        "a wrapped refusal",
			err:         wrappedError{inner: recovery.ErrSubjectHasSecondFactor},
			want:        http.StatusConflict,
			wantCode:    CodeConflict,
			wantDetail:  "second factor",
			notInDetail: "wrapped",
		},
		{
			name:        "something else entirely",
			err:         errDatabaseWentAway,
			want:        http.StatusInternalServerError,
			wantCode:    CodeInternal,
			notInDetail: "10.0.0.5",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSessionLinkFixture(t)
			f.recovery.mintErr = tc.err

			rec := f.mint(t, f.happyBody(), f.apiKey)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tc.want, rec.Body)
			}
			problem := decodeProblem(t, rec)
			if problem.Code != tc.wantCode {
				t.Errorf("code = %q, want %q", problem.Code, tc.wantCode)
			}
			// The document's own status, which is a field a client may read instead of
			// the HTTP one. core says `code` is the contract and `status` is advisory, so
			// the two disagreeing is a bug a client cannot see and this is where it is
			// seen.
			if problem.Status != tc.want {
				t.Errorf("the document's own status = %d, want %d", problem.Status, tc.want)
			}
			if tc.wantDetail != "" && !strings.Contains(problem.Detail, tc.wantDetail) {
				t.Errorf("detail = %q, want it to mention %q", problem.Detail, tc.wantDetail)
			}
			if tc.notInDetail != "" && strings.Contains(problem.Detail, tc.notInDetail) {
				t.Errorf("the detail leaked an internal fact: %q", problem.Detail)
			}
			if rec.Header().Get("Content-Type") != "application/problem+json" {
				t.Errorf("a %d is not application/problem+json", rec.Code)
			}
		})
	}
}

// TestTheMintsValidationRefusalCarriesTheFieldError is the 422's shape: the field
// name and the code in `errors[]`, which is core's contract for "the request was
// understood and is not acceptable".
//
// IT IS DRIVEN FROM A USE-CASE ERROR RATHER THAN HANDLED IN THE HANDLER, and that is
// the point: `writeSessionLinkError` maps what the use case refused and does not
// re-decide it, so the bound this route publishes is `recovery`'s and not a second
// copy here.
func TestTheMintsValidationRefusalCarriesTheFieldError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		code string
	}{
		{"a window over the ceiling", &users.FieldError{Field: "window", Code: users.CodeTooLong}, users.CodeTooLong},
		{"a negative window", &users.FieldError{Field: "window", Code: users.CodeInvalidFormat}, users.CodeInvalidFormat},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSessionLinkFixture(t)
			f.recovery.mintErr = tc.err

			rec := f.mint(t, f.happyBody(), f.apiKey)
			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422; body: %s", rec.Code, rec.Body)
			}
			problem := decodeProblem(t, rec)
			if len(problem.Errors) != 1 {
				t.Fatalf("errors[] has %d entries, want 1: %+v", len(problem.Errors), problem.Errors)
			}
			if problem.Errors[0].Field != "window" {
				t.Errorf("field = %q, want %q", problem.Errors[0].Field, "window")
			}
			if problem.Errors[0].Code != tc.code {
				t.Errorf("code = %q, want %q", problem.Errors[0].Code, tc.code)
			}
		})
	}
}

// TestAMalformedSubjectIsRefusedBeforeTheUseCase is the route's own validation, and
// it is checked both ways: a 422 (or 400) naming the field, and no call into the use
// case.
//
// THE NIL UUID IS IN THE TABLE BECAUSE IT IS NOT A MALFORMED STRING. It parses. It
// is a value no row can hold, and a store that treated it as a wildcard would mint a
// link for an arbitrary subject — so it is refused here for the same reason
// accountIDFrom refuses it, and the reason is on the handler.
func TestAMalformedSubjectIsRefusedBeforeTheUseCase(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"not a uuid at all", `{"user_id":"kaka"}`},
		{"an empty string", `{"user_id":""}`},
		{"the field is absent", `{}`},
		{"the field is the wrong type", `{"user_id":42}`},
		{"the nil uuid", `{"user_id":"00000000-0000-0000-0000-000000000000"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSessionLinkFixture(t)

			rec := f.mint(t, tc.body, f.apiKey)
			// 422 for a field whose value this endpoint cannot accept, and 400 for a
			// body whose JSON is fine but whose type is not — core's shapes for two
			// different mistakes, and both asserted so a change to either is visible.
			if rec.Code != http.StatusUnprocessableEntity && rec.Code != http.StatusBadRequest {
				t.Fatalf("%s = %d, want 422 or 400; body: %s", tc.name, rec.Code, rec.Body)
			}
			if len(f.recovery.mints) != 0 {
				t.Errorf("%s reached the use case. A subject this service cannot parse must be "+
					"refused here, or a uuid parse inside the transaction decides who gets a link",
					tc.name)
			}
		})
	}
}

// TestTheMintsRefusalsCarryATraceID is the operational half: an error a caller can
// quote and an operator can search for.
//
// It is one test and it is here because `writeProblem` sets the header and the body
// from the same source "because core requires" — which is a claim, and a claim with
// no test is a comment.
func TestTheMintsRefusalsCarryATraceID(t *testing.T) {
	f := newSessionLinkFixture(t)
	f.recovery.mintErr = recovery.ErrSubjectNotFound

	rec := f.mint(t, f.happyBody(), f.apiKey)
	problem := decodeProblem(t, rec)
	if problem.TraceID == "" {
		t.Error("the problem document carries no trace_id, so a caller cannot quote it")
	}
	if header := rec.Header().Get(TraceHeader); header != problem.TraceID {
		t.Errorf("the %s header is %q and the body's trace_id is %q. core requires them to be "+
			"the same value", TraceHeader, header, problem.TraceID)
	}
}

// wrappedError is an error carrying a sentinel underneath, which is what every real
// refusal out of a store looks like on the way to the HTTP layer.
type wrappedError struct{ inner error }

func (e wrappedError) Error() string { return "recovery: " + e.inner.Error() }
func (e wrappedError) Unwrap() error { return e.inner }

// errDatabaseWentAway is an internal failure whose message carries a host and a port,
// which is exactly what must never reach a caller.
var errDatabaseWentAway = wrappedError{inner: connectionRefused{}}

type connectionRefused struct{}

func (connectionRefused) Error() string { return "dial tcp 10.0.0.5:5432: connection refused" }
