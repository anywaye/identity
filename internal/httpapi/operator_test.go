package httpapi

// THE OPERATOR SURFACE: `POST /v1/users/:id/disable` and `/enable`.
//
// Every test here drives the REAL router through `requireOperatorToken` against a
// programmable `Auth` double, so what is under test is the credential gate, the
// path parsing and the error mapping — the three things this commit adds — and not
// the transaction, which internal/auth's own tests hold against a real database.
//
// THE `reached` COLUMN IS THE ASSERTION AND THE STATUS IS THE FOOTNOTE. Every
// refusal below asserts that the use case was NOT called, because a disable that
// answered 403 after stamping the column has turned an account off for a caller who
// was told it did not happen. The status code is what a client sees; the column is
// what an attacker wanted.
//
// THE THREE CREDENTIALS ARE THE SUBJECT OF THIS FILE, and the account-scoped one
// is the row that matters: a token holding `accounts:write` is a token an account
// admin's CI job holds, and the route refuses it. A user is not an account — the
// same person belongs to ten of them — so "may this account's admin turn this user
// off" has no answer inside the account boundary, and the scope that does answer it
// is `users:disable`, which no account route grants and which carries no account.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cafaye/identity/internal/apikeys"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/users"
)

// operatorFixture is the operator surface's router: one auth double, one api-key
// caller, and the credentials below.
type operatorFixture struct {
	handler http.Handler
	auth    *fakeAuth
	// subject is the user id in the path, and keyHolder is the user behind the token.
	// They are different ids on purpose: the route's whole contract is that the
	// subject comes from the PATH and is not the caller, and a fixture where the two
	// coincided could not tell a handler that got it right from one that got it wrong
	// by accident.
	subject   id.UUID
	keyHolder id.UUID
	// keyID is the api key's own row id. It is kept beside keyHolder because
	// disabled-04 needs all THREE apart from each other: the subject is in the path,
	// the actor's user is the token's holder, and the actor's KEY is a third value
	// that neither of the others can stand in for. A fixture with two ids could not
	// tell a handler that threaded the actor through from one that filled both
	// columns with the holder's id.
	keyID  id.UUID
	apiKey string
	// strangerToken is token-shaped and resolves to nothing, which is the 401 row.
	strangerToken string
	session       string
}

func newOperatorFixture(t *testing.T, scopes ...string) *operatorFixture {
	t.Helper()

	if len(scopes) == 0 {
		scopes = []string{apikeys.ScopeUsersDisable}
	}
	return newOperatorFixtureWithGrant(t, scopes)
}

// newOperatorFixtureWithGrant takes the grant verbatim, including an empty one.
//
// IT IS SEPARATE FROM `newOperatorFixture` FOR ONE REASON, and the reason is the
// empty grant: a variadic cannot say "no scopes" without also saying "use the
// default", and "a token holding nothing" is a case the scope check has to be
// tested against — `Allows("")` is false for every granted set, and a fixture that
// cannot express it has not checked that.
func newOperatorFixtureWithGrant(t *testing.T, scopes []string) *operatorFixture {
	t.Helper()

	auth := newFakeAuth()
	keyHolder := id.MustNew()
	keyID := id.MustNew()
	// THE KEY'S OWNER IS THE CALLER, and this line makes the fixture say so. It was
	// incoherent before: the key declared `UserID: keyHolder` while the caller the
	// fake resolved carried `newFakeAuth`'s fixed user, so the two disagreed about
	// who was holding the token.
	//
	// That mattered once the route started THREADING the actor rather than discarding
	// it, because there is now one question with a right answer and the fixture gave
	// two. Production cannot be incoherent — `apikeys.Caller` resolves the key's owner
	// and the row together, and `actor_user_id` is that person's id — so a fixture that
	// says otherwise would have been asserting a state no deployment can reach.
	auth.user = users.User{ID: keyHolder, Email: auth.user.Email}
	return &operatorFixture{
		handler: New(nil,
			WithAuth(auth),
			WithAPIKeyCaller(newFakeAPIKeyCaller(auth.user, apikeys.Key{
				ID:     keyID,
				UserID: keyHolder,
				// An account id nothing else in this file knows. The route names no
				// account and never consults one, and a test that started passing
				// because of a tenancy lookup would have had to invent one — which is
				// the assertion in TestTheDisabledSubjectIsTheOneThePathNames.
				AccountID: id.MustNew(),
				Scopes:    scopes,
			})),
			WithLogger(slogLogger(&recordingHandler{})),
		),
		auth:          auth,
		subject:       id.MustNew(),
		keyHolder:     keyHolder,
		keyID:         keyID,
		apiKey:        apiKeySecret,
		strangerToken: scopedTokenForTheMatrix,
		session:       "a-session-token",
	}
}

// send posts to one of the two routes with one credential.
func (f *operatorFixture) send(t *testing.T, action, credential string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/v1/users/"+f.subject.String()+"/"+action, nil)
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

// credential resolves the case name to one of the fixture's values.
func (f *operatorFixture) credential(name string) string {
	switch name {
	case "apiKey":
		return f.apiKey
	case "session":
		return f.session
	case "strangerToken":
		return f.strangerToken
	default:
		return ""
	}
}

// ---------------------------------------------------------------------------
// the happy path
// ---------------------------------------------------------------------------

// TestAnOperatorDisablesAndReEnables is the route working in both directions.
//
// The two are driven in one test because they are one concept with two directions,
// and a pair of separate tests would let one of them answer 204 without the other
// ever being reachable. NO BODY ON EITHER, and the absence is the difference from the
// bulk admin revocation rather than an oversight: the URL names the one thing being
// changed, so there is nothing in the request that could be misread as "and
// everything else".
func TestAnOperatorDisablesAndReEnables(t *testing.T) {
	f := newOperatorFixture(t)

	disabled := f.send(t, "disable", f.apiKey)
	if disabled.Code != http.StatusNoContent {
		t.Fatalf("a token holding %s disabling = %d, want 204; body: %s",
			apikeys.ScopeUsersDisable, disabled.Code, disabled.Body)
	}
	if disabled.Body.Len() != 0 {
		t.Errorf("a 204 carried a body: %s", disabled.Body)
	}
	if len(f.auth.disabled) != 1 || f.auth.disabled[0] != f.subject {
		t.Fatalf("the use case was asked to disable %v, want [%s]", f.auth.disabled, f.subject)
	}
	if len(f.auth.enabled) != 0 {
		t.Errorf("the disable reached the re-enable path as well: %v", f.auth.enabled)
	}

	enabled := f.send(t, "enable", f.apiKey)
	if enabled.Code != http.StatusNoContent {
		t.Fatalf("re-enabling = %d, want 204; body: %s", enabled.Code, enabled.Body)
	}
	if len(f.auth.enabled) != 1 || f.auth.enabled[0] != f.subject {
		t.Errorf("the use case was asked to enable %v, want [%s]", f.auth.enabled, f.subject)
	}
}

// TestTheDisabledSubjectIsTheOneThePathNames is the wiring rather than the status.
//
// The fixture gives the token an account id and a holder id that nothing else in
// this file knows, so "the subject came from the path" is a claim about two
// different values. A handler that disabled the CALLER instead would pass every
// status assertion above while turning off the wrong person — which is the failure
// mode a deployment operator's credential has and a session does not.
func TestTheDisabledSubjectIsTheOneThePathNames(t *testing.T) {
	f := newOperatorFixture(t)

	if rec := f.send(t, "disable", f.apiKey); rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", rec.Code, rec.Body)
	}
	if f.auth.disabled[0] == f.keyHolder {
		t.Error("the route disabled the CALLER. The subject is named in the path and is not " +
			"the caller, which is the whole reason this route needs a scope rather than a session")
	}
}

// THE ACTOR REACHES THE USE CASE, and this is the assertion the packet needs at this
// layer.
//
// `requireOperatorToken` resolved the caller and — until disabled-04 — threw it away,
// which was correct while nothing downstream wanted it. Now the use case writes a row
// naming this operator and this api key, and a route that dropped the caller on the
// floor would produce an audit row with zero ids in it: a record of a decision with no
// responsible party, which is the one thing this table exists to prevent.
//
// IT ASSERMS ALL THREE IDS SEPARATELY, because they are three different values and a
// single "the actor is right" check could not tell a handler that threaded the key
// through from one that wrote the holder's id into both columns.
func TestTheOperatorRouteHandsTheUseCaseItsOwnIdentity(t *testing.T) {
	f := newOperatorFixture(t)

	if rec := f.send(t, "disable", f.apiKey); rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", rec.Code, rec.Body)
	}

	if len(f.auth.disableInputs) != 1 {
		t.Fatalf("the use case was asked %d times, want 1", len(f.auth.disableInputs))
	}
	in := f.auth.disableInputs[0]

	if in.ActorKeyID != f.keyID {
		t.Errorf("the input's actor KEY is %s, want the presented key's row id %s. Without it the "+
			"audit row names no credential, and 'somebody' is not an answer an incident review "+
			"can use — it is the id an operator revokes by.", in.ActorKeyID, f.keyID)
	}
	if in.ActorUserID != f.keyHolder {
		t.Errorf("the input's actor USER is %s, want the token holder %s", in.ActorUserID, f.keyHolder)
	}
	if in.UserID != f.subject {
		t.Errorf("the input's SUBJECT is %s, want the path's %s", in.UserID, f.subject)
	}

	// The trace id, and it must be the REQUEST's rather than an invented one: it is
	// what joins the audit row to the request's log line, and a value generated
	// anywhere else would desynchronise the header from the row.
	if in.TraceID == "" {
		t.Error("the input carries no trace id, so the audit row cannot be joined to the " +
			"request's log line")
	}

	// The enable direction carries the same actor, and it is a separate assertion
	// because the two handlers are separate functions.
	if rec := f.send(t, "enable", f.apiKey); rec.Code != http.StatusNoContent {
		t.Fatalf("re-enabling: status = %d, want 204; body: %s", rec.Code, rec.Body)
	}
	if len(f.auth.enableInputs) != 1 {
		t.Fatalf("the use case was asked to enable %d times, want 1", len(f.auth.enableInputs))
	}
	en := f.auth.enableInputs[0]
	if en.ActorKeyID != f.keyID || en.ActorUserID != f.keyHolder || en.UserID != f.subject {
		t.Errorf("the enable's input is {%s, %s, %s}, want subject %s, holder %s, key %s. A "+
			"re-enable that records nobody leaves a trail saying the person is still disabled.",
			en.UserID, en.ActorUserID, en.ActorKeyID, f.subject, f.keyHolder, f.keyID)
	}
}

// TestARefusedOperatorRouteNeverCarriesACaller is the negative direction, and it is
// what makes the previous test's ordering mean something.
//
// `requireOperatorToken` puts the caller on the context only after the scope check,
// so a route answering 403 or 401 must not be running with an authenticated caller in
// its context. A context that carries a credential a request was REFUSED for is a
// context that lies, and the next thing written from it would be an audit row naming
// an operator whose request did not happen.
func TestARefusedOperatorRouteNeverCarriesACaller(t *testing.T) {
	tests := []struct {
		name       string
		credential string
	}{
		// A session: refused at the credential gate, before anything is resolved.
		{"a session", "session"},
		// A token-shaped value that resolves to no key: the 401 row.
		{"a stranger's token", "strangerToken"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newOperatorFixture(t)

			if rec := f.send(t, "disable", tt.credential); rec.Code == http.StatusNoContent {
				t.Fatalf("status = 204 for %s, want a refusal", tt.name)
			}
			if len(f.auth.disableInputs) != 0 {
				t.Errorf("a refused request still reached the use case %d time(s): %+v",
					len(f.auth.disableInputs), f.auth.disableInputs)
			}
		})
	}

	// And the scope case: a caller that IS authenticated but does not hold the scope.
	// This is the one where the caller genuinely exists, so it is the one where a
	// context set before the check would go unnoticed.
	t.Run("a credential without the scope", func(t *testing.T) {
		f := newOperatorFixtureWithGrant(t, []string{})

		if rec := f.send(t, "disable", f.apiKey); rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
		if len(f.auth.disableInputs) != 0 {
			t.Errorf("an under-scoped caller reached the use case: %+v", f.auth.disableInputs)
		}
	})
}

// TestDisablingIsRepeatableAndNeitherDirectionInspectsTheAccountsState is the
// idempotence, stated rather than assumed.
//
// A second disable is not an error and an enable of an enabled account is not an
// error, because an operator running a script that re-applies a state is not making
// a mistake and should not have to read the column first to find out. The use case
// reports a missing ROW as a 404 — that is a user id this service never issued —
// and nothing else, so there is no `409` for "it was already in that state" to be
// wrong about.
func TestDisablingIsRepeatableAndNeitherDirectionInspectsTheAccountsState(t *testing.T) {
	f := newOperatorFixture(t)

	for attempt := 1; attempt <= 2; attempt++ {
		if rec := f.send(t, "disable", f.apiKey); rec.Code != http.StatusNoContent {
			t.Fatalf("disable %d = %d, want 204; body: %s", attempt, rec.Code, rec.Body)
		}
	}
	if len(f.auth.disabled) != 2 {
		t.Errorf("the use case was called %d times, want once per request", len(f.auth.disabled))
	}
}

// ---------------------------------------------------------------------------
// the credential gate — the three-credential refusal matrix
// ---------------------------------------------------------------------------

// TestTheOperatorRoutesAreReachableByExactlyOneCredential is the gate, as a table
// over the callers that exist, on BOTH routes.
//
// The three credentials are: a scoped token holding `users:disable`, a browser
// session, and a token that is scoped to an ACCOUNT and carries none of the
// operator's scope. Each of the last two is 403 rather than 401, because both ARE
// authenticated — a 401 would send a client hunting a login problem that does not
// exist, and 404 would be a lie about a route that exists.
func TestTheOperatorRoutesAreReachableByExactlyOneCredential(t *testing.T) {
	cases := []struct {
		name string
		// credential names which of the fixture's four values the request presents.
		credential string
		// build assembles the router for this row, because one row needs a grant the
		// variadic default cannot express — the empty one — and a conditional in the
		// loop deciding that would be where a row stops reading as a case.
		build func(t *testing.T) *operatorFixture
		want  int
		// wantCode is asserted on every row where there IS a problem document, so a row
		// cannot pass on the status alone.
		wantCode string
		// reached says whether the use case may be called at all.
		reached bool
	}{
		{
			name:       "a token holding users:disable",
			credential: "apiKey",
			build:      func(t *testing.T) *operatorFixture { return newOperatorFixture(t) },
			want:       http.StatusNoContent,
			reached:    true,
		},
		{
			// THE ROW THIS SURFACE EXISTS TO HOLD. An account-scoped credential is
			// what an account admin's automation holds, and it is refused — not
			// because of the scope it lacks but because no account route grants
			// `users:disable` at all. A user belongs to as many accounts as they like,
			// so "may this account's admin disable this person" has no answer inside
			// the account boundary, and a route that answered it there would let one
			// tenant reach every other tenant's user.
			name:       "an account-scoped token holding accounts:write",
			credential: "apiKey",
			build: func(t *testing.T) *operatorFixture {
				return newOperatorFixture(t, apikeys.ScopeAccountsRead, apikeys.ScopeAccountsWrite)
			},
			want:     http.StatusForbidden,
			wantCode: CodeForbidden,
		},
		{
			// The admin surface's own scopes, which is the closest thing to an
			// operator credential this service had before this one. A token holding
			// both is refused here for the same reason: the admin boundary is one
			// sentence about invitations and audit, and `users:disable` is not part of
			// it.
			name:       "a token holding both admin scopes",
			credential: "apiKey",
			build: func(t *testing.T) *operatorFixture {
				return newOperatorFixture(t, apikeys.ScopeAuditLogRead, apikeys.ScopeAccountInvitationsWrite)
			},
			want:     http.StatusForbidden,
			wantCode: CodeForbidden,
		},
		{
			// A browser session is refused, and 403 rather than 401: it IS
			// authenticated. The same rule holds on the session-link mint and on the
			// admin surface, and it is asserted on each of them separately because a
			// rule restated in one place is a rule that quietly changes in the other.
			name:       "a browser session",
			credential: "session",
			build:      func(t *testing.T) *operatorFixture { return newOperatorFixture(t) },
			want:       http.StatusForbidden,
			wantCode:   CodeForbidden,
		},
		{
			// NO CREDENTIAL AT ALL IS ALSO 403, not 401. This surface is token-only,
			// so "you are not a scoped token" is a statement about the surface and it
			// is true of a stranger exactly as it is of a signed-in person.
			name:       "no credential",
			credential: "",
			build:      func(t *testing.T) *operatorFixture { return newOperatorFixture(t) },
			want:       http.StatusForbidden,
			wantCode:   CodeForbidden,
		},
		{
			name:       "a token holding no scopes",
			credential: "apiKey",
			build: func(t *testing.T) *operatorFixture {
				return newOperatorFixtureWithGrant(t, []string{})
			},
			want:     http.StatusForbidden,
			wantCode: CodeForbidden,
		},
		{
			// A token-shaped value that resolves to no key. It is refused at the
			// AUTHENTICATION step, which is a 401 and not the surface's 403 — the
			// difference is asserted rather than assumed: 403 means "your credential
			// cannot use this route", and this caller has no credential at all.
			name:       "a token that resolves to nothing",
			credential: "strangerToken",
			build: func(t *testing.T) *operatorFixture {
				f := newOperatorFixture(t)
				// The caller that resolves NOTHING rather than a key with no scopes.
				// `fakeAPIKeyCaller` otherwise resolves whatever it is handed, which
				// would make this row a duplicate of the empty-grant one above — and the
				// difference between "no such credential" and "a credential without the
				// scope" is exactly the 401/403 split being asserted here.
				caller := newFakeAPIKeyCaller(f.auth.user, apikeys.Key{ID: id.MustNew()})
				caller.err = apikeys.ErrNotFound
				f.handler = New(nil,
					WithAuth(f.auth),
					WithAPIKeyCaller(caller),
					WithLogger(slogLogger(&recordingHandler{})),
				)
				return f
			},
			want:     http.StatusUnauthorized,
			wantCode: CodeUnauthorized,
		},
	}

	for _, action := range []string{"disable", "enable"} {
		for _, tc := range cases {
			t.Run(action+"/"+tc.name, func(t *testing.T) {
				f := tc.build(t)

				rec := f.send(t, action, f.credential(tc.credential))
				if rec.Code != tc.want {
					t.Fatalf("POST /v1/users/{id}/%s as %s = %d, want %d; body: %s",
						action, tc.name, rec.Code, tc.want, rec.Body)
				}
				if rec.Code >= 400 {
					if got := decodeProblem(t, rec).Code; got != tc.wantCode {
						t.Errorf("code = %q, want %q", got, tc.wantCode)
					}
					if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
						t.Errorf("a %d carried Content-Type %q, want application/problem+json",
							rec.Code, ct)
					}
				}

				// The half of the assertion a status code cannot make.
				reached := len(f.auth.disabled)+len(f.auth.enabled) > 0
				if reached != tc.reached {
					if tc.reached {
						t.Error("the use case was never reached, so the 204 is a refusal")
					} else {
						t.Errorf("the use case WAS reached and the route answered %d. A disable "+
							"that refuses after the commit has already ended every session the "+
							"subject held and stamped the column", rec.Code)
					}
				}
			})
		}
	}
}

// TestTheScopeRefusalNamesTheMissingScope is the whole of what a developer needs
// from the 403: which scope to add to the token they minted.
//
// It asserts the NAME rather than merely that there is a refusal, because a refusal
// that says "forbidden" without naming the scope sends somebody to the vocabulary
// table with no idea which row to look at.
func TestTheOperatorScopeRefusalNamesTheMissingScope(t *testing.T) {
	f := newOperatorFixture(t, apikeys.ScopeAccountsRead)

	for _, action := range []string{"disable", "enable"} {
		rec := f.send(t, action, f.apiKey)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s with the wrong scope = %d, want 403; body: %s", action, rec.Code, rec.Body)
		}
		if !strings.Contains(rec.Body.String(), apikeys.ScopeUsersDisable) {
			t.Errorf("the 403 for %s does not name %s: %s", action, apikeys.ScopeUsersDisable, rec.Body)
		}
	}
}

// TestTheSessionRefusalNamesTheScopeATokenWouldNeed is the other 403, from the
// other check, asserted separately because a developer's browser getting this one
// needs to know it is not a login problem.
func TestTheOperatorSessionRefusalNamesTheScopeATokenWouldNeed(t *testing.T) {
	f := newOperatorFixture(t)

	rec := f.send(t, "disable", f.session)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a browser session disabling = %d, want 403; body: %s", rec.Code, rec.Body)
	}
	problem := decodeProblem(t, rec)
	if !strings.Contains(problem.Detail, apikeys.ScopeUsersDisable) {
		t.Errorf("the 403 does not name the scope a token would need: %q", problem.Detail)
	}
	if len(f.auth.disabled) != 0 {
		t.Error("a browser session reached the use case")
	}
}

// ---------------------------------------------------------------------------
// the refusals the use case returns
// ---------------------------------------------------------------------------

// TestTheOperatorRoutesRefusalsAreTheStatusesThisServicePromises is a TABLE over
// the errors `Disable` and `Enable` can return, because the mapping is a contract
// with clients: a 404 knows the id is not a user this service issued, and a 500
// knows the caller may retry.
//
// THE 404 IS SAFE HERE AND ONLY HERE, on the same argument D12 records for the
// session-link mint: these routes are behind a credential holding an operator
// scope, so there is no anonymous stranger to protect, and an operator told "no
// user with that id" can act on it. It is the opposite of the self-service routes,
// which answer 202 to an unknown address for exactly that reason.
func TestTheOperatorRoutesRefusalsAreTheStatusesThisServicePromises(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		want       int
		wantCode   string
		wantDetail string
		notIn      string
	}{
		{
			name:       "a user id this service never issued",
			err:        users.ErrNotFound,
			want:       http.StatusNotFound,
			wantCode:   CodeNotFound,
			wantDetail: "no user with that id",
			notIn:      "SELECT",
		},
		{
			// A WRAPPED sentinel, which is what a real one looks like: `errors.Is` has
			// to do the work, so a mapper comparing by string would fail here and one
			// comparing by equality would too.
			name:       "a wrapped refusal",
			err:        wrappedError{inner: users.ErrNotFound},
			want:       http.StatusNotFound,
			wantCode:   CodeNotFound,
			wantDetail: "no user with that id",
			notIn:      "wrapped",
		},
		{
			// Everything else is a 500, and the cause goes to the log rather than the
			// body: this includes the transaction that rolled back, and a caller told
			// "it failed" alongside a mutation that did not happen is the honest
			// answer.
			name:     "the database went away",
			err:      errDatabaseWentAway,
			want:     http.StatusInternalServerError,
			wantCode: CodeInternal,
			notIn:    "10.0.0.5",
		},
	}

	for _, action := range []string{"disable", "enable"} {
		for _, tc := range cases {
			t.Run(action+"/"+tc.name, func(t *testing.T) {
				f := newOperatorFixture(t)
				f.auth.disableErr = tc.err
				f.auth.enableErr = tc.err

				rec := f.send(t, action, f.apiKey)
				if rec.Code != tc.want {
					t.Fatalf("status = %d, want %d; body: %s", rec.Code, tc.want, rec.Body)
				}
				problem := decodeProblem(t, rec)
				if problem.Code != tc.wantCode {
					t.Errorf("code = %q, want %q", problem.Code, tc.wantCode)
				}
				if problem.Status != tc.want {
					t.Errorf("the document's own status = %d, want %d", problem.Status, tc.want)
				}
				if tc.wantDetail != "" && !strings.Contains(problem.Detail, tc.wantDetail) {
					t.Errorf("detail = %q, want it to mention %q", problem.Detail, tc.wantDetail)
				}
				if tc.notIn != "" && strings.Contains(problem.Detail, tc.notIn) {
					t.Errorf("the detail leaked an internal fact: %q", problem.Detail)
				}
			})
		}
	}
}

// TestAMalformedSubjectIsRefusedBeforeTheUseCase is the route's own validation.
//
// The NIL UUID IS IN THE TABLE BECAUSE IT IS NOT A MALFORMED STRING. It parses. It
// is a value no row can hold, and a store that treated it as a wildcard would turn
// off an arbitrary user — so it is refused here for the same reason `accountIDFrom`
// refuses it, and the reason is on the handler.
func TestAMalformedOperatorSubjectIsRefusedBeforeTheUseCase(t *testing.T) {
	cases := []struct {
		name string
		path string
	}{
		{"not a uuid at all", "/v1/users/kaka/disable"},
		{"an empty segment", "/v1/users//disable"},
		{"the nil uuid", "/v1/users/00000000-0000-0000-0000-000000000000/disable"},
		{"a uuid with trailing junk", "/v1/users/ab000000-0000-0000-0000-0000000000b1x/disable"},
	}

	for _, action := range []string{"disable", "enable"} {
		for _, tc := range cases {
			t.Run(action+"/"+tc.name, func(t *testing.T) {
				f := newOperatorFixture(t)

				req := httptest.NewRequest(http.MethodPost, strings.Replace(tc.path, "/disable", "/"+action, 1), nil)
				req.Header.Set("Authorization", "Bearer "+f.apiKey)
				rec := httptest.NewRecorder()
				f.handler.ServeHTTP(rec, req)

				// 404 rather than 422: the path is part of a resource's identity, and
				// "this is not an id this service issued" has to be the same answer as
				// "this id is one you cannot see" — see accountIDFrom.
				if rec.Code != http.StatusNotFound {
					t.Fatalf("%s %s = %d, want 404; body: %s", tc.name, action, rec.Code, rec.Body)
				}
				if len(f.auth.disabled)+len(f.auth.enabled) != 0 {
					t.Errorf("%s reached the use case. A user id this service cannot parse must "+
						"be refused here, or a uuid parse inside the transaction decides whose "+
						"account gets turned off", tc.name)
				}
			})
		}
	}
}

// TestTheOperatorRefusalsCarryATraceID is the operational half: an error a caller can
// quote and an operator can search for.
//
// It is one test and it is here because `writeProblem` sets the header and the body
// from the same source — which is a claim, and a claim with no test is a comment.
func TestTheOperatorRefusalsCarryATraceID(t *testing.T) {
	f := newOperatorFixture(t)
	f.auth.disableErr = users.ErrNotFound

	rec := f.send(t, "disable", f.apiKey)
	problem := decodeProblem(t, rec)
	if problem.TraceID == "" {
		t.Error("the problem document carries no trace_id, so a caller cannot quote it")
	}
	if header := rec.Header().Get(TraceHeader); header != problem.TraceID {
		t.Errorf("the %s header is %q and the body's trace_id is %q. core requires them to be "+
			"the same value", TraceHeader, header, problem.TraceID)
	}
}

// ---------------------------------------------------------------------------
// the surface's place in this repository's tables
// ---------------------------------------------------------------------------

// TestTheOperatorRoutesAreVisibleToEveryRouterWalk is the fourth instance of
// router_walk_test.go's bug, for two routes that hang off NO conditional surface of
// their own.
//
// The registrar is called unconditionally from `registerRoutes`, which every walk
// already reaches, so there is no missing-field failure mode here to catch — which is
// exactly why the row is worth stating: a route no walk can see is a route whose
// document entry, matrix row and README row nothing verifies, and the checks would
// report agreement about a service smaller than the one that runs.
func TestTheOperatorRoutesAreVisibleToEveryRouterWalk(t *testing.T) {
	want := []operationKey{
		{Method: "POST", Path: "/v1/users/{}/disable"},
		{Method: "POST", Path: "/v1/users/{}/enable"},
	}

	served := servedRoutes(t)
	for _, key := range want {
		if _, seen := served[key]; !seen {
			t.Errorf("servedRoutes did not report %s as served. TestEveryServedRouteIsDocumentedOrNamed "+
				"depends on this walk seeing every mounted route, so a route missing from it has its "+
				"documentation checked in neither direction", key)
		}
		if _, seen := routesIn(t, walkOptions())[key]; !seen {
			t.Errorf("walkOptions did not report %s. The two options literals describe the same "+
				"deployed router, and a suite walking two different routers reports agreement about "+
				"a service neither one is", key)
		}
	}
}

// TestTheOperatorRoutesAreInTheAnonymousEnumerationAudit is the census row, restated
// as a check.
//
// `/v1/users` is one of `anonymousFamilyAudit`'s family prefixes, so both routes are
// inside the family the census walks and they need rows of their own. This test does
// not restate what those rows say — `TestEveryRouteThatAnswersAnAnonymousCallerIsInThisAudit`
// already fails on a route with no row, and it walks the router rather than
// trusting this list. What it adds is the direction a stray reader would get wrong:
// these two routes answer a stranger with 403, and a stranger's answer must not
// depend on whether the user id is real.
func TestTheOperatorRoutesAreInTheAnonymousEnumerationAudit(t *testing.T) {
	present := map[string]bool{}
	for _, row := range anonymousFamilyAudit() {
		present[row.method+" "+row.pattern] = true
	}

	for _, key := range []string{"POST /v1/users/{userID}/disable", "POST /v1/users/{userID}/enable"} {
		if !present[key] {
			t.Errorf("%s has no row in the enumeration audit. It answers an anonymous caller, so "+
				"the question 'can the response distinguish \"this user exists\" from \"it does not\"?' "+
				"has to be answered out loud. The census itself would fail too — this row is here so "+
				"the failure names the route rather than the table", key)
		}
	}
}
