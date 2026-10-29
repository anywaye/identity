package httpapi


import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anywaye/identity/internal/apikeys"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/users"
)

type operatorFixture struct {
	handler http.Handler
	auth    *fakeAuth
	subject   id.UUID
	keyHolder id.UUID
	keyID  id.UUID
	apiKey string
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

func newOperatorFixtureWithGrant(t *testing.T, scopes []string) *operatorFixture {
	t.Helper()

	auth := newFakeAuth()
	keyHolder := id.MustNew()
	keyID := id.MustNew()
	auth.user = users.User{ID: keyHolder, Email: auth.user.Email}
	return &operatorFixture{
		handler: New(nil,
			WithAuth(auth),
			WithAPIKeyCaller(newFakeAPIKeyCaller(auth.user, apikeys.Key{
				ID:     keyID,
				UserID: keyHolder,
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

func (f *operatorFixture) send(t *testing.T, action, credential string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/users/"+f.subject.String()+"/"+action, nil)
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

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

	if in.TraceID == "" {
		t.Error("the input carries no trace id, so the audit row cannot be joined to the " +
			"request's log line")
	}

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

func TestARefusedOperatorRouteNeverCarriesACaller(t *testing.T) {
	tests := []struct {
		name       string
		credential string
	}{
		{"a session", "session"},
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


func TestTheOperatorRoutesAreReachableByExactlyOneCredential(t *testing.T) {
	cases := []struct {
		name string
		credential string
		build func(t *testing.T) *operatorFixture
		want  int
		wantCode string
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
			name:       "an account-scoped token holding accounts:write",
			credential: "apiKey",
			build: func(t *testing.T) *operatorFixture {
				return newOperatorFixture(t, apikeys.ScopeAccountsRead, apikeys.ScopeAccountsWrite)
			},
			want:     http.StatusForbidden,
			wantCode: CodeForbidden,
		},
		{
			name:       "a token holding both admin scopes",
			credential: "apiKey",
			build: func(t *testing.T) *operatorFixture {
				return newOperatorFixture(t, apikeys.ScopeAuditLogRead, apikeys.ScopeAccountInvitationsWrite)
			},
			want:     http.StatusForbidden,
			wantCode: CodeForbidden,
		},
		{
			name:       "a browser session",
			credential: "session",
			build:      func(t *testing.T) *operatorFixture { return newOperatorFixture(t) },
			want:       http.StatusForbidden,
			wantCode:   CodeForbidden,
		},
		{
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
			name:       "a token that resolves to nothing",
			credential: "strangerToken",
			build: func(t *testing.T) *operatorFixture {
				f := newOperatorFixture(t)
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
			name:       "a wrapped refusal",
			err:        wrappedError{inner: users.ErrNotFound},
			want:       http.StatusNotFound,
			wantCode:   CodeNotFound,
			wantDetail: "no user with that id",
			notIn:      "wrapped",
		},
		{
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

				req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, strings.Replace(tc.path, "/disable", "/"+action, 1), nil)
				req.Header.Set("Authorization", "Bearer "+f.apiKey)
				rec := httptest.NewRecorder()
				f.handler.ServeHTTP(rec, req)

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
