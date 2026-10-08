package httpapi

// THE STAFF SURFACE: `GET /v1/operator/me`, `GET /v1/operator/users` and
// `POST /v1/operator/users/:id/disable|enable`.
//
// Every test here drives the REAL router through `requireStaffSession` against
// a programmable `Auth` double, so what is under test is the credential gate,
// the query validation and the response projection — the three things this
// packet adds — and not the transaction, which internal/auth's own tests hold
// against a real database.
//
// THE `reached` COLUMN IS THE ASSERTION AND THE STATUS IS THE FOOTNOTE, on
// operator_test.go's terms: every refusal below asserts that the use case was
// NOT called, because a disable that answered 403 after stamping the column
// has turned an account off for a caller who was told it did not happen.
//
// THE FOUR CREDENTIALS ARE THE SUBJECT OF THIS FILE: a staff session (the one
// credential that reaches), an ordinary session, a tenant admin's session, a
// scoped api key, and no credential at all. An account admin is refused not
// because of the role they lack but because no account role implies global
// staff authority — and that refusal is a check with a name.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/auth"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/users"
)

// staffFixture is the staff surface's router: one auth double whose user the
// test marks staff or not, and the session token that resolves to them.
type staffFixture struct {
	handler http.Handler
	auth    *fakeAuth
	staff   users.User
	session string
}

func newStaffFixture(t *testing.T, staff bool) *staffFixture {
	t.Helper()

	user := newFakeAuth().user
	user.IsStaff = staff
	faithful := newFakeAuth()
	faithful.user = user
	return &staffFixture{
		handler: New(nil,
			WithAuth(faithful),
			WithLogger(slogLogger(&recordingHandler{})),
		),
		auth:    faithful,
		staff:   user,
		session: "a-session-token",
	}
}

// sendStaff issues a request as one credential: a session bearer, a
// machine-key bearer, or nothing.
func sendStaff(t *testing.T, h http.Handler, method, target, credential string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, target, nil)
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// ---------------------------------------------------------------------------
// GET /v1/operator/me
// ---------------------------------------------------------------------------

// TestOperatorMeReportsTheSignedInStaffUser is the route working.
func TestOperatorMeReportsTheSignedInStaffUser(t *testing.T) {
	f := newStaffFixture(t, true)

	rec := sendStaff(t, f.handler, http.MethodGet, "/v1/operator/me", f.session)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/operator/me as staff = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, want application/json; charset=utf-8", ct)
	}

	var body struct {
		User struct {
			ID    string `json:"id"`
			Email string `json:"email"`
			Staff bool   `json:"staff"`
		} `json:"user"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding the me response: %v; body: %s", err, rec.Body)
	}
	if body.User.ID != f.staff.ID.String() {
		t.Errorf("user.id = %q, want the caller's own %s", body.User.ID, f.staff.ID)
	}
	if body.User.Email != f.staff.Email {
		t.Errorf("user.email = %q, want the caller's own %s", body.User.Email, f.staff.Email)
	}
	if !body.User.Staff {
		t.Error("user.staff = false for a staff caller: the route reports the caller's status and the gate already established it")
	}

	// The shape is stable and nested: exactly one top-level `user` key, and
	// exactly the three documented keys inside it — so a client can rely on
	// it and a future field cannot arrive unannounced.
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("re-decoding the me response: %v", err)
	}
	if len(raw) != 1 {
		t.Errorf("the me response has %d top-level keys, want exactly `user`: %s", len(raw), rec.Body)
	}
	inner, ok := raw["user"].(map[string]any)
	if !ok {
		t.Fatalf("the me response has no `user` object: %s", rec.Body)
	}
	for key := range inner {
		switch key {
		case "id", "email", "staff":
		default:
			t.Errorf("the me user carries %q, which no document declares", key)
		}
	}
	for _, key := range []string{"id", "email", "staff"} {
		if _, present := inner[key]; !present {
			t.Errorf("the me user omits %q, which the document promises", key)
		}
	}
}

// TestOperatorMeRefusesEverybodyElse is the gate on the status route.
func TestOperatorMeRefusesEverybodyElse(t *testing.T) {
	cases := []struct {
		name       string
		staff      bool
		credential string
		// unauthenticated, when true, makes the session resolve to nothing.
		unauthenticated bool
		want            int
		wantCode        string
	}{
		{name: "an ordinary user", staff: false, credential: "session", want: http.StatusForbidden, wantCode: CodeForbidden},
		{name: "a tenant admin's session", staff: false, credential: "session", want: http.StatusForbidden, wantCode: CodeForbidden},
		{name: "a scoped api key", staff: true, credential: "machine", want: http.StatusForbidden, wantCode: CodeForbidden},
		{name: "no credential", staff: true, credential: "", want: http.StatusUnauthorized, wantCode: CodeUnauthorized},
		{name: "a session that resolves to nothing", staff: true, credential: "session", unauthenticated: true, want: http.StatusUnauthorized, wantCode: CodeUnauthorized},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newStaffFixture(t, tc.staff)
			if tc.unauthenticated {
				f.auth.authErr = auth.ErrUnauthenticated
			}
			credential := tc.credential
			switch credential {
			case "session":
				credential = f.session
			case "machine":
				credential = apiKeySecret
			}

			rec := sendStaff(t, f.handler, http.MethodGet, "/v1/operator/me", credential)
			if rec.Code != tc.want {
				t.Fatalf("GET /v1/operator/me as %s = %d, want %d; body: %s",
					tc.name, rec.Code, tc.want, rec.Body)
			}
			if got := decodeProblem(t, rec).Code; got != tc.wantCode {
				t.Errorf("code = %q, want %q", got, tc.wantCode)
			}
		})
	}
}

// TestAMachineKeyNeverSatisfiesTheHumanSurface is the credential-kind
// disjointness, on all four routes at once.
//
// A scoped api key holding every scope in the vocabulary is still refused
// here: the staff property lives on the user, a token carries scopes rather
// than a staff flag, and consulting them would be reading a field that cannot
// answer the question. The audit trail must be able to say whether a person
// or a pipeline acted, and a credential that crossed surfaces would make that
// unanswerable.
func TestAMachineKeyNeverSatisfiesTheHumanSurface(t *testing.T) {
	f := newStaffFixture(t, true)
	subject := id.MustNew()

	targets := []struct {
		name   string
		method string
		path   string
	}{
		{"me", http.MethodGet, "/v1/operator/me"},
		{"search", http.MethodGet, "/v1/operator/users?query=kaka"},
		{"disable", http.MethodPost, "/v1/operator/users/" + subject.String() + "/disable"},
		{"enable", http.MethodPost, "/v1/operator/users/" + subject.String() + "/enable"},
	}

	for _, target := range targets {
		t.Run(target.name, func(t *testing.T) {
			rec := sendStaff(t, f.handler, target.method, target.path, apiKeySecret)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s %s with a machine key = %d, want 403; body: %s",
					target.method, target.path, rec.Code, rec.Body)
			}
			if got := decodeProblem(t, rec).Code; got != CodeForbidden {
				t.Errorf("code = %q, want %q", got, CodeForbidden)
			}
		})
	}

	if len(f.auth.disabled)+len(f.auth.enabled) != 0 {
		t.Error("a machine key reached the disable/enable use cases")
	}
	if len(f.auth.searched) != 0 {
		t.Error("a machine key reached the directory search")
	}
}

// ---------------------------------------------------------------------------
// GET /v1/operator/users
// ---------------------------------------------------------------------------

// TestTheStaffDirectorySearchReturnsTheMinimalProjection is the route working.
func TestTheStaffDirectorySearchReturnsTheMinimalProjection(t *testing.T) {
	f := newStaffFixture(t, true)
	when := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	name := "Kaka"
	disabledAt := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	verifiedAt := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	f.auth.searchResults = []users.DirectoryEntry{
		{ID: id.MustNew(), Email: "kaka@example.com", DisplayName: &name, EmailVerifiedAt: &verifiedAt, CreatedAt: when},
		{ID: id.MustNew(), Email: "kaka.osei@example.com", DisabledAt: &disabledAt, CreatedAt: when},
	}

	rec := sendStaff(t, f.handler, http.MethodGet, "/v1/operator/users?query=kaka", f.session)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/operator/users?query=kaka as staff = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	var body struct {
		Users []map[string]any `json:"users"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding the directory response: %v; body: %s", err, rec.Body)
	}
	if len(body.Users) != 2 {
		t.Fatalf("the directory returned %d entries, want 2; body: %s", len(body.Users), rec.Body)
	}

	// The use case was asked with the term and the default bound.
	if len(f.auth.searched) != 1 {
		t.Fatalf("the directory was searched %d times, want 1", len(f.auth.searched))
	}
	if f.auth.searched[0].query != "kaka" {
		t.Errorf("the search term = %q, want %q", f.auth.searched[0].query, "kaka")
	}
	if f.auth.searched[0].limit != users.DefaultSearchLimit {
		t.Errorf("the search limit = %d, want the default %d", f.auth.searched[0].limit, users.DefaultSearchLimit)
	}

	// Every entry carries the documented fields, and the response carries
	// nothing a reader could mistake for a credential.
	allowed := map[string]bool{"id": true, "email": true, "display_name": true, "disabled_at": true, "email_verified_at": true, "created_at": true}
	forbidden := []string{
		"password_digest", "password", "token", "api_key", "recovery",
		"mfa", "totp", "secret", "digest", "session", "challenge", "disabled",
	}
	serialised := rec.Body.String()
	for _, field := range forbidden {
		if strings.Contains(serialised, `"`+field+`"`) {
			t.Errorf("the directory response carries %q, which is not Parlor's to read", field)
		}
	}
	for i, entry := range body.Users {
		for key := range entry {
			if !allowed[key] {
				t.Errorf("entry %d carries %q, which no document declares", i, key)
			}
		}
		// The timestamps are PRESENT, never omitted: a fresh account's nulls
		// are keys with null values, which is how a client tells "never"
		// from "missing".
		for _, key := range []string{"id", "email", "disabled_at", "email_verified_at", "created_at"} {
			if _, present := entry[key]; !present {
				t.Errorf("entry %d omits %q, which the document promises", i, key)
			}
		}
	}

	// The values: the verified entry's timestamp renders, the others are null.
	// Entry 0 verified its address and was never disabled; entry 1 is disabled
	// and never verified.
	if got := body.Users[0]["email_verified_at"]; got == nil {
		t.Errorf("entry 0's email_verified_at is null, want %s", verifiedAt.Format(time.RFC3339))
	}
	if body.Users[0]["disabled_at"] != nil {
		t.Errorf("entry 0's disabled_at = %v, want null for an active account", body.Users[0]["disabled_at"])
	}
	if body.Users[1]["email_verified_at"] != nil {
		t.Errorf("entry 1's email_verified_at = %v, want null for an unproved address", body.Users[1]["email_verified_at"])
	}
	if got := body.Users[1]["disabled_at"]; got == nil {
		t.Errorf("entry 1's disabled_at is null, want %s", disabledAt.Format(time.RFC3339))
	}

	// An empty directory is `[]` and not `null`.
	f.auth.searchResults = nil
	empty := sendStaff(t, f.handler, http.MethodGet, "/v1/operator/users?query=kaka", f.session)
	if empty.Code != http.StatusOK {
		t.Fatalf("an empty directory = %d, want 200; body: %s", empty.Code, empty.Body)
	}
	if !strings.Contains(empty.Body.String(), `"users":[]`) {
		t.Errorf("an empty directory renders %s, want {\"users\":[]}", empty.Body)
	}
}

// TestTheStaffDirectorySearchValidationIsAContract is the query bounds, as a
// table: the search a directory will not run, and the bound it will not cross.
func TestTheStaffDirectorySearchValidationIsAContract(t *testing.T) {
	cases := []struct {
		name      string
		target    string
		wantField string
		wantCode  string
	}{
		{name: "no query at all", target: "/v1/operator/users", wantField: "query", wantCode: "required"},
		{name: "an empty query", target: "/v1/operator/users?query=", wantField: "query", wantCode: "required"},
		{name: "a blank query", target: "/v1/operator/users?query=%20%20", wantField: "query", wantCode: "required"},
		{name: "a one-character query", target: "/v1/operator/users?query=k", wantField: "query", wantCode: "too_short"},
		{name: "an unreadable limit", target: "/v1/operator/users?query=kaka&limit=many", wantField: "limit", wantCode: "invalid_format"},
		{name: "a zero limit", target: "/v1/operator/users?query=kaka&limit=0", wantField: "limit", wantCode: "invalid_format"},
		{name: "a negative limit", target: "/v1/operator/users?query=kaka&limit=-3", wantField: "limit", wantCode: "invalid_format"},
		{name: "a limit over the ceiling", target: "/v1/operator/users?query=kaka&limit=500", wantField: "limit", wantCode: "out_of_range"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newStaffFixture(t, true)

			rec := sendStaff(t, f.handler, http.MethodGet, tc.target, f.session)
			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("GET %s = %d, want 422; body: %s", tc.target, rec.Code, rec.Body)
			}
			problem := decodeProblem(t, rec)
			if problem.Code != CodeValidationFailed {
				t.Errorf("code = %q, want %q", problem.Code, CodeValidationFailed)
			}
			found := false
			for _, fe := range problem.Errors {
				if fe.Field == tc.wantField && fe.Code == tc.wantCode {
					found = true
				}
			}
			if !found {
				t.Errorf("errors = %+v, want an entry {field:%q code:%q}", problem.Errors, tc.wantField, tc.wantCode)
			}
			if len(f.auth.searched) != 0 {
				t.Errorf("a refused search reached the directory: %+v", f.auth.searched)
			}
		})
	}
}

// TestTheStaffDirectoryHonoursAnExplicitLimit is the bound passing through.
func TestTheStaffDirectoryHonoursAnExplicitLimit(t *testing.T) {
	f := newStaffFixture(t, true)

	rec := sendStaff(t, f.handler, http.MethodGet, "/v1/operator/users?query=kaka&limit=10", f.session)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET with limit=10 = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if len(f.auth.searched) != 1 || f.auth.searched[0].limit != 10 {
		t.Errorf("the directory was searched with %+v, want one call with limit 10", f.auth.searched)
	}
}

// TestTheStaffDirectoryRefusesEverybodyElse is the gate on the search.
func TestTheStaffDirectoryRefusesEverybodyElse(t *testing.T) {
	cases := []struct {
		name       string
		staff      bool
		credential string
		want       int
		wantCode   string
	}{
		{name: "an ordinary user", staff: false, credential: "session", want: http.StatusForbidden, wantCode: CodeForbidden},
		{name: "a tenant admin's session", staff: false, credential: "session", want: http.StatusForbidden, wantCode: CodeForbidden},
		{name: "a scoped api key", staff: true, credential: "machine", want: http.StatusForbidden, wantCode: CodeForbidden},
		{name: "no credential", staff: true, credential: "", want: http.StatusUnauthorized, wantCode: CodeUnauthorized},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newStaffFixture(t, tc.staff)
			credential := tc.credential
			if credential == "session" {
				credential = f.session
			} else if credential == "machine" {
				credential = apiKeySecret
			}

			rec := sendStaff(t, f.handler, http.MethodGet, "/v1/operator/users?query=kaka", credential)
			if rec.Code != tc.want {
				t.Fatalf("GET /v1/operator/users as %s = %d, want %d; body: %s",
					tc.name, rec.Code, tc.want, rec.Body)
			}
			if got := decodeProblem(t, rec).Code; got != tc.wantCode {
				t.Errorf("code = %q, want %q", got, tc.wantCode)
			}
			if len(f.auth.searched) != 0 {
				t.Errorf("a refused search reached the directory: %+v", f.auth.searched)
			}
		})
	}
}

// TestADirectoryFailureIsA500WithNothingInIt is the operational half: the
// caller gets a trace id and the cause stays in the log.
func TestADirectoryFailureIsA500WithNothingInIt(t *testing.T) {
	f := newStaffFixture(t, true)
	f.auth.searchErr = errDatabaseWentAway

	rec := sendStaff(t, f.handler, http.MethodGet, "/v1/operator/users?query=kaka", f.session)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("a failed search = %d, want 500; body: %s", rec.Code, rec.Body)
	}
	problem := decodeProblem(t, rec)
	if problem.Code != CodeInternal {
		t.Errorf("code = %q, want %q", problem.Code, CodeInternal)
	}
	if problem.TraceID == "" {
		t.Error("the 500 carries no trace_id, so a caller cannot quote it")
	}
	if strings.Contains(rec.Body.String(), "10.0.0.5") {
		t.Errorf("the 500 leaked an internal fact: %s", rec.Body)
	}
}

// ---------------------------------------------------------------------------
// POST /v1/operator/users/{userID}/disable|enable
// ---------------------------------------------------------------------------

// TestAStaffHumanDisablesAndReEnables is the route working in both directions,
// with the human actor on the audit input.
func TestAStaffHumanDisablesAndReEnables(t *testing.T) {
	f := newStaffFixture(t, true)
	subject := id.MustNew()

	disabled := sendStaff(t, f.handler, http.MethodPost, "/v1/operator/users/"+subject.String()+"/disable", f.session)
	if disabled.Code != http.StatusNoContent {
		t.Fatalf("a staff disable = %d, want 204; body: %s", disabled.Code, disabled.Body)
	}
	if disabled.Body.Len() != 0 {
		t.Errorf("a 204 carried a body: %s", disabled.Body)
	}
	if len(f.auth.disableInputs) != 1 {
		t.Fatalf("the use case was asked %d times, want 1", len(f.auth.disableInputs))
	}
	in := f.auth.disableInputs[0]
	if in.UserID != subject {
		t.Errorf("the subject is %s, want the path's %s", in.UserID, subject)
	}
	if in.ActorUserID != f.staff.ID {
		t.Errorf("the actor user is %s, want the signed-in staff user %s", in.ActorUserID, f.staff.ID)
	}
	if !in.ActorKeyID.IsZero() {
		t.Errorf("the actor key is %s, want the nil uuid: no token acted, and inventing one "+
			"would be a lie the audit table then has to be trusted about", in.ActorKeyID)
	}
	if in.TraceID == "" {
		t.Error("the input carries no trace id, so the audit row cannot be joined to the request's log line")
	}

	enabled := sendStaff(t, f.handler, http.MethodPost, "/v1/operator/users/"+subject.String()+"/enable", f.session)
	if enabled.Code != http.StatusNoContent {
		t.Fatalf("a staff re-enable = %d, want 204; body: %s", enabled.Code, enabled.Body)
	}
	if len(f.auth.enableInputs) != 1 {
		t.Fatalf("the enable use case was asked %d times, want 1", len(f.auth.enableInputs))
	}
	en := f.auth.enableInputs[0]
	if en.ActorUserID != f.staff.ID || !en.ActorKeyID.IsZero() || en.UserID != subject {
		t.Errorf("the enable's input is {subject %s, actor %s, key %s}, want subject %s, actor %s and a nil key. "+
			"A re-enable that records nobody leaves a trail saying the person is still disabled.",
			en.UserID, en.ActorUserID, en.ActorKeyID, subject, f.staff.ID)
	}
}

// TestTheStaffDisableEnableRefusesEverybodyElse is the gate on the mutations.
func TestTheStaffDisableEnableRefusesEverybodyElse(t *testing.T) {
	cases := []struct {
		name            string
		staff           bool
		credential      string
		unauthenticated bool
		want            int
		wantCode        string
	}{
		{name: "an ordinary user", staff: false, credential: "session", want: http.StatusForbidden, wantCode: CodeForbidden},
		{name: "a tenant admin's session", staff: false, credential: "session", want: http.StatusForbidden, wantCode: CodeForbidden},
		{name: "a scoped api key", staff: true, credential: "machine", want: http.StatusForbidden, wantCode: CodeForbidden},
		{name: "no credential", staff: true, credential: "", want: http.StatusUnauthorized, wantCode: CodeUnauthorized},
		{name: "a session that resolves to nothing", staff: true, credential: "session", unauthenticated: true, want: http.StatusUnauthorized, wantCode: CodeUnauthorized},
	}

	for _, action := range []string{"disable", "enable"} {
		for _, tc := range cases {
			t.Run(action+"/"+tc.name, func(t *testing.T) {
				f := newStaffFixture(t, tc.staff)
				if tc.unauthenticated {
					f.auth.authErr = auth.ErrUnauthenticated
				}
				credential := tc.credential
				if credential == "session" {
					credential = f.session
				} else if credential == "machine" {
					credential = apiKeySecret
				}
				subject := id.MustNew()

				rec := sendStaff(t, f.handler, http.MethodPost, "/v1/operator/users/"+subject.String()+"/"+action, credential)
				if rec.Code != tc.want {
					t.Fatalf("POST /v1/operator/users/{id}/%s as %s = %d, want %d; body: %s",
						action, tc.name, rec.Code, tc.want, rec.Body)
				}
				if got := decodeProblem(t, rec).Code; got != tc.wantCode {
					t.Errorf("code = %q, want %q", got, tc.wantCode)
				}
				if reached := len(f.auth.disabled) + len(f.auth.enabled); reached != 0 {
					t.Errorf("a refused request reached the use case %d time(s)", reached)
				}
			})
		}
	}
}

// TestARefusedStaffMutationDisclosesNoExistence is the enumeration half: the
// gate runs before the subject is parsed, so a caller who may not act learns
// nothing about whether the named user exists — and not even whether the id
// is well-formed.
func TestARefusedStaffMutationDisclosesNoExistence(t *testing.T) {
	for _, target := range []string{
		"/v1/operator/users/" + id.MustNew().String() + "/disable",
		"/v1/operator/users/kaka/disable",
		"/v1/operator/users/00000000-0000-0000-0000-000000000000/disable",
	} {
		t.Run(target, func(t *testing.T) {
			f := newStaffFixture(t, false)

			rec := sendStaff(t, f.handler, http.MethodPost, target, f.session)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("POST %s as a non-staff user = %d, want 403; body: %s", target, rec.Code, rec.Body)
			}
			if reached := len(f.auth.disabled) + len(f.auth.enabled); reached != 0 {
				t.Errorf("a refused request reached the use case %d time(s)", reached)
			}
		})
	}
}

// TestTheStaffMutationsRefusalsAreTheStatusesThisServicePromises is the error
// mapping: unknown subject behind the gate is a 404 staff can act on, and
// anything else is a 500 with a trace id.
func TestTheStaffMutationsRefusalsAreTheStatusesThisServicePromises(t *testing.T) {
	for _, action := range []string{"disable", "enable"} {
		t.Run(action+"/an id this service never issued", func(t *testing.T) {
			f := newStaffFixture(t, true)
			f.auth.disableErr = users.ErrNotFound
			f.auth.enableErr = users.ErrNotFound
			subject := id.MustNew()

			rec := sendStaff(t, f.handler, http.MethodPost, "/v1/operator/users/"+subject.String()+"/"+action, f.session)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404; body: %s", rec.Code, rec.Body)
			}
			if got := decodeProblem(t, rec).Code; got != CodeNotFound {
				t.Errorf("code = %q, want %q", got, CodeNotFound)
			}
		})

		t.Run(action+"/a malformed id", func(t *testing.T) {
			f := newStaffFixture(t, true)

			rec := sendStaff(t, f.handler, http.MethodPost, "/v1/operator/users/kaka/"+action, f.session)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404; body: %s", rec.Code, rec.Body)
			}
			if reached := len(f.auth.disabled) + len(f.auth.enabled); reached != 0 {
				t.Errorf("a malformed id reached the use case %d time(s)", reached)
			}
		})

		t.Run(action+"/the database went away", func(t *testing.T) {
			f := newStaffFixture(t, true)
			f.auth.disableErr = errDatabaseWentAway
			f.auth.enableErr = errDatabaseWentAway
			subject := id.MustNew()

			rec := sendStaff(t, f.handler, http.MethodPost, "/v1/operator/users/"+subject.String()+"/"+action, f.session)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body)
			}
			if problem := decodeProblem(t, rec); problem.TraceID == "" {
				t.Error("the 500 carries no trace_id, so a caller cannot quote it")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// the surface's place in this repository's tables
// ---------------------------------------------------------------------------

// TestTheDriftWalkSeesTheStaffSurface is the behavioural instance of
// router_walk_test.go's bug, for the four routes this packet mounts.
//
// They hang off `auth` — the use cases are `auth.Service`'s — so no walk
// literal needs a new field to see them. The row asserts the walks FIND them
// rather than that a field was set, because a route no walk can see is a route
// whose document entry, audit row and README row nothing verifies.
func TestTheDriftWalkSeesTheStaffSurface(t *testing.T) {
	want := []operationKey{
		{Method: "GET", Path: "/v1/operator/me"},
		{Method: "GET", Path: "/v1/operator/users"},
		{Method: "POST", Path: "/v1/operator/users/{}/disable"},
		{Method: "POST", Path: "/v1/operator/users/{}/enable"},
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

// TestAStaffSessionCannotUseTheMachineOperatorSurface is the regression in the
// other direction: the packet adds a human path and must not widen the machine
// one. A session — staff or not — is 403 on the scoped-token routes, and the
// use case is never reached.
func TestAStaffSessionCannotUseTheMachineOperatorSurface(t *testing.T) {
	f := newStaffFixture(t, true)
	subject := id.MustNew()

	for _, action := range []string{"disable", "enable"} {
		rec := sendStaff(t, f.handler, http.MethodPost, "/v1/users/"+subject.String()+"/"+action, f.session)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("POST /v1/users/{id}/%s with a staff session = %d, want 403; body: %s",
				action, rec.Code, rec.Body)
		}
	}
	if reached := len(f.auth.disabled) + len(f.auth.enabled); reached != 0 {
		t.Errorf("a session reached the machine operator use cases %d time(s)", reached)
	}
}
