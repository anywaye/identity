package httpapi


import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/anywaye/identity/internal/accounts"
	"github.com/anywaye/identity/internal/admin"
	"github.com/anywaye/identity/internal/apikeys"
	"github.com/anywaye/identity/internal/platform/id"
)


type fakeAdmin struct {
	revokedOne   int
	revokedMany  int
	revokeOneErr error
	revokeManyEr error
	listErr      error
	records      []admin.Record

	sawRevokeOne  bool
	sawRevokeMany bool
	sawList       bool
	lastActor admin.Actor
}

func (f *fakeAdmin) RevokeInvitation(_ context.Context, in admin.RevokeInvitationInput) (int, error) {
	f.sawRevokeOne = true
	f.lastActor = in.Actor
	if f.revokeOneErr != nil {
		return 0, f.revokeOneErr
	}
	return f.revokedOne, nil
}

func (f *fakeAdmin) RevokeInvitations(_ context.Context, in admin.RevokeInvitationsInput) (int, error) {
	f.sawRevokeMany = true
	f.lastActor = in.Actor
	if f.revokeManyEr != nil {
		return 0, f.revokeManyEr
	}
	return f.revokedMany, nil
}

func (f *fakeAdmin) List(_ context.Context, _ id.UUID, _ admin.Page) ([]admin.Record, error) {
	f.sawList = true
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.records, nil
}

func newFakeAdmin() *fakeAdmin { return &fakeAdmin{revokedOne: 1, revokedMany: 1} }

var _ Admin = (*fakeAdmin)(nil)

var errAuditFailure = errors.New("appending the audit record: injected failure")


type adminFixture struct {
	handler http.Handler
	admin   *fakeAdmin

	accountID id.UUID
	memberID  id.UUID
	token   string
	session string
}

func newAdminFixture(t *testing.T, scopes ...string) *adminFixture {
	t.Helper()

	if len(scopes) == 0 {
		scopes = []string{apikeys.ScopeAuditLogRead, apikeys.ScopeAccountInvitationsWrite}
	}
	return newAdminFixtureAs(t, accounts.RoleOwner, scopes...)
}

func newAdminFixtureAs(t *testing.T, role accounts.Role, scopes ...string) *adminFixture {
	t.Helper()

	if len(scopes) == 0 {
		scopes = []string{apikeys.ScopeAuditLogRead, apikeys.ScopeAccountInvitationsWrite}
	}

	auth := newFakeAuth()
	accountID := id.MustNew()
	memberID := auth.user.ID

	tenancy := adminTenancy(accountID, role)
	caller := newFakeAPIKeyCaller(auth.user, apikeys.Key{
		ID:        id.MustNew(),
		UserID:    memberID,
		AccountID: accountID,
		Scopes:    scopes,
	})
	adminSvc := &fakeAdmin{revokedOne: 1, revokedMany: 1}

	handler := New(nil,
		WithAuth(auth),
		WithTenancy(tenancy),
		WithAPIKeyCaller(caller),
		WithAdmin(adminSvc),
	)

	return &adminFixture{
		handler:   handler,
		admin:     adminSvc,
		accountID: accountID,
		memberID:  memberID,
		token:     apiKeySecret,
		session:   "session-for-the-same-user",
	}
}

func adminTenancy(accountID id.UUID, role accounts.Role) *fakeTenancy {
	tenancy := newFakeTenancy()
	tenancy.account = accounts.Account{
		ID: accountID, Name: "Admin Fixture", Slug: "admin-fixture",
	}
	tenancy.role = role
	return tenancy
}

func (f *adminFixture) adminSend(t *testing.T, method, path, body, credential string) *httptest.ResponseRecorder {
	t.Helper()

	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequestWithContext(context.Background(), method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func (f *adminFixture) auditPath() string {
	return "/v1/accounts/" + f.accountID.String() + "/admin/audit-log"
}

func (f *adminFixture) revokeOnePath() string {
	return "/v1/accounts/" + f.accountID.String() + "/admin/invitations/" + id.MustNew().String()
}

func (f *adminFixture) revokeAllPath() string {
	return "/v1/accounts/" + f.accountID.String() + "/admin/invitation-revocations"
}


func TestTheAdminRoutesAnswer(t *testing.T) {
	t.Parallel()

	t.Run("the audit trail", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixture(t)
		f.admin.records = []admin.Record{{
			ID: id.MustNew(), AccountID: f.accountID, Action: admin.ActionInvitationRevoked,
			ActorUserID: f.memberID, ActorKeyID: id.MustNew(), Target: id.MustNew().String(),
			Affected: 1, TraceID: "trace-abc",
			OccurredAt: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC),
		}}

		rec := f.adminSend(t, http.MethodGet, f.auditPath(), "", f.token)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("Content-Type = %q, want JSON", ct)
		}

		var got auditLogResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("the body is not JSON: %v; body: %s", err, rec.Body)
		}
		if len(got.Entries) != 1 {
			t.Fatalf("got %d entries, want 1", len(got.Entries))
		}
		one := got.Entries[0]
		if one.Action != string(admin.ActionInvitationRevoked) {
			t.Errorf("action = %q", one.Action)
		}
		if one.Affected != 1 {
			t.Errorf("affected = %d, want 1", one.Affected)
		}
		if one.ActorKeyID == "" || one.ActorUserID == "" {
			t.Error("the record does not name the credential and the user that acted")
		}
		var raw map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
			t.Fatal(err)
		}
		for _, entry := range raw["entries"].([]any) {
			for _, field := range []string{"token", "secret", "bearer", "jwt", "password", "digest"} {
				if _, present := entry.(map[string]any)[field]; present {
					t.Errorf("the audit entry has a %q field. This response is what an operator copies "+
						"into an incident ticket, and a shape with a credential field is one somebody "+
						"will eventually populate", field)
				}
			}
		}
	})

	t.Run("revoking one invitation", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixture(t)
		rec := f.adminSend(t, http.MethodDelete, f.revokeOnePath(), "", f.token)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204; body: %s", rec.Code, rec.Body)
		}
		if rec.Body.Len() != 0 {
			t.Errorf("a 204 carried a body: %s", rec.Body)
		}
		if !f.admin.sawRevokeOne {
			t.Error("the use case was not reached")
		}
		if f.admin.lastActor.KeyID.IsZero() {
			t.Error("the actor carries no key id, so the audit record would name no credential")
		}
		if f.admin.lastActor.UserID != f.memberID {
			t.Errorf("actor user = %s, want the caller %s", f.admin.lastActor.UserID, f.memberID)
		}
	})

	t.Run("revoking many", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixture(t)
		f.admin.revokedMany = 2
		ids := []string{id.MustNew().String(), id.MustNew().String()}

		body := `{"invitation_ids":["` + ids[0] + `","` + ids[1] + `"],"confirm":true}`
		rec := f.adminSend(t, http.MethodPost, f.revokeAllPath(), body, f.token)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
		}

		var got bulkRevokeResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("the body is not JSON: %v", err)
		}
		if got.Requested != 2 || got.Revoked != 2 {
			t.Errorf("requested = %d, revoked = %d; want 2 and 2", got.Requested, got.Revoked)
		}
	})
}


func TestNoAdminRouteIsReachableWithASessionAlone(t *testing.T) {
	t.Parallel()

	routes := []struct {
		name   string
		method string
		path   func(*adminFixture) string
		body   string
	}{
		{
			name: "read the audit trail", method: http.MethodGet,
			path: func(f *adminFixture) string { return f.auditPath() },
		},
		{
			name: "revoke one invitation", method: http.MethodDelete,
			path: func(f *adminFixture) string { return f.revokeOnePath() },
		},
		{
			name:   "revoke many invitations",
			method: http.MethodPost,
			path:   func(f *adminFixture) string { return f.revokeAllPath() },
			body:   `{"invitation_ids":["` + id.MustNew().String() + `"],"confirm":true}`,
		},
	}

	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			t.Parallel()
			f := newAdminFixture(t)

			rec := f.adminSend(t, route.method, route.path(f), route.body, f.session)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("a browser session reached %s %s = %d, want 403; body: %s",
					route.method, route.path(f), rec.Code, rec.Body)
			}
			p := decodeProblem(t, rec)
			if p.Code != CodeForbidden {
				t.Errorf("code = %q, want %q", p.Code, CodeForbidden)
			}
			if f.admin.sawList || f.admin.sawRevokeOne || f.admin.sawRevokeMany {
				t.Error("a session reached the admin use case. A 403 is the right answer, but a 403 " +
					"written by a handler that had already performed the action is not a refusal")
			}
		})
	}
}

func TestTheSessionRefusalIsSpecificEnoughToActOn(t *testing.T) {
	t.Parallel()

	f := newAdminFixture(t)
	rec := f.adminSend(t, http.MethodGet, f.auditPath(), "", f.session)

	p := decodeProblem(t, rec)
	if !strings.Contains(p.Detail, "api key") {
		t.Errorf("detail = %q; it should say the surface wants a scoped api key, so a reader knows "+
			"the fix is a different credential rather than a different role", p.Detail)
	}
	for _, leak := range []string{"token=", f.session, apiKeySecret} {
		if strings.Contains(p.Detail, leak) {
			t.Errorf("the refusal detail contains %q", leak)
		}
	}
}


func TestATokenWithNoAccountIsRefused(t *testing.T) {
	t.Parallel()

	routes := []struct {
		name   string
		method string
		path   func(*adminFixture) string
		body   string
	}{
		{
			name: "read the audit trail", method: http.MethodGet,
			path: func(f *adminFixture) string { return f.auditPath() },
		},
		{
			name: "revoke one invitation", method: http.MethodDelete,
			path: func(f *adminFixture) string { return f.revokeOnePath() },
		},
		{
			name:   "revoke many invitations",
			method: http.MethodPost,
			path:   func(f *adminFixture) string { return f.revokeAllPath() },
			body:   `{"invitation_ids":["` + id.MustNew().String() + `"],"confirm":true}`,
		},
	}

	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			t.Parallel()

			auth := newFakeAuth()
			accountless := newFakeAPIKeyCaller(auth.user, apikeys.Key{
				ID:     id.MustNew(),
				UserID: auth.user.ID,
				Scopes: apikeys.AllScopes(),
			})
			if !accountless.key.AccountID.IsZero() {
				t.Fatal("the double is not accountless, so this test would prove nothing")
			}

			accountID := id.MustNew()
			adminSvc := &fakeAdmin{revokedOne: 1, revokedMany: 1}
			handler := New(nil,
				WithAuth(auth),
				WithTenancy(adminTenancy(accountID, accounts.RoleAdmin)),
				WithAPIKeyCaller(accountless),
				WithAdmin(adminSvc),
			)

			path := strings.Replace(route.path(&adminFixture{accountID: accountID}), "{", "", 1)
			req := httptest.NewRequestWithContext(context.Background(), route.method, path, strings.NewReader(route.body))
			if route.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			req.Header.Set("Authorization", "Bearer "+apiKeySecret)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code == http.StatusOK || rec.Code == http.StatusNoContent {
				t.Fatalf("a token with NO account reached %s %s = %d. The tenancy check had nothing "+
					"to check and the action was performed anyway; body: %s",
					route.method, path, rec.Code, rec.Body)
			}
			switch rec.Code {
			case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			default:
				t.Errorf("status = %d; a refusal is 401, 403 or 404, and anything else means the request "+
					"failed for a reason that is not the tenancy guard", rec.Code)
			}
			if adminSvc.sawList || adminSvc.sawRevokeOne || adminSvc.sawRevokeMany {
				t.Error("a token with no account_id reached the admin use case")
			}
		})
	}
}


func TestAFailedAuditWriteIsAFiveHundred(t *testing.T) {
	t.Parallel()

	t.Run("revoking one", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixture(t)
		f.admin.revokeOneErr = errAuditFailure

		rec := f.adminSend(t, http.MethodDelete, f.revokeOnePath(), "", f.token)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500. A 204 here would tell the caller the invitation is "+
				"revoked when the rollback means it is not; body: %s", rec.Code, rec.Body)
		}
		p := decodeProblem(t, rec)
		if p.Code != CodeInternal {
			t.Errorf("code = %q, want %q", p.Code, CodeInternal)
		}
		if p.TraceID == "" {
			t.Error("no trace id on the failure; an operator cannot quote what they were given")
		}
		if strings.Contains(p.Detail, "audit") || strings.Contains(p.Detail, "SQL") {
			t.Errorf("the 500 body leaks internals: %q", p.Detail)
		}
	})

	t.Run("revoking many", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixture(t)
		f.admin.revokeManyEr = errAuditFailure

		body := `{"invitation_ids":["` + id.MustNew().String() + `"],"confirm":true}`
		rec := f.adminSend(t, http.MethodPost, f.revokeAllPath(), body, f.token)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body)
		}
	})
}


func TestTheAuditTrailIsNotWritableThroughThisAPI(t *testing.T) {
	t.Parallel()

	const auditPrefix = "/v1/accounts/{accountID}/admin/audit-log"

	mux := newMux(nil, options{
		auth:        newFakeAuth(),
		tenancy:     newFakeTenancy(),
		apiKeys:     newFakeAPIKeys(),
		oidcClients: newFakeOIDCClients(),
		admin:       &fakeAdmin{},
	})

	var found []string
	err := chi.Walk(mux, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if strings.HasPrefix(route, auditPrefix) {
			found = append(found, method+" "+route)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the router: %v", err)
	}

	if len(found) != 1 {
		t.Fatalf("the audit trail is reachable by %d operations (%v), want exactly one GET. Every "+
			"method beyond the read is a way to change the record of what an admin did",
			len(found), found)
	}
	if found[0] != "GET "+auditPrefix {
		t.Errorf("the audit trail's only operation is %q, want a GET", found[0])
	}

	t.Run("the check would notice a DELETE", func(t *testing.T) {
		t.Parallel()

		opts := options{
			auth:        newFakeAuth(),
			tenancy:     newFakeTenancy(),
			apiKeys:     newFakeAPIKeys(),
			admin:       &fakeAdmin{},
			oidcClients: newFakeOIDCClients(),
		}

		injected := chi.NewRouter()
		opts.registerAdminRoutes(injected)
		injected.Delete(auditPrefix, func(http.ResponseWriter, *http.Request) {})

		var methods []string
		if err := chi.Walk(injected, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
			if strings.HasPrefix(route, auditPrefix) {
				methods = append(methods, method)
			}
			return nil
		}); err != nil {
			t.Fatalf("walking the injected router: %v", err)
		}

		var hasDelete bool
		for _, m := range methods {
			if m == http.MethodDelete {
				hasDelete = true
			}
		}
		if !hasDelete {
			t.Fatal("the injected DELETE is not on the audit path, so the assertion above would not " +
				"have caught it and the check is not testing what it claims")
		}
		if len(methods) == 1 {
			t.Error("only one method found, so this subtest did not exercise the failure")
		}
	})
}


// TestTheAuditLogBoundsAreEnforced is R5 at the API, and each case is a value a
// client can actually send.
//
// The over-the-ceiling case is a 422 and NOT a silent clamp, and that is the
// substantive claim: a client that asked for 500 rows and was quietly given 100
// has been told a lie about how much of the trail it has read, and an operator
// building an export would produce a short one without knowing.
func TestTheAuditLogBoundsAreEnforced(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		query     string
		wantCode  int
		wantField string
	}{
		{name: "no limit", query: "", wantCode: http.StatusOK},
		{name: "at the ceiling", query: "?limit=100", wantCode: http.StatusOK},
		{name: "one over the ceiling", query: "?limit=101", wantCode: http.StatusUnprocessableEntity, wantField: "limit"},
		{name: "absurd", query: "?limit=100000", wantCode: http.StatusUnprocessableEntity, wantField: "limit"},
		{name: "zero is the default", query: "?limit=0", wantCode: http.StatusOK},
		{name: "negative", query: "?limit=-1", wantCode: http.StatusUnprocessableEntity, wantField: "limit"},
		{name: "not a number", query: "?limit=lots", wantCode: http.StatusUnprocessableEntity, wantField: "limit"},

		{name: "a forged cursor", query: "?before=not-a-real-cursor", wantCode: http.StatusUnprocessableEntity, wantField: "before"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newAdminFixture(t)

			rec := f.adminSend(t, http.MethodGet, f.auditPath()+tt.query, "", f.token)
			if rec.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantCode, rec.Body)
			}
			if tt.wantField == "" {
				return
			}
			p := decodeProblem(t, rec)
			if p.Code != CodeValidationFailed {
				t.Errorf("code = %q, want %q", p.Code, CodeValidationFailed)
			}
			var named bool
			for _, fe := range p.Errors {
				if fe.Field == tt.wantField {
					named = true
				}
			}
			if !named {
				t.Errorf("the field errors do not name %q: %+v", tt.wantField, p.Errors)
			}
			if f.admin.sawList {
				t.Error("a rejected query reached the use case")
			}
		})
	}
}

func TestTheBulkBoundsAreEnforced(t *testing.T) {
	t.Parallel()

	t.Run("confirm is required", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixture(t)
		body := `{"invitation_ids":["` + id.MustNew().String() + `"]}`
		rec := f.adminSend(t, http.MethodPost, f.revokeAllPath(), body, f.token)

		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422; body: %s", rec.Code, rec.Body)
		}
		if f.admin.sawRevokeMany {
			t.Fatal("a bulk revocation WITHOUT confirmation performed the action. This is the " +
				"off-by-one-is-an-outage case, and the confirmation is what stands between a " +
				"mis-typed request and every pending invitation in the account")
		}
		p := decodeProblem(t, rec)
		var named bool
		for _, fe := range p.Errors {
			if fe.Field == "confirm" {
				named = true
			}
		}
		if !named {
			t.Errorf("the error does not name the confirm field: %+v", p.Errors)
		}
	})

	t.Run("confirm false is the same as absent", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixture(t)
		body := `{"invitation_ids":["` + id.MustNew().String() + `"],"confirm":false}`
		rec := f.adminSend(t, http.MethodPost, f.revokeAllPath(), body, f.token)

		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422", rec.Code)
		}
		if f.admin.sawRevokeMany {
			t.Error("confirm:false performed the action")
		}
	})

	t.Run("an empty array", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixture(t)
		rec := f.adminSend(t, http.MethodPost, f.revokeAllPath(),
			`{"invitation_ids":[],"confirm":true}`, f.token)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422", rec.Code)
		}
		if f.admin.sawRevokeMany {
			t.Error("an empty array performed the action")
		}
	})

	t.Run("one over the ceiling", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixture(t)
		ids := make([]string, 0, admin.MaxBulkInvitationIDs+1)
		for range admin.MaxBulkInvitationIDs + 1 {
			ids = append(ids, `"`+id.MustNew().String()+`"`)
		}
		rec := f.adminSend(t, http.MethodPost, f.revokeAllPath(),
			`{"invitation_ids":[`+strings.Join(ids, ",")+`],"confirm":true}`, f.token)

		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422; body: %s", rec.Code, rec.Body)
		}
		if f.admin.sawRevokeMany {
			t.Errorf("a request of %d ids reached the use case", len(ids))
		}
	})

	t.Run("at the ceiling is allowed", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixture(t)
		ids := make([]string, 0, admin.MaxBulkInvitationIDs)
		for range admin.MaxBulkInvitationIDs {
			ids = append(ids, `"`+id.MustNew().String()+`"`)
		}
		rec := f.adminSend(t, http.MethodPost, f.revokeAllPath(),
			`{"invitation_ids":[`+strings.Join(ids, ",")+`],"confirm":true}`, f.token)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 at the ceiling; body: %s", rec.Code, rec.Body)
		}
	})

	t.Run("a malformed id names the field", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixture(t)
		rec := f.adminSend(t, http.MethodPost, f.revokeAllPath(),
			`{"invitation_ids":["not-a-uuid"],"confirm":true}`, f.token)

		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422; body: %s", rec.Code, rec.Body)
		}
		if f.admin.sawRevokeMany {
			t.Error("a malformed id reached the use case")
		}
		p := decodeProblem(t, rec)
		if len(p.Errors) == 0 || p.Errors[0].Field != "invitation_ids" {
			t.Errorf("the error does not name invitation_ids: %+v", p.Errors)
		}
	})

	t.Run("an unknown field is refused", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixture(t)
		rec := f.adminSend(t, http.MethodPost, f.revokeAllPath(),
			`{"invitation_ids":["`+id.MustNew().String()+`"],"confirm_all":true}`, f.token)

		if rec.Code == http.StatusOK {
			t.Error("an unknown field was accepted; a client that misspelled confirm would have " +
				"revoked every pending invitation believing it had been asked to confirm")
		}
		if f.admin.sawRevokeMany {
			t.Error("the action ran despite an unknown field")
		}
	})
}

func TestTheBulkRouteIsOwnerOnly(t *testing.T) {
	t.Parallel()

	ids := `"` + id.MustNew().String() + `"`
	body := `{"invitation_ids":[` + ids + `],"confirm":true}`

	t.Run("an admin may revoke one", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixtureAs(t, accounts.RoleAdmin)
		rec := f.adminSend(t, http.MethodDelete, f.revokeOnePath(), "", f.token)
		if rec.Code != http.StatusNoContent {
			t.Errorf("an admin revoking one invitation = %d, want 204; body: %s", rec.Code, rec.Body)
		}
	})

	t.Run("an admin may read the trail", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixtureAs(t, accounts.RoleAdmin)
		rec := f.adminSend(t, http.MethodGet, f.auditPath(), "", f.token)
		if rec.Code != http.StatusOK {
			t.Errorf("an admin reading the trail = %d, want 200; body: %s", rec.Code, rec.Body)
		}
	})

	t.Run("an admin may NOT revoke them all", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixtureAs(t, accounts.RoleAdmin)
		rec := f.adminSend(t, http.MethodPost, f.revokeAllPath(), body, f.token)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("an admin revoking every pending invitation = %d, want 403. The bulk route is "+
				"the one where an off-by-one is an outage, and owner is the whole of why; body: %s",
				rec.Code, rec.Body)
		}
		if f.admin.sawRevokeMany {
			t.Fatal("the use case was reached by an admin")
		}
	})

	t.Run("a member may do none of it", func(t *testing.T) {
		t.Parallel()
		f := newAdminFixtureAs(t, accounts.RoleMember)
		for _, tt := range []struct {
			name   string
			method string
			path   string
			body   string
		}{
			{"read the trail", http.MethodGet, f.auditPath(), ""},
			{"revoke one", http.MethodDelete, f.revokeOnePath(), ""},
			{"revoke all", http.MethodPost, f.revokeAllPath(), body},
		} {
			rec := f.adminSend(t, tt.method, tt.path, tt.body, f.token)
			if rec.Code != http.StatusForbidden {
				t.Errorf("a member %s = %d, want 403; body: %s", tt.name, rec.Code, rec.Body)
			}
		}
		if f.admin.sawList || f.admin.sawRevokeOne || f.admin.sawRevokeMany {
			t.Error("a member reached the admin use case")
		}
	})
}

func TestTheSingleRouteNeedsNoConfirmation(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		body string
	}{
		{name: "no body at all", body: ""},
		{name: "an empty object", body: "{}"},
		{name: "a confirmation field, harmlessly ignored", body: `{"confirm":true}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newAdminFixture(t)
			rec := f.adminSend(t, http.MethodDelete, f.revokeOnePath(), tt.body, f.token)
			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want 204; body: %s", rec.Code, rec.Body)
			}
		})
	}
}


func TestTheScopeTableIsTheWholeBoundary(t *testing.T) {
	t.Parallel()

	want := map[string]string{
		"GET /v1/accounts/{accountID}/admin/audit-log":                     apikeys.ScopeAuditLogRead,
		"DELETE /v1/accounts/{accountID}/admin/invitations/{invitationID}": apikeys.ScopeAccountInvitationsWrite,
		"POST /v1/accounts/{accountID}/admin/invitation-revocations":       apikeys.ScopeAccountInvitationsWrite,
	}

	var adminRoutes []string
	for route := range accountRouteScopes {
		if strings.Contains(route, "/admin/") {
			adminRoutes = append(adminRoutes, route)
		}
	}
	if len(adminRoutes) != len(want) {
		t.Errorf("the scope table declares %d admin routes, want %d: %v",
			len(adminRoutes), len(want), adminRoutes)
	}
	for route, scope := range want {
		got, declared := accountRouteScopes[route]
		if !declared {
			t.Errorf("%s has no scope row, so it is CLOSED to tokens. That is the safe direction, but "+
				"it means the route cannot be reached by the credential the admin surface requires, so "+
				"one of these two facts is wrong", route)
			continue
		}
		if got != scope {
			t.Errorf("%s requires %q, want %q", route, got, scope)
		}
	}
}

func TestAnAdminTokenHoldingNeitherScopeIsRefused(t *testing.T) {
	t.Parallel()

	for _, scope := range []string{apikeys.ScopeAccountsRead, apikeys.ScopeAccountsWrite, "invented:scope"} {
		t.Run(scope, func(t *testing.T) {
			t.Parallel()
			f := newAdminFixture(t, scope)

			rec := f.adminSend(t, http.MethodGet, f.auditPath(), "", f.token)
			if rec.Code != http.StatusForbidden {
				t.Errorf("a token with %s reached the audit trail = %d, want 403", scope, rec.Code)
			}
			if f.admin.sawList {
				t.Error("the use case was reached")
			}
		})
	}
}

func TestTheAdminRoutesAreAbsentWithoutTheService(t *testing.T) {
	t.Parallel()

	auth := newFakeAuth()
	handler := New(nil,
		WithAuth(auth),
		WithTenancy(newFakeTenancy()),
		WithAPIKeyCaller(newFakeAPIKeyCaller(auth.user, apikeys.Key{
			ID: id.MustNew(), UserID: auth.user.ID, AccountID: id.MustNew(),
			Scopes: apikeys.AllScopes(),
		})),
	)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/accounts/"+id.MustNew().String()+"/admin/audit-log", nil)
	req.Header.Set("Authorization", "Bearer "+apiKeySecret)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404; body: %s", rec.Code, rec.Body)
	}
}
