package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"log/slog"

	"github.com/anywaye/identity/internal/accounts"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/users"
)


func TestTenancyStatusCodes(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "a not-found is a 404",
			err:        accounts.ErrNotFound,
			wantStatus: http.StatusNotFound,
			wantCode:   CodeNotFound,
		},
		{
			name:       "not being a member is a 404, not a 403",
			err:        accounts.ErrNotAMember,
			wantStatus: http.StatusNotFound,
			wantCode:   CodeNotFound,
		},
		{
			name:       "a taken slug is a 409",
			err:        accounts.ErrSlugTaken,
			wantStatus: http.StatusConflict,
			wantCode:   CodeConflict,
		},
		{
			name:       "an existing membership is a 409",
			err:        accounts.ErrAlreadyAMember,
			wantStatus: http.StatusConflict,
			wantCode:   CodeConflict,
		},
		{
			name:       "a pending invitation already exists is a 409",
			err:        accounts.ErrInvitationEmailTaken,
			wantStatus: http.StatusConflict,
			wantCode:   CodeConflict,
		},
		{
			name:       "an expired invitation is a 410",
			err:        accounts.ErrInvitationExpired,
			wantStatus: http.StatusGone,
			wantCode:   CodeGone,
		},
		{
			name:       "a spent invitation is a 410",
			err:        accounts.ErrInvitationUsed,
			wantStatus: http.StatusGone,
			wantCode:   CodeGone,
		},
		{
			name:       "a wrong token is a 404",
			err:        accounts.ErrInvitationNotFound,
			wantStatus: http.StatusNotFound,
			wantCode:   CodeNotFound,
		},
		{
			name:       "demoting the only owner is a 422",
			err:        accounts.ErrSelfRoleChange,
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   CodeValidationFailed,
		},
		{
			name:       "removing the only owner is a 422",
			err:        accounts.ErrLastOwner,
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   CodeValidationFailed,
		},
		{
			name:       "an admin removing an owner is a 403",
			err:        accounts.ErrOwnerProtected,
			wantStatus: http.StatusForbidden,
			wantCode:   CodeForbidden,
		},
		{
			name:       "inviting an owner is a 422",
			err:        accounts.ErrRoleNotInvitable,
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   CodeValidationFailed,
		},
		{
			name:       "a field error is a 422 with errors[]",
			err:        &accounts.FieldError{Field: "name", Code: accounts.CodeRequired},
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   CodeValidationFailed,
		},
		{
			name:       "a users field error is a 422 too",
			err:        &users.FieldError{Field: "email", Code: users.CodeInvalidFormat},
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   CodeValidationFailed,
		},
		{
			name:       "anything else is a 500",
			err:        errors.New("the connection pool is exhausted"),
			wantStatus: http.StatusInternalServerError,
			wantCode:   CodeInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeTenancy()
			fake.createErr = tt.err
			auth := newFakeAuth()
			rec := requestAs(t, New(nil, WithAuth(auth), WithTenancy(fake)), auth.token,
				http.MethodPost, "/v1/accounts", `{"name":"Acme"}`)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body)
			}
			p := decodeProblem(t, rec)
			if p.Code != tt.wantCode {
				t.Errorf("code = %q, want %q", p.Code, tt.wantCode)
			}
			if p.Status != tt.wantStatus {
				t.Errorf("the body's status = %d, want %d — they must agree with the response line", p.Status, tt.wantStatus)
			}
			if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
				t.Errorf("Content-Type = %q, want application/problem+json", got)
			}
			if tt.wantStatus == http.StatusUnprocessableEntity {
				if len(p.Errors) == 0 {
					t.Error("a 422 with no errors[]; core scopes that array to 422 and it is empty")
				}
			} else if p.Errors != nil {
				t.Errorf("errors = %v on a %d; core scopes errors[] to 422", p.Errors, tt.wantStatus)
			}
		})
	}
}

func TestTenancyInternalErrorsAreLoggedNotReturned(t *testing.T) {
	fake := newFakeTenancy()
	fake.createErr = errors.New("dial tcp 10.0.0.5:5432: connection refused")

	auth := newFakeAuth()
	rec := requestAs(t, New(nil, WithAuth(auth), WithTenancy(fake)), auth.token,
		http.MethodPost, "/v1/accounts", `{"name":"Acme"}`)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "10.0.0.5") {
		t.Errorf("the 500 body leaks an internal address: %s", rec.Body)
	}
	p := decodeProblem(t, rec)
	if p.TraceID == "" {
		t.Error("the 500 carries no trace id, so support has nothing to quote")
	}
	if p.TraceID != rec.Header().Get(TraceHeader) {
		t.Errorf("the body's trace_id %q does not match the header %q", p.TraceID, rec.Header().Get(TraceHeader))
	}
}

func TestRequireAccountRoleDistinguishesInvisibleFromForbidden(t *testing.T) {
	accountID := id.MustNew()
	auth := newFakeAuth()

	tests := []struct {
		name       string
		role       accounts.Role
		min        accounts.Role
		lookupErr  error
		wantStatus int
	}{
		{name: "a member meets the member minimum", role: accounts.RoleMember, min: accounts.RoleMember, wantStatus: http.StatusOK},
		{name: "an admin meets the member minimum", role: accounts.RoleAdmin, min: accounts.RoleMember, wantStatus: http.StatusOK},
		{name: "an owner meets the owner minimum", role: accounts.RoleOwner, min: accounts.RoleOwner, wantStatus: http.StatusOK},
		{name: "a member does not meet the admin minimum", role: accounts.RoleMember, min: accounts.RoleAdmin, wantStatus: http.StatusForbidden},
		{name: "an admin does not meet the owner minimum", role: accounts.RoleAdmin, min: accounts.RoleOwner, wantStatus: http.StatusForbidden},
		{
			name:       "no membership is a 404, whatever the minimum",
			role:       accounts.RoleMember,
			min:        accounts.RoleMember,
			lookupErr:  accounts.ErrNotAMember,
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "no membership is a 404 even for the owner minimum",
			role:       accounts.RoleMember,
			min:        accounts.RoleOwner,
			lookupErr:  accounts.ErrNotAMember,
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "a lookup failure is a 500",
			role:       accounts.RoleMember,
			min:        accounts.RoleMember,
			lookupErr:  errors.New("the connection pool is exhausted"),
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeTenancy()
			fake.getErr = tt.lookupErr
			fake.account = accounts.Account{ID: accountID, Name: "Acme", Slug: "acme"}
			fake.role = tt.role

			rec := requestAs(t, probeRouter(auth, fake, tt.min),
				auth.token, http.MethodGet, "/probe/"+accountID.String(), "")

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body)
			}
			switch tt.wantStatus {
			case http.StatusNotFound:
				if code := decodeProblem(t, rec).Code; code != CodeNotFound {
					t.Errorf("code = %q, want %q", code, CodeNotFound)
				}
			case http.StatusForbidden:
				if code := decodeProblem(t, rec).Code; code != CodeForbidden {
					t.Errorf("code = %q, want %q", code, CodeForbidden)
				}
			}
		})
	}
}

func probeRouter(a Auth, ten Tenancy, min accounts.Role) http.Handler {
	opts := options{
		auth:    a,
		tenancy: ten,
		logger:  slog.New(slog.DiscardHandler),
	}
	r := chi.NewRouter()
	r.Get("/probe/{accountID}", opts.requireAccountRole(min, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"reached": "the handler"})
	}))
	return traceMiddleware(r)
}

func TestTheTwoDenialsDoNotLeakExistence(t *testing.T) {
	accountID := id.MustNew()
	auth := newFakeAuth()

	denial := func(role accounts.Role, min accounts.Role, lookupErr error) string {
		fake := newFakeTenancy()
		fake.getErr = lookupErr
		fake.account = accounts.Account{ID: accountID, Name: "Secret Project", Slug: "secret-project"}
		fake.role = role

		rec := requestAs(t, probeRouter(auth, fake, min),
			auth.token, http.MethodGet, "/probe/"+accountID.String(), "")
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 or 404", rec.Code)
		}
		return rec.Body.String()
	}

	bodies := map[string]string{
		"not a member":     denial(accounts.RoleMember, accounts.RoleMember, accounts.ErrNotAMember),
		"under-privileged": denial(accounts.RoleMember, accounts.RoleAdmin, nil),
	}

	for label, body := range bodies {
		if strings.Contains(body, "secret-project") {
			t.Errorf("a %s denial names the account's slug: %s", label, body)
		}
		if strings.Contains(body, "Secret Project") {
			t.Errorf("a %s denial names the account: %s", label, body)
		}
	}
}

func TestTenancyRoutesAreAbsentWithoutTenancy(t *testing.T) {
	h := New(nil, WithAuth(newFakeAuth()))

	for _, path := range []string{
		"/v1/accounts",
		"/v1/accounts/" + id.MustNew().String(),
		"/v1/accounts/" + id.MustNew().String() + "/invitations",
		"/v1/accounts/" + id.MustNew().String() + "/members/" + id.MustNew().String(),
		"/v1/invitations/accept",
	} {
		rec := request(t, h, http.MethodGet, path, "")
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s with no tenancy service = %d, want 404 — the route should not be mounted", path, rec.Code)
		}
	}
}

func TestAccountResponseShape(t *testing.T) {
	accountID := id.MustNew()
	created := testInstant

	fake := newFakeTenancy()
	fake.account = accounts.Account{
		ID: accountID, Name: "Acme Corp", Slug: "acme-corp", Personal: false,
		CreatedAt: created, UpdatedAt: created,
	}
	fake.role = accounts.RoleAdmin
	fake.members = []accounts.MemberSummary{
		{Account: fake.account, Role: accounts.RoleOwner},
		{Account: fake.account, Role: accounts.RoleAdmin},
	}

	auth := newFakeAuth()
	rec := requestAs(t, New(nil, WithAuth(auth), WithTenancy(fake)), auth.token,
		http.MethodGet, "/v1/accounts/"+accountID.String(), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	var body accountResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not JSON: %v\n%s", err, rec.Body)
	}
	if body.ID != accountID.String() || body.Name != "Acme Corp" || body.Slug != "acme-corp" {
		t.Errorf("body = %+v, want the account that was created", body)
	}
	if body.Role != accounts.RoleAdmin {
		t.Errorf("role = %q, want the caller's own role %q", body.Role, accounts.RoleAdmin)
	}
	if len(body.Members) != 2 {
		t.Errorf("members = %+v, want 2 entries", body.Members)
	}
	if !body.CreatedAt.Equal(created) {
		t.Errorf("created_at = %s, want %s", body.CreatedAt, created)
	}
}

func TestAccountListIsAnArrayNotNull(t *testing.T) {
	fake := newFakeTenancy()
	fake.list = []accounts.MemberSummary{}

	auth := newFakeAuth()
	rec := requestAs(t, New(nil, WithAuth(auth), WithTenancy(fake)), auth.token, http.MethodGet, "/v1/accounts", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	var body []accountListItem
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not a JSON array: %v\n%s", err, rec.Body)
	}
	if len(body) != 0 {
		t.Errorf("body = %+v, want an empty array", body)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != "[]" {
		t.Errorf("an empty list rendered as %q, want []", got)
	}
}

func TestEveryMemberInAMemberListIdentifiesItself(t *testing.T) {
	accountID, ownerID, memberID, adminID := id.MustNew(), id.MustNew(), id.MustNew(), id.MustNew()
	joined := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
	account := accounts.Account{ID: accountID, Name: "Acme Corp", Slug: "acme-corp", CreatedAt: joined, UpdatedAt: joined}

	fake := newFakeTenancy()
	fake.account = account
	fake.role = accounts.RoleOwner
	fake.members = []accounts.MemberSummary{
		{Account: account, UserID: adminID, JoinedAt: joined, Role: accounts.RoleAdmin},
		{Account: account, UserID: ownerID, JoinedAt: joined, Role: accounts.RoleOwner},
		{Account: account, UserID: memberID, JoinedAt: joined, Role: accounts.RoleMember},
	}

	auth := newFakeAuth()
	handler := New(nil, WithAuth(auth), WithTenancy(fake))

	for _, target := range []string{
		"/v1/accounts/" + accountID.String(),
		"/v1/accounts/" + accountID.String() + "/members",
	} {
		rec := requestAs(t, handler, auth.token, http.MethodGet, target, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200; body: %s", target, rec.Code, rec.Body)
		}

		var envelope struct {
			Members     []membershipResponse `json:"members"`
			Memberships []membershipResponse `json:"memberships"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
			t.Fatalf("GET %s is not JSON: %v\n%s", target, err, rec.Body)
		}
		got := envelope.Members
		if got == nil {
			got = envelope.Memberships
		}

		if len(got) != 3 {
			t.Fatalf("GET %s returned %d membership(s), want 3; body: %s", target, len(got), rec.Body)
		}
		seen := map[string]accounts.Role{}
		for _, m := range got {
			if m.UserID == "" {
				t.Errorf("GET %s — a membership carries no user_id: %+v\n"+
					"The two other routes that act on a member are "+
					"PATCH and DELETE /v1/accounts/{account_id}/members/{user_id}, so an entry "+
					"without one cannot be acted on by anything.", target, m)
				continue
			}
			if m.AccountID != accountID.String() {
				t.Errorf("GET %s — membership.account_id = %q, want %q", target, m.AccountID, accountID)
			}
			if m.CreatedAt.IsZero() {
				t.Errorf("GET %s — membership for %s has a zero created_at; it is when this user "+
					"joined, and a client rendering a member list shows it", target, m.UserID)
			}
			seen[m.UserID] = m.Role
		}
		for user, role := range map[id.UUID]accounts.Role{
			ownerID: accounts.RoleOwner, memberID: accounts.RoleMember, adminID: accounts.RoleAdmin,
		} {
			if seen[user.String()] != role {
				t.Errorf("GET %s — no entry for %s with role %q; the list read %v",
					target, user, role, seen)
			}
		}
	}
}

func TestInvitationResponseCarriesTheTokenOnce(t *testing.T) {
	accountID := id.MustNew()
	fake := newFakeTenancy()
	fake.invite = accounts.Invited{
		Invitation: accounts.Invitation{
			ID:          id.MustNew(),
			AccountID:   accountID,
			Email:       "invitee@example.com",
			Role:        accounts.RoleMember,
			ExpiresAt:   time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC),
			TokenDigest: "0f7c" + strings.Repeat("a", 60),
		},
		Token: "the-one-time-token",
	}

	auth := newFakeAuth()
	fake.role = accounts.RoleAdmin
	rec := requestAs(t, New(nil, WithAuth(auth), WithTenancy(fake)), auth.token,
		http.MethodPost, "/v1/accounts/"+accountID.String()+"/invitations",
		`{"email":"invitee@example.com","role":"member"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", rec.Code, rec.Body)
	}

	var body invitationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	if body.Token != "the-one-time-token" {
		t.Errorf("token = %q, want the one-time token", body.Token)
	}
	if strings.Contains(rec.Body.String(), fake.invite.Invitation.TokenDigest) {
		t.Errorf("the response carries the stored digest: %s", rec.Body)
	}
}

func TestAcceptInvitationReturnsTheMembership(t *testing.T) {
	accountID := id.MustNew()
	userID := id.MustNew()
	acceptedAt := testInstant

	fake := newFakeAuth()
	tenancy := newFakeTenancy()
	tenancy.accepted = accounts.Membership{
		AccountID: accountID, UserID: userID, Role: accounts.RoleAdmin, CreatedAt: acceptedAt,
	}

	rec := requestAs(t, New(nil, WithAuth(fake), WithTenancy(tenancy)), fake.token,
		http.MethodPost, "/v1/invitations/accept", `{"token":"a-token"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	var body membershipResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not JSON: %v", err)
	}
	if body.AccountID != accountID.String() || body.UserID != userID.String() || body.Role != accounts.RoleAdmin {
		t.Errorf("body = %+v, want the membership that was created", body)
	}
}

func TestAcceptInvitationAnswersTheDocumentedStatuses(t *testing.T) {
	cases := map[string]struct {
		err  error
		want int
	}{
		"a revoked invitation, and a token that never existed": {accounts.ErrInvitationNotFound, http.StatusNotFound},
		"one that expired":                 {accounts.ErrInvitationExpired, http.StatusGone},
		"one already accepted":             {accounts.ErrInvitationUsed, http.StatusGone},
		"a membership that already exists": {accounts.ErrAlreadyAMember, http.StatusConflict},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fake := newFakeAuth()
			tenancy := newFakeTenancy()
			tenancy.acceptErr = tc.err

			rec := requestAs(t, New(nil, WithAuth(fake), WithTenancy(tenancy)), fake.token,
				http.MethodPost, "/v1/invitations/accept", `{"token":"a-token"}`)
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d; body: %s", rec.Code, tc.want, rec.Body)
			}
		})
	}
}

func TestMalformedAccountIDIsNotFound(t *testing.T) {
	for _, path := range []string{
		"/v1/accounts/not-a-uuid",
		"/v1/accounts/12345",
		"/v1/accounts/00000000-0000-0000-0000-000000000000",
		"/v1/accounts/../../../etc/passwd",
		"/v1/accounts/%2e%2e%2f%2e%2e",
	} {
		t.Run(path, func(t *testing.T) {
			auth := newFakeAuth()
			rec := requestAs(t, New(nil, WithAuth(auth), WithTenancy(newFakeTenancy())),
				auth.token, http.MethodGet, path, "")
			if rec.Code != http.StatusNotFound {
				t.Errorf("GET %s = %d, want 404; body: %s", path, rec.Code, rec.Body)
			}
		})
	}
}

func TestRoleBodyErrorsAreFieldErrors(t *testing.T) {
	accountID := id.MustNew()
	userID := id.MustNew()
	fakeAuth := newFakeAuth()

	tests := []struct {
		name     string
		body     string
		wantCode string
	}{
		{name: "an unknown role", body: `{"role":"superuser"}`, wantCode: accounts.CodeUnknownRole},
		{name: "an empty role", body: `{"role":""}`, wantCode: accounts.CodeUnknownRole},
		{name: "a role with the wrong case", body: `{"role":"Admin"}`, wantCode: accounts.CodeUnknownRole},
		{name: "no role at all", body: `{}`, wantCode: accounts.CodeUnknownRole},
		{name: "a role with trailing space", body: `{"role":"member "}`, wantCode: accounts.CodeUnknownRole},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tenancy := newFakeTenancy()
			tenancy.role = accounts.RoleOwner

			path := fmt.Sprintf("/v1/accounts/%s/members/%s", accountID, userID)
			rec := requestAs(t, New(nil, WithAuth(fakeAuth), WithTenancy(tenancy)),
				fakeAuth.token, http.MethodPatch, path, tt.body)

			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422; body: %s", rec.Code, rec.Body)
			}
			p := decodeProblem(t, rec)
			found := false
			for _, fe := range p.Errors {
				if fe.Field == "role" && fe.Code == tt.wantCode {
					found = true
				}
			}
			if !found {
				t.Errorf("errors = %+v, want an entry for role/%s", p.Errors, tt.wantCode)
			}
		})
	}
}

func TestRoleOfTheWrongJSONTypeIs400(t *testing.T) {
	auth := newFakeAuth()
	tenancy := newFakeTenancy()
	tenancy.role = accounts.RoleOwner

	path := fmt.Sprintf("/v1/accounts/%s/members/%s", id.MustNew(), id.MustNew())
	rec := requestAs(t, New(nil, WithAuth(auth), WithTenancy(tenancy)),
		auth.token, http.MethodPatch, path, `{"role":7}`)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body: %s", rec.Code, rec.Body)
	}
	if code := decodeProblem(t, rec).Code; code != CodeInvalidJSON {
		t.Errorf("code = %q, want %q", code, CodeInvalidJSON)
	}
}
