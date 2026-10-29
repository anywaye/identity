package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/anywaye/identity/internal/accounts"
	"github.com/anywaye/identity/internal/platform/id"
)


func TestTheTransferResponseCarriesBothMembershipsAndTheDemotion(t *testing.T) {
	accountID := id.MustNew()
	heir := id.MustNew()

	fake := newFakeTenancy()
	fake.account = accounts.Account{ID: accountID, Name: "Acme Corp", Slug: "acme-corp"}
	fake.role = accounts.RoleOwner

	auth := newFakeAuth()
	owner := auth.user.ID
	h := New(nil, WithAuth(auth), WithTenancy(fake))

	rec := requestAs(t, h, auth.token, http.MethodPost,
		"/v1/accounts/"+accountID.String()+"/ownership-transfers",
		`{"new_owner_user_id":"`+heir.String()+`"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}

	var body ownershipTransferResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding the response: %v; body: %s", err, rec.Body)
	}

	if body.NewOwner.UserID != heir.String() {
		t.Errorf("new_owner.user_id = %s, want the heir %s", body.NewOwner.UserID, heir)
	}
	if body.NewOwner.Role != accounts.RoleOwner {
		t.Errorf("new_owner.role = %q, want owner", body.NewOwner.Role)
	}
	if body.PreviousOwner.UserID != owner.String() {
		t.Errorf("previous_owner.user_id = %s, want the caller %s", body.PreviousOwner.UserID, owner)
	}
	if body.PreviousOwner.Role != accounts.RoleAdmin {
		t.Errorf("previous_owner.role = %q, want admin — the demotion is the answer this route owes the caller", body.PreviousOwner.Role)
	}
	if body.Account.Role != accounts.RoleOwner {
		t.Errorf("account.role = %q — it is the role the middleware resolved BEFORE the transfer", body.Account.Role)
	}
	if body.Account.ID != accountID.String() || body.Account.Slug != "acme-corp" {
		t.Errorf("account = %+v, want the path's account unchanged in every field", body.Account)
	}
}

func TestTheCallerComesFromTheCredentialAndTheHeirFromTheBody(t *testing.T) {
	accountID := id.MustNew()

	fake := newFakeTenancy()
	fake.account = accounts.Account{ID: accountID, Name: "Acme Corp", Slug: "acme-corp"}
	fake.role = accounts.RoleOwner

	auth := newFakeAuth()
	h := New(nil, WithAuth(auth), WithTenancy(fake))

	heir := id.MustNew()
	rec := requestAs(t, h, auth.token, http.MethodPost,
		"/v1/accounts/"+accountID.String()+"/ownership-transfers",
		`{"new_owner_user_id":"`+heir.String()+`"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	got := fake.transferredFor
	if got.Actor != auth.user.ID {
		t.Errorf("the use case was given Actor = %s, want the authenticated user %s — the actor is never read from the body", got.Actor, auth.user.ID)
	}
	if got.Heir != heir {
		t.Errorf("the use case was given Heir = %s, want %s from the body", got.Heir, heir)
	}
	if got.AccountID != accountID {
		t.Errorf("the use case was given AccountID = %s, want the path's %s", got.AccountID, accountID)
	}
}

func TestABodyThatNamesAnActorIsRefusedRatherThanHonoured(t *testing.T) {
	accountID := id.MustNew()

	fake := newFakeTenancy()
	fake.account = accounts.Account{ID: accountID, Name: "Acme Corp", Slug: "acme-corp"}
	fake.role = accounts.RoleOwner

	auth := newFakeAuth()
	rec := requestAs(t, New(nil, WithAuth(auth), WithTenancy(fake)), auth.token, http.MethodPost,
		"/v1/accounts/"+accountID.String()+"/ownership-transfers",
		`{"new_owner_user_id":"`+id.MustNew().String()+`","actor":"`+id.MustNew().String()+`"}`)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body: %s", rec.Code, rec.Body)
	}
	if !fake.transferredFor.AccountID.IsZero() {
		t.Errorf("the use case was reached (%+v) for a body carrying an actor field", fake.transferredFor)
	}
}

func TestTheTransferRefusalsEachCarryTheirOwnCode(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "a non-owner is a 403",
			err:        accounts.ErrNotOwner,
			wantStatus: http.StatusForbidden,
			wantCode:   CodeForbidden,
		},
		{
			name:       "a personal or one-member account is a 422",
			err:        accounts.ErrNotTransferable,
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   CodeValidationFailed,
		},
		{
			name:       "naming yourself is its own 422",
			err:        accounts.ErrTransferToSelf,
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   CodeValidationFailed,
		},
		{
			name:       "a target who is not a member is a 404",
			err:        accounts.ErrNotAMember,
			wantStatus: http.StatusNotFound,
			wantCode:   CodeNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accountID := id.MustNew()
			fake := newFakeTenancy()
			fake.account = accounts.Account{ID: accountID, Name: "Acme Corp", Slug: "acme-corp"}
			fake.role = accounts.RoleOwner
			fake.transferErr = tt.err

			auth := newFakeAuth()
			rec := requestAs(t, New(nil, WithAuth(auth), WithTenancy(fake)), auth.token, http.MethodPost,
				"/v1/accounts/"+accountID.String()+"/ownership-transfers",
				`{"new_owner_user_id":"`+id.MustNew().String()+`"}`)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body)
			}
			if code := decodeProblem(t, rec).Code; code != tt.wantCode {
				t.Errorf("code = %q, want %q", code, tt.wantCode)
			}
		})
	}
}

func TestAMalformedHeirIsRefusedLikeAnInvisibleAccount(t *testing.T) {
	accountID := id.MustNew()
	fake := newFakeTenancy()
	fake.account = accounts.Account{ID: accountID, Name: "Acme Corp", Slug: "acme-corp"}
	fake.role = accounts.RoleOwner

	auth := newFakeAuth()
	h := New(nil, WithAuth(auth), WithTenancy(fake))

	for _, body := range []string{
		`{"new_owner_user_id":"not-a-uuid"}`,
		`{"new_owner_user_id":""}`,
		`{"new_owner_user_id":"00000000-0000-0000-0000-000000000000"}`,
	} {
		rec := requestAs(t, h, auth.token, http.MethodPost,
			"/v1/accounts/"+accountID.String()+"/ownership-transfers", body)

		if rec.Code != http.StatusNotFound {
			t.Errorf("%s = %d, want 404; body: %s", body, rec.Code, rec.Body)
		}
	}

	if !fake.transferredFor.AccountID.IsZero() {
		t.Errorf("the use case was called for %+v on a malformed heir; the 404 happens first", fake.transferredFor)
	}
}

func TestAnUnexpectedTransferFailureIsA500(t *testing.T) {
	accountID := id.MustNew()
	fake := newFakeTenancy()
	fake.account = accounts.Account{ID: accountID, Name: "Acme Corp", Slug: "acme-corp"}
	fake.role = accounts.RoleOwner
	fake.transferErr = errors.New("the connection pool is exhausted")

	auth := newFakeAuth()
	rec := requestAs(t, New(nil, WithAuth(auth), WithTenancy(fake)), auth.token, http.MethodPost,
		"/v1/accounts/"+accountID.String()+"/ownership-transfers",
		`{"new_owner_user_id":"`+id.MustNew().String()+`"}`)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body)
	}
}
