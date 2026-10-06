package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/cafaye/identity/internal/accounts"
	"github.com/cafaye/identity/internal/platform/id"
)

// The transfer handler, against a programmable double.
//
// The matrix covers WHICH CALLERS reach this route and with what status. This
// file covers the two things the matrix structurally cannot: what the handler
// hands the use case — in particular that the caller's id comes from the
// credential and the heir's from the body, which is the whole authorization
// story on a route where both ids are about people — and what it writes on the
// way back.

// The response is asserted field by field rather than for status alone, because
// this is a response a client renders a state change from. A transfer that
// returned the heir and not the previous owner would leave the person who made
// the request needing a second round trip to discover what they are now; a
// response carrying `role: owner` on the account would tell them they still run
// it. Both are wrong in a way only the body shows.
func TestTheTransferResponseCarriesBothMembershipsAndTheDemotion(t *testing.T) {
	accountID := id.MustNew()
	heir := id.MustNew()

	fake := newFakeTenancy()
	fake.account = accounts.Account{ID: accountID, Name: "Acme Corp", Slug: "acme-corp"}
	fake.role = accounts.RoleOwner

	auth := newFakeAuth()
	// The caller is the fake session's user, not a local variable: the whole
	// point of this route is that the previous owner is whoever presented the
	// credential, and a test that named its own would not notice if the handler
	// invented one.
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
	// The caller's role on the ACCOUNT, read after the transfer. It is `admin`
	// rather than `owner` because the middleware resolved it before the write,
	// and that is correct: the previous owner no longer owns it.
	if body.Account.Role != accounts.RoleOwner {
		t.Errorf("account.role = %q — it is the role the middleware resolved BEFORE the transfer", body.Account.Role)
	}
	if body.Account.ID != accountID.String() || body.Account.Slug != "acme-corp" {
		t.Errorf("account = %+v, want the path's account unchanged in every field", body.Account)
	}
}

// The two ids this route accepts come from two different places and must never be
// confused. A handler that read the caller out of the body would let anybody who
// can write JSON name themselves as the owner of an account they do not run, and
// the only thing standing between that and a takeover is which field is read.
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

	// The status is asserted BEFORE the recorded call, and that ordering is the
	// fix for a version of this test that read the recorded call and nothing
	// else: when the body below is rejected the handler is never reached, the
	// recorded call is all zeros, and the three assertions pass vacuously. It
	// passed for a whole commit that way — `go test -run Transfer` ran it alone,
	// where a *different* body reached the handler, and the full suite did not.
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

// A body that names an ACTOR is refused outright, and the document says so with
// `additionalProperties: false`.
//
// This is the same property as the test above reached from the other direction,
// and it is here because it is enforced by `decodeBody`'s DisallowUnknownFields
// rather than by this route: there is no `actor` field to honour, so a caller who
// sends one gets a 400 and a use case call with all three ids zero. That is
// stronger than ignoring the field, and it is worth a test that names the
// mechanism — a handler that grew an actor field would still pass the test above
// on a body that did not carry one.
func TestABodyThatNamesAnActorIsRefusedRatherThanHonoured(t *testing.T) {
	accountID := id.MustNew()

	fake := newFakeTenancy()
	fake.account = accounts.Account{ID: accountID, Name: "Acme Corp", Slug: "acme-corp"}
	fake.role = accounts.RoleOwner

	auth := newFakeAuth()
	rec := requestAs(t, New(nil, WithAuth(auth), WithTenancy(fake)), auth.token, http.MethodPost,
		"/v1/accounts/"+accountID.String()+"/ownership-transfers",
		`{"new_owner_user_id":"`+id.MustNew().String()+`","actor":"`+id.MustNew().String()+`"}`)

	// 422 and not 400: the body parsed as JSON and one of its fields is not one
	// this endpoint accepts, which is exactly what decodeBody's
	// DisallowUnknownFields answers with. The status is measured, not assumed —
	// it was 400 in the first draft of this assertion and the test said so.
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body: %s", rec.Code, rec.Body)
	}
	if !fake.transferredFor.AccountID.IsZero() {
		t.Errorf("the use case was reached (%+v) for a body carrying an actor field", fake.transferredFor)
	}
}

// The three refusals, each with its own status and its own code. Two of them
// share a 422 and they still must not share a code: `not_transferable` is a
// statement about the account and `transfer_to_self` is about the request, and a
// client that cannot tell them apart will offer the wrong advice for one of them.
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
			// A stranger is a 404, not a 403: this operation cannot admit anybody,
			// so naming somebody who is not a member is the same answer a stranger
			// gets, and nothing here is a statement about whether the account
			// exists.
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

// A new_owner_user_id that is not an id this service issued is a 404 and not a
// 422. The rule is the one every path id in this service follows — "this is not an
// id we issued" and "this is one and you may not have it" are not distinguishable
// from outside — and a 422 here would make the request body a probing surface.
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

	// And the use case was never reached — a 404 that had already called the
	// service would mean the refusal is decided after a write attempt.
	if !fake.transferredFor.AccountID.IsZero() {
		t.Errorf("the use case was called for %+v on a malformed heir; the 404 happens first", fake.transferredFor)
	}
}

// A database failure is a 500, not a 422. An error that is not one of the three
// refusals above is an outage, and answering it with a semantic failure would
// tell a client the account cannot be transferred when it may well be
// transferable once the database is back.
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
