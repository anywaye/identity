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

	authsvc "github.com/cafaye/identity/internal/auth"
	"github.com/cafaye/identity/internal/deletion"
	"github.com/cafaye/identity/internal/platform/clock"
)

// # THE HTTP HALF OF THE DELETION.
//
// `internal/deletion` proves the transaction against the real policies and
// `internal/httpapi` proves the route. The split is not tidiness: the service
// tests have no session, no problem document and no status code, so "a deletion
// nobody can invoke" and "a deletion that answers 204" are indistinguishable
// there.
//
// # WHY THESE USE A FAKE AND NOT A DATABASE
//
// The properties here are about the RESPONSE — which status, which content type,
// which problem code, and what an anonymous caller learns — and a fake service is
// what makes them assertable at all. The end-to-end shape, including that the row
// is actually gone and the credentials actually stopped working, is
// `internal/deletion/deletion_rls_test.go`'s, against the real policies.

// fakeDeletion records the call and answers whatever it was told to.
type fakeDeletion struct {
	calls []deletion.DeleteInput
	err   error
	// onDelete runs against the router, so a test can assert that the session
	// that made the request stops working AS A RESULT of it — which is the only
	// version of "the credentials are revoked" a caller can observe.
	onDelete func()
}

func (f *fakeDeletion) Delete(_ context.Context, in deletion.DeleteInput) error {
	f.calls = append(f.calls, in)
	if f.onDelete != nil {
		f.onDelete()
	}
	return f.err
}

// newFakeDeletion is the double every route walk mounts. It exists here rather
// than in the file that owns `newFakeAuth` because the walks' options literals are
// a completeness obligation on whoever adds a surface, and the least error-prone
// way to add one is for the constructor to already exist.
func newFakeDeletion() *fakeDeletion { return &fakeDeletion{} }

// deletionRouter is the router with every surface mounted, so `DELETE /v1/me` is
// visible to the walks. The `deletion` field is the point: a walk whose options
// literal omits it sees no deletion route at all, which is how
// `TestEveryServedRouteIsDocumentedOrNamed` once went green with three
// undocumented operations mounted — the reason AGENTS.md calls a struct literal
// that configures a check a completeness obligation.
func deletionRouter(t *testing.T, d Deletion) http.Handler {
	t.Helper()

	return New(nil,
		WithAuth(newFakeAuth()),
		WithDeletion(d),
		WithClock(deletionClock()),
	)
}

// deletionClock is one fixed instant, so the assertion that `DeleteInput.At` is
// non-zero is about the handler reading the injected clock rather than about
// wall time happening to be non-zero. A handler using time.Now() would also pass
// that assertion, which is why it is stated as "the clock was read" and not as
// "the value was right".
func deletionClock() clock.Clock {
	return clock.NewFake(time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC))
}

// liveToken is the session token `newFakeAuth` resolves, and it is the only one
// that reaches a handler's `currentUser`. It is named rather than inlined so a
// reader can see that every test in this file authenticates the SAME way and none
// of them is passing by accident through a different surface.
const liveToken = "a-session-token"

// TestTheRouteDeletesTheCallersOwnAccount is the happy path at the HTTP layer:
// a live session, a 204, and no body.
//
// The two things asserted beyond the status are the ones a 204 makes easy to get
// wrong: `Content-Length` of zero and no `Content-Type`, because a body on a 204
// is a framing violation that `net/http` will not stop a handler from writing.
func TestTheRouteDeletesTheCallersOwnAccount(t *testing.T) {
	t.Parallel()

	svc := &fakeDeletion{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+liveToken)
	deletionRouter(t, svc).ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d. Body: %s", rec.Code, http.StatusNoContent, rec.Body)
	}
	if body := rec.Body.Bytes(); len(body) != 0 {
		t.Errorf("a 204 carried a body: %q", body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "" {
		t.Errorf("Content-Type = %q on a 204. There is nothing to describe: the resource is gone",
			ct)
	}
	if len(svc.calls) != 1 {
		t.Fatalf("the deletion service was called %d times, want exactly 1", len(svc.calls))
	}
	if svc.calls[0].UserID.IsZero() {
		t.Error("the deletion was asked for the nil user. The route must resolve the session and " +
			"pass ITS user, not the id from the path — there is no id in the path.")
	}
	if svc.calls[0].At.IsZero() {
		t.Error("the deletion carried no instant, so nothing would be stamped and the event " +
			"would be dated at the database's now() instead of the service's clock")
	}
}

// TestTheRouteIsRefusedWithAConflictThatNamesTheAccount is the refusal at the
// HTTP layer, and the assertions are on what a CALLER can do with the response:
// the code is a stable string they can switch on, the detail names the account,
// and the status is 409 rather than 422.
//
// 422 is the interesting one. It is what every validation failure in this service
// uses, and it would tell the client the REQUEST was wrong. It was not: the
// request is well-formed and understood, and what conflicts is the state of an
// account this person has never heard of in this conversation.
func TestTheRouteIsRefusedWithAConflictThatNamesTheAccount(t *testing.T) {
	t.Parallel()

	svc := &fakeDeletion{err: deletion.ErrSolelyOwnedAccounts}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+liveToken)
	deletionRouter(t, svc).ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d. Body: %s", rec.Code, http.StatusConflict, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want %q. Every non-2xx from this service is a problem "+
			"document and the generated client's errors.go switches on that", ct, "application/problem+json")
	}

	body := rec.Body.String()
	for _, want := range []string{"account_ownership_conflict", "sole owner"} {
		if !servesContains(body, want) {
			t.Errorf("the problem document does not contain %q, so a consumer cannot act on "+
				"it. Body: %s", want, body)
		}
	}

	// The `type` and `title` are asserted as a PAIR with the code rather than left
	// to `TestProblemTitlesAreStablePerCode`, because the failure they were written
	// for is specific to this route: the code first shipped as a bare string
	// literal at the call site, and a code that is not a declared constant is a
	// code `titles` does not hold — so the document rendered the fallback
	// "Request failed", a title that names neither the conflict nor the remedy.
	// That passed this test, which is why the assertion lives here.
	//
	// `type` is the machine-readable contract (`errors.cafaye.com/<code>`, exactly
	// the code) and a client matching on it must not find a base URI this service
	// emits nowhere else. Both were wrong in the first draft of the document, and
	// neither was visible to a reader of the handler.
	var p Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("decoding the problem document: %v. Body: %s", err, body)
	}
	if want := errorTypeBase + CodeAccountOwnershipConflict; p.Type != want {
		t.Errorf("problem type = %q, want %q", p.Type, want)
	}
	if want := "Account ownership conflict"; p.Title != want {
		t.Errorf("problem title = %q, want %q — the fixed summary per code, and a client "+
			"that renders it is showing the person what happened", p.Title, want)
	}
	if p.Status != http.StatusConflict || p.Code != CodeAccountOwnershipConflict {
		t.Errorf("status/code = %d/%q, want %d/%q", p.Status, p.Code,
			http.StatusConflict, CodeAccountOwnershipConflict)
	}
	if svc.calls[0].UserID.IsZero() {
		t.Error("the refusal was not made against a resolved user")
	}
}

// TestAnUnexpectedFailureIsNotLeaked is the fail-closed half of the handler's
// error switch. A 500 from this service must not carry the database's wording,
// because the one thing a deletion can fail on that a caller might care about is
// a constraint name — and `account_invitations_invited_by_fkey` in a response
// body tells a stranger which table still names them.
func TestAnUnexpectedFailureIsNotLeaked(t *testing.T) {
	t.Parallel()

	svc := &fakeDeletion{err: errors.New("deleting a user: ERROR: update or delete on table " +
		"\"users\" violates foreign key constraint \"account_invitations_invited_by_fkey\"")}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+liveToken)
	deletionRouter(t, svc).ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if servesContains(rec.Body.String(), "account_invitations_invited_by_fkey") {
		t.Errorf("the 500 body names the constraint that blocked it, which tells the caller which "+
			"table still references them: %s", rec.Body)
	}
}

// TestAnAnonymousCallerGetsTheOne401AndNothingElse is the enumeration answer,
// measured at the handler rather than only in the audit table.
//
// One assertion carries two properties: the status is the same 401 an unknown or
// expired session gets (so a deleted account and a never-existed one are
// indistinguishable), and the body says nothing at all — no email, no id, no
// "account not found".
func TestAnAnonymousCallerGetsTheOne401AndNothingElse(t *testing.T) {
	t.Parallel()

	svc := &fakeDeletion{}
	rec := httptest.NewRecorder()
	deletionRouter(t, svc).ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/v1/me", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if len(svc.calls) != 0 {
		t.Errorf("the deletion service was called for an anonymous request: %v", svc.calls)
	}
	if !servesContains(rec.Body.String(), "unauthorized") {
		t.Errorf("body is %s, want the service's one unauthenticated problem", rec.Body)
	}
}

// TestTheDeletionIsIdempotentFromTheCallersPointOfView is about the SECOND
// request with the same session, and it is the property the cascade buys.
//
// The first DELETE removes the row, so the session is gone with it and the second
// request is a 401 — not a 204 and not a 500. There is no "already deleted" state
// to answer, because "already deleted" and "never existed" are the same state
// after a deletion, and answering them differently would turn the route into an
// oracle for which user ids are real.
func TestTheDeletionIsIdempotentFromTheCallersPointOfView(t *testing.T) {
	t.Parallel()

	// The session stops resolving the moment the deletion runs, which is what the
	// users-row cascade really does: `sessions.user_id` is ON DELETE CASCADE, so
	// the row is gone and `Authenticate` finds nothing to hash.
	//
	// It is expressed through `authErr` rather than a new fake method because that
	// is the same seam production uses — an unknown token is what `Authenticate`
	// reports, and a deleted user's session token is unknown.
	auth := newFakeAuth()
	svc := &fakeDeletion{onDelete: func() { auth.authErr = authsvc.ErrUnauthenticated }}
	rec := httptest.NewRecorder()

	req := httptest.NewRequest(http.MethodDelete, "/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+liveToken)
	New(nil, WithAuth(auth), WithDeletion(svc), WithClock(deletionClock())).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("the first DELETE answered %d, want %d", rec.Code, http.StatusNoContent)
	}

	second := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodDelete, "/v1/me", nil)
	req2.Header.Set("Authorization", "Bearer "+liveToken)
	New(nil, WithAuth(auth), WithDeletion(svc), WithClock(deletionClock())).ServeHTTP(second, req2)

	if second.Code != http.StatusUnauthorized {
		t.Errorf("the second DELETE with the same session answered %d, want %d. After a deletion "+
			"the session cannot resolve, and \"already deleted\" must not be a distinguishable "+
			"answer from \"never existed\"", second.Code, http.StatusUnauthorized)
	}
}

// servesContains is a substring test, named apart from the slice-shaped
// `contains` this package already has for route lists. Two functions with one
// name and two signatures is the kind of thing a reader resolves by grepping the
// call, so this one says which kind it is at the call site instead.
func servesContains(haystack, needle string) bool { return strings.Contains(haystack, needle) }
