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

	authsvc "github.com/anywaye/identity/internal/auth"
	"github.com/anywaye/identity/internal/deletion"
	"github.com/anywaye/identity/internal/platform/clock"
)


type fakeDeletion struct {
	calls []deletion.DeleteInput
	err   error
	onDelete func()
}

func (f *fakeDeletion) Delete(_ context.Context, in deletion.DeleteInput) error {
	f.calls = append(f.calls, in)
	if f.onDelete != nil {
		f.onDelete()
	}
	return f.err
}

func newFakeDeletion() *fakeDeletion { return &fakeDeletion{} }

func deletionRouter(t *testing.T, d Deletion) http.Handler {
	t.Helper()

	return New(nil,
		WithAuth(newFakeAuth()),
		WithDeletion(d),
		WithClock(deletionClock()),
	)
}

func deletionClock() clock.Clock {
	return clock.NewFake(time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC))
}

const liveToken = "a-session-token"

func TestTheRouteDeletesTheCallersOwnAccount(t *testing.T) {
	t.Parallel()

	svc := &fakeDeletion{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/v1/me", nil)
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

func TestTheRouteIsRefusedWithAConflictThatNamesTheAccount(t *testing.T) {
	t.Parallel()

	svc := &fakeDeletion{err: deletion.ErrSolelyOwnedAccounts}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/v1/me", nil)
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

func TestAnUnexpectedFailureIsNotLeaked(t *testing.T) {
	t.Parallel()

	svc := &fakeDeletion{err: errors.New("deleting a user: ERROR: update or delete on table " +
		"\"users\" violates foreign key constraint \"account_invitations_invited_by_fkey\"")}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/v1/me", nil)
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

func TestAnAnonymousCallerGetsTheOne401AndNothingElse(t *testing.T) {
	t.Parallel()

	svc := &fakeDeletion{}
	rec := httptest.NewRecorder()
	deletionRouter(t, svc).ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/v1/me", nil))

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

func TestTheDeletionIsIdempotentFromTheCallersPointOfView(t *testing.T) {
	t.Parallel()

	auth := newFakeAuth()
	svc := &fakeDeletion{onDelete: func() { auth.authErr = authsvc.ErrUnauthenticated }}
	rec := httptest.NewRecorder()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+liveToken)
	New(nil, WithAuth(auth), WithDeletion(svc), WithClock(deletionClock())).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("the first DELETE answered %d, want %d", rec.Code, http.StatusNoContent)
	}

	second := httptest.NewRecorder()
	req2 := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/v1/me", nil)
	req2.Header.Set("Authorization", "Bearer "+liveToken)
	New(nil, WithAuth(auth), WithDeletion(svc), WithClock(deletionClock())).ServeHTTP(second, req2)

	if second.Code != http.StatusUnauthorized {
		t.Errorf("the second DELETE with the same session answered %d, want %d. After a deletion "+
			"the session cannot resolve, and \"already deleted\" must not be a distinguishable "+
			"answer from \"never existed\"", second.Code, http.StatusUnauthorized)
	}
}

func servesContains(haystack, needle string) bool { return strings.Contains(haystack, needle) }
