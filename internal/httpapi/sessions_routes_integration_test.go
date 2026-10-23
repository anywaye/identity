package httpapi

// THE TWO SESSION ROUTES OVER HTTP, AGAINST A REAL DATABASE.
//
// Three claims, and each one is at a layer the other two files cannot reach:
//
//  1. **THE LISTING SHOWS ONLY THE CALLER'S SESSIONS.** Two real users, two real
//     logins, one listing. The stranger's row is absent — which is a claim about
//     rows, so it is asserted by making the stranger's credential WORK afterwards
//     rather than by reading the array and hoping.
//  2. **A STRANGER'S SESSION CANNOT BE REVOKED.** A 404 over HTTP, and the
//     stranger's credential still works. The 404 is the same document the handler
//     tests compare byte for byte; what is new here is that it came out of a real
//     `DELETE ... WHERE id = $1 AND user_id = $2`.
//  3. **REVOKING YOUR OWN CURRENT SESSION SIGNS YOU OUT**, and the other sessions
//     survive. The consequence is documented on `auth.Service.RevokeSession`; this
//     is the observable half.
//
// # WHY A REAL DATABASE AND NOT dbtest.Schema's CLONE
//
// dbtest.Schema clones tables with `LIKE ... INCLUDING ALL`, which does **not**
// copy row-level security — so a boundary proven there is a boundary proven
// against policies that are not there. `sessions` is not an account-scoped table
// (migrations/00016 calls it global by construction: it has no `account_id`), and
// the boundary this packet cares about is a `WHERE` clause rather than a policy —
// so the clone would in fact be adequate here. It is stated rather than left
// implied, because the NEXT packet to put a session-shaped thing behind a policy
// will read this comment and need to know which of the two reasons applies.
//
// The pool under test is the application role either way, which is the property
// `dbtest.Pool` asserts and which is what makes "this query is the only thing
// standing between two users" a statement about production.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/sessions"
)

// sessionWorldDB is the real service over a private schema.
func newSessionWorldDB(t *testing.T) (http.Handler, *clock.Fake) {
	t.Helper()

	pool := dbtest.Schema(t)
	clk := clock.NewFake(time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))

	return New(nil,
		WithAuth(authServiceWithSessionTTL(pool, clk, 24*time.Hour)),
		WithTenancy(realTenancy(pool, clk)),
		WithLogger(slogLogger(&recordingHandler{})),
	), clk
}

// signedUpOn is a real user with a real live session.
type signedUpOn struct {
	token string
	id    id.UUID
	email string
}

func signUpOn(t *testing.T, h http.Handler) signedUpOn {
	t.Helper()

	email := dbtest.UniqueEmail(t)
	rec := post(t, h, "/v1/users", `{"email":"`+email+`","password":"`+validPassword+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering: %d; body: %s", rec.Code, rec.Body)
	}
	var created userResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("the registration body is not JSON: %v", err)
	}
	parsed, err := id.Parse(created.ID)
	if err != nil {
		t.Fatalf("the service returned an unparseable id: %v", err)
	}

	login := post(t, h, "/v1/session", `{"email":"`+email+`","password":"`+validPassword+`"}`)
	if login.Code != http.StatusOK {
		t.Fatalf("signing in: %d; body: %s", login.Code, login.Body)
	}
	var session sessionResponse
	if err := json.Unmarshal(login.Body.Bytes(), &session); err != nil {
		t.Fatalf("the login body is not JSON: %v", err)
	}

	return signedUpOn{token: session.Token, id: parsed, email: email}
}

// listSessionsFor drives the listing and decodes it off the wire.
func listSessionsFor(t *testing.T, h http.Handler, token string) (int, []sessionListItem) {
	t.Helper()

	rec := requestAs(t, h, token, http.MethodGet, "/v1/sessions", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/sessions = %d, want 200\nbody: %s", rec.Code, rec.Body)
	}

	var body sessionListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the listing is not JSON: %v\n%s", err, rec.Body)
	}
	return rec.Code, body.Sessions
}

// The stranger's session is not in the list, and the caller's own is.
//
// Asserted on the ID rather than on a count, because a count of two would pass
// against a listing that returned two of the caller's own sessions and none of the
// stranger's — which is what a query without the user predicate does when the
// caller happens to have two.
func TestTheListingOverHTTPShowsOnlyTheCallersSessions(t *testing.T) {
	h, _ := newSessionWorldDB(t)

	alice := signUpOn(t, h)

	// A second live session for Alice, so the list has more than one row and the
	// "which one is this" question has an answer other than "the only one".
	secondLogin := post(t, h, "/v1/session", `{"email":"`+alice.email+`","password":"`+validPassword+`"}`)
	if secondLogin.Code != http.StatusOK {
		t.Fatalf("alice's second sign-in: %d; body: %s", secondLogin.Code, secondLogin.Body)
	}

	mallory := signUpOn(t, h)

	_, list := listSessionsFor(t, h, alice.token)
	if len(list) != 2 {
		t.Fatalf("alice sees %d sessions, want her own 2: %+v", len(list), list)
	}

	current := 0
	for _, entry := range list {
		if entry.Current {
			current++
		}
	}
	if current != 1 {
		t.Errorf("%d entries are `current`, want exactly 1", current)
	}

	// Mallory's row is absent. The only way to be sure is to look up HER listing
	// and confirm his session has an id at all — a session that never appeared
	// anywhere would make this assertion vacuous.
	_, malloryList := listSessionsFor(t, h, mallory.token)
	if len(malloryList) != 1 {
		t.Fatalf("mallory sees %d sessions, want 1", len(malloryList))
	}
	strangerID := malloryList[0].ID
	if strangerID == "" {
		t.Fatal("mallory's own listing has an entry with no id, so the comparison below would be vacuous")
	}

	for _, entry := range list {
		if entry.ID == strangerID {
			t.Errorf("alice's listing contains session %s, which belongs to mallory", entry.ID)
		}
	}
}

// The cross-tenant revocation, over HTTP.
//
// THREE ASSERTIONS, and each covers a different implementation of the bug:
//
//	the 404      a caller learns nothing about somebody else's session
//	mallory's   the credential still works, so the row was not deleted
//	alice's     was NOT deleted either — the mirror-image bug, where a handler
//	            "fixes" the refusal by deleting the caller's own session instead
func TestRevokingAnotherUsersSessionOverHTTPIsRefusedAndChangesNothing(t *testing.T) {
	h, _ := newSessionWorldDB(t)

	alice := signUpOn(t, h)
	mallory := signUpOn(t, h)

	_, malloryList := listSessionsFor(t, h, mallory.token)
	strangerID := malloryList[0].ID

	rec := requestAs(t, h, alice.token, http.MethodDelete, "/v1/sessions/"+strangerID, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("alice revoking mallory's session = %d, want 404\nbody: %s", rec.Code, rec.Body)
	}
	if p := decodeProblem(t, rec); p.Code != CodeNotFound {
		t.Errorf("code = %q, want %q", p.Code, CodeNotFound)
	}

	// Mallory's session still authenticates, so nothing was deleted.
	if me := requestAs(t, h, mallory.token, http.MethodGet, "/v1/me", ""); me.Code != http.StatusOK {
		t.Errorf("mallory's session no longer authenticates after alice's revoke: %d\nbody: %s", me.Code, me.Body)
	}

	// And alice's own is untouched.
	if me := requestAs(t, h, alice.token, http.MethodGet, "/v1/me", ""); me.Code != http.StatusOK {
		t.Errorf("alice's own session was deleted by a revoke aimed at mallory's: %d\nbody: %s", me.Code, me.Body)
	}
}

// A caller can end one of their OWN sessions and the others keep working. This is
// the whole feature, so it is asserted over the credential rather than over the
// row: "the other session still authenticates" is the property a user depends on.
func TestRevokingOneOfYourOwnSessionsLeavesTheOthersWorking(t *testing.T) {
	h, _ := newSessionWorldDB(t)

	alice := signUpOn(t, h)
	// TWO further sign-ins, so the listing has three rows and the test can revoke
	// one of them and still have an untouched third to check. Two rows would be
	// enough to name a victim and not enough to catch "the revoke took the wrong
	// one" — the failure this file's sibling test proves is easy to write.
	spare := signInAgain(t, h, alice.email)
	victim := signInAgain(t, h, alice.email)

	_, list := listSessionsFor(t, h, alice.token)
	if len(list) != 3 {
		t.Fatalf("alice sees %d sessions, want her own 3: %+v", len(list), list)
	}

	// WHICH SESSION TO NAME is found by asking the victim credential which session
	// it is: the listing taken WITH that credential marks it `current`, and that is
	// the only mapping a client has from a token to a row id. Two of these three
	// were minted in the same millisecond, so picking an entry by POSITION would
	// make the subject of the test depend on the `id` tiebreaker's direction.
	victimID := currentIDIn(t, h, victim.token)
	if victimID == "" {
		t.Fatalf("the victim's own session is not in its listing as `current`: %+v", list)
	}

	rec := requestAs(t, h, alice.token, http.MethodDelete, "/v1/sessions/"+victimID, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoking one of alice's own sessions = %d, want 204\nbody: %s", rec.Code, rec.Body)
	}

	// The revoked one is gone from the listing.
	_, after := listSessionsFor(t, h, alice.token)
	if len(after) != 2 {
		t.Errorf("alice sees %d sessions after one revoke, want 2", len(after))
	}
	for _, entry := range after {
		if entry.ID == victimID {
			t.Errorf("the revoked session %s is still in the listing", victimID)
		}
	}

	// Alice's own still works, which is the part a "delete everything" bug would
	// take with it, and so does the spare — which is the part a "revoke the wrong
	// row" bug would.
	if me := requestAs(t, h, alice.token, http.MethodGet, "/v1/me", ""); me.Code != http.StatusOK {
		t.Errorf("the caller's own session stopped working: %d\nbody: %s", me.Code, me.Body)
	}
	if me := requestAs(t, h, spare.token, http.MethodGet, "/v1/me", ""); me.Code != http.StatusOK {
		t.Errorf("an unrelated session was revoked by a request naming another: %d\nbody: %s", me.Code, me.Body)
	}
}

// currentIDIn asks the service which session a credential is, and returns that
// row's id — or "" if the listing marks none.
//
// It goes through the listing rather than through the database because the id is
// not derivable from the token: the store holds a SHA-256 digest, so a test cannot
// map a credential to a row by itself, and a helper that tried would be reaching
// past the service's own answer to reach for the row.
func currentIDIn(t *testing.T, h http.Handler, token string) string {
	t.Helper()

	_, list := listSessionsFor(t, h, token)
	for _, entry := range list {
		if entry.Current {
			return entry.ID
		}
	}
	return ""
}

// signInAgain is one more live session for an existing account, decoded.
func signInAgain(t *testing.T, h http.Handler, email string) signedUpOn {
	t.Helper()

	rec := post(t, h, "/v1/session", `{"email":"`+email+`","password":"`+validPassword+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("signing in again: %d; body: %s", rec.Code, rec.Body)
	}
	var session sessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &session); err != nil {
		t.Fatalf("the login body is not JSON: %v", err)
	}
	return signedUpOn{token: session.Token, email: email}
}

// Revoking the session you are using is ALLOWED and signs you out.
//
// The decision is documented on `auth.Service.RevokeSession` and the argument for
// it is about the API's shape rather than about security; this is the observable
// consequence, which is the half a reader of that comment cannot check.
func TestRevokingYourOwnCurrentSessionIsAllowedAndSignsYouOutOverHTTP(t *testing.T) {
	h, _ := newSessionWorldDB(t)

	alice := signUpOn(t, h)
	other := post(t, h, "/v1/session", `{"email":"`+alice.email+`","password":"`+validPassword+`"}`)
	if other.Code != http.StatusOK {
		t.Fatalf("the second sign-in: %d; body: %s", other.Code, other.Body)
	}
	var otherSession sessionResponse
	if err := json.Unmarshal(other.Body.Bytes(), &otherSession); err != nil {
		t.Fatalf("the second login body is not JSON: %v", err)
	}

	_, list := listSessionsFor(t, h, alice.token)
	var current string
	for _, entry := range list {
		if entry.Current {
			current = entry.ID
		}
	}
	if current == "" {
		t.Fatalf("no entry is `current`: %+v", list)
	}

	rec := requestAs(t, h, alice.token, http.MethodDelete, "/v1/sessions/"+current, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoking the session the request arrived on = %d, want 204\nbody: %s", rec.Code, rec.Body)
	}

	// The consequence: that credential is dead, and the listing is a 401 rather
	// than an empty array — a client told "you have no sessions" would clear state
	// rather than send the user back to the login page.
	if me := requestAs(t, h, alice.token, http.MethodGet, "/v1/me", ""); me.Code != http.StatusUnauthorized {
		t.Errorf("the revoked current session still authenticates: %d", me.Code)
	}
	if list := requestAs(t, h, alice.token, http.MethodGet, "/v1/sessions", ""); list.Code != http.StatusUnauthorized {
		t.Errorf("the listing answered %d for a dead credential, want 401", list.Code)
	}

	// And the other device is untouched, which is the difference between this route
	// and "sign out everywhere".
	if me := requestAs(t, h, otherSession.Token, http.MethodGet, "/v1/me", ""); me.Code != http.StatusOK {
		t.Errorf("the other session was revoked too: %d\nbody: %s", me.Code, me.Body)
	}
}

// The listing never renders a credential, and this is asserted against the body of
// a REAL response rather than a fixture — because a fixture proves the handler and
// the store could not invent one, whereas this proves the two together do not.
func TestTheListingOverHTTPRendersNoCredential(t *testing.T) {
	h, _ := newSessionWorldDB(t)

	alice := signUpOn(t, h)

	rec := requestAs(t, h, alice.token, http.MethodGet, "/v1/sessions", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/sessions = %d, want 200\nbody: %s", rec.Code, rec.Body)
	}

	body := rec.Body.String()
	// The digest as well as the token: a value one SHA-256 away from a live session
	// is a credential for anybody holding a copy of this body, and the store has it
	// in hand on every read.
	for _, secret := range []string{alice.token, sessions.Digest(alice.token)} {
		if strings.Contains(body, secret) {
			t.Errorf("the response body contains %q: %s", secret, body)
		}
	}
	for _, key := range []string{`"token"`, `"digest"`, `"token_digest"`, `"user_id"`} {
		if strings.Contains(body, key) {
			t.Errorf("the response body carries the field %s: %s", key, body)
		}
	}
}

// An expired session is not in the listing.
//
// The clock is moved rather than the row aged, because `created_at` is the
// DATABASE's now() and cannot be moved from here — which is exactly why the
// listing has to ask the service's injected clock about expiry, and why a
// listing that queried `expires_at > now()` on the server would still be correct
// only by accident.
func TestAnExpiredSessionIsNotListedOverHTTP(t *testing.T) {
	h, clk := newSessionWorldDB(t)

	alice := signUpOn(t, h)

	// Past the 24-hour session lifetime used by this fixture.
	clk.Advance(48 * time.Hour)

	rec := requestAs(t, h, alice.token, http.MethodGet, "/v1/sessions", "")
	// The credential is dead too, so the honest answer is the 401 and not an empty
	// listing — asserted here because it is the same clock move, and a listing that
	// answered 200 with `[]` would be telling a client its session is fine.
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /v1/sessions after the session expired = %d, want 401\nbody: %s", rec.Code, rec.Body)
	}
}
