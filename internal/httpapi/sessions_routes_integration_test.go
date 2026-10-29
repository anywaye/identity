package httpapi


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

func TestTheListingOverHTTPShowsOnlyTheCallersSessions(t *testing.T) {
	h, _ := newSessionWorldDB(t)

	alice := signUpOn(t, h)

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

	if me := requestAs(t, h, mallory.token, http.MethodGet, "/v1/me", ""); me.Code != http.StatusOK {
		t.Errorf("mallory's session no longer authenticates after alice's revoke: %d\nbody: %s", me.Code, me.Body)
	}

	if me := requestAs(t, h, alice.token, http.MethodGet, "/v1/me", ""); me.Code != http.StatusOK {
		t.Errorf("alice's own session was deleted by a revoke aimed at mallory's: %d\nbody: %s", me.Code, me.Body)
	}
}

func TestRevokingOneOfYourOwnSessionsLeavesTheOthersWorking(t *testing.T) {
	h, _ := newSessionWorldDB(t)

	alice := signUpOn(t, h)
	spare := signInAgain(t, h, alice.email)
	victim := signInAgain(t, h, alice.email)

	_, list := listSessionsFor(t, h, alice.token)
	if len(list) != 3 {
		t.Fatalf("alice sees %d sessions, want her own 3: %+v", len(list), list)
	}

	victimID := currentIDIn(t, h, victim.token)
	if victimID == "" {
		t.Fatalf("the victim's own session is not in its listing as `current`: %+v", list)
	}

	rec := requestAs(t, h, alice.token, http.MethodDelete, "/v1/sessions/"+victimID, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoking one of alice's own sessions = %d, want 204\nbody: %s", rec.Code, rec.Body)
	}

	_, after := listSessionsFor(t, h, alice.token)
	if len(after) != 2 {
		t.Errorf("alice sees %d sessions after one revoke, want 2", len(after))
	}
	for _, entry := range after {
		if entry.ID == victimID {
			t.Errorf("the revoked session %s is still in the listing", victimID)
		}
	}

	if me := requestAs(t, h, alice.token, http.MethodGet, "/v1/me", ""); me.Code != http.StatusOK {
		t.Errorf("the caller's own session stopped working: %d\nbody: %s", me.Code, me.Body)
	}
	if me := requestAs(t, h, spare.token, http.MethodGet, "/v1/me", ""); me.Code != http.StatusOK {
		t.Errorf("an unrelated session was revoked by a request naming another: %d\nbody: %s", me.Code, me.Body)
	}
}

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

	if me := requestAs(t, h, alice.token, http.MethodGet, "/v1/me", ""); me.Code != http.StatusUnauthorized {
		t.Errorf("the revoked current session still authenticates: %d", me.Code)
	}
	if list := requestAs(t, h, alice.token, http.MethodGet, "/v1/sessions", ""); list.Code != http.StatusUnauthorized {
		t.Errorf("the listing answered %d for a dead credential, want 401", list.Code)
	}

	if me := requestAs(t, h, otherSession.Token, http.MethodGet, "/v1/me", ""); me.Code != http.StatusOK {
		t.Errorf("the other session was revoked too: %d\nbody: %s", me.Code, me.Body)
	}
}

func TestTheListingOverHTTPRendersNoCredential(t *testing.T) {
	h, _ := newSessionWorldDB(t)

	alice := signUpOn(t, h)

	rec := requestAs(t, h, alice.token, http.MethodGet, "/v1/sessions", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/sessions = %d, want 200\nbody: %s", rec.Code, rec.Body)
	}

	body := rec.Body.String()
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

func TestAnExpiredSessionIsNotListedOverHTTP(t *testing.T) {
	h, clk := newSessionWorldDB(t)

	alice := signUpOn(t, h)

	clk.Advance(48 * time.Hour)

	rec := requestAs(t, h, alice.token, http.MethodGet, "/v1/sessions", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /v1/sessions after the session expired = %d, want 401\nbody: %s", rec.Code, rec.Body)
	}
}
