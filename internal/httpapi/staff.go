package httpapi

// THE STAFF SURFACE: THE HUMAN OPERATOR'S FOUR ROUTES.
//
//	GET  /v1/operator/me                      200  signed-in staff session
//	GET  /v1/operator/users?query=&limit=      200  signed-in staff session
//	POST /v1/operator/users/{userID}/disable   204  signed-in staff session
//	POST /v1/operator/users/{userID}/enable    204  signed-in staff session
//
// # WHY THIS IS NOT THE MACHINE OPERATOR SURFACE, AND WHY IT IS NOT THE ADMIN ONE
//
// `POST /v1/users/{userID}/disable` (operator.go, DECISIONS.md D14) is reachable
// by a scoped api key holding `users:disable` and by nothing else: a session is
// refused there, because D14's operator is a deployment fact rather than a
// login. This surface is the mirror: reachable by a signed-in STAFF human's
// session and by nothing else, because the Parlor console is a browser and a
// browser holds no api key. A machine key is refused HERE, exactly as a session
// is refused THERE — the two surfaces are disjoint by credential kind, and a
// credential that could cross from one to the other would make the audit trail
// unable to say whether a person or a pipeline acted.
//
// It is not the admin surface either, for D14's reason restated: a user is not
// an account. These routes name no account, consult no role, and grant no
// tenant admin anything — an account admin, owner included, is 403 here
// whatever else they hold. DECISIONS.md D19 revises D14 for this surface and is
// the entry that owns the argument; this comment owns the mechanics.
//
// # THE STAFF PROPERTY, SAID ONCE
//
// `users.is_staff` (migrations/00030) is a first-class boolean on the person,
// default false, writable only by `users.Store.SetStaff` — which the
// `identity-staff` operator command calls and no HTTP route does. It is never
// self-service writable and never writable through tenant-admin APIs. The gate
// below reads it off the row `Authenticate` already returned, so there is no
// second lookup and no second place for the answer to disagree with itself.
//
// # THE REFUSALS, AND EACH IS CHOSEN RATHER THAN DEFAULTED
//
//	401  no credential, or a session token that resolves to nothing. The normal
//	     authentication refusal: a login would fix it, so 401 is honest here —
//	     unlike the machine surface, where a session is the wrong credential to
//	     hold at all.
//	403  a scoped api key (wrong credential kind for a human surface), or an
//	     authenticated session whose user is not staff (a tenant admin lands
//	     here too: no account role implies global staff authority). The gate
//	     runs BEFORE the subject is parsed, so a refusal discloses nothing
//	     about whether the named user exists.
//	404  a user id this service never issued — staff only, behind the gate, on
//	     D12's terms: there is no stranger left to protect and an operator told
//	     "no user with that id" can act on it.
//	422  a search the directory will not run: no query, a one-character query,
//	     or an unreadable/out-of-range limit. Over the ceiling is a refusal,
//	     never a silent truncation.
//	500  everything else, with the cause in the log.
//
// # THE AUDIT RECORD NAMES THE HUMAN
//
// The disable/enable reuse `auth.Service.Disable`/`Enable` — the same
// transaction (sessions, access tokens, column, audit row) the machine surface
// uses. The actor differs: a staff session has no api key row to name, so the
// row carries the staff user's id, a zero key id and the request's trace id.
// `useraudit.Actor.HumanSession` is how a reader tells the two apart. A row
// that named nobody would be unattributable, which D14 named as the defect;
// a row that invented a key id would be a lie the table then has to be trusted
// about.

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cafaye/identity/internal/apikeys"
	"github.com/cafaye/identity/internal/auth"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/users"
)

// registerStaffRoutes mounts the four routes.
//
// IT IS CALLED UNCONDITIONALLY from registerRoutes and takes NO OPTION, for the
// reason `registerOperatorRoutes` does: the use cases hang off `auth.Service`
// (Disable/Enable) and the directory read off it too (`SearchUsers`), and
// `registerRoutes` has already returned early if there is no auth service at
// all. A conditional surface here would be one more field on `options`, one
// more entry in `router_walk_test.go`'s list, and one more way for a walk of
// the router to read a smaller service than the one that runs.
func (o options) registerStaffRoutes(r chiRouter) {
	r.Get("/v1/operator/me", o.requireStaffSession(o.handleOperatorMe))
	r.Get("/v1/operator/users", o.requireStaffSession(o.handleSearchOperatorUsers))
	r.Post("/v1/operator/users/{userID}/disable", o.requireStaffSession(o.handleStaffDisableUser))
	r.Post("/v1/operator/users/{userID}/enable", o.requireStaffSession(o.handleStaffEnableUser))
}

// requireStaffSession is this surface's credential gate: a signed-in STAFF
// human's session, and nothing else.
//
// THE ORDER IS THE ARGUMENT:
//
//  1. IS THIS A HUMAN CREDENTIAL? A scoped api key — or a request presenting
//     one — is refused with 403 before anything is resolved. A token carries
//     scopes, not a staff property, so consulting them would be reading a field
//     that cannot answer the question.
//  2. WHO IS THIS? `currentUser` resolves the session, writing the normal 401
//     for every unusable credential. Anonymous callers are refused here, before
//     any subject is parsed.
//  3. ARE THEY STAFF? 403, naming the property: the caller IS authenticated,
//     so 401 would send them hunting a login problem, and the sentence must not
//     vary by what they hold — a tenant admin learns nothing about staff
//     membership beyond "not you".
//
// The resolved user travels on the context, so handlers neither re-resolve the
// credential nor reach past the gate into a query they wrote themselves.
func (o options) requireStaffSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if o.isAPIKeyRequest(r) {
			problemFor(w, r, http.StatusForbidden, CodeForbidden,
				"the staff surface is reachable by a signed-in staff member's session only; "+
					"a scoped api key may not use it. The machine operator surface is "+
					"POST /v1/users/{userID}/disable, and the two credentials do not cross")
			return
		}
		user, ok := o.currentUser(w, r)
		if !ok {
			return
		}
		if !user.IsStaff {
			problemFor(w, r, http.StatusForbidden, CodeForbidden,
				"this route is for platform staff; your account is not marked as staff. "+
					"No account role grants this — staff is a property of the user, not of a membership")
			return
		}
		next(w, r.WithContext(withStaffCaller(r.Context(), user)))
	}
}

// staffCallerKey is the context key. A private struct type, like
// operatorCallerKey, so no other package can put or read this value by
// accident.
type staffCallerKey struct{}

func withStaffCaller(ctx context.Context, user users.User) context.Context {
	return context.WithValue(ctx, staffCallerKey{}, user)
}

// staffFrom returns the staff user requireStaffSession resolved. A handler
// behind the gate can rely on the second being true AND on the user being
// staff; a handler not behind it must not read the first.
func staffFrom(ctx context.Context) (users.User, bool) {
	user, ok := ctx.Value(staffCallerKey{}).(users.User)
	if !ok || !user.IsStaff {
		return users.User{}, false
	}
	return user, true
}

// ---------------------------------------------------------------------------
// response shapes
// ---------------------------------------------------------------------------

// operatorMeResponse is the 200 from GET /v1/operator/me: the caller's own
// operator status under a `user` key, and nothing about anybody else's.
//
// NESTED RATHER THAN FLAT, which is the Parlor contract: the console renders
// a user, and the status it needs is that user's staff flag beside the id and
// address it already renders. A flat `{id, email, staff}` would read as three
// facts about the request; `{user: {…}}` reads as one fact about a person.
type operatorMeResponse struct {
	User operatorMeUser `json:"user"`
}

// operatorMeUser is the user inside the me response. `staff` is always true
// on a 200 — the gate established it, and a 403 IS the status for everybody
// else.
type operatorMeUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Staff bool   `json:"staff"`
}

// staffUserEntry is one row of the staff directory.
//
// THE FIELDS PARLOR NEEDS AND NOTHING ELSE. There is no password digest, no
// api key, no recovery token, no MFA secret and no session token here — and it
// is a dedicated type rather than `users.User` so none of those can reach the
// body by being added to the domain struct.
//
// THE TIMESTAMPS ARE PRESENT AS NULL, never omitted and never folded into a
// boolean. `disabled_at` is null for an active account and `email_verified_at`
// is null for an address nobody has proved; a client can tell "never" from
// "missing", and `created_at` is what the console sorts by when the query
// ties. There is deliberately no `omitempty` on either: an omitted key and a
// null one are two spellings of one answer, and the contract promises one.
type staffUserEntry struct {
	ID              string     `json:"id"`
	Email           string     `json:"email"`
	DisplayName     *string    `json:"display_name,omitempty"`
	DisabledAt      *time.Time `json:"disabled_at"`
	EmailVerifiedAt *time.Time `json:"email_verified_at"`
	CreatedAt       time.Time  `json:"created_at"`
}

// staffUserListResponse is the 200 from GET /v1/operator/users.
//
// AN OBJECT WITH A NAMED FIELD, NOT A BARE ARRAY, for the reason
// sessionListResponse gives: room to grow a cursor without a second breaking
// change. The list is never null: an empty directory renders `[]`.
type staffUserListResponse struct {
	Users []staffUserEntry `json:"users"`
}

// ---------------------------------------------------------------------------
// handlers
// ---------------------------------------------------------------------------

// handleOperatorMe reports the current signed-in staff user's operator status.
//
//	GET /v1/operator/me  →  200 {user: {id, email, staff: true}}
//
// The gate has already established staff, so the flag is always true here —
// and that is the point rather than a tautology: a 200 names the status, a 403
// IS the status for everybody else, and neither answer discloses anything
// about another user.
func (o options) handleOperatorMe(w http.ResponseWriter, r *http.Request) {
	staff, ok := staffFrom(r.Context())
	if !ok {
		unexpected(w, r, o.logger, errNoStaffCaller)
		return
	}
	writeJSON(w, http.StatusOK, operatorMeResponse{
		User: operatorMeUser{
			ID:    staff.ID.String(),
			Email: staff.Email,
			Staff: true,
		},
	})
}

// handleSearchOperatorUsers answers the staff directory search.
//
//	GET /v1/operator/users?query=...&limit=...  →  200 {users: [...]}
//
// THE QUERY IS REQUIRED AND MUST BE USEFUL: an empty term, or a
// one-character one, is a directory dump wearing a query string, and a dump
// the caller did not have to think about is the one that ends up in a ticket.
// THE LIMIT IS BOUNDED: absent means the default, over the ceiling is a 422
// naming `limit` — a bound refused beats a bound clamped, because a client
// that asked for 500 rows and received 50 has been told a lie about how much
// directory it has read.
func (o options) handleSearchOperatorUsers(w http.ResponseWriter, r *http.Request) {
	query := strings.TrimSpace(r.URL.Query().Get("query"))
	if query == "" {
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the directory search needs a query to search for").
			withFieldErrors([]FieldError{{Field: "query", Code: apikeys.CodeRequired}}))
		return
	}
	if len([]rune(query)) < users.MinSearchLength {
		writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
			withDetail("the directory search needs a longer query to search for").
			withFieldErrors([]FieldError{{Field: "query", Code: users.CodeTooShort}}))
		return
	}

	limit := users.DefaultSearchLimit
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 {
			writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
				withDetail("the directory search limit is not one this endpoint accepts").
				withFieldErrors([]FieldError{{Field: "limit", Code: apikeys.CodeInvalidFormat}}))
			return
		}
		if parsed > users.MaxSearchLimit {
			writeProblem(w, r, newProblem(http.StatusUnprocessableEntity, CodeValidationFailed).
				withDetail("the directory search limit is not one this endpoint accepts").
				withFieldErrors([]FieldError{{Field: "limit", Code: apikeys.CodeOutOfRange}}))
			return
		}
		limit = parsed
	}

	entries, err := o.auth.SearchUsers(r.Context(), query, limit)
	if err != nil {
		unexpected(w, r, o.logger, err)
		return
	}

	// Non-nil, so an empty directory is `[]` and not `null`.
	out := make([]staffUserEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, staffUserEntry{
			ID:              e.ID.String(),
			Email:           e.Email,
			DisplayName:     e.DisplayName,
			DisabledAt:      e.DisabledAt,
			EmailVerifiedAt: e.EmailVerifiedAt,
			CreatedAt:       e.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, staffUserListResponse{Users: out})
}

// errNoStaffCaller means a staff handler ran without a staff user in context,
// which requireStaffSession should have made impossible. A 500 for the same
// reason operator.go's is: nothing about the caller is wrong, and a 403 would
// tell a client its session was insufficient when the real fault is that the
// gate did not run.
var errNoStaffCaller = errors.New("a staff route reached its handler with no staff user in context")

// handleStaffDisableUser turns an account off, from a staff human's session.
//
//	POST /v1/operator/users/{userID}/disable  →  204
//
// THE TRANSACTION IS THE MACHINE SURFACE'S: `auth.Service.Disable` deletes the
// session rows, revokes the access tokens and stamps the column in ONE
// transaction, then writes the audit row in it. What differs is the actor: a
// staff session has no api key row, so the row carries the staff user's id, a
// zero key id and the request's trace id — `HumanSession` is how a reader
// tells it from a token's.
func (o options) handleStaffDisableUser(w http.ResponseWriter, r *http.Request) {
	staff, ok := staffFrom(r.Context())
	if !ok {
		unexpected(w, r, o.logger, errNoStaffCaller)
		return
	}
	userID, ok := operatorSubject(r)
	if !ok {
		notFound(w, r)
		return
	}

	if err := o.auth.Disable(r.Context(), auth.DisableInput{
		UserID:      userID,
		ActorUserID: staff.ID,
		ActorKeyID:  id.UUID{},
		TraceID:     traceIDFrom(r.Context()),
		At:          o.clk.Now(),
	}); err != nil {
		o.writeOperatorError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleStaffEnableUser lifts a disable, from a staff human's session.
//
//	POST /v1/operator/users/{userID}/enable  →  204
//
// IT RESTORES THE COLUMN AND NOTHING ELSE, on `auth.Service.Enable`'s contract:
// the sessions the disable ended are gone and do not come back, so the owner
// signs in again. The actor is the staff user's, for the reason the disable's
// is — a re-enable that records nobody leaves a trail saying the person is
// still disabled.
func (o options) handleStaffEnableUser(w http.ResponseWriter, r *http.Request) {
	staff, ok := staffFrom(r.Context())
	if !ok {
		unexpected(w, r, o.logger, errNoStaffCaller)
		return
	}
	userID, ok := operatorSubject(r)
	if !ok {
		notFound(w, r)
		return
	}

	if err := o.auth.Enable(r.Context(), auth.EnableInput{
		UserID:      userID,
		ActorUserID: staff.ID,
		ActorKeyID:  id.UUID{},
		TraceID:     traceIDFrom(r.Context()),
		At:          o.clk.Now(),
	}); err != nil {
		o.writeOperatorError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
