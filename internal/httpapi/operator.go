package httpapi

// THE OPERATOR SURFACE: TWO ROUTES, ONE SCOPE, AND NO ACCOUNT ANYWHERE.
//
//	POST /v1/users/{userID}/disable   204   scoped api key, users:disable
//	POST /v1/users/{userID}/enable    204   scoped api key, users:disable
//
// # WHY IT IS NOT THE ADMIN SURFACE, SAID HERE AND NOT ONLY IN DECISIONS.md
//
// `internal/admin` is ACCOUNT-scoped: its rows carry `account_id`, its privilege
// boundary is one sentence about account admins and invitations, and its audit
// table cannot describe this action. A **user is not an account** — the same person
// belongs to several — so mounting this under `/v1/accounts/{accountID}/admin/…`
// would mean inventing a tenancy for an action whose subject is the person rather
// than one of their memberships. The obvious invention, "the caller's own
// account", is the defect: a user who belongs to ten tenants would grant tenant
// one the power to reach the employee tenant two also employs, ten times over.
//
// So there is no account in the path, no role minimum, and — the part that is
// load-bearing — **no route under `/v1/accounts/…` that consults `users:disable`
// at all**. An account-scoped credential is refused on this surface whatever its
// role and whatever else it holds, and that refusal is a check rather than an
// omission: `TestAnAccountScopedCredentialCannotDisableAUser` holds it by name.
//
// # WHY A MACHINE CREDENTIAL AND NOT A SESSION
//
// An operator is a deployment fact, not a login, and the thing being acted on is
// a person — so a browser session here would be an account turning itself off or
// on. There is no version of that which is not either a self-harm button or a
// privilege escalation. It is the same rule `requireAdminToken` and
// `requireSessionLinkMint` already enforce, for the same reason: a session is a
// cookie, and a cookie is one CSRF away from being somebody else's.
//
// # WHY 204 AND NO BODY
//
// The URL names the one thing being changed and there is nothing in the request
// that could be misread as "and everything else" — the difference from the bulk
// admin revocation, which needs a `confirm` in the body precisely because its
// subject is an ARRAY. There is no state a caller needs back: the answer to "is
// this account disabled?" is on the login, and a response that reported the
// column would publish a user's state to whoever asked.
//
// The refusals, and each is chosen rather than defaulted:
//
//	403  no credential, a session, or a token that does not hold users:disable.
//	     403 rather than 401 for all three: the first two are a statement about
//	     the SURFACE — it is reachable by a scoped api key and nothing else — and
//	     the third is a caller who IS authenticated and lacks authority. A 401
//	     on any of them sends a client hunting a login problem that does not exist.
//	404  a user id this service never issued. Safe HERE ONLY because the route is
//	     behind the operator credential: there is no stranger to protect, and an
//	     operator told "no user with that id" can act on it. This is D12's ruling,
//	     and it is the opposite of the self-service recovery routes, which answer
//	     202 to an unknown address for exactly this reason.
//	500  everything else, with the cause in the log. That includes the
//	     transaction rolling back: the caller is told the request failed, no
//	     session was ended and no column was written, and they have a trace id.

import (
	"context"
	"errors"
	"net/http"

	"github.com/cafaye/identity/internal/apikeys"
	"github.com/cafaye/identity/internal/auth"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/useraudit"
	"github.com/cafaye/identity/internal/users"
)

// registerOperatorRoutes mounts the two routes.
//
// IT IS CALLED UNCONDITIONALLY from registerRoutes and takes NO OPTION, for the
// reason `registerSessionLinkRoutes` does: `Disable` and `Enable` live on
// `auth.Service`, and `registerRoutes` has already returned early if there is no
// auth service at all. A conditional surface here would be one more field on
// `options`, one more entry somebody has to remember to add to
// `router_walk_test.go`'s list, and one more way for a walk of the router to read a
// smaller service than the one that runs. There is nothing here that can be
// configured away — the routes are present with a database and absent without one,
// which is the rule every other surface follows for the same reason.
//
// THE SCOPE CHECK IS IN THE MIDDLEWARE rather than in the handlers, so that a route
// added next to these two inherits it by being wrapped. The property being protected
// is "no route on this surface is reachable without `users:disable`", and that is
// what wrapping states; a check in a handler states "this handler remembered".
func (o options) registerOperatorRoutes(r chiRouter) {
	r.Post("/v1/users/{userID}/disable", o.requireOperatorToken(o.handleDisableUser))
	r.Post("/v1/users/{userID}/enable", o.requireOperatorToken(o.handleEnableUser))
}

// requireOperatorToken is this surface's credential gate: a scoped api key holding
// `users:disable`, and nothing else.
//
// THE ORDER IS THE ARGUMENT, and it is the same order `requireSessionLinkMint`
// uses for the same two reasons:
//
//  1. IS THIS A TOKEN? A session — or a request with no credential at all — is
//     refused with 403 before its scopes are consulted. A session carries no scopes
//     by construction, so checking them would be reading a field that is empty and
//     answering "this credential lacks users:disable" for a credential that has no
//     scopes to lack.
//  2. DOES IT HOLD THE SCOPE? 403 again, naming the scope, because the caller is
//     authenticated and the missing thing is authority rather than identity.
//
// AN UNRESOLVABLE TOKEN IS A 401 AND NOT THIS SURFACE'S 403, and the difference is
// asserted rather than assumed: 403 means "your credential cannot use this route",
// while a value belonging to no key is not a credential at all. That is one answer
// for no such token, a revoked one, an expired one, and one whose user has since
// gone — the rule every other route in this service answers "who are you" with.
//
// IT IS A SEPARATE FUNCTION RATHER THAN A REUSE of `requireAdminToken` or
// `requireSessionLinkMint`, because this surface is neither: the admin gate is a
// token plus an ACCOUNT ROLE, the mint's is a token plus a scope, and reusing one of
// them would give one function two names and make "which rule protects this route" a
// question about call order.
func (o options) requireOperatorToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !o.isAPIKeyRequest(r) {
			problemFor(w, r, http.StatusForbidden, CodeForbidden,
				"this route turns a person's account off, which is a deployment decision and not "+
					"something an account does to itself. It is reachable by a scoped api key holding "+
					"the "+apikeys.ScopeUsersDisable+" scope; a browser session may not use it, and "+
					"neither may an account-scoped credential")
			return
		}

		// A process with no api key support refuses a presented token rather than
		// panicking on it, and the answer is the one an unknown credential gets: there
		// is nothing here that could check it, and 401 keeps the two indistinguishable.
		if o.apiKeyCaller == nil {
			unauthorized(w, r)
			return
		}

		caller, err := o.apiKeyCaller.Authenticate(r.Context(), o.presentedAPIKey(r), o.clk.Now())
		if err != nil || caller.Key.ID.IsZero() {
			unauthorized(w, r)
			return
		}

		// THE SCOPE COMES OUT OF THE TABLE, not out of a constant written here. That is
		// the difference between a declaration and a description:
		// `accountRouteScopes` is walked by `TestEveryScopeIsEnforcedOnItsRoutes`
		// against the vocabulary, so deleting the row fails that test AND closes these
		// routes to tokens — `Allows("")` is false for every granted set, and a route
		// nobody declared a scope for is closed rather than open. That is the
		// fail-closed direction this table exists to guarantee.
		if required := scopeRequiredBy(r); !caller.Key.Allows(required) {
			problemFor(w, r, http.StatusForbidden, CodeForbidden,
				"this api key does not carry the "+required+" scope")
			return
		}

		// THE CALLER GOES ON THE CONTEXT, and this line is the reason the audit trail
		// exists. The gate above knows exactly who is calling and was about to discard
		// it — which was correct until disabled-04, because nothing downstream wanted
		// it. `auth.Service.Disable` now has to write a row naming this operator and
		// this api key, and a record that says "somebody" cannot answer the question
		// the packet was written for.
		//
		// It is set AFTER the scope check rather than before, so the context a handler
		// runs with never carries a credential that was refused. A route that
		// answered an error while its context held an authenticated caller would be a
		// context that lied.
		next(w, r.WithContext(withOperatorCaller(r.Context(), operatorCaller{
			UserID: caller.User.ID,
			KeyID:  caller.Key.ID,
		})))
	}
}

// operatorCallerKey is the context key. A private struct type, like accountContextKey
// and traceIDKey, so no other package can put or read this value by accident.
type operatorCallerKey struct{}

type operatorCaller struct {
	UserID id.UUID
	KeyID  id.UUID
}

func withOperatorCaller(ctx context.Context, c operatorCaller) context.Context {
	return context.WithValue(ctx, operatorCallerKey{}, c)
}

// operatorActorFrom assembles the audit actor from what requireOperatorToken resolved.
//
// IT REQUIRES A KEY ID AND FAILS LOUDLY WITHOUT ONE, on `adminActorFrom`'s terms: a
// zero key id means the row would name no credential, and this surface is reachable
// only by a token (D14 — a session is refused before it reaches a handler), so a
// caller reaching here without one is a wiring fault and not a request to be served.
// It is a 500 for the same reason: nothing about the caller is wrong, and a 403 would
// tell a client its credential was insufficient when the real fault is that the gate
// did not run.
//
// THE TRACE ID COMES FROM THE SAME CONTEXT every other audited action reads it from,
// so the row joins to the request's log line by exactly one mechanism.
func operatorActorFrom(ctx context.Context) (useraudit.Actor, bool) {
	c, ok := ctx.Value(operatorCallerKey{}).(operatorCaller)
	if !ok || c.KeyID.IsZero() {
		return useraudit.Actor{}, false
	}
	return useraudit.Actor{UserID: c.UserID, KeyID: c.KeyID, TraceID: traceIDFrom(ctx)}, true
}

// errNoOperatorActor means an operator handler reached its actor assembly with no
// api key in context, which requireOperatorToken should have made impossible.
var errNoOperatorActor = errors.New("an operator route reached its handler with no api key in context")

// ---------------------------------------------------------------------------
// handlers
// ---------------------------------------------------------------------------

// handleDisableUser turns an account off, in one transaction with the revocation of
// every session it holds.
//
//	POST /v1/users/{userID}/disable  →  204
//
// THE TRANSACTION IS NOT THIS FILE'S BUSINESS and the reason is worth stating,
// because a handler that seemed to need the order would be tempted to write it:
// `auth.Service.Disable` deletes the session rows and stamps the column in ONE
// transaction, sessions first. A column write and a later sweep is a window whose
// length is not a number anybody chose. See DECISIONS.md D13.
func (o options) handleDisableUser(w http.ResponseWriter, r *http.Request) {
	userID, ok := operatorSubject(r)
	if !ok {
		notFound(w, r)
		return
	}
	actor, ok := operatorActorFrom(r.Context())
	if !ok {
		unexpected(w, r, o.logger, errNoOperatorActor)
		return
	}

	if err := o.auth.Disable(r.Context(), auth.DisableInput{
		UserID:      userID,
		ActorUserID: actor.UserID,
		ActorKeyID:  actor.KeyID,
		TraceID:     actor.TraceID,
		At:          o.clk.Now(),
	}); err != nil {
		o.writeOperatorError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleEnableUser lifts a disable.
//
//	POST /v1/users/{userID}/enable  →  204
//
// IT RESTORES THE COLUMN AND NOTHING ELSE, and that is `auth.Service.Enable`'s
// contract rather than this handler's: the sessions the disable ended are gone and
// do not come back, so the owner signs in again. "Enable" reads like the inverse of
// everything a disable did, and a route that resurrected sessions would hand back
// credentials minted before the account was turned off — which is the thing the
// revocation exists to prevent.
func (o options) handleEnableUser(w http.ResponseWriter, r *http.Request) {
	userID, ok := operatorSubject(r)
	if !ok {
		notFound(w, r)
		return
	}
	// Same assembly as the disable, and it is not optional here either: a re-enable
	// that leaves no record leaves a trail saying the person is still disabled. See
	// `auth.Service.Enable`.
	actor, ok := operatorActorFrom(r.Context())
	if !ok {
		unexpected(w, r, o.logger, errNoOperatorActor)
		return
	}

	if err := o.auth.Enable(r.Context(), auth.EnableInput{
		UserID:      userID,
		ActorUserID: actor.UserID,
		ActorKeyID:  actor.KeyID,
		TraceID:     actor.TraceID,
		At:          o.clk.Now(),
	}); err != nil {
		o.writeOperatorError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// operatorSubject reads and parses the user id in the path.
//
// A MALFORMED ID IS ErrNotFound RATHER THAN A 422, on `accountIDFrom`'s terms: the
// path is part of a resource's identity, and "this is not an id this service issued"
// has to be the same answer as "this id is one this service issued and you cannot
// see it" — otherwise the second becomes probeable by anyone who can send a request.
//
// It reuses `userIDFrom`, the reader the member routes already use, rather than
// declaring a second one over the same chi parameter. Two readers over one parameter
// is two places to disagree about what "not an id" means, and the disagreement would
// show up as one route answering 404 where the other answers 422.
func operatorSubject(r *http.Request) (id.UUID, bool) {
	return userIDFrom(r)
}

// writeOperatorError maps this surface's refusals onto problem documents.
//
// IT IS SEPARATE FROM writeAdminError AND writeTenancyError for the reason
// `writeAdminError` gives for itself: the surfaces answer different questions, and a
// shared mapper would give each one an arm per case the others cannot produce — and
// the mapping is a contract with clients, so it should be one list somebody can read
// rather than a union that has to be read against every surface's vocabulary.
func (o options) writeOperatorError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, users.ErrNotFound):
		// 404, and one sentence for a user id that never existed and for one that
		// this deployment does not have. Behind the operator credential there is no
		// stranger to protect, and an operator told "no user with that id" can act on
		// it — see D12 for the contrast with the anonymous routes.
		problemFor(w, r, http.StatusNotFound, CodeNotFound,
			"no user with that id exists on this deployment")

	default:
		// Everything else is a 500, and the cause goes to the log rather than the
		// body. This includes a transaction that rolled back: a caller told the
		// request failed, no session was ended, and the operator has a trace id.
		unexpected(w, r, o.logger, err)
	}
}
