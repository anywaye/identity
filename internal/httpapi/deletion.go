package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/cafaye/identity/internal/deletion"
)

// # THE ROUTE THAT ENDS A PERSON'S PRESENCE.
//
// One route, one file, mounted on the AUTH routes rather than the tenancy ones
// because its subject is a person and not one of their memberships — the same
// distinction DECISIONS.md D14 draws for the operator surface's scope, and the
// same reason `TestEveryMountedRouteIsAnAccountRoute` would refuse a
// `/v1/accounts/...` path here.
//
// # WHY IT IS SESSION-ONLY AND NOT `requireAccountRole`
//
// Every account route goes through `requireAccountRole` because it has an
// `{accountID}` in its path to resolve a role against. This one has no account:
// a user belongs to as many accounts as they like, so there is no single
// membership to authorize against, and inventing one — "their personal account"
// — would make deleting a person depend on which account the router happened to
// pick. So the credential is resolved the way `GET /v1/me` resolves it, with
// `currentUser`, and the answer to "who is this" has one implementation in this
// service rather than one per route.
//
// # AND WHY IT IS NOT IN accountRouteScopes
//
// It is not there because it CANNOT be reached by a scoped token at all, and the
// table's contract is about routes a token might reach. `requireAccountRole` is
// what consults `scopeRequiredBy`, this route does not go through it, and there
// is no scope that would be right: deleting a person is not a permission any
// machine credential should hold, because the whole subject of the operation is
// "the caller is this person". Adding a row would be a type with no enforcement
// behind it, which is worse than an absent one — it would read as a decision.
//
// The enforcement that DOES exist is the absence of any token path: there is no
// scope check here to pass because there is no token here to check, and
// `currentUser` answers 401 for a token that resolves to no session.

// Deletion is the slice of internal/deletion this surface needs.
//
// It is one method rather than the service type, for the reason `Auth` and
// `Tenancy` are interfaces: the HTTP layer takes the use case and not the
// package, so a handler cannot reach a store and a test cannot reach a database
// through this struct.
type Deletion interface {
	Delete(ctx context.Context, in deletion.DeleteInput) error
}

// WithDeletion mounts DELETE /v1/me.
//
// It is ignored when d is nil, which leaves the route unmounted rather than
// mounted-and-500 — the same rule as every other Option here.
func WithDeletion(d Deletion) Option {
	return func(o *options) {
		if d != nil {
			o.deletion = d
		}
	}
}

// registerDeletionRoute mounts DELETE /v1/me.
//
// It has its own registrar for the reason every other surface does — a name a
// reader can go looking for — and because this route is conditional on something
// nothing else on the auth surface is conditional on. `GET /v1/me` is mounted
// whenever there is an auth service, in every deployment, forever; this one is
// mounted when the deletion use case was built, which is a wiring decision rather
// than a platform fact.
func (o options) registerDeletionRoute(r chiRouter) {
	if o.deletion == nil {
		return
	}

	// SESSION-ONLY, and the reason is in the file header: there is no scope that
	// could authorize this for a token, so a token is refused by the handler's own
	// resolution rather than by a scope check. `sessionCredentialOnly` is NOT
	// wrapped around it because that middleware does not authenticate — it only
	// refuses the api-key prefix — and the 401 has to come from somewhere anyway.
	r.Delete("/v1/me", o.handleDeleteMe)
}

// handleDeleteMe ends the caller's own account.
//
//	DELETE /v1/me  →  204
//
// # 204 AND NOT 200 WITH A BODY
//
// There is nothing to describe. The resource is gone, and a body describing a
// deleted thing is a second claim about state the caller is not entitled to
// anything further about. `DELETE /v1/session` answers 204 for the same reason.
//
// # 401 IS THE ONLY ANONYMOUS ANSWER, AND IT SAYS NOTHING
//
// `currentUser` collapses a missing token, an unknown one, an expired one, a
// revoked one, and an api key — which resolves to no session — into one 401 with
// one body. That is the enumeration answer this route can give: "this session is
// not valid", which carries no statement about whether an account exists, and
// could not be turned into one, because no identifier arrives from a stranger.
// The row in `internal/httpapi/anonymous_enumeration_test.go` says so in a
// sentence and is measured by a probe.
//
// # 409 IS THE REFUSAL, AND IT NAMES THE ACCOUNTS
//
// `ErrSolelyOwnedAccounts` becomes a 409 rather than a 422. The request was
// well-formed and the server understood it perfectly; what conflicts is the
// account's state — this person is the only owner of a team account — and 409 is
// the status for exactly that. A 422 would say the CALLER sent something wrong,
// which is the opposite of the truth and would send a client looking for a
// validation bug in a request that has none.
//
// The detail names every account, because the alternative is a count the caller
// cannot act on. It is emitted through `writeProblem` like every other refusal,
// so the code is the DECLARED `CodeAccountOwnershipConflict` rather than a string
// literal, and the names are in the human-readable `detail` field — a machine
// consumer switches on the code and a person reads the detail.
//
// # AND THE CONSTANT IS LOAD-BEARING RATHER THAN TIDY
//
// `problemFor` looks the code up in a fixed `titles` map, and a code that is NOT
// in it renders the fallback "Request failed". A refusal whose human-readable
// summary says nothing about ownership is a refusal somebody has to read in full
// to understand, and the entire point of naming the accounts is that they are
// acted on rather than read. Declaring the code and leaving it out of that map
// would have shipped a 409 titled "Request failed" — correct by the spec and
// useless to the person it was written for.
//
// `problem_test.go`'s `TestProblemTitlesAreStablePerCode` and
// `TestProblemStatusAndCodeAgree` are what hold it: a code added to the const
// block without a title fails the first, and one added with the wrong status
// fails the second.
func (o options) handleDeleteMe(w http.ResponseWriter, r *http.Request) {
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	err := o.deletion.Delete(r.Context(), deletion.DeleteInput{
		UserID: user.ID,
		At:     o.clk.Now(),
	})
	switch {
	case err == nil:
		noContent(w)

	case errors.Is(err, deletion.ErrSolelyOwnedAccounts):
		problemFor(w, r, http.StatusConflict, CodeAccountOwnershipConflict, err.Error())

	default:
		unexpected(w, r, o.logger, err)
	}
}

// The compile-time assertion that the real service satisfies the seam, so a change
// to `deletion.Service`'s signature is a build failure HERE rather than a wiring
// failure in production. Without it the handler compiles against the interface
// and the mismatch only surfaces at the one line in `cmd/identity` that builds it.
var _ Deletion = (*deletion.Service)(nil)
