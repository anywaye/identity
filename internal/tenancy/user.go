// The CALLER, carried the same way the account is.
//
// A separate file rather than two more functions in scope.go, for the reason
// scope.go's own package comment gives: that file's whole argument is that there
// is exactly ONE place that writes `cafaye.account_id`, and a reader hunting that
// one place should not have to decide whether a second statement is part of it.
// The same reader is going to come here.
//
// # WHY THIS EXISTS AT ALL
//
// `GET /v1/accounts` asked "which accounts is this person in", and the answer was
// an empty list for a user who owned one. The membership row was in the database,
// the join was correct, and the query succeeded — `account_users` is protected by
// `account_id = (select cafaye.current_account_id())`, and a caller who has not
// chosen an account yet is not standing in one.
//
// That is a different question from the one the account seam answers, so it needs
// a different seam. `cafaye.begin_user/1` names the CALLER for the same reason
// `cafaye.begin_account/1` names the account: naming a thing is what a GUC is
// for, and the value is the one the service has ALREADY resolved — the same
// `users.id` the middleware authenticated — so nothing here is chosen by the
// caller.
//
// # THE ASYMMETRY WORTH KNOWING BEFORE THE FIRST PAGER RENDERS
//
// Forgetting `begin_account` makes every account-scoped read empty. That is loud:
// the service's first integration test goes red and somebody looks at it.
//
// Forgetting `begin_user` makes ONE list empty — "your accounts" — while every
// other query on the same connection keeps working, because the account scope is
// untouched by the caller scope. The symptom is a screen that always says "no
// accounts yet" for a user who has one, and nothing anywhere fails: no error, no
// denied query, no red assertion. It looks exactly like a permission that was
// never granted, and that is what it looks like in a log too.
//
// WHICH IS WHY THIS IS NOT WIRED INTO TxRunner. The account seam lives there
// because every account-scoped write goes through a use case, so "every write
// runs under an identity" is a property of one type. That argument does not carry
// over: only one query in this service needs the caller scope, and paying a round
// trip on every transaction of every request to satisfy it is the cost
// scope.go explicitly declines for the account seam's own empty case. So the one
// call site opens the transaction it needs — the same shape as BeginAccount, which
// exists for exactly one call site and says so.

package tenancy

import (
	"context"
	"fmt"

	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
)

// beginUserSQL is kit's seam, called by name rather than written out, for the
// reason beginAccountSQL gives.
const beginUserSQL = `select cafaye.begin_user($1)`

// userKey is the context key the caller travels on.
//
// An unexported struct type rather than a string, for the reason accountKey
// gives: a context key that is a plain string can be forged by any package that
// guesses the name, and this one decides whose memberships a statement can see.
type userKey struct{}

// WithUser returns a context carrying the caller.
//
// It is called with the SAME `users.id` the authentication middleware resolved,
// never with anything from a body or a path. That is the whole rule that keeps
// this seam out of caller-supplied input, and it is why this exists at all rather
// than a caller passing its own id to a store method: a value that reached the
// database from a request could be chosen by whoever made the request.
//
// A zero user is refused rather than carried, for the reason WithAccount refuses
// a zero account: "no caller" and "the nil uuid" must not be two spellings of one
// thing, and a caller that meant "no caller" does not have a membership query.
func WithUser(ctx context.Context, user id.UUID) context.Context {
	return context.WithValue(ctx, userKey{}, user)
}

// UserFrom returns the caller a request is acting as, and whether it set one.
//
// The bool carries the same weight as AccountFrom's: no caller is expected on a
// login, on a registration's pre-user phase, and on every health check, and
// "expected" and "never wired" have to be distinguishable.
func UserFrom(ctx context.Context) (id.UUID, bool) {
	user, ok := ctx.Value(userKey{}).(id.UUID)
	if !ok || user.IsZero() {
		return id.UUID{}, false
	}
	return user, true
}

// BeginUser sets the caller on the caller's own transaction, for the reads that
// happen BEFORE a request has chosen an account.
//
// THIS EXISTS FOR EXACTLY ONE CALL SITE — the account list — and the reason is
// the same shape as BeginAccount's: the read is scoped by the caller rather than
// by an account, and a store handed a bare pool cannot see the caller at all,
// because `begin_user` is transaction-local and a pooled connection outside a
// transaction has already forgotten it by the time the next statement runs.
//
// A zero user is REFUSED rather than cleared, and this is BeginAccount's contract
// rather than its opposite: a caller reaching this with no user is about to run
// the one query whose entire subject is the caller, and clearing would make it
// return an empty list that reads exactly like a real answer. Naming it here
// makes the mistake legible at the call site rather than leaving it to be read
// out of a `[]`.
//
// The substrate's own `cafaye.begin_user(NULL)` DOES clear, because a worker with
// no caller is a legitimate call and it goes through there rather than through a
// hand-rolled `set_config`. This wrapper refuses because its only call site is a
// membership read, and a membership read with no membership to find is not a
// thing anybody meant to ask for.
func BeginUser(ctx context.Context, q db.Querier, user id.UUID) error {
	if user.IsZero() {
		return fmt.Errorf("%w: refusing to begin as the nil user", ErrNoIdentity)
	}
	if _, err := q.Exec(ctx, beginUserSQL, user); err != nil {
		return fmt.Errorf("%w: %w", ErrNoIdentity, err)
	}
	return nil
}
