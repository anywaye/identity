
package tenancy

import (
	"context"
	"fmt"

	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
)

const beginUserSQL = `select anywaye.begin_user($1)`

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
// The substrate's own `anywaye.begin_user(NULL)` DOES clear, because a worker with
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
