package tenancy

import (
	"context"
	"errors"
	"fmt"

	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
)

// ErrNoIdentity is returned when the GUC could not be set.
//
// It is a sentinel so a caller can match it with errors.Is rather than by
// substring, and it exists at all because a failure here is NOT an absent
// account. An absent account reads zero rows and looks like a service with no
// data; a REFUSED begin_account looks like a database problem, and the two
// demand different responses.
var ErrNoIdentity = errors.New("setting the account identity on the transaction")

const beginAccountSQL = `select anywaye.begin_account($1)`

type accountKey struct{}

// WithAccount returns a context carrying the account a request acts as.
//
// It is called by the middleware that has already resolved the account, and by
// the registration use case for the account it has just created. Both are places
// where the account is a FACT rather than something read from a request body,
// which is the rule that keeps tenancy out of caller-supplied input.
//
// A zero account is refused rather than carried: it would read as an account no
// row can have, and a caller that meant "no account" wanted WithNoAccount, which
// this package does not offer because "none" and "the nil uuid" must not be two
// spellings of one thing.
func WithAccount(ctx context.Context, account id.UUID) context.Context {
	return context.WithValue(ctx, accountKey{}, account)
}

// AccountFrom returns the account a request is acting as, and whether it set one.
//
// The bool is not a convenience. "No account" is a legitimate and LOAD-BEARING
// state — a login and a registration's pre-account phase both have none — and it
// has to be distinguishable from a context that was never given one, because the
// first is expected and the second is a wiring bug.
func AccountFrom(ctx context.Context) (id.UUID, bool) {
	account, ok := ctx.Value(accountKey{}).(id.UUID)
	if !ok || account.IsZero() {
		return id.UUID{}, false
	}
	return account, true
}

func beginAccount(ctx context.Context, q db.Querier, account id.UUID) error {
	if _, err := q.Exec(ctx, beginAccountSQL, account); err != nil {
		return fmt.Errorf("%w: %w", ErrNoIdentity, err)
	}
	return nil
}

// BeginAccount sets the identity on the caller's own transaction, for the write
// that CREATES the account it acts as.
//
// THIS EXISTS FOR EXACTLY ONE CALL SITE, and it is the exception that proves the
// rule. A request that authenticates resolves its account before it writes, so
// TxRunner can set the identity from the context. Registration does not have an
// account at all until the middle of its transaction: it creates a personal
// account and then writes the owner's membership into it, and the membership
// INSERT meets `with check (account_id = (select anywaye.current_account_id()))`
// with a NULL identity, which is not true and is refused with SQLSTATE 42501.
//
// So the account has to be named before the membership is written, and the value
// that names it is the one the provisioning step just returned. Calling it here,
// on the same transaction, is "begin_account as the NEW account" rather than as
// nobody.
//
// It is a function rather than a field on the request because the identity is a
// property of the TRANSACTION, and the transaction is what the substrate scopes
// it to. Anything else — a context value, a parameter threaded through the store
// — would put it somewhere the RLS policies cannot see.
func BeginAccount(ctx context.Context, q db.Querier, account id.UUID) error {
	if account.IsZero() {
		return fmt.Errorf("%w: refusing to begin as the nil account", ErrNoIdentity)
	}
	return beginAccount(ctx, q, account)
}

// TxRunner is the UnitOfWork every service in this repository is constructed
// with, in place of db.TxRunner.
//
// It is a DROP-IN for db.TxRunner — same field, same Do — because six packages
// declare their own `UnitOfWork` interface with an identical method set, and a
// seam that had to be threaded through all six would be a seam somebody would
// route around. This type satisfies all of them with no signature change
// anywhere, so a service cannot be constructed with an unwired transaction
// runner by accident.
//
// WHAT IT DOES, AND WHY IT IS NOT OPTIONAL: after Begin it sets the account
// identity, when the request has one, before handing the transaction to the use
// case. Every account-scoped write in this service goes through a use case that
// goes through here, so "every account-scoped write runs under an identity" is a
// property of this one type rather than a rule repeated at each call site.
//
// A request with NO account — a login, a session lookup, a registration's first
// statements — is left alone. Setting `begin_account(NULL)` would be the same
// state, but it would be a statement on the hot authentication path whose only
// effect is to clear a GUC that is already unset on a fresh connection, and a
// service that pays a round trip to say nothing is a service that will be
// measured on it.
//
// Every query KEEPS its own `where account_id = ?`. That is unchanged by this
// type and is not optional: the predicate is what makes the query indexable, and
// RLS is defense in depth rather than a license to delete it.
type TxRunner struct {
	db.TxRunner
}

// Do runs fn inside a transaction that already carries the request's account.
//
// On any failure the transaction is rolled back by db.TxRunner, which also covers
// the failure of beginAccount itself — the identity is set before the use case
// runs, so a transaction that never got one never gets to write anything.
func (r TxRunner) Do(ctx context.Context, fn func(ctx context.Context, q db.Querier) error) error {
	return r.TxRunner.Do(ctx, func(ctx context.Context, q db.Querier) error {
		if account, ok := AccountFrom(ctx); ok {
			if err := beginAccount(ctx, q, account); err != nil {
				return err
			}
		}
		return fn(ctx, q)
	})
}
