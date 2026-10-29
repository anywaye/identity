package deletion

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/anywaye/identity/internal/accounts"
	"github.com/anywaye/identity/internal/outbox"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/tenancy"
)

// ErrSolelyOwnedAccounts is the refusal: this user is the only owner of a team
// account, and a deletion cannot take that account with them.
//
// IT IS A REFUSAL AND NOT A CASCADE, and the choice is the whole of this
// package's hardest decision. The alternative — delete the account and everything
// scoped by it — is legal in one statement and destroys other people's data: the
// api keys other members hold, the OIDC registrations their products depend on,
// the pending invitations the account still wants, and the memberships
// themselves. Every one of those is somebody else's, and none of them asked to
// disappear because one person left.
//
// # WHY IT IS A REFUSAL RATHER THAN A TRANSFER WE INVENT HERE
//
// `accounts.Service.TransferOwnership` exists and could have been composed into
// a deletion that transfers first and deletes second. It was not, because it
// would be guessing: transfer needs a RECIPIENT, and the only person who knows
// who should inherit a workspace is whoever is still in it. A deletion that
// silently picked somebody would be a far worse failure than one that stops and
// names the account, so the answer is to refuse, name the accounts, and let the
// owner hand over ownership in the ordinary way — after which the departing user
// can delete their account in one more request.
//
// The refusal is deliberately NOT silent and NOT a count: it names every account,
// because a caller who is told "you own 2 accounts" and cannot find them cannot
// act on it, and one of those two accounts might be the only thing in the way.
var ErrSolelyOwnedAccounts = errors.New("sole owner of a team account")

// UnitOfWork runs a function inside a transaction.
//
// It is accounts.UnitOfWork again rather than a shared one, and the reason is
// that this package must not create an import edge to `accounts` for a type with
// one method — the interface is the seam, and two declarations of a one-method
// interface cost less than a shared package that exists to hold it.
type UnitOfWork interface {
	Do(ctx context.Context, fn func(ctx context.Context, q db.Querier) error) error
}

// UserStore is the slice of the users table a deletion needs, which is one
// statement.
//
// `DeleteForAccount` takes the account the user row is being removed on behalf
// of, and the reason is not a schema one. `accounts` has no foreign key to
// `users` in either direction, so removing a personal account cannot remove its
// user; the two are separate writes that happen to be in one transaction. Naming
// the account on the user delete makes the pairing explicit at the call site and
// is what lets the real-policy tests read back "this user's row went, inside the
// same transaction that took this account", which is a claim a signature can
// carry and a bare user id cannot.
type UserStore interface {
	DeleteForAccount(ctx context.Context, q db.Querier, accountID, userID id.UUID) error
}

// AccountReader is the two reads that decide whether a deletion can proceed.
//
// It returns `accounts.Account` rather than a local type because the caller
// already hands these rows to `accounts.Store.Delete`, and a conversion in
// between would be a second spelling of the same row.
type AccountReader interface {
	PersonalAccounts(ctx context.Context, q db.Querier, userID id.UUID) ([]accounts.Account, error)
	SolelyOwnedTeamAccounts(ctx context.Context, q db.Querier, userID id.UUID) ([]accounts.Account, error)
	Delete(ctx context.Context, q db.Querier, accountID id.UUID) error
}

// CredentialSweeper ends every credential the user holds.
//
// # IT IS A NAMED INTERFACE AND NOT recovery.Service, AND THAT IS NOT AN OVERSIGHT
//
// `recovery.Service.revokeEveryCredential` is the model, and it is unexported —
// it is two flows' private business, and both of them are in that package. This
// is the third flow, in a different package, with a different reason to sweep:
// recovery ends credentials so the OLD PASSWORD cannot come back, and deletion
// ends them because the person they belonged to does not exist.
//
// The interface is declared here anyway, and `cmd/identity` hands it a value
// built from `sessions.Store` and `oidc.Store` — the same two calls, in the same
// order. That is a duplication of two statements, and it is preferred to
// exporting recovery's unexported method because the alternative makes a package
// that knows about password resets and mail the dependency of a package that
// knows about deletion. The duplication is held to the original by
// `TestTheSweepIsTheRecoverySweep`'s twin in `internal/deletion/sweep_test.go`,
// which asserts the same two tables are swept in the same order.
//
// # IT MAY BE NIL, and then the deletion still removes the rows
//
// Every table this sweep touches cascades from `users` on delete anyway
// (00003, 00009, 00010, 00011, 00015), so a nil sweeper produces an end state
// that is correct and an audit trail that is silent. It is allowed rather than
// refused for the reason `accounts.CredentialRevoker` allows nil: a wiring bug
// should be visible as a missing capability at construction, not as a deletion
// that half-works in production.
type CredentialSweeper interface {
	RevokeEveryCredential(ctx context.Context, q db.Querier, userID id.UUID, at time.Time) error
}

// EventAppender is the slice of outbox.Store this use case needs.
type EventAppender interface {
	Append(ctx context.Context, q db.Querier, e outbox.Envelope) error
}

// Service is the account-deletion use cases.
type Service struct {
	uow      UnitOfWork
	users    UserStore
	accounts AccountReader
	sweep    CredentialSweeper
	events   EventAppender
}

// NewService wires the use case.
//
// sweep may be nil; see CredentialSweeper.
func NewService(
	uow UnitOfWork,
	users UserStore,
	acct AccountReader,
	sweep CredentialSweeper,
	events EventAppender,
) *Service {
	return &Service{uow: uow, users: users, accounts: acct, sweep: sweep, events: events}
}

// DeleteInput is a request to end a person's account.
//
// It is a struct for one reason that is not style: the account identity has to
// travel with the user id, because the transaction stands in as the USER and the
// two are different facts. `Delete(ctx, userID, at)` has nowhere to put it, and a
// method that cannot be told who is deleting whom is a method whose transaction
// cannot be given the right policy identity.
type DeleteInput struct {
	UserID id.UUID
	At time.Time
}

// Delete removes the user, and everything that belongs to them and to nobody
// else, in ONE transaction.
//
// # THE ORDER, AND IT IS THE REVERSE OF auth.Service.Disable'S
//
// That one goes: revocations, state change, record. This one goes: ownership
// question, revocations, the personal account, the user row, the event. Both
// orders put the revocations before the thing they are revoking against, and both
// put the irreversible write last — but the sequence here is otherwise different
// because the row the credentials belong to is the row that goes.
//
// # 1. THE OWNERSHIP QUESTION IS ASKED FIRST AND BEFORE ANYTHING IS REMOVED
//
// This is the only ordering choice in the function that is not forced, and it is
// forced the right way round. `SolelyOwnedTeamAccounts` asks "is this user the
// only owner of a team account", and if the memberships were deleted first the
// answer would be a lie: every account the user was in would have no owner at
// all, and the query would report all of them as solely-owned. Asking first is
// also what makes the refusal cost nothing — it happens before the first write,
// so a refused deletion has touched no row and written no event.
//
// # 2. THEN THE CREDENTIALS, ON THE REVERSE GROUNDING
//
// `auth.Service.Disable` sweeps because revocation is the only guarantee for a
// JWT, which nothing in this service's database can recall. Here the row itself
// is the guarantee: every credential table cascades from `users`. The sweep is
// still written, and the reason is that the cascade and the sweep do not say the
// same thing to a reader of the database. The cascade is invisible — an operator
// inspecting `sessions` sees rows simply absent, with no way to tell a deletion
// from a session that expired and was reaped. The sweep says it. And the sweep
// runs FIRST, so the credential tables are emptied by a statement that is
// attributable rather than by a side effect of the last one.
//
// # 3. THEN THE PERSONAL ACCOUNTS, THEN THE USER ROW
//
// The personal account first, and it is not tidiness: `accounts` has no foreign
// key to `users` in either direction, so the account a registration created for
// this user is an ORPHAN the moment the user row goes unless it is removed by
// name. Nothing cascades between them and nothing ever will, because the
// relationship runs the other way — a registration creates both, and the account
// is not derived from the user.
//
// # 4. AND THE EVENT IS WRITTEN INSIDE THE TRANSACTION THAT DID IT
//
// Last, for the reason `auth.Service.Disable` puts its audit row last: it cannot
// fail after the work is done and leave the work done, and there is nothing after
// it. A `identity.user.deleted` row that exists without the deletion is the one
// state a consumer cannot recover from — it would remove a customer that is
// still signing in.
func (s *Service) Delete(ctx context.Context, in DeleteInput) error {
	if in.UserID.IsZero() {
		return fmt.Errorf("%w: refusing to delete the nil user", accounts.ErrNotAMember)
	}
	if in.At.IsZero() {
		return fmt.Errorf("%w: a deletion with no instant stamps nothing and dates nothing", accounts.ErrNotAMember)
	}

	return s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		if err := tenancy.BeginUser(ctx, q, in.UserID); err != nil {
			return fmt.Errorf("naming the caller for the deletion: %w", err)
		}

		sole, err := s.accounts.SolelyOwnedTeamAccounts(ctx, q, in.UserID)
		if err != nil {
			return fmt.Errorf("checking for team accounts this user solely owns: %w", err)
		}
		if len(sole) > 0 {
			return soleOwnedError(sole)
		}

		if s.sweep != nil {
			if err := s.sweep.RevokeEveryCredential(ctx, q, in.UserID, in.At); err != nil {
				return fmt.Errorf("ending the deleted user's credentials: %w", err)
			}
		}

		if err := tenancy.BeginUser(ctx, q, in.UserID); err != nil {
			return fmt.Errorf("naming the caller for the personal account list: %w", err)
		}
		personal, err := s.accounts.PersonalAccounts(ctx, q, in.UserID)
		if err != nil {
			return fmt.Errorf("listing the personal accounts to remove: %w", err)
		}
		for _, account := range personal {
			if err := s.accounts.Delete(ctx, q, account.ID); err != nil {
				return fmt.Errorf("removing the personal account %q: %w", account.Name, err)
			}
		}

		var lastAccount id.UUID
		if len(personal) > 0 {
			lastAccount = personal[len(personal)-1].ID
		}
		if err := s.users.DeleteForAccount(ctx, q, lastAccount, in.UserID); err != nil {
			return fmt.Errorf("removing the user row: %w", err)
		}

		event, err := outbox.NewUserDeleted(in.At, in.UserID)
		if err != nil {
			return fmt.Errorf("building the %s event: %w", outbox.EventUserDeleted, err)
		}
		return s.events.Append(ctx, q, event)
	})
}

func soleOwnedError(sole []accounts.Account) error {
	names := make([]string, 0, len(sole))
	for _, account := range sole {
		names = append(names, fmt.Sprintf("%q (%s)", account.Name, account.Slug))
	}

	return fmt.Errorf("%w: %s. Transfer ownership to somebody else, or delete the account, "+
		"and then this request will succeed. A deletion cannot pick a new owner, because "+
		"only the people still in the account know who should have it",
		ErrSolelyOwnedAccounts, strings.Join(names, ", "))
}
