// Command identity-staff grants and revokes the staff property.
//
// `users.is_staff` (migrations/00030) is writable by exactly one code path —
// `users.Store.SetStaff` — and this command is its only caller. There is no
// HTTP route that writes the column, no self-service grant and no tenant-admin
// grant: the first staff user, and every one after them, is made by an
// operator running this with the database URL in hand.
//
// Usage:
//
//	identity-staff grant <email>   mark the account as staff
//	identity-staff revoke <email>  clear the mark
//	identity-staff status <email>  report the mark
//
// DATABASE_URL names the database, like the service's. The email is normalized
// exactly as registration normalizes it, so `KAKA@Example.com` grants the row
// stored as `kaka@example.com` rather than reporting "no such user".
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/users"
)

// grantTimeout bounds the whole command. It is a local operator tool, not a
// request handler: ten seconds is generous for two statements, and an
// unbounded wait would leave the operator guessing whether the grant landed.
const grantTimeout = 10 * time.Second

func main() {
	os.Exit(run(os.Args[1:], os.LookupEnv, os.Stdout, os.Stderr))
}

// run is the command, separated from main so tests can drive the argument
// parsing and the usage without a database. Anything that needs the database
// goes through apply, which the integration test below drives against a real
// one.
func run(args []string, lookup func(string) (string, bool), stdout, stderr *os.File) int {
	action, email, err := parse(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprintln(stderr, usage())
		return 2
	}

	dsn, ok := lookup("DATABASE_URL")
	if !ok || dsn == "" {
		fmt.Fprintln(stderr, "DATABASE_URL is not set: this command writes to the database the service reads")
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), grantTimeout)
	defer cancel()

	pool, err := db.Open(ctx, dsn, db.DefaultOptions())
	if err != nil {
		fmt.Fprintln(stderr, "opening the database pool:", err)
		return 1
	}
	defer pool.Close()

	user, err := apply(ctx, users.NewStore(pool), pool, action, email)
	if err != nil {
		if errors.Is(err, users.ErrNotFound) {
			fmt.Fprintf(stderr, "no user with address %q exists on this deployment\n", email)
			return 1
		}
		fmt.Fprintln(stderr, "the staff change failed:", err)
		return 1
	}

	fmt.Fprintf(stdout, "%s staff=%t\n", user.Email, user.IsStaff)
	return 0
}

// action is what the operator asked for.
type action string

const (
	actionGrant  action = "grant"
	actionRevoke action = "revoke"
	actionStatus action = "status"
)

// parse reads the action and the address, or reports the usage as an error.
//
// THE ADDRESS IS NORMALIZED HERE, not at the call site: registration stores
// the normalized form, so granting the raw form would look up a row that is
// never there. An empty address after normalization is a usage error rather
// than a lookup, because "no user with address ”" would be a confusing answer
// to a missing argument.
func parse(args []string) (action, string, error) {
	if len(args) != 2 {
		return "", "", errors.New("identity-staff: want exactly an action and an email address")
	}
	var act action
	switch args[0] {
	case "grant":
		act = actionGrant
	case "revoke":
		act = actionRevoke
	case "status":
		act = actionStatus
	default:
		return "", "", fmt.Errorf("identity-staff: unknown action %q", args[0])
	}
	email := users.NormalizeEmail(args[1])
	if email == "" {
		return "", "", errors.New("identity-staff: the email address is empty")
	}
	if err := users.ValidateEmail(email); err != nil {
		return "", "", fmt.Errorf("identity-staff: %w", err)
	}
	return act, email, nil
}

func usage() string {
	return "usage: identity-staff (grant|revoke|status) <email>  # with DATABASE_URL set"
}

// apply performs the action against the store and returns the row as it now
// stands, so the operator sees what the command did rather than what it was
// asked to do.
//
// GRANT AND REVOKE ARE IDEMPOTENT: setting what is already set is a success,
// because an operator re-applying a state from a runbook is not making a
// mistake. STATUS writes nothing.
func apply(ctx context.Context, store *users.Store, q db.Querier, act action, email string) (users.User, error) {
	user, err := store.ByEmail(ctx, q, email)
	if err != nil {
		return users.User{}, err
	}

	switch act {
	case actionGrant:
		if err := store.SetStaff(ctx, q, user.ID, true); err != nil {
			return users.User{}, err
		}
	case actionRevoke:
		if err := store.SetStaff(ctx, q, user.ID, false); err != nil {
			return users.User{}, err
		}
	case actionStatus:
		// Nothing to write: the row below is the answer.
	default:
		return users.User{}, fmt.Errorf("identity-staff: unknown action %q", act)
	}

	return store.ByID(ctx, q, user.ID)
}
