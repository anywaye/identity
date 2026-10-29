package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/users"
)

const grantTimeout = 10 * time.Second

func main() {
	os.Exit(run(os.Args[1:], os.LookupEnv, os.Stdout, os.Stderr))
}

func run(args []string, lookup func(string) (string, bool), stdout, stderr *os.File) int {
	action, email, err := parse(args)
	if err != nil {
		if werr := say(stderr, err.Error()); werr != nil {
			return 1
		}
		if werr := say(stderr, usage()); werr != nil {
			return 1
		}
		return 2
	}

	dsn, ok := lookup("DATABASE_URL")
	if !ok || dsn == "" {
		if werr := say(stderr, "DATABASE_URL is not set: this command writes to the database the service reads"); werr != nil {
			return 1
		}
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), grantTimeout)
	defer cancel()

	pool, err := db.Open(ctx, dsn, db.DefaultOptions())
	if err != nil {
		if werr := say(stderr, fmt.Sprintf("opening the database pool: %v", err)); werr != nil {
			return 1
		}
		return 1
	}
	defer pool.Close()

	user, err := apply(ctx, users.NewStore(pool), pool, action, email)
	if err != nil {
		if errors.Is(err, users.ErrNotFound) {
			if werr := say(stderr, fmt.Sprintf("no user with address %q exists on this deployment", email)); werr != nil {
				return 1
			}
			return 1
		}
		if werr := say(stderr, fmt.Sprintf("the staff change failed: %v", err)); werr != nil {
			return 1
		}
		return 1
	}

	if werr := say(stdout, fmt.Sprintf("%s staff=%t", user.Email, user.IsStaff)); werr != nil {
		return 1
	}
	return 0
}

func say(w *os.File, msg string) error {
	_, err := fmt.Fprintln(w, msg)
	return err
}

type action string

const (
	actionGrant  action = "grant"
	actionRevoke action = "revoke"
	actionStatus action = "status"
)

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
	default:
		return users.User{}, fmt.Errorf("identity-staff: unknown action %q", act)
	}

	return store.ByID(ctx, q, user.ID)
}
