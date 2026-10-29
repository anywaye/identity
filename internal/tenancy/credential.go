package tenancy

import (
	"context"
	"errors"
	"fmt"

	"github.com/anywaye/identity/internal/platform/db"
)


// ErrNoCredential is returned when the credential GUC could not be set.
//
// It is a sentinel, and for the same reason ErrNoIdentity is one: a failure here
// is NOT an unknown credential. An unknown credential reads zero rows and looks
// like a service with no data; a REFUSED begin_credential looks like a database
// problem, and the two demand different responses.
var ErrNoCredential = errors.New("setting the credential digest on the transaction")

const beginCredentialSQL = `select anywaye.begin_credential($1)`

func beginCredential(ctx context.Context, q db.Querier, digest string) error {
	if digest == "" {
		return fmt.Errorf("%w: refusing to begin with an empty digest", ErrNoCredential)
	}
	if _, err := q.Exec(ctx, beginCredentialSQL, digest); err != nil {
		return fmt.Errorf("%w: %w", ErrNoCredential, err)
	}
	return nil
}

// BeginCredential sets the presented digest on the caller's own transaction,
// for the read that NAMES the account it acts as.
//
// THIS EXISTS FOR EXACTLY ONE CALL SITE, and it is the exception that proves
// the rule the way BeginAccount is. `accounts.Service.Accept` resolves an
// invitation by its token digest before any account is known — the account is
// what that lookup is FOR — so CredentialResolver's transaction cannot serve
// it: the resolution and the redemption write are one use case, and splitting
// them across two transactions would reopen the revocation window
// `MarkInvitationAccepted`'s conditional UPDATE exists to close.
//
// It is a function rather than a second seam type because the digest it sets
// is the one the caller already computed — `accounts.Digest` hashes the token
// off the request before any query runs — and this type never derives one from
// a result. That direction is load-bearing for the reason CredentialResolver.Do
// states.
func BeginCredential(ctx context.Context, q db.Querier, digest string) error {
	if digest == "" {
		return fmt.Errorf("%w: refusing to begin with an empty digest", ErrNoCredential)
	}
	return beginCredential(ctx, q, digest)
}

// CredentialResolver runs one resolution inside a transaction that already
// carries the digest the caller presented.
//
// It is the structural mirror of TxRunner, and it is a drop-in for it in the
// same sense — same embedded `db.TxRunner`, same `Do` — with ONE difference that
// is the entire reason this is a second type: `Do` takes the digest, and there
// is no account parameter for a caller to pass.
type CredentialResolver struct {
	db.TxRunner
}

// Do runs fn inside a transaction that carries `digest`, before fn runs.
//
// The digest is what the caller PRESENTED, computed by the caller before any
// query — `apikeys.Digest` hashes the token off the request — and this type
// never derives one from a result. That direction is load-bearing: a digest
// computed FROM a row would be a digest the database chose, and a policy
// qualified by it would scope the read to whatever the substrate decided was
// interesting rather than to what the caller proved it held.
//
// # IT IS TRANSACTION-LOCAL, FOR THE SAME REASON begin_account IS
//
// `set_config(..., is_local => true)` outside an explicit transaction expires at
// the end of the statement that set it, which is why the digest is set INSIDE the
// transaction `db.TxRunner` has already begun rather than on a pooled connection.
// It is also why the safe form is the transaction-local one: a session-level
// digest would survive the pool and hand one resolution's credential to the next
// connection to be leased, which is a bearer token delivered to a stranger. After
// the transaction commits the digest is gone and the connection is an ordinary
// no-identity session, until `requireAccountRole` sets the account.
//
// # WHAT THE SESSION MAY DO WITH IT
//
// Exactly two things, and the second is 00028's: read the credential row
// whose digest it presented, and read the membership rows of that row's
// (account, user) pair — which is what lets ByDigest's JOIN return. The
// membership half is admitted by account_users_anywaye_resolve, whose EXISTS
// runs under api_keys' own policies and so can only match the presented
// row, and only while it is live (revoked_at IS NULL is in the policy).
// `select *` from api_keys inside one of these transactions returns THAT row
// and not the table, because the predicate is in the POLICY as well as in
// the caller's query — RLS policies combine permissively, and a policy that
// merely said "a credential session may select this table" would hand the
// caller a table-wide browse.
//
// It cannot write. There is no insert/update/delete counterpart on either
// resolve policy, so a resolution session meets the ordinary account policies
// on the write side, where a NULL identity is 42501: a service cannot mint a
// credential while resolving one.
//
// And it opens no third table. Two policies, on the two named tables the
// resolution query joins, and the membership one names the credential's own
// pair rather than the caller — there is still no session in which a digest
// reads a membership it did not present the credential for.
func (r CredentialResolver) Do(ctx context.Context, digest string, fn func(ctx context.Context, q db.Querier) error) error {
	return r.TxRunner.Do(ctx, func(ctx context.Context, q db.Querier) error {
		if err := beginCredential(ctx, q, digest); err != nil {
			return err
		}
		return fn(ctx, q)
	})
}
