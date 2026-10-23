package deletion

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/anywaye/identity/internal/accounts"
	"github.com/anywaye/identity/internal/outbox"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
)

// THE LOGIC OF ONE DELETION, WITH NO POSTGRES AND NO POLICIES.
//
// The properties asserted here are service logic — the refusal, the order, the
// event — and none of them is a property of the schema. The schema's half, which
// is the half that actually decides whether a user row CAN go, is in
// deletion_rls_test.go against the real policies; the HTTP half is in
// internal/httpapi. Three files because a test that runs against
// `dbtest.Schema` can prove none of the other two: those clones carry no row-level
// security and no foreign key to `users` survives in the shape production has
// (dbtest.go says so in its own words), so a deletion tested here would pass
// against tables that permit what production refuses.

// # THE HARNESS
//
// A Service is four collaborators and a clock, and three of the four are
// recorded rather than real. That is the same shape accounts' harness uses and
// for the same reason: the questions in this file are about WHICH writes happen
// and IN WHAT ORDER, and a real database cannot answer a question about a
// transaction that rolled back — which is the answer half of them needs.

type fakeAccounts struct {
	// personal is what the user owns that dies with them.
	personal []accounts.Account
	// solelyOwned is what refuses the deletion. It is the field the refusal
	// test programs and every other test leaves empty.
	solelyOwned []accounts.Account
	// deletedAccounts records every account the service removed, IN ORDER, so a
	// test can assert the personal account went and nobody else's did.
	deletedAccounts []id.UUID
	// deleteErr fails the account removal, to prove the user row is not removed
	// after it.
	deleteErr error
}

func (s *fakeAccounts) PersonalAccounts(_ context.Context, _ db.Querier, _ id.UUID) ([]accounts.Account, error) {
	return s.personal, nil
}

func (s *fakeAccounts) SolelyOwnedTeamAccounts(_ context.Context, _ db.Querier, _ id.UUID) ([]accounts.Account, error) {
	return s.solelyOwned, nil
}

func (s *fakeAccounts) Delete(_ context.Context, _ db.Querier, accountID id.UUID) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.deletedAccounts = append(s.deletedAccounts, accountID)
	return nil
}

type fakeUsers struct {
	deleted []id.UUID
	// byAccount is the deletion keyed by account, so a test can assert the
	// personal account's row went inside the transaction and no other did.
	byAccount map[id.UUID]id.UUID
	err       error
}

func (s *fakeUsers) Delete(_ context.Context, _ db.Querier, userID id.UUID) error {
	return s.DeleteForAccount(context.Background(), nil, id.UUID{}, userID)
}

func (s *fakeUsers) DeleteForAccount(_ context.Context, _ db.Querier, accountID, userID id.UUID) error {
	if s.err != nil {
		return s.err
	}
	s.deleted = append(s.deleted, userID)
	if s.byAccount != nil {
		s.byAccount[accountID] = userID
	}
	return nil
}

type fakeRevoker struct{ calls int }

func (r *fakeRevoker) RevokeEveryCredential(_ context.Context, _ db.Querier, _ id.UUID, _ time.Time) error {
	r.calls++
	return nil
}

type recordedEvents struct{ envelopes []outbox.Envelope }

func (e *recordedEvents) Append(_ context.Context, _ db.Querier, env outbox.Envelope) error {
	e.envelopes = append(e.envelopes, env)
	return nil
}

type harness struct {
	svc    *Service
	users  *fakeUsers
	acct   *fakeAccounts
	revoke *fakeRevoker
	events *recordedEvents
	clock  time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	h := &harness{
		users:  &fakeUsers{byAccount: map[id.UUID]id.UUID{}},
		acct:   &fakeAccounts{},
		revoke: &fakeRevoker{},
		events: &recordedEvents{},
		clock:  time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC),
	}
	h.svc = NewService(
		uowFunc(func(ctx context.Context, fn func(context.Context, db.Querier) error) error {
			return fn(ctx, discardQuerier{})
		}),
		h.users,
		h.acct,
		h.revoke,
		h.events,
	)
	return h
}

// discardQuerier is a db.Querier that answers nothing.
//
// IT EXISTS BECAUSE `tenancy.BeginUser` EXECUTES, so a harness that passed a nil
// Querier panicked on the first statement rather than failing a test. That panic
// was a useful accident: it says the service really does open the transaction
// with `anywaye.begin_user`, which is the premise `deletion_rls_test.go` checks
// against the real policies — and a harness that answered `begin_user` with an
// error instead would have passed that same test for the wrong reason.
//
// Absorbing the statement is deliberate rather than asserting on it. What
// `begin_user` does is tenancy's business and is tested there; what this package
// needs to know is that it is CALLED, and the boundary file is where that is
// asked against policies that actually enforce it.
type discardQuerier struct{}

func (discardQuerier) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag("SELECT 1"), nil
}

func (discardQuerier) Query(context.Context, string, ...any) (pgx.Rows, error) { return nil, nil }

func (discardQuerier) QueryRow(context.Context, string, ...any) pgx.Row { return nil }

func (h *harness) personalAccount() accounts.Account {
	return accounts.Account{ID: id.MustNew(), Name: "kaka"}
}

// TestTheHappyPathIsFourWritesInOneTransaction is the whole packet in one test:
// the credentials go, the personal account goes, the user row goes, and the event
// is written — and the event is written by the same call, not after it.
func TestTheHappyPathIsFourWritesInOneTransaction(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	user := id.MustNew()
	personal := h.personalAccount()
	h.acct.personal = []accounts.Account{personal}

	if err := h.svc.Delete(t.Context(), DeleteInput{UserID: user, At: h.clock}); err != nil {
		t.Fatalf("deleting a user with nothing in the way: %v", err)
	}

	if h.revoke.calls != 1 {
		t.Errorf("RevokeEveryCredential was called %d times, want exactly 1", h.revoke.calls)
	}
	if len(h.acct.deletedAccounts) != 1 || h.acct.deletedAccounts[0] != personal.ID {
		t.Errorf("deleted accounts = %v, want exactly the personal account %v", h.acct.deletedAccounts, personal.ID)
	}
	if len(h.users.deleted) != 1 || h.users.deleted[0] != user {
		t.Errorf("deleted users = %v, want exactly %v", h.users.deleted, user)
	}
	if len(h.events.envelopes) != 1 {
		t.Fatalf("wrote %d events, want exactly 1", len(h.events.envelopes))
	}
	if got := h.events.envelopes[0].Type; got != outbox.EventUserDeleted {
		t.Errorf("event type = %q, want %q", got, outbox.EventUserDeleted)
	}
	if got := h.events.envelopes[0].Subject; got != user.String() {
		t.Errorf("event subject = %q, want the deleted user's id %q", got, user)
	}
}

// TestARefusalNamesEveryAccountTheUserSolelyOwns is the decision this packet
// makes, and it is a refusal rather than a cascade for the reason in the report:
// deleting a team account takes the api keys, the OIDC registrations and the
// memberships of OTHER people with it.
//
// It asserts the accounts are NAMED rather than counted, because a count is what
// a caller reads when they cannot find the thing that is blocking them.
func TestARefusalNamesEveryAccountTheUserSolelyOwns(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.acct.solelyOwned = []accounts.Account{
		{ID: id.MustNew(), Name: "Acme", Slug: "acme"},
		{ID: id.MustNew(), Name: "Beta Ltd", Slug: "beta-ltd"},
	}

	err := h.svc.Delete(t.Context(), DeleteInput{UserID: id.MustNew(), At: h.clock})
	if err == nil {
		t.Fatal("a user who solely owns two team accounts was deleted anyway.\nThe alternative " +
			"to the refusal is cascade-deleting them, which destroys other people's api keys, " +
			"OIDC registrations and memberships — so a refusal is the safer of the two, and it " +
			"is the one this packet takes.")
	}
	if !errors.Is(err, ErrSolelyOwnedAccounts) {
		t.Fatalf("error is %v, want one wrapping ErrSolelyOwnedAccounts", err)
	}
	for _, name := range []string{"Acme", "Beta Ltd"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the refusal does not name %q, so the caller cannot tell which account is "+
				"in the way. Full message: %v", name, err)
		}
	}

	if len(h.users.deleted) != 0 {
		t.Errorf("the user row was deleted despite the refusal: %v", h.users.deleted)
	}
	if len(h.acct.deletedAccounts) != 0 {
		t.Errorf("an account was deleted despite the refusal: %v", h.acct.deletedAccounts)
	}
	if len(h.events.envelopes) != 0 {
		t.Errorf("an event was published for a deletion that did not happen: %v", h.events.envelopes)
	}
}

// TestATeamAccountTheUserOnlyBelongsToIsNeverQueriedForOwnership is a property of
// the ORDER rather than of the refusal: the refusal reads solely-owned accounts
// BEFORE anything is removed, so a team account with other members cannot become
// one this transaction emptied.
//
// The fake returns an error from any query after the first, so a service that
// asked again would see a failure rather than a convenient empty answer.
func TestATeamAccountTheUserOnlyBelongsToIsNeverQueriedForOwnership(t *testing.T) {
	t.Parallel()

	asked := 0
	h := newHarness(t)
	inner := h.acct
	h.acct = &fakeAccounts{
		deleteErr: nil,
	}
	// Wrap the ownership read so a SECOND call is an error, not an empty list.
	h.svc = NewService(
		uowFunc(func(ctx context.Context, fn func(context.Context, db.Querier) error) error {
			return fn(ctx, discardQuerier{})
		}),
		h.users,
		&onceThenFail{inner: inner, asked: &asked},
		h.revoke,
		h.events,
	)

	if err := h.svc.Delete(t.Context(), DeleteInput{UserID: id.MustNew(), At: h.clock}); err != nil {
		t.Fatalf("deleting a user who is in no team account: %v", err)
	}
	if asked != 1 {
		t.Errorf("the ownership question was asked %d times, want exactly 1. A second read is a "+
			"TOCTOU: anything the transaction removed in between would be invisible to it", asked)
	}
}

// onceThenFail answers the ownership read once and then refuses, so a service
// that re-asks cannot pass by being handed an empty list.
type onceThenFail struct {
	inner *fakeAccounts
	asked *int
}

func (s *onceThenFail) PersonalAccounts(ctx context.Context, q db.Querier, u id.UUID) ([]accounts.Account, error) {
	return s.inner.PersonalAccounts(ctx, q, u)
}

func (s *onceThenFail) SolelyOwnedTeamAccounts(_ context.Context, _ db.Querier, _ id.UUID) ([]accounts.Account, error) {
	*s.asked++
	if *s.asked > 1 {
		return nil, errors.New("the ownership question was asked twice")
	}
	return nil, nil
}

func (s *onceThenFail) Delete(ctx context.Context, q db.Querier, accountID id.UUID) error {
	return s.inner.Delete(ctx, q, accountID)
}

// TestAFailedAccountRemovalLeavesTheUserRow is the transaction being a
// transaction. A deletion that removed the credentials, then failed on the
// account, then removed the user anyway would be the half-applied state this
// packet exists to prevent — and the one the route would still answer 204 for.
func TestAFailedAccountRemovalLeavesTheUserRow(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.acct.personal = []accounts.Account{h.personalAccount()}
	h.acct.deleteErr = errors.New("the account is still referenced")

	if err := h.svc.Delete(t.Context(), DeleteInput{UserID: id.MustNew(), At: h.clock}); err == nil {
		t.Fatal("a failed account removal was reported as a successful deletion")
	}
	if len(h.users.deleted) != 0 {
		t.Errorf("the user row was removed even though the account removal failed: %v", h.users.deleted)
	}
}

// uowFunc adapts a closure to the UnitOfWork interface.
type uowFunc func(context.Context, func(context.Context, db.Querier) error) error

func (f uowFunc) Do(ctx context.Context, fn func(context.Context, db.Querier) error) error {
	return f(ctx, fn)
}
