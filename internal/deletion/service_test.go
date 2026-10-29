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



type fakeAccounts struct {
	personal []accounts.Account
	solelyOwned []accounts.Account
	deletedAccounts []id.UUID
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

type discardQuerier struct{}

func (discardQuerier) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag("SELECT 1"), nil
}

func (discardQuerier) Query(context.Context, string, ...any) (pgx.Rows, error) { return nil, nil }

func (discardQuerier) QueryRow(context.Context, string, ...any) pgx.Row { return nil }

func (h *harness) personalAccount() accounts.Account {
	return accounts.Account{ID: id.MustNew(), Name: "kaka"}
}

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

func TestATeamAccountTheUserOnlyBelongsToIsNeverQueriedForOwnership(t *testing.T) {
	t.Parallel()

	asked := 0
	h := newHarness(t)
	inner := h.acct
	h.acct = &fakeAccounts{
		deleteErr: nil,
	}
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

type uowFunc func(context.Context, func(context.Context, db.Querier) error) error

func (f uowFunc) Do(ctx context.Context, fn func(context.Context, db.Querier) error) error {
	return f(ctx, fn)
}
