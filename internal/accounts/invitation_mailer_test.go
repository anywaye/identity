package accounts

// # THIS FILE IS THE PACKET'S RED TEST, AND IT IS RED ON MASTER
//
// It fails to BUILD against master's tree, and the build failure is the honest
// red: `InvitationMailer`, `OutgoingInvitation` and the mailer parameter on
// `NewService` do not exist, because on master nobody sends an invitation email
// at all. The test expresses the contract this packet adds — an invite with a
// wired mailer sends exactly one team_invitation, after the transaction
// commits, and a send that fails is returned rather than swallowed — and it is
// committed red so the tree with no mailer in it is a tree somebody can recover.
//
// The fakes below are the same shape as service_test.go's recordedEvents and
// recordedRevocations: the use case's dependencies are interfaces precisely so a
// test can program the one behavior under test without standing up Postgres.

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/anywaye/identity/internal/outbox"
	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/users"
)

// fakeQuerier is a db.Querier that answers every statement with nothing.
//
// It exists because the use cases under test read through s.read after the
// transaction commits, and those reads are faked at the STORE layer — the
// querier is carried along for tenancy.BeginUser's SET, which is a no-op here.
// A nil querier would panic inside BeginUser; this one simply answers, and a
// test that accidentally issues a real query gets a nil row rather than a
// database.
type fakeQuerier struct{}

func (fakeQuerier) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func (fakeQuerier) Query(context.Context, string, ...any) (pgx.Rows, error) { return nil, nil }

func (fakeQuerier) QueryRow(context.Context, string, ...any) pgx.Row { return nil }

// orderLog records the sequence of things that happened, so a test can assert
// WHERE in the sequence the send happened rather than only that it did.
type orderLog struct {
	mu    sync.Mutex
	steps []string
}

func (l *orderLog) add(step string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.steps = append(l.steps, step)
}

func (l *orderLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.steps...)
}

// fakeUow runs the function immediately, the way db.TxRunner does, and records
// the commit as a step of its own: the ordering test reads the log to prove the
// send is after it.
type fakeUow struct {
	order *orderLog
}

func (f fakeUow) Do(ctx context.Context, fn func(context.Context, db.Querier) error) error {
	if err := fn(ctx, fakeQuerier{}); err != nil {
		return err
	}
	f.order.add("commit")
	return nil
}

// fakeStore is the AccountStore double.
//
// It EMBEDS the interface rather than implementing its fourteen methods, because
// Invite touches three of them and the rest would be noise a reader has to
// verify is never called. An embedded nil interface panics if something does
// call one, which is the honest answer for a dependency that should not be
// reached.
type fakeStore struct {
	AccountStore
	order       *orderLog
	account     Account
	member      Membership
	invitation  Invitation
	createCalls int
}

func (f *fakeStore) CreateInvitation(_ context.Context, _ db.Querier, n NewInvitation) (Invitation, error) {
	f.order.add("create-invitation")
	f.createCalls++
	inv := f.invitation
	if inv.ID.IsZero() {
		inv.ID = id.MustNew()
	}
	inv.AccountID = n.AccountID
	inv.Email = n.Email
	inv.Role = n.Role
	inv.TokenDigest = n.TokenDigest
	inv.ExpiresAt = n.ExpiresAt
	inv.InvitedBy = n.InvitedBy
	return inv, nil
}

func (f *fakeStore) ByID(_ context.Context, _ db.Querier, _ id.UUID) (Account, error) {
	return f.account, nil
}

func (f *fakeStore) Member(_ context.Context, _ db.Querier, _ id.UUID, _ id.UUID) (Membership, error) {
	return f.member, nil
}

// fakeUsers is the UserEmailReader double.
type fakeUsers struct {
	user users.User
}

func (f fakeUsers) ByID(_ context.Context, _ db.Querier, _ id.UUID) (users.User, error) {
	return f.user, nil
}

// fakeEvents is the EventAppender double.
type fakeEvents struct {
	order *orderLog
}

func (f *fakeEvents) Append(_ context.Context, _ db.Querier, _ outbox.Envelope) error {
	f.order.add("append-event")
	return nil
}

// fakeRead is the QuerierSource double: post-commit reads get the no-op
// querier, because the stores above are faked and issue nothing real.
type fakeRead struct{}

func (fakeRead) Queryer() db.Querier { return fakeQuerier{} }

// fakeMailer is the InvitationMailer double: it records what it was asked to
// send, and can be told to fail.
type fakeMailer struct {
	order    *orderLog
	failWith error
	sends    []OutgoingInvitation
}

func (f *fakeMailer) SendInvitation(_ context.Context, invitation OutgoingInvitation) error {
	// Recorded before the failure check: a send that was ATTEMPTED and failed
	// is still a send that happened after the commit, and the ordering test
	// asserts the attempt, not only the successes.
	f.order.add("send")
	if f.failWith != nil {
		return f.failWith
	}
	f.sends = append(f.sends, invitation)
	return nil
}

// invitationFixture is one account, one inviter, one invitee.
type invitationFixture struct {
	account    Account
	inviter    users.User
	invitee    string
	role       Role
	invitation Invitation
}

func newInvitationFixture() invitationFixture {
	displayName := "Kaka"
	return invitationFixture{
		account: Account{ID: id.MustNew(), Name: "Acme Corporation"},
		inviter: users.User{
			ID:          id.MustNew(),
			Email:       "kaka@example.com",
			DisplayName: &displayName,
		},
		invitee: "teammate@example.com",
		role:    RoleMember,
		invitation: Invitation{
			ID:        id.MustNew(),
			Email:     "teammate@example.com",
			Role:      RoleMember,
			ExpiresAt: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC),
		},
	}
}

// newInvitationService builds a Service over the fakes, with the mailer wired.
func newInvitationService(
	order *orderLog,
	store *fakeStore,
	mailer InvitationMailer,
	clk *clock.Fake,
	fx invitationFixture,
) *Service {
	store.account = fx.account
	store.invitation = fx.invitation
	store.member = Membership{Role: RoleOwner}
	store.order = order
	return NewService(
		fakeUow{order: order},
		store,
		fakeUsers{user: fx.inviter},
		&fakeEvents{order: order},
		nil, // revokes: Invite revokes nothing, and a nil revoker is supported
		clk,
		fakeRead{},
		mailer,
	)
}

// TestInviteSendsExactlyOneInvitationEmail is the packet's red test: an invite
// with a wired mailer sends exactly one team_invitation, to the invitee, whose
// link carries the one-time token, and whose account_name and invited_by are
// the real ones — the account's name and the inviter's name, not placeholders
// a template would render as blanks.
func TestInviteSendsExactlyOneInvitationEmail(t *testing.T) {
	fx := newInvitationFixture()
	order := &orderLog{}
	store := &fakeStore{}
	mailer := &fakeMailer{order: order}
	clk := clock.NewFake(time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC))
	svc := newInvitationService(order, store, mailer, clk, fx)

	invited, err := svc.Invite(context.Background(), InviteInput{
		AccountID: fx.account.ID,
		Email:     fx.invitee,
		Role:      fx.role,
		InvitedBy: fx.inviter.ID,
	})
	if err != nil {
		t.Fatalf("Invite: %v", err)
	}

	if len(mailer.sends) != 1 {
		t.Fatalf("mailer was asked to send %d invitations, want exactly 1 — "+
			"an invitation mails the invitee once, and a second send is a second "+
			"email in their inbox", len(mailer.sends))
	}
	sent := mailer.sends[0]

	if sent.ID != invited.Invitation.ID {
		t.Errorf("send names invitation %v, want the one Invite created (%v)",
			sent.ID, invited.Invitation.ID)
	}
	if sent.Email != users.NormalizeEmail(fx.invitee) {
		t.Errorf("send is to %q, want the invitee %q", sent.Email, users.NormalizeEmail(fx.invitee))
	}
	if sent.Token != invited.Token {
		t.Errorf("the link's token is %q, want the one-time token Invite returned (%q) — "+
			"a link carrying anything else is a link the invitee cannot redeem",
			sent.Token, invited.Token)
	}
	if sent.AccountName != fx.account.Name {
		t.Errorf("account_name is %q, want the account's real name %q",
			sent.AccountName, fx.account.Name)
	}
	if sent.InvitedBy != "Kaka" {
		t.Errorf("invited_by is %q, want the inviter's display name %q — courier's "+
			"template renders it immediately before \"invited you to join\", so an "+
			"address or a blank there is a mail that says who sent it wrong",
			sent.InvitedBy, "Kaka")
	}
	if sent.Role != string(fx.role) {
		t.Errorf("role is %q, want %q", sent.Role, string(fx.role))
	}
}

// TestInviteSendsAfterTheTransactionCommits holds the ordering that makes the
// failure semantics survivable.
//
// A mail cannot be rolled back, so it cannot go inside the transaction: an
// invitation that rolled back with its mail sent is a link to nothing, and an
// invitation that committed with its mail unsent is an admin who can revoke
// and re-invite. The second is recoverable and the first is not, so the send is
// after the commit whatever the mailer does with it.
func TestInviteSendsAfterTheTransactionCommits(t *testing.T) {
	order := &orderLog{}
	store := &fakeStore{}
	mailer := &fakeMailer{order: order}
	clk := clock.NewFake(time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC))
	fx := newInvitationFixture()
	svc := newInvitationService(order, store, mailer, clk, fx)

	if _, err := svc.Invite(context.Background(), InviteInput{
		AccountID: fx.account.ID,
		Email:     fx.invitee,
		Role:      fx.role,
		InvitedBy: fx.inviter.ID,
	}); err != nil {
		t.Fatalf("Invite: %v", err)
	}

	// The invitation's own writes, then the commit, then the send.
	//
	// THE ASSERTION IS ON THE LAST FOUR STEPS rather than on the whole log,
	// because Invite reads the inviter's membership first and that read is its
	// own transaction — its "commit" is the first entry here, and it is not the
	// commit the send is ordered against. What must hold is that the
	// invitation's writes precede ITS commit, and the send follows it: a send
	// anywhere before that commit is a mail that outlives a rollback.
	want := []string{"create-invitation", "append-event", "commit", "send"}
	got := order.snapshot()
	if len(got) < len(want) || !reflect.DeepEqual(got[len(got)-len(want):], want) {
		t.Errorf("the last steps were %v (full log %v), want %v — the send must "+
			"be after the commit, never inside the transaction", got[len(got)-len(want):], got, want)
	}
}

// TestInviteReturnsTheSendFailureAndKeepsTheInvitation states the failure
// semantics out loud, because they are the half of this packet that is easy to
// paper over.
//
// The acceptance token is NOT stored — only its digest is — so a send that
// fails after the commit cannot be retried with the same link: the link is
// gone. What survives is the invitation row, and that is what the admin acts
// on. So the failure is RETURNED — the admin is told the invite did not reach
// anybody — and the row is left in place, revocable and re-invitable. A
// half-state that says nothing is the defect; this says both halves.
func TestInviteReturnsTheSendFailureAndKeepsTheInvitation(t *testing.T) {
	fx := newInvitationFixture()
	order := &orderLog{}
	store := &fakeStore{}
	sendErr := errors.New("courier did not accept the message")
	mailer := &fakeMailer{order: order, failWith: sendErr}
	clk := clock.NewFake(time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC))
	svc := newInvitationService(order, store, mailer, clk, fx)

	_, err := svc.Invite(context.Background(), InviteInput{
		AccountID: fx.account.ID,
		Email:     fx.invitee,
		Role:      fx.role,
		InvitedBy: fx.inviter.ID,
	})
	if !errors.Is(err, sendErr) {
		t.Fatalf("Invite returned %v, want the send failure %v — a failed send "+
			"that reaches the caller as a success is an admin told the invitee was "+
			"emailed when nobody was", err, sendErr)
	}

	// The invitation row survived: the store was asked for it exactly once, and
	// the event that announces it was appended — both inside the committed
	// transaction, which the send failure cannot unwind.
	if store.createCalls != 1 {
		t.Errorf("the store was asked to create the invitation %d times, want 1 — "+
			"the row either survived the failed send or it did not", store.createCalls)
	}
	// The same suffix as the ordering test: the inviter-membership read's own
	// commit leads the log, and what matters is the invitation's writes, its
	// commit, then the one failed send.
	want := []string{"create-invitation", "append-event", "commit", "send"}
	got := order.snapshot()
	if len(got) < len(want) || !reflect.DeepEqual(got[len(got)-len(want):], want) {
		t.Errorf("the last steps were %v (full log %v), want the committed "+
			"invitation followed by exactly one failed send", got[len(got)-len(want):], got)
	}
}

// TestInviteWithoutAMailerCreatesTheInvitation is the nil-mailer case, and it
// is a supported state rather than a broken one: a deployment with no mail path
// still has a tenancy feature. The invitation is created, the token is
// returned, and no mail is claimed — the 201 does not say an email was on its
// way.
func TestInviteWithoutAMailerCreatesTheInvitation(t *testing.T) {
	fx := newInvitationFixture()
	order := &orderLog{}
	store := &fakeStore{}
	clk := clock.NewFake(time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC))
	svc := newInvitationService(order, store, nil, clk, fx) // nil mailer: no mail path

	invited, err := svc.Invite(context.Background(), InviteInput{
		AccountID: fx.account.ID,
		Email:     fx.invitee,
		Role:      fx.role,
		InvitedBy: fx.inviter.ID,
	})
	if err != nil {
		t.Fatalf("Invite: %v — a deployment with no mail path is a supported state, "+
			"not a failed invite", err)
	}
	if invited.Token == "" {
		t.Error("Invite returned no token, so the admin has nothing to give the " +
			"invitee by hand and the invitation is only revocable")
	}
	// The same suffix as the ordering test, minus the send: the inviter
	// membership read's own commit leads the log.
	want := []string{"create-invitation", "append-event", "commit"}
	got := order.snapshot()
	if len(got) < len(want) || !reflect.DeepEqual(got[len(got)-len(want):], want) {
		t.Errorf("the last steps were %v (full log %v), want the committed "+
			"invitation and no send", got[len(got)-len(want):], got)
	}
}
