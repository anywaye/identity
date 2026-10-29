package accounts


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

type fakeQuerier struct{}

func (fakeQuerier) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func (fakeQuerier) Query(context.Context, string, ...any) (pgx.Rows, error) { return nil, nil }

func (fakeQuerier) QueryRow(context.Context, string, ...any) pgx.Row { return nil }

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

type fakeUsers struct {
	user users.User
}

func (f fakeUsers) ByID(_ context.Context, _ db.Querier, _ id.UUID) (users.User, error) {
	return f.user, nil
}

type fakeEvents struct {
	order *orderLog
}

func (f *fakeEvents) Append(_ context.Context, _ db.Querier, _ outbox.Envelope) error {
	f.order.add("append-event")
	return nil
}

type fakeRead struct{}

func (fakeRead) Queryer() db.Querier { return fakeQuerier{} }

type fakeMailer struct {
	order    *orderLog
	failWith error
	sends    []OutgoingInvitation
}

func (f *fakeMailer) SendInvitation(_ context.Context, invitation OutgoingInvitation) error {
	f.order.add("send")
	if f.failWith != nil {
		return f.failWith
	}
	f.sends = append(f.sends, invitation)
	return nil
}

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
		nil,
		clk,
		fakeRead{},
		mailer,
	)
}

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

	want := []string{"create-invitation", "append-event", "commit", "send"}
	got := order.snapshot()
	if len(got) < len(want) || !reflect.DeepEqual(got[len(got)-len(want):], want) {
		t.Errorf("the last steps were %v (full log %v), want %v — the send must "+
			"be after the commit, never inside the transaction", got[len(got)-len(want):], got, want)
	}
}

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

	if store.createCalls != 1 {
		t.Errorf("the store was asked to create the invitation %d times, want 1 — "+
			"the row either survived the failed send or it did not", store.createCalls)
	}
	want := []string{"create-invitation", "append-event", "commit", "send"}
	got := order.snapshot()
	if len(got) < len(want) || !reflect.DeepEqual(got[len(got)-len(want):], want) {
		t.Errorf("the last steps were %v (full log %v), want the committed "+
			"invitation followed by exactly one failed send", got[len(got)-len(want):], got)
	}
}

func TestInviteWithoutAMailerCreatesTheInvitation(t *testing.T) {
	fx := newInvitationFixture()
	order := &orderLog{}
	store := &fakeStore{}
	clk := clock.NewFake(time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC))
	svc := newInvitationService(order, store, nil, clk, fx)

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
	want := []string{"create-invitation", "append-event", "commit"}
	got := order.snapshot()
	if len(got) < len(want) || !reflect.DeepEqual(got[len(got)-len(want):], want) {
		t.Errorf("the last steps were %v (full log %v), want the committed "+
			"invitation and no send", got[len(got)-len(want):], got)
	}
}
