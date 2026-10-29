package agents

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/tenancy"
)


var serviceInstant = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

type serviceFixture struct {
	pool    *pgxpool.Pool
	clk     *clock.Fake
	svc     *Service
	account id.UUID
	user    id.UUID
}

func newServiceFixture(t *testing.T) *serviceFixture {
	t.Helper()

	pool := dbtest.Schema(t)
	f := &serviceFixture{pool: pool, clk: clock.NewFake(serviceInstant), svc: NewService(pool)}
	f.seed(t)
	return f
}

func (f *serviceFixture) seed(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	f.user = id.MustNew()
	if _, err := f.pool.Exec(ctx,
		`INSERT INTO users (id, email, password_digest) VALUES ($1, $2, $3)`,
		f.user, dbtest.UniqueEmail(t), "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$c2FsdHNhbHRzYWx0c2FsdHNhbHQ"); err != nil {
		t.Fatalf("inserting the claiming user: %v", err)
	}

	f.account = id.MustNew()
	if _, err := f.pool.Exec(ctx,
		`INSERT INTO accounts (id, name, slug) VALUES ($1, $2, $3)`,
		f.account, "Claiming account", "claiming-"+f.account.String()[:8]); err != nil {
		t.Fatalf("inserting the claiming account: %v", err)
	}
}

func (f *serviceFixture) register(t *testing.T, name string) string {
	t.Helper()

	link, digest, err := NewToken()
	if err != nil {
		t.Fatalf("minting a claim link: %v", err)
	}
	store := NewStore(f.pool)
	if _, err := store.Create(context.Background(), f.pool, NewAgent{
		Name:               name,
		ClaimDigest:        digest,
		ClaimLinkExpiresAt: serviceInstant.Add(ClaimLinkTTL),
		CreatedAt:          serviceInstant,
	}); err != nil {
		t.Fatalf("registering %q: %v", name, err)
	}
	return link
}

func (f *serviceFixture) claimCtx() context.Context {
	return tenancy.WithAccount(context.Background(), f.account)
}

func TestAClaimBindsTheAgentAndRecordsWhoDidIt(t *testing.T) {
	f := newServiceFixture(t)

	link := f.register(t, "Noel")

	claimed, err := f.svc.Claim(f.claimCtx(), ClaimInput{
		Token:   link,
		Account: f.account,
		User:    f.user,
		TraceID: "trace-1",
		Now:     serviceInstant,
	})
	if err != nil {
		t.Fatalf("claiming: %v", err)
	}
	if !claimed.Agent.IsClaimed() {
		t.Error("the claimed agent reports it is not claimed")
	}
	if claimed.Agent.Status != StatusClaimed {
		t.Errorf("status = %q, want %q", claimed.Agent.Status, StatusClaimed)
	}

	events, err := NewStore(f.pool).ListEvents(context.Background(), f.pool, claimed.Agent.ID)
	if err != nil {
		t.Fatalf("reading the agent's events: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("the agent has %d events, want 2 (the claim and the mint it caused)", len(events))
	}

	var claim *EventRecord
	for i := range events {
		if events[i].Action == ActionClaimed {
			claim = &events[i]
		}
	}
	if claim == nil {
		t.Fatal("the claim wrote no agent.claimed event, so the binding has no cause in the trail")
	}
	if claim.UserID != f.user {
		t.Errorf("the event names user %v, want the human who claimed %v", claim.UserID, f.user)
	}
	if !claim.TokenID.IsZero() {
		t.Errorf("a claim's actor names a token %v, and a claim has no token actor", claim.TokenID)
	}
	if claim.TraceID != "trace-1" {
		t.Errorf("the event carries trace id %q, want the request's", claim.TraceID)
	}
}

func TestAClaimMintsTheCredentialItPresents(t *testing.T) {
	f := newServiceFixture(t)

	link := f.register(t, "Noel")

	claimed, err := f.svc.Claim(f.claimCtx(), ClaimInput{
		Token:   link,
		Account: f.account,
		User:    f.user,
		TraceID: "trace-mint",
		Now:     serviceInstant,
	})
	if err != nil {
		t.Fatalf("claiming: %v", err)
	}
	if claimed.TokenPlaintext == "" {
		t.Fatal("the claim returned no credential, so an agent bound by the claim cannot use the binding")
	}
	if claimed.Token.Name != claimTokenName {
		t.Errorf("the claim's credential is named %q, want %q", claimed.Token.Name, claimTokenName)
	}
	if claimed.Token.AgentID != claimed.Agent.ID {
		t.Errorf("the credential belongs to %v, want the agent just claimed %v", claimed.Token.AgentID, claimed.Agent.ID)
	}

	owner, err := f.svc.Authenticate(context.Background(), claimed.TokenPlaintext, serviceInstant)
	if err != nil {
		t.Fatalf("the claim-minted credential does not resolve: %v", err)
	}
	if owner.Agent.ID != claimed.Agent.ID {
		t.Errorf("the credential resolved to %v, want the claimed agent %v", owner.Agent.ID, claimed.Agent.ID)
	}
	if err := owner.RequireClaimed(); err != nil {
		t.Errorf("a credential minted by a claim is refused as unclaimed: %v", err)
	}

	stored, err := NewStore(f.pool).ByTokenID(context.Background(), f.pool, claimed.Token.ID)
	if err != nil {
		t.Fatalf("reading the minted credential back: %v", err)
	}
	if stored.TokenDigest != Digest(claimed.TokenPlaintext) {
		t.Error("the stored digest is not the digest of the value the claim returned")
	}
	if strings.Contains(stored.TokenDigest, claimed.TokenPlaintext) {
		t.Error("the digest column carries the plaintext, which is impossible by construction and would be a catastrophe")
	}

	events, err := NewStore(f.pool).ListEvents(context.Background(), f.pool, claimed.Agent.ID)
	if err != nil {
		t.Fatalf("reading the agent's events: %v", err)
	}
	var mint *EventRecord
	for i := range events {
		if events[i].Action == ActionTokenMinted {
			mint = &events[i]
		}
	}
	if mint == nil {
		t.Fatal("the claim wrote no token_minted event, so the credential in the row has no cause in the trail")
	}
	if mint.UserID != f.user {
		t.Errorf("the mint's actor is %v, want the human whose claim caused it %v", mint.UserID, f.user)
	}
	if !mint.TokenID.IsZero() {
		t.Errorf("the mint's actor names a token %v, and the credential cannot be its own actor", mint.TokenID)
	}
}

func TestTheClaimIsOneTransactionWithItsRecord(t *testing.T) {
	f := newServiceFixture(t)

	link := f.register(t, "Noel")
	digest := Digest(link)
	store := NewStore(f.pool)

	claimErr := db.TxRunner{Pool: f.pool}.Do(context.Background(), func(ctx context.Context, tx db.Querier) error {
		if err := tenancy.BeginAccount(ctx, tx, f.account); err != nil {
			return err
		}
		agent, err := store.ByClaimDigest(ctx, tx, digest, serviceInstant)
		if err != nil {
			return err
		}
		if _, err := store.Claim(ctx, tx, agent.ID, digest, f.account, serviceInstant); err != nil {
			return err
		}
		if _, appendErr := store.AppendEvent(ctx, tx, Event{
			AgentID: agent.ID, Action: Action("agent.not_a_thing"),
			UserID: f.user, TraceID: "trace-2", OccurredAt: serviceInstant,
		}); appendErr != nil {
			return appendErr
		}
		return nil
	})
	if claimErr == nil {
		t.Fatal("the transaction committed with an event that could not be written")
	}

	listed, err := store.ListForAccount(context.Background(), f.pool, f.account)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(listed) != 0 {
		t.Errorf("the claim survived a rolled-back transaction, and %d agent(s) are now bound", len(listed))
	}

	if _, err := store.ByClaimDigest(context.Background(), f.pool, digest, serviceInstant); err != nil {
		t.Errorf("the claim link no longer resolves after a rolled-back claim: %v", err)
	}
}

func TestTheClaimRefusesALinkItCannotResolve(t *testing.T) {
	f := newServiceFixture(t)

	link := f.register(t, "Noel")

	if _, err := f.svc.Claim(f.claimCtx(), ClaimInput{
		Token: "anywaye_" + link[7:] + "x", Account: f.account, User: f.user, TraceID: "t", Now: serviceInstant,
	}); !errors.Is(err, ErrNotFound) {
		t.Errorf("a wrong token returned %v, want ErrNotFound", err)
	}

	if _, err := f.svc.Claim(f.claimCtx(), ClaimInput{
		Token: "", Account: f.account, User: f.user, TraceID: "t", Now: serviceInstant,
	}); !errors.Is(err, ErrNotFound) {
		t.Errorf("an empty token returned %v, want ErrNotFound", err)
	}

	if _, err := f.svc.Claim(f.claimCtx(), ClaimInput{
		Token: link, Account: f.account, User: f.user, TraceID: "t", Now: serviceInstant,
	}); err != nil {
		t.Fatalf("the first claim: %v", err)
	}
	if _, err := f.svc.Claim(f.claimCtx(), ClaimInput{
		Token: link, Account: f.account, User: f.user, TraceID: "t", Now: serviceInstant,
	}); !errors.Is(err, ErrNotFound) {
		t.Errorf("a second claim on the same link returned %v, want ErrNotFound — one answer for a spent link", err)
	}
}

func TestAClaimNeedsACaller(t *testing.T) {
	f := newServiceFixture(t)
	link := f.register(t, "Noel")

	if _, err := f.svc.Claim(f.claimCtx(), ClaimInput{
		Token: link, Account: f.account, TraceID: "t", Now: serviceInstant,
	}); err == nil {
		t.Error("a claim with no human succeeded")
	}
	if _, err := f.svc.Claim(f.claimCtx(), ClaimInput{
		Token: link, User: f.user, TraceID: "t", Now: serviceInstant,
	}); err == nil {
		t.Error("a claim with no account succeeded")
	}
}

func TestTheDatabaseTierActuallyRanForTheService(t *testing.T) {
	if os.Getenv(dbtest.EnvVar) == "" {
		t.Fatalf("%s is not set, so every test in this file skipped. A green run without it verifies nothing.",
			dbtest.EnvVar)
	}
}
