package agents

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/tenancy"
)

// The claim use case, over a real Postgres in a private schema.
//
// These run the SQL rather than a double because the properties that matter are
// properties of the transaction: that the claim and the event recording who did it
// are one fact, that the account boundary is set on the transaction the use case
// opens rather than somewhere a caller could forget, and that a failing append
// takes the claim with it.

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

// register writes an unclaimed agent and returns its claim link's plaintext.
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

// claimCtx is the request context the route hands over: the account on it, the way
// requireAccountRole leaves it.
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

	// The event row, written by the same transaction.
	events, err := NewStore(f.pool).ListEvents(context.Background(), f.pool, claimed.Agent.ID)
	if err != nil {
		t.Fatalf("reading the agent's events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("the agent has %d events, want 1", len(events))
	}
	if events[0].Action != ActionClaimed {
		t.Errorf("the event's action is %q, want %q", events[0].Action, ActionClaimed)
	}
	if events[0].UserID != f.user {
		t.Errorf("the event names user %v, want the human who claimed %v", events[0].UserID, f.user)
	}
	if !events[0].TokenID.IsZero() {
		t.Errorf("a claim's actor names a token %v, and a claim has no token actor", events[0].TokenID)
	}
	if events[0].TraceID != "trace-1" {
		t.Errorf("the event carries trace id %q, want the request's", events[0].TraceID)
	}
}

// TestTheClaimIsOneTransactionWithItsRecord proves the three statements are one
// fact by breaking the last one.
//
// IT USES THE STORE DIRECTLY INSIDE A TxRunner, and that is not a shortcut around
// the use case: the property under test is a property of the TRANSACTION, and the
// use case is the thing that opens it. Adding a `badAction` field to `Service` so a
// test could ask the use case to write an unusable event would put a test seam in
// production code, which is the thing AGENTS.md's "no globals, no init-time state"
// rule exists to refuse. The transaction's shape is what has to hold, and it is
// exercised here with the same three calls in the same order the use case makes
// them.
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
		// An action this build does not implement. It is refused by
		// AppendEvent's own validation rather than by the database, which is
		// enough to roll the claim back — and the direction is the one that
		// matters: a claim that survived would be a binding nobody recorded.
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

	// And the agent is still unclaimed.
	listed, err := store.ListForAccount(context.Background(), f.pool, f.account)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(listed) != 0 {
		t.Errorf("the claim survived a rolled-back transaction, and %d agent(s) are now bound", len(listed))
	}

	// The link still resolves, so a refused claim costs the caller a retry rather
	// than a registration.
	if _, err := store.ByClaimDigest(context.Background(), f.pool, digest, serviceInstant); err != nil {
		t.Errorf("the claim link no longer resolves after a rolled-back claim: %v", err)
	}
}

// TestTheClaimRefusesALinkItCannotResolve is the 404 the surface is built on.
func TestTheClaimRefusesALinkItCannotResolve(t *testing.T) {
	f := newServiceFixture(t)

	link := f.register(t, "Noel")

	// A wrong token.
	if _, err := f.svc.Claim(f.claimCtx(), ClaimInput{
		Token: "cafaye_" + link[7:] + "x", Account: f.account, User: f.user, TraceID: "t", Now: serviceInstant,
	}); !errors.Is(err, ErrNotFound) {
		t.Errorf("a wrong token returned %v, want ErrNotFound", err)
	}

	// An empty one.
	if _, err := f.svc.Claim(f.claimCtx(), ClaimInput{
		Token: "", Account: f.account, User: f.user, TraceID: "t", Now: serviceInstant,
	}); !errors.Is(err, ErrNotFound) {
		t.Errorf("an empty token returned %v, want ErrNotFound", err)
	}

	// A claim that succeeds, then the same link again — the 404 is the same value.
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

// TestAClaimNeedsACaller is the fail-closed direction: a use case that writes a
// row naming nobody is a use case that has been reached by a route that forgot.
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

// TestTheDatabaseTierActuallyRan fails rather than skips when TEST_DATABASE_URL is
// unset.
func TestTheDatabaseTierActuallyRanForTheService(t *testing.T) {
	if os.Getenv(dbtest.EnvVar) == "" {
		t.Fatalf("%s is not set, so every test in this file skipped. A green run without it verifies nothing.",
			dbtest.EnvVar)
	}
}
