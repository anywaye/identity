package agents

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
)


const claimUIRegisterTest = "https://anywaye.example"

type registerFixture struct {
	base *serviceFixture
	svc  *Service
	now  time.Time
}

func newRegisterFixture(t *testing.T) *registerFixture {
	t.Helper()
	f := newServiceFixture(t)
	return &registerFixture{
		base: f,
		svc:  NewService(f.pool, WithClaimUI(claimUIRegisterTest)),
		now:  serviceInstant,
	}
}

func (f *registerFixture) register(t *testing.T, name, username string) Registered {
	t.Helper()
	registered, err := f.svc.Register(context.Background(), RegisterInput{
		Name:     name,
		Username: username,
		TraceID:  "reg",
		Now:      f.now,
	})
	if err != nil {
		t.Fatalf("registering %q: %v", name, err)
	}
	return registered
}

func TestRegisterMintsEverythingAndWritesNoPlaintext(t *testing.T) {
	f := newRegisterFixture(t)

	registered := f.register(t, "Noel", "")

	if registered.Agent.Status != StatusUnclaimed {
		t.Errorf("status = %q, want %q — a registration is unclaimed by definition (D4)", registered.Agent.Status, StatusUnclaimed)
	}
	if registered.Agent.ClaimedByAccountID != nil {
		t.Error("an unclaimed agent reports an account, which is the state the table's CHECK refuses")
	}
	if !ValidUsername(registered.Agent.Username) {
		t.Errorf("a generated handle %q is not itself a valid handle", registered.Agent.Username)
	}
	if registered.TokenPlaintext == "" || registered.ClaimURL == "" {
		t.Fatal("the registration returned no token or no claim URL; the CLI would have nothing to hand a human")
	}

	store := NewStore(f.base.pool)

	row, err := store.ByID(context.Background(), f.base.pool, registered.Agent.ID)
	if err != nil {
		t.Fatalf("reading the principal back: %v", err)
	}

	if row.ClaimTokenDigest != nil && *row.ClaimTokenDigest == registered.TokenPlaintext {
		t.Error("the claim TOKEN's plaintext is stored on the agent row as the claim digest")
	}
	if Digest(registered.TokenPlaintext) == registered.TokenPlaintext {
		t.Error("the token digests to itself, which cannot be true for SHA-256")
	}

	stored, err := store.ByTokenID(context.Background(), f.base.pool, registered.Token.ID)
	if err != nil {
		t.Fatalf("reading the bootstrap credential back: %v", err)
	}
	if stored.TokenDigest == registered.TokenPlaintext {
		t.Fatal("the bootstrap token's PLAINTEXT is stored in agent_tokens.token_digest")
	}
	if stored.TokenDigest != Digest(registered.TokenPlaintext) {
		t.Errorf("token_digest = %q, want the SHA-256 of the plaintext %q",
			stored.TokenDigest, Digest(registered.TokenPlaintext))
	}
	link := registered.ClaimURL[len(claimUIRegisterTest+claimLinkPath):]
	if row.ClaimTokenDigest == nil || *row.ClaimTokenDigest != Digest(link) {
		t.Error("the agent's claim digest is not the SHA-256 of the link in the claim URL")
	}

	events, err := store.ListEvents(context.Background(), f.base.pool, registered.Agent.ID)
	if err != nil {
		t.Fatalf("reading events: %v", err)
	}
	if len(events) != 1 || events[0].Action != ActionRegistered {
		t.Fatalf("the registration's events = %+v, want a single agent.registered", events)
	}
	if !events[0].UserID.IsZero() || !events[0].TokenID.IsZero() {
		t.Error("a registration names an actor, and a registration is performed by nobody")
	}
}

func TestRegisterRetriesOnAUsernameCollisionWithoutDisclosingIt(t *testing.T) {
	f := newRegisterFixture(t)

	first := f.register(t, "Noel", "")
	second := f.register(t, "Noel", "")

	if first.Agent.ID == second.Agent.ID {
		t.Fatal("two registrations produced one principal")
	}
	if first.Agent.Username == second.Agent.Username {
		t.Errorf("two collisions on the same generated base %q produced the same handle "+
			"— the retry did not mint a new suffix", first.Agent.Username)
	}
	if second.ClaimURL == first.ClaimURL {
		t.Error("two refreshes of the same collision shared a claim link")
	}
}

func TestRegisterRefusesAUsernameThatIsAlreadyTakenAndNamesTheField(t *testing.T) {
	f := newRegisterFixture(t)

	f.register(t, "Noel", "noel")

	_, err := f.svc.Register(context.Background(), RegisterInput{
		Name: "Other Noel", Username: "noel", TraceID: "reg", Now: f.now,
	})
	if !errors.Is(err, ErrInvalidUsername) {
		t.Fatalf("a taken supplied handle returned %v, want an ErrInvalidUsername-wrapped refusal", err)
	}
}

func TestARegistrationWithNoClaimScreenRefusesRatherThanMinting(t *testing.T) {
	f := newServiceFixture(t)
	svcWithoutClaimUI := NewService(f.pool)

	if _, err := svcWithoutClaimUI.Register(context.Background(), RegisterInput{
		Name: "Noel", TraceID: "reg", Now: serviceInstant,
	}); !errors.Is(err, ErrNoClaimUI) {
		t.Errorf("registering with no claim UI returned %v, want ErrNoClaimUI", err)
	}
}

func TestRefreshGivesANewLinkAndDoesNotClaim(t *testing.T) {
	f := newRegisterFixture(t)

	registered := f.register(t, "Noel", "")

	refreshed, err := f.svc.RefreshClaimLink(context.Background(), RefreshClaimInput{
		Token:   registered.TokenPlaintext,
		TraceID: "refresh",
		Now:     f.now,
	})
	if err != nil {
		t.Fatalf("refreshing: %v", err)
	}

	if refreshed.Agent.Status != StatusUnclaimed {
		t.Errorf("after a refresh the status is %q, want %q — a refresh MUST NOT claim (D4)",
			refreshed.Agent.Status, StatusUnclaimed)
	}
	if refreshed.Agent.IsClaimed() {
		t.Error("the refreshed agent reports it is claimed; a refresh that claims is the bug this method refuses to be")
	}
	if refreshed.ClaimURL == registered.ClaimURL {
		t.Error("the refresh returned the same claim URL; it did not regenerate the link")
	}

	oldLink := registered.ClaimURL[len(claimUIRegisterTest+claimLinkPath):]
	if _, err := NewStore(f.base.pool).ByClaimDigest(context.Background(), f.base.pool, Digest(oldLink), f.now); !errors.Is(err, ErrNotFound) {
		t.Error("the pre-refresh claim link still resolves; a refresh must spend the link it replaces")
	}
}

func TestRefreshRefusesAClaimedAgent(t *testing.T) {
	f := newRegisterFixture(t)

	registered := f.register(t, "Noel", "")

	link := registered.ClaimURL[len(claimUIRegisterTest+claimLinkPath):]
	claimAcount := id.MustNew()
	if _, err := f.base.pool.Exec(context.Background(),
		`INSERT INTO accounts (id, name, slug) VALUES ($1, $2, $3)`,
		claimAcount, "Claimer", "claimer-"+claimAcount.String()[:8]); err != nil {
		t.Fatalf("inserting an account to claim with: %v", err)
	}
	claimErr := db.TxRunner{Pool: f.base.pool}.Do(context.Background(), func(ctx context.Context, tx db.Querier) error {
		_, err := NewStore(f.base.pool).Claim(ctx, tx, registered.Agent.ID, Digest(link), claimAcount, f.now)
		return err
	})
	if claimErr != nil {
		t.Fatalf("claiming for the test: %v", claimErr)
	}

	if _, err := f.svc.RefreshClaimLink(context.Background(), RefreshClaimInput{
		Token: registered.TokenPlaintext, TraceID: "r", Now: f.now,
	}); !errors.Is(err, ErrNotFound) {
		t.Errorf("refreshing a claimed agent returned %v, want ErrNotFound — the same answer a wrong token gets", err)
	}
}
