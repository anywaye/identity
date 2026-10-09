package agents

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
)

// THE REGISTRATION AND THE REFRESH, over a real Postgres in a private schema.
//
// The properties that matter are properties of what is and is not written: that a
// registration produces a principal, a token and a claim link and stores none of
// the two plaintexts; that a generated-handle collision retries without ever
// disclosing occupancy; and that a refresh gives an agent a new link WITHOUT
// claiming it. All three are checked against the database rather than a double,
// because "no plaintext at rest" and "the status guard holds" are SQL facts, not
// logic a fake could assert.

const claimUIRegisterTest = "https://cafaye.example"

type registerFixture struct {
	base *serviceFixture
	svc  *Service
	now  time.Time
}

func newRegisterFixture(t *testing.T) *registerFixture {
	t.Helper()
	f := newServiceFixture(t)
	// The claim UI base, which registration needs to render a claim URL. A string
	// literal rather than a config.Load: the URL's construction is the use case's,
	// and a test that read it from the environment would be testing the loader.
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

// TestRegisterMintsEverythingAndWritesNoPlaintext is the happy path AND the
// SHA-256 property in one: the response carries a token and a claim link, and the
// database row carries neither.
//
// THE NO-PLAINTEXT HALF IS THE POINT. It reads the row back through the store and
// asserts the token's plaintext appears in NO column — the digest is a SHA-256, and
// there is no column a plaintext could be written into. The same for the claim
// link. This is the check that would catch a future change that stashed the link on
// the row "just until it's emailed", which is exactly how a plaintext secret ends
// up in a backup.
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

	// THE ROW, read back by id.
	row, err := store.ByID(context.Background(), f.base.pool, registered.Agent.ID)
	if err != nil {
		t.Fatalf("reading the principal back: %v", err)
	}

	// The token's plaintext is nowhere. The digest is the only credential-shaped
	// value on the storage side, and it equals SHA-256(token) and nothing equals the
	// token itself.
	if row.ClaimTokenDigest != nil && *row.ClaimTokenDigest == registered.TokenPlaintext {
		t.Error("the claim TOKEN's plaintext is stored on the agent row as the claim digest")
	}
	if Digest(registered.TokenPlaintext) == registered.TokenPlaintext {
		t.Error("the token digests to itself, which cannot be true for SHA-256")
	}

	// Read the credential back and prove its stored digest is the hash, never the value.
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
	// And the claim link's digest on the row is the hash of the link, not the link.
	// The URL is <base>/agents/claim/<link>, so recover the link from the tail.
	link := registered.ClaimURL[len(claimUIRegisterTest+claimLinkPath):]
	if row.ClaimTokenDigest == nil || *row.ClaimTokenDigest != Digest(link) {
		t.Error("the agent's claim digest is not the SHA-256 of the link in the claim URL")
	}

	// The registration event, with nobody as its actor.
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

// TestRegisterRetriesOnAUsernameCollisionWithoutDisclosingIt is the conflict-retry
// property, and the disclosure half is the reason it exists.
//
// Registering the same name twice succeeds twice with DIFFERENT handles, because a
// generated collision retries under the hood — the public answer is never "taken",
// so the endpoint cannot be used to probe which handles exist. The two principals
// are genuinely two rows.
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

// TestRegisterRefusesAUsernameThatIsAlreadyTakenAndNamesTheField is the one case a
// caller learns a collision: they supplied the handle deliberately, so swapping in
// a generated one would be a surprise, and the refusal names the field rather than
// pretending the request was unparseable.
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

// TestARegistrationWithNoClaimScreenRefusesRatherThanMinting unblocks the fail-
// closed direction: a deployment with no claim URL configured must not register an
// agent, because an unclaimed agent with no link is an agent nobody can finish.
func TestARegistrationWithNoClaimScreenRefusesRatherThanMinting(t *testing.T) {
	f := newServiceFixture(t)
	svcWithoutClaimUI := NewService(f.pool) // no WithClaimUI

	if _, err := svcWithoutClaimUI.Register(context.Background(), RegisterInput{
		Name: "Noel", TraceID: "reg", Now: serviceInstant,
	}); !errors.Is(err, ErrNoClaimUI) {
		t.Errorf("registering with no claim UI returned %v, want ErrNoClaimUI", err)
	}
}

// TestRefreshGivesANewLinkAndDoesNotClaim is the property the method exists for:
// the agent STAYS unclaimed, gets a new link, and the old one is spent.
func TestRefreshGivesANewLinkAndDoesNotClaim(t *testing.T) {
	f := newRegisterFixture(t)

	registered := f.register(t, "Noel", "")

	// The agent authenticates with its own bootstrap token, which is exactly what
	// OwnerByTokenDigest resolves while the principal is unclaimed.
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

	// The OLD link no longer resolves, and the NEW one does — one live link at a
	// time, which is what "regenerates in place" means.
	oldLink := registered.ClaimURL[len(claimUIRegisterTest+claimLinkPath):]
	if _, err := NewStore(f.base.pool).ByClaimDigest(context.Background(), f.base.pool, Digest(oldLink), f.now); !errors.Is(err, ErrNotFound) {
		t.Error("the pre-refresh claim link still resolves; a refresh must spend the link it replaces")
	}
}

// TestRefreshRefusesAClaimedAgent is the other half of the status guard: once a
// human has claimed the agent, the agent's own token no longer refreshes a link —
// the access belongs to the account now.
func TestRefreshRefusesAClaimedAgent(t *testing.T) {
	f := newRegisterFixture(t)

	registered := f.register(t, "Noel", "")

	// Claim the agent through the store, the way the W1-P1 claim route does, so the
	// row is a real claimed row rather than a hand-written one.
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

	// Now the agent's own token tries to refresh, and is refused as a 404.
	if _, err := f.svc.RefreshClaimLink(context.Background(), RefreshClaimInput{
		Token: registered.TokenPlaintext, TraceID: "r", Now: f.now,
	}); !errors.Is(err, ErrNotFound) {
		t.Errorf("refreshing a claimed agent returned %v, want ErrNotFound — the same answer a wrong token gets", err)
	}
}
