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
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
)

// The store, over a real Postgres in a private schema.
//
// The tests run the SQL rather than a double because the interesting properties
// are properties of the SCHEMA and of the CONDITIONAL UPDATE — the partial
// unique index that makes rotation two requests, the CHECK that makes
// unclaimed → disabled unrepresentable, the WHERE that makes two concurrent
// claims one claim — and none of them exist in a fake.

var testInstant = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

type fixture struct {
	pool    *pgxpool.Pool
	clk     *clock.Fake
	store   *Store
	account id.UUID
}

// theClaimDigest is a syntactically valid 64-hex digest, so a probe of the shape
// a caller could send is the same shape a real one is.
func theClaimDigest(tag string) string {
	return Digest("anywaye_" + strings.Repeat("c", 43) + tag)
}

func theTokenDigest(tag string) string {
	return Digest("anywaye_" + strings.Repeat("t", 43) + tag)
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	pool := dbtest.Schema(t)
	clk := clock.NewFake(testInstant)

	f := &fixture{pool: pool, clk: clk, store: NewStore(pool)}
	f.seed(t)
	return f
}

// seed writes the one account the foreign key needs. An agent registers with no
// account at all, which is the whole point of the table, so the claim is what
// gives a fixture its account.
func (f *fixture) seed(t *testing.T) {
	t.Helper()

	f.account = id.MustNew()
	if _, err := f.store.Pool().Exec(context.Background(),
		`INSERT INTO accounts (id, name, slug) VALUES ($1, $2, $3)`,
		f.account, "Claiming account", "claiming-account"); err != nil {
		t.Fatalf("inserting the claiming account: %v", err)
	}
}

// register writes an unclaimed agent through the store under test.
func (f *fixture) register(t *testing.T, name string) Agent {
	t.Helper()

	agent, err := f.store.Create(context.Background(), f.store.Pool(), NewAgent{
		Name:               name,
		ClaimDigest:        theClaimDigest(name),
		ClaimLinkExpiresAt: testInstant.Add(ClaimLinkTTL),
		CreatedAt:          testInstant,
		Device:             map[string]any{"host": "box-1"},
	})
	if err != nil {
		t.Fatalf("registering %q: %v", name, err)
	}
	return agent
}

// TestARegisteredAgentIsUnclaimedAndCarriesNoAuthority is the row W1-P2's
// registration route writes, asserted at the store so the shape is pinned
// before any route depends on it.
func TestARegisteredAgentIsUnclaimedAndCarriesNoAuthority(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	agent := f.register(t, "Noel")

	if agent.Status != StatusUnclaimed {
		t.Errorf("a fresh registration is %q, want %q", agent.Status, StatusUnclaimed)
	}
	if agent.IsClaimed() {
		t.Error("a fresh registration reports IsClaimed, and it belongs to nobody")
	}
	if agent.ClaimTokenDigest == nil || *agent.ClaimTokenDigest != theClaimDigest("Noel") {
		t.Errorf("the row does not carry the claim digest it was given: %v", agent.ClaimTokenDigest)
	}
	if agent.ClaimLinkExpiresAt == nil {
		t.Fatal("an unclaimed agent has no claim link expiry, and the table's CHECK says it must")
	}
	if agent.Device["host"] != "box-1" {
		t.Errorf("the device document did not survive the round trip: %v", agent.Device)
	}
	// Equal rather than ==: a time read back from Postgres carries the SESSION's
	// location, and two representations of one instant are one instant.
	if !agent.CreatedAt.Equal(testInstant) {
		t.Errorf("created_at = %v, want the service's clock %v", agent.CreatedAt, testInstant)
	}

	// The plaintext claim link is nowhere: the struct has no field for it, and
	// the row holds only the digest.
	if agent.ClaimTokenDigest != nil && strings.Contains(*agent.ClaimTokenDigest, "anywaye_") {
		t.Error("the row holds the claim link itself rather than its digest")
	}

	// And it is not readable by a stranger guessing a digest.
	if _, err := f.store.ByClaimDigest(ctx, f.store.Pool(), theClaimDigest("wrong"), f.clk.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unknown claim digest returned %v, want ErrNotFound", err)
	}
}

// TestAClaimLinkResolvesOnlyWhileItIsLiveIsUnclaimedAndIsNotYetSpent is the
// claim route's lookup, and its three filters are the point: a wrong digest, an
// already-claimed agent and an expired link are ONE answer.
func TestAClaimLinkResolvesOnlyWhileItIsLiveIsUnclaimedAndIsNotYetSpent(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	agent := f.register(t, "Noel")

	// A live link resolves.
	if _, err := f.store.ByClaimDigest(ctx, f.store.Pool(), theClaimDigest("Noel"), f.clk.Now()); err != nil {
		t.Fatalf("a live claim link did not resolve: %v", err)
	}

	// THREE REFUSALS, AND THEY ARE THE SAME VALUE.
	//
	//   an expired link        the clock has passed the expiry
	//   an already-claimed     the agent is bound
	//   a digest that was
	//   never issued           a stranger guessing
	//
	// Each is asserted to be ErrNotFound and nothing else, so a future change
	// that made one of them distinguishable would be visible here rather than in
	// a 410 on a route a stranger can reach.
	cases := []struct {
		name   string
		now    time.Time
		mutate func(t *testing.T)
		digest string
	}{
		{
			name:   "an expired link",
			now:    testInstant.Add(ClaimLinkTTL + time.Second),
			digest: theClaimDigest("Noel"),
		},
		{
			name:   "a link that was never issued",
			now:    f.clk.Now(),
			digest: theClaimDigest("nobody"),
		},
		{
			name:   "an already-claimed agent",
			now:    f.clk.Now(),
			digest: theClaimDigest("Noel"),
			mutate: func(t *testing.T) {
				if _, err := f.store.Claim(ctx, f.store.Pool(), agent.ID, theClaimDigest("Noel"), f.account, testInstant); err != nil {
					t.Fatalf("claiming before the refusal: %v", err)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.mutate != nil {
				tc.mutate(t)
			}
			_, err := f.store.ByClaimDigest(ctx, f.store.Pool(), tc.digest, tc.now)
			if !errors.Is(err, ErrNotFound) {
				t.Fatalf("the lookup returned %v, want ErrNotFound — one shape of answer for every failure", err)
			}
		})
	}

	// THE BOUNDARY ITSELF. `expires_at > now`, so an expiry exactly at now is
	// spent. Two implementations of one boundary is how a link stays redeemable
	// for a second longer than the response that used it said it would.
	_, err := f.store.ByClaimDigest(ctx, f.store.Pool(), theClaimDigest("Noel"),
		testInstant.Add(ClaimLinkTTL))
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("a link whose expiry is exactly now resolved, and the boundary is > now: %v", err)
	}
}

// TestTheClaimSpendsTheLinkAndBindsTheAccount is the conditional UPDATE.
//
// ZERO ROWS IS THE 404, and the 404 never says "expired": the statement's WHERE
// carries the digest, the status and the expiry together, so the database is what
// decides and there is no read to disagree with.
func TestTheClaimSpendsTheLinkAndBindsTheAccount(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	agent := f.register(t, "Noel")

	claimed, err := f.store.Claim(ctx, f.store.Pool(), agent.ID, theClaimDigest("Noel"), f.account, testInstant)
	if err != nil {
		t.Fatalf("claiming: %v", err)
	}
	if claimed.Status != StatusClaimed {
		t.Errorf("status = %q, want %q", claimed.Status, StatusClaimed)
	}
	if !claimed.IsClaimed() {
		t.Error("the claimed agent reports it is not claimed")
	}
	if claimed.ClaimedByAccountID == nil || *claimed.ClaimedByAccountID != f.account {
		t.Errorf("claimed_by_account_id = %v, want %v", claimed.ClaimedByAccountID, f.account)
	}
	if claimed.ClaimedAt == nil || !claimed.ClaimedAt.Equal(testInstant) {
		t.Errorf("claimed_at = %v, want the service's clock", claimed.ClaimedAt)
	}
	// THE LINK IS SPENT, and spent means the digest is gone rather than
	// merely unreachable.
	if claimed.ClaimTokenDigest != nil {
		t.Errorf("the claim link's digest survived the claim: %v", *claimed.ClaimTokenDigest)
	}
	if claimed.ClaimLinkExpiresAt != nil {
		t.Error("the claim link's expiry survived the claim")
	}

	// A SECOND CLAIM ON THE SAME LINK updates zero rows, and the answer is
	// ErrAlreadyClaimed to the caller that holds the row — which the route
	// renders as the same 404 a wrong token gets.
	if _, err := f.store.Claim(ctx, f.store.Pool(), agent.ID, theClaimDigest("Noel"), f.account, testInstant); !errors.Is(err, ErrAlreadyClaimed) {
		t.Errorf("a second claim returned %v, want ErrAlreadyClaimed", err)
	}

	// And the spent link no longer resolves to the row at all.
	if _, err := f.store.ByClaimDigest(ctx, f.store.Pool(), theClaimDigest("Noel"), f.clk.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("a spent claim link still resolved: %v", err)
	}

	// The account now lists it.
	listed, err := f.store.ListForAccount(ctx, f.store.Pool(), f.account)
	if err != nil {
		t.Fatalf("listing the account's agents: %v", err)
	}
	if len(listed) != 1 || listed[0].ID != agent.ID {
		t.Fatalf("the account lists %d agents, want the one just claimed", len(listed))
	}

	// An account that claimed nothing lists nothing, rather than listing the
	// unclaimed agents of the world.
	other := id.MustNew()
	if _, err := f.store.Pool().Exec(ctx,
		`INSERT INTO accounts (id, name, slug) VALUES ($1, $2, $3)`,
		other, "Other", "other-account"); err != nil {
		t.Fatalf("inserting a second account: %v", err)
	}
	empty, err := f.store.ListForAccount(ctx, f.store.Pool(), other)
	if err != nil {
		t.Fatalf("listing an empty account: %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("an account that claimed nothing lists %d agents", len(empty))
	}
}

// TestTheClaimRouteCannotBindAnAccountWithAWrongToken is the 404 the whole
// surface is shaped around: a wrong digest, an expired link and an agent that
// never existed are indistinguishable.
func TestTheClaimRouteCannotBindAnAccountWithAWrongToken(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	agent := f.register(t, "Noel")

	// A wrong digest is refused, and it binds nothing.
	if _, err := f.store.Claim(ctx, f.store.Pool(), agent.ID, theClaimDigest("wrong"), f.account, testInstant); !errors.Is(err, ErrNotFound) {
		t.Errorf("a claim with the wrong digest returned %v, want ErrNotFound", err)
	}

	// The row is untouched by the refusal.
	reloaded, err := f.store.ByID(ctx, f.store.Pool(), agent.ID)
	if err != nil {
		t.Fatalf("reloading after the refusal: %v", err)
	}
	if reloaded.Status != StatusUnclaimed {
		t.Errorf("a refused claim moved the agent to %q", reloaded.Status)
	}
	if reloaded.ClaimTokenDigest == nil {
		t.Error("a refused claim spent the link")
	}

	// And an agent that never existed is the same value.
	missing := id.MustNew()
	if _, err := f.store.Claim(ctx, f.store.Pool(), missing, theClaimDigest("Noel"), f.account, testInstant); !errors.Is(err, ErrNotFound) {
		t.Errorf("a claim against an agent that never existed returned %v, want ErrNotFound", err)
	}
}

// TestRefreshClaimLinkReplacesTheLinkWithoutClaiming is W1-P2's rotation, and
// the property that matters is that "give me a new link" can never bind an
// account.
func TestRefreshClaimLinkReplacesTheLinkWithoutClaiming(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	agent := f.register(t, "Noel")
	first := theClaimDigest("Noel")
	second := theClaimDigest("Noel-rotated")
	later := testInstant.Add(time.Hour)

	refreshed, err := f.store.RefreshClaimLink(ctx, f.store.Pool(), agent.ID, second, later, later)
	if err != nil {
		t.Fatalf("refreshing the claim link: %v", err)
	}
	if refreshed.Status != StatusUnclaimed {
		t.Errorf("a refresh moved the agent to %q, and a refresh must not claim", refreshed.Status)
	}
	if refreshed.ClaimTokenDigest == nil || *refreshed.ClaimTokenDigest != second {
		t.Fatalf("the row does not carry the new digest")
	}

	// The OLD link is dead and the NEW one resolves.
	if _, err := f.store.ByClaimDigest(ctx, f.store.Pool(), first, f.clk.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("the superseded link still resolved: %v", err)
	}
	if _, err := f.store.ByClaimDigest(ctx, f.store.Pool(), second, f.clk.Now()); err != nil {
		t.Errorf("the refreshed link did not resolve: %v", err)
	}

	// A CLAIMED agent has no link to refresh, and the WHERE says so: zero rows,
	// ErrNotFound, no credential resurrected.
	if _, err := f.store.Claim(ctx, f.store.Pool(), agent.ID, second, f.account, testInstant); err != nil {
		t.Fatalf("claiming with the refreshed link: %v", err)
	}
	if _, err := f.store.RefreshClaimLink(ctx, f.store.Pool(), agent.ID, theClaimDigest("again"), later, later); !errors.Is(err, ErrNotFound) {
		t.Errorf("a refresh against a claimed agent returned %v, want ErrNotFound", err)
	}
}

// TestSetStatusIsGuardedByTheStateMachine is the second of the two layers that
// refuse unclaimed → disabled. The table's CHECK is the first; this is the one a
// caller reaches before either.
func TestSetStatusIsGuardedByTheStateMachine(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	agent := f.register(t, "Noel")

	// UNCLAIMED → DISABLED is refused in Go, with the transition named.
	_, err := f.store.SetStatus(ctx, f.store.Pool(), agent.ID, StatusDisabled, testInstant)
	if !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("disabling an unclaimed agent returned %v, want ErrIllegalTransition", err)
	}
	if !strings.Contains(err.Error(), "unclaimed") || !strings.Contains(err.Error(), "disabled") {
		t.Errorf("the refusal does not name the transition it refused: %v", err)
	}

	// AND IN THE TABLE, which is the layer a psql session cannot bypass. The Go
	// guard is proved first; this writes the illegal state directly to show the
	// CHECK refuses it too, because a caller who got past one would meet the other.
	_, dbErr := f.store.Pool().Exec(ctx,
		`UPDATE agents SET status = 'disabled' WHERE id = $1`, agent.ID)
	if dbErr == nil {
		t.Fatal("the database accepted unclaimed → disabled, and the CHECK exists to refuse it")
	}

	// The legal moves work, and the re-enable brings the agent back rather than
	// making a new one.
	if _, err := f.store.Claim(ctx, f.store.Pool(), agent.ID, theClaimDigest("Noel"), f.account, testInstant); err != nil {
		t.Fatalf("claiming: %v", err)
	}
	disabled, err := f.store.SetStatus(ctx, f.store.Pool(), agent.ID, StatusDisabled, testInstant.Add(time.Minute))
	if err != nil {
		t.Fatalf("disabling a claimed agent: %v", err)
	}
	// A DISABLED AGENT IS STILL CLAIMED — "was it claimed" and "is it live" are
	// two questions, and IsClaimed answers the first.
	if !disabled.IsClaimed() {
		t.Error("a disabled agent reports it was never claimed")
	}
	reenabled, err := f.store.SetStatus(ctx, f.store.Pool(), agent.ID, StatusClaimed, testInstant.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("re-enabling: %v", err)
	}
	if reenabled.ID != agent.ID {
		t.Error("re-enabling produced a different agent")
	}

	// And an un-claim is not a transition anybody may ask for.
	if _, err := f.store.SetStatus(ctx, f.store.Pool(), agent.ID, StatusUnclaimed, testInstant.Add(3*time.Minute)); !errors.Is(err, ErrIllegalTransition) {
		t.Errorf("un-claiming returned %v, want ErrIllegalTransition", err)
	}
}

// TestAnAgentCredentialResolvesOnlyForAClaimedPrincipal is the introspection
// join, and it is four filters rather than one: a revoked token, a spent token,
// an agent that is disabled and a digest that was never issued are one answer.
func TestAnAgentCredentialResolvesOnlyForAClaimedPrincipal(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	agent := f.register(t, "Noel")
	if _, err := f.store.Claim(ctx, f.store.Pool(), agent.ID, theClaimDigest("Noel"), f.account, testInstant); err != nil {
		t.Fatalf("claiming: %v", err)
	}

	live, err := f.store.CreateToken(ctx, f.store.Pool(), NewAgentToken{
		AgentID:   agent.ID,
		Name:      "ci-deploy",
		Digest:    theTokenDigest("live"),
		CreatedAt: testInstant,
		ExpiresAt: testInstant.Add(30 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("minting a credential: %v", err)
	}

	resolved, err := f.store.ByTokenDigest(ctx, f.store.Pool(), live.TokenDigest, testInstant)
	if err != nil {
		t.Fatalf("resolving a live credential: %v", err)
	}
	if resolved.AgentStatus != StatusClaimed {
		t.Errorf("the resolution read status %q, want %q", resolved.AgentStatus, StatusClaimed)
	}
	if !resolved.UsableAt(testInstant) {
		t.Error("a live credential for a claimed agent reports unusable")
	}

	// A token held by a DISABLED agent does not resolve. The principal's status
	// is in the WHERE, so this is the query's answer and not a caller's check.
	if _, err := f.store.SetStatus(ctx, f.store.Pool(), agent.ID, StatusDisabled, testInstant); err != nil {
		t.Fatalf("disabling: %v", err)
	}
	if _, err := f.store.ByTokenDigest(ctx, f.store.Pool(), live.TokenDigest, testInstant); !errors.Is(err, ErrNotFound) {
		t.Errorf("a token held by a disabled agent resolved: %v", err)
	}

	// A revoked token does not resolve, and it is the same answer.
	if _, err := f.store.SetStatus(ctx, f.store.Pool(), agent.ID, StatusClaimed, testInstant); err != nil {
		t.Fatalf("re-enabling: %v", err)
	}
	revoked, err := f.store.RevokeToken(ctx, f.store.Pool(), live.ID, agent.ID, testInstant, "rotated")
	if err != nil {
		t.Fatalf("revoking: %v", err)
	}
	if !revoked.IsRevoked() {
		t.Error("the revoked row does not report itself revoked")
	}
	if _, err := f.store.ByTokenDigest(ctx, f.store.Pool(), live.TokenDigest, testInstant); !errors.Is(err, ErrNotFound) {
		t.Errorf("a revoked credential resolved: %v", err)
	}

	// A second revocation of the same row is told apart, because the caller
	// already holds the row and "I clicked twice" is worth an honest answer.
	if _, err := f.store.RevokeToken(ctx, f.store.Pool(), live.ID, agent.ID, testInstant, "again"); !errors.Is(err, ErrAlreadyRevoked) {
		t.Errorf("a second revocation returned %v, want ErrAlreadyRevoked", err)
	}

	// A token that expired does not resolve.
	spent, err := f.store.CreateToken(ctx, f.store.Pool(), NewAgentToken{
		AgentID:   agent.ID,
		Name:      "short-lived",
		Digest:    theTokenDigest("spent"),
		CreatedAt: testInstant,
		ExpiresAt: testInstant.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("minting a second credential: %v", err)
	}
	if _, err := f.store.ByTokenDigest(ctx, f.store.Pool(), spent.TokenDigest, testInstant.Add(time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Errorf("a spent credential resolved: %v", err)
	}

	// And one that was never issued is the same value as all three above.
	if _, err := f.store.ByTokenDigest(ctx, f.store.Pool(), theTokenDigest("nobody"), testInstant); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unknown credential digest returned %v, want ErrNotFound", err)
	}
}

// TestOneLiveTokenPerNamePerAgent is what makes rotation two requests rather
// than a transaction: a revoked "ci-deploy" and the live one that replaced it
// coexist, and two LIVE ones do not.
func TestOneLiveTokenPerNamePerAgent(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	agent := f.register(t, "Noel")
	if _, err := f.store.Claim(ctx, f.store.Pool(), agent.ID, theClaimDigest("Noel"), f.account, testInstant); err != nil {
		t.Fatalf("claiming: %v", err)
	}

	mint := func(name, tag string) Token {
		t.Helper()
		token, err := f.store.CreateToken(ctx, f.store.Pool(), NewAgentToken{
			AgentID:   agent.ID,
			Name:      name,
			Digest:    theTokenDigest(tag),
			CreatedAt: testInstant,
			ExpiresAt: testInstant.Add(30 * 24 * time.Hour),
		})
		if err != nil {
			t.Fatalf("minting %q: %v", name, err)
		}
		return token
	}

	first := mint("ci-deploy", "first")

	// mintExpectingFail mints a token the store is expected to refuse, so the
	// collision is asserted on the ERROR rather than on a row that must not exist.
	mintRefused := func(name, tag string) error {
		t.Helper()
		_, err := f.store.CreateToken(ctx, f.store.Pool(), NewAgentToken{
			AgentID:   agent.ID,
			Name:      name,
			Digest:    theTokenDigest(tag),
			CreatedAt: testInstant,
			ExpiresAt: testInstant.Add(30 * 24 * time.Hour),
		})
		return err
	}

	if err := mintRefused("ci-deploy", "second"); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("a second live token of the same name returned %v, want ErrNameTaken", err)
	}

	// Revoke the first and the name is free again, which is the whole arrangement.
	if _, err := f.store.RevokeToken(ctx, f.store.Pool(), first.ID, agent.ID, testInstant, "rotated"); err != nil {
		t.Fatalf("revoking: %v", err)
	}
	second := mint("ci-deploy", "second")
	if second.ID == first.ID {
		t.Error("the rotation returned the revoked row")
	}

	// The agent lists both, newest first, revoked ones included: "was this
	// withdrawn, or was it always broken?" is a support question.
	listed, err := f.store.ListTokensForAgent(ctx, f.store.Pool(), agent.ID)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(listed) != 2 {
		t.Fatalf("the agent lists %d credentials, want 2", len(listed))
	}
}

// TestTouchIsBoundedAndASuccessEitherWay is the only write on the read path.
//
// Zero rows is the rate limit working, not a failure, and a revoked token is
// never touched — `last_used_at` on a dead credential is a column asserting
// that it was working.
func TestTouchIsBoundedAndASuccessEitherWay(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	agent := f.register(t, "Noel")
	if _, err := f.store.Claim(ctx, f.store.Pool(), agent.ID, theClaimDigest("Noel"), f.account, testInstant); err != nil {
		t.Fatalf("claiming: %v", err)
	}
	token, err := f.store.CreateToken(ctx, f.store.Pool(), NewAgentToken{
		AgentID:   agent.ID,
		Name:      "ci-deploy",
		Digest:    theTokenDigest("touch"),
		CreatedAt: testInstant,
		ExpiresAt: testInstant.Add(30 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("minting: %v", err)
	}

	if err := f.store.Touch(ctx, f.store.Pool(), token.ID, testInstant); err != nil {
		t.Fatalf("the first touch: %v", err)
	}
	afterFirst, err := f.store.ByTokenID(ctx, f.store.Pool(), token.ID)
	if err != nil {
		t.Fatalf("reloading: %v", err)
	}
	if afterFirst.LastUsedAt == nil {
		t.Fatal("the first touch did not record a use")
	}

	// A second touch inside the window is a SUCCESS and leaves the column alone.
	if err := f.store.Touch(ctx, f.store.Pool(), token.ID, testInstant.Add(time.Minute)); err != nil {
		t.Fatalf("a touch inside the window returned an error, and zero rows is the limit working: %v", err)
	}
	afterSecond, err := f.store.ByTokenID(ctx, f.store.Pool(), token.ID)
	if err != nil {
		t.Fatalf("reloading: %v", err)
	}
	if !afterSecond.LastUsedAt.Equal(*afterFirst.LastUsedAt) {
		t.Errorf("a touch inside the window moved last_used_at from %v to %v", afterFirst.LastUsedAt, afterSecond.LastUsedAt)
	}

	// Past the window it moves again.
	if err := f.store.Touch(ctx, f.store.Pool(), token.ID, testInstant.Add(TokenTouchWindow+time.Minute)); err != nil {
		t.Fatalf("a touch past the window: %v", err)
	}
	afterThird, err := f.store.ByTokenID(ctx, f.store.Pool(), token.ID)
	if err != nil {
		t.Fatalf("reloading: %v", err)
	}
	if afterThird.LastUsedAt.Equal(*afterFirst.LastUsedAt) {
		t.Error("a touch past the window left last_used_at where it was")
	}
}

// TestTheDatabaseTierActuallyRan fails rather than skips when TEST_DATABASE_URL
// is unset. Everything in this file is a database test, so without the variable
// this whole file has proven nothing and a suite reporting "ok" has reported
// something false.
func TestTheDatabaseTierActuallyRan(t *testing.T) {
	if os.Getenv(dbtest.EnvVar) == "" {
		t.Fatalf("%s is not set, so every test in this file skipped. A green run without it verifies nothing: "+
			"`docker compose up -d postgres`, `goose -dir migrations postgres \"$DATABASE_URL\" up`, and re-run with %s set.",
			dbtest.EnvVar, dbtest.EnvVar)
	}
	pool := dbtest.Pool(t)
	if err := pool.Ping(context.Background()); err != nil {
		t.Fatalf("the test database is not reachable: %v", err)
	}
}
