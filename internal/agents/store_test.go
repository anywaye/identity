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


var testInstant = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

type fixture struct {
	pool    *pgxpool.Pool
	clk     *clock.Fake
	store   *Store
	account id.UUID
}

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

func (f *fixture) seed(t *testing.T) {
	t.Helper()

	f.account = id.MustNew()
	if _, err := f.store.Pool().Exec(context.Background(),
		`INSERT INTO accounts (id, name, slug) VALUES ($1, $2, $3)`,
		f.account, "Claiming account", "claiming-account"); err != nil {
		t.Fatalf("inserting the claiming account: %v", err)
	}
}

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
	if !agent.CreatedAt.Equal(testInstant) {
		t.Errorf("created_at = %v, want the service's clock %v", agent.CreatedAt, testInstant)
	}

	if agent.ClaimTokenDigest != nil && strings.Contains(*agent.ClaimTokenDigest, "anywaye_") {
		t.Error("the row holds the claim link itself rather than its digest")
	}

	if _, err := f.store.ByClaimDigest(ctx, f.store.Pool(), theClaimDigest("wrong"), f.clk.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unknown claim digest returned %v, want ErrNotFound", err)
	}
}

func TestAClaimLinkResolvesOnlyWhileItIsLiveIsUnclaimedAndIsNotYetSpent(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	agent := f.register(t, "Noel")

	if _, err := f.store.ByClaimDigest(ctx, f.store.Pool(), theClaimDigest("Noel"), f.clk.Now()); err != nil {
		t.Fatalf("a live claim link did not resolve: %v", err)
	}

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

	_, err := f.store.ByClaimDigest(ctx, f.store.Pool(), theClaimDigest("Noel"),
		testInstant.Add(ClaimLinkTTL))
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("a link whose expiry is exactly now resolved, and the boundary is > now: %v", err)
	}
}

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
	if claimed.ClaimTokenDigest != nil {
		t.Errorf("the claim link's digest survived the claim: %v", *claimed.ClaimTokenDigest)
	}
	if claimed.ClaimLinkExpiresAt != nil {
		t.Error("the claim link's expiry survived the claim")
	}

	if _, err := f.store.Claim(ctx, f.store.Pool(), agent.ID, theClaimDigest("Noel"), f.account, testInstant); !errors.Is(err, ErrAlreadyClaimed) {
		t.Errorf("a second claim returned %v, want ErrAlreadyClaimed", err)
	}

	if _, err := f.store.ByClaimDigest(ctx, f.store.Pool(), theClaimDigest("Noel"), f.clk.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("a spent claim link still resolved: %v", err)
	}

	listed, err := f.store.ListForAccount(ctx, f.store.Pool(), f.account)
	if err != nil {
		t.Fatalf("listing the account's agents: %v", err)
	}
	if len(listed) != 1 || listed[0].ID != agent.ID {
		t.Fatalf("the account lists %d agents, want the one just claimed", len(listed))
	}

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

func TestTheClaimRouteCannotBindAnAccountWithAWrongToken(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	agent := f.register(t, "Noel")

	if _, err := f.store.Claim(ctx, f.store.Pool(), agent.ID, theClaimDigest("wrong"), f.account, testInstant); !errors.Is(err, ErrNotFound) {
		t.Errorf("a claim with the wrong digest returned %v, want ErrNotFound", err)
	}

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

	missing := id.MustNew()
	if _, err := f.store.Claim(ctx, f.store.Pool(), missing, theClaimDigest("Noel"), f.account, testInstant); !errors.Is(err, ErrNotFound) {
		t.Errorf("a claim against an agent that never existed returned %v, want ErrNotFound", err)
	}
}

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

	if _, err := f.store.ByClaimDigest(ctx, f.store.Pool(), first, f.clk.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("the superseded link still resolved: %v", err)
	}
	if _, err := f.store.ByClaimDigest(ctx, f.store.Pool(), second, f.clk.Now()); err != nil {
		t.Errorf("the refreshed link did not resolve: %v", err)
	}

	if _, err := f.store.Claim(ctx, f.store.Pool(), agent.ID, second, f.account, testInstant); err != nil {
		t.Fatalf("claiming with the refreshed link: %v", err)
	}
	if _, err := f.store.RefreshClaimLink(ctx, f.store.Pool(), agent.ID, theClaimDigest("again"), later, later); !errors.Is(err, ErrNotFound) {
		t.Errorf("a refresh against a claimed agent returned %v, want ErrNotFound", err)
	}
}

func TestSetStatusIsGuardedByTheStateMachine(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	agent := f.register(t, "Noel")

	_, err := f.store.SetStatus(ctx, f.store.Pool(), agent.ID, StatusDisabled, testInstant)
	if !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("disabling an unclaimed agent returned %v, want ErrIllegalTransition", err)
	}
	if !strings.Contains(err.Error(), "unclaimed") || !strings.Contains(err.Error(), "disabled") {
		t.Errorf("the refusal does not name the transition it refused: %v", err)
	}

	_, dbErr := f.store.Pool().Exec(ctx,
		`UPDATE agents SET status = 'disabled' WHERE id = $1`, agent.ID)
	if dbErr == nil {
		t.Fatal("the database accepted unclaimed → disabled, and the CHECK exists to refuse it")
	}

	if _, err := f.store.Claim(ctx, f.store.Pool(), agent.ID, theClaimDigest("Noel"), f.account, testInstant); err != nil {
		t.Fatalf("claiming: %v", err)
	}
	disabled, err := f.store.SetStatus(ctx, f.store.Pool(), agent.ID, StatusDisabled, testInstant.Add(time.Minute))
	if err != nil {
		t.Fatalf("disabling a claimed agent: %v", err)
	}
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

	if _, err := f.store.SetStatus(ctx, f.store.Pool(), agent.ID, StatusUnclaimed, testInstant.Add(3*time.Minute)); !errors.Is(err, ErrIllegalTransition) {
		t.Errorf("un-claiming returned %v, want ErrIllegalTransition", err)
	}
}

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

	if _, err := f.store.SetStatus(ctx, f.store.Pool(), agent.ID, StatusDisabled, testInstant); err != nil {
		t.Fatalf("disabling: %v", err)
	}
	if _, err := f.store.ByTokenDigest(ctx, f.store.Pool(), live.TokenDigest, testInstant); !errors.Is(err, ErrNotFound) {
		t.Errorf("a token held by a disabled agent resolved: %v", err)
	}

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

	if _, err := f.store.RevokeToken(ctx, f.store.Pool(), live.ID, agent.ID, testInstant, "again"); !errors.Is(err, ErrAlreadyRevoked) {
		t.Errorf("a second revocation returned %v, want ErrAlreadyRevoked", err)
	}

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

	if _, err := f.store.ByTokenDigest(ctx, f.store.Pool(), theTokenDigest("nobody"), testInstant); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unknown credential digest returned %v, want ErrNotFound", err)
	}
}

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

	if _, err := f.store.RevokeToken(ctx, f.store.Pool(), first.ID, agent.ID, testInstant, "rotated"); err != nil {
		t.Fatalf("revoking: %v", err)
	}
	second := mint("ci-deploy", "second")
	if second.ID == first.ID {
		t.Error("the rotation returned the revoked row")
	}

	listed, err := f.store.ListTokensForAgent(ctx, f.store.Pool(), agent.ID)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(listed) != 2 {
		t.Fatalf("the agent lists %d credentials, want 2", len(listed))
	}
}

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
