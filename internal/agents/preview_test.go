package agents

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/platform/id"
)


type previewFixture struct{ *serviceFixture }

func newPreviewFixture(t *testing.T) *previewFixture {
	t.Helper()
	return &previewFixture{serviceFixture: newServiceFixture(t)}
}

func (f *previewFixture) previewCtx() context.Context { return context.Background() }

func (f *previewFixture) registerWith(t *testing.T, name string, device map[string]any) (link, username string) {
	t.Helper()

	username = "noel-" + id.MustNew().String()[:8]
	linkValue, digest, err := NewToken()
	if err != nil {
		t.Fatalf("minting a claim link: %v", err)
	}
	store := NewStore(f.pool)
	if _, err := store.Create(context.Background(), f.pool, NewAgent{
		Name:               name,
		Username:           username,
		Device:             device,
		ClaimDigest:        digest,
		ClaimLinkExpiresAt: serviceInstant.Add(ClaimLinkTTL),
		CreatedAt:          serviceInstant,
	}); err != nil {
		t.Fatalf("registering %q: %v", name, err)
	}
	return linkValue, username
}

func TestThePreviewRendersTheFirstFrameTheClaimScreenReads(t *testing.T) {
	f := newPreviewFixture(t)

	link, username := f.registerWith(t, "Noel", map[string]any{
		"host": "noels-macbook",
		"os":   "darwin",
		"cpus": 8,
	})

	preview, err := f.svc.PreviewClaim(f.previewCtx(), PreviewInput{
		Token:   link,
		TraceID: "trace-preview",
		Now:     serviceInstant,
	})
	if err != nil {
		t.Fatalf("previewing a live link: %v", err)
	}

	if preview.Agent.Name != "Noel" {
		t.Errorf("name = %q, want Noel", preview.Agent.Name)
	}
	if preview.Agent.Username != username {
		t.Errorf("username = %q, want the registration's handle %q", preview.Agent.Username, username)
	}
	if preview.Agent.Status != StatusUnclaimed {
		t.Errorf("status = %q, want %q", preview.Agent.Status, StatusUnclaimed)
	}
	if !preview.Agent.CreatedAt.Equal(serviceInstant) {
		t.Errorf("created_at = %s, want the registration's instant %s", preview.Agent.CreatedAt, serviceInstant)
	}
	if len(preview.Agent.Device) != 3 {
		t.Errorf("the device document holds %d entries, want 3 — the agent's own keys are passed through, not projected", len(preview.Agent.Device))
	}
	if preview.Agent.Device["host"] != "noels-macbook" {
		t.Errorf("device.host = %v, want noels-macbook", preview.Agent.Device["host"])
	}

	if !preview.ClaimLinkExpiresAt.Equal(serviceInstant.Add(ClaimLinkTTL)) {
		t.Errorf("the link expiry = %s, want %s", preview.ClaimLinkExpiresAt, serviceInstant.Add(ClaimLinkTTL))
	}

	if preview.Agent.IsClaimed() {
		t.Error("the preview of a live link reports the agent as claimed")
	}
	if preview.Agent.ClaimedByAccountID != nil {
		t.Error("the preview carries an account, and a live link has none")
	}
}

func TestThePreviewWritesNothing(t *testing.T) {
	f := newPreviewFixture(t)

	link, _ := f.registerWith(t, "Noel", map[string]any{"host": "laptop"})

	preview, err := f.svc.PreviewClaim(f.previewCtx(), PreviewInput{
		Token: link, TraceID: "trace-preview", Now: serviceInstant,
	})
	if err != nil {
		t.Fatalf("previewing: %v", err)
	}

	events, err := NewStore(f.pool).ListEvents(context.Background(), f.pool, preview.Agent.ID)
	if err != nil {
		t.Fatalf("reading the agent's events: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("the preview wrote %d event(s) to agent_events, want 0", len(events))
	}

	tokens, err := NewStore(f.pool).ListTokensForAgent(context.Background(), f.pool, preview.Agent.ID)
	if err != nil {
		t.Fatalf("reading the agent's tokens: %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("the preview left %d token(s) behind, want 0 — a preview must not mint", len(tokens))
	}

	claimed, err := f.svc.Claim(f.claimCtx(), ClaimInput{
		Token:   link,
		Account: f.account,
		User:    f.user,
		TraceID: "trace-claim",
		Now:     serviceInstant,
	})
	if err != nil {
		t.Fatalf("claiming a link that was previewed: %v — the preview spent something", err)
	}
	if !claimed.Agent.IsClaimed() {
		t.Error("the claim did not bind the agent")
	}
	if claimed.TokenPlaintext == "" {
		t.Error("the claim minted no credential after the preview, so the agent has nothing to present")
	}
}

func TestThePreviewCannotTellTheFourWaysALinkIsDeadApart(t *testing.T) {
	f := newPreviewFixture(t)

	live, _ := f.registerWith(t, "Noel", nil)
	claimedLink, _ := f.registerWith(t, "Marc", nil)
	if _, err := f.svc.Claim(f.claimCtx(), ClaimInput{
		Token:   claimedLink,
		Account: f.account,
		User:    f.user,
		TraceID: "trace-claim",
		Now:     serviceInstant,
	}); err != nil {
		t.Fatalf("claiming Marc's link for the third row: %v", err)
	}

	for _, tc := range []struct {
		name  string
		token string
		now time.Time
	}{
		{name: "a wrong token", token: agentsPrefix + strings.Repeat("z", 43), now: serviceInstant},
		{name: "an empty token", token: "", now: serviceInstant},
		{name: "an expired link", token: live, now: serviceInstant.Add(ClaimLinkTTL + time.Second)},
		{name: "an already-claimed agent", token: claimedLink, now: serviceInstant},
		{name: "a token that never existed", token: agentsPrefix + strings.Repeat("q", 43), now: serviceInstant},
	} {
		t.Run(tc.name, func(t *testing.T) {
			preview, err := f.svc.PreviewClaim(f.previewCtx(), PreviewInput{
				Token: tc.token, TraceID: "trace-preview", Now: tc.now,
			})
			if !errors.Is(err, ErrNotFound) {
				t.Fatalf("previewing %s answered %v, want ErrNotFound — the four dead shapes "+
					"must be one value, and a distinct one would tell a stranger which guess was close",
					tc.name, err)
			}
			if !preview.Agent.ID.IsZero() {
				t.Errorf("a refused preview carries agent %s, want none", preview.Agent.ID)
			}
		})
	}
}

func TestAPreviewAfterTheClockPassesTheExpiry(t *testing.T) {
	f := newPreviewFixture(t)

	link, _ := f.registerWith(t, "Noel", nil)

	if _, err := f.svc.PreviewClaim(f.previewCtx(), PreviewInput{
		Token: link, Now: serviceInstant.Add(ClaimLinkTTL - time.Second),
	}); err != nil {
		t.Errorf("one second before the expiry: %v, want it to resolve", err)
	}
	if _, err := f.svc.PreviewClaim(f.previewCtx(), PreviewInput{
		Token: link, Now: serviceInstant.Add(ClaimLinkTTL),
	}); !errors.Is(err, ErrNotFound) {
		t.Errorf("at the expiry: %v, want ErrNotFound", err)
	}
}

const agentsPrefix = Prefix
