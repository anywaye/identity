package agents

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/platform/id"
)

// THE CLAIM PREVIEW, OVER A REAL POSTGRES IN A PRIVATE SCHEMA.
//
// These are the properties the HTTP layer's own tests cannot reach, and one of
// them is the whole justification for the route existing at all.
//
// # WHAT IS PROVED HERE
//
//	1. A live link resolves to the principal it names, with the fields the claim
//	   screen renders — and nothing else. No account, no `claimed_at`, no
//	   credential.
//	2. The four ways a link is dead are ONE value, over the real SQL. This is the
//	   property the website depends on: because identity's failures are one
//	   collapsed shape, a route that was MISSING rendered a perfectly live link as
//	   "unrecognized", and a route that told the four apart would render a
//	   stranger's guess as information.
//	3. A preview writes nothing. No event row, no credential, and the link is
//	   still claimable afterwards — which is the only statement that a preview is
//	   not spending anything.

// previewFixture is the service fixture the preview tests share, and it is a
// wrapper rather than a second fixture so these tests cannot drift from the
// claim's own world about what "the real service" means.
type previewFixture struct{ *serviceFixture }

func newPreviewFixture(t *testing.T) *previewFixture {
	t.Helper()
	return &previewFixture{serviceFixture: newServiceFixture(t)}
}

// previewCtx is the context the route hands over. A preview needs no account on
// it — there is no account in the flow — so this is the bare context.
func (f *previewFixture) previewCtx() context.Context { return context.Background() }

// registerWith writes an unclaimed agent with a device document, the way a
// registration through the service would, and returns its claim link and handle.
//
// THE HANDLE IS MINTED PER CALL rather than spelled out, because the unique index
// on `username` would refuse the second agent in the same private schema and the
// failure would read as a defect in the use case under test.
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

// TestThePreviewRendersTheFirstFrameTheClaimScreenReads is the happy path, and
// the fields are the website's own list rather than this package's opinion:
// `AgentClaim` in website/src/lib/identity.ts, read by `getAgentClaim` and
// rendered by the screen at src/app/agents/claim/[token].
func TestThePreviewRendersTheFirstFrameTheClaimScreenReads(t *testing.T) {
	f := newPreviewFixture(t)

	link, username := f.registerWith(t, "Noel", map[string]any{
		"host": "noels-macbook",
		"os":   "darwin",
		// A NON-STRING VALUE, deliberately: the device document has no schema, so
		// the projection rule belongs to the client (it keeps string values and
		// skips the rest) and the service must not refuse the row or drop the
		// rest of the document over one odd value.
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

	// THE EXPIRY IS A FACT ABOUT THE LINK, beside the agent rather than on it.
	if !preview.ClaimLinkExpiresAt.Equal(serviceInstant.Add(ClaimLinkTTL)) {
		t.Errorf("the link expiry = %s, want %s", preview.ClaimLinkExpiresAt, serviceInstant.Add(ClaimLinkTTL))
	}

	// AND WHAT IS NOT HERE. A live link names an UNCLAIMED agent, so the account
	// and the claim instant are both absent — a response that carried them would
	// be a response a client reads as a signal.
	if preview.Agent.IsClaimed() {
		t.Error("the preview of a live link reports the agent as claimed")
	}
	if preview.Agent.ClaimedByAccountID != nil {
		t.Error("the preview carries an account, and a live link has none")
	}
}

// TestThePreviewWritesNothing is the one property that makes the route safe to
// mount anonymously.
//
// IT IS BEHAVIORAL RATHER THAN A COMMENT ABOUT WHAT THE CODE DOES NOT DO: the
// preview runs, then the SAME link is claimed and the claim has to succeed. A
// preview that wrote an event row or spent the link would be a preview that made
// the claim that follows it fail, and no amount of reading the implementation
// proves otherwise — only claiming afterwards does.
func TestThePreviewWritesNothing(t *testing.T) {
	f := newPreviewFixture(t)

	link, _ := f.registerWith(t, "Noel", map[string]any{"host": "laptop"})

	preview, err := f.svc.PreviewClaim(f.previewCtx(), PreviewInput{
		Token: link, TraceID: "trace-preview", Now: serviceInstant,
	})
	if err != nil {
		t.Fatalf("previewing: %v", err)
	}

	// NO EVENT ROW. A preview is a page load and not an act, and an event table
	// with one row per page view is a table nobody can read.
	events, err := NewStore(f.pool).ListEvents(context.Background(), f.pool, preview.Agent.ID)
	if err != nil {
		t.Fatalf("reading the agent's events: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("the preview wrote %d event(s) to agent_events, want 0", len(events))
	}

	// NO CREDENTIAL. There was none before and there is none after.
	tokens, err := NewStore(f.pool).ListTokensForAgent(context.Background(), f.pool, preview.Agent.ID)
	if err != nil {
		t.Fatalf("reading the agent's tokens: %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("the preview left %d token(s) behind, want 0 — a preview must not mint", len(tokens))
	}

	// AND THE LINK STILL CLAIMS, which is the assertion that holds the other two
	// to something rather than to a count of rows.
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

// TestThePreviewCannotTellTheFourWaysALinkIsDeadApart is the invariant W1-P1
// established and the reason the route had to read through the store's own
// statement.
//
// THE NEGATIVE CONTROL IS PART OF THE TEST, not an assumption: a wrong token is
// one of the four rows, and it is the one that must NEVER resolve. Without it a
// use case that resolved everything would pass three of these four cases.
func TestThePreviewCannotTellTheFourWaysALinkIsDeadApart(t *testing.T) {
	f := newPreviewFixture(t)

	live, _ := f.registerWith(t, "Noel", nil)
	// A link that is real and will be claimed — the third row.
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
		// the clock, for the row that needs the link to have aged out
		now time.Time
	}{
		{name: "a wrong token", token: agentsPrefix + strings.Repeat("z", 43), now: serviceInstant},
		{name: "an empty token", token: "", now: serviceInstant},
		{name: "an expired link", token: live, now: serviceInstant.Add(ClaimLinkTTL + time.Second)},
		{name: "an already-claimed agent", token: claimedLink, now: serviceInstant},
		// The counterexample that makes the other four mean something: a link
		// nobody ever issued, in a database full of live ones.
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
			// The returned value is the ZERO one. A use case that returned the
			// agent it failed to resolve would be a use case whose handler can
			// render a partial body.
			if !preview.Agent.ID.IsZero() {
				t.Errorf("a refused preview carries agent %s, want none", preview.Agent.ID)
			}
		})
	}
}

// TestAPreviewAfterTheClockPassesTheExpiry is the boundary, and it is stated
// because the expiry is the one conjunct of the three that has an opinion about
// time: `claim_link_expires_at > now`, so the instant of expiry itself is spent.
func TestAPreviewAfterTheClockPassesTheExpiry(t *testing.T) {
	f := newPreviewFixture(t)

	link, _ := f.registerWith(t, "Noel", nil)

	// Just inside the window: still resolves.
	if _, err := f.svc.PreviewClaim(f.previewCtx(), PreviewInput{
		Token: link, Now: serviceInstant.Add(ClaimLinkTTL - time.Second),
	}); err != nil {
		t.Errorf("one second before the expiry: %v, want it to resolve", err)
	}
	// At the expiry: spent. `>` and not `>=`, which is the same boundary the
	// claim uses, and two implementations of one boundary is how a link stays
	// usable for a second longer than the response said it would.
	if _, err := f.svc.PreviewClaim(f.previewCtx(), PreviewInput{
		Token: link, Now: serviceInstant.Add(ClaimLinkTTL),
	}); !errors.Is(err, ErrNotFound) {
		t.Errorf("at the expiry: %v, want ErrNotFound", err)
	}
}

// agentsPrefix is the public shape of a credential, spelled out here rather than
// imported from the transport test helpers so this file is not coupled to the
// HTTP layer's fixtures.
const agentsPrefix = Prefix
