package httpapi

import (
	"context"
	"time"

	"github.com/cafaye/identity/internal/agents"
	"github.com/cafaye/identity/internal/platform/id"
)

// The double for the agent claim use case.
//
// IT EXISTS SO THE WALKS CAN SEE THE ROUTE. `servedRoutes`, `mountedAccountRoutes`,
// `mountedFamilyRoutes` and `walkOptions` each build an `options` literal, and a
// field any of them leaves out is a surface the corresponding walk cannot read —
// which is how five routes were mounted and green with no document entry. This
// double is what makes the claim route visible to all four; the route it stands in
// for is served by `agents.Service` in a real process.
//
// The assertions are deliberately few. A double that asserted real behavior would
// be a second implementation of the use case, and the use case's own tests in
// internal/agents are where the behavior is proved. What this one owes the suite
// is that calling it is visible: it records what it was asked to do and hands back
// a claim that looks like the one production produces.
type fakeAgents struct {
	calls  []agents.ClaimInput
	claims []agents.Claimed
	// err is returned on the next call, and nil is the default so the happy path
	// needs no setup.
	err error

	// The W1-P2 fields, same err pattern per method so a test can drive a
	// refusal, plus an optional authenticated owner and list result.
	regErr     error
	refreshErr error
	authErr    error
	tokenErr   error
	listErr    error
	owner      *agents.Owner
	tokens     []agents.Token

	// The claim preview's queued error and results, same pattern as the token
	// lifecycle's, so a test can drive the collapsed 404 and the 200 shape.
	previewErr error
	previews   []agents.ClaimPreview
}

func newFakeAgents() *fakeAgents { return &fakeAgents{} }

// fail queues an error for the next Claim call.
func (f *fakeAgents) fail(err error) { f.err = err }

func (f *fakeAgents) Claim(_ context.Context, in agents.ClaimInput) (agents.Claimed, error) {
	f.calls = append(f.calls, in)
	if f.err != nil {
		return agents.Claimed{}, f.err
	}
	if len(f.claims) > 0 {
		out := f.claims[0]
		f.claims = f.claims[1:]
		return out, nil
	}
	// A claimed agent is what the route renders, and it is the shape the table's
	// CHECK produces rather than a hand-written struct literal that could drift
	// from it: an account, an instant and no link. The id is minted per call
	// because the route renders it and a shared one would make two claims in one
	// test look like the same agent.
	agent := agents.Agent{
		ID:                 id.MustNew(),
		Name:               "Noel",
		Status:             agents.StatusClaimed,
		ClaimedByAccountID: &in.Account,
		ClaimedAt:          &in.Now,
	}
	return agents.Claimed{Agent: agent}, nil
}

// lastCall is the most recent Claim this double received.
func (f *fakeAgents) lastCall() agents.ClaimInput {
	if len(f.calls) == 0 {
		return agents.ClaimInput{}
	}
	return f.calls[len(f.calls)-1]
}

// count is how many times Claim was called.
func (f *fakeAgents) count() int { return len(f.calls) }

// --- the claim preview ------------------------------------------------

// PreviewClaim resolves a presented claim link to an unclaimed agent.
//
// THE DEFAULT IS ErrNotFound AND THAT IS THE FAITHFUL DEFAULT, not a shortcut.
// Production resolves a claim link through the store's own ByClaimDigest, which
// filters the digest, the status AND the expiry in one statement, so a link
// nobody set up does not resolve — every time. A double that answered a happy
// path for any segment would be a double that made the route's collapsed 404
// unreachable, and the census's own probe (`TestEveryAuditedRouteStillAnswersWhatItsRowSays`,
// which asks for a link it did not create) would then be answered 200 and the
// audit row would have to be rewritten to describe a lie. So: a link a test
// queues resolves, and anything else is one 404, exactly as on the claim route.
func (f *fakeAgents) PreviewClaim(_ context.Context, in agents.PreviewInput) (agents.ClaimPreview, error) {
	if f.previewErr != nil {
		return agents.ClaimPreview{}, f.previewErr
	}
	if len(f.previews) > 0 {
		out := f.previews[0]
		f.previews = f.previews[1:]
		return out, nil
	}
	return agents.ClaimPreview{}, agents.ErrNotFound
}

// queuePreview queues the resolved claim a PreviewClaim call will return.
func (f *fakeAgents) queuePreview(p agents.ClaimPreview) { f.previews = append(f.previews, p) }

// failPreview queues an error for the next PreviewClaim call.
func (f *fakeAgents) failPreview(err error) { f.previewErr = err }

// --- the W1-P2 surface ------------------------------------------------
//
// These make the fake satisfy the whole Agents interface, which is what lets the
// router walks (servedRoutes, mountedFamilyRoutes, walkOptions) MOUNT the
// registration and token routes and therefore require their document entries and
// enumeration-audit rows. Their behavior is deliberately thin: the use cases have
// their own tables in internal/agents, and this double's only obligation here is
// that the surface is WIRED, not that it is correct.
//
// regErr is queued for the next Register, mirroring Claim's err, so a test can
// drive the mapper's refusal arms.

// Register mints a stand-in registration. It records nothing the assertion reads;
// it exists so the route it mounts answers something shaped like production's.
func (f *fakeAgents) Register(_ context.Context, in agents.RegisterInput) (agents.Registered, error) {
	if f.regErr != nil {
		return agents.Registered{}, f.regErr
	}
	now := in.Now
	name := in.Name
	if name == "" {
		name = "agent"
	}
	return agents.Registered{
		Agent: agents.Agent{
			ID:       id.MustNew(),
			Name:     name,
			Username: in.Username,
			Status:   agents.StatusUnclaimed,
		},
		Token: agents.Token{
			ID:        id.MustNew(),
			Name:      "bootstrap",
			CreatedAt: now,
			ExpiresAt: now.Add(time.Hour),
		},
		TokenPlaintext:     agents.Prefix + "fake-registration-token",
		ClaimURL:           "https://cafaye.example/agents/claim/fake",
		ClaimLinkExpiresAt: now.Add(time.Hour),
	}, nil
}

// RefreshClaimLink hands back a fresh link without claiming, matching production's
// refreshed shape.
func (f *fakeAgents) RefreshClaimLink(_ context.Context, in agents.RefreshClaimInput) (agents.RefreshedClaim, error) {
	if f.refreshErr != nil {
		return agents.RefreshedClaim{}, f.refreshErr
	}
	return agents.RefreshedClaim{
		Agent: agents.Agent{
			ID:     id.MustNew(),
			Name:   "Noel",
			Status: agents.StatusUnclaimed,
		},
		ClaimURL:           "https://cafaye.example/agents/claim/fake-refresh",
		ClaimLinkExpiresAt: in.Now.Add(time.Hour),
	}, nil
}

// Authenticate resolves the bearer credential to an owner. With an authenticated
// owner configured it returns it; otherwise it hands back an unclaimed principal,
// which is what a freshly-registered agent's token resolves to.
func (f *fakeAgents) Authenticate(_ context.Context, _ string, _ time.Time) (agents.Owner, error) {
	if f.authErr != nil {
		return agents.Owner{}, f.authErr
	}
	if f.owner != nil {
		return *f.owner, nil
	}
	agentID := id.MustNew()
	return agents.Owner{
		Agent:   agents.Agent{ID: agentID, Name: "Noel", Status: agents.StatusUnclaimed},
		Token:   agents.Token{ID: id.MustNew(), AgentID: agentID, Name: "bootstrap"},
		ActorID: id.MustNew(),
	}, nil
}

// IssueToken mints a stand-in credential.
func (f *fakeAgents) IssueToken(_ context.Context, in agents.TokenInput) (agents.IssuedToken, error) {
	if f.tokenErr != nil {
		return agents.IssuedToken{}, f.tokenErr
	}
	return agents.IssuedToken{
		Token: agents.Token{
			ID:        id.MustNew(),
			AgentID:   in.Agent,
			Name:      in.Name,
			CreatedAt: in.Now,
			ExpiresAt: in.Now.Add(time.Hour),
		},
		Plaintext: agents.Prefix + "fake-agent-token",
	}, nil
}

// ListTokens returns whatever the test queued.
func (f *fakeAgents) ListTokens(_ context.Context, _ id.UUID) ([]agents.Token, error) {
	return f.tokens, f.listErr
}

// RevokeToken returns the passed row on success.
func (f *fakeAgents) RevokeToken(_ context.Context, _, tokenID id.UUID, _ string, _ string, _ time.Time) (agents.Token, error) {
	if f.tokenErr != nil {
		return agents.Token{}, f.tokenErr
	}
	return agents.Token{ID: tokenID, Name: "bootstrap"}, nil
}

// RotateToken mints a stand-in replacement.
func (f *fakeAgents) RotateToken(_ context.Context, agentID, tokenID id.UUID, _ *time.Duration, _ string, now time.Time) (agents.IssuedToken, error) {
	if f.tokenErr != nil {
		return agents.IssuedToken{}, f.tokenErr
	}
	return agents.IssuedToken{
		Token: agents.Token{
			ID:        id.MustNew(),
			AgentID:   agentID,
			Name:      "bootstrap",
			CreatedAt: now,
			ExpiresAt: now.Add(time.Hour),
		},
		Plaintext: agents.Prefix + "fake-rotated-token",
	}, nil
}

// failRegister queues an error for the next Register call.
func (f *fakeAgents) failRegister(err error) { f.regErr = err }

// failRefresh queues an error for the next RefreshClaimLink call.
func (f *fakeAgents) failRefresh(err error) { f.refreshErr = err }

// failAuth queues an error for the next Authenticate call.
func (f *fakeAgents) failAuth(err error) { f.authErr = err }
