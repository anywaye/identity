package httpapi

import (
	"context"
	"time"

	"github.com/anywaye/identity/internal/agents"
	"github.com/anywaye/identity/internal/platform/id"
)

type fakeAgents struct {
	claims []agents.Claimed
	err error

	regErr     error
	refreshErr error
	authErr    error
	tokenErr   error
	listErr    error
	owner      *agents.Owner
	tokens     []agents.Token

	previewErr error
	previews   []agents.ClaimPreview
}

func newFakeAgents() *fakeAgents { return &fakeAgents{} }

func (f *fakeAgents) Claim(_ context.Context, in agents.ClaimInput) (agents.Claimed, error) {
	if f.err != nil {
		return agents.Claimed{}, f.err
	}
	if len(f.claims) > 0 {
		out := f.claims[0]
		f.claims = f.claims[1:]
		return out, nil
	}
	agent := agents.Agent{
		ID:                 id.MustNew(),
		Name:               "Noel",
		Status:             agents.StatusClaimed,
		ClaimedByAccountID: &in.Account,
		ClaimedAt:          &in.Now,
	}
	return agents.Claimed{Agent: agent}, nil
}


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
		ClaimURL:           "https://anywaye.example/agents/claim/fake",
		ClaimLinkExpiresAt: now.Add(time.Hour),
	}, nil
}

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
		ClaimURL:           "https://anywaye.example/agents/claim/fake-refresh",
		ClaimLinkExpiresAt: in.Now.Add(time.Hour),
	}, nil
}

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

func (f *fakeAgents) ListTokens(_ context.Context, _ id.UUID) ([]agents.Token, error) {
	return f.tokens, f.listErr
}

func (f *fakeAgents) RevokeToken(_ context.Context, _, tokenID id.UUID, _ string, _ string, _ time.Time) (agents.Token, error) {
	if f.tokenErr != nil {
		return agents.Token{}, f.tokenErr
	}
	return agents.Token{ID: tokenID, Name: "bootstrap"}, nil
}

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

func (f *fakeAgents) ListAgents(_ context.Context, _ id.UUID) ([]agents.Agent, error) {
	return nil, nil
}
