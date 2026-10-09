package httpapi

import (
	"context"

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
// The assertions are deliberately few. A double that asserted real behaviour would
// be a second implementation of the use case, and the use case's own tests in
// internal/agents are where the behaviour is proved. What this one owes the suite
// is that calling it is visible: it records what it was asked to do and hands back
// a claim that looks like the one production produces.
type fakeAgents struct {
	calls  []agents.ClaimInput
	claims []agents.Claimed
	// err is returned on the next call, and nil is the default so the happy path
	// needs no setup.
	err error
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
