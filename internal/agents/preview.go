package agents

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cafaye/identity/internal/platform/db"
)

// THE CLAIM PREVIEW — the read a claim screen makes BEFORE anybody approves.
//
// # WHY IT IS A SEPARATE USE CASE AND NOT A FLAG ON THE CLAIM
//
// The website's claim screen renders its first frame from `GET
// /v1/agents/claim/{token}`: the agent's name, when it registered, and the device
// document it described itself with. Without it, the screen's whole opening is a
// 404 that reads as "unrecognised" — including for a link that is perfectly live
// — because identity's failures are one collapsed shape and a missing route is
// indistinguishable from a bad token once the answer is a 404.
//
// The obvious implementation of the fix is a `preview bool` on ClaimInput. That
// is wrong in a way that matters: the claim MINTS. A flag on the claim reaches
// the mint on every call it is not meant to disable, and the day a handler
// forgets to set it the preview is claiming agents. So this is a separate method
// with no access to the credential machinery at all — `CreateToken` is not
// reachable from here, and there is no parameter that could make it so.
//
// # WHAT IT IS ALLOWED TO SAY
//
// A great deal about the principal, and nothing about the world around it. The
// response is the agent's own name, its registration instant, its self-description
// and when its link stops working. It is NOT a login: no credential, no session,
// no claim, and nothing that changes a row. `agent_events` gains nothing, and the
// absence is deliberate — a preview is a page load, not an act, and an event row
// per page view is a table nobody can read.
//
// # WHY IT IS NOT AN ENUMERATION ORACLE EITHER
//
// The read is the store's `ByClaimDigest`, which filters on the digest, the
// status AND the expiry in ONE statement. A wrong token, an expired link, an
// already-claimed agent and an agent that was never issued are therefore one
// value here, exactly as they are on the claim that follows. The preview does not
// get to be more talkative than the claim: a preview that said "this link was
// real but expired" would tell a stranger which of their guesses was close, which
// is the oracle the claim route refuses to be.
//
// WHAT IS DELIBERATELY NOT EXPORTED: the claim link's plaintext. It arrives as a
// path segment, is digested here, and no struct on this file's return path holds
// it again. `ClaimTokenDigest` is on Agent because the row holds it, and the
// handler's response type does not read it.

// PreviewInput is what a preview needs, and it is small on purpose.
type PreviewInput struct {
	// Token is the claim link exactly as the screen presents it. It is a
	// credential and not an identifier: there is no `agent_id` here and there
	// never will be, because a route that accepted one would let a caller name a
	// principal they were never given a link for.
	Token string
	// TraceID joins the refusal's log line to the request that caused it.
	TraceID string
	// Now is the service's clock, passed in so the expiry is judged against the
	// same instant the response is stamped with.
	Now time.Time
}

// ClaimPreview is what a live claim link reveals, and it reveals nothing else.
//
// ClaimLinkExpiresAt is beside the agent rather than on it, and that is the
// design: the expiry is a fact about the LINK, which is a separate thing from the
// principal and which the claim spends. Putting it on Agent would say the agent
// expires.
type ClaimPreview struct {
	Agent              Agent
	ClaimLinkExpiresAt time.Time
}

// PreviewClaim resolves a live claim link to the unclaimed agent it names.
//
// IT IS THE STORE'S OWN READ AND NOTHING ELSE. There is no write, no event, no
// credential and no second query. The transaction is opened for the same reason
// `Authenticate` opens one — the read has to see a consistent view of the row it
// resolves — and not to hold a write.
//
// THE FOUR REFUSALS ARE ONE VALUE. `ByClaimDigest` collapses a digest miss, a
// spent status and a dead expiry into ErrNotFound, and `ErrAlreadyClaimed` is
// folded onto the same value below for the same reason the claim folds it: it is
// distinct in the store for the benefit of a caller who already holds the row,
// and a stranger holding a link is not that caller.
func (s *Service) PreviewClaim(ctx context.Context, in PreviewInput) (ClaimPreview, error) {
	// The plaintext lives in exactly one place — this local — and is never written
	// anywhere and never logged.
	digest := Digest(in.Token)
	if digest == "" {
		return ClaimPreview{}, ErrNotFound
	}

	var (
		agent    Agent
		expiry   time.Time
		resolved bool
	)
	err := db.TxRunner{Pool: s.pool}.Do(ctx, func(ctx context.Context, tx db.Querier) error {
		found, err := s.store.ByClaimDigest(ctx, tx, digest, in.Now)
		if err != nil {
			if errors.Is(err, ErrAlreadyClaimed) {
				return ErrNotFound
			}
			return err
		}
		if found.ClaimLinkExpiresAt == nil {
			// The table's `agents_unclaimed_has_a_live_link` CHECK makes this
			// unreachable for a status of unclaimed, and it is refused rather than
			// rendered as a zero instant because a body carrying
			// `0001-01-01T00:00:00Z` is one that reads as "expired" to a screen.
			return ErrNotFound
		}
		agent, expiry, resolved = found, *found.ClaimLinkExpiresAt, true
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			// One sentence in the log, and it names no reason. The route renders
			// one 404 and the four ways this fails stay indistinguishable on the
			// wire, which is the invariant W1-P1 established and this read must
			// not weaken.
			return ClaimPreview{}, fmt.Errorf("agents: a claim link did not resolve: %w", ErrNotFound)
		}
		return ClaimPreview{}, err
	}
	if !resolved {
		return ClaimPreview{}, ErrNotFound
	}
	return ClaimPreview{Agent: agent, ClaimLinkExpiresAt: expiry}, nil
}
