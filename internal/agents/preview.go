package agents

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/anywaye/identity/internal/platform/db"
)


// PreviewInput is what a preview needs, and it is small on purpose.
type PreviewInput struct {
	Token string
	TraceID string
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
			return ErrNotFound
		}
		agent, expiry, resolved = found, *found.ClaimLinkExpiresAt, true
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ClaimPreview{}, fmt.Errorf("agents: a claim link did not resolve: %w", ErrNotFound)
		}
		return ClaimPreview{}, err
	}
	if !resolved {
		return ClaimPreview{}, ErrNotFound
	}
	return ClaimPreview{Agent: agent, ClaimLinkExpiresAt: expiry}, nil
}
