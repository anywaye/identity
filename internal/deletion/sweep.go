package deletion

import (
	"context"
	"fmt"
	"time"

	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
)

// The credential sweep, as a value rather than as recovery's private method.
//
// # WHY THIS IS NOT recovery.Service.revokeEveryCredential
//
// That function is the model and it is two statements in the right order:
// `sessions.RevokeAllForUser`, then `access.RevokeAccessTokensForUser`. It is
// also UNEXPORTED, and it should stay that way — it is private business of two
// flows inside the recovery package, and exporting it to share two statements
// with a third package would make `internal/recovery` (which knows about password
// resets, mail delivery and rate limits) a dependency of `internal/deletion`.
//
// So the two calls are made here against interfaces, and the duplication is
// held to the original by `TestTheSweepIsTwoStatementsInThisOrder` below, which
// fails if either call is dropped or if the order is reversed. That test is the
// reason this is acceptable rather than merely convenient: a "refactor" that
// quietly stopped revoking access tokens would keep every other test in the
// repository green, because nothing else sweeps them for this flow.

// SessionSweeper is `sessions.Store`'s one method this needs.
type SessionSweeper interface {
	RevokeAllForUser(ctx context.Context, q db.Querier, userID id.UUID) error
}

// AccessTokenSweeper is `oidc.Store`'s one method this needs.
type AccessTokenSweeper interface {
	RevokeAccessTokensForUser(ctx context.Context, q db.Querier, subject id.UUID, at time.Time) error
}

// Sweeper is the concrete CredentialSweeper, built from the two stores.
type Sweeper struct {
	sessions SessionSweeper
	access   AccessTokenSweeper
}

// NewSweeper returns the deletion credential sweep.
//
// It REFUSES a nil for either half rather than allowing one, and the direction is
// the point. `CredentialSweeper` itself may be nil — see its doc comment — but a
// Sweeper built with half a sweep is a value that would revoke sessions and
// leave every JWT standing, and the only symptom of that is a token that keeps
// working for up to fifteen minutes after the person deleted their account. A
// wiring bug should stop the process at construction, not reach a user request.
func NewSweeper(sessions SessionSweeper, access AccessTokenSweeper) (*Sweeper, error) {
	if sessions == nil {
		return nil, fmt.Errorf("deletion: refusing to build a sweeper that ends sessions with nothing to end them with")
	}
	if access == nil {
		return nil, fmt.Errorf("deletion: refusing to build a sweeper that cannot revoke access tokens")
	}
	return &Sweeper{sessions: sessions, access: access}, nil
}

// RevokeEveryCredential ends every session and every OIDC access token the user
// holds, in that order.
//
// The ORDER IS sessions-then-tokens and it is recovery's order, for a reason that
// is about a person rather than about tables: the session is the credential the
// person is most likely to still be holding, and a sweep that failed halfway
// should have taken the one they can reach by one click.
//
// `at` is the caller's clock so the access-token stamps and the
// `identity.user.deleted` event agree on one instant. The session sweep takes no
// timestamp because `sessions.Store.RevokeAllForUser` DELETES rather than
// stamping — a revoked session is deliberately indistinguishable from one that
// never existed.
func (s *Sweeper) RevokeEveryCredential(ctx context.Context, q db.Querier, userID id.UUID, at time.Time) error {
	if err := s.sessions.RevokeAllForUser(ctx, q, userID); err != nil {
		return fmt.Errorf("deleting the user's sessions: %w", err)
	}
	if err := s.access.RevokeAccessTokensForUser(ctx, q, userID, at); err != nil {
		return fmt.Errorf("revoking the user's access tokens: %w", err)
	}
	return nil
}
