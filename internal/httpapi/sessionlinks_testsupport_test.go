package httpapi

import (
	"context"

	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
)

// noEnrolledSecondFactor is `mfa.Service.Enabled` answering "no" for every subject.
//
// IT IS HERE AND NOT IN internal/mfa BECAUSE THE FIXTURES THAT NEED IT DO NOT BUILD
// AN MFA SERVICE, and requiring one would put a vault and a signing key in the path
// of every recovery-route test for the sake of a boolean. The real lookup is
// exercised in internal/mfa's own store test; what these fixtures need is for the
// session-link mint to be answerable at all, and a hard `false` is that.
//
// IT IS NOT AN OPTIONAL FIELD ON `recovery.NewService`. The constructor argument is
// required so that no deployment can be built unable to ask — and the mint's own
// test proves that a nil seam is refused rather than read as "no second factor".
type noEnrolledSecondFactor struct{}

func (noEnrolledSecondFactor) Enabled(context.Context, db.Querier, id.UUID) (bool, error) {
	return false, nil
}
