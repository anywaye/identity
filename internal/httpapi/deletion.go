package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/anywaye/identity/internal/deletion"
)


// Deletion is the slice of internal/deletion this surface needs.
//
// It is one method rather than the service type, for the reason `Auth` and
// `Tenancy` are interfaces: the HTTP layer takes the use case and not the
// package, so a handler cannot reach a store and a test cannot reach a database
// through this struct.
type Deletion interface {
	Delete(ctx context.Context, in deletion.DeleteInput) error
}

// WithDeletion mounts DELETE /v1/me.
//
// It is ignored when d is nil, which leaves the route unmounted rather than
// mounted-and-500 — the same rule as every other Option here.
func WithDeletion(d Deletion) Option {
	return func(o *options) {
		if d != nil {
			o.deletion = d
		}
	}
}

func (o options) registerDeletionRoute(r chiRouter) {
	if o.deletion == nil {
		return
	}

	r.Delete("/v1/me", o.handleDeleteMe)
}

func (o options) handleDeleteMe(w http.ResponseWriter, r *http.Request) {
	user, ok := o.currentUser(w, r)
	if !ok {
		return
	}

	err := o.deletion.Delete(r.Context(), deletion.DeleteInput{
		UserID: user.ID,
		At:     o.clk.Now(),
	})
	switch {
	case err == nil:
		noContent(w)

	case errors.Is(err, deletion.ErrSolelyOwnedAccounts):
		problemFor(w, r, http.StatusConflict, CodeAccountOwnershipConflict, err.Error())

	default:
		unexpected(w, r, o.logger, err)
	}
}

var _ Deletion = (*deletion.Service)(nil)
