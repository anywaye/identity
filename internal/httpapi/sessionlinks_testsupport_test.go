package httpapi

import (
	"context"

	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
)

type noEnrolledSecondFactor struct{}

func (noEnrolledSecondFactor) Enabled(context.Context, db.Querier, id.UUID) (bool, error) {
	return false, nil
}
