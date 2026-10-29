package db

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPoolAndTxBothSatisfyQuerier(t *testing.T) {
	t.Parallel()

	var _ Querier = (*pgxpool.Pool)(nil)
	var _ Querier = (pgx.Tx)(nil)
}

func TestPoolSatisfiesPool(t *testing.T) {
	t.Parallel()

	var _ Pool = (*pgxpool.Pool)(nil)
}

func TestPoolBeginYieldsAQuerier(t *testing.T) {
	t.Parallel()

	var p Pool

	defer func() {
		if recover() == nil {
			t.Fatal("Begin on a nil Pool did not reach the concrete type")
		}
	}()

	_ = p
	_, _ = p.Begin(context.Background())
}
