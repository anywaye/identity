package db

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type fakeTx struct {
	committed  bool
	rolledBack bool
	commitErr  error
	queryerUsedByFunction Querier
}

func (t *fakeTx) Commit(context.Context) error {
	t.committed = true
	return t.commitErr
}

func (t *fakeTx) Rollback(context.Context) error {
	t.rolledBack = true
	return nil
}

func (t *fakeTx) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func (t *fakeTx) QueryRow(context.Context, string, ...any) pgx.Row { return nil }

func (t *fakeTx) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("not implemented in this test double")
}

func (t *fakeTx) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, errors.New("not implemented in this test double")
}

func (t *fakeTx) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	return nil, errors.New("not implemented in this test double")
}

func (t *fakeTx) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults {
	return nil
}

func (t *fakeTx) LargeObjects() pgx.LargeObjects { return pgx.LargeObjects{} }

func (t *fakeTx) Begin(context.Context) (pgx.Tx, error) {
	return nil, errors.New("not implemented in this test double")
}

func (t *fakeTx) Conn() *pgx.Conn { return nil }

type fakePool struct {
	tx *fakeTx
	pool poolFacts
}

type poolFacts struct {
	began bool
	poolQuerier Querier
}

func (p *fakePool) Begin(context.Context) (pgx.Tx, error) {
	p.pool.began = true
	return p.tx, nil
}

func (p *fakePool) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func (p *fakePool) QueryRow(context.Context, string, ...any) pgx.Row { return nil }

func (p *fakePool) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("not implemented in this test double")
}

type fakeRunner struct {
	TxRunner
	tx   *fakeTx
	pool *fakePool
}

func newFakeTxRunner() (fakeRunner, *fakeTx) {
	tx := &fakeTx{}
	pool := &fakePool{tx: tx}
	pool.pool.poolQuerier = tx
	return fakeRunner{TxRunner: TxRunner{Pool: pool}, tx: tx, pool: pool}, tx
}
