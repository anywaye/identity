package tenancy

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/anywaye/identity/internal/platform/db"
)

type recordingPool struct {
	tx *recordingTx

	began bool
	execs []string
	args  [][]any
}

type recordingTx struct {
	failBeginAccountWith error

	onExec func(sql string, args []any)

	execs []string
	args  [][]any

	committed  bool
	rolledBack bool
}

var (
	_ db.Pool = (*recordingPool)(nil)
	_ pgx.Tx  = (*recordingTx)(nil)
)

func newRecording() (*recordingPool, *recordingTx) {
	tx := &recordingTx{}
	return &recordingPool{tx: tx}, tx
}

func (p *recordingPool) Begin(context.Context) (pgx.Tx, error) {
	p.began = true
	return p.tx, nil
}

func (p *recordingPool) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if p.tx.onExec != nil {
		p.tx.onExec(sql, args)
	}
	p.execs = append(p.execs, sql)
	p.args = append(p.args, args)
	return pgconn.CommandTag{}, nil
}

func (p *recordingPool) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return nil, errors.New("recordingPool does not produce rows; this seam issues no reads")
}

func (p *recordingPool) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	panic("the account seam issues no reads; QueryRow reaching the fake is a defect in it")
}

func (t *recordingTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if t.onExec != nil {
		t.onExec(sql, args)
	}
	if sql == beginAccountSQL && t.failBeginAccountWith != nil {
		return pgconn.CommandTag{}, t.failBeginAccountWith
	}
	t.execs = append(t.execs, sql)
	t.args = append(t.args, args)
	return pgconn.CommandTag{}, nil
}

func (t *recordingTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return nil, errors.New("recordingTx does not produce rows; this seam issues no reads")
}

func (t *recordingTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	panic("the account seam issues no reads; QueryRow reaching the fake is a defect in it")
}

func (t *recordingTx) Commit(context.Context) error {
	t.committed = true
	return nil
}

func (t *recordingTx) Rollback(context.Context) error {
	t.rolledBack = true
	return nil
}

func (t *recordingTx) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, errors.New("not used by the account seam")
}

func (t *recordingTx) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	return nil, errors.New("not used by the account seam")
}

func (t *recordingTx) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults {
	return nil
}

func (t *recordingTx) LargeObjects() pgx.LargeObjects { return pgx.LargeObjects{} }

func (t *recordingTx) Begin(context.Context) (pgx.Tx, error) {
	return nil, errors.New("the account seam does not open nested transactions")
}

func (t *recordingTx) Conn() *pgx.Conn { return nil }
