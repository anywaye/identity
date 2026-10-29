package db

import (
	"context"
	"errors"
	"testing"
)


func TestTxRunnerCommitsWhenTheFunctionSucceeds(t *testing.T) {
	t.Parallel()

	runner, fake := newFakeTxRunner()

	ran := false
	err := runner.Do(context.Background(), func(_ context.Context, _ Querier) error {
		ran = true
		return nil
	})

	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !ran {
		t.Error("the function never ran")
	}
	if !fake.committed {
		t.Error("the transaction was not committed")
	}
	if fake.rolledBack {
		t.Error("the transaction was rolled back after a successful function")
	}
}

func TestTxRunnerRollsBackAndReturnsTheError(t *testing.T) {
	t.Parallel()

	runner, fake := newFakeTxRunner()
	boom := errors.New("second write failed")

	err := runner.Do(context.Background(), func(context.Context, Querier) error {
		return boom
	})

	if !errors.Is(err, boom) {
		t.Errorf("Do = %v, want the function's error verbatim", err)
	}
	if !fake.rolledBack {
		t.Error("the transaction was not rolled back")
	}
	if fake.committed {
		t.Error("the transaction was committed after the function failed")
	}
}

func TestTxRunnerHandsOverTheTransactionNotThePool(t *testing.T) {
	t.Parallel()

	runner, fake := newFakeTxRunner()

	var inside Querier
	if err := runner.Do(context.Background(), func(_ context.Context, q Querier) error {
		inside = q
		fake.queryerUsedByFunction = q
		return nil
	}); err != nil {
		t.Fatalf("Do: %v", err)
	}

	if inside == nil {
		t.Fatal("the function was handed a nil Querier")
	}
	if fake.queryerUsedByFunction == nil {
		t.Error("the function was not handed the transaction")
	}
}

func TestTxRunnerRecoversAPanicAndRollsBack(t *testing.T) {
	t.Parallel()

	runner, fake := newFakeTxRunner()

	var recovered any
	func() {
		defer func() { recovered = recover() }()

		if err := runner.Do(context.Background(), func(context.Context, Querier) error {
			panic("the second write panicked")
		}); err == nil {
			t.Error("Do returned nil after a panic, want an error")
		}
	}()

	if recovered != nil {
		t.Errorf("the panic escaped Do: %v", recovered)
	}
	if !fake.rolledBack {
		t.Error("the transaction was not rolled back after a panic")
	}
}

func TestTxRunnerReportsACommitFailure(t *testing.T) {
	t.Parallel()

	runner, fake := newFakeTxRunner()
	fake.commitErr = errors.New("connection lost during COMMIT")

	err := runner.Do(context.Background(), func(context.Context, Querier) error { return nil })

	if !errors.Is(err, fake.commitErr) {
		t.Errorf("Do = %v, want the commit failure", err)
	}
}

func TestTxRunnerRefusesADeadContext(t *testing.T) {
	t.Parallel()

	runner, _ := newFakeTxRunner()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := runner.Do(ctx, func(context.Context, Querier) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Errorf("Do on a canceled context = %v, want context.Canceled", err)
	}
	if runner.pool.pool.began {
		t.Error("a transaction was begun for an already-canceled context")
	}
}

func TestTxRunnerRefusesANilFunction(t *testing.T) {
	t.Parallel()

	runner, _ := newFakeTxRunner()

	if err := runner.Do(context.Background(), nil); err == nil {
		t.Error("Do(nil) returned no error, want a rejection")
	}
}
