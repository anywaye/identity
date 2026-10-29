package tenancy

import (
	"context"
	"errors"
	"testing"

	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
)


func TestAnAccountTravelsOnTheContextAndComesBack(t *testing.T) {
	t.Parallel()

	account := mustNewAccount(t)
	ctx := WithAccount(context.Background(), account)

	got, ok := AccountFrom(ctx)
	if !ok {
		t.Fatal("AccountFrom reported no account on a context carrying one")
	}
	if got != account {
		t.Errorf("AccountFrom = %v, want the account that was put on the context (%v)", got, account)
	}
}

func TestAContextWithNoAccountSaysSo(t *testing.T) {
	t.Parallel()

	for name, ctx := range map[string]context.Context{
		"nothing was put on it": context.Background(),
		"the nil uuid was":      WithAccount(context.Background(), id.UUID{}),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if account, ok := AccountFrom(ctx); ok {
				t.Errorf("AccountFrom = (%v, true), want (zero, false): a request with no account must not read as one", account)
			}
		})
	}
}

func TestTxRunnerSetsTheIdentityBeforeTheUseCaseRuns(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		account id.UUID
		wantSet bool
	}{
		{name: "a request with an account sets it", account: mustNewAccount(t), wantSet: true},
		{name: "a request with none does not", wantSet: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pool, tx := newRecording()
			runner := TxRunner{TxRunner: db.TxRunner{Pool: pool}}

			ctx := context.Background()
			if !tc.account.IsZero() {
				ctx = WithAccount(ctx, tc.account)
			}

			var sawSet bool
			var sawArgument any
			tx.onExec = func(sql string, args []any) {
				if sql != beginAccountSQL {
					return
				}
				sawSet = true
				if len(args) == 1 {
					sawArgument = args[0]
				}
			}

			ran := false
			err := runner.Do(ctx, func(ctx context.Context, q db.Querier) error {
				ran = true
				if sawSet != tc.wantSet {
					t.Errorf("inside the use case, begin_account had been issued = %v, want %v", sawSet, tc.wantSet)
				}
				return nil
			})
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			if !ran {
				t.Fatal("Do committed without running the function")
			}

			if sawSet != tc.wantSet {
				t.Fatalf("begin_account was issued = %v, want %v", sawSet, tc.wantSet)
			}
			if tc.wantSet && sawArgument != tc.account {
				t.Errorf("begin_account was called with %v, want the request's account %v", sawArgument, tc.account)
			}
		})
	}
}

func TestTheIdentityIsSetOnTheTransactionAndNotOnThePool(t *testing.T) {
	t.Parallel()

	pool, tx := newRecording()
	runner := TxRunner{TxRunner: db.TxRunner{Pool: pool}}

	if err := runner.Do(WithAccount(context.Background(), mustNewAccount(t)), func(context.Context, db.Querier) error {
		return nil
	}); err != nil {
		t.Fatalf("Do: %v", err)
	}

	if len(pool.execs) != 0 {
		t.Errorf("the pool received %d statements, want none: begin_account is transaction-local and must "+
			"never be issued on the pool, where it would outlive the request. Statements: %v",
			len(pool.execs), pool.execs)
	}
	if len(tx.execs) != 1 {
		t.Fatalf("the transaction received %d statements, want exactly one (the identity): %v", len(tx.execs), tx.execs)
	}
}

func TestAFailedIdentityFailsTheTransactionWithoutRunningTheUseCase(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("the GUC would not set")
	pool, tx := newRecording()
	tx.failBeginAccountWith = sentinel
	runner := TxRunner{TxRunner: db.TxRunner{Pool: pool}}

	ran := false
	err := runner.Do(WithAccount(context.Background(), mustNewAccount(t)), func(context.Context, db.Querier) error {
		ran = true
		return nil
	})

	if !errors.Is(err, ErrNoIdentity) {
		t.Errorf("Do returned %v, want something matching ErrNoIdentity, so a caller can tell a refused identity from an absent account", err)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("Do returned %v, want it to wrap the underlying failure too", err)
	}
	if ran {
		t.Error("the use case ran after the identity was refused")
	}
	if !tx.rolledBack {
		t.Error("the transaction was not rolled back after the identity was refused")
	}
	if tx.committed {
		t.Error("the transaction committed after the identity was refused")
	}
}

func TestARequestWithNoAccountPaysNoRoundTrip(t *testing.T) {
	t.Parallel()

	pool, tx := newRecording()
	runner := TxRunner{TxRunner: db.TxRunner{Pool: pool}}

	if err := runner.Do(context.Background(), func(context.Context, db.Querier) error {
		return nil
	}); err != nil {
		t.Fatalf("Do: %v", err)
	}

	if len(tx.execs) != 0 {
		t.Errorf("the transaction received %d statements, want none for a request with no account: %v",
			len(tx.execs), tx.execs)
	}
}

func TestTheSeamDoesNotSwallowTheUseCasesError(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("the store said no")
	pool, tx := newRecording()
	runner := TxRunner{TxRunner: db.TxRunner{Pool: pool}}

	err := runner.Do(WithAccount(context.Background(), mustNewAccount(t)), func(context.Context, db.Querier) error {
		return sentinel
	})

	if !errors.Is(err, sentinel) {
		t.Errorf("Do returned %v, want the use case's own error unwrapped", err)
	}
	if tx.committed {
		t.Error("a transaction whose use case failed was committed")
	}
}

func TestBeginAccountRefusesTheNilAccount(t *testing.T) {
	t.Parallel()

	pool, tx := newRecording()
	err := BeginAccount(context.Background(), pool, id.UUID{})

	if !errors.Is(err, ErrNoIdentity) {
		t.Errorf("BeginAccount with the nil account returned %v, want something matching ErrNoIdentity", err)
	}
	if len(pool.execs)+len(tx.execs) != 0 {
		t.Errorf("BeginAccount issued %d statements for the nil account, want none: a caller about to write "+
			"a membership for nobody must be told, not sent to the database to be refused there",
			len(pool.execs)+len(tx.execs))
	}
}

func TestBeginAccountSetsTheGivenAccountOnTheCallersTransaction(t *testing.T) {
	t.Parallel()

	account := mustNewAccount(t)
	pool, _ := newRecording()

	if err := BeginAccount(context.Background(), pool, account); err != nil {
		t.Fatalf("BeginAccount: %v", err)
	}

	if len(pool.execs) != 1 || pool.execs[0] != beginAccountSQL {
		t.Errorf("the querier received %v, want exactly [%s]", pool.execs, beginAccountSQL)
	}
	if len(pool.args) != 1 || len(pool.args[0]) != 1 || pool.args[0][0] != account {
		t.Errorf("begin_account was called with %v, want the account it was handed (%v)", pool.args, account)
	}
}

func mustNewAccount(t *testing.T) id.UUID {
	t.Helper()
	account, err := id.New()
	if err != nil {
		t.Fatalf("generating a uuid: %v", err)
	}
	return account
}
