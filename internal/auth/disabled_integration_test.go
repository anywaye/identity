package auth


import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/anywaye/identity/internal/oidc"
	"github.com/anywaye/identity/internal/outbox"
	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/sessions"
	"github.com/anywaye/identity/internal/useraudit"
	"github.com/anywaye/identity/internal/users"
)

type integrationFixture struct {
	svc   *Service
	pool  *pgxpool.Pool
	owner *pgxpool.Pool
	now   time.Time
	user  users.User
	token string
}

func newDisabledIntegrationFixture(t *testing.T) integrationFixture {
	t.Helper()

	pool, owner := dbtest.SchemaWithOwner(t)
	clk := clock.NewFake(start)

	svc := NewService(
		db.TxRunner{Pool: pool},
		db.Direct{Pool: pool},
		users.NewStore(pool),
		sessions.NewStore(pool),
		outbox.NewStore(pool),
		realTenancy(pool, clk),
		realSecondFactor(t, pool, clk),
		oidc.NewStore(pool),
		useraudit.NewStore(pool),
		users.NewHasherWithParams(&argon2id.Params{
			Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
		}),
		clk,
		24*time.Hour,
		false,
	)

	ctx := context.Background()
	email := dbtest.UniqueEmail(t)

	registered, err := svc.Register(ctx, RegisterInput{
		Email: email, Password: "correct horse battery",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	live, err := svc.Login(ctx, LoginInput{Email: email, Password: "correct horse battery"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if live.Token == "" {
		t.Fatal("Login minted no token, so there is no live session to revoke")
	}

	parsed, err := id.Parse(registered.ID.String())
	if err != nil {
		t.Fatalf("parsing the registered id: %v", err)
	}

	return integrationFixture{
		svc:   svc,
		pool:  pool,
		owner: owner,
		now:   clk.Now(),
		user:  users.User{ID: parsed, Email: email},
		token: live.Token,
	}
}

func (f integrationFixture) secondSession(t *testing.T, agent string) {
	t.Helper()
	if _, err := f.svc.Login(context.Background(), LoginInput{
		Email: f.user.Email, Password: "correct horse battery", UserAgent: agent,
	}); err != nil {
		t.Fatalf("the login for %s: %v", agent, err)
	}
}

func TestDisablingEndsTheLiveSessionInTheSameTransaction(t *testing.T) {
	f := newDisabledIntegrationFixture(t)
	ctx := context.Background()

	if _, err := f.svc.Authenticate(ctx, f.token); err != nil {
		t.Fatalf("the live session does not authenticate before the disable: %v", err)
	}

	if err := f.svc.Disable(ctx, disableFor(f.user.ID, f.now)); err != nil {
		t.Fatalf("Disable: %v", err)
	}

	if _, err := f.svc.Authenticate(ctx, f.token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("presenting the live session for a disabled user = %v, want ErrUnauthenticated. "+
			"A refusal here is what the same-transaction revocation buys: the row is gone, so the "+
			"lookup misses for a reason the caller cannot tell from a token that never existed",
			err)
	}
}

func TestDisablingDeletesEverySessionRowRatherThanFlaggingThem(t *testing.T) {
	f := newDisabledIntegrationFixture(t)
	ctx := context.Background()

	f.secondSession(t, "device-two")

	if got := countSessions(t, f.pool, f.user.ID); got != 2 {
		t.Fatalf("%d session rows before the disable, want 2", got)
	}

	if err := f.svc.Disable(ctx, disableFor(f.user.ID, f.now)); err != nil {
		t.Fatalf("Disable: %v", err)
	}

	if got := countSessions(t, f.pool, f.user.ID); got != 0 {
		t.Errorf("%d session rows remain after the disable, want 0: revocation is DELETE, and a flag "+
			"on a row nobody reads is not a revocation", got)
	}
}

func TestAFailedRevocationRollsBackTheDisableWithIt(t *testing.T) {
	f := newDisabledIntegrationFixture(t)
	ctx := context.Background()

	refuseTableWrites(t, f.owner, "sessions", "DELETE")

	err := f.svc.Disable(ctx, disableFor(f.user.ID, f.now))
	if err == nil {
		t.Fatal("Disable succeeded while the sessions DELETE was being refused, so the column " +
			"write committed on its own — two statements that were supposed to be one transaction")
	}
	if !strings.Contains(err.Error(), injectedRefusal) {
		t.Fatalf("Disable = %v, want the error the trigger raised (%q): a rollback caused by "+
			"something else proves nothing about the two writes being one transaction", err, injectedRefusal)
	}

	read := readUserByID(t, f.pool, f.user.ID)
	if read.DisabledAt != nil {
		t.Errorf("DisabledAt = %v after a failed revocation, want nil: the column write must roll "+
			"back with the DELETE it was supposed to be atomic with", read.DisabledAt)
	}
	if got := countSessions(t, f.pool, f.user.ID); got != 1 {
		t.Errorf("%d session rows after a failed revocation, want 1: the whole transaction rolled "+
			"back, so the session is untouched and the account is untouched", got)
	}

	if _, err := f.svc.Login(ctx, LoginInput{
		Email: f.user.Email, Password: "correct horse battery",
	}); err != nil {
		t.Errorf("Login after a rolled-back disable = %v, want success: nothing was disabled, so "+
			"nothing about this account changed", err)
	}
}

func TestAFailedColumnWriteLeavesTheSessionsAlone(t *testing.T) {
	f := newDisabledIntegrationFixture(t)
	ctx := context.Background()

	refuseTableWrites(t, f.owner, "users", "UPDATE")

	err := f.svc.Disable(ctx, disableFor(f.user.ID, f.now))
	if err == nil {
		t.Fatal("Disable succeeded while the users UPDATE was being refused")
	}
	if !strings.Contains(err.Error(), injectedRefusal) {
		t.Fatalf("Disable = %v, want the error the trigger raised (%q)", err, injectedRefusal)
	}

	if got := countSessions(t, f.pool, f.user.ID); got != 1 {
		t.Errorf("%d session rows after a failed disable, want 1: a rollback that dropped the DELETE "+
			"and kept the UPDATE would sign an operator's subjects out for nothing and leave the "+
			"account working", got)
	}
	if read := readUserByID(t, f.pool, f.user.ID); read.DisabledAt != nil {
		t.Errorf("DisabledAt = %v, want nil: the column write is the one that failed", read.DisabledAt)
	}
}

func TestReEnablingDoesNotRestoreTheSessionsItEnded(t *testing.T) {
	f := newDisabledIntegrationFixture(t)
	ctx := context.Background()

	if err := f.svc.Disable(ctx, disableFor(f.user.ID, f.now)); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if err := f.svc.Enable(ctx, enableFor(f.user.ID, f.now)); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	if _, err := f.svc.Authenticate(ctx, f.token); err == nil {
		t.Error("the session ended by the disable authenticates again after re-enabling: the " +
			"revocation was undone by a later call")
	}

	result, err := f.svc.Login(ctx, LoginInput{
		Email: f.user.Email, Password: "correct horse battery",
	})
	if err != nil {
		t.Fatalf("Login after re-enabling = %v, want the door open again", err)
	}
	if result.Token == "" {
		t.Error("Login after re-enabling minted no session")
	}
}

func TestTheRevocationIsNotSomethingThatMerelyExpires(t *testing.T) {
	f := newDisabledIntegrationFixture(t)
	ctx := context.Background()

	store := sessions.NewStore(f.pool)

	if _, err := store.ByToken(ctx, f.pool, f.token, f.now); err != nil {
		t.Fatalf("ByToken before the disable = %v, want the live session", err)
	}

	if err := f.svc.Disable(ctx, disableFor(f.user.ID, f.now)); err != nil {
		t.Fatalf("Disable: %v", err)
	}

	if _, err := store.ByToken(ctx, f.pool, f.token, f.now); !errors.Is(err, sessions.ErrNotFound) {
		t.Fatalf("ByToken immediately after the disable = %v, want sessions.ErrNotFound", err)
	}

	muchLater := f.now.Add(365 * 24 * time.Hour)
	if _, err := store.ByToken(ctx, f.pool, f.token, muchLater); !errors.Is(err, sessions.ErrNotFound) {
		t.Errorf("ByToken a year after the disable = %v, want sessions.ErrNotFound: this is a "+
			"revocation and not a lockout, and only one of those two answers this", err)
	}
}


func TestTheDisableLeavesARecordNamingTheOperatorInTheDatabase(t *testing.T) {
	f := newDisabledIntegrationFixture(t)
	ctx := context.Background()

	requireUserAuditTable(t, f.pool)

	if err := f.svc.Disable(ctx, disableFor(f.user.ID, f.now)); err != nil {
		t.Fatalf("Disable: %v", err)
	}

	var (
		gotSubject, gotActorUser, gotActorKey id.UUID
		gotAction, gotTrace                   string
		gotAt                                 time.Time
	)
	err := f.pool.QueryRow(ctx, `
		SELECT user_id, action, actor_user_id, actor_key_id, trace_id, occurred_at
		  FROM user_audit_log
		 WHERE user_id = $1`, f.user.ID).
		Scan(&gotSubject, &gotAction, &gotActorUser, &gotActorKey, &gotTrace, &gotAt)
	if err != nil {
		t.Fatalf("reading the audit row for the disabled user: %v\n"+
			"A disable that records nothing is the gap this packet closes, and the count "+
			"above is not an assertion about there being one.", err)
	}

	if gotSubject != f.user.ID {
		t.Errorf("the row's subject is %s, want the disabled user %s", gotSubject, f.user.ID)
	}
	if gotActorUser != auditActorUserID {
		t.Errorf("the row's actor user is %s, want %s", gotActorUser, auditActorUserID)
	}
	if gotActorKey != auditActorKeyID {
		t.Errorf("the row's actor KEY is %s, want %s — without the key id there is no credential "+
			"to revoke and no way to answer 'which token did this'", gotActorKey, auditActorKeyID)
	}
	if gotAction != string(useraudit.ActionUserDisabled) {
		t.Errorf("the row's action is %q, want %q", gotAction, useraudit.ActionUserDisabled)
	}
	if gotTrace != auditTraceID {
		t.Errorf("the row's trace id is %q, want %q — it is what joins the row to the request's "+
			"log line", gotTrace, auditTraceID)
	}
	if !gotAt.Equal(f.now) {
		t.Errorf("the row happened at %s, want %s: one instant for the whole event, so the "+
			"revocations, the column and the record cannot disagree about when it was", gotAt, f.now)
	}
}

func TestTheReEnableIsRecordedAsItsOwnEvent(t *testing.T) {
	f := newDisabledIntegrationFixture(t)
	ctx := context.Background()

	requireUserAuditTable(t, f.pool)

	if err := f.svc.Disable(ctx, disableFor(f.user.ID, f.now)); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	afterDisable := countUserAuditRows(t, f.pool, f.user.ID)

	later := f.now.Add(time.Hour)
	if err := f.svc.Enable(ctx, enableFor(f.user.ID, later)); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	var gotAction string
	if err := f.pool.QueryRow(ctx, `
		SELECT action FROM user_audit_log
		 WHERE user_id = $1 ORDER BY occurred_at DESC, id DESC LIMIT 1`, f.user.ID).
		Scan(&gotAction); err != nil {
		t.Fatalf("reading the newest audit row: %v", err)
	}
	if gotAction != string(useraudit.ActionUserEnabled) {
		t.Errorf("the newest action is %q, want %q", gotAction, useraudit.ActionUserEnabled)
	}
	if got := countUserAuditRows(t, f.pool, f.user.ID); got != afterDisable+1 {
		t.Errorf("%d audit rows after the re-enable, want %d — a re-enable that records nothing "+
			"leaves a trail saying the person is still disabled, which is the one conclusion an "+
			"investigator must never draw from a trail that is silent about the event that would "+
			"have corrected it", got, afterDisable+1)
	}
}

func TestAFailedAuditWriteRollsBackTheWholeDisable(t *testing.T) {
	f := newDisabledIntegrationFixture(t)
	ctx := context.Background()

	requireUserAuditTable(t, f.pool)
	refuseTableWrites(t, f.owner, "user_audit_log", "INSERT")

	err := f.svc.Disable(ctx, disableFor(f.user.ID, f.now))
	if err == nil {
		t.Fatal("the disable SUCCEEDED with a failing audit write. The record and the revocation " +
			"are not in the same transaction, so a disable can commit every revocation and the " +
			"column write with nothing to account for it.")
	}
	if !strings.Contains(err.Error(), injectedRefusal) {
		t.Fatalf("Disable = %v, want the error the trigger raised (%q)", err, injectedRefusal)
	}

	if got := countSessions(t, f.pool, f.user.ID); got != 1 {
		t.Errorf("%d session rows after a failed audit write, want 1: the fixture signs in one "+
			"session, so a rollback that dropped the DELETE would have signed the user out for "+
			"nothing while reporting failure", got)
	}
	if read := readUserByID(t, f.pool, f.user.ID); read.DisabledAt != nil {
		t.Errorf("DisabledAt = %v, want nil: the column write rolled back with the record", read.DisabledAt)
	}
	if got := countLiveTokens(t, f.pool, f.user.ID); got != 0 {
		t.Errorf("%d live access tokens after a failed audit write, want 0", got)
	}

	if got := countUserAuditRows(t, f.pool, f.user.ID); got != 0 {
		t.Errorf("%d audit rows survived a rolled-back disable: the trail claims an event that "+
			"did not happen, which is worse than no trail", got)
	}
}

func TestAFailedRevocationLeavesNoAuditRow(t *testing.T) {
	f := newDisabledIntegrationFixture(t)
	ctx := context.Background()

	requireUserAuditTable(t, f.pool)
	refuseTableWrites(t, f.owner, "sessions", "DELETE")

	if err := f.svc.Disable(ctx, disableFor(f.user.ID, f.now)); err == nil {
		t.Fatal("Disable succeeded while the sessions DELETE was being refused")
	}
	if got := countUserAuditRows(t, f.pool, f.user.ID); got != 0 {
		t.Errorf("%d audit rows after a disable whose revocation failed, want 0: a row here would "+
			"tell an investigator the disable was accounted for when the person is not disabled "+
			"at all", got)
	}
}

func TestTheRowADisableWroteCannotBeEditedOrDeleted(t *testing.T) {
	f := newDisabledIntegrationFixture(t)
	ctx := context.Background()

	requireUserAuditTable(t, f.pool)
	if err := f.svc.Disable(ctx, disableFor(f.user.ID, f.now)); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	var recID id.UUID
	if err := f.pool.QueryRow(ctx,
		`SELECT id FROM user_audit_log WHERE user_id = $1`, f.user.ID).Scan(&recID); err != nil {
		t.Fatalf("reading the written row's id: %v", err)
	}

	if _, err := f.pool.Exec(ctx,
		`UPDATE user_audit_log SET action = 'user.enabled' WHERE id = $1`, recID); err == nil {
		t.Error("an UPDATE to the record SUCCEEDED: the trail is editable by whoever can reach the " +
			"database, which includes the operator whose action is in it")
	} else if !strings.Contains(err.Error(), "append-only") {
		t.Errorf("the UPDATE failed for a reason that is not the append-only rule: %v", err)
	}

	if _, err := f.pool.Exec(ctx, `DELETE FROM user_audit_log WHERE id = $1`, recID); err == nil {
		t.Error("a DELETE from the record SUCCEEDED: an emptied trail is indistinguishable from " +
			"one where nothing suspicious happened")
	} else if !strings.Contains(err.Error(), "append-only") {
		t.Errorf("the DELETE failed for a reason that is not the append-only rule: %v", err)
	}

	if got := countUserAuditRows(t, f.pool, f.user.ID); got != 1 {
		t.Errorf("%d rows remain after a refused UPDATE and a refused DELETE, want 1 — a trigger "+
			"that raised AFTER writing would satisfy every assertion above", got)
	}
}

func requireUserAuditTable(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	var name string
	if err := pool.QueryRow(t.Context(),
		`SELECT relname FROM pg_class WHERE oid = to_regclass('user_audit_log')`).Scan(&name); err != nil {
		t.Fatalf("looking up user_audit_log: %v\n"+
			"Have the migrations been applied? `goose -dir migrations postgres \"$DATABASE_URL\" up` "+
			"— and is the table in dbtest's per-schema COPY list? A table missing from that "+
			"list does not fail loudly here; it fails as a missing relation.", err)
	}
	if name != "user_audit_log" {
		t.Fatalf("to_regclass('user_audit_log') resolved to %q, so every count below would be "+
			"about a different relation", name)
	}
}

func countUserAuditRows(t *testing.T, pool *pgxpool.Pool, subject id.UUID) int {
	t.Helper()

	var n int
	if err := pool.QueryRow(t.Context(),
		`SELECT count(*) FROM user_audit_log WHERE user_id = $1`, subject).Scan(&n); err != nil {
		t.Fatalf("counting user_audit_log rows: %v", err)
	}
	return n
}


func countLiveTokens(t *testing.T, pool *pgxpool.Pool, subject id.UUID) int {
	t.Helper()
	var n int
	err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM oidc_access_tokens WHERE subject = $1 AND revoked_at IS NULL`, subject).Scan(&n)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("counting live access tokens: %v", err)
	}
	return n
}

const injectedRefusal = "injected write failure for one test"

func refuseTableWrites(t *testing.T, pool *pgxpool.Pool, table, op string) {
	t.Helper()
	ctx := context.Background()

	fn := table + "_refuses_" + op
	_, err := pool.Exec(ctx, `
		CREATE FUNCTION `+fn+`() RETURNS trigger AS $$
		BEGIN
			RAISE EXCEPTION '`+injectedRefusal+`'
				USING ERRCODE = 'restrict_violation';
		END;
		$$ LANGUAGE plpgsql`)
	if err != nil {
		t.Fatalf("creating the trigger function: %v", err)
	}

	_, err = pool.Exec(ctx, `
		CREATE TRIGGER `+fn+`
		BEFORE `+op+` ON `+table+`
		FOR EACH ROW EXECUTE FUNCTION `+fn+`()`)
	if err != nil {
		t.Fatalf("creating the trigger: %v", err)
	}
}

func readUserByID(t *testing.T, pool *pgxpool.Pool, userID id.UUID) users.User {
	t.Helper()
	user, err := users.NewStore(pool).ByID(context.Background(), pool, userID)
	if err != nil {
		t.Fatalf("reading back the user: %v", err)
	}
	return user
}

func countSessions(t *testing.T, pool *pgxpool.Pool, userID id.UUID) int {
	t.Helper()
	var n int
	err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM sessions WHERE user_id = $1`, userID).Scan(&n)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("counting sessions: %v", err)
	}
	return n
}
