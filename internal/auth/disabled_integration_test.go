package auth

// PACKET identity-disabled-01: THE REVOCATION, AGAINST A REAL DATABASE.
//
// The doubles in disabled_test.go prove the branch. They cannot prove the claim
// this file exists for, and the claim is the whole of the packet's second half:
//
//	THE SAME TRANSACTION THAT SETS disabled_at DELETES THE USER'S SESSION ROWS.
//
// `fakeUnitOfWork` cannot roll anything back — its own comment says so — so a
// double-based suite would pass happily against an implementation that set the
// column in one transaction and swept the sessions in another, or in neither. The
// failure mode of that bug is a disabled account holding live sessions for as long
// as the sweeper is late, which is not a number anybody chose and not a number
// anybody would notice.
//
// So: real Postgres, real SQL, and BOTH directions of the failure.
//
//	failed session delete  →  the column write rolls back with it and the user is
//	                          NOT disabled. A disable that reported success here
//	                          would have disabled nobody.
//	failed column write    →  the sessions survive, because the transaction rolled
//	                          back. This is the direction that matters most: a
//	                          half-applied disable is an account an operator reads
//	                          as disabled and that keeps working anyway.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cafaye/identity/internal/oidc"
	"github.com/cafaye/identity/internal/outbox"
	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/sessions"
	"github.com/cafaye/identity/internal/useraudit"
	"github.com/cafaye/identity/internal/users"
)

// integrationFixture is a registered user, a real password digest and a real
// session minted through the real use case.
//
// The login goes through the service rather than the store so that the session row
// is one this service would recognise: a test that inserted a session by hand
// would be asserting about a row it built itself.
type integrationFixture struct {
	svc   *Service
	pool  *pgxpool.Pool
	owner *pgxpool.Pool
	now   time.Time
	user  users.User
	token string
}

// newDisabledIntegrationFixture builds the service over a private schema AND
// keeps the owner half of it.
//
// The owner pool is here for the trigger installation and nothing else, and the
// reason it is needed at all is the same privilege that makes 00012's append-only
// guarantee worth anything: `identity_app` — the role the pool under test is
// connected as, and the role production runs as — cannot create a function or a
// trigger. A test that could do either could make every revocation fail, or stop
// failing, at will. See migrations/README.md, "TEST_DATABASE_URL IS THE OWNER".
//
// The service under test runs on the APP pool, so every assertion below is
// answered under production's grants. Nothing is asserted through `owner`.
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
		// THE REAL SWEEP, over the real table — because the doubles in
		// access_token_sweep_test.go prove the use case ASKS and cannot prove the
		// ask REACHES the rows. Every assertion in that file would pass against a
		// store that swept nothing at all, since the double is what stands in for
		// this one.
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

// secondSession logs in again on another "device", so a test can prove the
// revocation takes EVERY row rather than the one it happens to see first.
func (f integrationFixture) secondSession(t *testing.T, agent string) {
	t.Helper()
	if _, err := f.svc.Login(context.Background(), LoginInput{
		Email: f.user.Email, Password: "correct horse battery", UserAgent: agent,
	}); err != nil {
		t.Fatalf("the login for %s: %v", agent, err)
	}
}

// The test. Disable, then present the live session.
//
// It is the red-proof stated as an assertion rather than run by hand. The session
// is proved to work FIRST, because a test that only checks the refusal passes just
// as well against a token that was never valid — which is the failure direction
// that matters here, since the whole claim is about a session that used to work.
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

// The rows are gone, not flagged.
//
// This asserts against the sessions TABLE rather than through Authenticate,
// because Authenticate's refusal could equally be produced by a check that reads
// disabled_at — a defence-in-depth branch that works and leaves every session row
// in the database. That is a different property and a worse one: the rows would
// still be there for anything else reading that table.
func TestDisablingDeletesEverySessionRowRatherThanFlaggingThem(t *testing.T) {
	f := newDisabledIntegrationFixture(t)
	ctx := context.Background()

	// Two sessions, on two "devices", so this is about EVERY session and not about
	// one row: an implementation that revoked only the newest would pass a
	// single-session test, and an account is rarely signed in on one device.
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

// THE FAILURE DIRECTION, and it is the one that makes the transaction claim mean
// anything.
//
// A trigger that refuses the DELETE makes the revoke step fail. The disable must
// then leave NOTHING behind: not a disabled account with live sessions, which is
// the exact state this packet exists to make unrepresentable.
func TestAFailedRevocationRollsBackTheDisableWithIt(t *testing.T) {
	f := newDisabledIntegrationFixture(t)
	ctx := context.Background()

	refuseTableWrites(t, f.owner, "sessions", "DELETE")

	// The failure is SURFACED, not swallowed. A disable that reported success and
	// disabled nobody is worse than one that reports a problem, because the caller
	// has already told somebody their access ended.
	err := f.svc.Disable(ctx, disableFor(f.user.ID, f.now))
	if err == nil {
		t.Fatal("Disable succeeded while the sessions DELETE was being refused, so the column " +
			"write committed on its own — two statements that were supposed to be one transaction")
	}
	// …and it is the INJECTED error. Without this the assertions below would pass
	// against a Disable that failed for any other reason and rolled back for the
	// wrong cause, which is the state of a check that never fires being
	// indistinguishable from a correct one.
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

	// And the door is still open, which is the honest consequence of a disable that
	// did not happen. Asserted through the real password path, so this is about the
	// concept rather than about a column.
	if _, err := f.svc.Login(ctx, LoginInput{
		Email: f.user.Email, Password: "correct horse battery",
	}); err != nil {
		t.Errorf("Login after a rolled-back disable = %v, want success: nothing was disabled, so "+
			"nothing about this account changed", err)
	}
}

// The other direction, because a test that only fires one way does not know which
// way it fires.
//
// A trigger on `users` makes the COLUMN write fail, and the sessions must survive:
// this is the "half-applied disable" shape, and it is the worse of the two because
// the account would read as disabled to an operator inspecting the table while
// continuing to work for whoever holds a session.
func TestAFailedColumnWriteLeavesTheSessionsAlone(t *testing.T) {
	f := newDisabledIntegrationFixture(t)
	ctx := context.Background()

	refuseTableWrites(t, f.owner, "users", "UPDATE")

	err := f.svc.Disable(ctx, disableFor(f.user.ID, f.now))
	if err == nil {
		t.Fatal("Disable succeeded while the users UPDATE was being refused")
	}
	// Same reason as the test above: the error has to be the injected one, or the
	// assertions below are about a coincidence.
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

// RE-ENABLE DOES NOT BRING THE SESSIONS BACK, and that is a decision rather than an
// omission.
//
// "Enable" reads like the inverse of everything Disable did, and it is not: the
// sessions it ended were minted before the account was turned off, and restoring
// them would hand back the exact credentials the revocation removed. The owner
// signs in again.
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

	// The door, though, is open — through the real password path.
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

// THERE IS NO GRACE WINDOW, and this is the sentence stated as an assertion.
//
// It reads the SESSIONS TABLE directly rather than through Authenticate, because
// the claim is about the row: a request already in flight dies at its next store
// read because the thing it reads is gone, not because a later check consulted a
// column. The clock is moved a long way forward afterwards to make sure the
// revocation was not something that merely had not expired yet — which is the
// distinction the whole migration header argues for.
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

	// A very long time afterwards, and at the same instant too. A lockout would
	// answer "live again" at one of these and the difference would be invisible.
	muchLater := f.now.Add(365 * 24 * time.Hour)
	if _, err := store.ByToken(ctx, f.pool, f.token, muchLater); !errors.Is(err, sessions.ErrNotFound) {
		t.Errorf("ByToken a year after the disable = %v, want sessions.ErrNotFound: this is a "+
			"revocation and not a lockout, and only one of those two answers this", err)
	}
}

// ---------------------------------------------------------------------------
// disabled-04: THE RECORD, AGAINST A REAL POSTGRES
// ---------------------------------------------------------------------------

// The audit row EXISTS, and it says the four things an incident review asks.
//
// This is the half the doubles cannot reach. Every test in user_audit_test.go runs
// against a `fakeAuditRecorder` whose `calls` slice is a Go value: it proves the
// recorder was ASKED, and it cannot prove the row reached the table, because the
// double is what stands in for the table. A writer that dropped its INSERT on the
// floor, or wrote to a different relation, would satisfy every one of them.
//
// IT READS THE TABLE DIRECTLY rather than through the store, and the store has no
// reader anyway: 00022's table has no route and no List method, so a raw count is the
// only way to look, which is the honest shape of a log nothing reads yet.
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

	// The subject and the actor are different uuids in disableFor, so each of these
	// distinguishes a swapped pair from a correct one.
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

// The re-enable records too, and it is the same row with a DIFFERENT action.
//
// The count is taken before and after rather than asserted absolutely, because a
// fixture that shares a schema with another test could otherwise see somebody else's
// rows and pass for the wrong reason — or fail, spuriously, on them.
func TestTheReEnableIsRecordedAsItsOwnEvent(t *testing.T) {
	f := newDisabledIntegrationFixture(t)
	ctx := context.Background()

	requireUserAuditTable(t, f.pool)

	if err := f.svc.Disable(ctx, disableFor(f.user.ID, f.now)); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	afterDisable := countUserAuditRows(t, f.pool, f.user.ID)

	// A LATER INSTANT, and the fixture's clock does not move on its own. Both events
	// landing on `f.now` would make "the newest row" ambiguous — ORDER BY occurred_at
	// DESC, id DESC is a total order, but a reader cannot tell which of two rows at
	// the same instant is newer by looking at the instants, and this test would then be
	// asserting whichever the planner returned. It is the same boundary case 00022's
	// header warns about for a cursor, met here in a query rather than in a page.
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

// THE FAILURE DIRECTION, AND IT IS THE ONE THE PACKET NAMED: A DISABLE THAT RECORDS
// AND DOES NOT REVOKE IS THE SAME GAP WEARING A DIFFERENT HAT.
//
// An audit trail claiming an event that did not happen is worse than no trail at all,
// because an investigator who finds the row STOPS looking — the trail has told them
// the disable is accounted for, and they have no reason to ask whether the person is
// actually signed out.
//
// The injection is a BEFORE INSERT trigger on user_audit_log raising, on the OWNER's
// pool because creating a trigger is DDL and identity_app may not do it. It is a
// SEPARATE trigger rather than a replacement of the append-only one, on
// admin's_store_test.go's reasoning: the production trigger fires on UPDATE and
// DELETE, so replacing its body would make it fail on the wrong operations and this
// test would pass without the INSERT ever reaching it.
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
	// The INJECTED error, or the assertions below are about a coincidence: a rollback
	// caused by anything else proves nothing about the record being inside the
	// transaction.
	if !strings.Contains(err.Error(), injectedRefusal) {
		t.Fatalf("Disable = %v, want the error the trigger raised (%q)", err, injectedRefusal)
	}

	// The revocations rolled back with the record. This is the assertion that matters,
	// and it is read from the database rather than from a double's call log.
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

	// And no row claiming it happened.
	if got := countUserAuditRows(t, f.pool, f.user.ID); got != 0 {
		t.Errorf("%d audit rows survived a rolled-back disable: the trail claims an event that "+
			"did not happen, which is worse than no trail", got)
	}
}

// The other direction, on the same transaction: a disable that FAILS EARLIER must not
// leave a record behind either.
//
// It is the same claim from the other side — nothing in the trail may describe an
// action that did not happen — and it is a separate test because the injection is on a
// different table. A single test with a table-driven injection would prove that at
// least one of them fires, which is a weaker statement than either.
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

// THE APPEND-ONLY TRIGGER, PROVEN IN THE SCHEMA THE SERVICE ACTUALLY RUNS AGAINST.
//
// internal/useraudit's store_test.go proves this over the table it creates itself.
// This one proves it over the row a real disable wrote, which is the version that
// matters: the guarantee has to hold for the rows production's writer produces, and a
// trigger installed on a table nothing writes to is a trigger that has never fired.
//
// It goes AROUND the service, issuing the UPDATE directly — a test that called the
// package would only show that the package has no Update method, which is true and
// irrelevant to somebody with psql.
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

// requireUserAuditTable is the guard against a check over nothing, in the integration
// tier specifically.
//
// The tests above count rows in `user_audit_log`. A count of zero is the answer both
// "nothing was recorded" and "there is no such table" would give if the query were
// allowed to fail quietly — and this repository has been bitten by a comparison of two
// empty things twice already. So the TABLE is resolved before any of them reasons
// about its contents.
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

// countUserAuditRows counts one subject's trail, so a test comparing before and after
// is unaffected by another test sharing the database.
func countUserAuditRows(t *testing.T, pool *pgxpool.Pool, subject id.UUID) int {
	t.Helper()

	var n int
	if err := pool.QueryRow(t.Context(),
		`SELECT count(*) FROM user_audit_log WHERE user_id = $1`, subject).Scan(&n); err != nil {
		t.Fatalf("counting user_audit_log rows: %v", err)
	}
	return n
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// countLiveTokens counts the access tokens a subject holds that are NOT revoked.
//
// IT COUNTS THE LIVE ONES RATHER THAN ALL OF THEM, because "the sweep matched no
// rows" and "the sweep revoked every live row" are both consistent with a count of
// all rows being right — and the first of those is the failure the tests above
// would otherwise accept as success.
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

// refuseTableWrites puts a trigger on one table that raises on one operation.
//
// IT IS A TRIGGER AND NOT A DOUBLED ERROR because the property under test is the
// ROLLBACK, and a double returning an error from one call inside a real
// transaction would not roll anything back — it would only return. A trigger
// fires inside the database, inside the transaction, and the rollback is the
// database's own.
//
// Nothing is dropped afterwards: dbtest.SchemaWithOwner gives every test a private
// schema and drops it on cleanup, so a leftover trigger cannot reach the next test.
//
// The message is a CONSTANT rather than a formatted one, because the tests assert
// on it: an error that merely happened to mention the table would be accepted by a
// test that only checked for an error, and the injection would quietly stop being
// the thing under test.
const injectedRefusal = "injected write failure for one test"

// refuseTableWrites installs that refusal on one table for one operation.
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

// readUser fetches the row Register created, through the real store.
//
// It takes the RegisteredUser rather than a bare id so that no call site can
// parse an id incorrectly and still compile — `registered.ID` is already a
// string here and `id.Parse` is the one way this repository turns one into a UUID.
func readUser(t *testing.T, pool *pgxpool.Pool, registered RegisteredUser) users.User {
	t.Helper()
	user, err := users.NewStore(pool).ByID(context.Background(), pool, registered.ID)
	if err != nil {
		t.Fatalf("reading back the registered user: %v", err)
	}
	return user
}

// readUserByID is readUser for the cases that already hold a UUID, which is most
// of them: the fixture keeps the user as a `users.User` rather than as the
// registration's own return value.
func readUserByID(t *testing.T, pool *pgxpool.Pool, userID id.UUID) users.User {
	t.Helper()
	user, err := users.NewStore(pool).ByID(context.Background(), pool, userID)
	if err != nil {
		t.Fatalf("reading back the user: %v", err)
	}
	return user
}

// countSessions is the count that makes "the row is gone" a fact about the table.
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
