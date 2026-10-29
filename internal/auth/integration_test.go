package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/anywaye/identity/internal/mfa"
	"github.com/anywaye/identity/internal/oidc"
	"github.com/anywaye/identity/internal/outbox"
	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/sessions"
	"github.com/anywaye/identity/internal/useraudit"
	"github.com/anywaye/identity/internal/users"
)


func newIntegrationService(t *testing.T) (*Service, *pgxpool.Pool, *clock.Fake) {
	t.Helper()
	svc, pool, clk, _ := newIntegrationServiceWithMFA(t)
	return svc, pool, clk
}

func newIntegrationServiceWithMFA(t *testing.T) (*Service, *pgxpool.Pool, *clock.Fake, *mfa.Service) {
	t.Helper()

	pool := dbtest.Schema(t)
	clk := clock.NewFake(start)
	second := realSecondFactor(t, pool, clk)

	svc := NewService(
		db.TxRunner{Pool: pool},
		db.Direct{Pool: pool},
		users.NewStore(pool),
		sessions.NewStore(pool),
		outbox.NewStore(pool),
		realTenancy(pool, clk),
		second,
		oidc.NewStore(pool),
		useraudit.NewStore(pool),
		users.NewHasherWithParams(&argon2id.Params{
			Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
		}),
		clk,
		24*time.Hour,
		false,
	)
	return svc, pool, clk, second
}

func TestIntegrationRegisterCommitsTheUserAndTheEventTogether(t *testing.T) {
	svc, pool, _ := newIntegrationService(t)
	ctx := context.Background()
	email := dbtest.UniqueEmail(t)

	got, err := svc.Register(ctx, RegisterInput{Email: "  " + email + "  ", Password: "correct horse battery"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if got.Email != email {
		t.Errorf("Email = %q, want the trimmed, lower-cased %q", got.Email, email)
	}
	stored, err := users.NewStore(pool).ByEmail(ctx, pool, email)
	if err != nil {
		t.Fatalf("the user was not committed: %v", err)
	}
	if !strings.HasPrefix(stored.PasswordDigest, "$argon2id$") {
		t.Errorf("PasswordDigest = %q, want an argon2id digest", stored.PasswordDigest)
	}

	var (
		eventType    string
		eventSource  string
		eventSubject string
		publishedAt  *time.Time
		raw          []byte
	)
	err = pool.QueryRow(ctx, `
		SELECT type, source, subject, published_at, envelope
		FROM outbox_events WHERE subject = $1`, got.ID.String()).
		Scan(&eventType, &eventSource, &eventSubject, &publishedAt, &raw)
	if err != nil {
		t.Fatalf("the event was not committed: %v", err)
	}
	if eventType != outbox.EventUserCreated {
		t.Errorf("type = %q, want %q", eventType, outbox.EventUserCreated)
	}
	if eventSource != outbox.SourceIdentity {
		t.Errorf("source = %q, want %q", eventSource, outbox.SourceIdentity)
	}
	if eventSubject != got.ID.String() {
		t.Errorf("subject = %q, want %q", eventSubject, got.ID)
	}
	if publishedAt != nil {
		t.Error("published_at is set; nothing has been published yet")
	}

	var e outbox.Envelope
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatalf("the stored envelope does not parse: %v", err)
	}
	if err := e.Validate(); err != nil {
		t.Errorf("the stored envelope fails core's schema: %v", err)
	}
	if bytes.Contains(raw, []byte(stored.PasswordDigest)) {
		t.Error("the stored envelope contains the password digest")
	}
}

func TestIntegrationRegisterDuplicateWritesNoEvent(t *testing.T) {
	svc, pool, _ := newIntegrationService(t)
	ctx := context.Background()
	email := dbtest.UniqueEmail(t)

	if _, err := svc.Register(ctx, RegisterInput{Email: email, Password: "correct horse battery"}); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	before := countEvents(t, pool)

	if _, err := svc.Register(ctx, RegisterInput{Email: email, Password: "another good passphrase"}); !errors.Is(err, users.ErrEmailTaken) {
		t.Fatalf("second Register = %v, want errors.Is(_, users.ErrEmailTaken)", err)
	}

	if after := countEvents(t, pool); after != before {
		t.Errorf("outbox_events went from %d to %d rows; a rejected registration wrote an event", before, after)
	}
}

func TestIntegrationFullLifecycle(t *testing.T) {
	svc, pool, _ := newIntegrationService(t)
	ctx := context.Background()
	email := dbtest.UniqueEmail(t)
	const password = "correct horse battery staple"

	registered, err := svc.Register(ctx, RegisterInput{Email: email, Password: password})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	login, err := svc.Login(ctx, LoginInput{
		Email:     email,
		Password:  password,
		UserAgent: "integration-test",
		IP:        ptrAddr("203.0.113.7"),
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if login.User.ID != registered.ID {
		t.Errorf("the session belongs to %s, want %s", login.User.ID, registered.ID)
	}

	me, err := svc.Authenticate(ctx, login.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if me.Email != email {
		t.Errorf("Email = %q, want %q", me.Email, email)
	}
	var storedDigest string
	if err := pool.QueryRow(ctx, `SELECT token_digest FROM sessions WHERE user_id = $1`, registered.ID).Scan(&storedDigest); err != nil {
		t.Fatalf("reading the session: %v", err)
	}
	if storedDigest == login.Token {
		t.Error("the raw token is in the sessions table")
	}
	if storedDigest != sessions.Digest(login.Token) {
		t.Error("the stored digest is not Digest(token)")
	}

	if err := svc.Logout(ctx, login.Token); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := svc.Authenticate(ctx, login.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("the token still authenticates after Logout: %v", err)
	}
}

func TestIntegrationLockoutPersistsAcrossServiceInstances(t *testing.T) {
	svc, pool, clk := newIntegrationService(t)
	ctx := context.Background()
	email := dbtest.UniqueEmail(t)
	const password = "correct horse battery staple"

	if _, err := svc.Register(ctx, RegisterInput{Email: email, Password: password}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	for attempt := 1; attempt <= sessions.MaxFailedAttempts; attempt++ {
		if _, err := svc.Login(ctx, LoginInput{Email: email, Password: "wrong"}); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d = %v, want ErrInvalidCredentials", attempt, err)
		}
	}

	var lockedUntil *time.Time
	if err := pool.QueryRow(ctx, `SELECT locked_until FROM users WHERE email = $1`, email).Scan(&lockedUntil); err != nil {
		t.Fatalf("reading the lock: %v", err)
	}
	if lockedUntil == nil {
		t.Fatal("locked_until is NULL after five consecutive failures")
	}
	if want := start.Add(sessions.LockoutDuration); !lockedUntil.Equal(want) {
		t.Errorf("locked_until = %s, want %s — the lock is stamped from the injected clock", lockedUntil, want)
	}

	_, err := svc.Login(ctx, LoginInput{Email: email, Password: password})
	var locked *LockedError
	if !errors.As(err, &locked) {
		t.Fatalf("Login while locked = %v, want a *LockedError", err)
	}
	if locked.RetryAfter != sessions.LockoutDuration {
		t.Errorf("RetryAfter = %s, want %s", locked.RetryAfter, sessions.LockoutDuration)
	}

	clk.Set(start.Add(sessions.LockoutDuration))
	if _, err := svc.Login(ctx, LoginInput{Email: email, Password: password}); err != nil {
		t.Fatalf("Login after the window closed = %v, want success", err)
	}
}

func TestIntegrationLockIsVisibleToAnotherServiceInstance(t *testing.T) {
	svc, pool, _ := newIntegrationService(t)
	ctx := context.Background()
	email := dbtest.UniqueEmail(t)
	const password = "correct horse battery staple"

	if _, err := svc.Register(ctx, RegisterInput{Email: email, Password: password}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	for range sessions.MaxFailedAttempts {
		if _, err := svc.Login(ctx, LoginInput{Email: email, Password: "wrong"}); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("Login = %v, want ErrInvalidCredentials", err)
		}
	}

	other := NewService(
		db.TxRunner{Pool: pool},
		db.Direct{Pool: pool},
		users.NewStore(pool),
		sessions.NewStore(pool),
		outbox.NewStore(pool),
		realTenancy(pool, clock.NewFake(start)),
		realSecondFactor(t, pool, clock.NewFake(start)),
		oidc.NewStore(pool),
		useraudit.NewStore(pool),
		users.NewHasherWithParams(&argon2id.Params{
			Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
		}),
		clock.NewFake(start),
		24*time.Hour,
		false,
	)

	var locked *LockedError
	if _, err := other.Login(ctx, LoginInput{Email: email, Password: password}); !errors.As(err, &locked) {
		t.Errorf("a second service instance saw %v, want a *LockedError", err)
	}
}

func TestIntegrationRegisterIsAtomicWhenTheEventIsRejected(t *testing.T) {
	pool := dbtest.Schema(t)
	ctx := context.Background()
	email := dbtest.UniqueEmail(t)

	userStore := users.NewStore(pool)
	failingEvents := &rejectingAppender{inner: outbox.NewStore(pool), bad: outbox.Envelope{
		SpecVersion: outbox.SpecVersion,
		Type:        "NOT A VALID TYPE",
		Source:      outbox.SourceIdentity,
		Time:        start,
		Data:        json.RawMessage(`{}`),
	}}

	svc := NewService(
		db.TxRunner{Pool: pool},
		db.Direct{Pool: pool},
		userStore,
		sessions.NewStore(pool),
		failingEvents,
		realTenancy(pool, clock.NewFake(start)),
		realSecondFactor(t, pool, clock.NewFake(start)),
		oidc.NewStore(pool),
		useraudit.NewStore(pool),
		users.NewHasherWithParams(&argon2id.Params{
			Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
		}),
		clock.NewFake(start),
		24*time.Hour,
		false,
	)

	if _, err := svc.Register(ctx, RegisterInput{Email: email, Password: "correct horse battery"}); err == nil {
		t.Fatal("Register succeeded even though the event was rejected")
	}

	if _, err := userStore.ByEmail(ctx, pool, email); !errors.Is(err, users.ErrNotFound) {
		t.Errorf("the user survived a failed event write: %v — registration is not atomic", err)
	}
	if n := countEvents(t, pool); n != 0 {
		t.Errorf("outbox_events has %d rows, want 0", n)
	}
	if n := countRows(t, pool, "accounts"); n != 0 {
		t.Errorf("accounts has %d rows after a failed registration, want 0", n)
	}
}

type rejectingAppender struct {
	inner *outbox.Store
	bad   outbox.Envelope
}

func (r *rejectingAppender) Append(ctx context.Context, q db.Querier, _ outbox.Envelope) error {
	return r.inner.Append(ctx, q, r.bad)
}

func ptrAddr(s string) *netip.Addr {
	a := netip.MustParseAddr(s)
	return &a
}

func countEvents(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	return countRows(t, pool, "outbox_events")
}

func countRows(t *testing.T, pool *pgxpool.Pool, table string) int {
	t.Helper()

	var n int
	query := `SELECT count(*) FROM ` + table
	if err := pool.QueryRow(context.Background(), query).Scan(&n); err != nil {
		t.Fatalf("counting %s: %v", table, err)
	}
	return n
}
