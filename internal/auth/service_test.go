package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/anywaye/identity/internal/outbox"
	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/sessions"
	"github.com/anywaye/identity/internal/users"
)

var start = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)


type fakeUsers struct {
	byEmail map[string]users.User
	byID    map[id.UUID]users.User
	nextID  int

	createErr error
	recordErr error
	cleared int
	searchErr error
	creates int
}

func newFakeUsers() *fakeUsers {
	return &fakeUsers{byEmail: map[string]users.User{}, byID: map[id.UUID]users.User{}, nextID: 1}
}

func (f *fakeUsers) Create(_ context.Context, _ db.Querier, p users.CreateParams) (users.User, error) {
	f.creates++
	if f.createErr != nil {
		return users.User{}, f.createErr
	}
	if _, taken := f.byEmail[p.Email]; taken {
		return users.User{}, users.ErrEmailTaken
	}

	var raw id.UUID
	raw[15] = byte(f.nextID)
	f.nextID++

	u := users.User{ID: raw, Email: p.Email, PasswordDigest: p.PasswordDigest}
	f.byEmail[p.Email] = u
	f.byID[u.ID] = u
	return u, nil
}

func (f *fakeUsers) ByEmail(_ context.Context, _ db.Querier, email string) (users.User, error) {
	u, ok := f.byEmail[email]
	if !ok {
		return users.User{}, users.ErrNotFound
	}
	return u, nil
}

func (f *fakeUsers) ByID(_ context.Context, _ db.Querier, want id.UUID) (users.User, error) {
	u, ok := f.byID[want]
	if !ok {
		return users.User{}, users.ErrNotFound
	}
	return u, nil
}

func (f *fakeUsers) RecordFailedLogin(_ context.Context, _ db.Querier, userID id.UUID, attempts int, lockedUntil *time.Time) error {
	if f.recordErr != nil {
		return f.recordErr
	}
	u, ok := f.byID[userID]
	if !ok {
		return users.ErrNotFound
	}
	u.FailedLoginAttempts = attempts
	u.LockedUntil = lockedUntil
	f.byID[userID] = u
	f.byEmail[u.Email] = u
	return nil
}

func (f *fakeUsers) Disable(_ context.Context, _ db.Querier, userID id.UUID, at time.Time) error {
	u, ok := f.byID[userID]
	if !ok {
		return users.ErrNotFound
	}
	u.DisabledAt = &at
	f.byID[userID] = u
	f.byEmail[u.Email] = u
	return nil
}

func (f *fakeUsers) Enable(_ context.Context, _ db.Querier, userID id.UUID) error {
	u, ok := f.byID[userID]
	if !ok {
		return users.ErrNotFound
	}
	u.DisabledAt = nil
	f.byID[userID] = u
	f.byEmail[u.Email] = u
	return nil
}

func (f *fakeUsers) UpdateName(_ context.Context, _ db.Querier, userID id.UUID, name *string) error {
	u, ok := f.byID[userID]
	if !ok {
		return users.ErrNotFound
	}
	u.DisplayName = name
	f.byID[userID] = u
	f.byEmail[u.Email] = u
	return nil
}

func (f *fakeUsers) UpdateTheme(_ context.Context, _ db.Querier, userID id.UUID, theme *string) error {
	u, ok := f.byID[userID]
	if !ok {
		return users.ErrNotFound
	}
	u.Preferences.Theme = theme
	f.byID[userID] = u
	f.byEmail[u.Email] = u
	return nil
}

func (f *fakeUsers) ClearFailures(_ context.Context, _ db.Querier, userID id.UUID) error {
	f.cleared++
	u, ok := f.byID[userID]
	if !ok {
		return users.ErrNotFound
	}
	u.FailedLoginAttempts = 0
	u.LockedUntil = nil
	f.byID[userID] = u
	f.byEmail[u.Email] = u
	return nil
}

func (f *fakeUsers) Search(_ context.Context, _ db.Querier, query string, limit int) ([]users.DirectoryEntry, error) {
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	lowered := strings.ToLower(query)
	var out []users.DirectoryEntry
	for _, u := range f.byID {
		if !strings.Contains(strings.ToLower(u.Email), lowered) {
			continue
		}
		out = append(out, users.DirectoryEntry{
			ID:              u.ID,
			Email:           u.Email,
			DisplayName:     u.DisplayName,
			DisabledAt:      u.DisabledAt,
			EmailVerifiedAt: u.EmailVerifiedAt,
		})
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	if out == nil {
		out = []users.DirectoryEntry{}
	}
	return out, nil
}

type fakeSessions struct {
	minted []sessions.NewSession
	live   map[string]id.UUID
	owners map[id.UUID]id.UUID
	nextID int
	revoked []id.UUID
	createErr  error
	byTokenErr error
	listErr    error
	nowSeen []time.Time

	listedFor  []id.UUID
	revokedOne []revokeOneCall
}

type revokeOneCall struct {
	userID    id.UUID
	sessionID id.UUID
	found bool
}

func newFakeSessions() *fakeSessions {
	return &fakeSessions{live: map[string]id.UUID{}, owners: map[id.UUID]id.UUID{}, nextID: 1}
}

func (f *fakeSessions) Create(_ context.Context, _ db.Querier, n sessions.NewSession) (sessions.Session, error) {
	if f.createErr != nil {
		return sessions.Session{}, f.createErr
	}
	f.minted = append(f.minted, n)
	var sid id.UUID
	sid[14] = byte(f.nextID)
	f.nextID++
	f.live[n.TokenDigest] = sid
	f.owners[sid] = n.UserID
	return sessions.Session{ID: sid, UserID: n.UserID, ExpiresAt: n.ExpiresAt, UserAgent: n.UserAgent, IP: n.IP}, nil
}

func (f *fakeSessions) ByToken(_ context.Context, _ db.Querier, token string, now time.Time) (sessions.Session, error) {
	f.nowSeen = append(f.nowSeen, now)
	if f.byTokenErr != nil {
		return sessions.Session{}, f.byTokenErr
	}
	sid, ok := f.live[sessions.Digest(token)]
	if !ok {
		return sessions.Session{}, sessions.ErrNotFound
	}
	return sessions.Session{ID: sid, UserID: f.owners[sid]}, nil
}

func (f *fakeSessions) RevokeAllForUser(_ context.Context, _ db.Querier, userID id.UUID) error {
	for digest, sid := range f.live {
		if f.owners[sid] == userID {
			delete(f.live, digest)
		}
	}
	return nil
}

func (f *fakeSessions) Revoke(_ context.Context, _ db.Querier, sessionID id.UUID) error {
	f.revoked = append(f.revoked, sessionID)
	for digest, sid := range f.live {
		if sid == sessionID {
			delete(f.live, digest)
		}
	}
	return nil
}

func (f *fakeSessions) ListLiveForUser(_ context.Context, _ db.Querier, userID id.UUID, now time.Time) ([]sessions.Session, error) {
	f.listedFor = append(f.listedFor, userID)
	f.nowSeen = append(f.nowSeen, now)
	if f.listErr != nil {
		return nil, f.listErr
	}

	out := make([]sessions.Session, 0, len(f.live))
	for digest, sid := range f.live {
		if f.owners[sid] != userID {
			continue
		}
		row := sessions.Session{ID: sid, UserID: userID}
		for _, m := range f.minted {
			if m.TokenDigest == digest {
				row.ExpiresAt = m.ExpiresAt
				row.UserAgent = m.UserAgent
				row.IP = m.IP
			}
		}
		out = append(out, row)
	}
	return out, nil
}

func (f *fakeSessions) RevokeOneForUser(_ context.Context, _ db.Querier, userID, sessionID id.UUID) (bool, error) {
	owner := f.owners[sessionID]
	live := false
	for _, sid := range f.live {
		if sid == sessionID {
			live = true
		}
	}
	found := live && owner == userID
	f.revokedOne = append(f.revokedOne, revokeOneCall{userID: userID, sessionID: sessionID, found: found})
	if !found {
		return false, nil
	}
	for digest, sid := range f.live {
		if sid == sessionID {
			delete(f.live, digest)
		}
	}
	return true, nil
}

type fakeEvents struct {
	appended []outbox.Envelope
	appendErr error
	queriersUsed []db.Querier
}

func (f *fakeEvents) Append(_ context.Context, q db.Querier, e outbox.Envelope) error {
	f.queriersUsed = append(f.queriersUsed, q)
	if f.appendErr != nil {
		return f.appendErr
	}
	f.appended = append(f.appended, e)
	return nil
}

type fakeUnitOfWork struct {
	ran     int
	querier db.Querier
	failWith error
}

func (f *fakeUnitOfWork) Do(ctx context.Context, fn func(context.Context, db.Querier) error) error {
	f.ran++
	if f.failWith != nil {
		return f.failWith
	}
	return fn(ctx, f.querier)
}

type fakeAccessRevoker struct {
	sweeps []accessSweepCall
	err error
}

type accessSweepCall struct {
	userID  id.UUID
	at      time.Time
	querier db.Querier
}

func (f *fakeAccessRevoker) RevokeAccessTokensForUser(_ context.Context, q db.Querier, userID id.UUID, at time.Time) error {
	f.sweeps = append(f.sweeps, accessSweepCall{userID: userID, at: at, querier: q})
	if f.err != nil {
		return f.err
	}
	return nil
}

type fixture struct {
	svc      *Service
	users    *fakeUsers
	sessions *fakeSessions
	events   *fakeEvents
	tenancy  *fakeTenancy
	mfa      *fakeSecondFactor
	access   *fakeAccessRevoker
	audit    *fakeAuditRecorder
	uow      *fakeUnitOfWork
	reader   *fakeReader
	clock    *clock.Fake
}

type markerQuerier struct{ name string }

func (m markerQuerier) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func (m markerQuerier) QueryRow(context.Context, string, ...any) pgx.Row { return nil }

func (m markerQuerier) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("markerQuerier returns no rows")
}

type fakeReader struct{ q db.Querier }

func (r *fakeReader) Queryer() db.Querier { return r.q }

func newFixture() *fixture {
	f := &fixture{
		users:    newFakeUsers(),
		sessions: newFakeSessions(),
		events:   &fakeEvents{},
		tenancy:  &fakeTenancy{},
		clock:    clock.NewFake(start),
	}
	f.reader = &fakeReader{q: markerQuerier{name: "reader"}}
	f.uow = &fakeUnitOfWork{querier: markerQuerier{name: "transaction"}}

	f.mfa = newFakeSecondFactor()
	f.access = &fakeAccessRevoker{}
	f.audit = &fakeAuditRecorder{}
	f.svc = NewService(
		f.uow,
		f.reader,
		f.users,
		f.sessions,
		f.events,
		f.tenancy,
		f.mfa,
		f.access,
		f.audit,
		users.NewHasherWithParams(&argon2id.Params{
			Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
		}),
		f.clock,
		24*time.Hour,
		false,
	)
	return f
}

func newFixtureWithoutAccessRevoker() *fixture {
	f := newFixture()
	f.access = nil
	f.svc = NewService(
		f.uow,
		f.reader,
		f.users,
		f.sessions,
		f.events,
		f.tenancy,
		f.mfa,
		nil,
		f.audit,
		users.NewHasherWithParams(&argon2id.Params{
			Memory: 8 << 10, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
		}),
		f.clock,
		24*time.Hour,
		false,
	)
	return f
}

func newFixtureWithoutAuditRecorder() *fixture {
	f := newFixture()
	f.svc = NewService(
		f.uow,
		f.reader,
		f.users,
		f.sessions,
		f.events,
		f.tenancy,
		f.mfa,
		f.access,
		nil,
		users.NewHasherWithParams(&argon2id.Params{
			Memory: 8 << 10, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
		}),
		f.clock,
		24*time.Hour,
		false,
	)
	return f
}

func (f *fixture) seedSession(userID id.UUID) {
	f.sessions.nextID++
	var raw id.UUID
	raw[15] = byte(f.sessions.nextID)
	sid := raw
	digest := "digest-" + sid.String()
	f.sessions.live[digest] = sid
	f.sessions.owners[sid] = userID
}

func (f *fixture) register(t *testing.T, email, password string) users.User {
	t.Helper()

	u, err := f.users.Create(context.Background(), f.uow.querier, users.CreateParams{
		Email:          email,
		PasswordDigest: mustHash(t, password),
	})
	if err != nil {
		t.Fatalf("seeding a user: %v", err)
	}
	return u
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func ptr(t time.Time) *time.Time { return &t }

func ptrStr(s string) *string { return &s }

func (f *fixture) disable(t *testing.T, userID id.UUID) {
	t.Helper()
	if err := f.svc.Disable(context.Background(), disableFor(userID, f.clock.Now())); err != nil {
		t.Fatalf("Disable: %v", err)
	}
}

func (f *fixture) enable(t *testing.T, userID id.UUID) {
	t.Helper()
	if err := f.svc.Enable(context.Background(), enableFor(userID, f.clock.Now())); err != nil {
		t.Fatalf("Enable: %v", err)
	}
}

func mustHash(t *testing.T, password string) string {
	t.Helper()

	digest, err := users.NewHasherWithParams(&argon2id.Params{
		Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	}).Hash(password)
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}
	return digest
}


func TestRegisterCreatesTheUserAndTheEventInOneTransaction(t *testing.T) {
	t.Parallel()

	f := newFixture()

	got, err := f.svc.Register(context.Background(), RegisterInput{
		Email:    "Kaka@Example.com",
		Password: "correct horse battery staple",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if got.Email != "kaka@example.com" {
		t.Errorf("Email = %q, want the normalized kaka@example.com", got.Email)
	}
	if f.users.byEmail["kaka@example.com"].PasswordDigest == "" || f.users.byEmail["kaka@example.com"].PasswordDigest == "correct horse battery staple" {
		t.Errorf("PasswordDigest = %q, want an argon2id digest", f.users.byEmail["kaka@example.com"].PasswordDigest)
	}
	if strings.Contains(f.users.byEmail["kaka@example.com"].PasswordDigest, "correct horse") {
		t.Error("the digest contains the plaintext password")
	}

	if len(f.events.appended) != 1 {
		t.Fatalf("%d events were written, want exactly 1", len(f.events.appended))
	}
	e := f.events.appended[0]
	if err := e.Validate(); err != nil {
		t.Errorf("the event does not satisfy core's schema: %v", err)
	}
	if e.Type != outbox.EventUserCreated {
		t.Errorf("event type = %q, want %q", e.Type, outbox.EventUserCreated)
	}
	if e.Source != outbox.SourceIdentity {
		t.Errorf("event source = %q, want %q", e.Source, outbox.SourceIdentity)
	}
	if e.Subject != got.ID.String() {
		t.Errorf("event subject = %q, want the user id %q", e.Subject, got.ID)
	}
	if strings.Contains(string(e.Data), f.users.byEmail["kaka@example.com"].PasswordDigest) {
		t.Error("the event payload contains the password digest")
	}
	if !strings.Contains(string(e.Data), `"email":"kaka@example.com"`) {
		t.Errorf("event payload = %s, want it to carry the email", e.Data)
	}

	if f.uow.ran != 1 {
		t.Errorf("the unit of work ran %d times, want 1", f.uow.ran)
	}
	if len(f.events.queriersUsed) != 1 {
		t.Fatalf("Append was called %d times, want 1", len(f.events.queriersUsed))
	}
	if f.events.queriersUsed[0] != f.uow.querier {
		t.Error("the event was appended outside the registration transaction")
	}
}

func TestRegisterValidatesBeforeTouchingTheDatabase(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		give     RegisterInput
		wantCode string
	}{
		{
			name:     "a short password",
			give:     RegisterInput{Email: "kaka@example.com", Password: "1234567"},
			wantCode: "too_short",
		},
		{
			name:     "an empty password",
			give:     RegisterInput{Email: "kaka@example.com", Password: ""},
			wantCode: "required",
		},
		{
			name:     "a malformed address",
			give:     RegisterInput{Email: "not an address", Password: "correct horse battery"},
			wantCode: "invalid_format",
		},
		{
			name:     "an empty address",
			give:     RegisterInput{Email: "", Password: "correct horse battery"},
			wantCode: "required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture()

			_, err := f.svc.Register(context.Background(), tt.give)
			assertFieldError(t, err, tt.wantCode)

			if f.uow.ran != 0 {
				t.Error("a transaction was opened for an invalid registration")
			}
			if f.users.creates != 0 {
				t.Error("a user row was written for an invalid registration")
			}
			if len(f.events.appended) != 0 {
				t.Error("an event was written for an invalid registration")
			}
		})
	}
}

func TestRegisterPropagatesAnAppendFailure(t *testing.T) {
	t.Parallel()

	f := newFixture()
	f.events.appendErr = errors.New("outbox insert failed")

	_, err := f.svc.Register(context.Background(), RegisterInput{
		Email:    "kaka@example.com",
		Password: "correct horse battery",
	})
	if err == nil {
		t.Fatal("Register succeeded even though the event could not be written")
	}
}

func TestRegisterRejectsATakenAddress(t *testing.T) {
	t.Parallel()

	f := newFixture()
	f.register(t, "kaka@example.com", "correct horse battery")

	_, err := f.svc.Register(context.Background(), RegisterInput{
		Email:    "KAKA@example.com",
		Password: "another good passphrase",
	})
	if !errors.Is(err, users.ErrEmailTaken) {
		t.Errorf("Register = %v, want errors.Is(_, users.ErrEmailTaken)", err)
	}
	if len(f.events.appended) != 0 {
		t.Error("an event was written for a rejected registration")
	}
}

func TestRegisterMintsAFreshEventIDEachTime(t *testing.T) {
	t.Parallel()

	f := newFixture()

	first, err := f.svc.Register(context.Background(), RegisterInput{Email: "a@example.com", Password: "correct horse battery"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	second, err := f.svc.Register(context.Background(), RegisterInput{Email: "b@example.com", Password: "correct horse battery"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if first.ID == second.ID {
		t.Error("two registrations produced the same user id")
	}
	if f.events.appended[0].ID == f.events.appended[1].ID {
		t.Error("two registrations produced the same envelope id")
	}
}

func TestRegisterUsesTheInjectedClock(t *testing.T) {
	t.Parallel()

	f := newFixture()
	later := start.Add(72 * time.Hour)
	f.clock.Set(later)

	if _, err := f.svc.Register(context.Background(), RegisterInput{Email: "kaka@example.com", Password: "correct horse battery"}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if got := f.events.appended[0].Time; !got.Equal(later) {
		t.Errorf("event time = %s, want the injected clock's %s", got, later)
	}
}


func TestLoginSucceedsAndMintsASession(t *testing.T) {
	t.Parallel()

	f := newFixture()
	f.register(t, "kaka@example.com", "correct horse battery staple")

	got, err := f.svc.Login(context.Background(), LoginInput{
		Email:     "KAKA@Example.com",
		Password:  "correct horse battery staple",
		UserAgent: "Mozilla/5.0",
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	if got.User.Email != "kaka@example.com" {
		t.Errorf("Email = %q, want kaka@example.com", got.User.Email)
	}
	if got.Token == "" {
		t.Fatal("Login returned no token; the API client surface would be broken")
	}
	if want := start.Add(24 * time.Hour); !got.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %s, want %s — the TTL comes from the configuration", got.ExpiresAt, want)
	}

	if len(f.sessions.minted) != 1 {
		t.Fatalf("%d sessions were minted, want 1", len(f.sessions.minted))
	}
	minted := f.sessions.minted[0]
	if minted.TokenDigest == got.Token {
		t.Error("the stored digest equals the token returned to the client")
	}
	if minted.TokenDigest != sessions.Digest(got.Token) {
		t.Error("the stored digest is not Digest(token)")
	}
	if minted.UserAgent != "Mozilla/5.0" {
		t.Errorf("UserAgent = %q, want the one from the request", minted.UserAgent)
	}
	if minted.UserID != got.User.ID {
		t.Errorf("the session belongs to %s, want %s", minted.UserID, got.User.ID)
	}
}

func TestLoginDoesNotDistinguishAWrongPasswordFromAnUnknownAddress(t *testing.T) {
	t.Parallel()

	f := newFixture()
	f.register(t, "kaka@example.com", "correct horse battery staple")

	wrongPassword, wrongPasswordErr := f.svc.Login(context.Background(), LoginInput{
		Email: "kaka@example.com", Password: "not the right password",
	})
	unknownEmail, unknownEmailErr := f.svc.Login(context.Background(), LoginInput{
		Email: "nobody@example.com", Password: "not the right password",
	})

	if !errors.Is(wrongPasswordErr, ErrInvalidCredentials) {
		t.Errorf("a wrong password gave %v, want ErrInvalidCredentials", wrongPasswordErr)
	}
	if !errors.Is(unknownEmailErr, ErrInvalidCredentials) {
		t.Errorf("an unknown address gave %v, want ErrInvalidCredentials", unknownEmailErr)
	}
	if wrongPasswordErr.Error() != unknownEmailErr.Error() {
		t.Errorf("the two errors differ in text: %q vs %q. The message is rendered to an anonymous caller.",
			wrongPasswordErr, unknownEmailErr)
	}
	if wrongPassword.Token != "" || unknownEmail.Token != "" {
		t.Error("a failed login returned a session token")
	}
	if !wrongPassword.ExpiresAt.IsZero() || !unknownEmail.ExpiresAt.IsZero() {
		t.Error("a failed login returned an expiry")
	}
	if !wrongPassword.User.ID.IsZero() || !unknownEmail.User.ID.IsZero() {
		t.Error("a failed login returned a user")
	}
}

func TestLoginAgainstAnUnknownAddressWritesNoState(t *testing.T) {
	t.Parallel()

	f := newFixture()

	if _, err := f.svc.Login(context.Background(), LoginInput{Email: "nobody@example.com", Password: "correct horse battery"}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login = %v, want ErrInvalidCredentials", err)
	}

	if f.users.cleared != 0 {
		t.Error("a failed login against an unknown address cleared failures")
	}
	if len(f.sessions.minted) != 0 {
		t.Error("a failed login minted a session")
	}
	if f.uow.ran != 0 {
		t.Error("a failed login against an unknown address opened a transaction")
	}
}

func TestLoginLockoutMatrix(t *testing.T) {
	t.Parallel()

	const password = "correct horse battery staple"

	t.Run("five failures then locked", func(t *testing.T) {
		t.Parallel()

		f := newFixture()
		f.register(t, "kaka@example.com", password)

		for attempt := 1; attempt <= sessions.MaxFailedAttempts-1; attempt++ {
			_, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "wrong"})
			if !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("attempt %d = %v, want ErrInvalidCredentials", attempt, err)
			}
			u, _ := f.users.ByEmail(context.Background(), f.uow.querier, "kaka@example.com")
			if u.FailedLoginAttempts != attempt {
				t.Errorf("after attempt %d the counter is %d, want %d", attempt, u.FailedLoginAttempts, attempt)
			}
			if u.IsLocked(f.clock.Now()) {
				t.Fatalf("locked after only %d failures", attempt)
			}
		}

		_, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "wrong"})
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("the fifth attempt = %v, want ErrInvalidCredentials", err)
		}

		u, _ := f.users.ByEmail(context.Background(), f.uow.querier, "kaka@example.com")
		if !u.IsLocked(f.clock.Now()) {
			t.Fatal("not locked after five consecutive failures")
		}

		_, err = f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: password})
		var locked *LockedError
		if !errors.As(err, &locked) {
			t.Fatalf("the sixth attempt = %v, want a *LockedError", err)
		}
		if want := sessions.LockoutDuration; locked.RetryAfter != want {
			t.Errorf("RetryAfter = %s, want %s", locked.RetryAfter, want)
		}
		if len(f.sessions.minted) != 0 {
			t.Error("a locked account was given a session")
		}
	})

	t.Run("the lock lifts when the window closes", func(t *testing.T) {
		t.Parallel()

		f := newFixture()
		f.register(t, "kaka@example.com", password)

		for range sessions.MaxFailedAttempts {
			if _, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "wrong"}); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("Login = %v, want ErrInvalidCredentials", err)
			}
		}

		f.clock.Set(start.Add(sessions.LockoutDuration - time.Nanosecond))
		var locked *LockedError
		if _, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: password}); !errors.As(err, &locked) {
			t.Fatalf("just before expiry = %v, want a *LockedError", err)
		}
		if got := locked.RetryAfter; got != time.Nanosecond {
			t.Errorf("RetryAfter = %s, want 1ns", got)
		}

		f.clock.Set(start.Add(sessions.LockoutDuration))
		got, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: password})
		if err != nil {
			t.Fatalf("Login after the window closed = %v, want success", err)
		}
		if got.Token == "" {
			t.Error("Login after the window closed returned no token")
		}
	})

	t.Run("a success resets the run", func(t *testing.T) {
		t.Parallel()

		f := newFixture()
		f.register(t, "kaka@example.com", password)

		for range sessions.MaxFailedAttempts - 1 {
			if _, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "wrong"}); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("Login = %v, want ErrInvalidCredentials", err)
			}
		}
		if _, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: password}); err != nil {
			t.Fatalf("the interleaved success failed: %v", err)
		}

		u, _ := f.users.ByEmail(context.Background(), f.uow.querier, "kaka@example.com")
		if u.FailedLoginAttempts != 0 {
			t.Errorf("FailedAttempts after a success = %d, want 0", u.FailedLoginAttempts)
		}
		if u.IsLocked(f.clock.Now()) {
			t.Error("locked despite a successful login")
		}

		for range sessions.MaxFailedAttempts - 1 {
			if _, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "wrong"}); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("Login = %v, want ErrInvalidCredentials", err)
			}
		}
		u, _ = f.users.ByEmail(context.Background(), f.uow.querier, "kaka@example.com")
		if u.IsLocked(f.clock.Now()) {
			t.Error("locked after 4 post-success failures")
		}
	})

	t.Run("failures are per account", func(t *testing.T) {
		t.Parallel()

		f := newFixture()
		f.register(t, "victim@example.com", password)
		f.register(t, "bystander@example.com", password)

		for range sessions.MaxFailedAttempts {
			if _, err := f.svc.Login(context.Background(), LoginInput{Email: "victim@example.com", Password: "wrong"}); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("Login = %v, want ErrInvalidCredentials", err)
			}
		}

		if _, err := f.svc.Login(context.Background(), LoginInput{Email: "bystander@example.com", Password: password}); err != nil {
			t.Errorf("an unrelated account was locked too: %v", err)
		}
	})
}

func TestLoginChecksTheLockBeforeThePassword(t *testing.T) {
	t.Parallel()

	f := newFixture()
	f.register(t, "kaka@example.com", "correct horse battery staple")
	for range sessions.MaxFailedAttempts {
		if _, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "wrong"}); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("Login = %v, want ErrInvalidCredentials", err)
		}
	}

	before := len(f.sessions.minted)
	if _, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "wrong"}); err == nil {
		t.Fatal("a locked account accepted a login attempt")
	}
	if len(f.sessions.minted) != before {
		t.Error("a locked attempt minted a session")
	}

	u, _ := f.users.ByEmail(context.Background(), f.uow.querier, "kaka@example.com")
	var locked *LockedError
	_, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "wrong"})
	if !errors.As(err, &locked) {
		t.Fatalf("Login = %v, want a *LockedError", err)
	}
	if got := locked.RetryAfter; got != sessions.LockoutDuration {
		t.Errorf("RetryAfter = %s, want the original %s; a rejected attempt extended the lock", got, sessions.LockoutDuration)
	}
	_ = u
}

func TestLoginMintsTheSessionAndClearsFailuresTogether(t *testing.T) {
	t.Parallel()

	f := newFixture()
	f.register(t, "kaka@example.com", "correct horse battery staple")
	if _, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "wrong"}); err == nil {
		t.Fatal("the seeded failure did not fail")
	}

	f.sessions.createErr = errors.New("insert into sessions failed")

	_, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "correct horse battery staple"})
	if err == nil {
		t.Fatal("Login succeeded even though the session could not be written")
	}
	if f.uow.ran != 1 {
		t.Errorf("the unit of work ran %d times, want 1 — only the successful attempt", f.uow.ran)
	}
	if f.users.cleared != 0 {
		t.Error("the failure run was cleared even though no session was minted")
	}
}

func TestLoginReportsAFailureToRecordTheAttempt(t *testing.T) {
	t.Parallel()

	f := newFixture()
	f.register(t, "kaka@example.com", "correct horse battery staple")
	f.users.recordErr = errors.New("update users failed")

	_, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "wrong"})
	if !errors.Is(err, f.users.recordErr) {
		t.Errorf("Login = %v, want the store error to surface", err)
	}
	if errors.Is(err, ErrInvalidCredentials) {
		t.Error("a store failure was reported as invalid credentials; the lockout would stop counting")
	}
}

func TestLoginValidatesTheInputShape(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		give     LoginInput
		wantCode string
	}{
		{name: "an empty address", give: LoginInput{Email: "", Password: "whatever"}, wantCode: "required"},
		{name: "a malformed address", give: LoginInput{Email: "not an address", Password: "whatever"}, wantCode: "invalid_format"},
		{name: "an empty password", give: LoginInput{Email: "kaka@example.com", Password: ""}, wantCode: "required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture()

			_, err := f.svc.Login(context.Background(), tt.give)
			assertFieldError(t, err, tt.wantCode)

			if f.uow.ran != 0 {
				t.Error("a transaction was opened for a malformed login")
			}
		})
	}
}

func TestLoginRejectsAnOverLongPassword(t *testing.T) {
	t.Parallel()

	f := newFixture()
	f.register(t, "kaka@example.com", "correct horse battery staple")

	_, err := f.svc.Login(context.Background(), LoginInput{
		Email:    "kaka@example.com",
		Password: strings.Repeat("a", users.MaxPasswordLength+1),
	})
	assertFieldError(t, err, "too_long")
}

func TestLoginRecordsTheRequestAddress(t *testing.T) {
	t.Parallel()

	f := newFixture()
	f.register(t, "kaka@example.com", "correct horse battery staple")
	ip := mustAddr("203.0.113.7")

	if _, err := f.svc.Login(context.Background(), LoginInput{
		Email: "kaka@example.com", Password: "correct horse battery staple", IP: &ip,
	}); err != nil {
		t.Fatalf("Login: %v", err)
	}

	minted := f.sessions.minted[0]
	if minted.IP == nil || minted.IP.String() != "203.0.113.7" {
		t.Errorf("IP = %v, want 203.0.113.7 recorded for the incident trail", minted.IP)
	}
}


func TestAuthenticateResolvesATokenToItsUser(t *testing.T) {
	t.Parallel()

	f := newFixture()
	f.register(t, "kaka@example.com", "correct horse battery staple")

	login, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	got, err := f.svc.Authenticate(context.Background(), login.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got.ID != login.User.ID {
		t.Errorf("Authenticate returned user %s, want %s", got.ID, login.User.ID)
	}
	if got.Email != "kaka@example.com" {
		t.Errorf("Email = %q, want kaka@example.com", got.Email)
	}
}

func TestAuthenticateRejectsUnusableTokens(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		token string
	}{
		{name: "empty", token: ""},
		{name: "not a token", token: "nonsense"},
		{name: "a well-formed token that was never issued", token: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{name: "a revoked token", token: "revoked"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture()
			if _, err := f.svc.Authenticate(context.Background(), tt.token); !errors.Is(err, ErrUnauthenticated) {
				t.Errorf("Authenticate(%q) = %v, want ErrUnauthenticated", tt.name, err)
			}
		})
	}
}

func TestAuthenticateUsesTheInjectedClock(t *testing.T) {
	t.Parallel()

	f := newFixture()
	f.register(t, "kaka@example.com", "correct horse battery staple")
	login, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	f.clock.Now()
	if _, err := f.svc.Authenticate(context.Background(), login.Token); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if len(f.sessions.nowSeen) == 0 {
		t.Fatal("the session lookup never happened")
	}
	if got := f.sessions.nowSeen[len(f.sessions.nowSeen)-1]; !got.Equal(f.clock.Now()) {
		t.Errorf("the lookup was given %s, want the injected clock's %s", got, f.clock.Now())
	}
}

func TestUpdateDisplayNameIsVisibleToTheNextAuthenticate(t *testing.T) {
	t.Parallel()

	f := newFixture()
	f.register(t, "kaka@example.com", "correct horse battery staple")
	login, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	readName := func() *string {
		t.Helper()
		got, err := f.svc.Authenticate(context.Background(), login.Token)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		return got.DisplayName
	}

	if got := readName(); got != nil {
		t.Errorf("DisplayName before any write = %q, want nil", *got)
	}

	if err := f.svc.UpdateDisplayName(context.Background(), login.User.ID, ptrStr("Kaka")); err != nil {
		t.Fatalf("UpdateDisplayName: %v", err)
	}
	if got := readName(); got == nil || *got != "Kaka" {
		t.Errorf("DisplayName after the write = %v, want Kaka", got)
	}

	if err := f.svc.UpdateDisplayName(context.Background(), login.User.ID, nil); err != nil {
		t.Fatalf("UpdateDisplayName clear: %v", err)
	}
	if got := readName(); got != nil {
		t.Errorf("DisplayName after clearing = %q, want nil", *got)
	}
}

func TestUpdateDisplayNameOnAMissingUserIsRefused(t *testing.T) {
	t.Parallel()

	f := newFixture()
	if err := f.svc.UpdateDisplayName(context.Background(), id.MustNew(), ptrStr("Kaka")); !errors.Is(err, users.ErrNotFound) {
		t.Errorf("UpdateDisplayName on a missing user = %v, want errors.Is(_, users.ErrNotFound)", err)
	}
}

func TestLogoutRevokesTheSession(t *testing.T) {
	t.Parallel()

	f := newFixture()
	f.register(t, "kaka@example.com", "correct horse battery staple")
	login, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := f.svc.Authenticate(context.Background(), login.Token); err != nil {
		t.Fatalf("the token did not authenticate before logout: %v", err)
	}

	if err := f.svc.Logout(context.Background(), login.Token); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	if _, err := f.svc.Authenticate(context.Background(), login.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("the token still authenticates after Logout: %v", err)
	}
}

func TestLogoutIsIdempotent(t *testing.T) {
	t.Parallel()

	f := newFixture()

	if err := f.svc.Logout(context.Background(), "never-issued"); err != nil {
		t.Errorf("Logout of an unknown token = %v, want nil", err)
	}
}

func TestLogoutLeavesOtherSessionsAlone(t *testing.T) {
	t.Parallel()

	f := newFixture()
	f.register(t, "kaka@example.com", "correct horse battery staple")

	first, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatalf("first Login: %v", err)
	}
	second, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatalf("second Login: %v", err)
	}

	if err := f.svc.Logout(context.Background(), first.Token); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	if _, err := f.svc.Authenticate(context.Background(), first.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Error("the logged-out token still authenticates")
	}
	if _, err := f.svc.Authenticate(context.Background(), second.Token); err != nil {
		t.Errorf("an unrelated session was revoked too: %v", err)
	}
}

func TestListSessionsAsksAboutTheCallerAndNobodyElse(t *testing.T) {
	t.Parallel()

	f := newFixture()
	user := f.register(t, "kaka@example.com", "correct horse battery staple")

	login, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	if _, err := f.svc.ListSessions(context.Background(), login.Token); err != nil {
		t.Fatalf("ListSessions: %v", err)
	}

	if len(f.sessions.listedFor) != 1 {
		t.Fatalf("the store was asked %d times, want once", len(f.sessions.listedFor))
	}
	if f.sessions.listedFor[0] != user.ID {
		t.Errorf("the listing asked about user %s, want the credential's own user %s. "+
			"The user id comes from the session the token resolved to, never from the caller.",
			f.sessions.listedFor[0], user.ID)
	}
}

func TestListSessionsMarksExactlyTheCurrentSession(t *testing.T) {
	t.Parallel()

	f := newFixture()
	f.register(t, "kaka@example.com", "correct horse battery staple")

	_, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatalf("first Login: %v", err)
	}
	second, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatalf("second Login: %v", err)
	}

	list, err := f.svc.ListSessions(context.Background(), second.Token)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("ListSessions returned %d entries, want 2", len(list))
	}

	var secondID id.UUID
	for digest, sid := range f.sessions.live {
		if digest == sessions.Digest(second.Token) {
			secondID = sid
		}
	}

	current := 0
	for _, s := range list {
		if !s.Current {
			continue
		}
		current++
		if s.ID != secondID {
			t.Errorf("session %s is marked Current but the request arrived on %s", s.ID, secondID)
		}
	}
	if current != 1 {
		t.Errorf("%d entries are marked Current, want exactly 1", current)
	}
}

func TestListSessionsRefusesAnUnusableToken(t *testing.T) {
	t.Parallel()

	for _, token := range []string{"", "never-issued"} {
		f := newFixture()
		if _, err := f.svc.ListSessions(context.Background(), token); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("ListSessions(%q) = %v, want ErrUnauthenticated", token, err)
		}
	}
}

func TestListSessionsReportsAStoreFailure(t *testing.T) {
	t.Parallel()

	f := newFixture()
	f.register(t, "kaka@example.com", "correct horse battery staple")
	login, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	boom := errors.New("the database is down")
	f.sessions.listErr = boom
	if _, err := f.svc.ListSessions(context.Background(), login.Token); !errors.Is(err, boom) {
		t.Errorf("ListSessions = %v, want the store's error. A blip reported as 'no sessions' "+
			"signs a user out of every device in their UI at once.", err)
	}
}

func TestRevokeSessionCarriesTheCallersUserId(t *testing.T) {
	t.Parallel()

	f := newFixture()
	user := f.register(t, "kaka@example.com", "correct horse battery staple")

	first, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatalf("first Login: %v", err)
	}
	second, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatalf("second Login: %v", err)
	}

	var secondID id.UUID
	for digest, sid := range f.sessions.live {
		if digest == sessions.Digest(second.Token) {
			secondID = sid
		}
	}

	if err := f.svc.RevokeSession(context.Background(), first.Token, secondID); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}

	if len(f.sessions.revokedOne) != 1 {
		t.Fatalf("the store was asked %d times, want once", len(f.sessions.revokedOne))
	}
	call := f.sessions.revokedOne[0]
	if call.userID != user.ID {
		t.Errorf("RevokeOneForUser was given user %s, want the caller's %s", call.userID, user.ID)
	}
	if call.sessionID != secondID {
		t.Errorf("RevokeOneForUser was given session %s, want the id from the request %s", call.sessionID, secondID)
	}

	if _, err := f.svc.Authenticate(context.Background(), second.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Error("the revoked session still authenticates")
	}
	if _, err := f.svc.Authenticate(context.Background(), first.Token); err != nil {
		t.Errorf("the caller's own session was revoked by a request that named another: %v", err)
	}
}

func TestRevokingTheCurrentSessionIsAllowedAndSignsYouOut(t *testing.T) {
	t.Parallel()

	f := newFixture()
	f.register(t, "kaka@example.com", "correct horse battery staple")

	login, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	other, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatalf("second Login: %v", err)
	}

	var ownID id.UUID
	for digest, sid := range f.sessions.live {
		if digest == sessions.Digest(login.Token) {
			ownID = sid
		}
	}

	if err := f.svc.RevokeSession(context.Background(), login.Token, ownID); err != nil {
		t.Fatalf("revoking the caller's own current session = %v, want nil", err)
	}

	if _, err := f.svc.Authenticate(context.Background(), login.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Error("the revoked current session still authenticates")
	}
	if _, err := f.svc.Authenticate(context.Background(), other.Token); err != nil {
		t.Errorf("the other session was revoked too: %v", err)
	}
}

func TestRevokeSessionReportsOneErrorForEveryWayOfBeingWrong(t *testing.T) {
	t.Parallel()

	f := newFixture()
	f.register(t, "kaka@example.com", "correct horse battery staple")

	login, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	keep, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatalf("second Login: %v", err)
	}
	keepToken := keep.Token

	var ownID, liveID id.UUID
	for digest, sid := range f.sessions.live {
		switch digest {
		case sessions.Digest(login.Token):
			ownID = sid
		case sessions.Digest(keepToken):
			liveID = sid
		}
	}

	if err := f.svc.RevokeSession(context.Background(), login.Token, ownID); err != nil {
		t.Fatalf("the first revoke: %v", err)
	}

	tests := []struct {
		name      string
		token     string
		sessionID id.UUID
		want      error
	}{
		{name: "no credential at all", token: "", sessionID: liveID, want: ErrUnauthenticated},
		{name: "a token that resolves to nothing", token: "never-issued", sessionID: liveID, want: ErrUnauthenticated},
		{name: "a session that does not exist", token: keepToken, sessionID: id.MustNew(), want: ErrSessionNotFound},
		{name: "one already revoked", token: keepToken, sessionID: ownID, want: ErrSessionNotFound},
		{name: "the nil uuid", token: keepToken, sessionID: id.UUID{}, want: ErrSessionNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := f.svc.RevokeSession(context.Background(), tt.token, tt.sessionID); !errors.Is(err, tt.want) {
				t.Errorf("RevokeSession = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestUserResultsCarryNoDigest(t *testing.T) {
	t.Parallel()

	f := newFixture()
	user := f.register(t, "kaka@example.com", "correct horse battery staple")

	login, err := f.svc.Login(context.Background(), LoginInput{Email: "kaka@example.com", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	authed, err := f.svc.Authenticate(context.Background(), login.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	projections := map[string]any{
		"register":     RegisteredUser{ID: user.ID, Email: user.Email},
		"login":        login.User,
		"authenticate": RegisteredUser{ID: authed.ID, Email: authed.Email},
	}
	for name, projection := range projections {
		encoded, err := json.Marshal(projection)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, secret := range []string{"$argon2id$", "password_digest", "digest"} {
			if strings.Contains(string(encoded), secret) {
				t.Errorf("%s result renders %q: %s", name, secret, encoded)
			}
		}
	}
}

func assertFieldError(t *testing.T, err error, wantCode string) {
	t.Helper()

	if err == nil {
		t.Fatalf("got nil error, want code %q", wantCode)
	}
	var fe *users.FieldError
	if !errors.As(err, &fe) {
		t.Fatalf("error = %v (%T), want a *users.FieldError", err, err)
	}
	if fe.Code != wantCode {
		t.Errorf("code = %q, want %q", fe.Code, wantCode)
	}
}
