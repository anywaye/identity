package recovery

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/anywaye/identity/internal/outbox"
	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/sessions"
	"github.com/anywaye/identity/internal/users"
)


type harness struct {
	t      *testing.T
	svc    *Service
	pool   *pgxpool.Pool
	clk    *clock.Fake
	mailer *recordingMailer
	access *recordingAccessRevoker
	users  *users.Store
	secondFactor *stubSecondFactor
	token string
}

type recordingMailer struct {
	mu       sync.Mutex
	sent     []Message
	readyErr error
	sendErr  error
}

func (m *recordingMailer) Ready(context.Context) error { return m.readyErr }

func (m *recordingMailer) Send(_ context.Context, msg Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sendErr != nil {
		return m.sendErr
	}
	m.sent = append(m.sent, msg)
	return nil
}

func (m *recordingMailer) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

func (m *recordingMailer) last(t *testing.T) Message {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sent) == 0 {
		t.Fatal("no message was delivered; the flow under test never reached the seam")
	}
	return m.sent[len(m.sent)-1]
}

type recordingAccessRevoker struct {
	mu      sync.Mutex
	revoked map[id.UUID]time.Time
}

func newRecordingAccessRevoker() *recordingAccessRevoker {
	return &recordingAccessRevoker{revoked: map[id.UUID]time.Time{}}
}

func (r *recordingAccessRevoker) RevokeAccessTokensForUser(_ context.Context, _ db.Querier, userID id.UUID, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked[userID] = at
	return nil
}

func (r *recordingAccessRevoker) swept(userID id.UUID) (time.Time, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	at, ok := r.revoked[userID]
	return at, ok
}

type stubSecondFactor struct {
	enrolled bool
	err      error
}

func (s *stubSecondFactor) Enabled(context.Context, db.Querier, id.UUID) (bool, error) {
	return s.enrolled, s.err
}

func newHarness(t *testing.T, schema bool) *harness {
	t.Helper()

	pool := dbtest.Pool(t)
	if schema {
		pool = dbtest.Schema(t)
	}

	clk := clock.NewFake(issuedAt())
	mailer := &recordingMailer{}
	access := newRecordingAccessRevoker()
	userStore := users.NewStore(pool)

	secondFactor := &stubSecondFactor{}

	return &harness{
		t:            t,
		pool:         pool,
		clk:          clk,
		mailer:       mailer,
		access:       access,
		users:        userStore,
		secondFactor: secondFactor,
		svc: NewService(
			db.TxRunner{Pool: pool},
			db.Direct{Pool: pool},
			NewStore(pool),
			userStore,
			sessions.NewStore(pool),
			access,
			outbox.NewStore(pool),
			mailer,
			testHasher(),
			clk,
			secondFactor,
		),
	}
}

func issuedAt() time.Time {
	return time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
}

func testHasher() *users.Hasher {
	params := users.DefaultParams()
	params.Memory = 8 * 1024
	params.Iterations = 1
	params.Parallelism = 1
	return users.NewHasherWithParams(params)
}

type account struct {
	id    id.UUID
	email string
}

func (h *harness) register(email, password string) account {
	h.t.Helper()

	digest, err := testHasher().Hash(password)
	if err != nil {
		h.t.Fatalf("hashing: %v", err)
	}

	var user users.User
	err = db.TxRunner{Pool: h.pool}.Do(h.t.Context(), func(ctx context.Context, q db.Querier) error {
		created, err := h.users.Create(ctx, q, users.CreateParams{Email: email, PasswordDigest: digest})
		if err != nil {
			return err
		}
		user = created
		token, tokenDigest, err := sessions.NewToken()
		if err != nil {
			return err
		}
		_, err = sessions.NewStore(h.pool).Create(ctx, q, sessions.NewSession{
			UserID:      created.ID,
			TokenDigest: tokenDigest,
			ExpiresAt:   h.now().Add(24 * time.Hour),
		})
		if err != nil {
			return err
		}
		h.token = token
		return nil
	})
	if err != nil {
		h.t.Fatalf("registering %s: %v", email, err)
	}

	return account{id: user.ID, email: user.Email}
}

func (h *harness) registerSimple() account {
	h.t.Helper()
	return h.register(dbtest.UniqueEmail(h.t), "correct horse battery staple")
}

func (h *harness) now() time.Time { return h.clk.Now() }

func (h *harness) sessionsFor(userID id.UUID) int {
	h.t.Helper()
	var n int
	err := h.pool.QueryRow(h.t.Context(),
		`SELECT count(*) FROM sessions WHERE user_id = $1`, userID).Scan(&n)
	if err != nil {
		h.t.Fatalf("counting sessions: %v", err)
	}
	return n
}

func tokenFrom(t *testing.T, m Message) string {
	t.Helper()
	for _, line := range strings.Split(m.Body, "\n") {
		candidate := strings.TrimSpace(line)
		if len(candidate) == 43 && !strings.ContainsAny(candidate, " \t") && isBase64URL(candidate) {
			return candidate
		}
	}
	t.Fatalf("no token in the delivered body:\n%s", m.Body)
	return ""
}

func isBase64URL(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

func (h *harness) tokenRowCount(userID id.UUID, purpose Purpose) int {
	h.t.Helper()
	var n int
	err := h.pool.QueryRow(h.t.Context(),
		`SELECT count(*) FROM recovery_tokens WHERE user_id = $1 AND purpose = $2`,
		userID, purpose).Scan(&n)
	if err != nil {
		h.t.Fatalf("counting %s tokens: %v", purpose, err)
	}
	return n
}

func (h *harness) storedTokenRow(tokenID id.UUID) map[string]any {
	h.t.Helper()
	rows, err := h.pool.Query(h.t.Context(),
		`SELECT * FROM recovery_tokens WHERE id = $1`, tokenID)
	if err != nil {
		h.t.Fatalf("reading the token row: %v", err)
	}
	defer rows.Close()

	fields := rows.FieldDescriptions()
	out := map[string]any{}
	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			h.t.Fatalf("reading the token row: %v", err)
		}
		for i, f := range fields {
			out[f.Name] = values[i]
		}
	}
	if len(out) == 0 {
		h.t.Fatalf("no recovery_tokens row with id %s", tokenID)
	}
	return out
}

func (h *harness) hasTargetDigest(tokenID id.UUID) bool {
	h.t.Helper()
	var present bool
	if err := h.pool.QueryRow(h.t.Context(),
		`SELECT target_token_digest IS NOT NULL FROM recovery_tokens WHERE id = $1`,
		tokenID).Scan(&present); err != nil {
		h.t.Fatalf("reading the target digest state: %v", err)
	}
	return present
}

func dbCreate(email string) users.CreateParams {
	return users.CreateParams{Email: email, PasswordDigest: "$argon2id$fixture-not-a-real-digest"}
}

func (h *harness) newestTokenID(userID id.UUID, purpose Purpose) id.UUID {
	h.t.Helper()
	var rowID id.UUID
	err := h.pool.QueryRow(h.t.Context(),
		`SELECT id FROM recovery_tokens WHERE user_id = $1 AND purpose = $2
		 ORDER BY created_at DESC, id DESC LIMIT 1`, userID, purpose).Scan(&rowID)
	if err != nil {
		h.t.Fatalf("reading the newest %s token id: %v", purpose, err)
	}
	return rowID
}

func TestTheDatabaseTierActuallyRan(t *testing.T) {
	if os.Getenv(dbtest.EnvVar) == "" {
		t.Fatalf("%s is not set. Every test in internal/recovery is a database test, and a skip "+
			"here reads like coverage. Run `goose -dir migrations postgres \"$DATABASE_URL\" up` and "+
			"then `TEST_DATABASE_URL=\"$DATABASE_URL\" go test ./...`; see README.md, Testing.",
			dbtest.EnvVar)
	}
}

func errIsFieldError(err error, field string) bool {
	var fe *users.FieldError
	if !errors.As(err, &fe) {
		return false
	}
	return fe.Field == field
}
