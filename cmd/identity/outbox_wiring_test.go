package main


import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/anywaye/identity/internal/config"
	"github.com/anywaye/identity/internal/outbox"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/signup"
)

func startNATS(t *testing.T) string {
	t.Helper()

	s, err := server.NewServer(&server.Options{
		Host:      "127.0.0.1",
		Port:      -1,
		JetStream: true,
		StoreDir:  t.TempDir(),
	})
	if err != nil {
		t.Fatalf("starting the in-process NATS server: %v", err)
	}
	go s.Start()
	if !s.ReadyForConnections(5 * time.Second) {
		s.Shutdown()
		t.Fatal("the in-process NATS server did not become ready in 5s")
	}
	t.Cleanup(s.Shutdown)

	return s.ClientURL()
}

func addStream(t *testing.T, url string, subjects ...string) {
	t.Helper()

	nc, err := nats.Connect(url)
	if err != nil {
		t.Fatalf("connecting to the in-process NATS server: %v", err)
	}
	t.Cleanup(nc.Close)

	js, err := nc.JetStream()
	if err != nil {
		t.Fatalf("opening the JetStream context: %v", err)
	}
	if _, err := js.AddStream(&nats.StreamConfig{Name: "TEST", Subjects: subjects}); err != nil {
		t.Fatalf("adding the test stream: %v", err)
	}
}

func TestNewAppWithoutNATSURLStartsNoPublisher(t *testing.T) {
	cfg := withSignupKey(config.Config{Port: "0", LogLevel: "error"})

	a, err := newApp(context.Background(), cfg, discardLogger())
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	defer a.Close()

	if a.outboxPublisher != nil {
		t.Error("a publisher was built with NATS_URL unset; the loop would drain the outbox into a broker that does not exist")
	}
}

func TestNewAppWithNATSURLPublishesWhatTheProcessWrites(t *testing.T) {
	dsn := testDatabaseURL(t)
	broker := startNATS(t)
	addStream(t, broker, "identity.>")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := withSignupKey(config.Config{Port: "0", LogLevel: "error", DatabaseURL: dsn, NATSURL: broker})
	a, err := newApp(ctx, cfg, discardLogger())
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	defer a.Close()

	if a.outboxPublisher == nil {
		t.Fatal("no publisher was built with NATS_URL set; the outbox would accumulate forever")
	}

	email := dbtest.UniqueEmail(t)
	const password = "correct horse battery staple"

	pairRec := serveBody(t, a, http.MethodPost, "/v1/signup-timestamp", "", nil)
	if pairRec.Code != http.StatusOK {
		t.Fatalf("POST /v1/signup-timestamp = %d, want 201; body: %s", pairRec.Code, pairRec.Body)
	}
	var pair struct {
		Timestamp int64  `json:"timestamp"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(pairRec.Body.Bytes(), &pair); err != nil {
		t.Fatalf("the minted pair is not JSON: %v\n%s", err, pairRec.Body)
	}

	time.Sleep(signup.MinAge + 500*time.Millisecond)

	rec := serveBody(t, a, http.MethodPost, "/v1/users", `{"email":"`+email+`","password":"`+password+
		`","timestamp":`+strconv.FormatInt(pair.Timestamp, 10)+`,"signature":"`+pair.Signature+`"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /v1/users = %d, want 201; body: %s", rec.Code, rec.Body)
	}

	pool := dbtest.Pool(t)
	deadline := time.Now().Add(10 * time.Second)
	for {
		var publishedAt *time.Time
		if err := pool.QueryRow(context.Background(),
			`SELECT published_at FROM outbox_events WHERE type = 'identity.user.created' AND subject IN (SELECT id::text FROM users WHERE email = $1)`,
			email).Scan(&publishedAt); err != nil {
			t.Fatalf("reading the outbox row: %v", err)
		}
		if publishedAt != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the outbox row was never published; the loop is not draining")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestNewAppWithNATSURLButNoStreamLeavesTheRowUnpublished(t *testing.T) {
	dsn := testDatabaseURL(t)
	broker := startNATS(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := withSignupKey(config.Config{Port: "0", LogLevel: "error", DatabaseURL: dsn, NATSURL: broker})
	a, err := newApp(ctx, cfg, discardLogger())
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	defer a.Close()

	if a.outboxPublisher == nil {
		t.Fatal("no publisher was built with NATS_URL set")
	}

	pool := dbtest.Pool(t)
	e, err := outbox.NewUserCreated(time.Now(), id.MustNew(), "nobody@example.com")
	if err != nil {
		t.Fatalf("building the envelope: %v", err)
	}
	envelope, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshaling the envelope: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO outbox_events (id, type, source, subject, occurred_at, payload, envelope)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		e.ID, e.Type, e.Source, e.Subject, e.Time, e.Data, envelope); err != nil {
		t.Fatalf("inserting the outbox row: %v", err)
	}

	time.Sleep(3 * time.Second)

	var (
		publishedAt *time.Time
		attempts    int
		lastError   *string
	)
	if err := pool.QueryRow(context.Background(),
		`SELECT published_at, attempts, last_error FROM outbox_events WHERE id = $1`,
		e.ID).Scan(&publishedAt, &attempts, &lastError); err != nil {
		t.Fatalf("reading the outbox row: %v", err)
	}
	if publishedAt != nil {
		t.Errorf("published_at = %v, want NULL — a refused publish is not a delivery", *publishedAt)
	}
	if attempts < 1 {
		t.Errorf("attempts = %d, want at least 1 — the loop never tried, so this test proves nothing about the broker", attempts)
	}
	if lastError == nil || *lastError == "" {
		t.Error("last_error is empty; an operator watching attempts climb has nothing to act on")
	}
}

func TestNewAppStopsThePublisherLoopWithItsContext(t *testing.T) {
	dsn := testDatabaseURL(t)
	broker := startNATS(t)

	ctx, cancel := context.WithCancel(context.Background())

	cfg := withSignupKey(config.Config{Port: "0", LogLevel: "error", DatabaseURL: dsn, NATSURL: broker})
	a, err := newApp(ctx, cfg, discardLogger())
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}

	if a.outboxPublisher == nil {
		t.Fatal("no publisher was built with NATS_URL set")
	}

	cancel()
	if err := a.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
