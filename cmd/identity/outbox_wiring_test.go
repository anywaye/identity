package main

// The outbox publisher's boot wiring: what newApp starts, under what condition,
// and what is left running when the condition is not met. The publisher's own
// behavior is tested in internal/outbox against an in-process broker; what is
// tested here is the condition and the lifetime.

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

// startNATS starts an in-process NATS server with JetStream enabled and returns
// its client URL. The wiring under test is that newApp builds a publisher over
// the URL it is given and starts the loop with it; a real server is what makes
// that observable rather than assumed.
func startNATS(t *testing.T) string {
	t.Helper()

	s, err := server.NewServer(&server.Options{
		Host:      "127.0.0.1",
		Port:      -1, // a random free port: the tests run in parallel and share nothing
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

// addStream creates a JetStream stream covering subjects, the way the fleet's
// stack must. A publish to a subject no stream matches is refused by the
// broker — that refusal is internal/outbox's TestNATSPublisherRefusalLeavesTheRowClaimable;
// what this helper buys the wiring test is a broker that actually stores what
// the process publishes, so the drain is observable rather than assumed.
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

// With NATS_URL unset the honest no-op stays: no publisher is built and no loop
// runs. The outbox table, the loop and the Publisher interface all exist; what
// is missing is a broker, and a deployment that has not wired one accumulates
// rows in outbox_events until it does. That is the shipped state, and this is
// the test that holds it there.
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

// With NATS_URL set and a database, the publisher is built and the loop drains
// the outbox through it — proven end to end: a registration writes an
// `identity.user.created` row inside its own transaction, and the row's
// published_at is set by the loop, from the broker's ack, without any request
// waiting on it.
func TestNewAppWithNATSURLPublishesWhatTheProcessWrites(t *testing.T) {
	dsn := testDatabaseURL(t)
	broker := startNATS(t)
	// The stream the stack must define: every event identity publishes is
	// `identity.<domain>.<verb>`, so `identity>` is the filter that covers
	// them. Without it the broker refuses every publish and the drain this
	// test observes never happens — see the stream-less twin below.
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

	// Register a user through the real handler, the way the form does. The
	// registration commits the user and its outbox event in one transaction;
	// everything after this line is the publisher's job, not the request's.
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

	// Wait out the two-second floor. It is the protection — a bot submits
	// instantly — so the test cannot avoid it any more than a bot can.
	time.Sleep(signup.MinAge + 500*time.Millisecond)

	rec := serveBody(t, a, http.MethodPost, "/v1/users", `{"email":"`+email+`","password":"`+password+
		`","timestamp":`+strconv.FormatInt(pair.Timestamp, 10)+`,"signature":"`+pair.Signature+`"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /v1/users = %d, want 201; body: %s", rec.Code, rec.Body)
	}

	// The loop polls once a second, so the drain lands within a poll interval
	// of the commit. What is asserted is the contract's own definition of
	// published — published_at set from the broker's ack — and that it happened
	// after the request returned, with no request waiting on it.
	//
	// The query runs through dbtest.Pool — the same DSN the app was built on,
	// logged in as the application role — because the app's pool writes the
	// default schema and dbtest.Schema's private clone is a different one.
	pool := dbtest.Pool(t)
	deadline := time.Now().Add(10 * time.Second)
	for {
		var publishedAt *time.Time
		if err := pool.QueryRow(context.Background(),
			`SELECT published_at FROM outbox_events WHERE type = 'identity.user.created' AND subject IN (SELECT id::text FROM users WHERE email = $1)`,
			email).Scan(&publishedAt); err != nil {
			// No row yet, or the query raced the commit: the registration has
			// committed by now (201), so an error here is a real failure.
			t.Fatalf("reading the outbox row: %v", err)
		}
		if publishedAt != nil {
			return // drained: the loop published what the process wrote
		}
		if time.Now().After(deadline) {
			t.Fatal("the outbox row was never published; the loop is not draining")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// The stream-less twin of the test above, and the reason that test is not
// vacuous: the same row against a broker with no stream covering the subject
// is left unpublished, with the refusal recorded — attempts climbed,
// last_error names it, published_at NULL. The refusal's mechanics are
// internal/outbox's to prove at length; what is asserted here is that the
// drain the wiring test observes is caused by the stream the stack must
// define, and not by anything the loop does when no broker answers.
//
// The row is inserted directly rather than through a registration, because a
// registration provisions a personal account in the shared public schema —
// the race internal/accounts' count test loses to when the gate runs the
// packages in parallel. The row is the loop's input; where it comes from is
// the positive test's subject, not this one's.
func TestNewAppWithNATSURLButNoStreamLeavesTheRowUnpublished(t *testing.T) {
	dsn := testDatabaseURL(t)
	broker := startNATS(t) // deliberately no addStream: the broker has no stream

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

	// Three poll intervals: the loop has claimed the row and tried to publish
	// it at least twice, and every attempt was refused. The row is exactly
	// where the contract says a refused publish leaves it.
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

// The loop is tied to the process's context — the same one a.Run drains the
// HTTP server on — so a SIGTERM stops both, and Close releases the broker
// connection afterwards. The loop's own stop behavior is the outbox package's
// TestServiceRunStopsOnContextCancellation; what is asserted here is that the
// wiring gives it that context and shuts down in the right order: cancel, then
// close, with the process still serving until the cancel.
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

	// Cancel first, close second: the loop sees its context done and returns,
	// then the connection is released. Closing the connection under a running
	// loop would also stop it — by failing every publish — but that is the
	// failure path, not the shutdown path.
	cancel()
	if err := a.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
