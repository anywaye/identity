package outbox


import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
)

func startNATS(t *testing.T) *nats.Conn {
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

	nc, err := nats.Connect(s.ClientURL())
	if err != nil {
		t.Fatalf("connecting to the in-process NATS server: %v", err)
	}
	t.Cleanup(nc.Close)

	return nc
}

func addStream(t *testing.T, nc *nats.Conn, subjects ...string) {
	t.Helper()

	js, err := nc.JetStream()
	if err != nil {
		t.Fatalf("opening the JetStream context: %v", err)
	}
	if _, err := js.AddStream(&nats.StreamConfig{Name: "TEST", Subjects: subjects}); err != nil {
		t.Fatalf("adding the test stream: %v", err)
	}
}

func subscribe(t *testing.T, nc *nats.Conn, subject string) chan *nats.Msg {
	t.Helper()

	msgs := make(chan *nats.Msg, 16)
	sub, err := nc.Subscribe(subject, func(m *nats.Msg) { msgs <- m })
	if err != nil {
		t.Fatalf("subscribing to %s: %v", subject, err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("flushing after subscribing to %s: %v", subject, err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })

	return msgs
}

func receive(t *testing.T, msgs chan *nats.Msg) *nats.Msg {
	t.Helper()

	select {
	case m := <-msgs:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("nothing arrived on the subject within 5s")
		return nil
	}
}

func assertSameEnvelope(t *testing.T, raw []byte, want Envelope) {
	t.Helper()

	var got Envelope
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("the received document is not an envelope: %v\n%s", err, raw)
	}
	if got.ID != want.ID {
		t.Errorf("received id = %s, want %s", got.ID, want.ID)
	}
	if got.Type != want.Type {
		t.Errorf("received type = %q, want %q", got.Type, want.Type)
	}
	if got.Source != want.Source {
		t.Errorf("received source = %q, want %q", got.Source, want.Source)
	}
	if got.Subject != want.Subject {
		t.Errorf("received subject = %q, want %q", got.Subject, want.Subject)
	}
	if got.SpecVersion != want.SpecVersion {
		t.Errorf("received specversion = %q, want %q", got.SpecVersion, want.SpecVersion)
	}
	if !got.Time.Equal(want.Time) {
		t.Errorf("received time = %s, want %s", got.Time, want.Time)
	}
	if string(got.Data) != string(want.Data) {
		t.Errorf("received data = %s, want %s", got.Data, want.Data)
	}
}

type rowState struct {
	attempts  int
	lastError *string
	published *time.Time
}

func rowStateOf(t *testing.T, pool *pgxpool.Pool, eventID id.UUID) rowState {
	t.Helper()

	var state rowState
	if err := pool.QueryRow(context.Background(),
		`SELECT attempts, last_error, published_at FROM outbox_events WHERE id = $1`, eventID).
		Scan(&state.attempts, &state.lastError, &state.published); err != nil {
		t.Fatalf("reading the row: %v", err)
	}
	return state
}

func TestNATSPublisherPublishesTheEnvelopeOnTheSubjectOfTheType(t *testing.T) {
	t.Parallel()

	nc := startNATS(t)
	addStream(t, nc, "identity.>")
	msgs := subscribe(t, nc, EventUserCreated)

	pool := dbtest.Schema(t)
	store := NewStore(pool)
	ctx := context.Background()

	e := mustUserCreated(t, dbtest.UniqueEmail(t))
	if err := store.Append(ctx, pool, e); err != nil {
		t.Fatalf("Append: %v", err)
	}

	if state := rowStateOf(t, pool, e.ID); state.published != nil {
		t.Fatalf("published_at = %v before the pass, want NULL", *state.published)
	}

	pub, err := NewNATSPublisher(nc.ConnectedUrl(), discardLogger())
	if err != nil {
		t.Fatalf("NewNATSPublisher: %v", err)
	}
	defer pub.Close()

	svc := NewService(store, pub, discardLogger(), 0)
	n, err := svc.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 {
		t.Errorf("RunOnce published %d events, want 1", n)
	}

	m := receive(t, msgs)
	if m.Subject != e.Type {
		t.Errorf("the message arrived on subject %q, want the event's type %q", m.Subject, e.Type)
	}
	assertSameEnvelope(t, m.Data, e)

	if state := rowStateOf(t, pool, e.ID); state.published == nil {
		t.Error("published_at is still NULL after an acknowledged publish")
	}
}

func assertFailedPublishLeftTheRowClaimable(ctx context.Context, t *testing.T, pool *pgxpool.Pool, store *Store, e Envelope) {
	t.Helper()

	state := rowStateOf(t, pool, e.ID)
	if state.attempts != 1 {
		t.Errorf("attempts = %d, want 1", state.attempts)
	}
	if state.published != nil {
		t.Errorf("published_at = %v, want NULL — a failed publish is not a delivery", *state.published)
	}
	if state.lastError == nil || *state.lastError == "" {
		t.Error("last_error is empty; an operator watching attempts climb has nothing to act on")
	}

	batch, err := store.Claim(ctx, 10)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	defer batch.Release(ctx)

	claimable := false
	for _, got := range batch.Events() {
		if got.ID == e.ID {
			claimable = true
		}
	}
	if !claimable {
		t.Error("the failed event is no longer claimable")
	}
}

func TestNATSPublisherFailureLeavesTheRowClaimable(t *testing.T) {
	t.Parallel()

	nc := startNATS(t)
	msgs := subscribe(t, nc, EventUserCreated)

	pool := dbtest.Schema(t)
	store := NewStore(pool)
	ctx := context.Background()

	e := mustUserCreated(t, dbtest.UniqueEmail(t))
	if err := store.Append(ctx, pool, e); err != nil {
		t.Fatalf("Append: %v", err)
	}

	pub, err := NewNATSPublisher(nc.ConnectedUrl(), discardLogger())
	if err != nil {
		t.Fatalf("NewNATSPublisher: %v", err)
	}
	defer pub.Close()

	svc := NewService(store, pub, discardLogger(), 0)
	n, err := svc.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce = %v; a silent publish must not fail the pass", err)
	}
	if n != 0 {
		t.Errorf("RunOnce published %d events, want 0", n)
	}

	assertFailedPublishLeftTheRowClaimable(ctx, t, pool, store, e)

	select {
	case m := <-msgs:
		if m.Subject != e.Type {
			t.Errorf("the message arrived on subject %q, want %q", m.Subject, e.Type)
		}
	default:
		t.Error("nothing reached the core subscriber; the silence this test depends on could not have happened")
	}
}

func TestNATSPublisherRefusalLeavesTheRowClaimable(t *testing.T) {
	t.Parallel()

	nc := startNATS(t)

	pool := dbtest.Schema(t)
	store := NewStore(pool)
	ctx := context.Background()

	e := mustUserCreated(t, dbtest.UniqueEmail(t))
	if err := store.Append(ctx, pool, e); err != nil {
		t.Fatalf("Append: %v", err)
	}

	pub, err := NewNATSPublisher(nc.ConnectedUrl(), discardLogger())
	if err != nil {
		t.Fatalf("NewNATSPublisher: %v", err)
	}
	defer pub.Close()

	svc := NewService(store, pub, discardLogger(), 0)
	n, err := svc.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce = %v; a refused publish must not fail the pass", err)
	}
	if n != 0 {
		t.Errorf("RunOnce published %d events, want 0", n)
	}

	assertFailedPublishLeftTheRowClaimable(ctx, t, pool, store, e)
}

func TestNATSPublisherADuplicateCarriesTheSameEnvelopeID(t *testing.T) {
	t.Parallel()

	nc := startNATS(t)
	addStream(t, nc, "identity.>")
	msgs := subscribe(t, nc, EventUserCreated)

	pool := dbtest.Schema(t)
	store := NewStore(pool)
	ctx := context.Background()

	e := mustUserCreated(t, dbtest.UniqueEmail(t))
	if err := store.Append(ctx, pool, e); err != nil {
		t.Fatalf("Append: %v", err)
	}

	pub, err := NewNATSPublisher(nc.ConnectedUrl(), discardLogger())
	if err != nil {
		t.Fatalf("NewNATSPublisher: %v", err)
	}
	defer pub.Close()

	first, err := store.Claim(ctx, 10)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	for _, got := range first.Events() {
		if got.ID == e.ID {
			if err := pub.Publish(ctx, got); err != nil {
				t.Fatalf("Publish: %v", err)
			}
		}
	}
	if err := first.Release(ctx); err != nil {
		t.Fatalf("Release: %v", err)
	}

	second, err := store.Claim(ctx, 10)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	defer second.Release(ctx)
	for _, got := range second.Events() {
		if got.ID == e.ID {
			if err := pub.Publish(ctx, got); err != nil {
				t.Fatalf("Publish: %v", err)
			}
		}
	}

	firstMsg := receive(t, msgs)
	secondMsg := receive(t, msgs)

	var env1, env2 Envelope
	if err := json.Unmarshal(firstMsg.Data, &env1); err != nil {
		t.Fatalf("decoding the first delivery: %v", err)
	}
	if err := json.Unmarshal(secondMsg.Data, &env2); err != nil {
		t.Fatalf("decoding the second delivery: %v", err)
	}
	if env1.ID != env2.ID {
		t.Errorf("the duplicate carried a different id (%s vs %s); the consumer's dedupe key would not dedupe", env1.ID, env2.ID)
	}
	if string(firstMsg.Data) != string(secondMsg.Data) {
		t.Error("the duplicate is not byte-identical to the original")
	}
}

func TestNewNATSPublisherRefusesAnUnparseableURL(t *testing.T) {
	t.Parallel()

	if _, err := NewNATSPublisher("nats://\x7finvalid", discardLogger()); err == nil {
		t.Error("NewNATSPublisher accepted an unparseable URL, want a refusal")
	}
}
