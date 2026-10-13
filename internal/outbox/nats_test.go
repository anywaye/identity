package outbox

// The NATS publisher's tests run against an in-process NATS server with
// JetStream enabled and a real outbox table, because the behavior under test
// IS the wire: the subject a row is published on, the envelope that arrives,
// and the row's columns after the broker acks or refuses. A mock would prove
// the loop calls something; this proves what a consumer on the fleet's bus
// receives.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
)

// startNATS starts an in-process NATS server with JetStream enabled and returns
// a client connected to it.
//
// Port -1 is a random free port and StoreDir is the test's own directory, so
// parallel tests share nothing. The server is the fleet's broker in miniature:
// it acks what it stores, refuses what no stream matches, and delivers to
// subscribers — which is every property these tests assert on.
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

// addStream creates a JetStream stream covering subjects, the way the fleet's
// stack must. A publish to a subject no stream matches is refused by the
// broker — that refusal is a test case below, not an error in these helpers.
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

// subscribe collects everything published on subject. A core subscription
// receives JetStream-published messages: the stream is a subscriber itself and
// the broker fans out to both, so this is what a consumer on the real bus sees.
func subscribe(t *testing.T, nc *nats.Conn, subject string) chan *nats.Msg {
	t.Helper()

	msgs := make(chan *nats.Msg, 16)
	sub, err := nc.Subscribe(subject, func(m *nats.Msg) { msgs <- m })
	if err != nil {
		t.Fatalf("subscribing to %s: %v", subject, err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })

	return msgs
}

// receive waits for the next message on a subscription and fails the test if
// none arrives: a silent hang and a silent pass look the same from the outside,
// and the difference is the whole of the publisher's contract.
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

// assertSameEnvelope decodes a received document and compares it field by
// field with the envelope that was appended. The comparison is on the decoded
// document rather than the bytes because the store round-trips the envelope
// through Postgres' json type, which reflows whitespace — the fields are the
// contract, and a consumer decodes too.
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

// rowState is the publisher's side of the contract, read back off the row.
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

// The whole packet in one test: a committed outbox row leaves the table on the
// subject named by its type — no mapping, no rewriting — carrying core's
// envelope, and the row is marked published only once the broker has acked.
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

	// Unpublished before the pass. The row is the promise; the promise is not
	// kept until the broker acks, so published_at is NULL right up to the mark.
	if state := rowStateOf(t, pool, e.ID); state.published != nil {
		t.Fatalf("published_at = %v before the pass, want NULL", *state.published)
	}

	pub, err := NewNATSPublisher(nc.ConnectedUrl())
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

	// The broker stored it: a subscriber on the subject received the envelope,
	// on the subject equal to the event's type — the contract's "no mapping
	// table, no prefix rewriting", asserted as the subject the bytes arrived on.
	m := receive(t, msgs)
	if m.Subject != e.Type {
		t.Errorf("the message arrived on subject %q, want the event's type %q", m.Subject, e.Type)
	}
	assertSameEnvelope(t, m.Data, e)

	// And only now is the row marked published. The mark is downstream of the
	// ack — PublishMsg blocks until the broker answers, and MarkPublished runs
	// only after it returns nil — so a set published_at here is a set published
	// the broker has seen.
	if state := rowStateOf(t, pool, e.ID); state.published == nil {
		t.Error("published_at is still NULL after an acknowledged publish")
	}
}

// assertFailedPublishLeftTheRowClaimable asserts the row state a failed
// publish leaves: attempts incremented, published_at NULL, the reason
// recorded, and the row still claimable. Both failure modes — a silent broker
// and a refusing one — leave the row in exactly this state, which is the
// contract.
func assertFailedPublishLeftTheRowClaimable(t *testing.T, pool *pgxpool.Pool, store *Store, ctx context.Context, e Envelope) {
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

	// And the row is still claimable, so the retry is real.
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

// A publish the broker never answers must leave the row exactly as the
// contract says: attempts incremented, published_at NULL, the reason recorded,
// the row still claimable. The next pass republishes it — same id, so a
// consumer that already saw it dedupes.
//
// The broker here is SILENT, not refusing, and the distinction is the whole of
// this test. There is no stream covering the subject, so JetStream never acks;
// and there IS a core subscriber on the subject, which suppresses the broker's
// no-responders error. The publish is delivered to core interest and then waits
// for an ack that will not come — with an unbounded context it waits forever,
// which is the production hang this packet fixes. DefaultPublishTimeout is
// what turns that silence into the failure the contract requires: Publish
// returns an error, the loop records it, and the row stays claimable.
func TestNATSPublisherFailureLeavesTheRowClaimable(t *testing.T) {
	t.Parallel()

	nc := startNATS(t)
	// Deliberately no stream, and deliberately a core subscriber: the
	// subscriber is what makes the broker go silent rather than refuse.
	msgs := subscribe(t, nc, EventUserCreated)

	pool := dbtest.Schema(t)
	store := NewStore(pool)
	ctx := context.Background()

	e := mustUserCreated(t, dbtest.UniqueEmail(t))
	if err := store.Append(ctx, pool, e); err != nil {
		t.Fatalf("Append: %v", err)
	}

	pub, err := NewNATSPublisher(nc.ConnectedUrl())
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

	assertFailedPublishLeftTheRowClaimable(t, pool, store, ctx, e)

	// The message DID reach the core subscriber — that is the mechanism of the
	// silence, and asserting it is what proves the hang was real rather than a
	// broker that refused. A core subscriber suppresses the no-responders
	// error; with no stream, JetStream never acks. The publish was delivered to
	// core interest and then waited for an ack that the budget turned into a
	// failure.
	select {
	case m := <-msgs:
		if m.Subject != e.Type {
			t.Errorf("the message arrived on subject %q, want %q", m.Subject, e.Type)
		}
	default:
		t.Error("nothing reached the core subscriber; the silence this test depends on could not have happened")
	}
}

// The other way a publish fails: the broker REFUSES. No stream and no core
// subscriber, so nothing answers the request and the broker returns
// no-responders, which nats.go retries and then reports as
// ErrNoStreamResponse. This is the case production actually hits when the
// stack defines no stream (see "THE STREAM IS THE STACK'S" above): the
// refusal is fast and loud, and the row is left claimable exactly as the
// silence case leaves it.
func TestNATSPublisherRefusalLeavesTheRowClaimable(t *testing.T) {
	t.Parallel()

	nc := startNATS(t)
	// Deliberately no stream and deliberately no subscriber: with nothing to
	// answer the request, the broker refuses it rather than going silent.

	pool := dbtest.Schema(t)
	store := NewStore(pool)
	ctx := context.Background()

	e := mustUserCreated(t, dbtest.UniqueEmail(t))
	if err := store.Append(ctx, pool, e); err != nil {
		t.Fatalf("Append: %v", err)
	}

	pub, err := NewNATSPublisher(nc.ConnectedUrl())
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

	assertFailedPublishLeftTheRowClaimable(t, pool, store, ctx, e)
}

// At-least-once means a duplicate is survivable, and it is survivable only
// because the envelope id is a function of the row rather than of the publish:
// a re-claimed row republishes the same id, and the consumer's dedupe key
// actually dedupes.
//
// The duplicate here is the one production produces: the broker acked, the
// process died before the mark committed, and the next pass re-claims the same
// row. Releasing the batch without committing is that crash, simulated at the
// batch boundary.
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

	pub, err := NewNATSPublisher(nc.ConnectedUrl())
	if err != nil {
		t.Fatalf("NewNATSPublisher: %v", err)
	}
	defer pub.Close()

	// First pass: the publish acks, then the batch is released uncommitted —
	// the crash between the ack and the mark.
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

	// The next pass claims the same row and republishes it.
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

	// Two deliveries, one envelope id — the property the consumer's dedupe
	// depends on.
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

// A NATS_URL that does not parse is a boot failure, not a silent no-op: a
// deployment that believes it has a bus and does not is the worse of the two
// states, and the refusal belongs at construction, where an operator reads it,
// rather than at the first event, where nobody does.
func TestNewNATSPublisherRefusesAnUnparseableURL(t *testing.T) {
	t.Parallel()

	// The control character is what makes url.Parse fail; an unknown scheme
	// would be dialed and refused at the TCP layer, which RetryOnFailedConnect
	// deliberately swallows.
	if _, err := NewNATSPublisher("nats://\x7finvalid"); err == nil {
		t.Error("NewNATSPublisher accepted an unparseable URL, want a refusal")
	}
}
