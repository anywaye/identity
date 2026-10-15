package outbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/cafaye/identity/internal/platform/dbtest"
)

// freePort asks the kernel for a free port, closes the listener and returns the
// port. The caller must be prepared to retry if the subsequent server fails to
// bind — the port is not reserved — but in practice the window is tiny and the
// helper is retried by the caller where it matters.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

// startServerOnPort starts a NATS server with JetStream on the given port.
func startServerOnPort(t *testing.T, port int) *server.Server {
	t.Helper()
	s, err := server.NewServer(&server.Options{
		Host:      "127.0.0.1",
		Port:      port,
		JetStream: true,
		StoreDir:  t.TempDir(),
	})
	if err != nil {
		t.Fatalf("starting NATS on %d: %v", port, err)
	}
	go s.Start()
	if !s.ReadyForConnections(5 * time.Second) {
		s.Shutdown()
		t.Fatalf("NATS on %d not ready in 5s", port)
	}
	t.Cleanup(s.Shutdown)
	return s
}

// safeBuf is a bytes.Buffer guarded by a mutex, because the NATS handlers
// are called from a different goroutine than the test's reads and
// bytes.Buffer is not safe for concurrent use.
type safeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// captureLogger returns a logger that writes to a thread-safe buffer, and the
// buffer. The logger's handler is async (NATS calls it from its own
// goroutine), so the buffer must be safe for concurrent use.
func captureLogger() (*slog.Logger, *safeBuf) {
	buf := &safeBuf{}
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return logger, buf
}

// waitForStatus waits until nc.Status() == want or timeout.
func waitForStatus(t *testing.T, nc *nats.Conn, want nats.Status, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if nc.Status() == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("nats status = %v, want %v after %s", nc.Status(), want, timeout)
}

// TestNewNATSPublisherDoesNotFailWhenBrokerIsDownAtBoot proves the boot
// behaviour is unchanged: a broker that is down when the process starts is NOT
// a startup failure. With RetryOnFailedConnect the client enters RECONNECTING
// and NewNATSPublisher returns nil error so the outbox table can accumulate.
func TestNewNATSPublisherDoesNotFailWhenBrokerIsDownAtBoot(t *testing.T) {
	t.Parallel()

	port := freePort(t)
	url := fmt.Sprintf("nats://127.0.0.1:%d", port)

	pub, err := NewNATSPublisher(url, discardLogger())
	if err != nil {
		t.Fatalf("NewNATSPublisher with broker down: %v, want nil (RetryOnFailedConnect)", err)
	}
	defer pub.Close()

	// The connection is not closed — it is retrying.
	if pub.nc.IsClosed() {
		t.Error("connection is closed with broker down at boot; want reconnecting")
	}
	if st := pub.nc.Status(); st != nats.RECONNECTING && st != nats.CONNECTING {
		t.Errorf("status = %v, want RECONNECTING/CONNECTING while broker is away", st)
	}
	if pub.nc.Opts.MaxReconnect != -1 {
		t.Errorf("MaxReconnect = %d, want -1 (infinite)", pub.nc.Opts.MaxReconnect)
	}
}

// TestNATSPublisherMaxReconnectIsInfinite asserts the reconnect budget is
// unbounded. The old budget was 60 attempts at 2s = ~120s; a broker away for
// nine minutes (the live 1200 failures) exceeds it and left the connection
// closed. -1 is nats.go's "never give up".
func TestNATSPublisherMaxReconnectIsInfinite(t *testing.T) {
	t.Parallel()

	port := freePort(t)
	s := startServerOnPort(t, port)
	url := fmt.Sprintf("nats://127.0.0.1:%d", port)

	pub, err := NewNATSPublisher(url, discardLogger())
	if err != nil {
		t.Fatalf("NewNATSPublisher: %v", err)
	}
	defer pub.Close()

	if got := pub.nc.Opts.MaxReconnect; got != -1 {
		t.Errorf("MaxReconnect = %d, want -1 (unbounded)", got)
	}
	// Ensure the server was actually used — the test is not vacuous.
	if !pub.nc.IsConnected() {
		t.Error("publisher not connected after successful start")
	}
	_ = s
}

// TestNATSPublisherRecoversAfterExtendedOutage is the green control: broker
// away longer than the old budget, publisher reconnects when it returns and
// the queued rows publish.
//
// The old budget is 60 × 2s = 120s. With a production 2s ReconnectWait the
// test would take two minutes, so the reconnect loop is accelerated to 10ms
// for the test via a direct nats.Connect with the same MaxReconnects(-1) the
// publisher uses — the injectable reconnect path the packet allows when a real
// broker would be too slow. The behaviour is identical: infinite vs 60, only
// the wait is shorter.
//
// Steps: broker up → publish succeeds → broker down (longer than 60 fast
// attempts = 600ms) → publishes fail → broker up → queued row drains.
func TestNATSPublisherRecoversAfterExtendedOutage(t *testing.T) {
	// Not parallel with other port-reusing tests to avoid port clash; but can
	// still run parallel with DB tests because port is unique.
	port := freePort(t)
	url := fmt.Sprintf("nats://127.0.0.1:%d", port)

	s1 := startServerOnPort(t, port)

	// Stream the stack must define.
	{
		nc, err := nats.Connect(url)
		if err != nil {
			t.Fatalf("connect for addStream: %v", err)
		}
		js, _ := nc.JetStream()
		if _, err := js.AddStream(&nats.StreamConfig{Name: "TEST", Subjects: []string{"identity.>"}}); err != nil {
			t.Fatalf("addStream: %v", err)
		}
		nc.Close()
	}

	// Build publisher with infinite reconnect and fast wait.
	logger, _ := captureLogger()
	nc, err := nats.Connect(url,
		nats.RetryOnFailedConnect(true),
		nats.Timeout(DefaultNATSConnectTimeout),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(10*time.Millisecond),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			logger.Warn("nats connection disconnected; will retry", "error", err)
		}),
		nats.ClosedHandler(func(c *nats.Conn) {
			if err := c.LastError(); err != nil {
				logger.Warn("nats connection closed", "error", err)
			}
		}),
	)
	if err != nil {
		t.Fatalf("n bank connect: %v", err)
	}
	js, err := nc.JetStream()
	if err != nil {
		t.Fatalf("JetStream: %v", err)
	}
	pub := &NATSPublisher{nc: nc, js: js}
	defer pub.Close()

	// Connected.
	waitForStatus(t, nc, nats.CONNECTED, 2*time.Second)

	// One successful publish before the outage.
	pool := dbtest.Schema(t)
	store := NewStore(pool)
	ctx := context.Background()
	e1 := mustUserCreated(t, dbtest.UniqueEmail(t))
	if err := store.Append(ctx, pool, e1); err != nil {
		t.Fatalf("Append: %v", err)
	}
	svc := NewService(store, pub, discardLogger(), 0)
	if n, err := svc.RunOnce(ctx); err != nil || n != 1 {
		t.Fatalf("RunOnce before outage: n=%d err=%v", n, err)
	}

	// Take the broker away.
	s1.Shutdown()
	waitForStatus(t, nc, nats.RECONNECTING, 2*time.Second)

	// Stay away longer than the old budget would allow: 70 fast attempts
	// = 700ms > 60×10ms. The old 60-budget client would be closed by now;
	// the infinite one is still reconnecting.
	time.Sleep(700 * time.Millisecond)
	if nc.IsClosed() {
		t.Fatal("infinite-reconnect publisher is closed after extended outage; want reconnecting")
	}
	if nc.Status() != nats.RECONNECTING {
		t.Errorf("status after extended outage = %v, want RECONNECTING", nc.Status())
	}

	// Queue another row while broker is away — the durable outbox: rows
	// accumulate while the broker is away.
	e2 := mustUserCreated(t, dbtest.UniqueEmail(t))
	if err := store.Append(ctx, pool, e2); err != nil {
		t.Fatalf("Append while down: %v", err)
	}
	// Publishing while down fails. Use a short context so the test does not
	// wait DefaultPublishTimeout (10s) per event — a direct Publish with a
	// 500ms deadline fails the same way (broker unanswered) but returns
	// quickly. The row has not been claimed yet, so published_at is still
	// NULL regardless.
	shortCtx, shortCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	err = pub.Publish(shortCtx, e2)
	shortCancel()
	if err == nil {
		t.Error("Publish while down succeeded, want failure")
	}
	if state := rowStateOf(t, pool, e2.ID); state.published != nil {
		t.Error("row published while broker down")
	}

	// Broker returns on same port.
	s2 := startServerOnPort(t, port)
	{
		nc2, err := nats.Connect(url)
		if err != nil {
			t.Fatalf("connect for addStream s2: %v", err)
		}
		js2, _ := nc2.JetStream()
		if _, err := js2.AddStream(&nats.StreamConfig{Name: "TEST2", Subjects: []string{"identity.>"}}); err != nil {
			// May already exist if store reused; ignore.
		}
		nc2.Close()
	}

	// Publisher reconnects.
	waitForStatus(t, nc, nats.CONNECTED, 5*time.Second)

	// Queued row drains.
	deadline := time.Now().Add(5 * time.Second)
	for {
		n, err := svc.RunOnce(ctx)
		if err != nil {
			t.Fatalf("RunOnce after return: %v", err)
		}
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("queued row never drained after broker returned")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if state := rowStateOf(t, pool, e2.ID); state.published == nil {
		t.Error("published_at still NULL after drain")
	}

	// And a fresh publish still works.
	e3 := mustUserCreated(t, dbtest.UniqueEmail(t))
	if err := store.Append(ctx, pool, e3); err != nil {
		t.Fatalf("Append e3: %v", err)
	}
	if n, err := svc.RunOnce(ctx); err != nil || n != 1 {
		t.Fatalf("RunOnce e3 after reconnect: n=%d err=%v", n, err)
	}
	_ = s2

	// Subscribe to verify delivery on the new server — proves the publish
	// reached the broker, not just the row marked.
	verifyNC, err := nats.Connect(url)
	if err != nil {
		t.Fatalf("verify connect: %v", err)
	}
	defer verifyNC.Close()
	sub, err := verifyNC.SubscribeSync(e3.Type)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	// Publish one more to catch.
	e4 := mustUserCreated(t, dbtest.UniqueEmail(t))
	if err := pub.Publish(ctx, e4); err != nil {
		t.Fatalf("Publish after reconnect: %v", err)
	}
	// FIFTEEN SECONDS, not two, and the two was a measured flake rather than a
	// tightness anyone wanted: this is a read WAIT, so the assertion ("the
	// message is delivered on the new server") is unchanged — only the deadline
	// a loaded machine gets. Two seconds timed out under the gate's real shape
	// (the whole suite, -race, one package binary per CPU: run 38659743130's
	// gate job failed here with `nextMsg: nats: timeout`), and the packet that
	// added this test measured the same red three times locally under
	// `go test ./...` while the test passed alone and passed serial. A broken
	// publish still fails this line; it fails it fifteen seconds later.
	msg, err := sub.NextMsg(15 * time.Second)
	if err != nil {
		t.Fatalf("nextMsg: %v", err)
	}
	var got Envelope
	if err := json.Unmarshal(msg.Data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ID != e4.ID {
		t.Errorf("got id %s, want %s", got.ID, e4.ID)
	}
}

// TestNATSPublisherWithBoundedBudgetGivesUp is the RED control: with the old
// 60-attempt budget, a broker away for longer than the budget leaves the
// connection closed and rows never draining. This test uses a small budget
// (5 attempts at 10ms = 50ms) to show the same terminal behaviour quickly.
// It proves the old code's defect rather than the new code's fix.
func TestNATSPublisherWithBoundedBudgetGivesUp(t *testing.T) {
	port := freePort(t)
	url := fmt.Sprintf("nats://127.0.0.1:%d", port)
	s1 := startServerOnPort(t, port)

	nc, err := nats.Connect(url,
		nats.RetryOnFailedConnect(true),
		nats.Timeout(DefaultNATSConnectTimeout),
		nats.MaxReconnects(5),
		nats.ReconnectWait(10*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("connect bounded: %v", err)
	}
	defer nc.Close()
	waitForStatus(t, nc, nats.CONNECTED, 2*time.Second)

	s1.Shutdown()
	waitForStatus(t, nc, nats.RECONNECTING, 2*time.Second)

	// Longer than budget: 5×10ms + jitter (up to 100ms each).
	time.Sleep(1 * time.Second)

	if !nc.IsClosed() {
		t.Error("bounded publisher should be closed after budget exhausted, but is still reconnecting")
	}
	if nc.Status() != nats.CLOSED {
		t.Errorf("status = %v, want CLOSED after budget exhausted", nc.Status())
	}
	// Every publish now sees "connection closed".
	js, _ := nc.JetStream()
	pub := &NATSPublisher{nc: nc, js: js}
	err = pub.Publish(context.Background(), mustUserCreated(t, dbtest.UniqueEmail(t)))
	if err == nil || !strings.Contains(err.Error(), "connection closed") {
		t.Errorf("Publish after budget exhausted = %v, want 'connection closed'", err)
	}
}

// TestNATSPublisherLogsConnectionStateOncePerClosure is the second RED control:
// the "connection closed"/"disconnected" line is emitted once per closure, not
// once per publish. A retry-loop log per publish is how a real defect gets
// buried — 1200 WARNs in five minutes hid the one line that explained them.
func TestNATSPublisherLogsConnectionStateOncePerClosure(t *testing.T) {
	port := freePort(t)
	url := fmt.Sprintf("nats://127.0.0.1:%d", port)
	s1 := startServerOnPort(t, port)

	buf := &safeBuf{}
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	nc, err := nats.Connect(url,
		nats.RetryOnFailedConnect(true),
		nats.Timeout(DefaultNATSConnectTimeout),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(10*time.Millisecond),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			logger.Warn("nats connection disconnected; will retry", "error", err)
		}),
		nats.ClosedHandler(func(c *nats.Conn) {
			if err := c.LastError(); err != nil {
				logger.Warn("nats connection closed", "error", err)
			} else {
				logger.Info("nats connection closed")
			}
		}),
	)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	js, _ := nc.JetStream()
	pub := &NATSPublisher{nc: nc, js: js}
	defer pub.Close()
	waitForStatus(t, nc, nats.CONNECTED, 2*time.Second)

	s1.Shutdown()
	waitForStatus(t, nc, nats.RECONNECTING, 2*time.Second)
	// Give the disconnect handler time to fire.
	time.Sleep(50 * time.Millisecond)

	// Publish multiple events while disconnected — each publish fails and the
	// loop would log one WARN per event, but the connection-state line must
	// appear only once. Direct Publish with a short context is used so the
	// test does not wait DefaultPublishTimeout (10s) per event.
	for i := 0; i < 5; i++ {
		e := mustUserCreated(t, dbtest.UniqueEmail(t))
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		_ = pub.Publish(ctx, e)
		cancel()
	}

	disconnectedCount := strings.Count(buf.String(), "will retry")
	closedCount := strings.Count(buf.String(), "connection closed")
	total := disconnectedCount + closedCount
	if total != 1 {
		t.Errorf("connection-state log appeared %d times, want 1 (once per closure, not per publish)\nlog:\n%s", total, buf.String())
	}
	if disconnectedCount != 1 && closedCount != 1 {
		t.Errorf("expected exactly one disconnect or closed line, got disconnect=%d closed=%d\nlog:\n%s", disconnectedCount, closedCount, buf.String())
	}
	// The per-publish WARNs are elsewhere (Service logs), not this handler.
}
