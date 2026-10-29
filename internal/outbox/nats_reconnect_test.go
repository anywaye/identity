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

	"github.com/anywaye/identity/internal/platform/dbtest"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

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

func captureLogger() (*slog.Logger, *safeBuf) {
	buf := &safeBuf{}
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return logger, buf
}

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

func TestNewNATSPublisherDoesNotFailWhenBrokerIsDownAtBoot(t *testing.T) {
	t.Parallel()

	port := freePort(t)
	url := fmt.Sprintf("nats://127.0.0.1:%d", port)

	pub, err := NewNATSPublisher(url, discardLogger())
	if err != nil {
		t.Fatalf("NewNATSPublisher with broker down: %v, want nil (RetryOnFailedConnect)", err)
	}
	defer pub.Close()

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
	if !pub.nc.IsConnected() {
		t.Error("publisher not connected after successful start")
	}
	_ = s
}

func TestNATSPublisherRecoversAfterExtendedOutage(t *testing.T) {
	port := freePort(t)
	url := fmt.Sprintf("nats://127.0.0.1:%d", port)

	s1 := startServerOnPort(t, port)

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

	waitForStatus(t, nc, nats.CONNECTED, 2*time.Second)

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

	s1.Shutdown()
	waitForStatus(t, nc, nats.RECONNECTING, 2*time.Second)

	time.Sleep(700 * time.Millisecond)
	if nc.IsClosed() {
		t.Fatal("infinite-reconnect publisher is closed after extended outage; want reconnecting")
	}
	if nc.Status() != nats.RECONNECTING {
		t.Errorf("status after extended outage = %v, want RECONNECTING", nc.Status())
	}

	e2 := mustUserCreated(t, dbtest.UniqueEmail(t))
	if err := store.Append(ctx, pool, e2); err != nil {
		t.Fatalf("Append while down: %v", err)
	}
	shortCtx, shortCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	err = pub.Publish(shortCtx, e2)
	shortCancel()
	if err == nil {
		t.Error("Publish while down succeeded, want failure")
	}
	if state := rowStateOf(t, pool, e2.ID); state.published != nil {
		t.Error("row published while broker down")
	}

	s2 := startServerOnPort(t, port)
	{
		nc2, err := nats.Connect(url)
		if err != nil {
			t.Fatalf("connect for addStream s2: %v", err)
		}
		js2, _ := nc2.JetStream()
		if _, err := js2.AddStream(&nats.StreamConfig{Name: "TEST2", Subjects: []string{"identity.>"}}); err != nil {
			_ = err
		}
		nc2.Close()
	}

	waitForStatus(t, nc, nats.CONNECTED, 5*time.Second)

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

	e3 := mustUserCreated(t, dbtest.UniqueEmail(t))
	if err := store.Append(ctx, pool, e3); err != nil {
		t.Fatalf("Append e3: %v", err)
	}
	if n, err := svc.RunOnce(ctx); err != nil || n != 1 {
		t.Fatalf("RunOnce e3 after reconnect: n=%d err=%v", n, err)
	}
	_ = s2

	verifyNC, err := nats.Connect(url)
	if err != nil {
		t.Fatalf("verify connect: %v", err)
	}
	defer verifyNC.Close()
	sub, err := verifyNC.SubscribeSync(e3.Type)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	if err := verifyNC.Flush(); err != nil {
		t.Fatalf("flush after subscribe: %v", err)
	}
	e4 := mustUserCreated(t, dbtest.UniqueEmail(t))
	if err := pub.Publish(ctx, e4); err != nil {
		t.Fatalf("Publish after reconnect: %v", err)
	}
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

	time.Sleep(1 * time.Second)

	if !nc.IsClosed() {
		t.Error("bounded publisher should be closed after budget exhausted, but is still reconnecting")
	}
	if nc.Status() != nats.CLOSED {
		t.Errorf("status = %v, want CLOSED after budget exhausted", nc.Status())
	}
	js, _ := nc.JetStream()
	pub := &NATSPublisher{nc: nc, js: js}
	err = pub.Publish(context.Background(), mustUserCreated(t, dbtest.UniqueEmail(t)))
	if err == nil || !strings.Contains(err.Error(), "connection closed") {
		t.Errorf("Publish after budget exhausted = %v, want 'connection closed'", err)
	}
}

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
	time.Sleep(50 * time.Millisecond)

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
}
