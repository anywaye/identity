package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/config"
)

const testTimeout = 5 * time.Second

var signupKeyValue = []byte("0123456789abcdef0123456789abcdef")

func withSignupKey(cfg config.Config) config.Config {
	cfg.SignupSigningKeyValue = signupKeyValue
	return cfg
}

func newDiscardApp(t *testing.T, cfg config.Config) *app {
	t.Helper()

	a, err := newApp(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("newApp() error = %v", err)
	}
	return a
}

func newServer(t *testing.T, cfg config.Config) *app {
	t.Helper()

	a := newDiscardApp(t, cfg)
	if err := a.Listen(); err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() {
		_ = a.srv.Close()
		_ = a.Close()
	})
	return a
}

func freePort(t *testing.T) string {
	t.Helper()

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	defer ln.Close()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("splitting %q: %v", ln.Addr(), err)
	}
	return port
}

func getRaw(url string) (int, string, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, "", err
	}
	return resp.StatusCode, strings.TrimSpace(string(body)), nil
}

func mustGet(t *testing.T, url string) (int, string) {
	t.Helper()

	code, body, err := getRaw(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return code, body
}

func serveOne(t *testing.T, a *app, method, target string) (int, string) {
	t.Helper()

	rec := httptest.NewRecorder()
	a.srv.Handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), method, target, nil))
	return rec.Code, strings.TrimSpace(rec.Body.String())
}

func TestRunServesRequestsAndStopsWhenTheContextIsCancelled(t *testing.T) {
	a := newServer(t, withSignupKey(config.Config{Port: "0", LogLevel: "info"}))
	base := "http://" + a.Addr()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	if code, body := mustGet(t, base+"/healthz"); code != http.StatusOK || body != `{"status":"ok"}` {
		t.Fatalf("GET /healthz = %d %s, want 200 {\"status\":\"ok\"}", code, body)
	}
	if code, body := mustGet(t, base+"/readyz"); code != http.StatusOK || body != `{"status":"ok","deps":"none"}` {
		t.Fatalf("GET /readyz = %d %s, want 200 with deps none", code, body)
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run() after cancel = %v, want nil", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("Run() did not return after the context was canceled")
	}

	if conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp", a.Addr()); err == nil {
		conn.Close()
		t.Errorf("listener on %s still accepts connections after shutdown", a.Addr())
	}
}

func TestRunLetsInFlightRequestsFinish(t *testing.T) {
	a := newServer(t, withSignupKey(config.Config{Port: "0", LogLevel: "info"}))

	started := make(chan struct{})
	release := make(chan struct{})
	a.srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"in-flight"}`))
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	type result struct {
		code int
		body string
		err  error
	}
	results := make(chan result, 1)
	go func() {
		code, body, err := getRaw("http://" + a.Addr() + "/healthz")
		results <- result{code: code, body: body, err: err}
	}()

	<-started
	cancel()
	close(release)

	select {
	case got := <-results:
		if got.err != nil {
			t.Fatalf("in-flight request failed during shutdown: %v", got.err)
		}
		if got.code != http.StatusOK || got.body != `{"status":"in-flight"}` {
			t.Errorf("in-flight response = %d %s, want 200 {\"status\":\"in-flight\"}", got.code, got.body)
		}
	case <-time.After(testTimeout):
		t.Fatal("in-flight request never completed")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run() = %v, want nil", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("Run() did not return after shutdown")
	}
}

func TestRunReportsServeFailures(t *testing.T) {
	a := newServer(t, withSignupKey(config.Config{Port: "0", LogLevel: "info"}))
	if err := a.listener.Close(); err != nil {
		t.Fatalf("closing the listener: %v", err)
	}

	err := a.Run(context.Background())

	if err == nil {
		t.Fatal("Run() = nil, want the serve failure")
	}
	if errors.Is(err, http.ErrServerClosed) {
		t.Errorf("Run() = %v, want the underlying accept error", err)
	}
}

func TestNewAppWiresReadinessToTheDatabase(t *testing.T) {
	t.Run("no DATABASE_URL means no dependencies", func(t *testing.T) {
		a := newDiscardApp(t, withSignupKey(config.Config{Port: "0", LogLevel: "info"}))
		defer a.Close()

		code, body := serveOne(t, a, http.MethodGet, "/readyz")

		if code != http.StatusOK {
			t.Errorf("status = %d, want 200", code)
		}
		if !strings.Contains(body, `"deps":"none"`) {
			t.Errorf("body = %s, want deps none", body)
		}
	})

	t.Run("an unreachable database fails readiness", func(t *testing.T) {
		a := newDiscardApp(t, withSignupKey(config.Config{
			Port:        "0",
			LogLevel:    "info",
			DatabaseURL: "postgres://identity@127.0.0.1:" + freePort(t) + "/identity?sslmode=disable",
		}))
		defer a.Close()

		code, body := serveOne(t, a, http.MethodGet, "/readyz")

		if code != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want 503", code)
		}
		if !strings.Contains(body, `"deps":"postgres"`) {
			t.Errorf("body = %s, want the postgres dependency named", body)
		}
	})

	t.Run("a reachable database passes readiness", func(t *testing.T) {
		dsn := os.Getenv("TEST_DATABASE_URL")
		if dsn == "" {
			t.Skip("TEST_DATABASE_URL not set; skipping Postgres integration test")
		}

		a := newDiscardApp(t, withSignupKey(config.Config{Port: "0", LogLevel: "info", DatabaseURL: dsn}))
		defer a.Close()

		code, body := serveOne(t, a, http.MethodGet, "/readyz")

		if code != http.StatusOK {
			t.Errorf("status = %d, want 200 (body %s)", code, body)
		}
		if !strings.Contains(body, `"deps":"postgres"`) {
			t.Errorf("body = %s, want the postgres dependency named", body)
		}
	})
}

func TestNewAppRejectsAnUnusableDatabaseURL(t *testing.T) {
	a, err := newApp(context.Background(), withSignupKey(config.Config{
		Port:        "0",
		LogLevel:    "info",
		DatabaseURL: "postgres://user@host:not-a-port/db",
	}), slog.New(slog.NewTextHandler(io.Discard, nil)))

	if err == nil {
		a.Close()
		t.Fatal("newApp() = nil error, want a failure for an unusable DATABASE_URL")
	}
	if a != nil {
		t.Error("newApp() returned an app alongside an error, want nil")
	}
}

func TestMainHandlesSIGTERM(t *testing.T) {
	if os.Getenv("IDENTITY_TEST_CHILD") == "1" {
		main()
		os.Exit(0)
	}

	port := freePort(t)
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestMainHandlesSIGTERM$")
	cmd.Env = append(os.Environ(),
		"IDENTITY_TEST_CHILD=1",
		"PORT="+port,
		"LOG_LEVEL=info",
		"SIGNUP_SIGNING_KEY=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY",
	)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("StderrPipe(): %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the child: %v", err)
	}

	lines := make(chan string, 64)
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		close(lines)
	}()

	waitForLine(t, lines, "listening")

	if code, body := mustGet(t, "http://127.0.0.1:"+port+"/healthz"); code != http.StatusOK || body != `{"status":"ok"}` {
		t.Fatalf("child GET /healthz = %d %s, want 200 {\"status\":\"ok\"}", code, body)
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("sending SIGTERM: %v", err)
	}

	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()

	select {
	case err := <-waitErr:
		if err != nil {
			t.Fatalf("child exited with %v, want a clean exit after SIGTERM", err)
		}
	case <-time.After(testTimeout):
		_ = cmd.Process.Kill()
		t.Fatal("child did not exit within 5s of SIGTERM")
	}

	assertNotListening(t, "127.0.0.1:"+port)
}

func waitForLine(t *testing.T, lines <-chan string, want string) {
	t.Helper()

	deadline := time.After(testTimeout)
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatalf("child output closed before %q appeared", want)
			}
			if strings.Contains(line, want) {
				return
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %q in the child's output", want)
		}
	}
}

func assertNotListening(t *testing.T, addr string) {
	t.Helper()

	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp", addr)
	if err != nil {
		return
	}
	conn.Close()
	t.Errorf("%s still accepts connections after the child exited", addr)
}
