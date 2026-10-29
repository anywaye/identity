package main


import (
	"bufio"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

const bootCourierToken = "svc-7f3a9c1e4b8d2056-the-credential"

func TestTheComposeManifestBootsTheBinary(t *testing.T) {
	if os.Getenv("IDENTITY_TEST_CHILD") == "1" {
		main()
		os.Exit(0)
	}

	env := composeIdentityEnv(t)
	env["COURIER_TOKEN"] = bootCourierToken

	resolved := make(map[string]string, len(env))
	for key, raw := range env {
		value, err := composeInterpolate(raw)
		if err != nil {
			t.Fatalf("resolving %s: %v — this is the error docker compose would print", key, err)
		}
		resolved[key] = value
	}

	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestTheComposeManifestBootsTheBinary$")
	cmd.Env = append(mapToEnv(resolved), "IDENTITY_TEST_CHILD=1")

	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("StderrPipe(): %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the child: %v", err)
	}

	out := &childOutput{lines: make(chan string, 64)}
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			out.lines <- scanner.Text()
		}
		close(out.lines)
	}()

	out.wait(t, "listening")

	port := resolved["PORT"]

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
}

type childOutput struct {
	lines chan string
	said  []string
}

func (c *childOutput) wait(t *testing.T, want string) {
	t.Helper()

	deadline := time.After(testTimeout)
	for {
		select {
		case line, ok := <-c.lines:
			if !ok {
				t.Fatalf("the child closed its output before %q appeared. The child said:\n%s",
					want, strings.Join(c.said, "\n"))
			}
			c.said = append(c.said, line)
			if strings.Contains(line, want) {
				return
			}
		case <-deadline:
			t.Fatalf("timed out after %s waiting for %q in the child's output. The child said:\n%s",
				testTimeout, want, strings.Join(c.said, "\n"))
		}
	}
}

func mapToEnv(env map[string]string) []string {
	out := make([]string, 0, len(env))
	for key, value := range env {
		out = append(out, key+"="+value)
	}
	return out
}
