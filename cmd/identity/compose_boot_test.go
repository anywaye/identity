package main

// THE AGREEMENT BETWEEN THE COMPOSE MANIFEST AND THE BINARY IT DECLARES.
//
// # WHAT THIS FILE HOLDS
//
// `docker-compose.yml` is the manifest that boots identity for a developer,
// and the env it declares for the service has to be an env the binary accepts.
// That agreement is not automatic: SIGNUP_SIGNING_KEY is the one secret with
// no supported absent state — config.Load refuses to start without it — and a
// manifest that does not carry it produces a `docker compose up` that exits
// at config.Load naming a variable the developer has never heard of. The fix
// is a manifest change, and the proof that the fix worked has to be an
// agreement test rather than a literal: a hand-written env literal in this
// file would pass on the day the manifest breaks, which is exactly the defect
// this check exists to close.
//
// So the env is read OUT of docker-compose.yml by `composeIdentityEnv` — the
// parser `mailer_compose_wiring_test.go` wrote for the same agreement on the
// mail path — resolved by `composeInterpolate` the way compose resolves it,
// and the real main() is booted with exactly that.
//
// # WHY THE INSTRUMENT IS A RE-EXECUTED TEST BINARY RATHER THAN `go build`
//
// `TestMainHandlesSIGTERM` above established the pattern this repository uses
// for "run the real process": the test binary re-execs itself with
// IDENTITY_TEST_CHILD=1 and the child runs the REAL main(), which reads the
// REAL environment through the REAL config.Load. The boot path under test —
// config.Load, app construction, Listen — is the same code the shipped binary
// runs; the test harness only adds the frame around it. Building a second
// binary with `go build` inside the test would test the same path at the cost
// of requiring a `go` tool on PATH during the suite and sharing the build
// cache with the suite itself.
//
// # THE ONE FIXTURE, AND THE ONE VARIABLE THAT IS NOT
//
// COURIER_TOKEN is supplied by the test, because the manifest requires it from
// the host (`${VAR:?...}` — compose's refusal form) and config.Load's
// all-or-nothing courier rule needs it present alongside COURIER_BASE_URL.
// The test is the host; the value is a fixture, exactly as in
// `TestTheComposeServiceEnvWiresTheMailer`.
//
// SIGNUP_SIGNING_KEY is the opposite: it reaches the child from the manifest
// and from nowhere else. The child's environment is the resolved block and
// nothing else — not the host's environment with the block layered on top,
// which is what `TestMainHandlesSIGTERM` does and what would let a
// developer's shell supply the key on the day the manifest drops it. A
// container carries its service's environment, not the daemon's, and the
// test is faithful to that: if the manifest stops declaring the key, the
// child never sees it and config.Load refuses to start.
//
// # WHAT THIS IS NOT
//
// It does not run docker, so it does not prove the container comes up, the
// compose network resolves, or the database answers. It proves the half of the
// boot contract a manifest can break silently: that the env the manifest
// declares is an env config.Load accepts and the process then serves. The
// database host `postgres` does not resolve on a developer's laptop and does
// not need to — the pool is lazy, and /healthz is unconditional.

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

// bootCourierToken is the fixture for the one variable the manifest requires
// from the host. It is a value, not a secret: the test proves the manifest
// carries the variable into the boot, not that any particular credential
// exists, and config.Load never dials it.
const bootCourierToken = "svc-7f3a9c1e4b8d2056-the-credential"

// TestTheComposeManifestBootsTheBinary is the agreement test.
//
// It reads the identity service's environment out of docker-compose.yml,
// resolves its ${...} forms, and boots the real main() with the result. The
// assertions are the ones a boot implies: the process reaches "listening",
// /healthz answers 200 {"status":"ok"} unconditionally, and SIGTERM drains
// it to a clean exit. A manifest whose env config.Load refuses fails at the
// first assertion, with the child's own output — which names the variable —
// as the failure message.
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
			// This is the error docker compose would print, and it is a failure
			// rather than a skip: a stack that cannot resolve does not boot.
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

	// The child's output is collected as it arrives, because the failure this
	// test exists to produce is a child that DIES, and the reason it died is
	// the only useful part of its output.
	out := &childOutput{lines: make(chan string, 64)}
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			out.lines <- scanner.Text()
		}
		close(out.lines)
	}()

	out.wait(t, "listening")

	// The port is the manifest's, whatever it is — a test that hardcoded 8080
	// would stop testing the manifest the day the manifest moved.
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

// childOutput collects the child's stderr as it arrives, so a failure can
// print what the child said before it died.
type childOutput struct {
	lines chan string
	said  []string
}

// wait blocks until a line containing want appears, and fails with the
// child's collected output if the child dies first or the wait outlives the
// test timeout.
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

// mapToEnv renders a resolved environment as KEY=VALUE entries for exec.
func mapToEnv(env map[string]string) []string {
	out := make([]string, 0, len(env))
	for key, value := range env {
		out = append(out, key+"="+value)
	}
	return out
}
