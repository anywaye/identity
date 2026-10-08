package main

// THE PACKAGING TEST: the image ships the staff command without serving it.
//
// README promises an operator `identity-staff grant` that works after
// deployment, but the runtime is distroless — no shell, no `go run`. So the
// Dockerfile builds a second static binary into the same image, and a
// deployment runs it as a one-shot Job with an overridden command. This file
// holds that promise to the Dockerfile's text, because a Dockerfile edit that
// drops the second build is a bootstrap path that silently stops existing —
// and building the image to prove it is Docker, which this suite does not run.
//
// It asserts three things, each of which has failed once in review:
//  1. the builder compiles `./cmd/identity-staff` (not a renamed path),
//  2. the runtime stage copies it to `/app/identity-staff` (built and shipped
//     are different facts),
//  3. ENTRYPOINT is still `/app/service` (the staff binary is a Job override,
//     never the server — a swapped entrypoint would boot every replica into
//     a usage error).

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func dockerfile(t *testing.T) string {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed, so the Dockerfile cannot be found")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "Dockerfile"))
	if err != nil {
		t.Fatalf("reading the Dockerfile: %v", err)
	}
	return string(raw)
}

func TestTheImageBuildsAndShipsIdentityStaff(t *testing.T) {
	contents := dockerfile(t)

	if !strings.Contains(contents, "./cmd/identity-staff") {
		t.Error("the Dockerfile builds no ./cmd/identity-staff: the image ships no grant tool and the README's bootstrap path does not exist")
	}
	if !strings.Contains(contents, "/app/identity-staff") {
		t.Error("the Dockerfile copies nothing to /app/identity-staff: a binary built and not copied is a bootstrap path that stops at the builder stage")
	}
}

func TestTheImageStillBootsTheService(t *testing.T) {
	contents := dockerfile(t)

	if !strings.Contains(contents, `ENTRYPOINT ["/app/service"]`) {
		t.Error("the Dockerfile's ENTRYPOINT is not /app/service: the staff binary must be a Job override, never the server")
	}
	if strings.Contains(contents, `ENTRYPOINT ["/app/identity-staff"]`) {
		t.Error("the Dockerfile boots identity-staff as the server: every replica would exit with a usage error")
	}
}
