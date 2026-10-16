// The backend switch: `ci/backend` names the backend that runs
// `ci/pipeline.sh`, and this file holds that one line to the contract.
//
// kit's `backends/README.md` is the contract: it defines the switch ("Change
// the one line in `ci/backend`"), names `github-actions` the fallback, and
// owns the table of backends a pipeline may name. A backend kit does not ship
// is a pipeline nothing runs — the agent polls a project whose backend has no
// provisioner, or Actions is asked to run a workflow the switch no longer
// points at — so an unknown value fails here rather than idling somewhere.
//
// # What this deliberately does not do
//
// It does not read kit's table out of the kit tree. The kit checkout beside
// this repository is a sparse CI artifact (the courier and substrate drift
// checks read through it); the lint-config checkout cafe and box carry has no
// `backends/` in it at all. A check that needs a sibling to answer is a check
// that skips without one, and a backend check that skipped is the exact hole
// this file exists to close. The allowlist below is therefore written out, and
// a third backend lands here in the same commit that adopts it — the same
// shape as every other exception in this repository: the lint exclusion, the
// coverage exclusions, and `knownDrift`.
package ci

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// knownBackends is the mirror of kit's `backends/README.md` backend table.
// `github-actions` is the fallback the contract names; `instabox` is the
// sandbox backend this repository runs on.
var knownBackends = map[string]bool{
	"github-actions": true,
	"instabox":       true,
}

// readBackend reads `ci/backend` and returns the one line it must hold. A
// backend file that is empty, or that carries more than its line, is not a
// switch set to something unknown — it is a switch that was never set, and it
// fails as its own case rather than as an unknown backend.
func readBackend(t *testing.T, path string) string {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v. The backend switch this file checks does not exist", path, err)
	}
	backend := strings.TrimSpace(string(raw))
	if backend == "" {
		t.Fatalf("ci/backend is empty. An unset switch is not the fallback; write %q for that",
			"github-actions")
	}
	if strings.Contains(backend, "\n") {
		t.Fatalf("ci/backend holds more than one line %q. The switch is one backend, chosen once", backend)
	}
	return backend
}

// TestTheBackendIsOneKitShips is the check: the value in `ci/backend` is a
// backend kit's contract names.
func TestTheBackendIsOneKitShips(t *testing.T) {
	backend := readBackend(t, filepath.Join(repoRoot(t), "ci", "backend"))
	if !knownBackends[backend] {
		t.Errorf("ci/backend names %q, which kit's backends/README.md does not ship. "+
			"A backend nothing runs is a pipeline nothing runs: adopt it in kit first, "+
			"then mirror it in knownBackends in the same commit.", backend)
	}
}

// TestBackendValidationRefusesWhatKitDoesNotShip is the proof the check fires.
// It drives the allowlist with values no backend table holds — including the
// near-misses a typo produces — so a validation that stopped validating is
// red here rather than silent. The real file is untouched: this is the
// injected fault, not the tree.
func TestBackendValidationRefusesWhatKitDoesNotShip(t *testing.T) {
	for _, backend := range []string{
		"",
		"github_actions",
		"GitHub-Actions",
		"instabox ",
		"actions",
		"sandbox",
		"localhost",
	} {
		trimmed := strings.TrimSpace(backend)
		if trimmed == "" || strings.Contains(trimmed, "\n") {
			continue // readBackend's own cases, covered above, not this table's
		}
		if knownBackends[backend] {
			t.Errorf("backend %q is accepted, so this table cannot prove refusal. "+
				"A negative control that passes is not a control.", backend)
		}
	}
	for _, backend := range []string{"github-actions", "instabox"} {
		if !knownBackends[backend] {
			t.Errorf("backend %q is refused, so a legal switch value fails the gate. "+
				"The allowlist drifted from kit's table.", backend)
		}
	}
}

// TestThePipelineIsShellSound runs `bash -n` over `ci/pipeline.sh`. The
// pipeline carries awk programs inside shell single-quoted strings, where an
// apostrophe in a comment closes the quote and the shell re-parses the rest
// as commands — the defect TestEveryRunBlockIsValidShell exists to catch in
// the workflow. The pipeline deserves the same parse check, for the same
// reason: a file that cannot be parsed cannot gate anything.
func TestThePipelineIsShellSound(t *testing.T) {
	path := filepath.Join(repoRoot(t), "ci", "pipeline.sh")
	out, err := exec.CommandContext(context.Background(), "bash", "-n", path).CombinedOutput()
	if err != nil {
		t.Errorf("bash -n %s: %v\n%s. A pipeline with a syntax error gates nothing.", path, err, out)
	}
}

// TestThePipelineIsExecutable asserts the bit the backend needs. The instabox
// agent calls `ci/pipeline.sh` as a command; a committed file without the
// executable bit is a pipeline the backend cannot start, and the failure
// arrives as an agent log rather than as a red gate.
func TestThePipelineIsExecutable(t *testing.T) {
	path := filepath.Join(repoRoot(t), "ci", "pipeline.sh")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v. The pipeline this file checks does not exist", path, err)
	}
	if info.Mode()&0o111 == 0 {
		t.Errorf("ci/pipeline.sh mode %s carries no executable bit. "+
			"The backend executes this file; commit it with `chmod +x`.", info.Mode())
	}
}
