package client

// THE LINT EXCLUSION IS ONE FILE, AND THIS IS THE TEST THAT KEEPS IT THAT WAY.
//
// The exclusion in `.golangci.yml` is a comment with teeth only if something reads
// it. Left alone it is a piece of prose that everybody agrees with and nobody
// checks, and the ways it erodes are all quiet:
//
//   - somebody widens `client/api.gen.go` to `client/` while chasing a new
//     generated file, and from then on the hand-written wrapper is unlinted too;
//   - somebody deletes the exclusion because golangci-lint's release notes said
//     the default set changed, and the generated file becomes a wall of
//     complaints that gets "fixed" by gitignoring it;
//   - the linter list goes stale against a new default set, and the generated
//     file is half-linted with no edit to this repository at all.
//
// The third one is the subtle one and it is why this test asks golangci-lint what
// it has enabled rather than hard-coding a list. A generated file that is
// accidentally half-linted produces findings nobody reads and then a growing pile
// of `//nolint` comments in a file that is overwritten by the next regeneration —
// which is worse than being fully linted, because the `//nolint`s survive into
// code that no longer has the findings.
//
// So this test parses the config, checks the path is anchored to exactly the one
// file, and cross-checks the linter list against the tool's own view of what is
// enabled. A failure in any of the three is a finding about the exclusion, and
// the message says which one.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const generatedPath = "client/generated/api.gen.go"

const lintConfig = ".golangci.yml"

var (
	lintPathValue = regexp.MustCompile(`^\s*- path:\s*(\S+)\s*$`)
	lintLinterItem = regexp.MustCompile(`^\s*-\s+([a-z][a-z0-9]*)\s*$`)
)

func TestTheLintExclusionIsOneFileAndNotAPrefix(t *testing.T) {
	root := repoRoot(t)
	paths := lintExclusionPaths(t, root)

	if len(paths) == 0 {
		t.Fatalf("%s excludes no path at all.\n"+
			"client/%s is %d lines of `go:generate` output and is not hand-written code, "+
			"so it is exempt from lint — but an exemption with no path in it is not an "+
			"exemption, it is a missing rule that will be added later without anyone "+
			"deciding to.", lintConfig, generatedFile, lineCount(t, filepath.Join(root, "client", generatedFile)))
	}

	for _, path := range paths {
		re := regexp.MustCompile(path)

		if !re.MatchString(generatedPath) {
			t.Errorf("the lint exclusion %q does not match %s.\n"+
				"That means the generated file is not exempt and will report every finding "+
				"oapi-codegen produces, which is what the exclusion exists to prevent.",
				path, generatedPath)
			continue
		}

		for _, other := range goFiles(t, root) {
			if other == generatedPath {
				continue
			}
			if re.MatchString(other) {
				t.Errorf("the lint exclusion %q also matches %s, which is hand-written.\n"+
					"An exclusion is allowed to cover the generated file and NOTHING else. "+
					"This one covers code a reviewer is responsible for, and it was widened "+
					"from `^client/api\\.gen\\.go$` to something broader — which is how a real "+
					"file stops being linted.", path, other)
			}
		}
	}
}

// TestTheLintExclusionNamesEveryEnabledLinter is the staleness check, and it is
// why the linter list is written out in the config rather than left implicit.
//
// golangci-lint's enabled set is a default that moves between releases. If this
// test hard-coded the list, it would pass forever while the tool gained a linter,
// and the generated file would quietly become half-linted — the worst outcome,
// because findings nobody reads accumulate `//nolint` comments that survive into
// regenerated code which no longer has those findings.
//
// So the list is asked of the tool. If golangci-lint is not installed the test
// FAILS rather than skipping, for the reason this repository uses everywhere: a
// check that quietly does not run is indistinguishable from a check that passed,
// and `ci/ci.yml` fails the build on a `--- SKIP:` line for exactly
// this reason. The failure says how to install it.
//
// ## WHY ONE ENABLED LINTER IS ALLOWED TO BE MISSING FROM THE LIST
//
// `lintersKeptOnGenerated` names the enabled linters this repository deliberately
// does NOT exclude from the generated file, each with the reason it stays on.
// Every enabled linter must be either excluded or named there, so an upgrade that
// adds a linter fails this test rather than producing findings nobody reads.
//
// `govet` is the one entry, and it is the case that matters: `go vet ./client/`
// passes on the generated file, so excluding `govet` would buy nothing and would
// drop the check most likely to catch a generator bug. An exclusion list should
// carry linters that report on STYLE and never one that reports on CORRECTNESS.
//
// This test found its own gap, which is worth recording because the wrong fix was
// available. It first failed naming `govet` as unaccounted for, and adding `govet`
// to the exclusion would have made it green — a broader exclusion, in exchange for
// nothing, satisfying the test that was supposed to prevent exactly that. The
// right fix was to record why it stays on. A test that can be satisfied by
// widening the thing it checks is the wrong test; this is the evidence that it is
// not one.
func TestTheLintExclusionNamesEveryEnabledLinter(t *testing.T) {
	enabled := golangciLintEnabled(t)

	if len(enabled) == 0 {
		t.Fatalf("`golangci-lint linters` reported no enabled linters, so this test " +
			"cannot tell whether the exclusion list is stale.\n" +
			"Got the command's output but parsed no names out of it, which means the " +
			"output shape changed and this test is now reading nothing and passing for " +
			"the wrong reason.")
	}

	excluded := lintExclusionLinters(t, repoRoot(t))
	if len(excluded) == 0 {
		t.Fatalf("the exclusion in %s names no linter.\n"+
			"A path with an empty linter list matches no finding, so the generated file "+
			"is not exempt.", lintConfig)
	}

	var unaccounted []string
	for _, name := range enabled {
		if excluded[name] {
			continue
		}
		if _, kept := lintersKeptOnGenerated[name]; kept {
			continue
		}
		unaccounted = append(unaccounted, name)
	}

	if len(unaccounted) > 0 {
		t.Errorf("golangci-lint has %d enabled linter(s) that %s neither excludes from "+
			"the generated file nor lists in lintersKeptOnGenerated:\n\n  %s\n\n"+
			"The generated file is %d lines of `go:generate` output. An enabled linter that "+
			"is neither excluded nor accounted for reports findings on it, and those findings "+
			"are either noise nobody reads or pressure to delete the exclusion.\n\n"+
			"Either add the name under the exclusion in %s, or — if the linter inspects "+
			"correctness rather than style, as govet does — add it to lintersKeptOnGenerated "+
			"in this file WITH the reason it stays on. Widening the exclusion is the wrong fix "+
			"whenever the linter is catching real problems in generated code.",
			len(unaccounted), lintConfig, strings.Join(unaccounted, "\n  "),
			lineCount(t, filepath.Join(repoRoot(t), "client", generatedFile)), lintConfig)
	}
}

var lintersKeptOnGenerated = map[string]string{
	"govet": "`go vet ./client/` passes on the generated file — verified, not assumed, when " +
		"this packet was written — so excluding it would buy nothing. It is also the one " +
		"enabled linter that inspects what the code MEANS rather than how it is shaped, and " +
		"AGENTS.md names `go vet ./...` as one of this repository's four gates; the " +
		"generated client is inside `./...`, so it is vetted in CI regardless of this file.",
}

func TestTheLintExclusionFileItselfIsLinted(t *testing.T) {
	paths := lintExclusionPaths(t, repoRoot(t))

	if len(paths) > 1 {
		t.Errorf("%s excludes %d paths: %s.\n"+
			"This configuration exists to exempt ONE file — the generated client — and this "+
			"packet added exactly one generated file.\n\n"+
			"If a second generated file now exists, this test and the exclusion belong in the "+
			"same commit as it, with each path anchored to its own file. Exemptions added one "+
			"at a time, each for a good reason, are how a repository ends up with nothing "+
			"linted.",
			lintConfig, len(paths), strings.Join(paths, ", "))
	}
}


func lintExclusionPaths(t *testing.T, root string) []string {
	t.Helper()

	raw := readLintConfig(t, root)

	var (
		paths     []string
		inRules   bool
		ruleDepth int
	)
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)

		switch {
		case strings.HasPrefix(trimmed, "linters:"):
			inRules = false
		case strings.HasPrefix(trimmed, "exclusions:"):
			inRules = false
		case strings.HasPrefix(trimmed, "rules:"):
			inRules = true
		case inRules && trimmed == "- path:":
			continue
		}

		if inRules {
			if m := lintPathValue.FindStringSubmatch(line); m != nil {
				paths = append(paths, m[1])
				ruleDepth = len(line) - len(strings.TrimLeft(line, " "))
			}
			_ = ruleDepth
		}
	}

	if !strings.Contains(raw, "exclusions:") {
		t.Fatalf("%s declares no `exclusions:` block, so this reader is looking for a "+
			"structure the file does not have and would report no paths.\n"+
			"If golangci-lint's schema moved again, update this test and the config in the "+
			"same commit — the point of this test is that the exclusion cannot change "+
			"shape unnoticed.", lintConfig)
	}

	return paths
}

func lintExclusionLinters(t *testing.T, root string) map[string]bool {
	t.Helper()

	raw := readLintConfig(t, root)

	names := map[string]bool{}
	lines := strings.Split(raw, "\n")

	for i, line := range lines {
		if lintPathValue.FindStringSubmatch(line) == nil {
			continue
		}

		keyIndent := len(line) - len(strings.TrimLeft(line, " "))
		inList := false

		for _, next := range lines[i+1:] {
			trimmed := strings.TrimSpace(next)
			if trimmed == "" {
				continue
			}
			nextIndent := len(next) - len(strings.TrimLeft(next, " "))

			if nextIndent <= keyIndent {
				break
			}
			if strings.HasPrefix(trimmed, "linters:") {
				inList = true
				continue
			}
			if !inList {
				continue
			}
			if m := lintLinterItem.FindStringSubmatch(next); m != nil {
				names[m[1]] = true
			}
		}
		break
	}

	return names
}

func readLintConfig(t *testing.T, root string) string {
	t.Helper()

	path := filepath.Join(root, lintConfig)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v\n"+
			"Without it the generated client is linted as if it were hand-written, and "+
			"every finding oapi-codegen produces becomes this repository's problem.",
			lintConfig, err)
	}
	return string(raw)
}

func golangciLintEnabled(t *testing.T) []string {
	t.Helper()

	if _, err := exec.LookPath("golangci-lint"); err != nil {
		t.Fatalf("golangci-lint is not on PATH, so the stale-linter check cannot run.\n"+
			"This test FAILS rather than skips on purpose: a check that silently does not "+
			"run is indistinguishable from one that passed, and a stale exclusion list is "+
			"exactly the drift this test exists to catch. Install it with "+
			"`mise install` — kit pins the version, or `brew install golangci-lint`.\n"+
			"Original error: %v", err)
	}

	cmd := exec.CommandContext(t.Context(), "golangci-lint", "linters", "--json")
	cmd.Dir = repoRoot(t)

	var stdout strings.Builder
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		t.Fatalf("`golangci-lint linters --json` failed: %v\n"+
			"This test reads the enabled linter set from the tool rather than hard-coding "+
			"it, so a tool that cannot answer leaves this check unable to run.", err)
	}

	return parseEnabledLinters(stdout.String())
}

func parseEnabledLinters(raw string) []string {
	var document struct {
		Enabled []struct {
			Name string `json:"name"`
		} `json:"Enabled"`
	}

	if err := json.Unmarshal([]byte(raw), &document); err != nil {
		return nil
	}

	names := make([]string, 0, len(document.Enabled))
	for _, linter := range document.Enabled {
		if linter.Name != "" {
			names = append(names, linter.Name)
		}
	}
	return names
}


func goFiles(t *testing.T, root string) []string {
	t.Helper()

	out, err := exec.CommandContext(t.Context(), "git", "-C", root, "ls-files", "*.go").CombinedOutput()
	if err != nil {
		t.Fatalf("git ls-files '*.go': %v\n%s", err, out)
	}

	var paths []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "vendor/") {
			continue
		}
		paths = append(paths, filepath.ToSlash(line))
	}

	if len(paths) == 0 {
		t.Fatal("git reported no Go files in this repository, so the exclusion check " +
			"matched nothing and passed for the wrong reason")
	}
	return paths
}

func lineCount(t *testing.T, path string) int {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return strings.Count(string(raw), "\n") + 1
}
