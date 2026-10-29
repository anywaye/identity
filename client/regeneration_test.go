package client


import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// generatorVersion is the pin, written out here rather than read out of
// generate.go's `//go:generate` line.
//
// Duplicated on purpose. The `//go:generate` line is what a developer runs and this
// constant is what the test runs, and a test that parsed the line would be testing
// that a string it just read contains the string it was written with. Two
// statements of one pin is the risk this package accepts; a third would be a
// maintenance tax for nothing. `TestThePinIsTheOneTheGeneratorDirectiveUses` is
// what keeps the two in step.
const generatorVersion = "v2.8.0"

const generatorModule = "github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen"

const generatedFile = "generated/api.gen.go"

const generateTimeout = 10 * time.Minute

func repoRoot(t *testing.T) string {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed, so the repository root cannot be found")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
}

func TestTheCommittedGeneratedFileIsWhatThePinnedGeneratorProduces(t *testing.T) {
	root := repoRoot(t)

	if _, err := exec.LookPath("git"); err != nil {
		t.Fatalf("git is not on PATH, so this test cannot ask whether the generator "+
			"produced a file the repository does not have: %v", err)
	}
	if out, err := exec.CommandContext(t.Context(), "git", "-C", root, "rev-parse", "--is-inside-work-tree").CombinedOutput(); err != nil {
		t.Fatalf("this checkout is not a git work tree, so the regeneration gate cannot "+
			"detect a generated file that is new rather than changed: %v\n%s", err, out)
	}

	out := filepath.Join(t.TempDir(), "api.gen.go")
	config := rewriteConfigFor(t, root, out)

	configPath := filepath.Join(t.TempDir(), "oapi-codegen.yaml")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("writing the scratch generator config: %v", err)
	}

	ctx, cancel := contextWithTimeout(generateTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "run",
		generatorModule+"@"+generatorVersion,
		"--config", configPath,
		"-generate", "models,client",
		filepath.Join(root, "openapi", "v1.yaml"),
	)
	cmd.Dir = filepath.Join(root, "client")

	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("the pinned generator (%s@%s) did not run: %v\n"+
			"This test cannot pass by skipping: a drift gate that does not run is not a gate.\n"+
			"stdout:\n%s\nstderr:\n%s",
			generatorModule, generatorVersion, err, stdout.String(), stderr.String())
	}

	want, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading the freshly generated file at %s: %v", out, err)
	}

	committedPath := filepath.Join(root, "client", generatedFile)
	got, err := os.ReadFile(committedPath)
	if err != nil {
		t.Fatalf("reading the committed %s: %v\n"+
			"The generated file is COMMITTED, deliberately: a generated file that is not "+
			"committed cannot be reviewed, and a diff nobody reads is a change nobody notices.\n"+
			"Run `go generate ./client/` and commit the result.", generatedFile, err)
	}

	if !bytes.Equal(got, want) {
		t.Errorf("%s is not what the pinned generator produces.\n\n"+
			"%s\n\n"+
			"Either the document changed without the client being regenerated, or the "+
			"generator was moved. Both are real events and both need the regenerated file "+
			"committed in the same commit — that commit IS the review.\n\n"+
			"To fix: `go generate ./client/`, read the diff, commit it.\n"+
			"Do NOT edit %s by hand and do NOT relax this test. A client that has drifted "+
			"from its document is the exact failure this check exists to catch, and it is "+
			"silent without it: nothing else in this package reads openapi/v1.yaml, so "+
			"every other test here would still pass.",
			generatedFile, firstDifference(got, want), generatedFile)
	}

	staged := gitOutput(t, root, "diff", "--cached", "--name-status", "--",
		filepath.Join("client", generatedFile))
	if staged != "" {
		t.Errorf("the generated file is staged with changes against the last commit:\n\n%s\n\n"+
			"If the document changed, regenerate and commit the result in the same commit — "+
			"that commit IS the review, and a generated file nobody reviews is a change "+
			"nobody notices. If the change is one you did not make, the working tree and "+
			"the last commit disagree about the client, which is the drift this gate is for.",
			staged)
	}
}

func TestTheGateFailsWhenTheCommittedFileIsWrong(t *testing.T) {
	root := repoRoot(t)

	committed, err := os.ReadFile(filepath.Join(root, "client", generatedFile))
	if err != nil {
		t.Fatalf("reading the committed %s: %v", generatedFile, err)
	}
	if len(committed) == 0 {
		t.Fatal("the committed generated file is empty, so there is nothing to perturb")
	}

	clause := regexp.MustCompile(`(?m)^package \w+$`)
	perturbed := clause.ReplaceAll(committed, []byte("package perturbedbypoof"))

	if bytes.Equal(perturbed, committed) {
		t.Fatal("the red proof could not perturb the generated file: it carries no " +
			"`package <name>` clause to change. The gate is comparing a file this test " +
			"cannot modify, so the red proof below would pass for the wrong reason.")
	}

	if bytes.Equal(committed, perturbed) {
		t.Fatal("the perturbation changed nothing, so the comparison below cannot fail " +
			"and this test would pass without proving anything")
	}

	if difference := firstDifference(committed, perturbed); difference == "" {
		t.Error("the comparison used by the regeneration gate reports no difference " +
			"between the committed file and a file whose package clause was changed.\n" +
			"The gate is therefore vacuous: it would pass against any content, and the " +
			"drift it exists to catch is not being caught.")
	}
}

func TestThePinIsTheOneTheGeneratorDirectiveUses(t *testing.T) {
	root := repoRoot(t)

	raw, err := os.ReadFile(filepath.Join(root, "client", "generate.go"))
	if err != nil {
		t.Fatalf("reading client/generate.go: %v", err)
	}

	directive := regexp.MustCompile(`(?m)^//go:generate\s+go run\s+(\S+@v[0-9][^\s]*)\s`)
	match := directive.FindSubmatch(raw)
	if match == nil {
		t.Fatalf("client/generate.go carries no `//go:generate go run <module>@<version>` line.\n" +
			"Without one there is no generation wiring, and this package's " +
			"generated file cannot be reproduced at all.")
	}

	gotModule, gotVersion, _ := strings.Cut(string(match[1]), "@")
	if gotModule != generatorModule {
		t.Errorf("client/generate.go generates from %q and this gate checks %q.\n"+
			"The gate would verify a file the documented command does not produce.",
			gotModule, generatorModule)
	}
	if gotVersion != generatorVersion {
		t.Errorf("client/generate.go pins the generator at %q and this gate runs %q.\n"+
			"Raise both in the same commit: the `//go:generate` line is what a developer "+
			"runs, and generatorVersion is what proves the committed file matches it. "+
			"A gate that checked a version nobody generates with would be a green lie.",
			gotVersion, generatorVersion)
	}
}

func TestTheGeneratedFileIsCommittedAndNotIgnored(t *testing.T) {
	root := repoRoot(t)
	rel := filepath.Join("client", generatedFile)

	if out, err := exec.CommandContext(t.Context(), "git", "-C", root, "ls-files", "--error-unmatch", "--", rel).CombinedOutput(); err != nil {
		t.Fatalf("git does not track %s.\n"+
			"The generated file is COMMITTED, on purpose: a generated file that is not "+
			"committed cannot be reviewed, and a diff nobody reads is a change nobody "+
			"notices. The generator's version is pinned, so the file is reproducible "+
			"without being built in CI.\n"+
			"If you have just added it to .gitignore, undo that — that is the exact "+
			"mistake this test exists to catch.\n\ngit said: %s",
			rel, out)
	}

	if err := exec.CommandContext(t.Context(), "git", "-C", root, "check-ignore", "-q", "--", rel).Run(); err == nil {
		t.Errorf("git IGNORES %s even though it is tracked.\n"+
			"A tracked-but-ignored file is the worst of the two states: it is in the "+
			"history and it is invisible to every status query, so a regeneration gate "+
			"reading it through git sees a clean tree no matter what changed.", rel)
	}
}

func rewriteConfigFor(t *testing.T, root, out string) string {
	t.Helper()

	path := filepath.Join(root, "client", "oapi-codegen.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	const key = "output: generated/api.gen.go"
	lines := strings.Split(string(raw), "\n")

	rewritten, replaced := 0, -1
	for i, line := range lines {
		if strings.HasPrefix(line, key) {
			rewritten++
			replaced = i
			lines[i] = "output: " + out
		}
	}

	if replaced < 0 {
		t.Fatalf("%s carries no %q line at the start of a line.\n"+
			"This test redirects the generator's output to a temporary directory and "+
			"relies on that exact line to do it. Update this test and the config in the "+
			"same commit.", path, key)
	}
	if rewritten > 1 {
		t.Fatalf("%s carries %q at the start of %d lines, so this test cannot tell "+
			"which one the generator reads.\n"+
			"Give the second one a comment so only the real key is at the start of a line.",
			path, key, rewritten)
	}

	return strings.Join(lines, "\n")
}

func firstDifference(got, want []byte) string {
	gotLines := strings.Split(string(got), "\n")
	wantLines := strings.Split(string(want), "\n")

	for i := 0; i < len(gotLines) && i < len(wantLines); i++ {
		if gotLines[i] != wantLines[i] {
			return "first difference at line " + itoa(i+1) + ":\n" +
				"  committed: " + truncate(gotLines[i], 120) + "\n" +
				"  generator: " + truncate(wantLines[i], 120)
		}
	}

	if len(gotLines) != len(wantLines) {
		short, long := "committed", "generator"
		if len(gotLines) > len(wantLines) {
			short, long = "generator", "committed"
		}
		return "line count differs: " + short + " has " + itoa(len(gotLines)) +
			" lines, " + long + " has " + itoa(len(wantLines)) + ".\n" +
			"A pure line-count difference usually means a generator option moved rather " +
			"than a document schema changing — check client/oapi-codegen.yaml first."
	}
	return ""
}

func gitOutput(t *testing.T, root string, args ...string) string {
	t.Helper()

	cmd := exec.CommandContext(t.Context(), "git", args...)
	cmd.Dir = root

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}
