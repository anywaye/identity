package ci

// The declaration behind `bin/prime --fast`, and the check that keeps it from
// rotting.
//
// # WHY THE TIER IS DECLARED RATHER THAN COMPUTED
//
// `--fast` runs the COMPLEMENT of the database tier, so the tier has to be
// written down somewhere both the shell and this file can read. It lives in
// gate.yml as `#   db-tier: ` marker lines, because core's gate.schema.json
// forbids a new key (`additionalProperties: false`) — the declaration rides in
// the file's existing comment structure, and the marker is the contract
// between gate.yml, bin/prime and this file.
//
// # WHY THE CHECK IS THE POINT, NOT THE SPEED
//
// The lazy `--fast` — unset TEST_DATABASE_URL and let the db packages skip —
// is a green gate over tests that never ran, which is the exact false green
// this fleet has been burned by before. So the tier is not merely declared:
// a package whose test binary links internal/platform/dbtest but is NOT in
// the declared tier fails the gate, naming the package. Without that, the
// first packet that adds a db package gets a fast tier that silently excludes
// it — a green inner loop over a tier that drifted into lying.
//
// The derivation is the same one bin/prime's shell pipeline performs:
//
//   go list -test -f '{{.ImportPath}} {{range .Deps}}{{.}} {{end}}' ./... |
//     awk '{deps=substr($0, length($1)+2); if (deps ~ /internal\/platform\/dbtest/) print $1}'
//
// keep the lines whose deps contain dbtest, normalise `P [P.test]` / `P.test`
// / `P_test` back to `P`. `internal/platform/dbtest` itself is not listed: it
// has no tests, and a package does not import itself.
//
// # WHAT THIS FILE PROVES, AND IN WHICH DIRECTION
//
// The comparison fails in BOTH directions, because a declaration that has
// never been shown to disagree is indistinguishable from one that cannot:
// a pool package missing from the list (the fast tier would silently skip it)
// and a listed package that opens no pool (the fast tier skips a package it
// does not need to) are both errors. And the shell-level refusal in bin/prime
// is proven red by a stubbed `go` that lies about one package's deps — a stub
// that is shadowed by a real go would let the refusal pass vacuously, so the
// test asserts the stub was actually invoked.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// dbtestImportPath is the package whose linkage marks a test binary as a pool
// opener. It is the only pool constructor the tests use: db.Open is called
// from cmd/identity and from dbtest itself, so a test that opens a pool
// reaches it through here.
const dbtestImportPath = "github.com/anywaye/identity/internal/platform/dbtest"

// dbTierMarker is the line prefix that declares the db tier in gate.yml.
// bin/prime's sed and this file's parser both read exactly these lines.
const dbTierMarker = "#   db-tier: "

// dbTierDeclaration reads the declared db tier out of a gate.yml document.
//
// It refuses a document with no marker lines: an empty declaration is not a
// smaller tier, it is the false-green trap — `--fast` would run every package
// including the ones that open a pool, and the anti-rot check in bin/prime
// would refuse, but a reader that found nothing here would report the
// declaration as vacuously fine.
func dbTierDeclaration(source string) ([]string, error) {
	var declared []string
	for i, line := range strings.Split(source, "\n") {
		if strings.HasPrefix(line, dbTierMarker) {
			name := strings.TrimPrefix(line, dbTierMarker)
			if name == "" {
				return nil, fmt.Errorf("line %d: %s with no package name", i+1, dbTierMarker)
			}
			declared = append(declared, name)
		}
	}
	if len(declared) == 0 {
		return nil, fmt.Errorf("no %s lines, so the db tier is empty and --fast would run every package", dbTierMarker)
	}
	return declared, nil
}

// goListPackages returns every package in the module, the way bin/prime's
// `go list ./...` does.
func goListPackages(t *testing.T) []string {
	t.Helper()
	out, err := goList(t, "./...")
	if err != nil {
		t.Fatalf("go list ./...: %v", err)
	}
	var pkgs []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			pkgs = append(pkgs, line)
		}
	}
	return pkgs
}

// poolOpeningPackages returns the packages whose test binaries link dbtest,
// derived the same way bin/prime derives them.
func poolOpeningPackages(t *testing.T) []string {
	t.Helper()
	out, err := goList(t, "-test", "-f", "{{.ImportPath}} {{range .Deps}}{{.}} {{end}}", "./...")
	if err != nil {
		t.Fatalf("go list -test: %v", err)
	}
	set := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pkg := fields[0]
		for _, dep := range fields[1:] {
			if dep == dbtestImportPath {
				set[normalisePackage(pkg)] = true
			}
		}
	}
	var pkgs []string
	for pkg := range set {
		pkgs = append(pkgs, pkg)
	}
	return pkgs
}

// normalisePackage maps the three spellings `go list -test` emits for one
// package back to the package itself: the test variant `P [P.test]` (whose
// first field is already `P`), the test main `P.test`, and the external test
// variant `P_test`. It mirrors the sed in bin/prime.
func normalisePackage(pkg string) string {
	pkg = strings.TrimSuffix(pkg, ".test")
	pkg = strings.TrimSuffix(pkg, "_test")
	return pkg
}

func goList(t *testing.T, args ...string) ([]byte, error) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "go", append([]string{"list"}, args...)...)
	cmd.Dir = repoRoot(t)
	return cmd.Output()
}

// tierDisagreement returns the ways a declared db tier disagrees with the
// packages that actually open a pool. It is a pure function of its inputs so
// the tripwire below can prove it fires; the real test feeds it the real
// gate.yml and the real derivation.
func tierDisagreement(declared, opens, all []string) []string {
	var problems []string

	declaredSet := make(map[string]bool, len(declared))
	for _, d := range declared {
		declaredSet[d] = true
	}
	opensSet := make(map[string]bool, len(opens))
	for _, p := range opens {
		opensSet[p] = true
	}
	allSet := make(map[string]bool, len(all))
	for _, p := range all {
		allSet[p] = true
	}

	for _, d := range declared {
		if !allSet[d] {
			problems = append(problems, fmt.Sprintf("%s is declared in gate.yml's db tier but is not a package in this module", d))
		}
	}
	// The direction the whole flag exists for: a pool opener that is not
	// declared is silently excluded from the fast tier.
	for _, p := range opens {
		if !declaredSet[p] {
			problems = append(problems, fmt.Sprintf("%s opens a pool but is not declared in gate.yml's db tier", p))
		}
	}
	for _, d := range declared {
		if !opensSet[d] {
			problems = append(problems, fmt.Sprintf("%s is declared in gate.yml's db tier but opens no pool", d))
		}
	}
	return problems
}

// TestTheDeclaredDbTierMatchesThePackagesThatOpenAPool is the declaration
// check. It reads the real gate.yml, derives the real pool-opening packages
// with `go list`, and asserts the two agree in both directions.
func TestTheDeclaredDbTierMatchesThePackagesThatOpenAPool(t *testing.T) {
	declared, err := dbTierDeclaration(readRepoFile(t, "gate.yml"))
	if err != nil {
		t.Fatalf("reading the db tier out of gate.yml: %v", err)
	}

	problems := tierDisagreement(declared, poolOpeningPackages(t), goListPackages(t))
	for _, problem := range problems {
		t.Error(problem)
	}
}

// TestTheTierDisagreementCheckFailsOnAnInjectedPackage is the tripwire's own
// tripwire. The comparison above can be shown to hold on the committed files,
// and a comparison that has never fired is indistinguishable from one that
// cannot — so this removes a pool package from the declaration and adds a
// non-pool package to it, and asserts the check reports both rather than
// agreeing with itself.
func TestTheTierDisagreementCheckFailsOnAnInjectedPackage(t *testing.T) {
	all := goListPackages(t)
	opens := poolOpeningPackages(t)
	if len(opens) == 0 {
		t.Fatal("no package opens a pool, so the injected cases below prove nothing")
	}

	opensSet := make(map[string]bool, len(opens))
	for _, p := range opens {
		opensSet[p] = true
	}

	// A pool package the declaration has dropped — the exact false green.
	var undeclaredPool string
	for _, p := range opens {
		undeclaredPool = p
		break
	}
	// A package that opens no pool but is declared as if it did.
	var nonPool string
	for _, p := range all {
		if !opensSet[p] {
			nonPool = p
			break
		}
	}
	if nonPool == "" {
		t.Fatal("every package opens a pool, so the declared-but-opens-no-pool case below proves nothing")
	}

	problems := tierDisagreement([]string{nonPool}, opens, all)
	found := false
	for _, problem := range problems {
		if strings.Contains(problem, undeclaredPool) && strings.Contains(problem, "is not declared") {
			found = true
		}
	}
	if !found {
		t.Errorf("the check did not report %s as a pool opener missing from the declaration.\n"+
			"This is the check going green without checking, which is the failure the whole file exists to prevent.", undeclaredPool)
	}

	problems = tierDisagreement([]string{nonPool}, opens, all)
	found = false
	for _, problem := range problems {
		if strings.Contains(problem, nonPool) && strings.Contains(problem, "opens no pool") {
			found = true
		}
	}
	if !found {
		t.Errorf("the check did not report %s as declared but opening no pool.", nonPool)
	}
}

// TestTheFastTierRefusesAnUndeclaredPoolPackage proves the shell-level
// anti-rot check red, end to end through bin/prime.
//
// A stub `go` is put first on PATH. It answers `go mod download` and
// `go build` with success, answers `go list ./...` by deferring to the real go,
// and answers `go list -test` with a LIE: it claims one fast-tier package's
// test binary links dbtest. bin/prime --fast must refuse, naming that package
// — the safe state is a red gate, never a quiet green over a skipped tier.
//
// The stub records every invocation, and the test asserts the record contains
// the steps bin/prime actually took. A stub that was shadowed by a real go
// would let the refusal pass vacuously, so the record is the evidence the
// refusal was earned.
func TestTheFastTierRefusesAnUndeclaredPoolPackage(t *testing.T) {
	root := repoRoot(t)

	declared, err := dbTierDeclaration(readRepoFile(t, "gate.yml"))
	if err != nil {
		t.Fatalf("reading the db tier out of gate.yml: %v", err)
	}
	declaredSet := make(map[string]bool, len(declared))
	for _, d := range declared {
		declaredSet[d] = true
	}

	// The victim: a real package that is NOT in the declared tier, so the lie
	// makes it an undeclared pool opener.
	var victim string
	for _, pkg := range goListPackages(t) {
		if !declaredSet[pkg] {
			victim = pkg
			break
		}
	}
	if victim == "" {
		t.Fatal("every package is declared in the db tier, so there is no fast-tier package to inject the lie into")
	}

	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("finding the real go: %v", err)
	}

	dir := t.TempDir()
	logPath := filepath.Join(dir, "invocations.log")

	// The stub. It logs every invocation, defers `go list ./...` to the real
	// go (found by absolute path, because `command -v go` from inside the stub
	// would find the stub itself), and lies about the victim's deps.
	stub := "#!/usr/bin/env bash\n" +
		"echo \"go $*\" >> '" + logPath + "'\n" +
		"case \"$1\" in\n" +
		"  mod|build) exit 0 ;;\n" +
		"  list)\n" +
		"    if [ \"$2\" = \"-test\" ]; then\n" +
		"      echo '" + victim + " " + dbtestImportPath + "'\n" +
		"    else\n" +
		"      exec '" + realGo + "' list ./...\n" +
		"    fi ;;\n" +
		"  test) exit 0 ;;\n" +
		"  *) exit 0 ;;\n" +
		"esac\n"

	stubPath := filepath.Join(dir, "go")
	if err := os.WriteFile(stubPath, []byte(stub), 0o755); err != nil {
		t.Fatalf("writing the stub go: %v", err)
	}

	cmd := exec.CommandContext(t.Context(), filepath.Join(root, "bin", "prime"), "--fast")
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	out, err := cmd.CombinedOutput()

	// The refusal is the assertion: a non-zero exit naming the victim.
	if err == nil {
		t.Fatalf("bin/prime --fast accepted a pool-opening package that is not declared in gate.yml's db tier.\n"+
			"The stub claimed %s links dbtest; the fast tier must refuse, not run.\nOutput:\n%s", victim, out)
	}
	if !strings.Contains(string(out), victim) {
		t.Errorf("bin/prime --fast refused, but not because of the undeclared pool package.\n"+
			"It should name %s. Output:\n%s", victim, out)
	}

	// The stub was actually invoked for each step, so the refusal was earned
	// rather than vacuous.
	log := readAll(t, logPath)
	for _, want := range []string{"go mod download", "go build", "go list ./...", "go list -test"} {
		if !strings.Contains(log, want) {
			t.Errorf("the stub go was never invoked as %q, so the refusal above proves nothing.\nInvocation log:\n%s", want, log)
		}
	}
}
