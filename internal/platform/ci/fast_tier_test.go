package ci


import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const dbtestImportPath = "github.com/anywaye/identity/internal/platform/dbtest"

const dbTierMarker = "#   db-tier: "

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

	var undeclaredPool string
	for _, p := range opens {
		undeclaredPool = p
		break
	}
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

	if err == nil {
		t.Fatalf("bin/prime --fast accepted a pool-opening package that is not declared in gate.yml's db tier.\n"+
			"The stub claimed %s links dbtest; the fast tier must refuse, not run.\nOutput:\n%s", victim, out)
	}
	if !strings.Contains(string(out), victim) {
		t.Errorf("bin/prime --fast refused, but not because of the undeclared pool package.\n"+
			"It should name %s. Output:\n%s", victim, out)
	}

	log := readAll(t, logPath)
	for _, want := range []string{"go mod download", "go build", "go list ./...", "go list -test"} {
		if !strings.Contains(log, want) {
			t.Errorf("the stub go was never invoked as %q, so the refusal above proves nothing.\nInvocation log:\n%s", want, log)
		}
	}
}
