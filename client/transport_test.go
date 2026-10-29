package client



import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/anywaye/identity/client/generated"
)

const generatedModule = "github.com/oapi-codegen/runtime"

func TestTheServiceBinaryDoesNotReachTheGeneratedClient(t *testing.T) {
	root := repoRoot(t)

	if _, err := exec.LookPath("go"); err != nil {
		t.Fatalf("go is not on PATH, so the dependency graph cannot be read: %v", err)
	}

	cmd := exec.CommandContext(t.Context(), "go", "list", "-deps", "./cmd/identity")
	cmd.Dir = root

	var stdout strings.Builder
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		t.Fatalf("go list -deps ./cmd/identity: %v\n"+
			"Without this the claim below cannot be checked at all, and a check that "+
			"cannot run is not a check.", err)
	}

	dependencies := strings.Split(stdout.String(), "\n")

	if len(strings.TrimSpace(stdout.String())) == 0 {
		t.Fatalf("`go list -deps ./cmd/identity` reported no dependencies at all, so this " +
			"check is reading nothing and would pass for the wrong reason.\n" +
			"The service imports pgx, chi and log/slog; a graph with none of them is not " +
			"a graph.")
	}

	for _, dependency := range dependencies {
		if strings.TrimSpace(dependency) == generatedModule {
			t.Errorf("%s reaches ./cmd/identity, so the service's binary now carries "+
				"oapi-codegen's runtime.\n\n"+
				"That is a supply-chain change to the artifact every anywaye service ships, "+
				"made by a client nobody asked for. DECISIONS.md D6 records that this "+
				"package does not reach the binary; if that has stopped being true, D2 is "+
				"wrong and the fix is to find the import that reached for it, not to edit "+
				"this test.\n\n"+
				"Full dependency list is %d packages; `go mod why %s` says who pulled it in.",
				generatedModule, len(dependencies), generatedModule)
		}
	}

	found := false
	for _, dependency := range dependencies {
		if strings.TrimSpace(dependency) == "github.com/anywaye/identity/client" {
			found = true
		}
	}
	if found {
		t.Errorf("./cmd/identity imports github.com/anywaye/identity/client.\n" +
			"The client is for CONSUMERS of identity, not for identity itself. A service " +
			"that called its own API over HTTP would add a network hop and a dependency " +
			"to itself for no benefit — it has the stores already.")
	}
}

func TestTheGeneratorIsNotAModuleDependency(t *testing.T) {
	root := repoRoot(t)

	raw, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}

	for i, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "github.com/oapi-codegen/oapi-codegen") {
			continue
		}
		t.Errorf("go.mod:%d requires the GENERATOR: %s\n\n"+
			"`go run <module>@<version>` runs in module-aware mode and ignores this "+
			"module's go.mod, so pinning the generator in a `//go:generate` line keeps it "+
			"out of the dependency graph — which is the same relationship goose is in "+
			"for migrations/README.md, and the reason `go.sum` does not move when the "+
			"generator is bumped. A `require` line here would put ten thousand lines of "+
			"generator and its own dependency tree into every consumer of this module.",
			i+1, trimmed)
	}
}

func TestTheTransportCoversEveryOperationInTheDocument(t *testing.T) {
	root := repoRoot(t)

	document := filepath.Join(root, "openapi", "v1.yaml")
	raw, err := os.ReadFile(document)
	if err != nil {
		t.Fatalf("reading %s: %v", document, err)
	}

	inDocument := regexp.MustCompile(`(?m)^\s*operationId:\s*(\S+)\s*$`).FindAllStringSubmatch(
		string(raw), -1)

	if len(inDocument) == 0 {
		t.Fatalf("%s declares no operationId at all.\n"+
			"A reader that finds nothing agrees with a document that has nothing in it, "+
			"and this check would pass while covering no operations — which is the shape "+
			"of failure `internal/httpapi`'s document-versus-router tripwire was written "+
			"to prevent.", document)
	}

	declared := map[string]bool{}
	for _, match := range inDocument {
		declared[strings.ToLower(match[1])] = true
	}

	transportSource := filepath.Join(root, "client", "transport.go")
	source, err := os.ReadFile(transportSource)
	if err != nil {
		t.Fatalf("reading %s: %v", transportSource, err)
	}

	method := regexp.MustCompile(`(?m)^\t([A-Z][A-Za-z0-9]*)\(ctx context\.Context`)
	implemented := map[string]bool{}
	for _, match := range method.FindAllStringSubmatch(string(source), -1) {
		implemented[strings.ToLower(match[1])] = true
	}

	if len(implemented) == 0 {
		t.Fatalf("no methods were read out of %s.\n"+
			"The pattern below no longer matches the interface's shape, so this check is "+
			"reading nothing and would pass while the transport covered nothing.",
			transportSource)
	}

	var missing []string
	for name := range declared {
		if !implemented[name] {
			missing = append(missing, name)
		}
	}

	if len(missing) > 0 {
		sortStrings(missing)
		t.Errorf("openapi/v1.yaml declares %d operationId(s) the Transport interface has "+
			"no method for:\n\n  %s\n\n"+
			"The interface DOES satisfy the generated client — that is the compile-time "+
			"assertion in transport.go — and it can do that while being incomplete. That "+
			"is the shape of drift this check exists for: the document gains an operation, "+
			"the generator emits it, and the wrapper never wraps it, so a caller has a "+
			"route they cannot call.\n\n"+
			"Add a method to Transport and a wrapper method to Client. Do not delete this "+
			"operation from the document to make it go away: the drift gate holds the two "+
			"documents to the router in both directions, and the router serves it.",
			len(missing), strings.Join(missing, "\n  "))
	}

	for name := range implemented {
		if !declared[name] {
			t.Errorf("Transport has a method %q that openapi/v1.yaml declares no "+
				"operationId for.\n"+
				"Either the document lost an operationId (which `TestEveryOperationHasAn"+
				"OperationId` in internal/httpapi would also catch) or the interface has "+
				"kept a method for an operation that is gone.", name)
		}
	}
}

func TestTheGeneratedProblemEnumIsUsedRatherThanAString(t *testing.T) {
	root := repoRoot(t)

	source, err := os.ReadFile(filepath.Join(root, "client", "errors.go"))
	if err != nil {
		t.Fatalf("reading client/errors.go: %v", err)
	}

	text := string(source)

	if !strings.Contains(text, "var problemTypes = map[string]func(problem) error{") {
		t.Error("client/errors.go no longer keys its code table as a map[string] of " +
			"constructors.\nThe table is what makes the fallback visible: a missing " +
			"entry reads as \"a code this build has not seen\", which is what it means.")
	}

	for _, code := range []generated.ProblemCode{
		generated.ProblemCodeUnauthorized,
		generated.ProblemCodeForbidden,
		generated.ProblemCodeNotFound,
		generated.ProblemCodeConflict,
		generated.ProblemCodeValidationFailed,
		generated.ProblemCodeRateLimited,
		generated.ProblemCodeAccountLocked,
	} {
		if code == "" {
			t.Error("the generated ProblemCode enum carries an empty value")
		}
		if !strings.Contains(text, strconv.Quote(string(code))) {
			t.Errorf("the code table does not contain %q.\n"+
				"It exists in the document and in the generated enum, so a missing row "+
				"means every response carrying it falls to *UnknownProblemError — which "+
				"works, but loses the specific type a caller may branch on.",
				string(code))
		}
	}
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
