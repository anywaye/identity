package ci


import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/anywaye/identity/internal/httpapi"
	"github.com/anywaye/identity/internal/oidc"
	"github.com/anywaye/identity/internal/platform/clock"
)

var htmlExtensions = []string{".html", ".htm", ".tmpl", ".gohtml", ".tpl"}

var htmlMarkers = []string{"text/html", "<html", "<form", "<!doctype", "<!DOCTYPE"}

func TestNoViewFileIsCommitted(t *testing.T) {
	files, err := trackedFiles(t)
	if err != nil {
		t.Fatalf("listing the repository's files: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no files were listed, so this walked nothing and passed for the wrong reason")
	}

	for _, name := range files {
		ext := strings.ToLower(filepath.Ext(name))
		for _, candidate := range htmlExtensions {
			if ext == candidate {
				t.Errorf("%s is committed. `identity` renders no views: the sign-in form is a "+
					"page in `parlor`, and a template file in this tree is a page that is not "+
					"being removed.", name)
			}
		}
	}
}

func TestNoGoFileCarriesMarkup(t *testing.T) {
	allowances := map[string]string{
		"internal/platform/ci/no_html_test.go": "this file: the marker list itself is a " +
			"string literal, and a check that cannot name what it forbids cannot be written",
		"internal/platform/oauthtest/oauthtest.go": "a double for an EXTERNAL OAuth server, " +
			"which answers an authorize request with a body of its own choosing. It is not " +
			"this service and nothing in cmd/identity reaches it",
		"client/errors_test.go": "the generated client parsing a non-problem response: an " +
			"upstream proxy answering 502 with an HTML error page is real, and the test is " +
			"what proves the client survives it",
		"internal/httpapi/oidc_test.go": "an assertion that a Content-Type is ABSENT; " +
			"writing \"must not be text/html\" is the test",
		"internal/oidc/loginui_test.go": "a data:text/html URL as a login UI, which is one of " +
			"the values ValidateLoginUIURL refuses; writing the value is the test",
	}

	files, err := trackedFiles(t)
	if err != nil {
		t.Fatalf("listing the repository's files: %v", err)
	}

	used := map[string]bool{}
	for _, name := range files {
		if !strings.HasSuffix(name, ".go") {
			continue
		}
		if _, ok := allowances[name]; ok {
			used[name] = true
			continue
		}
		for _, hit := range markupIn(t, name) {
			t.Errorf("%s carries %s. `identity` renders no views, and the sign-in form is a "+
				"page in `parlor`. The defect this catches took the shape of an inline "+
				"html/template literal, and this is the other shape it could take: a "+
				"Content-Type set by hand.", name, hit)
		}
	}

	for name, reason := range allowances {
		if !used[name] {
			t.Errorf("the allowance for %s is stale: that file is not in the tree, so the "+
				"allowance is a permission with nothing behind it. Delete the entry — and "+
				"check that the reason it recorded is still true somewhere else.\nIt said: %s",
				name, reason)
		}
	}
}

func markupIn(t *testing.T, name string) []string {
	t.Helper()

	path := filepath.Join(repoRoot(t), name)
	parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ParseComments)
	if err != nil {
		t.Errorf("parsing %s: %v", name, err)
		return nil
	}

	var hits []string
	for _, spec := range parsed.Imports {
		if strings.Contains(strings.Trim(spec.Path.Value, `"`), "html/template") {
			hits = append(hits, "an import of html/template")
		}
	}
	ast.Inspect(parsed, func(node ast.Node) bool {
		literal, ok := node.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		for _, marker := range htmlMarkers {
			if strings.Contains(literal.Value, marker) {
				hits = append(hits, "a string literal carrying "+strconv.Quote(marker))
			}
		}
		return true
	})
	sort.Strings(hits)
	return hits
}

func TestNoResponseNamesADocument(t *testing.T) {
	handler := serviceRouter(t)

	for _, target := range []string{
		"/oidc/login/00000000-0000-4000-8000-000000000000",
		"/oidc/nope",
		"/oidc/authorize",
		"/.well-known/openid-configuration",
		"/.well-known/jwks.json",
		"/v1/users",
		"/v1/session",
		"/v1/me",
		"/v1/password-resets",
		"/healthz",
		"/readyz",
		"/nothing-here",
	} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			req := httptest.NewRequestWithContext(context.Background(), method, target, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if got := rec.Header().Get("Content-Type"); strings.Contains(got, "text/html") {
				t.Errorf("%s %s answered Content-Type %q; `identity` serves no documents",
					method, target, got)
			}
			if isRedirectStatus(rec.Code) {
				if body := rec.Body.String(); body != "" {
					t.Errorf("%s %s answered a %d with a %d-byte body:\n%s\n"+
						"net/http writes an HTML anchor for a redirect, which is why "+
						"internal/httpapi's oidcRedirect and delegateOIDC both write the "+
						"status themselves.", method, target, rec.Code, len(body), body)
				}
			}
		}
	}
}

func isRedirectStatus(status int) bool { return status >= 300 && status < 400 }

func trackedFiles(t *testing.T) ([]string, error) {
	out, err := exec.CommandContext(t.Context(), "git", "-C", repoRoot(t), "ls-files").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w\n%s", err, out)
	}
	var paths []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		paths = append(paths, filepath.ToSlash(line))
	}
	sort.Strings(paths)
	return paths, nil
}

func serviceRouter(t *testing.T) http.Handler {
	t.Helper()

	key := throwawaySigningKey(t)
	storage := oidc.NewStorage(nil, oidc.NewProfileReader(), nil, key, clock.System{}, nil, oidc.PathLogin)
	provider, err := oidc.NewProvider(oidc.Config{
		Issuer:     "https://identity.test",
		SigningKey: key,
		LoginUIURL: "https://login.example.com/sign-in/oidc",
	}, storage)
	if err != nil {
		t.Fatalf("building the provider: %v", err)
	}
	return httpapi.New(nil, httpapi.WithOIDC(provider))
}

func throwawaySigningKey(t *testing.T) *oidc.SigningKey {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating a signing key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshaling the signing key: %v", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	key, err := oidc.LoadSigningKey(string(encoded), "anywaye-no-html-test")
	if err != nil {
		t.Fatalf("loading the signing key: %v", err)
	}
	return key
}
