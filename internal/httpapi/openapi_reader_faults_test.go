package httpapi


import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func writeDocument(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "v1.yaml")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("writing the test document: %v", err)
	}
	return path
}

func keysOf(doc openAPIDocument) []string {
	out := make([]string, 0, len(doc.Operations))
	for key := range doc.Operations {
		out = append(out, key.String())
	}
	sort.Strings(out)
	return out
}

func mustRead(t *testing.T, lines ...string) openAPIDocument {
	t.Helper()
	doc, err := readOpenAPIDocument(writeDocument(t, lines...))
	if err != nil {
		t.Fatalf("the reader refused a document it should have read: %v", err)
	}
	return doc
}

func TestTheReaderTakesThePathsAndTheMethodsAndNothingElse(t *testing.T) {
	doc := mustRead(t,
		"openapi: 3.1.0",
		"info:",
		"  title: identity",
		"  version: 9.9.9",
		"paths:",
		"  /v1/widgets:",
		"    get:",
		"      operationId: listWidgets",
		"    post:",
		"    patch:",
		"    delete:",
		"  /v1/widgets/{id}:",
		"    parameters:",
		"      - $ref: '#/components/parameters/WidgetId'",
		"    get:",
		"    put:",
		"components:",
		"  schemas:",
		"    Widget:",
		"      type: object",
	)

	want := []string{
		"DELETE /v1/widgets", "GET /v1/widgets", "GET /v1/widgets/{}",
		"PATCH /v1/widgets", "POST /v1/widgets", "PUT /v1/widgets/{}",
	}
	if got := keysOf(doc); !equalStrings(got, want) {
		t.Errorf("the reader found\n  %v\nand not\n  %v", got, want)
	}

	if doc.SpecVersion != "3.1.0" {
		t.Errorf("spec version is %q, not 3.1.0", doc.SpecVersion)
	}
	if doc.InfoVersion != "9.9.9" {
		t.Errorf("info.version is %q, not 9.9.9", doc.InfoVersion)
	}
}

func TestTheReaderKeepsTheSpellingsTheSourceUsed(t *testing.T) {
	doc := mustRead(t, "openapi: 3.1.0", "info:", "  version: 1.0.0",
		"paths:", "  /v1/widgets/{widget_id}:", "    get:")

	key := operationKey{Method: "GET", Path: "/v1/widgets/{}"}
	if got := doc.Operations[key].Path; got != "/v1/widgets/{widget_id}" {
		t.Errorf("the operation is named %q; a failure has to show the path as the "+
			"document wrote it, which is %q", got, "/v1/widgets/{widget_id}")
	}
}

func TestTheReaderReadsTheOperationIdAndOnlyTheOperationsOwn(t *testing.T) {
	doc := mustRead(t,
		"openapi: 3.1.0", "info:", "  version: 1.0.0",
		"paths:",
		"  /v1/widgets:",
		"    get:",
		"      operationId: listWidgets",
		"      responses:",
		"        '200':",
		"          content:",
		"            application/json:",
		"              examples:",
		"                one:",
		"                  value:",
		"                    operationId: notThisOne",
	)

	op := doc.Operations[operationKey{Method: "GET", Path: "/v1/widgets"}]
	if op.OperationID != "listWidgets" {
		t.Errorf("the operationId is %q, not %q. The field inside the example is the "+
			"payload's, not the operation's.", op.OperationID, "listWidgets")
	}
}

func TestAKeyThatMerelyStartsWithAMethodNameIsNotAnOperation(t *testing.T) {
	doc := mustRead(t, "openapi: 3.1.0", "info:", "  version: 1.0.0",
		"paths:", "  /v1/widgets:", "    get:", "    getaway:", "    posting:")

	if got := len(doc.Operations); got != 1 {
		t.Errorf("the reader found %d operations, and only `get:` is one", got)
	}
}

func TestCommentsAndBlankLinesInsideTheBlockAreSkipped(t *testing.T) {
	doc := mustRead(t,
		"openapi: 3.1.0", "info:", "  version: 1.0.0",
		"paths:",
		"  # the only surface this document ships",
		"  /v1/widgets:",
		"",
		"    # listing",
		"    get:",
		"")

	if got := len(doc.Operations); got != 1 {
		t.Errorf("the reader found %d operations, want 1", got)
	}
}

func TestTheTwoIndentationLevelsAreDerivedFromTheDocumentNotAssumed(t *testing.T) {
	doc := mustRead(t, "openapi: 3.1.0", "info:", "    version: 1.0.0",
		"paths:", "    /v1/widgets:", "        get:", "        post:")

	if got := len(doc.Operations); got != 2 {
		t.Errorf("the reader found %d operations in a four-space document, want 2", got)
	}
}

func TestAnythingDeeperThanTheOperationLevelIsAnOperationsBody(t *testing.T) {
	doc := mustRead(t,
		"openapi: 3.1.0", "info:", "  version: 1.0.0",
		"paths:",
		"  /v1/widgets/{id}:",
		"    parameters:",
		"      - $ref: '#/components/parameters/WidgetId'",
		"        description:",
		"          deeper still, inside the list entry",
		"    get:",
		"      responses:",
		"        '200':",
		"          description: ok",
		"          content:",
		"            application/json:",
		"              schema:",
		"                type: object")

	want := []string{"GET /v1/widgets/{}"}
	if got := keysOf(doc); !equalStrings(got, want) {
		t.Errorf("the reader found\n  %v\nand not\n  %v", got, want)
	}
}

func TestAKeyInsideABodySpelledLikeAMethodIsNotAnOperation(t *testing.T) {
	doc := mustRead(t,
		"openapi: 3.1.0", "info:", "  version: 1.0.0",
		"paths:",
		"  /v1/widgets:",
		"    get:",
		"      responses:",
		"        '200':",
		"          content:",
		"            application/json:",
		"              schema:",
		"                properties:",
		"                  delete:",
		"                    type: boolean",
		"                  patch:",
		"                    type: boolean",
		"    post:",
		"      requestBody:",
		"        content:",
		"          application/json:",
		"            schema:",
		"              properties:",
		"                get:",
		"                  type: string")

	want := []string{"GET /v1/widgets", "POST /v1/widgets"}
	if got := keysOf(doc); !equalStrings(got, want) {
		t.Errorf("the reader found\n  %v\nand not\n  %v — a body key spelled like a method "+
			"is not an operation", got, want)
	}
}

func TestAPathItemsOwnFieldsAreNotOperations(t *testing.T) {
	doc := mustRead(t, "openapi: 3.1.0", "info:", "  version: 1.0.0",
		"paths:", "  /v1/widgets:", "    summary: widgets", "    get:")

	if got := len(doc.Operations); got != 1 {
		t.Errorf("the reader found %d operations; `summary` is a Path Item Object field, "+
			"not an operation", got)
	}
}


func TestTheReaderRefusesRatherThanUnderReading(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lines []string
		want  string
	}{
		{
			name:  "a document with no top-level paths:",
			lines: []string{"openapi: 3.1.0", "info:", "  title: identity", "  version: 1.0.0"},
			want:  "no top-level `paths:`",
		},
		{
			name:  "a paths: block with nothing under it",
			lines: []string{"openapi: 3.1.0", "info:", "  version: 1.0.0", "paths:"},
			want:  "documents no operations",
		},
		{
			name: "a paths: block with one indentation level and no operations",
			lines: []string{"openapi: 3.1.0", "info:", "  version: 1.0.0",
				"paths:", "  /v1/widgets:"},
			want: "documents no operations",
		},
		{
			name: "a path item with no operation under it",
			lines: []string{"openapi: 3.1.0", "info:", "  version: 1.0.0",
				"paths:", "  /v1/widgets:", "    parameters:", "      - $ref: x"},
			want: "no operation under it",
		},
		{
			name: "a path key that does not start with a slash",
			lines: []string{"openapi: 3.1.0", "info:", "  version: 1.0.0",
				"paths:", "  v1/widgets:", "    get:"},
			want: "not a valid OpenAPI path",
		},
		{
			name: "a direct child of paths: that is neither a path nor a path-item field",
			lines: []string{"openapi: 3.1.0", "info:", "  version: 1.0.0",
				"paths:", "  widget:", "    get:"},
			want: "not a valid OpenAPI path",
		},
		{
			name:  "a document with no openapi: key",
			lines: []string{"info:", "  version: 1.0.0", "paths:", "  /v1/widgets:", "    get:"},
			want:  "no top-level `openapi:`",
		},
		{
			name:  "a document with no info.version",
			lines: []string{"openapi: 3.1.0", "info:", "  title: identity", "paths:", "  /v1/widgets:", "    get:"},
			want:  "no `info.version`",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readOpenAPIDocument(writeDocument(t, tc.lines...))
			if err == nil {
				t.Fatalf("the reader accepted a document it must refuse, so the check " +
					"would compare nothing and agree with nothing")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal does not say %q:\n  %v", tc.want, err)
			}
		})
	}
}

func TestAMissingDocumentIsAnError(t *testing.T) {
	_, err := readOpenAPIDocument(filepath.Join(t.TempDir(), "absent.yaml"))
	if err == nil || !strings.Contains(err.Error(), "could not read") {
		t.Fatalf("reading a missing document returned %v; a reader that finds no file "+
			"finds no paths, and a check over none passes", err)
	}
}

func TestTwoOperationsThatNormaliseOntoOneAreAnError(t *testing.T) {
	_, err := readOpenAPIDocument(writeDocument(t,
		"openapi: 3.1.0", "info:", "  version: 1.0.0",
		"paths:", "  /v1/widgets/{id}:", "    get:", "  /v1/widgets/{name}:", "    get:"))

	if err == nil || !strings.Contains(err.Error(), "both read as GET /v1/widgets/{}") {
		t.Fatalf("the reader accepted two paths that are one route to a client: %v", err)
	}
}


func TestARenamedPathParameterIsNotDrift(t *testing.T) {
	if got := normalisePath("/v1/accounts/{accountID}"); got != normalisePath("/v1/accounts/{account_id}") {
		t.Errorf("chi's `{accountID}` and the document's `{account_id}` normalise to %q "+
			"and %q; they are one route", got, normalisePath("/v1/accounts/{account_id}"))
	}
}

func TestTheParameterNameIsTheOnlyThingErasedAndOnlyInsideASegment(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"/v1/widgets/{id}", "/v1/widgets/{}"},
		{"/v1/widgets/:id", "/v1/widgets/{}"},
		{"/v1/widgets/extra", "/v1/widgets/extra"},
		{"/v1/widgets", "/v1/widgets"},
		{"/v1/widgets/{id}/parts/{part_id}", "/v1/widgets/{}/parts/{}"},
		{"/v1/widgets/{id}/parts", "/v1/widgets/{}/parts"},
		{"/v1/widgets/{id}.json", "/v1/widgets/{}"},
		{"/v1/widgets/:id.json", "/v1/widgets/{}"},
	} {
		if got := normalisePath(tc.in); got != tc.want {
			t.Errorf("normalisePath(%q) is %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestATrailingSlashIsNotADifference(t *testing.T) {
	if got := normalisePath("/healthz/"); got != "/healthz" {
		t.Errorf("normalisePath(\"/healthz/\") is %q, want /healthz", got)
	}
	if got := normalisePath("/healthz//"); got != "/healthz" {
		t.Errorf("normalisePath(\"/healthz//\") is %q, want /healthz", got)
	}
}

func TestTheRootPathKeepsItsSlash(t *testing.T) {
	if got := normalisePath("/"); got != "/" {
		t.Errorf("normalisePath(\"/\") is %q; stripping it would produce an empty path "+
			"that compares equal to nothing", got)
	}
}



func contractOf(pairs ...string) map[operationKey]documentedOperation {
	out := map[operationKey]documentedOperation{}
	for _, pair := range pairs {
		fields := strings.SplitN(pair, " ", 2)
		key := operationKey{Method: fields[0], Path: normalisePath(fields[1])}
		out[key] = documentedOperation{Method: fields[0], Path: fields[1], OperationID: "x"}
	}
	return out
}

func servedOf(pairs ...string) map[operationKey]string {
	out := map[operationKey]string{}
	for _, pair := range pairs {
		fields := strings.SplitN(pair, " ", 2)
		out[operationKey{Method: fields[0], Path: normalisePath(fields[1])}] = fields[1]
	}
	return out
}

func TestTheComparisonNamesADocumentedOperationTheRouterDoesNotServe(t *testing.T) {
	got := diff(
		contractOf("GET /v1/widgets", "GET /v1/gadgets"),
		servedOf("GET /v1/widgets"),
		nil)

	if !equalStrings(got.DocumentedNotServed, []string{"GET /v1/gadgets"}) {
		t.Errorf("the forward direction reported %v, want [GET /v1/gadgets]",
			got.DocumentedNotServed)
	}
	if len(got.ServedNotDocumented) != 0 {
		t.Errorf("the reverse direction reported %v and should have reported nothing",
			got.ServedNotDocumented)
	}
}

func TestTheComparisonNamesAServedOperationNoDocumentDescribes(t *testing.T) {
	got := diff(
		contractOf("GET /v1/widgets"),
		servedOf("GET /v1/widgets", "GET /v1/gadgets"),
		nil)

	if !equalStrings(got.Unexplained, []string{"GET /v1/gadgets"}) {
		t.Errorf("the reverse direction reported %v, want [GET /v1/gadgets]", got.Unexplained)
	}
	if len(got.DocumentedNotServed) != 0 {
		t.Errorf("the forward direction reported %v and should have reported nothing",
			got.DocumentedNotServed)
	}
}

func TestTheComparisonReportsARenamedPathOnBothSides(t *testing.T) {
	got := diff(
		contractOf("GET /v1/widgets", "GET /v1/wodgets/{id}"),
		servedOf("GET /v1/widgets", "GET /v1/widgets/{id}"),
		nil)

	if !equalStrings(got.DocumentedNotServed, []string{"GET /v1/wodgets/{}"}) {
		t.Errorf("the forward direction reported %v, want [GET /v1/wodgets/{}]",
			got.DocumentedNotServed)
	}
	if !equalStrings(got.Unexplained, []string{"GET /v1/widgets/{}"}) {
		t.Errorf("the reverse direction reported %v, want [GET /v1/widgets/{}]",
			got.Unexplained)
	}
}

func TestAMethodAddedOnOneSideOnlyIsDriftEvenThoughThePathMatches(t *testing.T) {
	document := contractOf("GET /v1/widgets")
	agreed := servedOf("GET /v1/widgets")

	if got := diff(document, agreed, nil); len(got.Unexplained) != 0 {
		t.Fatalf("the agreed pair already reports %v", got.Unexplained)
	}

	withDelete := servedOf("GET /v1/widgets", "DELETE /v1/widgets")
	got := diff(document, withDelete, nil)

	if !equalStrings(got.Unexplained, []string{"DELETE /v1/widgets"}) {
		t.Errorf("adding a second method to an already-documented path reported %v, want "+
			"[DELETE /v1/widgets]. A path-only or count comparison passes here.", got.Unexplained)
	}
	if len(got.DocumentedNotServed) != 0 {
		t.Errorf("the forward direction reported %v; the path set did not change, so it "+
			"should not have moved", got.DocumentedNotServed)
	}
}

func TestAnAdmissionCoversTheOperationItNamesAndNotAnotherMethodOnTheSamePath(t *testing.T) {
	document := contractOf("GET /v1/widgets")
	router := servedOf("GET /v1/widgets", "GET /healthz", "DELETE /healthz")

	admitted := map[operationKey]string{
		{Method: "GET", Path: "/healthz"}: "an infrastructure probe",
	}

	got := diff(document, router, admitted)

	if !equalStrings(got.ServedNotDocumented, []string{"DELETE /healthz", "GET /healthz"}) {
		t.Errorf("the served-but-undocumented set is %v, want both methods on /healthz",
			got.ServedNotDocumented)
	}
	if !equalStrings(got.Unexplained, []string{"DELETE /healthz"}) {
		t.Errorf("the unexplained set is %v, want [DELETE /healthz]. An admission keyed by "+
			"path would have covered both methods, which is how an undocumented method "+
			"survives a check that looks like it is holding the line.", got.Unexplained)
	}
}

func TestTheComparisonReportsEveryOffenderAndNotTheFirst(t *testing.T) {
	got := diff(
		contractOf("GET /v1/a", "GET /v1/b"),
		servedOf("GET /v1/c", "GET /v1/d", "GET /v1/e"),
		nil)

	want := []string{"GET /v1/c", "GET /v1/d", "GET /v1/e"}
	if !equalStrings(got.Unexplained, want) {
		t.Errorf("the comparison reported %v, want all of %v. Reporting one at a time turns "+
			"\"run the test, fix, run it again\" into a loop whose length nobody can see.",
			got.Unexplained, want)
	}
	if !equalStrings(got.DocumentedNotServed, []string{"GET /v1/a", "GET /v1/b"}) {
		t.Errorf("the forward direction reported %v, want both", got.DocumentedNotServed)
	}
}

func TestTwoEmptySetsAgreeAndThatIsNotAReasonToTrustTheComparison(t *testing.T) {
	got := diff(map[operationKey]documentedOperation{}, map[operationKey]string{}, nil)
	if len(got.Unexplained)+len(got.DocumentedNotServed) != 0 {
		t.Errorf("diff over two empty sets reported %v; it is supposed to report nothing, "+
			"and that is precisely why the readers must refuse rather than return empty",
			got)
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
