package httpapi


import (
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

const (
	v1Document     = "../../openapi/v1.yaml"
	openidDocument = "../../openid/openid.yaml"
)

var knownDrift = map[operationKey]string{}

type drift struct {
	DocumentedNotServed []string
	ServedNotDocumented []string
	Unexplained []string
}

func diff(contract map[operationKey]documentedOperation, served map[operationKey]string, known map[operationKey]string) drift {
	var out drift

	for key := range contract {
		if _, ok := served[key]; !ok {
			out.DocumentedNotServed = append(out.DocumentedNotServed, key.String())
		}
	}
	for key := range served {
		if _, ok := contract[key]; ok {
			continue
		}
		label := key.String()
		out.ServedNotDocumented = append(out.ServedNotDocumented, label)
		if _, admitted := known[key]; !admitted {
			out.Unexplained = append(out.Unexplained, label)
		}
	}

	sort.Strings(out.DocumentedNotServed)
	sort.Strings(out.ServedNotDocumented)
	sort.Strings(out.Unexplained)
	return out
}

func readTheContract(t *testing.T) map[operationKey]documentedOperation {
	t.Helper()

	contract := map[operationKey]documentedOperation{}
	for _, path := range []string{v1Document, openidDocument} {
		doc, err := readOpenAPIDocument(path)
		if err != nil {
			t.Fatalf("reading the contract: %v", err)
		}
		for key, op := range doc.Operations {
			if existing, clash := contract[key]; clash {
				t.Fatalf("%s and %s both declare %s, as %s and %s. Two documents describing "+
					"one operation means a generator has to pick one and this service has "+
					"not said which.", v1Document, path, key, existing.OperationID, op.OperationID)
			}
			contract[key] = op
		}
	}
	return contract
}

func servedRoutes(t *testing.T) map[operationKey]string {
	t.Helper()

	o := options{
		auth:         newFakeAuth(),
		deletion:     newFakeDeletion(),
		tenancy:      newFakeTenancy(),
		oidcClients:  newFakeOIDCClients(),
		oidc:         newFakeOIDC(),
		apiKeys:      newFakeAPIKeys(),
		mfa:          newFakeMFAManage(),
		introspector: newFakeIntrospector(),
		admin: newFakeAdmin(),
		recovery: newFakeRecovery(),
		social: newFakeSocial(),
		signup: newFakeSignup(),
		agents: newFakeAgents(),
	}

	served := map[operationKey]string{}
	err := chi.Walk(newMux(nil, o), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		key := operationKey{Method: method, Path: normalisePath(route)}
		if existing, clash := served[key]; clash {
			t.Fatalf("the router serves %s twice, at %s and at %s. Two registrations that "+
				"normalise onto one route is a routing decision this check cannot see, and "+
				"at runtime the second one is invisible too.", key, existing, route)
		}
		served[key] = route
		return nil
	})
	if err != nil {
		t.Fatalf("walking the router: %v", err)
	}
	if len(served) == 0 {
		t.Fatal("the router was read as serving no routes at all. A router-reading check that " +
			"finds nothing agrees with a document that finds nothing.")
	}
	return served
}


func TestEveryServedRouteIsDocumentedOrNamed(t *testing.T) {
	unexplained := diff(readTheContract(t), servedRoutes(t), knownDrift).Unexplained

	if len(unexplained) > 0 {
		sort.Strings(unexplained)
		t.Errorf("the router serves %d operation(s) that openapi/v1.yaml, openid/openid.yaml "+
			"and knownDrift all fail to account for:\n\n  %s\n\n"+
			"A route that is neither documented nor named is the failure this file exists to "+
			"catch, and the list must not become the place it hides. Do one of the two things:\n"+
			"  1. the route is part of the public surface — document it in openapi/v1.yaml or "+
			"openid/openid.yaml depending on which surface it is on, and give it an operationId.\n"+
			"  2. the route is not meant to be public — add it to knownDrift with the reason it "+
			"is not written down, and expect the pin on that list to fail so the addition gets "+
			"read rather than merged.\n\n"+
			"Do not add a prefix filter. A filter is a guess about intent, and it cannot see a "+
			"method — which is how PUT /v1/customers/{id} went on being served in billing under "+
			"a check that read paths only.",
			len(unexplained), strings.Join(unexplained, "\n  "))
	}
}

func TestEveryDocumentedOperationIsServed(t *testing.T) {
	contract := readTheContract(t)
	served := servedRoutes(t)
	unserved := diff(contract, served, knownDrift).DocumentedNotServed

	if len(unserved) > 0 {
		sort.Strings(unserved)
		t.Errorf("the documents declare %d operation(s) the router does not serve:\n\n  %s\n\n"+
			"A generated client calls these and gets a 404. Do one of the two things:\n"+
			"  1. the operation is shipping — mount it.\n"+
			"  2. it is not — delete it from the document, and note the removal in the CHANGELOG.",
			len(unserved), strings.Join(unserved, "\n  "))
	}
}


func TestKnownDriftIsEmptyBecauseEveryServedOperationIsDocumented(t *testing.T) {
	const want = 0

	if len(knownDrift) == want {
		return
	}

	names := make([]string, 0, len(knownDrift))
	for key, reason := range knownDrift {
		names = append(names, key.String()+" — "+reason)
	}
	sort.Strings(names)

	t.Errorf("knownDrift has %d entr(ies) and this file records %d: every route the router "+
		"serves is in openapi/v1.yaml or openid/openid.yaml.\n\n  %s\n\n"+
		"This map is NOT an exclusion list. An exclusion list says \"this is not part of "+
		"the contract\" and an entry in it is a claim about intent; an entry in THIS map "+
		"says \"this is served and written down nowhere\", and an entry is an admission "+
		"that the contract is missing an operation. Merging the two meanings is how a "+
		"future route gets excused by being called a bug.\n\n"+
		"Do one of the two things, and then DELETE the entry — which is the only way one "+
		"is ever removed:\n"+
		"  1. it is part of the public surface. Document it in openapi/v1.yaml or "+
		"openid/openid.yaml, whichever surface it is on, with an operationId. Ten tenancy "+
		"operations and two OIDC POSTs were closed exactly this way by packets identity-28 "+
		"and identity-11, and the list went to zero rather than growing.\n"+
		"  2. it is genuinely not contract surface. Record that in the document's header "+
		"AND in the README's endpoint table, in prose a consumer reads, and put the "+
		"reason here. Expect this test to fail either way — that is the point. A decision "+
		"to leave a route undocumented is three review-visible edits, not one line.\n\n"+
		"NEVER grow this list to make a red go away, and never add a prefix filter to the "+
		"check. A filter is a guess about intent and it cannot see a method — which is how "+
		"PUT /v1/customers/{id} went on being served in billing under a check that read "+
		"paths only.",
		len(knownDrift), want, strings.Join(names, "\n  "))
}

func TestKnownDriftNamesOnlyServedRoutes(t *testing.T) {
	contract := readTheContract(t)
	served := servedRoutes(t)

	for key, reason := range knownDrift {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("the knownDrift entry for %s has no reason. An entry with no reason is "+
				"an assertion, and an assertion is not reviewable.", key)
		}
		if op, documented := contract[key]; documented {
			t.Errorf("%s is in knownDrift and is also declared by a document, as %s. It is "+
				"documented, so it is not drift — remove the entry.", key, op.OperationID)
		}
		if _, ok := served[key]; !ok {
			t.Errorf("the knownDrift entry for %s names a route the router does not serve. "+
				"Drift is served-but-unwritten-down, so this entry has stopped meaning "+
				"anything and the list is lying about the size of the gap.", key)
		}
	}
}

func TestTheProbesAreDocumentedRatherThanExcluded(t *testing.T) {
	contract := readTheContract(t)

	for _, probe := range []string{"/healthz", "/readyz"} {
		key := operationKey{Method: "GET", Path: probe}
		if _, ok := contract[key]; !ok {
			t.Errorf("GET %s is not in either document. This file's header records that "+
				"identity documents its probes rather than excluding them, and if that has "+
				"changed then the header is wrong and the exclusion has to be written down "+
				"with a reason instead.", probe)
		}
	}
}


func TestEveryOperationHasAnOperationIdAndNoOperationIdIsUsedTwice(t *testing.T) {
	contract := readTheContract(t)

	byID := map[string][]operationKey{}
	for key, op := range contract {
		if op.OperationID == "" {
			t.Errorf("%s declares no operationId. That is the name of the method on a "+
				"generated client, so the operation is in the contract and in no client.", key)
			continue
		}
		byID[op.OperationID] = append(byID[op.OperationID], key)
	}

	for id, keys := range byID {
		if len(keys) > 1 {
			names := make([]string, 0, len(keys))
			for _, key := range keys {
				names = append(names, key.String())
			}
			sort.Strings(names)
			t.Errorf("the operationId %q is used by %d operations (%s). A generator emits "+
				"them as one method name and the second operation is unreachable from any "+
				"client.", id, len(keys), strings.Join(names, ", "))
		}
	}
}

func TestTheDocumentIsOpenAPI31AndCarriesAVersion(t *testing.T) {
	doc, err := readOpenAPIDocument(v1Document)
	if err != nil {
		t.Fatalf("reading %s: %v", v1Document, err)
	}

	if doc.SpecVersion != "3.1.0" {
		t.Errorf("%s declares openapi %q, not 3.1.0. 3.1 is what core's conventions require "+
			"and what makes `null` a valid type rather than a keyword that changes meaning.",
			v1Document, doc.SpecVersion)
	}

	const want = "1.17.0"
	if doc.InfoVersion != want {
		t.Errorf("%s declares info.version %q, not %q. core's sync rule is that the /v1 "+
			"prefix says which contract and this says which build of it, and a non-breaking "+
			"addition bumps this and nothing else. If the document gained operations, move "+
			"this pin in the same commit and say so in the CHANGELOG.",
			v1Document, doc.InfoVersion, want)
	}
}
