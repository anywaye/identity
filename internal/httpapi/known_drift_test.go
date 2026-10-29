package httpapi


import (
	"strings"
	"testing"
)

var documentedTwelve = []operationKey{
	{Method: "POST", Path: "/v1/accounts"},
	{Method: "GET", Path: "/v1/accounts"},
	{Method: "GET", Path: "/v1/accounts/{account_id}"},
	{Method: "PATCH", Path: "/v1/accounts/{account_id}"},
	{Method: "DELETE", Path: "/v1/accounts/{account_id}"},
	{Method: "GET", Path: "/v1/accounts/{account_id}/members"},
	{Method: "POST", Path: "/v1/accounts/{account_id}/invitations"},
	{Method: "PATCH", Path: "/v1/accounts/{account_id}/members/{user_id}"},
	{Method: "DELETE", Path: "/v1/accounts/{account_id}/members/{user_id}"},
	{Method: "POST", Path: "/v1/invitations/accept"},
	{Method: "POST", Path: "/oidc/authorize"},
	{Method: "POST", Path: "/oidc/userinfo"},
}

func TestTheTwelveThisPacketClosedAreCaughtAgainIfAnyOfThemReturns(t *testing.T) {
	if len(knownDrift) != 0 {
		t.Fatalf("knownDrift has %d entries, so this test is comparing against admissions "+
			"and the twelve below are not being measured on their own. That is a finding "+
			"about knownDrift, not about the comparison — read "+
			"TestKnownDriftIsEmptyBecauseEveryServedOperationIsDocumented first.",
			len(knownDrift))
	}

	full := readTheContract(t)
	before := map[operationKey]documentedOperation{}
	for key, op := range full {
		before[key] = op
	}
	for _, gone := range documentedTwelve {
		delete(before, operationKey{Method: gone.Method, Path: normalisePath(gone.Path)})
	}

	for _, gone := range documentedTwelve {
		key := operationKey{Method: gone.Method, Path: normalisePath(gone.Path)}
		if _, present := full[key]; !present {
			t.Fatalf("the two documents do not describe %s, so this packet closed nothing "+
				"and the assertion below would pass against a service that was never "+
				"documented. Fix the document or fix this test — do not let it rot.", key)
		}
		if _, still := before[key]; still {
			t.Fatalf("removing %s from the contract did not take, so the twelve below would "+
				"be unexplained for the wrong reason.", key)
		}
	}

	unexplained := diff(before, servedRoutes(t), knownDrift).Unexplained
	got := map[string]bool{}
	for _, name := range unexplained {
		got[name] = true
	}

	var missed []string
	for _, gone := range documentedTwelve {
		key := operationKey{Method: gone.Method, Path: normalisePath(gone.Path)}
		if !got[key.String()] {
			missed = append(missed, key.String())
		}
	}
	if len(missed) > 0 {
		sortStrings(missed)
		t.Errorf("with their document entries removed, %d of the twelve are NOT reported as "+
			"undocumented:\n\n  %s\n\n"+
			"The check that holds this repository's contract to its router does not see them. "+
			"Either diff stopped admitting what it cannot account for, or the empty knownDrift "+
			"is being consulted in some way this test cannot see — and both of those are the "+
			"failure a green suite would have hidden.",
			len(missed), strings.Join(missed, "\n  "))
	}

	if len(unexplained) != len(documentedTwelve) {
		names := append([]string(nil), unexplained...)
		sortStrings(names)
		t.Errorf("the pre-packet comparison reported %d unexplained operation(s), want exactly "+
			"the twelve:\n\n  %s\n\nA number other than twelve means the contract this test "+
			"reconstructed is not the pre-packet contract, and a check over the wrong set "+
			"proves nothing.", len(unexplained), strings.Join(names, "\n  "))
	}
}

func TestAnOperationTheDocumentDoesNotDescribeIsReported(t *testing.T) {
	served := servedRoutes(t)
	if len(served) == 0 {
		t.Fatal("the router was read as serving nothing, so there is no route to un-document.")
	}

	var victim operationKey
	for key := range served {
		victim = key
		break
	}

	contract := map[operationKey]documentedOperation{}
	for key, op := range readTheContract(t) {
		if key != victim {
			contract[key] = op
		}
	}

	got := diff(contract, served, knownDrift)
	if len(got.Unexplained) != 1 || got.Unexplained[0] != victim.String() {
		t.Errorf("with %s removed from the documents and left served, the check reported %v, "+
			"want exactly [%s].\n\n"+
			"This is the smallest possible statement of the property the check exists for: a "+
			"route that is served and documented nowhere, against an empty admission list, "+
			"has to be reported — otherwise the check is decoration and the next route nobody "+
			"wrote down goes straight through it.",
			victim, got.Unexplained, victim)
	}
	if len(got.DocumentedNotServed) != 0 {
		t.Errorf("taking one entry out of the documents reported %v as documented-but-unserved; "+
			"it is still served, so it belongs in Unexplained and nowhere else.",
			got.DocumentedNotServed)
	}
}
