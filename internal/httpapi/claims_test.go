package httpapi


import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

const (
	readmePath   = "../../README.md"
	manifestPath = "../../anywaye.yml"
)


var readmeAbsent = map[string]string{
	"/oidc/introspect":           "the OIDC provider declines it; absent from its discovery document",
	"/oidc/revoke":               "the OIDC provider declines it; absent from its discovery document",
	"/oidc/end-session":          "the OIDC provider declines it; absent from its discovery document",
	"/oidc/device_authorization": "the OIDC provider declines it; absent from its discovery document",
}

const readmeRouteRowsFloor = 45

func readmeClaims(t *testing.T) (map[operationKey]string, map[string]string) {
	t.Helper()

	raw, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("reading %s: %v", readmePath, err)
	}

	claims := map[operationKey]string{}
	absent := map[string]string{}
	rows := 0

	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for number := 1; scanner.Scan(); number++ {
		line := scanner.Text()
		if !strings.HasPrefix(strings.TrimSpace(line), "|") {
			continue
		}

		cell, ok := firstCell(line)
		if !ok {
			continue
		}
		spans := backtickSpans(cell)
		if len(spans) == 0 {
			continue
		}

		rowClaims, rowAbsent, isRouteRow, err := parseRouteCell(spans, number)
		if err != nil {
			t.Fatalf("%s:%d — %v", readmePath, number, err)
		}
		if !isRouteRow {
			continue
		}
		rows++

		for key, spelled := range rowClaims {
			if existing, clash := claims[key]; clash {
				t.Fatalf("%s:%d — %s and %s both read as %s. Two README rows describing one "+
					"route means one of them is describing something else.", readmePath, number,
					existing, spelled, key)
			}
			claims[key] = spelled
		}
		for path := range rowAbsent {
			absent[path] = cell
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("reading %s: %v", readmePath, err)
	}

	if rows < readmeRouteRowsFloor {
		t.Fatalf("%s has %d endpoint-table row(s) carrying a route; this check requires at "+
			"least %d. A reader that finds nothing agrees with a document that finds nothing, "+
			"and a table that was emptied or truncated would leave every remaining row correct "+
			"while the comparison below reported agreement between the README and the whole "+
			"router. Raise the floor if the surface really did shrink, and say so in the "+
			"CHANGELOG.", readmePath, rows, readmeRouteRowsFloor)
	}
	if len(claims) == 0 {
		t.Fatalf("%s's endpoint tables claim no operation at all. Nothing was read, so "+
			"nothing below can fail, and a check over nothing is green.", readmePath)
	}
	return claims, absent
}

func firstCell(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "|") {
		return "", false
	}
	rest := trimmed[1:]
	end := strings.Index(rest, "|")
	if end < 0 {
		return "", false
	}
	return strings.TrimSpace(rest[:end]), true
}

func backtickSpans(cell string) []string {
	var out []string
	for _, part := range strings.Split(cell, "`")[1:] {
		if before, _, found := strings.Cut(part, "`"); found {
			part = before
		}
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func parseRouteCell(spans []string, number int) (map[operationKey]string, map[string]bool, bool, error) {
	claims := map[operationKey]string{}
	absent := map[string]bool{}
	claimsRoutes := false

	for _, span := range spans {
		if !isRouteShaped(span) {
			continue
		}
		claimsRoutes = true

		if strings.HasPrefix(span, "/") {
			absent[normalisePath(span)] = true
			continue
		}

		methods, path, found := strings.Cut(span, " ")
		if !found || !strings.HasPrefix(path, "/") {
			return nil, nil, false, fmt.Errorf(
				"the cell quotes %q, which begins like a route — it starts with a method name or a "+
					"slash — but is not `METHOD /path` or a bare `/path`. A row this reader cannot "+
					"parse is a claim it would otherwise skip silently, and a skipped claim is "+
					"exactly how a check over a subset passes as a check over the whole table.", span)
		}

		for _, method := range strings.Split(methods, ",") {
			upper := strings.ToUpper(strings.TrimSpace(method))
			if !isHTTPMethod(upper) {
				return nil, nil, false, fmt.Errorf(
					"the cell quotes %q, whose method %q is not one of the eight HTTP method names. "+
						"Refusing rather than guessing: a method this reader cannot see is the same "+
						"blind spot a path-only comparison has, and that is how a served operation "+
						"ends up described nowhere.", span, method)
			}
			claims[operationKey{Method: upper, Path: normalisePath(strings.TrimSpace(path))}] = span
		}
	}

	if len(claims) > 0 && len(absent) > 0 {
		return nil, nil, false, fmt.Errorf(
			"the cell claims some operations are served and declares others are not. One row cannot " +
				"be a promise and a refusal at once, and this reader will not pick which half it " +
				"meant. Split them into two rows.")
	}
	if !claimsRoutes {
		return nil, nil, false, nil
	}
	return claims, absent, true, nil
}

func isRouteShaped(span string) bool {
	if strings.HasPrefix(span, "/") {
		return true
	}
	first, _, _ := strings.Cut(span, " ")
	upper := strings.ToUpper(first)
	for _, method := range openAPIOperationKeys {
		if strings.HasPrefix(upper, method) {
			return true
		}
	}
	return false
}

func isHTTPMethod(name string) bool {
	_, ok := openAPIOperationKeys[strings.ToLower(name)]
	return ok
}

func TestTheReadmeEndpointTablesAreTheRoutesTheRouterServes(t *testing.T) {
	claims, _ := readmeClaims(t)
	served := servedRoutes(t)

	var promised []string
	for key, spelled := range claims {
		if _, ok := served[key]; !ok {
			promised = append(promised, key.String()+"  (README spells it `"+spelled+"`)")
		}
	}
	sort.Strings(promised)

	if len(promised) > 0 {
		t.Errorf("README.md's endpoint tables advertise %d operation(s) this service does not "+
			"serve:\n\n  %s\n\n"+
			"A customer integrating from this README calls these and gets a 404, and the README "+
			"is the document a human reads before generating anything. Either the route is "+
			"shipping — mount it, document it in openapi/v1.yaml with an operationId, and give it "+
			"a row in the authorization matrix if it is account-scoped — or the claim is wrong, "+
			"and the honest fix is to take the row out and record the absence in the README's "+
			"`Not built yet` section.\n\n"+
			"Do not resolve this by widening the reader. A row this file cannot parse is "+
			"already an error, so there is nothing to widen.", len(promised), strings.Join(promised, "\n  "))
	}

	var undocumented []string
	for key := range served {
		if _, ok := claims[key]; !ok {
			undocumented = append(undocumented, key.String())
		}
	}
	sort.Strings(undocumented)

	if len(undocumented) > 0 {
		t.Errorf("this service serves %d operation(s) that README.md's endpoint tables do not "+
			"describe:\n\n  %s\n\n"+
			"The other direction, and the one a check written only for today's finding would "+
			"miss. A route nobody wrote down is an endpoint the next person discovers by reading "+
			"the router rather than the README, which is how a surface grows past what anybody "+
			"decided. Add the row.", len(undocumented), strings.Join(undocumented, "\n  "))
	}
}

func TestTheReadmeDeclaredAbsencesAreStillAbsent(t *testing.T) {
	_, declared := readmeClaims(t)
	served := servedRoutes(t)

	for path, reason := range readmeAbsent {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("the readmeAbsent entry for %s has no reason. An entry with no reason is "+
				"an assertion, and an assertion is not reviewable.", path)
		}
		if _, ok := declared[path]; !ok {
			t.Errorf("readmeAbsent names %s but the README no longer declares it absent. Either "+
				"the endpoint was removed — delete the entry and say so in the CHANGELOG — or it "+
				"is documented differently now, and the pinned list is stale.", path)
		}
	}

	for key := range served {
		if _, ok := readmeAbsent[key.Path]; !ok {
			continue
		}
		if _, declaredHere := declared[key.Path]; declaredHere {
			continue
		}
		t.Errorf("this service now serves %s, and readmeAbsent lists %s as one the README "+
			"declares answers 404. Either the route is real and the README row must go, or the "+
			"route was mounted by accident.", key, key.Path)
	}
}



const (
	injectedUndocumentedRoute = "/v1/claims-fault-injection"

	injectedUndocumentedSocialLoginRoute = socialLoginPrefix + "/{provider}/disconnect"
)

func TestEveryClaimCheckFailsOnAnInjectedRoute(t *testing.T) {
	for name, testCase := range map[string]struct {
		inject string
		check  func(t *testing.T, served map[operationKey]string) string
	}{
		"a served route with no README row": {
			inject: injectedUndocumentedRoute,
			check:  readmeUndocumentedRoutes,
		},
		"a social-login route with no README row": {
			inject: injectedUndocumentedSocialLoginRoute,
			check:  undocumentedSocialLoginRoutes,
		},
	} {
		t.Run(name, func(t *testing.T) {
			served := routesIn(t, walkOptions())
			served[operationKey{Method: "GET", Path: testCase.inject}] = testCase.inject

			reported := testCase.check(t, served)
			if reported == "" {
				t.Fatalf("the check reported nothing with %s in the served set. It is either "+
					"not reading the set it was handed, or not reporting a route that has no "+
					"claim beside it — and either way it would also pass over an empty "+
					"comparison, which is the failure mode this file exists to prevent.",
					testCase.inject)
			}
			if !strings.Contains(reported, testCase.inject) {
				t.Errorf("the check reported %q, which does not name the injected route %s. A "+
					"report a reader cannot act on is nearly as bad as no report.", reported, testCase.inject)
			}
		})
	}
}

func readmeUndocumentedRoutes(t *testing.T, served map[operationKey]string) string {
	t.Helper()

	claims, _ := readmeClaims(t)

	var reported []string
	for key := range served {
		if _, documented := claims[key]; !documented {
			reported = append(reported, key.String())
		}
	}
	if len(reported) == 0 {
		return ""
	}
	sort.Strings(reported)
	return "served but in no README row: " + strings.Join(reported, ", ")
}

func undocumentedSocialLoginRoutes(t *testing.T, served map[operationKey]string) string {
	t.Helper()

	claims, _ := readmeClaims(t)

	var reported []string
	for key := range served {
		if key.Path != socialLoginPrefix && !strings.HasPrefix(key.Path, socialLoginPrefix+"/") {
			continue
		}
		if _, documented := claims[key]; documented {
			continue
		}
		reported = append(reported, key.String())
	}
	if len(reported) == 0 {
		return ""
	}
	sort.Strings(reported)
	return "served under " + socialLoginPrefix + " with no README row: " + strings.Join(reported, ", ")
}


var manifestCapabilityEvidence = map[string][]string{
	"Authentication":       {"/v1/users", "/v1/session"},
	"sessions":             {"/v1/session"},
	"MFA":                  {"/v1/mfa"},
	"accounts and tenancy": {"/v1/accounts", "/v1/invitations/accept"},
	"scoped API tokens":    {"/v1/accounts/{}/api-keys", "/v1/introspections"},
	"social login":      {"/v1/auth/oauth/{}", "/v1/auth/oauth/{}/callback"},
	"the OIDC provider": {"/oidc/authorize", "/oidc/token"},
}

const manifestCapabilityCount = 7

func manifestDescription(t *testing.T) string {
	t.Helper()

	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("reading %s: %v", manifestPath, err)
	}

	description, err := readManifestDescription(string(raw))
	if err != nil {
		t.Fatalf("%s: %v", manifestPath, err)
	}
	return description
}

func readManifestDescription(manifest string) (string, error) {
	for number, line := range strings.Split(manifest, "\n") {
		value, found := strings.CutPrefix(line, "description:")
		if !found {
			continue
		}
		trimmed := strings.TrimSpace(value)

		if trimmed == "" || trimmed == "~" || trimmed == "null" {
			return "", fmt.Errorf("%s:%d — `description:` is empty. The manifest is what a "+
				"customer reads before deciding what this service does, and an empty one is a "+
				"claim this check cannot hold anything against.", manifestPath, number+1)
		}
		if isBlockScalarIndicator(trimmed) {
			return "", fmt.Errorf("%s:%d — `description:` is a block scalar. This reader "+
				"understands one line of `key: value` and refusing here is deliberate: returning "+
				"the indicator character would report a confident finding about a file written "+
				"some other way.", manifestPath, number+1)
		}

		if len(trimmed) >= 2 {
			if (strings.HasPrefix(trimmed, `"`) && strings.HasSuffix(trimmed, `"`)) ||
				(strings.HasPrefix(trimmed, "'") && strings.HasSuffix(trimmed, "'")) {
				trimmed = trimmed[1 : len(trimmed)-1]
			}
		}
		if trimmed == "" {
			return "", fmt.Errorf("%s:%d — `description:` is quoted but empty.", manifestPath, number+1)
		}
		return trimmed, nil
	}

	return "", fmt.Errorf("%s has no top-level `description:`. The schema requires one, and a "+
		"manifest without it cannot be checked against the router because it asserts nothing to "+
		"check.", manifestPath)
}

func isBlockScalarIndicator(value string) bool {
	for _, style := range []string{"|", ">"} {
		if value == style || value == style+"-" || value == style+"+" {
			return true
		}
	}
	return false
}

func manifestCapabilities(description string) []string {
	var out []string
	for _, part := range strings.Split(description, ",") {
		item := strings.TrimSpace(part)
		item = strings.TrimPrefix(item, "and ")
		item = strings.TrimSpace(item)
		item = strings.TrimSuffix(item, ".")
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func TestTheManifestDescribesOnlyCapabilitiesThisServiceHas(t *testing.T) {
	items := manifestCapabilities(manifestDescription(t))
	served := servedRoutes(t)

	servedPaths := map[string]bool{}
	for key := range served {
		servedPaths[key.Path] = true
	}

	var unknown []string
	for _, item := range items {
		evidence, declared := manifestCapabilityEvidence[item]
		if !declared {
			unknown = append(unknown, item)
			continue
		}
		for _, route := range evidence {
			if !servedPaths[normalisePath(route)] {
				t.Errorf("the manifest claims %q, and manifestCapabilityEvidence points at %s, "+
					"which the router does not serve. The claim outlived the capability.", item, route)
			}
		}
	}
	sort.Strings(unknown)

	if len(unknown) > 0 {
		t.Errorf("anywaye.yml's description claims %d capabilit(y/ies) this file has never heard "+
			"of:\n\n  %s\n\n"+
			"This is the check that found the OAuth claim. A customer reads the manifest and "+
			"decides what this service does, so an item with no route behind it is a promise in "+
			"the one file nobody diffs carefully. Either the capability is shipping — mount it, "+
			"and it will appear in the README's tables and in one of the documents — or the claim "+
			"is wrong and the word comes out of the manifest.\n\n"+
			"If the capability is real and simply new to this check, add it to "+
			"manifestCapabilityEvidence with the routes that prove it and bump "+
			"manifestCapabilityCount in the same commit — that edit is the review, so make it "+
			"legible.", len(unknown), strings.Join(unknown, "\n  "))
	}
}

func TestTheManifestCapabilityTableIsExactlyWhatItClaimsToBe(t *testing.T) {
	if len(manifestCapabilityEvidence) == manifestCapabilityCount {
		return
	}

	names := make([]string, 0, len(manifestCapabilityEvidence))
	for name := range manifestCapabilityEvidence {
		names = append(names, name)
	}
	sort.Strings(names)

	if len(manifestCapabilityEvidence) > manifestCapabilityCount {
		t.Errorf("manifestCapabilityEvidence has grown from %d entries to %d. Growing it is how "+
			"a manifest claim gets a route pointed at it without anybody deciding the claim was "+
			"true — the edit that makes the suite green is the edit that makes the lie "+
			"unfalsifiable. Add the capability to the manifest only when it is mounted, and "+
			"bump the constant in the same commit so the bump is a decision.\n\n  now: %v",
			manifestCapabilityCount, len(manifestCapabilityEvidence), names)
		return
	}
	t.Errorf("manifestCapabilityEvidence has %d entries and this file records %d. A table that "+
		"shrank means a capability was dropped from the table rather than from the manifest, "+
		"which TestTheManifestDescribesOnlyCapabilitiesThisServiceHas would then report as an "+
		"unknown claim. Delete the capability from anywaye.yml's description, or restore the "+
		"entry and re-pin.\n\n  now: %v", len(manifestCapabilityEvidence), manifestCapabilityCount, names)
}


var roadmapSurface = map[string][]string{
	"skeleton":              {"/healthz", "/readyz"},
	"password auth":         {"/v1/session", "/v1/me"},
	"email verification":    {"/v1/email-verifications", "/v1/password-resets", "/v1/email-changes"},
	"accounts, memberships": {"/v1/accounts", "/v1/invitations/accept"},
	"oidc provider":         {"/oidc/authorize", "/oidc/token"},
	"mfa: totp":             {"/v1/mfa"},
	"scoped api tokens":     {"/v1/accounts/{}/api-keys", "/v1/introspections"},
	"social login":          {"/v1/auth/oauth/{}", "/v1/auth/oauth/{}/callback"},
}

var roadmapNotSurface = map[string]string{
	"migration convention":       "packaging — a migration convention, an image and a compose stack, and none of them answers a request",
	"error envelope":             "the problem-document shape every route in the tables above already returns; it is not a route of its own",
	"outbox:":                    "the publisher is a background loop claiming rows with SKIP LOCKED, and it serves no request",
	"authorization matrix suite": "a test suite, not a capability a customer integrates against",
}

func roadmapCheckedItems(t *testing.T) []string {
	t.Helper()

	raw, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("reading %s: %v", readmePath, err)
	}

	items := roadmapItemsFrom(string(raw))
	if len(items) == 0 {
		t.Fatalf("%s's Roadmap section has no checked item at all. Every capability in it has "+
			"either been deleted or unchecked, and a check over no claims cannot fail.", readmePath)
	}
	return items
}

func roadmapItemsFrom(readme string) []string {
	inSection := false
	var items []string
	var current string

	flush := func() {
		if current != "" {
			items = append(items, current)
			current = ""
		}
	}

	for _, line := range strings.Split(readme, "\n") {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "## ") {
			flush()
			inSection = strings.EqualFold(trimmed, "## Roadmap")
			continue
		}
		if !inSection {
			continue
		}

		switch {
		case strings.HasPrefix(trimmed, "- [x]"):
			flush()
			current = strings.TrimSpace(strings.TrimPrefix(trimmed, "- [x]"))
		case strings.HasPrefix(trimmed, "- [ ]"):
			flush()
		case current != "" && trimmed != "":
			current += " " + trimmed
		}
	}
	flush()

	return items
}

func TestEveryCheckedRoadmapItemIsBackedByTheRouter(t *testing.T) {
	items := roadmapCheckedItems(t)
	served := servedRoutes(t)

	servedPaths := map[string]bool{}
	for key := range served {
		servedPaths[key.Path] = true
	}

	var unbacked []string
	for _, item := range items {
		lowered := strings.ToLower(item)

		matched := false
		for phrase, evidence := range roadmapSurface {
			if !strings.Contains(lowered, phrase) {
				continue
			}
			matched = true
			for _, route := range evidence {
				if !servedPaths[normalisePath(route)] {
					t.Errorf("the roadmap checks off %q and roadmapSurface points at %s, which the "+
						"router does not serve. The claim outlived the capability.", item, route)
				}
			}
		}
		if matched {
			continue
		}

		explained := false
		for phrase, reason := range roadmapNotSurface {
			if strings.Contains(lowered, phrase) {
				explained = true
				if strings.TrimSpace(reason) == "" {
					t.Errorf("the roadmapNotSurface entry for %q has no reason. An entry with no "+
						"reason is an assertion, and an assertion is not reviewable.", phrase)
				}
			}
		}
		if !explained {
			unbacked = append(unbacked, item)
		}
	}
	sort.Strings(unbacked)

	if len(unbacked) > 0 {
		t.Errorf("README.md's roadmap checks off %d item(s) that no route backs:\n\n  %s\n\n"+
			"This is the check the OAuth lie was for. `- [x] OAuth (social login) via goth` "+
			"asserted a capability this service did not have: there was no route, no handler "+
			"and no use case, and goth was not a dependency of this module at all. It is on the "+
			"roadmap now with no `goth`, because the routes are mounted — so the finding this "+
			"message describes is history, and the box it caught is the current one. A checkbox "+
			"is what somebody reads to decide whether to integrate, so do one of the two "+
			"things:\n"+
			"  1. the capability is shipping — mount it, document it, and add it to roadmapSurface "+
			"with the routes that prove it.\n"+
			"  2. it is not — uncheck the box, and record the absence in the README's "+
			"`Not built yet` section, which is the source of truth for what v0 does not claim.\n\n"+
			"Adding it to roadmapNotSurface is not a third option: that list is for capabilities "+
			"with genuinely no route, and a social sign-in endpoint has a route by definition.",
			len(unbacked), strings.Join(unbacked, "\n  "))
	}
}

func TestTheNotSurfaceListIsStillAboutTheItemsItNames(t *testing.T) {
	items := roadmapCheckedItems(t)
	lowered := make([]string, len(items))
	for i, item := range items {
		lowered[i] = strings.ToLower(item)
	}

	for phrase, reason := range roadmapNotSurface {
		found := false
		for _, item := range lowered {
			if strings.Contains(item, phrase) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("roadmapNotSurface names %q, and no checked roadmap item mentions it any "+
				"more. The entry has stopped meaning anything, which makes it a carve-out "+
				"matching nothing — a hole waiting for the next item somebody words that way. "+
				"Delete it, or reword the item to match what it is actually claiming.", phrase)
		}
		_ = reason
	}

	const want = 4
	if len(roadmapNotSurface) != want {
		t.Errorf("roadmapNotSurface has %d entries and this file records %d. It cannot grow: "+
			"growth is a capability being excused of having a route, which is the one move this "+
			"check exists to refuse. A capability that genuinely has no route belongs here with "+
			"a reason; one that ought to have a route has to be mounted.", len(roadmapNotSurface), want)
	}
}
