package httpapi


import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/go-chi/chi/v5"

	"github.com/anywaye/identity/internal/accounts"
	"github.com/anywaye/identity/internal/apikeys"
	"github.com/anywaye/identity/internal/deletion"
	"github.com/anywaye/identity/internal/outbox"
	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/recovery"
	"github.com/anywaye/identity/internal/sessions"
	"github.com/anywaye/identity/internal/users"
)

type auditRoute struct {
	name    string
	method  string
	pattern string

	identifier string

	probe string

	anonymous int

	discloses string
}

var auditFamilyPrefixes = []string{
	"/v1/users",
	"/v1/me",
	"/v1/session",
	"/v1/password-resets",
	"/v1/email-verification",
	"/v1/email-changes",
	"/v1/introspections",
	"/v1/signup-timestamp",
	"/v1/operator",
	"/v1/accounts/{accountID}/agents",
	"/v1/agents",
}

func anonymousFamilyAudit() []auditRoute {
	return []auditRoute{
		{
			name: "register", method: http.MethodPost, pattern: "/v1/users",
			identifier: "email",
			probe:      `{"email":"nobody@example.com","password":"` + validPassword + `"}`,
			anonymous:  http.StatusCreated,
			discloses: "THAT the address is taken, and nothing else about the account holding it. " +
				"One bit, and it is the one disclosure on this service that cannot be removed: " +
				"one account per address is the unique index, and a caller registering has to be " +
				"told. Pinned by TestRegistrationPublishesOnlyThatAnAddressIsTaken",
		},
		{
			name: "mint a signup timestamp", method: http.MethodPost, pattern: "/v1/signup-timestamp",
			probe:     `{}`,
			anonymous: http.StatusOK,
			discloses: "nothing: a fresh timestamp and signature, which are a bearer credential for " +
				"submitting the form and expire in one hour. No account, no user, no identifier — " +
				"the request carries nothing and the response carries nothing but the pair",
		},
		{
			name: "sign in", method: http.MethodPost, pattern: "/v1/session",
			identifier: "email, password",
			probe:      `{"email":"nobody@example.com","password":"not the right password"}`,
			anonymous:  http.StatusUnauthorized,
			discloses: "NOTHING to a stranger, and the two answers that say something are both " +
				"positioned behind the password. LOCKED answers 423, to a stranger who caused the " +
				"lockout themselves — six unauthenticated requests per candidate address, held and " +
				"measured by TestALockedAccountIsToldApartOnlyFromThePassword. DISABLED answers 403 " +
				"with the state named, and is reached only AFTER the password verifies, so a caller " +
				"who sees it has already proved they hold the credential and already knew the " +
				"account existed — which makes it strictly cheaper to be honest about than the 423 " +
				"above it. A wrong password on a disabled account is the same 401 as on any other. " +
				"Held by TestADisabledLoginWithTheWrongPasswordIsRefusedExactlyAsAnyOther",
		},
		{
			name: "read the session", method: http.MethodGet, pattern: "/v1/me",
			anonymous: http.StatusUnauthorized,
			discloses: "nothing: 401 without a credential, so no identifier arrives from a stranger",
		},
		{
			name: "update the session", method: http.MethodPatch, pattern: "/v1/me",
			anonymous: http.StatusUnauthorized,
			discloses: "nothing: 401 without a credential, so no identifier arrives from a stranger",
		},
		{
			name: "delete the session", method: http.MethodDelete, pattern: "/v1/me",
			anonymous: http.StatusUnauthorized,
			discloses: "nothing: 401 without a credential, and no identifier arrives from a stranger. " +
				"The 409 that names a solely-owned team account is reachable only by a " +
				"resolved session, so there is no anonymous path to the one answer on this " +
				"route that describes an account",
		},
		{
			name: "sign out", method: http.MethodDelete, pattern: "/v1/session",
			anonymous: http.StatusUnauthorized,
			discloses: "nothing: 401 without a credential. The session token IS the identifier, and " +
				"it is a credential rather than a name",
		},
		{
			name: "list my sessions", method: http.MethodGet, pattern: "/v1/sessions",
			anonymous: http.StatusUnauthorized,
			discloses: "nothing: 401 without a credential, so no session id and no user id ever " +
				"arrives from a stranger. Had it answered 200 with an empty list, the list " +
				"would still disclose nothing — but it would tell a client its session is " +
				"fine, which is why the dead-credential answer is 401. " +
				"Held by TestTheListingRefusesAnUnusableCredentialWith401",
		},
		{
			name: "sign out of one session", method: http.MethodDelete, pattern: "/v1/sessions/{sessionID}",
			identifier: "the session id in the path",
			anonymous:  http.StatusUnauthorized,
			discloses: "nothing, and the ORDER matters: 401 comes before the id is even parsed, so " +
				"no caller-supplied string reaches a query. The id is a 128-bit uuid with no " +
				"structure to guess, AND the three answers a caller can reach — yours, " +
				"somebody else's, and never-existed — are one 404 with one fixed sentence. " +
				"Held by TestTheFourRefusalsAreOneDocument",
		},
		{
			name: "answer the second factor", method: http.MethodPost, pattern: "/v1/session/mfa",
			identifier: "challenge, code",
			probe:      `{"challenge":"a-challenge-that-is-not-one","code":"000000"}`,
			anonymous:  http.StatusNotFound,
			discloses: "nothing about any ACCOUNT. The body carries no address, and the challenge it " +
				"carries is itself the credential: 43 characters of entropy, not an identifier " +
				"there is a space to guess",
		},
		{
			name: "exchange a session for an account-scoped token", method: http.MethodPost, pattern: "/v1/session/tokens",
			identifier: "account_id, audience",
			probe:      `{"account_id":"00000000-0000-4000-8000-000000000000","audience":"billing"}`,
			anonymous:  http.StatusUnauthorized,
			discloses: "nothing about any ACCOUNT, and the refusal comes BEFORE the body is read: an " +
				"unauthenticated caller is answered 401 whatever account it names, so the route " +
				"cannot be used to walk ids anonymously either. The membership question is only " +
				"ever asked of an authenticated caller, and that answer is the 404 this operation's " +
				"documentation describes",
		},
		{
			name: "ask for a reset link", method: http.MethodPost, pattern: "/v1/password-resets",
			identifier: "email", probe: `{"email":"nobody@example.com"}`,
			anonymous: http.StatusAccepted,
			discloses: "nothing: 202 with a constant body for a registered address, an unregistered " +
				"one, a proved one and one inside the cooldown",
		},
		{
			name: "spend a reset link", method: http.MethodPost, pattern: "/v1/password-resets/confirm",
			identifier: "token, password",
			probe:      `{"token":"a-token-that-is-not-one","password":"` + validPassword + `"}`,
			anonymous:  http.StatusNotFound,
			discloses: "nothing: one 404 for a token that never existed, expired, was spent or " +
				"belongs to another flow",
		},
		{
			name: "ask for a confirmation link", method: http.MethodPost, pattern: "/v1/email-verifications",
			identifier: "email", probe: `{"email":"nobody@example.com"}`,
			anonymous: http.StatusAccepted,
			discloses: "nothing: 202 with a constant body for every address, INCLUDING one whose " +
				"account has already proved it",
		},
		{
			name: "spend a confirmation link", method: http.MethodPost, pattern: "/v1/email-verifications/confirm",
			identifier: "token", probe: `{"token":"a-token-that-is-not-one"}`,
			anonymous: http.StatusNotFound,
			discloses: "nothing: one 404, including for a token of the wrong LENGTH — which is the " +
				"spec/live disagreement TestATruncatedTokenAnswers404Not422 settles",
		},
		{
			name: "read the confirmation state", method: http.MethodGet, pattern: "/v1/email-verification",
			anonymous: http.StatusUnauthorized,
			discloses: "the caller's OWN verification state, and only behind a session. This is the " +
				"route a client that needs to say \"already verified\" must ask instead of the 409",
		},
		{
			name: "start an email change", method: http.MethodPost, pattern: "/v1/email-changes",
			identifier: "email", probe: `{"email":"new-address@example.com"}`,
			anonymous: http.StatusUnauthorized,
			discloses: "whether the NEW address is taken — to a signed-in caller who typed it, which " +
				"is the same disclosure POST /v1/users makes and the one place in this service it is safe",
		},
		{
			name: "confirm the current address", method: http.MethodPost, pattern: "/v1/email-changes/current-address",
			identifier: "token", probe: `{"token":"a-token-that-is-not-one"}`,
			anonymous: http.StatusNotFound,
			discloses: "nothing: one 404, including for the SECOND token presented here and for a " +
				"first token presented to the other half",
		},
		{
			name: "confirm the new address", method: http.MethodPost, pattern: "/v1/email-changes/new-address",
			identifier: "token", probe: `{"token":"a-token-that-is-not-one"}`,
			anonymous: http.StatusNotFound,
			discloses: "nothing about any account. A 409 IS reachable here, and only by a caller " +
				"holding a token that cannot exist before two inbox proofs",
		},
		{
			name: "redeem a session link", method: http.MethodPost, pattern: "/v1/session-links/redeem",
			identifier: "token",
			probe:      `{"token":"a-token-that-is-not-one"}`,
			anonymous:  http.StatusNotFound,
			discloses: "nothing about any ACCOUNT, and nothing about whether any link exists. One " +
				"404 with a fixed `detail` for all six ways of being wrong: never existed, " +
				"expired, spent, minted for another flow, a disabled subject, and a subject who " +
				"enrolled a second factor. The last two are facts about an account rather than a " +
				"row, and the token IS the credential here, so naming either would publish it to " +
				"the person the operator acted about. Not answerable by guessing either — 256 bits " +
				"of entropy and no space to enumerate. Held by " +
				"TestTheRedemptionCannotBeToldApartFromALinkThatNeverExisted",
		},
		{
			name: "mint a session link", method: http.MethodPost, pattern: "/v1/session-links",
			identifier: "user_id",
			probe:      `{"user_id":"` + id.MustNew().String() + `"}`,
			anonymous:  http.StatusForbidden,
			discloses: "nothing: 403 without a scoped api key holding sessions:write, so a subject " +
				"id never reaches the use case from a stranger. Behind that credential the 404 for " +
				"an unknown subject IS a deliberate disclosure — see DECISIONS.md D12",
		},
		{
			name: "disable a user", method: http.MethodPost,
			pattern:   "/v1/users/{userID}/disable",
			probe:     `{}`,
			anonymous: http.StatusForbidden,
			discloses: "nothing: 403 without a scoped api key holding users:disable, and the refusal " +
				"happens BEFORE the user id in the path is parsed — so this is one answer for a real " +
				"user id, a made-up one and no id at all, and there is no row to tell apart. Behind the " +
				"credential the 404 for an id this service never issued is deliberate — see D12",
		},
		{
			name: "re-enable a user", method: http.MethodPost,
			pattern:   "/v1/users/{userID}/enable",
			probe:     `{}`,
			anonymous: http.StatusForbidden,
			discloses: "nothing, and it is the same nothing the disable route discloses: 403 without a " +
				"scoped api key holding users:disable, before the path is parsed. There is deliberately no " +
				"way to learn a user's disabled state from either direction anonymously — the only " +
				"answer that names it is the login, and it is behind the password (DECISIONS.md D13)",
		},
		{
			name: "introspect a token", method: http.MethodPost, pattern: "/v1/introspections",
			identifier: "token",
			probe:      `{"token":"` + scopedTokenForTheMatrix + `"}`,
			anonymous:  http.StatusUnauthorized,
			discloses: "EVERYTHING about a token, and that is what the endpoint is for. Its protection " +
				"is the credential the caller must present, not the shape of the answer. See " +
				"TestIntrospectionIsAnOracleByDesignAndGatedOnACredential before changing this row",
		},
		{
			name: "read my operator status", method: http.MethodGet, pattern: "/v1/operator/me",
			anonymous: http.StatusUnauthorized,
			discloses: "nothing: 401 without a session, so no status arrives from a stranger. " +
				"Behind a session the route answers the caller's own status and nothing about " +
				"anybody else's — which is the property TestOperatorMeReportsTheSignedInStaffUser holds",
		},
		{
			name: "search the staff directory", method: http.MethodGet, pattern: "/v1/operator/users",
			identifier: "query",
			anonymous:  http.StatusUnauthorized,
			discloses: "nothing: 401 without a staff session, before the query is read — so a " +
				"real term, a made-up one and no term at all are the same answer, and no " +
				"address reaches the directory from outside the trust boundary",
		},
		{
			name: "staff directory summary", method: http.MethodGet, pattern: "/v1/operator/summary",
			anonymous: http.StatusUnauthorized,
			discloses: "nothing: 401 without a staff session, so no counts arrive " +
				"from a stranger. Behind a session the route answers the platform's " +
				"aggregate counts and nothing about any individual user",
		},
		{
			name: "staff account search", method: http.MethodGet, pattern: "/v1/operator/accounts",
			anonymous: http.StatusUnauthorized,
			discloses: "nothing: 401 without a staff session, so no account data arrives " +
				"from a stranger. Behind a session the route answers the bounded account " +
				"list and nothing an individual caller could not already see",
		},
		{
			name: "claim an agent", method: http.MethodPost,
			pattern:   "/v1/accounts/{accountID}/agents/claim",
			probe:     `{"token":"anywaye_` + strings.Repeat("z", 43) + `"}`,
			anonymous: http.StatusUnauthorized,
			discloses: "nothing from a stranger: 401 before the token in the body is read. " +
				"Behind a session, one 404 for a wrong token, an expired link, an " +
				"already-claimed agent and an agent that never existed — the store collapses " +
				"all four into one statement and the mapper renders them with one sentence. " +
				"No 410 (which would say the link was real) and no 409 (which would say the " +
				"agent is taken). Held by internal/agents' " +
				"TestAClaimLinkResolvesOnlyWhileItIsLiveIsUnclaimedAndIsNotYetSpent",
		},
		{
			name: "staff-disable a user", method: http.MethodPost,
			pattern:   "/v1/operator/users/{userID}/disable",
			probe:     `{}`,
			anonymous: http.StatusUnauthorized,
			discloses: "nothing: 401 without a staff session, and the refusal happens BEFORE the " +
				"user id in the path is parsed — so this is one answer for a real user id, a " +
				"made-up one and no id at all, and there is no row to tell apart. Behind the " +
				"gate the 404 for an id this service never issued is deliberate — see D12",
		},
		{
			name: "staff re-enable a user", method: http.MethodPost,
			pattern:   "/v1/operator/users/{userID}/enable",
			probe:     `{}`,
			anonymous: http.StatusUnauthorized,
			discloses: "nothing, and it is the same nothing the staff disable discloses: 401 " +
				"without a staff session, before the path is parsed. There is deliberately no " +
				"way to learn a user's disabled state from either direction anonymously — the " +
				"only answer that names it is the login, and it is behind the password " +
				"(DECISIONS.md D13)",
		},
		{
			name: "preview an agent claim", method: http.MethodGet,
			pattern:    "/v1/agents/claim/{token}",
			identifier: "the claim link, which is a 256-bit secret",
			anonymous:  http.StatusNotFound,
			discloses: "that the presented 256-bit secret is live, unclaimed and unexpired — " +
				"one bit, affordably, because guessing it is not a search anybody can run. No " +
				"account is named in the request or the response. A dead link and a wrong one " +
				"are ONE 404: the read filters the digest, the status and the expiry in one " +
				"statement, so an expired link, an already-claimed agent and an agent that never " +
				"existed are not told apart from each other or from a stranger's guess. No 410, " +
				"no 409",
		},
		{
			name: "read the agent home", method: http.MethodGet, pattern: "/v1/agents/home",
			anonymous: http.StatusUnauthorized,
			discloses: "nothing: 401 without the agent's own bearer credential, so no principal " +
				"a stranger can name arrives at the use case. Behind the credential the body is " +
				"the caller's own identity, status and claiming account — an agent is told about " +
				"itself, and about nothing else. An unclaimed agent gets the same 200 with " +
				"`claimed: false`, which is the answer `caf agent whoami` exists to read",
		},
		{
			name: "register an agent", method: http.MethodPost, pattern: "/v1/agents",
			identifier: "username (optional; a collision is never disclosed)",
			probe:      `{"name":"census probe"}`,
			anonymous:  http.StatusCreated,
			discloses: "nothing about any account, because there is no account in this flow. " +
				"A 201 with a new unclaimed principal, a token and a claim URL is a product " +
				"of the request and not a fact about any row that predates it. The username " +
				"never answers 'is that handle taken' — see TestAgentRegistrationNeverSaysAUsernameIsTaken",
		},
		{
			name: "refresh an agent's claim link", method: http.MethodPost,
			pattern:   "/v1/agents/claim-link/refresh",
			probe:     `{}`,
			anonymous: http.StatusUnauthorized,
			discloses: "nothing: 401 without the agent's own bearer credential, so a foreign " +
				"claim link or token id never reaches the use case and there is no principal a " +
				"stranger can point the route at. Behind the credential, refreshing a CLAIMED " +
				"agent is a 404 — the refresh refuses to act as a claim (D4)",
		},
		{
			name: "mint an agent token", method: http.MethodPost, pattern: "/v1/agents/tokens",
			probe:     `{"name":"census"}`,
			anonymous: http.StatusUnauthorized,
			discloses: "nothing: 401 without the agent's own bearer credential. The token minted " +
				"belongs to the principal that credential resolves to, which a stranger is not",
		},
		{
			name: "list an agent's tokens", method: http.MethodGet, pattern: "/v1/agents/tokens",
			anonymous: http.StatusUnauthorized,
			discloses: "nothing: 401 without the agent's own bearer credential, so no token and " +
				"no agent id arrives from a stranger",
		},
		{
			name: "revoke an agent token", method: http.MethodDelete,
			pattern:   "/v1/agents/tokens/{tokenID}",
			anonymous: http.StatusUnauthorized,
			discloses: "nothing: 401 without the agent's own bearer credential, and the gate " +
				"answers BEFORE the token id in the path is parsed — so a real id, a made-up " +
				"one and no id at all are the same 401, and there is no row to tell apart",
		},
		{
			name: "rotate an agent token", method: http.MethodPost,
			pattern:   "/v1/agents/tokens/{tokenID}/rotate",
			probe:     `{}`,
			anonymous: http.StatusUnauthorized,
			discloses: "nothing: 401 without the agent's own bearer credential, before the token " +
				"id in the path is read. Rotating a revoked credential behind the gate is a 409, " +
				"never a fresh credential for a spent one",
		},
	}
}

func TestEveryRouteThatAnswersAnAnonymousCallerIsInThisAudit(t *testing.T) {
	audited := map[string]bool{}
	for _, row := range anonymousFamilyAudit() {
		key := normalizeRoute(row.method, row.pattern)
		if audited[key] {
			t.Errorf("%s has two rows in the enumeration audit, so a reader cannot tell which "+
				"answer is the audited one", key)
		}
		audited[key] = true
	}

	mounted := mountedFamilyRoutes()
	if len(mounted) == 0 {
		t.Fatal("the walk found no route in this family, so every assertion below would pass " +
			"vacuously. A walk that sees nothing agrees with a walk that sees nothing")
	}
	t.Logf("the family holds %d mounted routes and the audit has %d rows", len(mounted), len(audited))

	for _, key := range mounted {
		if !audited[key] {
			t.Errorf("%s is mounted under this family's prefixes and has no row in the "+
				"enumeration audit. Add one, and answer the question: can the response tell "+
				"\"this account exists\" from \"it does not\"?", key)
		}
	}

	for key := range audited {
		if !contains(mounted, key) {
			t.Errorf("the enumeration audit has a row for %s, which is not mounted under this "+
				"family's prefixes. A row about a route that is gone is a claim nothing checks; "+
				"delete it or mount the route", key)
		}
	}
}

func TestEveryAuditedRouteStillAnswersWhatItsRowSays(t *testing.T) {
	f := newAuditFixture(t)

	for _, row := range anonymousFamilyAudit() {
		if strings.TrimSpace(row.discloses) == "" {
			t.Errorf("the %s row records no answer. A row that does not say what the route "+
				"discloses is a route that has been walked past", row.name)
		}
		rec := anonymousProbe(t, f, row.method, row.pattern)
		if rec.Code != row.anonymous {
			t.Errorf("%s %s answered %d to the audit's own anonymous probe, want %d.\n"+
				"The row describes what this route discloses to a stranger, and a route that "+
				"has changed its answer without its row changing is the drift this catches.\n"+
				"body: %s", row.method, row.pattern, rec.Code, row.anonymous, rec.Body)
		}
	}
}


func TestRegistrationPublishesOnlyThatAnAddressIsTaken(t *testing.T) {
	f := newAuditFixture(t)

	proved, _ := f.signUp(t)
	f.verifyAddress(t, proved)
	unproved, _ := f.signUp(t)
	free := dbtest.UniqueEmail(t)

	created := post(t, f.handler, "/v1/users", `{"email":"`+free+`","password":"`+validPassword+`"}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("registering an unused address = %d, want 201; body: %s", created.Code, created.Body)
	}

	takenProved := post(t, f.handler, "/v1/users", `{"email":"`+proved+`","password":"`+validPassword+`"}`)
	takenUnproved := post(t, f.handler, "/v1/users", `{"email":"`+unproved+`","password":"`+validPassword+`"}`)
	for label, rec := range map[string]*httptest.ResponseRecorder{
		"a proved account":    takenProved,
		"an unproved account": takenUnproved,
	} {
		if rec.Code != http.StatusConflict {
			t.Fatalf("registering an address held by %s = %d, want 409; body: %s",
				label, rec.Code, rec.Body)
		}
		if got := decodeProblem(t, rec).Code; got != CodeConflict {
			t.Errorf("registering an address held by %s: code = %q, want %q", label, got, CodeConflict)
		}
	}

	a := decodeProblem(t, takenProved)
	b := decodeProblem(t, takenUnproved)
	a.TraceID, b.TraceID = "", ""
	if renderedA, renderedB := renderProblem(t, a), renderProblem(t, b); renderedA != renderedB {
		t.Errorf("the 409 differs between an account that has proved its address and one that has not:\n"+
			"  proved:   %s\n  unproved: %s", renderedA, renderedB)
	}

	want := Problem{
		Type:     "https://docs.anywaye.com/errors/conflict",
		Title:    "Conflict",
		Status:   http.StatusConflict,
		Detail:   "an account already exists for that email address",
		Instance: "/v1/users",
		Code:     CodeConflict,
	}
	if got, expected := renderProblem(t, a), renderProblem(t, want); got != expected {
		t.Errorf("the 409 is not the envelope and one fixed sentence.\n  got:  %s\n  want: %s\n"+
			"Anything beyond these seven fields is a fact about the account that already holds "+
			"the address, and this route is allowed to publish exactly one bit", got, expected)
	}

	malformed := post(t, f.handler, "/v1/users",
		`{"email":"not-an-address","password":"`+validPassword+`"}`)
	if malformed.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a malformed address = %d, want 422; body: %s", malformed.Code, malformed.Body)
	}
	if strings.Contains(malformed.Body.String(), proved) || strings.Contains(malformed.Body.String(), unproved) {
		t.Errorf("the 422 echoes a submitted address:\n%s", malformed.Body)
	}
}

func TestALockedAccountIsToldApartOnlyFromThePassword(t *testing.T) {
	f := newAuditFixture(t)

	known, _ := f.signUp(t)
	unknown := dbtest.UniqueEmail(t)
	sessionsBefore := f.sessionsFor(t, known)

	for attempt := 1; attempt <= sessions.MaxFailedAttempts; attempt++ {
		rec := post(t, f.handler, "/v1/session", `{"email":"`+known+`","password":"wrong"}`)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d against a registered address = %d, want 401; body: %s",
				attempt, rec.Code, rec.Body)
		}
	}

	locked := post(t, f.handler, "/v1/session", `{"email":"`+known+`","password":"wrong"}`)
	if locked.Code != http.StatusLocked {
		t.Fatalf("a wrong password against a locked account = %d, want 423; body: %s",
			locked.Code, locked.Body)
	}
	if got := locked.Header().Get(RetryAfterHeader); got == "" {
		t.Error("the 423 carries no Retry-After, so its \"retry after\" sentence names nothing")
	}

	againstUnknown := post(t, f.handler, "/v1/session", `{"email":"`+unknown+`","password":"wrong"}`)
	if againstUnknown.Code != http.StatusUnauthorized {
		t.Errorf("a wrong password against an address with no account = %d, want 401. The same "+
			"request against a LOCKED account answers %d, and that difference is the leak this "+
			"test exists to name", againstUnknown.Code, locked.Code)
	}

	for _, rec := range []*httptest.ResponseRecorder{
		post(t, f.handler, "/v1/session", `{"email":"`+known+`","password":"`+validPassword+`"}`),
		post(t, f.handler, "/v1/session", `{"email":"`+unknown+`","password":"`+validPassword+`"}`),
	} {
		if rec.Code != http.StatusLocked && rec.Code != http.StatusUnauthorized {
			t.Errorf("a sign-in attempt answered %d; on this route a stranger can reach a 423 "+
				"(locked) and a 401 (everything else), and this is a third: %s", rec.Code, rec.Body)
		}
	}

	withPassword := post(t, f.handler, "/v1/session",
		`{"email":"`+known+`","password":"`+validPassword+`"}`)
	if withPassword.Code != http.StatusLocked {
		t.Errorf("the correct password against a locked account = %d, want 423; body: %s",
			withPassword.Code, withPassword.Body)
	}
	if got := f.sessionsFor(t, known); got != sessionsBefore {
		t.Errorf("%d sessions exist during the lockout window, want the %d that existed before "+
			"it: a refused login mints nothing", got, sessionsBefore)
	}
}

func TestTheRequestRoutesCarryNoIdentifierToEnumerate(t *testing.T) {
	f := newAuditFixture(t)

	address := dbtest.UniqueEmail(t)
	for _, path := range []string{"/v1/password-resets", "/v1/email-verifications"} {
		rec := post(t, f.handler, path, `{"email":"`+address+`"}`)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("POST %s = %d, want 202; body: %s", path, rec.Code, rec.Body)
		}
		var raw map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
			t.Fatalf("the body of %s is not JSON: %v", path, err)
		}
		if len(raw) != 1 || raw["status"] != "accepted" {
			t.Errorf("POST %s answered with %v. This body IS the account-enumeration defense on "+
				"the route: one field, one value, whatever the row says. A second field is an "+
				"oracle and no other test in the repository would fail", path, raw)
		}
	}
}

func TestATokenRouteCannotBeToldApartFromASpentOne(t *testing.T) {
	f := newAuditFixture(t)
	email, session := f.signUp(t)

	spent := f.mintVerificationAndSpend(t, email)
	changeFirstHalf := f.mintEmailChange(t, session)
	liveVerification := f.mintVerification(t, email)

	if spent == liveVerification {
		t.Fatal("the two verification tokens are the same value, so the live case is not live")
	}

	for _, route := range []struct {
		path string
		wrong []struct{ label, token string }
	}{
		{
			path:  "/v1/email-verifications/confirm",
			wrong: []struct{ label, token string }{{"a live email-change token", changeFirstHalf}},
		},
		{
			path: "/v1/email-changes/current-address",
			wrong: []struct{ label, token string }{
				{"a live verification token", liveVerification},
			},
		},
		{
			path: "/v1/email-changes/new-address",
			wrong: []struct{ label, token string }{
				{"a live verification token", liveVerification},
				{"a live first-half email-change token", changeFirstHalf},
			},
		},
	} {
		cases := []struct{ label, token string }{
			{"a token that was spent", spent},
			{"a token that never existed", strings.Repeat("z", 43)},
		}
		cases = append(cases, route.wrong...)

		reference := ""
		for i, c := range cases {
			rec := post(t, f.handler, route.path, `{"token":"`+c.token+`"}`)
			if rec.Code != http.StatusNotFound {
				t.Errorf("POST %s with %s = %d, want 404; body: %s", route.path, c.label, rec.Code, rec.Body)
				continue
			}
			p := decodeProblem(t, rec)
			p.TraceID = ""
			rendered := renderProblem(t, p)
			switch {
			case i == 0:
				reference = rendered
			case rendered != reference:
				t.Errorf("POST %s answers differently for %s than for a spent token:\n  that:    %s\n"+
					"  a spent: %s", route.path, c.label, rendered, reference)
			}
		}
		if reference == "" {
			t.Errorf("POST %s produced no comparable answer, so the comparison above passed "+
				"vacuously", route.path)
		}
	}
}

func TestIntrospectionIsAnOracleByDesignAndGatedOnACredential(t *testing.T) {
	f := newAuditFixture(t)

	email, session := f.signUp(t)
	issued := f.issueAPIKey(t, email, session)

	active := sendWith(t, f.handler, http.MethodPost, "/v1/introspections", session, "",
		`{"token":"`+issued+`"}`)
	if active.Code != http.StatusOK {
		t.Fatalf("the owner introspecting its own account's live token = %d, want 200; body: %s",
			active.Code, active.Body)
	}
	var claims map[string]any
	if err := json.Unmarshal(active.Body.Bytes(), &claims); err != nil {
		t.Fatalf("the claim document is not JSON: %v", err)
	}
	if claims["active"] != true || claims["sub"] == nil {
		t.Errorf("the claim document does not describe a live token: %v", claims)
	}

	inactive := sendWith(t, f.handler, http.MethodPost, "/v1/introspections", session, "",
		`{"token":"`+strings.Repeat("z", 43)+`"}`)
	if inactive.Code != http.StatusOK {
		t.Fatalf("introspecting an unknown token = %d, want 200", inactive.Code)
	}
	if inactive.Body.String() == active.Body.String() {
		t.Error("a live token and an unknown one answered identically. That is the failure the " +
			"OTHER routes in this file guard against, and here it would be the endpoint failing " +
			"at its job rather than leaking")
	}

	if rec := anonymousProbe(t, f, http.MethodPost, "/v1/introspections"); rec.Code != http.StatusUnauthorized {
		t.Errorf("an anonymous introspection = %d, want 401. This route's protection is the "+
			"caller's credential and nothing else, so a 200 here would make every token in the "+
			"deployment publicly checkable", rec.Code)
	}

	_, strangerSession := f.signUp(t)
	refused := sendWith(t, f.handler, http.MethodPost, "/v1/introspections", strangerSession, "",
		`{"token":"`+issued+`"}`)
	if refused.Code != http.StatusForbidden && refused.Code != http.StatusNotFound {
		t.Errorf("a session from outside the account introspecting another account's token = %d, "+
			"want 403 or 404", refused.Code)
	}

	peer := f.issueAPIKey(t, email, session)
	if rec := sendWith(t, f.handler, http.MethodPost, "/v1/introspections", issued, "",
		`{"token":"`+peer+`"}`); rec.Code != http.StatusForbidden && rec.Code != http.StatusNotFound {
		t.Errorf("a token introspecting another token in the same account = %d, want 403 or 404; "+
			"reading a peer's scopes is reconnaissance", rec.Code)
	}
	if rec := sendWith(t, f.handler, http.MethodPost, "/v1/introspections", issued, "",
		`{"token":"`+issued+`"}`); rec.Code != http.StatusOK {
		t.Errorf("a token introspecting itself = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	if rec := sendWith(t, f.handler, http.MethodPost, "/v1/introspections", session, "",
		`{"token":"`+issued+`"}`); rec.Code != http.StatusOK {
		t.Errorf("the owner introspecting its own account's token with a session = %d, want 200; "+
			"body: %s", rec.Code, rec.Body)
	}
}


type auditFixture struct {
	*recoveryServerFixture
	accountID id.UUID
}

func newAuditFixture(t *testing.T, opts ...Option) *auditFixture {
	t.Helper()

	pool := dbtest.Schema(t)
	clk := clock.NewFake(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	mailer := &captureMailer{}
	access := &captureAccessRevoker{revoked: map[string]time.Time{}}
	tenancy := realTenancy(pool, clk)
	keys := matrixAPIKeys(pool, clk, tenancy)

	allOpts := []Option{
		WithAuth(authServiceFor(pool, clk)),
		WithTenancy(tenancy),
		WithOIDC(newFakeOIDC()),
		WithRecovery(recovery.NewService(
			db.TxRunner{Pool: pool},
			db.Direct{Pool: pool},
			recovery.NewStore(pool),
			users.NewStore(pool),
			sessions.NewStore(pool),
			access,
			outbox.NewStore(pool),
			mailer,
			users.NewHasherWithParams(&argon2id.Params{
				Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
			}),
			clk,
			noEnrolledSecondFactor{},
		)),
		WithAPIKeys(keys),
		WithAPIKeyCaller(keys),
		WithDeletion(deletion.NewService(
			db.TxRunner{Pool: pool},
			users.NewStore(pool),
			accounts.NewStore(pool),
			&auditSweeper{},
			outbox.NewStore(pool),
		)),
		WithAgents(newFakeAgents()),
		WithIntrospection(keys),
		WithSignup(acceptsEveryPair()),
		WithLogger(slogLogger(&recordingHandler{})),
	}
	allOpts = append(allOpts, opts...)
	handler := New(nil, allOpts...)

	fixtureUser := id.MustNew()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO users (id, email, password_digest) VALUES ($1, $2, $3)`,
		fixtureUser, dbtest.UniqueEmail(t), auditPasswordDigest); err != nil {
		t.Fatalf("inserting the audit fixture's user: %v", err)
	}

	return &auditFixture{
		recoveryServerFixture: &recoveryServerFixture{
			handler: handler,
			pool:    pool,
			clk:     clk,
			mailer:  mailer,
			access:  access,
		},
		accountID: auditAccount(t, tenancy, fixtureUser),
	}
}

const auditPasswordDigest = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$" +
	"c2FsdHNhbHRzYWx0c2FsdHNhbHQ"

func auditAccount(t *testing.T, tenancy Tenancy, owner id.UUID) id.UUID {
	t.Helper()

	created, err := tenancy.Create(context.Background(), accounts.CreateInput{
		Name:  "Audit fixture account",
		Owner: owner,
	})
	if err != nil {
		t.Fatalf("provisioning the audit fixture's account: %v", err)
	}
	return created.Account.ID
}

func substituteAccountParams(pattern, accountID string) string {
	out := strings.ReplaceAll(pattern, "{accountID}", accountID)
	if strings.Contains(out, "{accountID}") {
		return pattern
	}
	return out
}

func (f *auditFixture) mintVerification(t *testing.T, email string) string {
	t.Helper()

	rec := post(t, f.handler, "/v1/email-verifications", `{"email":"`+email+`"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /v1/email-verifications = %d, want 202; body: %s", rec.Code, rec.Body)
	}
	return tokenIn(t, f.mailer.last(t))
}

func (f *auditFixture) mintVerificationAndSpend(t *testing.T, email string) string {
	t.Helper()

	token := f.mintVerification(t, email)
	rec := post(t, f.handler, "/v1/email-verifications/confirm", `{"token":"`+token+`"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("spending the verification token = %d, want 204; body: %s", rec.Code, rec.Body)
	}
	return token
}

func (f *auditFixture) mintEmailChange(t *testing.T, session string) string {
	t.Helper()

	rec := sendWith(t, f.handler, http.MethodPost, "/v1/email-changes", session, "",
		`{"email":"`+dbtest.UniqueEmail(t)+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /v1/email-changes = %d, want 201; body: %s", rec.Code, rec.Body)
	}
	return tokenIn(t, f.mailer.last(t))
}

func (f *auditFixture) issueAPIKey(t *testing.T, email, session string) string {
	t.Helper()

	var accountID string
	if err := f.pool.QueryRow(t.Context(), `
		SELECT a.id::text FROM account_users au
		JOIN accounts a ON a.id = au.account_id
		JOIN users u ON u.id = au.user_id
		WHERE u.email = $1 ORDER BY a.created_at, a.id LIMIT 1`, email).Scan(&accountID); err != nil {
		t.Fatalf("finding an account for %s: %v", email, err)
	}

	rec := sendWith(t, f.handler, http.MethodPost,
		"/v1/accounts/"+accountID+"/api-keys", session, "",
		`{"name":"audit-`+id.MustNew().String()[:8]+`","scopes":["accounts:read"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("minting an api key = %d, want 201; body: %s", rec.Code, rec.Body)
	}

	var issued issuedAPIKeyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &issued); err != nil {
		t.Fatalf("the minting body is not JSON: %v", err)
	}
	if issued.Token == "" {
		t.Fatal("the 201 carried no token, so the introspection half of this test would prove nothing")
	}
	return issued.Token
}


func mountedFamilyRoutes() []string {
	var found []string

	r := chi.NewRouter()
	o := options{
		auth:         newFakeAuth(),
		deletion:     newFakeDeletion(),
		tenancy:      newFakeTenancy(),
		apiKeys:      newFakeAPIKeys(),
		apiKeyCaller: newFakeAPIKeyCaller(users.User{}, apikeys.Key{}),
		mfa:          newFakeMFAManage(),
		introspector: newFakeIntrospector(),
		oidc:         newFakeOIDC(),
		oidcClients:  newFakeOIDCClients(),
		admin:        newFakeAdmin(),
		recovery:     newFakeRecovery(),
		signup:       newFakeSignup(),
		agents: newFakeAgents(),
	}
	o.registerRoutes(r)
	o.registerSignupRoutes(r)

	_ = chi.Walk(r, func(method string, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		clean := normalizeRoute(method, route)
		if isAuditFamilyRoute(clean) {
			found = append(found, clean)
		}
		return nil
	})

	sort.Strings(found)
	return found
}

func isAuditFamilyRoute(route string) bool {
	_, path := splitRoute(route)
	for _, prefix := range auditFamilyPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func anonymousProbe(t *testing.T, f *auditFixture, method, pattern string) *httptest.ResponseRecorder {
	t.Helper()

	body := ""
	for _, row := range anonymousFamilyAudit() {
		if row.method == method && row.pattern == pattern {
			body = row.probe
			break
		}
	}
	path := substituteAccountParams(pattern, f.accountID.String())
	if strings.Contains(path, "{accountID}") {
		t.Fatalf("the census probe for %s carries an unsubstituted {accountID}, so it "+
			"would measure the route's parser rather than the route", pattern)
	}
	return sendWith(t, f.handler, method, path, "", "", body)
}

func renderProblem(t *testing.T, p Problem) string {
	t.Helper()
	p.TraceID = ""
	out, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("re-marshaling a problem document: %v", err)
	}
	return string(out)
}

func splitRoute(route string) (string, string) {
	method, pattern, _ := strings.Cut(route, " ")
	return method, pattern
}

func contains(haystack []string, needle string) bool {
	for _, item := range haystack {
		if item == needle {
			return true
		}
	}
	return false
}

type auditSweeper struct{}

func (auditSweeper) RevokeEveryCredential(ctx context.Context, q db.Querier, u id.UUID, at time.Time) error {
	return nil
}
