package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
)

// A fake GitHubIDReader, so the claim is tested without a database tier.
//
// It records what it was asked and answers what the test told it to. A fake
// rather than a real `oauth.Store` because the property under test is the claim's
// SHAPE and its presence-or-absence, neither of which needs a table — and a test
// that can only run against Postgres is a test that does not run.
type fakeGitHubIDs struct {
	id  string
	err error

	calls    int
	lastUser id.UUID
}

func (f *fakeGitHubIDs) GitHubIDForUser(_ context.Context, _ db.Querier, userID id.UUID) (string, error) {
	f.calls++
	f.lastUser = userID
	return f.id, f.err
}

func testUser(t *testing.T) id.UUID {
	t.Helper()
	parsed, err := id.Parse("00000000-0000-4000-8000-000000000001")
	if err != nil {
		t.Fatalf("parsing a test user id: %v", err)
	}
	return parsed
}

// claimsFor runs the claim builder over a set of scopes.
// markerQuerier is a db.QuerierSource that hands out nothing.
//
// The claim path passes a Querier to the reader, so SOMETHING has to be there
// even when the reader is a fake that ignores it. A real pool is not needed and
// would make this file a database-tier test for no gain; a nil source would
// panic inside the production function, which is why this is a marker rather
// than a nil. If a future change starts USING that querier, this test fails
// loudly instead of quietly exercising nothing.
type markerQuerier struct{}

func (markerQuerier) Queryer() db.Querier { return nil }

func claimsFor(t *testing.T, reader GitHubIDReader, scopes ...string) map[string]any {
	t.Helper()
	s := NewStorage(nil, NewProfileReader(), reader, nil, testClock{}, markerQuerier{}, PathLogin)
	claims, err := s.GetPrivateClaimsFromScopes(context.Background(), testUser(t).String(), "client", scopes)
	if err != nil {
		t.Fatalf("GetPrivateClaimsFromScopes(%v): %v", scopes, err)
	}
	return claims
}

// THE STRING IS THE POINT, and this is the test that holds it.
//
// MD21: gateway copies claims through a JavaScript `JSON.parse` and re-signs what
// comes out, so a `github_id` emitted as a JSON NUMBER is already a float64 by the
// time it is signed. Measured in node, 107346492749283471920 re-serializes as
// ...3480000 and round-trips through BigInt as ...3485475456 — every digit past
// 2^53 gone, inside a correctly-signed assertion, so nothing fails and `pantry`
// resolves a publisher who is not the caller.
//
// So the assertion is on the Go TYPE, not merely on the digits. A `float64` or an
// `int64` here would still hold 583454 in a test and still lose a real id in the
// fleet, which is why checking the value is not enough.
func TestTheGitHubIDClaimIsAStringNotANumber(t *testing.T) {
	claims := claimsFor(t, &fakeGitHubIDs{id: "583454"}, ScopeOpenID, ScopePublish)

	raw, ok := claims[ClaimGitHubID]
	if !ok {
		t.Fatalf("no %q claim on the publish scope: %v", ClaimGitHubID, claims)
	}
	str, ok := raw.(string)
	if !ok {
		t.Fatalf("%q is %T, not a string. gateway re-signs claims through a JSON.parse, "+
			"so a number is a float64 by the time it is signed and every digit past 2^53 "+
			"is silently rewritten -- see MD21.", ClaimGitHubID, raw)
	}
	if str != "583454" {
		t.Errorf("%q is %q, want %q", ClaimGitHubID, str, "583454")
	}
}

// And the digits must survive the JSON encoding a token actually goes through,
// which is a different question from the Go type above: a value can be a Go
// string and still be marshaled into a number by something upstream.
func TestTheGitHubIDClaimIsQuotedInTheEncodedToken(t *testing.T) {
	claims := claimsFor(t, &fakeGitHubIDs{id: "107346492749283471920"}, ScopeOpenID, ScopePublish)

	encoded, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("encoding the claim set: %v", err)
	}
	if !strings.Contains(string(encoded), `"github_id":"107346492749283471920"`) {
		t.Errorf("the encoded token is %s, which does not carry github_id as a quoted "+
			"string. An unquoted number here is the MD21 defect, one layer down.", encoded)
	}
}

// A user who has not linked GitHub gets NO claim, and that is the whole point of
// the omission rather than an empty string.
//
// MD19 wants such a caller to reach `pantry` and be told "no publisher record".
// An empty `github_id` would instead be parsed and rejected as a malformed
// assertion, which points an operator at their gateway instead of at the user who
// never linked an account. So the absent case must be ABSENT.
func TestNoGitHubAccountOmitsTheClaimRatherThanEmptyingIt(t *testing.T) {
	claims := claimsFor(t, &fakeGitHubIDs{err: ErrNoGitHubAccount}, ScopeOpenID, ScopePublish)

	raw, present := claims[ClaimGitHubID]
	if present {
		t.Fatalf("%q is present as %#v for a user with no linked account. It must be "+
			"omitted: an empty or zero claim reaches pantry as a malformed assertion "+
			"rather than as a missing one, and the two send an operator to different "+
			"components.", ClaimGitHubID, raw)
	}
}

// fakeProfiles answers the `accounts` claim without a database tier.
//
// It returns an empty membership list rather than an error, because the property
// under test is which reader gets asked -- not what a profile contains.
type fakeProfiles struct{}

func (fakeProfiles) Profile(_ context.Context, _ db.Querier, userID id.UUID) (Profile, error) {
	return Profile{UserID: userID}, nil
}

// claimsForWith is claimsFor with an explicit ProfileReader, for the one subtest
// that exercises the `accounts` branch.
func claimsForWith(t *testing.T, profiles ProfileReader, reader GitHubIDReader, scopes ...string) map[string]any {
	t.Helper()
	s := NewStorage(nil, profiles, reader, nil, testClock{}, markerQuerier{}, PathLogin)
	claims, err := s.GetPrivateClaimsFromScopes(context.Background(), testUser(t).String(), "client", scopes)
	if err != nil {
		t.Fatalf("GetPrivateClaimsFromScopes(%v): %v", scopes, err)
	}
	return claims
}

// The two scoped claims are INDEPENDENT. Written as one guarded block, `publish`
// would have been unreachable for every client that did not also ask for
// `accounts` -- which is the only client that wants it.
func TestPublishAndAccountsScopesDoNotDependOnEachOther(t *testing.T) {
	t.Run("publish alone asks the github reader", func(t *testing.T) {
		reader := &fakeGitHubIDs{id: "583454"}
		claims := claimsFor(t, reader, ScopeOpenID, ScopePublish)
		if reader.calls != 1 {
			t.Errorf("the github reader was asked %d times, want 1", reader.calls)
		}
		if _, present := claims[ClaimAccounts]; present {
			t.Errorf("%q is on a publish-only token: %v", ClaimAccounts, claims)
		}
	})

	t.Run("accounts alone never asks the github reader", func(t *testing.T) {
		// A nil reader is the assertion: reaching it would panic, so a client
		// that asked for memberships without `publish` cannot be holding a
		// publisher id it did not request.
		claims := claimsForWith(t, fakeProfiles{}, nil, ScopeOpenID, ScopeAccounts)
		if _, present := claims[ClaimGitHubID]; present {
			t.Errorf("%q is on an accounts-only token: %v", ClaimGitHubID, claims)
		}
	})

	t.Run("neither scope asks for nothing", func(t *testing.T) {
		reader := &fakeGitHubIDs{id: "583454"}
		claims := claimsFor(t, reader, ScopeOpenID)
		if reader.calls != 0 {
			t.Errorf("the github reader was asked %d times on a token with no publish "+
				"scope, want 0", reader.calls)
		}
		if _, present := claims[ClaimGitHubID]; present {
			t.Errorf("%q is on a token that never asked for it: %v", ClaimGitHubID, claims)
		}
	})
}

// A DATABASE FAILURE IS NOT "NO ACCOUNT", and collapsing the two would mint a
// token that silently drops the publisher claim during an outage -- so the writer
// would get a confusing refusal at publish time instead of an error here.
func TestAGitHubLookupFailureIsNotSwallowedAsAbsence(t *testing.T) {
	boom := errors.New("the database is on fire")
	s := NewStorage(nil, NewProfileReader(), &fakeGitHubIDs{err: boom}, nil, testClock{}, markerQuerier{}, PathLogin)

	_, err := s.GetPrivateClaimsFromScopes(context.Background(), testUser(t).String(), "client",
		[]string{ScopeOpenID, ScopePublish})
	if !errors.Is(err, boom) {
		t.Fatalf("a failed lookup returned %v, want the database error. Swallowing it "+
			"would produce a token with no github_id during an outage, and the publisher "+
			"would learn about it from pantry rather than from here.", err)
	}
}

// `publish` has to be a scope identity will actually honour. A scope name that
// is defined but absent from the supported list is dropped from the token request
// by NormalizeScopes, so the claim would be unreachable by a client that asked
// for it correctly -- which reads as "the feature does not work".
func TestPublishIsASupportedScope(t *testing.T) {
	if !IsSupportedScope(ScopePublish) {
		t.Errorf("%q is not a supported scope, so a client asking for it has it dropped "+
			"and never receives the claim", ScopePublish)
	}
	found := false
	for _, s := range SupportedScopes {
		if s == ScopePublish {
			found = true
		}
	}
	if !found {
		t.Errorf("%q is missing from SupportedScopes, so it is absent from the discovery "+
			"document and no client can discover it", ScopePublish)
	}
}
