package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/id"
)

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

type fakeProfiles struct{}

func (fakeProfiles) Profile(_ context.Context, _ db.Querier, userID id.UUID) (Profile, error) {
	return Profile{UserID: userID}, nil
}

func claimsForWith(t *testing.T, profiles ProfileReader, reader GitHubIDReader, scopes ...string) map[string]any {
	t.Helper()
	s := NewStorage(nil, profiles, reader, nil, testClock{}, markerQuerier{}, PathLogin)
	claims, err := s.GetPrivateClaimsFromScopes(context.Background(), testUser(t).String(), "client", scopes)
	if err != nil {
		t.Fatalf("GetPrivateClaimsFromScopes(%v): %v", scopes, err)
	}
	return claims
}

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
