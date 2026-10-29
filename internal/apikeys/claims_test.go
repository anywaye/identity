package apikeys

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/platform/id"
)


func claimKey() Key {
	return Key{
		ID:        id.MustNew(),
		UserID:    id.MustNew(),
		AccountID: id.MustNew(),
		Name:      "ci-deploy",
		Scopes:    []string{ScopeAccountsWrite, ScopeAccountsRead},
		Role:      "owner",
		CreatedAt: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 12, 30, 12, 0, 0, 0, time.UTC),
	}
}

func TestTheTwoScopeClaimNamesAreEqual(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		scopes []string
	}{
		{name: "one scope", scopes: []string{ScopeAccountsRead}},
		{name: "every scope", scopes: AllScopes()},
		{name: "reversed", scopes: []string{ScopeAccountsDelete, ScopeAccountsRead, ScopeAccountsWrite}},
		{name: "a single scope that sorts last", scopes: []string{ScopeOIDCClientsWrite}},
		{name: "a single scope that sorts first", scopes: []string{ScopeAccountsDelete}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			key := claimKey()
			key.Scopes = tt.scopes

			claims, err := ClaimsFor(key, key.CreatedAt)
			if err != nil {
				t.Fatalf("ClaimsFor: %v", err)
			}

			doc := claims.Document()
			primary, primaryOK := doc[ClaimScopes].(string)
			mirror, mirrorOK := doc[ClaimScope].(string)
			if !primaryOK || !mirrorOK {
				t.Fatalf("the document does not carry both names as strings: %#v", doc)
			}
			if primary != mirror {
				t.Errorf("%s = %q and %s = %q; they must be byte for byte equal or a consumer "+
					"reads a scope set that depends on which name it happens to use",
					ClaimScopes, primary, ClaimScope, mirror)
			}

			raw, err := json.Marshal(claims)
			if err != nil {
				t.Fatalf("rendering: %v", err)
			}
			var decoded map[string]any
			if err := json.Unmarshal(raw, &decoded); err != nil {
				t.Fatalf("decoding: %v", err)
			}
			if decoded[ClaimScopes] != decoded[ClaimScope] {
				t.Errorf("the rendered document disagrees: %s = %v, %s = %v",
					ClaimScopes, decoded[ClaimScopes], ClaimScope, decoded[ClaimScope])
			}
		})
	}
}

func TestTheScopeClaimIsASpaceSeparatedString(t *testing.T) {
	t.Parallel()

	key := claimKey()
	claims, err := ClaimsFor(key, key.CreatedAt)
	if err != nil {
		t.Fatalf("ClaimsFor: %v", err)
	}

	raw, err := json.Marshal(claims.Document())
	if err != nil {
		t.Fatalf("rendering: %v", err)
	}
	if strings.Contains(string(raw), `"scopes":[`) || strings.Contains(string(raw), `"scope":[`) {
		t.Errorf("a scope claim is an array: %s. gateway splits on whitespace and rejects a "+
			"non-string claim, so an array is a token it cannot read", raw)
	}

	want := "accounts:read accounts:write"
	if claims.Scopes != want {
		t.Errorf("scopes = %q, want %q", claims.Scopes, want)
	}
	for _, scope := range strings.Fields(claims.Scopes) {
		if !IsSupportedScope(scope) {
			t.Errorf("the claim carries %q, which is not in the vocabulary", scope)
		}
	}
}

func TestAccountIDIsRequiredAndNeverDerivedFromSub(t *testing.T) {
	t.Parallel()

	key := claimKey()
	claims, err := ClaimsFor(key, key.CreatedAt)
	if err != nil {
		t.Fatalf("ClaimsFor: %v", err)
	}

	if claims.AccountID != key.AccountID.String() {
		t.Errorf("account_id = %q, want the row's %q", claims.AccountID, key.AccountID)
	}
	if claims.Subject != key.UserID.String() {
		t.Errorf("sub = %q, want the row's user %q", claims.Subject, key.UserID)
	}
	if claims.AccountID == claims.Subject {
		t.Error("account_id and sub are the same value, so the tenancy key is the subject")
	}

	resolved, err := ResolveAccountID(claims)
	if err != nil {
		t.Fatalf("ResolveAccountID: %v", err)
	}
	if resolved != key.AccountID {
		t.Errorf("ResolveAccountID = %s, want %s", resolved, key.AccountID)
	}

	if _, err := ResolveAccountID(Claims{Active: true, Subject: key.UserID.String()}); !errors.Is(err, ErrNoAccountID) {
		t.Errorf("a claim with no account = %v, want ErrNoAccountID", err)
	}
	if _, err := ResolveAccountID(Claims{Active: true, AccountID: "not-a-uuid"}); !errors.Is(err, ErrNoAccountID) {
		t.Errorf("a claim with a malformed account = %v, want ErrNoAccountID", err)
	}
	if _, err := ClaimsFor(Key{ID: key.ID, UserID: key.UserID}, key.CreatedAt); !errors.Is(err, ErrNoAccountID) {
		t.Errorf("a key with no account = %v, want ErrNoAccountID", err)
	}
}

func TestAnUnusableTokenIsInactiveAndCarriesNothingElse(t *testing.T) {
	t.Parallel()

	revokedAt := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		give func(k *Key)
		at   time.Time
	}{
		{
			name: "revoked",
			give: func(k *Key) { k.RevokedAt = &revokedAt },
			at:   time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC),
		},
		{
			name: "expired",
			give: func(k *Key) {},
			at:   time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC),
		},
		{
			name: "exactly at its expiry",
			give: func(k *Key) {},
			at:   time.Date(2026, 12, 30, 12, 0, 0, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			key := claimKey()
			tt.give(&key)

			claims, err := ClaimsFor(key, tt.at)
			if err != nil {
				t.Fatalf("ClaimsFor: %v", err)
			}
			if claims.Active {
				t.Fatal("an unusable token produced an active claim document")
			}

			raw, err := json.Marshal(claims.Document())
			if err != nil {
				t.Fatalf("rendering: %v", err)
			}
			if got, want := strings.TrimSpace(string(raw)), `{"active":false}`; got != want {
				t.Errorf("the document is %s, want exactly %s. A refusal that carries a subject "+
					"is a user id handed to whoever asked", got, want)
			}
		})
	}

	key := claimKey()
	claims, err := ClaimsFor(key, key.ExpiresAt.Add(-time.Nanosecond))
	if err != nil {
		t.Fatalf("ClaimsFor: %v", err)
	}
	if !claims.Active {
		t.Error("a token one nanosecond before its expiry is already inactive")
	}
}

func TestTheClaimCarriesTheGrantAndNotTheCredential(t *testing.T) {
	t.Parallel()

	key := claimKey()
	key.TokenDigest = Digest(Prefix + strings.Repeat("x", 43))
	claims, err := ClaimsFor(key, key.CreatedAt)
	if err != nil {
		t.Fatalf("ClaimsFor: %v", err)
	}

	raw, err := json.Marshal(claims.Document())
	if err != nil {
		t.Fatalf("rendering: %v", err)
	}
	for _, forbidden := range []string{"digest", "token", "secret", Prefix, key.TokenDigest} {
		if strings.Contains(string(raw), forbidden) {
			t.Errorf("the claim document mentions %q: %s", forbidden, raw)
		}
	}

	for _, want := range []string{ClaimAccountID, ClaimScopes, ClaimScope, "sub", "jti", "iat", "exp"} {
		if _, present := claims.Document()[want]; !present {
			t.Errorf("the document has no %q", want)
		}
	}
}

func TestTheClaimIsStableForTheSameRow(t *testing.T) {
	t.Parallel()

	key := claimKey()
	key.Scopes = []string{ScopeAccountsWrite, ScopeAccountsRead, ScopeAccountsDelete}

	first, err := ClaimsFor(key, key.CreatedAt)
	if err != nil {
		t.Fatalf("ClaimsFor: %v", err)
	}
	key.Scopes = []string{ScopeAccountsDelete, ScopeAccountsRead, ScopeAccountsWrite}
	second, err := ClaimsFor(key, key.CreatedAt)
	if err != nil {
		t.Fatalf("ClaimsFor: %v", err)
	}

	a, _ := json.Marshal(first.Document())
	b, _ := json.Marshal(second.Document())
	if string(a) != string(b) {
		t.Errorf("two renderings of one row differ:\n%s\n%s", a, b)
	}
}

func TestTheClaimStringDoesNotLeak(t *testing.T) {
	t.Parallel()

	key := claimKey()
	claims, err := ClaimsFor(key, key.CreatedAt)
	if err != nil {
		t.Fatalf("ClaimsFor: %v", err)
	}

	rendered := claims.String()
	if !strings.Contains(rendered, key.AccountID.String()) {
		t.Errorf("the string form does not name the account, so a log line cannot be traced: %s", rendered)
	}
	if strings.Contains(rendered, key.UserID.String()) {
		t.Errorf("the string form carries the subject: %s", rendered)
	}
	if !strings.Contains(rendered, "active=true") {
		t.Errorf("the string form does not say the token is live: %s", rendered)
	}

	if got, want := InactiveClaims().String(), "apikeys.claims{active=false}"; got != want {
		t.Errorf("InactiveClaims().String() = %q, want %q", got, want)
	}
}
