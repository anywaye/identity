package apikeys

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)


func TestTheWireFormatIsAFixedShape(t *testing.T) {
	for i := range 32 {
		token, digest, err := NewToken()
		if err != nil {
			t.Fatalf("NewToken: %v", err)
		}

		if !strings.HasPrefix(token, Prefix) {
			t.Fatalf("token %d does not start with %q: %q", i, Prefix, token)
		}

		secret, ok := strings.CutPrefix(token, Prefix)
		if !ok {
			t.Fatalf("token %d does not carry the prefix", i)
		}
		if len(secret) != 43 {
			t.Errorf("token %d's secret is %d characters, want 43", i, len(secret))
		}
		if len(token) != len(Prefix)+43 {
			t.Errorf("token %d is %d characters, want %d", i, len(token), len(Prefix)+43)
		}
		if strings.ContainsAny(secret, "+/=") {
			t.Errorf("token %d's secret is not base64url without padding: %q", i, secret)
		}

		sum := sha256.Sum256([]byte(token))
		if want := hex.EncodeToString(sum[:]); digest != want {
			t.Errorf("token %d's digest is %q, want the SHA-256 of the whole value %q", i, digest, want)
		}
	}
}

func TestTokensAreDistinct(t *testing.T) {
	seen := make(map[string]string, 64)
	for range 64 {
		token, digest, err := NewToken()
		if err != nil {
			t.Fatalf("NewToken: %v", err)
		}
		if previous, clash := seen[digest]; clash {
			t.Fatalf("two mints produced the same digest: %q and %q", previous, token)
		}
		seen[digest] = token
	}
}

func TestThePrefixIsRecognisable(t *testing.T) {
	token, _, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}

	if !strings.HasPrefix(token, "anywaye_") {
		t.Errorf("the prefix is %q, want something that names the platform", Prefix)
	}
	if len(Prefix) < 6 {
		t.Errorf("the prefix is %d characters, too short to be a useful grep term", len(Prefix))
	}
	if !strings.Contains(Prefix, "_") {
		t.Error("the prefix does not end in a separator, so a truncated log line could read as a valid token")
	}
}

func TestDigestOfAnythingIsWellFormed(t *testing.T) {
	token, _, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}

	cases := []struct {
		name      string
		presented string
	}{
		{"empty", ""},
		{"one character", "x"},
		{"the prefix alone", Prefix},
		{"the prefix and nothing else", Prefix},
		{"a bare session token", strings.Repeat("A", 43)},
		{"a session token with a prefix glued on", Prefix + strings.Repeat("A", 43)},
		{"a real token", token},
		{"a real token with one character changed", token[:len(token)-1] + "z"},
		{"a real token with one character removed", token[:len(token)-1]},
		{"a real token doubled", token + token},
		{"a non-base64url body", Prefix + "!!!!"},
		{"very long", Prefix + strings.Repeat("A", 4096)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			digest := Digest(tc.presented)
			if len(digest) != 64 {
				t.Errorf("Digest returned %d characters, want 64", len(digest))
			}
			if digest != strings.ToLower(digest) {
				t.Error("the digest is not lower case, so an index built on it would miss")
			}
			if _, err := hex.DecodeString(digest); err != nil {
				t.Errorf("the digest is not hex: %v", err)
			}
		})
	}
}

func TestDigestDistinguishesEveryCharacter(t *testing.T) {
	token, digest, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}

	for at := range len(token) {
		altered := make([]byte, len(token))
		copy(altered, token)
		if altered[at] == 'A' {
			altered[at] = 'B'
		} else {
			altered[at] = 'A'
		}
		if Digest(string(altered)) == digest {
			t.Fatalf("changing byte %d of the token did not change the digest", at)
		}
	}
}


func TestEveryScopeIsWiredToARoute(t *testing.T) {
	want := map[string][]string{
		ScopeAccountsRead: {
			"GET /v1/accounts",
			"GET /v1/accounts/{accountID}",
			"GET /v1/accounts/{accountID}/members",
		},
		ScopeAccountsWrite: {
			"POST /v1/accounts",
			"PATCH /v1/accounts/{accountID}",
			"POST /v1/accounts/{accountID}/invitations",
			"PATCH /v1/accounts/{accountID}/members/{userID}",
			"DELETE /v1/accounts/{accountID}/members/{userID}",
			"POST /v1/invitations/accept",
		},
		ScopeAccountsDelete: {
			"DELETE /v1/accounts/{accountID}",
		},
		ScopeOIDCClientsWrite: {
			"POST /v1/accounts/{accountID}/oidc-clients",
			"GET /v1/accounts/{accountID}/oidc-clients",
			"GET /v1/accounts/{accountID}/oidc-clients/{clientID}",
			"DELETE /v1/accounts/{accountID}/oidc-clients/{clientID}",
		},
		ScopeAuditLogRead: {
			"GET /v1/accounts/{accountID}/admin/audit-log",
		},
		ScopeAccountInvitationsWrite: {
			"DELETE /v1/accounts/{accountID}/admin/invitations/{invitationID}",
			"POST /v1/accounts/{accountID}/admin/invitation-revocations",
		},
		ScopeSessionsWrite: {
			"POST /v1/session-links",
		},
		ScopeUsersDisable: {
			"POST /v1/users/{userID}/disable",
			"POST /v1/users/{userID}/enable",
		},
		ScopeTokensIntrospect: {
			"POST /v1/introspections",
		},
	}

	if len(want) != len(AllScopes()) {
		t.Fatalf("this test knows %d scopes and AllScopes lists %d: %v",
			len(want), len(AllScopes()), AllScopes())
	}
	for _, scope := range AllScopes() {
		routes, known := want[scope]
		if !known {
			t.Errorf("scope %q is in the vocabulary and has no route listed here, so nothing tests where it is enforced", scope)
			continue
		}
		if len(routes) == 0 {
			t.Errorf("scope %q is enforced on no route at all, which is what a comment with a type looks like", scope)
		}
	}
}

func TestAllScopesAreInCoreShape(t *testing.T) {
	for _, scope := range AllScopes() {
		resource, action, found := strings.Cut(scope, ":")
		if !found {
			t.Errorf("scope %q has no resource:action separator", scope)
			continue
		}
		if resource == "" || action == "" {
			t.Errorf("scope %q has an empty half", scope)
		}
		if resource != strings.ToLower(resource) || action != strings.ToLower(action) {
			t.Errorf("scope %q is not lower case", scope)
		}
	}
}

func TestNoScopeGrantsEverything(t *testing.T) {
	for _, scope := range AllScopes() {
		if scope == "*" || strings.Contains(scope, "*") {
			t.Errorf("scope %q is a wildcard; a scope set is a list of capabilities, not a pattern", scope)
		}
	}
	if HasScope(nil, "*") {
		t.Error("an empty scope set satisfies the wildcard, which is the same bug")
	}
}

func TestValidateScopes(t *testing.T) {
	cases := []struct {
		name    string
		give    []string
		want    []string
		wantErr *FieldError
	}{
		{
			name: "one supported scope",
			give: []string{ScopeAccountsRead},
			want: []string{ScopeAccountsRead},
		},
		{
			name: "sorted and deduplicated",
			give: []string{ScopeOIDCClientsWrite, ScopeAccountsRead, ScopeAccountsRead},
			want: []string{ScopeAccountsRead, ScopeOIDCClientsWrite},
		},
		{
			name: "surrounding whitespace is trimmed, and only that",
			give: []string{" " + ScopeAccountsRead + " "},
			want: []string{ScopeAccountsRead},
		},
		{
			name: "empty is refused rather than defaulted",
			give:    nil,
			wantErr: &FieldError{Field: "scopes", Code: CodeRequired},
		},
		{
			name:    "an empty list is the same as none",
			give:    []string{},
			wantErr: &FieldError{Field: "scopes", Code: CodeRequired},
		},
		{
			name:    "a list of empty strings is still no scopes",
			give:    []string{"", "  "},
			wantErr: &FieldError{Field: "scopes", Code: CodeRequired},
		},
		{
			name: "an unknown scope is refused, not dropped",
			give:    []string{ScopeAccountsRead, "accounts:admin"},
			wantErr: &FieldError{Field: "scopes", Code: CodeUnsupported},
		},
		{
			name: "a prefix of a real scope is not a real scope",
			give:    []string{"accounts"},
			wantErr: &FieldError{Field: "scopes", Code: CodeUnsupported},
		},
		{
			name:    "a superstring of a real scope is not a real scope",
			give:    []string{ScopeAccountsRead + "s"},
			wantErr: &FieldError{Field: "scopes", Code: CodeUnsupported},
		},
		{
			name:    "case does not fold",
			give:    []string{"Accounts:Read"},
			wantErr: &FieldError{Field: "scopes", Code: CodeUnsupported},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateScopes(tc.give)
			if tc.wantErr != nil {
				var fieldErr *FieldError
				assertFieldError(t, err, &fieldErr)
				if *fieldErr != *tc.wantErr {
					t.Fatalf("error = %+v, want %+v", *fieldErr, *tc.wantErr)
				}
				if got != nil {
					t.Errorf("a refused scope list still returned %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateScopes(%v): %v", tc.give, err)
			}
			assertScopes(t, got, tc.want)
		})
	}
}

func TestHasScope(t *testing.T) {
	given := []string{ScopeAccountsRead, ScopeOIDCClientsWrite}

	cases := []struct {
		name  string
		held  []string
		scope string
		want  bool
	}{
		{"held", given, ScopeAccountsRead, true},
		{"held, the second", given, ScopeOIDCClientsWrite, true},
		{"not held", given, ScopeAccountsDelete, false},
		{"not held, not in the vocabulary", given, "admin", false},
		{"an empty set holds nothing", nil, ScopeAccountsRead, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasScope(tc.held, tc.scope); got != tc.want {
				t.Errorf("HasScope(%v, %q) = %t, want %t", tc.held, tc.scope, got, tc.want)
			}
		})
	}
}

func TestHasScopeIsNotAPrefixMatch(t *testing.T) {
	given := []string{ScopeAccountsRead}
	for _, almost := range []string{"accounts", ScopeAccountsRead + "s", "accounts:Read", "accounts:read:all"} {
		if HasScope(given, almost) {
			t.Errorf("HasScope(%v, %q) is true; the comparison is a prefix match", given, almost)
		}
	}
}


func TestValidateName(t *testing.T) {
	cases := []struct {
		name    string
		give    string
		want    string
		wantErr *FieldError
	}{
		{name: "the shape a settings page shows", give: "ci-deploy", want: "ci-deploy"},
		{name: "spaces inside are kept", give: "GitHub Actions (main)", want: "GitHub Actions (main)"},
		{name: "surrounding whitespace is trimmed", give: "  staging  ", want: "staging"},
		{name: "empty", give: "", wantErr: &FieldError{Field: "name", Code: CodeRequired}},
		{name: "whitespace only", give: "   ", wantErr: &FieldError{Field: "name", Code: CodeRequired}},
		{
			name: "at the limit",
			give: strings.Repeat("n", MaxNameLength),
			want: strings.Repeat("n", MaxNameLength),
		},
		{
			name:    "over the limit",
			give:    strings.Repeat("n", MaxNameLength+1),
			wantErr: &FieldError{Field: "name", Code: CodeTooLong},
		},
		{
			name: "a multi-byte name is counted in characters",
			give: strings.Repeat("é", MaxNameLength),
			want: strings.Repeat("é", MaxNameLength),
		},
		{
			name:    "an interior control character is not a name",
			give:    "deploy\nelsewhere",
			wantErr: &FieldError{Field: "name", Code: CodeInvalidFormat},
		},
		{
			name:    "a tab is a control character",
			give:    "deploy\telsewhere",
			wantErr: &FieldError{Field: "name", Code: CodeInvalidFormat},
		},
		{
			name: "a trailing newline is trimmed rather than refused",
			give: "deploy\n",
			want: "deploy",
		},
		{
			name:    "a DEL is a control character",
			give:    "deploy\x7felsewhere",
			wantErr: &FieldError{Field: "name", Code: CodeInvalidFormat},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateName(tc.give)
			if tc.wantErr != nil {
				var fieldErr *FieldError
				assertFieldError(t, err, &fieldErr)
				if *fieldErr != *tc.wantErr {
					t.Fatalf("error = %+v, want %+v", *fieldErr, *tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateName(%q): %v", tc.give, err)
			}
			if got != tc.want {
				t.Errorf("ValidateName(%q) = %q, want %q", tc.give, got, tc.want)
			}
		})
	}
}

func TestResolveExpiry(t *testing.T) {
	created := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name    string
		give    *time.Duration
		want    time.Time
		wantErr *FieldError
	}{
		{
			name: "no request takes the default",
			give: nil,
			want: created.Add(DefaultTTL),
		},
		{
			name: "a requested lifetime is honored",
			give: durationPtr(24 * time.Hour),
			want: created.Add(24 * time.Hour),
		},
		{
			name: "exactly the ceiling",
			give: durationPtr(MaxTTL),
			want: created.Add(MaxTTL),
		},
		{
			name:    "past the ceiling is refused, not clamped",
			give:    durationPtr(MaxTTL + time.Hour),
			wantErr: &FieldError{Field: "expires_in", Code: CodeTooLong},
		},
		{
			name:    "an explicit zero is not 'never'",
			give:    durationPtr(0),
			wantErr: &FieldError{Field: "expires_in", Code: CodeOutOfRange},
		},
		{
			name:    "a negative lifetime is refused",
			give:    durationPtr(-time.Hour),
			wantErr: &FieldError{Field: "expires_in", Code: CodeOutOfRange},
		},
		{
			name:    "under the floor is refused",
			give:    durationPtr(time.Second),
			wantErr: &FieldError{Field: "expires_in", Code: CodeOutOfRange},
		},
		{
			name: "exactly the floor",
			give: durationPtr(MinTTL),
			want: created.Add(MinTTL),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveExpiry(created, tc.give)
			if tc.wantErr != nil {
				var fieldErr *FieldError
				assertFieldError(t, err, &fieldErr)
				if *fieldErr != *tc.wantErr {
					t.Fatalf("error = %+v, want %+v", *fieldErr, *tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveExpiry: %v", err)
			}
			if !got.Equal(tc.want) {
				t.Errorf("expiry = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestEveryExpiryIsWithinTheCeiling(t *testing.T) {
	created := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	for _, give := range []*time.Duration{nil, durationPtr(MinTTL), durationPtr(MaxTTL), durationPtr(DefaultTTL)} {
		got, err := ResolveExpiry(created, give)
		if err != nil {
			t.Fatalf("ResolveExpiry(%v): %v", give, err)
		}
		if got.After(created.Add(MaxTTL)) {
			t.Errorf("expiry %s is past the %s ceiling", got, MaxTTL)
		}
		if !got.After(created) {
			t.Errorf("expiry %s is not after creation", got)
		}
	}
}

func TestTheCeilingIsAYear(t *testing.T) {
	if want := 365 * 24 * time.Hour; MaxTTL != want {
		t.Errorf("MaxTTL is %s, want %s", MaxTTL, want)
	}
	if DefaultTTL > MaxTTL {
		t.Errorf("DefaultTTL is %s, past the %s ceiling", DefaultTTL, MaxTTL)
	}
}

func TestDigestIsNotReversible(t *testing.T) {
	token, digest, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}

	secret := strings.TrimPrefix(token, Prefix)
	sum := sha256.Sum256([]byte(token))
	if digest != hex.EncodeToString(sum[:]) {
		t.Fatalf("the digest is not the SHA-256 of the presented value")
	}

	if digest == token {
		t.Error("the digest is the token")
	}
	if digest == secret {
		t.Error("the digest is the token's secret")
	}
	if strings.Contains(digest, token) || strings.Contains(digest, secret) {
		t.Error("the digest contains the credential it was made from")
	}
	encoded := hex.EncodeToString([]byte(token))
	for at := 0; at+8 <= len(encoded); at++ {
		window := encoded[at : at+8]
		if strings.Contains(digest, window) {
			t.Errorf("the digest contains %q, which is eight characters of the credential", window)
		}
	}
}

func TestDigestIsAFunctionOfTheWholeValue(t *testing.T) {
	token, digest, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	for range 4 {
		if Digest(token) != digest {
			t.Fatal("Digest is not stable for the same input")
		}
	}
}


func durationPtr(d time.Duration) *time.Duration { return &d }

func assertScopes(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("scopes = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("scopes = %v, want %v", got, want)
		}
	}
}

func assertFieldError(t *testing.T, err error, target **FieldError) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a validation error and got nil")
	}
	fe := &FieldError{}
	if !errors.As(err, &fe) {
		t.Fatalf("error is %T, want *FieldError", err)
	}
	*target = fe
}
