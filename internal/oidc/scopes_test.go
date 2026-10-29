package oidc

import (
	"slices"
	"testing"
)


func TestSupportedScopesAreExactlyTheFive(t *testing.T) {
	t.Parallel()

	want := []string{"openid", "email", "profile", "accounts", "publish"}

	if !slices.Equal(SupportedScopes, want) {
		t.Fatalf("SupportedScopes = %v, want %v", SupportedScopes, want)
	}
}

func TestIsSupportedScope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
		want bool
	}{
		{name: "openid", give: ScopeOpenID, want: true},
		{name: "email", give: ScopeEmail, want: true},
		{name: "profile", give: ScopeProfile, want: true},
		{name: "accounts", give: ScopeAccounts, want: true},

		{name: "phone is not a anywaye scope", give: "phone"},
		{name: "address is not a anywaye scope", give: "address"},
		{name: "offline_access is not offered", give: "offline_access"},

		{name: "a plural is not the singular", give: "profiles"},
		{name: "an underscore is not a hyphen", give: "open-id"},
		{name: "empty", give: ""},
		{name: "nonsense", give: "admin:all"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := IsSupportedScope(tt.give); got != tt.want {
				t.Errorf("IsSupportedScope(%q) = %t, want %t", tt.give, got, tt.want)
			}
		})
	}
}

func TestNormalizeScopesIsStableAndDeduplicated(t *testing.T) {
	t.Parallel()

	got := NormalizeScopes([]string{"email", "openid", "email", "profile"})
	want := []string{"email", "openid", "profile"}

	if !slices.Equal(got, want) {
		t.Errorf("NormalizeScopes = %v, want %v", got, want)
	}
}

func TestNormalizeScopesDropsTheUnsupported(t *testing.T) {
	t.Parallel()

	got := NormalizeScopes([]string{"openid", "phone", "email"})

	if !slices.Equal(got, []string{"email", "openid"}) {
		t.Errorf("NormalizeScopes = %v, want the supported two in order", got)
	}
}

func TestFirstUnsupportedNamesTheScope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give []string
		want string
	}{
		{name: "all supported", give: []string{"openid", "email"}, want: ""},
		{name: "none requested", give: nil, want: ""},
		{name: "one unsupported", give: []string{"openid", "phone"}, want: "phone"},
		{name: "the first of several", give: []string{"nope", "also-nope"}, want: "nope"},
		{name: "reported in the order requested", give: []string{"phone", "address"}, want: "phone"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := FirstUnsupported(tt.give); got != tt.want {
				t.Errorf("FirstUnsupported(%v) = %q, want %q", tt.give, got, tt.want)
			}
		})
	}
}

func TestValidateRequestedScopesRequiresOpenID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		give    []string
		wantErr string
	}{
		{name: "openid with others", give: []string{"openid", "email"}},
		{name: "openid alone", give: []string{"openid"}},
		{name: "email alone", give: []string{"email"}, wantErr: "openid"},
		{name: "nothing at all", give: nil, wantErr: "openid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateRequestedScopes(tt.give)
			switch {
			case err == nil && tt.wantErr != "":
				t.Fatalf("ValidateRequestedScopes(%v) = nil, want an error naming %q", tt.give, tt.wantErr)
			case err != nil && tt.wantErr == "":
				t.Fatalf("ValidateRequestedScopes(%v) = %v, want nil", tt.give, err)
			case err != nil && !containsAll(err.Error(), tt.wantErr):
				t.Errorf("error = %q, want it to name %q", err, tt.wantErr)
			}
		})
	}
}

func containsAll(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
