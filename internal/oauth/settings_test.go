package oauth

import (
	"encoding/base64"
	"errors"
	"testing"
)


func TestSettingsValidateAcceptsAbsentOAuth(t *testing.T) {
	t.Parallel()

	var s Settings
	if err := s.Validate(); err != nil {
		t.Errorf("Validate on the zero Settings = %v, want nil", err)
	}
	if s.Enabled() {
		t.Error("Enabled on the zero Settings, want false")
	}
}

func TestSettingsValidateRejectsAHalfConfiguredProvider(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		s    Settings
	}{
		{
			name: "google without a secret",
			s: Settings{
				RedirectBaseURL: "https://identity.anywaye.com",
				EncryptionKey:   testKeyBase64(1),
				Google:          ProviderSettings{ClientID: "id"},
			},
		},
		{
			name: "github without an id",
			s: Settings{
				RedirectBaseURL: "https://identity.anywaye.com",
				EncryptionKey:   testKeyBase64(2),
				GitHub:          ProviderSettings{ClientSecret: "secret"},
			},
		},
		{
			name: "microsoft without a secret",
			s: Settings{
				RedirectBaseURL: "https://identity.anywaye.com",
				EncryptionKey:   testKeyBase64(3),
				Microsoft:       ProviderSettings{ClientID: "id"},
			},
		},
		{
			name: "apple without a secret",
			s: Settings{
				RedirectBaseURL: "https://identity.anywaye.com",
				EncryptionKey:   testKeyBase64(4),
				Apple:           ProviderSettings{ClientID: "id"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := tt.s.Validate(); !errors.Is(err, ErrIncompleteProvider) {
				t.Errorf("Validate = %v, want ErrIncompleteProvider", err)
			}
		})
	}
}

func TestSettingsValidateRejectsAProviderMissingItsSharedSettings(t *testing.T) {
	t.Parallel()

	google := ProviderSettings{ClientID: "id", ClientSecret: "secret"}

	tests := []struct {
		name string
		s    Settings
	}{
		{name: "no redirect base url", s: Settings{EncryptionKey: testKeyBase64(1), Google: google}},
		{name: "no encryption key", s: Settings{RedirectBaseURL: "https://identity.anywaye.com", Google: google}},
		{name: "neither", s: Settings{Google: google}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := tt.s.Validate(); !errors.Is(err, ErrIncompleteSettings) {
				t.Errorf("Validate = %v, want ErrIncompleteSettings", err)
			}
		})
	}
}

func TestSettingsValidateRejectsABadEncryptionKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		key  string
	}{
		{name: "not base64", key: "not base64 at all"},
		{name: "base64 of the wrong length", key: testKeyBase64(3)[:40]},
		{name: "a passphrase rather than a key", key: "correct horse battery staple"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := Settings{RedirectBaseURL: "https://identity.anywaye.com", EncryptionKey: tt.key}
			if err := s.Validate(); !errors.Is(err, ErrInvalidEncKey) {
				t.Errorf("Validate = %v, want ErrInvalidEncKey", err)
			}
		})
	}
}

func TestSettingsValidateChecksTheKeyWithoutAnyProvider(t *testing.T) {
	t.Parallel()

	s := Settings{EncryptionKey: "not a key"}
	if err := s.Validate(); !errors.Is(err, ErrInvalidEncKey) {
		t.Errorf("Validate = %v, want ErrInvalidEncKey", err)
	}
}

func TestSettingsValidateRejectsABadRedirectBase(t *testing.T) {
	t.Parallel()

	for _, base := range []string{
		"identity.anywaye.com",
		"ftp://identity.anywaye.com",
		"https://",
		"https://identity.anywaye.com?next=/v1",
		"https://identity.anywaye.com#frag",
	} {
		t.Run(base, func(t *testing.T) {
			t.Parallel()

			s := Settings{RedirectBaseURL: base}
			if err := s.Validate(); !errors.Is(err, ErrInvalidRedirectBaseURL) {
				t.Errorf("Validate(%q) = %v, want ErrInvalidRedirectBaseURL", base, err)
			}
		})
	}
}

func TestSettingsValidateAcceptsAWorkingConfiguration(t *testing.T) {
	t.Parallel()

	s := Settings{
		RedirectBaseURL: "https://identity.anywaye.com",
		EncryptionKey:   testKeyBase64(1),
		Google:          ProviderSettings{ClientID: "id", ClientSecret: "secret"},
		GitHub:          ProviderSettings{ClientID: "id2", ClientSecret: "secret2"},
		Microsoft:       ProviderSettings{ClientID: "id3", ClientSecret: "secret3"},
		Apple:           ProviderSettings{ClientID: "id4", ClientSecret: "secret4"},
	}

	if err := s.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !s.Enabled() {
		t.Error("Enabled = false with four configured providers")
	}

	providers := s.Providers()
	if len(providers) != 4 {
		t.Fatalf("Providers() returned %d, want 4", len(providers))
	}
	for _, p := range providers {
		if p.ClientID == "" || p.ClientSecret == "" {
			t.Errorf("provider %q has no credentials", p.Name)
		}
		if p.AuthorizeURL == "" || p.TokenURL == "" {
			t.Errorf("provider %q has an incomplete endpoint set: %+v", p.Name, p)
		}
		if p.Name != ProviderApple && p.UserInfoURL == "" {
			t.Errorf("provider %q has no userinfo endpoint: %+v", p.Name, p)
		}
	}
	if providers[0].Name != ProviderGoogle || providers[1].Name != ProviderGitHub || providers[2].Name != ProviderMicrosoft || providers[3].Name != ProviderApple {
		t.Errorf("Providers() = %q, %q, %q, %q; want a stable order", providers[0].Name, providers[1].Name, providers[2].Name, providers[3].Name)
	}
}

func TestProviderRedirectURIIsStable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		base string
		want string
	}{
		{base: "https://identity.anywaye.com", want: "https://identity.anywaye.com/v1/auth/oauth/google/callback"},
		{base: "https://identity.anywaye.com/", want: "https://identity.anywaye.com/v1/auth/oauth/google/callback"},
		{base: "https://example.test/identity", want: "https://example.test/identity/v1/auth/oauth/google/callback"},
	}

	for _, tt := range tests {
		t.Run(tt.base, func(t *testing.T) {
			t.Parallel()

			if got := Google().RedirectURI(tt.base); got != tt.want {
				t.Errorf("RedirectURI(%q) = %q, want %q", tt.base, got, tt.want)
			}
		})
	}
}

func TestConfiguredProvidersAreAllKnown(t *testing.T) {
	t.Parallel()

	s := Settings{
		RedirectBaseURL: "https://identity.anywaye.com",
		EncryptionKey:   testKeyBase64(1),
		Google:          ProviderSettings{ClientID: "id", ClientSecret: "secret"},
		GitHub:          ProviderSettings{ClientID: "id2", ClientSecret: "secret2"},
	}

	for _, p := range s.Providers() {
		found := false
		for _, known := range knownProviders {
			if p.Name == known {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("provider %q is not in knownProviders %v", p.Name, knownProviders)
		}
	}
}

func TestRegistryLookupDoesNotDistinguishUnconfiguredFromUnknown(t *testing.T) {
	t.Parallel()

	configured := Google()
	configured.ClientID = "id"
	configured.ClientSecret = "secret"

	registry, err := NewRegistry("https://identity.anywaye.com", configured)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	_, googleErr := registry.Lookup(ProviderGoogle)
	if googleErr != nil {
		t.Fatalf("Lookup(%q) = %v, want the configured provider", ProviderGoogle, googleErr)
	}

	for _, name := range []string{ProviderGitHub, ProviderMicrosoft, ProviderApple, "netflix", "", "GOOGLE", "../google"} {
		_, err := registry.Lookup(name)
		if !errors.Is(err, ErrUnknownProvider) {
			t.Errorf("Lookup(%q) = %v, want ErrUnknownProvider", name, err)
		}
	}
}

func TestNewRegistryRejectsABadBase(t *testing.T) {
	t.Parallel()

	if _, err := NewRegistry("nope", Google()); !errors.Is(err, ErrInvalidRedirectBaseURL) {
		t.Errorf("NewRegistry = %v, want ErrInvalidRedirectBaseURL", err)
	}
}

func TestNewRegistryDropsUnconfiguredProviders(t *testing.T) {
	t.Parallel()

	google := Google()
	google.ClientID = "id"
	google.ClientSecret = "secret"

	registry, err := NewRegistry("https://identity.anywaye.com", google, GitHub())
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	if got := registry.Names(); len(got) != 1 || got[0] != ProviderGoogle {
		t.Errorf("Names() = %v, want [google]", got)
	}
	if registry.Empty() {
		t.Error("Empty() = true with one configured provider")
	}
}

func TestEmptyRegistryIsEmpty(t *testing.T) {
	t.Parallel()

	registry, err := NewRegistry("https://identity.anywaye.com")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if !registry.Empty() {
		t.Error("Empty() = false with no providers")
	}
	if got := registry.Names(); len(got) != 0 {
		t.Errorf("Names() = %v, want empty", got)
	}
}

func testKeyBase64(n byte) string {
	return base64.StdEncoding.EncodeToString(testKey(n))
}
