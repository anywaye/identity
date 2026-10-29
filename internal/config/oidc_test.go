package config

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/anywaye/identity/internal/oidc"
)


func TestLoadOIDC(t *testing.T) {
	t.Parallel()

	const keyPEM = "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n"

	tests := []struct {
		name    string
		env     map[string]string
		wantErr error
		assert  func(t *testing.T, cfg Config)
	}{
		{
			name: "no OIDC configuration at all",
			env:  map[string]string{},
			assert: func(t *testing.T, cfg Config) {
				if cfg.OIDCEnabled() {
					t.Error("OIDCEnabled with no issuer and no key; the surface would be mounted and broken")
				}
			},
		},
		{
			name: "an issuer with no key",
			env:  map[string]string{"OIDC_ISSUER": "https://identity.anywaye.com"},
			wantErr: ErrInvalidOIDC,
		},
		{
			name:    "a key with no issuer",
			env:     map[string]string{"OIDC_SIGNING_KEY": keyPEM, "OIDC_SIGNING_KEY_ID": "anywaye-2026-09"},
			wantErr: ErrInvalidOIDC,
		},
		{
			name: "an issuer, a key and a key id",
			env: map[string]string{
				"OIDC_ISSUER":         "https://identity.anywaye.com",
				"OIDC_SIGNING_KEY":    keyPEM,
				"OIDC_SIGNING_KEY_ID": "anywaye-2026-09",
			},
			assert: func(t *testing.T, cfg Config) {
				if !cfg.OIDCEnabled() {
					t.Error("OIDCEnabled is false with a complete configuration")
				}
				if cfg.OIDCIssuer != "https://identity.anywaye.com" {
					t.Errorf("OIDCIssuer = %q", cfg.OIDCIssuer)
				}
				if cfg.OIDCKeyID != "anywaye-2026-09" {
					t.Errorf("OIDCKeyID = %q", cfg.OIDCKeyID)
				}
				if cfg.OIDCAllowInsecure {
					t.Error("OIDCAllowInsecure defaults to true; an http issuer must be asked for")
				}
			},
		},
		{
			name: "values are trimmed",
			env: map[string]string{
				"OIDC_ISSUER":         "  https://identity.anywaye.com  ",
				"OIDC_SIGNING_KEY":    keyPEM,
				"OIDC_SIGNING_KEY_ID": "  anywaye-2026-09  ",
			},
			assert: func(t *testing.T, cfg Config) {
				if cfg.OIDCIssuer != "https://identity.anywaye.com" {
					t.Errorf("OIDCIssuer = %q, want it trimmed", cfg.OIDCIssuer)
				}
				if cfg.OIDCKeyID != "anywaye-2026-09" {
					t.Errorf("OIDCKeyID = %q, want it trimmed", cfg.OIDCKeyID)
				}
			},
		},
		{
			name: "a key keeps its interior and loses its trailing whitespace",
			env: map[string]string{
				"OIDC_ISSUER":         "https://identity.anywaye.com",
				"OIDC_SIGNING_KEY":    keyPEM + "\n\n  ",
				"OIDC_SIGNING_KEY_ID": "anywaye-2026-09",
			},
			assert: func(t *testing.T, cfg Config) {
				if strings.HasSuffix(cfg.OIDCSigningKey, "\n") || strings.HasSuffix(cfg.OIDCSigningKey, " ") {
					t.Errorf("OIDCSigningKey = %q, want it trimmed", cfg.OIDCSigningKey)
				}
			},
		},
		{
			name: "an http issuer without the explicit opt-in",
			env: map[string]string{
				"OIDC_ISSUER":         "http://localhost:8080",
				"OIDC_SIGNING_KEY":    keyPEM,
				"OIDC_SIGNING_KEY_ID": "anywaye-2026-09",
			},
			wantErr: ErrInsecureOIDCIssuer,
		},
		{
			name: "an http issuer with the opt-in",
			env: map[string]string{
				"OIDC_ISSUER":         "http://localhost:8080",
				"OIDC_SIGNING_KEY":    keyPEM,
				"OIDC_SIGNING_KEY_ID": "anywaye-2026-09",
				"OIDC_ALLOW_INSECURE": "true",
			},
			assert: func(t *testing.T, cfg Config) {
				if !cfg.OIDCAllowInsecure {
					t.Error("OIDCAllowInsecure is false after being asked for")
				}
			},
		},
		{
			name: "a misspelled opt-in",
			env: map[string]string{
				"OIDC_ISSUER":         "https://identity.anywaye.com",
				"OIDC_SIGNING_KEY":    keyPEM,
				"OIDC_SIGNING_KEY_ID": "anywaye-2026-09",
				"OIDC_ALLOW_INSECURE": "yes-please",
			},
			wantErr: ErrInvalidOIDC,
		},
		{
			name: "an issuer that is not a URL",
			env: map[string]string{
				"OIDC_ISSUER":         "identity.anywaye.com",
				"OIDC_SIGNING_KEY":    keyPEM,
				"OIDC_SIGNING_KEY_ID": "anywaye-2026-09",
			},
			wantErr: ErrInvalidOIDC,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			env := map[string]string{}
			for key, value := range tt.env {
				env[key] = value
			}
			if _, set := env[oidc.LoginUIEnvVar]; !set && mentionsTheOIDCBlock(env) {
				env[oidc.LoginUIEnvVar] = "https://login.anywaye.com/sign-in/oidc"
			}
			if tt.wantErr == nil {
				env["SIGNUP_SIGNING_KEY"] = base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
			}

			cfg, err := Load(mapOf(env))
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Load = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			tt.assert(t, cfg)
		})
	}
}

func TestTheLoginUIIsPartOfTheOIDCBlock(t *testing.T) {
	t.Parallel()

	const keyPEM = "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n"

	block := map[string]string{
		"OIDC_ISSUER":         "https://identity.anywaye.com",
		"OIDC_SIGNING_KEY":    keyPEM,
		"OIDC_SIGNING_KEY_ID": "anywaye-2026-09",
	}

	tests := []struct {
		name    string
		env     map[string]string
		wantErr error
	}{
		{
			name:    "a complete block with no login UI",
			env:     block,
			wantErr: ErrInvalidOIDC,
		},
		{
			name: "a login UI with nothing to apply it to",
			env:  map[string]string{oidc.LoginUIEnvVar: "https://login.anywaye.com/sign-in/oidc"},
			wantErr: ErrInvalidOIDC,
		},
		{
			name: "a login UI that is not an address a browser can be sent to",
			env: map[string]string{
				"OIDC_ISSUER":         "https://identity.anywaye.com",
				"OIDC_SIGNING_KEY":    keyPEM,
				"OIDC_SIGNING_KEY_ID": "anywaye-2026-09",
				oidc.LoginUIEnvVar:    "javascript:alert(1)",
			},
			wantErr: ErrInvalidOIDC,
		},
		{
			name: "a complete block",
			env: map[string]string{
				"OIDC_ISSUER":         "https://identity.anywaye.com",
				"OIDC_SIGNING_KEY":    keyPEM,
				"OIDC_SIGNING_KEY_ID": "anywaye-2026-09",
				oidc.LoginUIEnvVar:    "https://login.anywaye.com/sign-in/oidc",
				"SIGNUP_SIGNING_KEY": base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg, err := Load(mapOf(tt.env))
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Load = %v, want %v", err, tt.wantErr)
				}
				if !strings.Contains(err.Error(), oidc.LoginUIEnvVar) {
					t.Errorf("the refusal does not name %s: %v", oidc.LoginUIEnvVar, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.OIDCLoginUIURL != "https://login.anywaye.com/sign-in/oidc" {
				t.Errorf("OIDCLoginUIURL = %q, want the configured one", cfg.OIDCLoginUIURL)
			}
		})
	}
}

func TestLoadTrimsTheSigningKey(t *testing.T) {
	t.Parallel()

	env := map[string]string{
		"OIDC_ISSUER":         "https://identity.anywaye.com",
		"OIDC_SIGNING_KEY":    "  -----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----  ",
		"OIDC_SIGNING_KEY_ID": "k1",
		oidc.LoginUIEnvVar:    "https://login.anywaye.com/sign-in/oidc",
		"SIGNUP_SIGNING_KEY": base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
	}
	cfg, err := Load(mapOf(env))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !strings.HasPrefix(cfg.OIDCSigningKey, "-----BEGIN") {
		t.Errorf("OIDCSigningKey = %q, want it to start at the PEM header", cfg.OIDCSigningKey)
	}
}

func mapOf(env map[string]string) Lookup {
	return func(key string) (string, bool) {
		value, ok := env[key]
		return value, ok
	}
}

func mentionsTheOIDCBlock(env map[string]string) bool {
	for _, key := range []string{"OIDC_ISSUER", "OIDC_SIGNING_KEY", "OIDC_SIGNING_KEY_ID"} {
		if env[key] != "" {
			return true
		}
	}
	return false
}
