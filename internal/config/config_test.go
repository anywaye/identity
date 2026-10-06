package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"
)

// lookupFrom builds a Lookup from a map, mirroring os.LookupEnv semantics
// (absent key -> ok=false, present-but-empty key -> ok=true, "").
func lookupFrom(env map[string]string) Lookup {
	return func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}
}

// signupTestKey is the SIGNUP_SIGNING_KEY every success case in this file
// supplies: 32 bytes, base64url, the shape the environment takes.
//
// It is a constant rather than a generated value because these tests compare
// the whole Config with reflect.DeepEqual, and a key that changed per run
// would have to be threaded through every expectation.
var signupTestKey = base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

// signupTestKeyValue is signupTestKey decoded, for the want side of the
// comparison.
var signupTestKeyValue = []byte("0123456789abcdef0123456789abcdef")

// withSignupKey returns a copy of env with SIGNUP_SIGNING_KEY set, for the
// cases that expect Load to succeed.
//
// Injected in the test loop rather than repeated in every map because a
// default every case must carry is a default a new case will forget — and
// the one case that must NOT carry it is the refusal case, which is about
// the key being absent.
func withSignupKey(env map[string]string) map[string]string {
	out := make(map[string]string, len(env)+1)
	for k, v := range env {
		out[k] = v
	}
	out["SIGNUP_SIGNING_KEY"] = signupTestKey
	return out
}

func TestLoad(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		env     map[string]string
		want    Config
		wantErr error
	}{
		{
			// THE ONE CASE WHERE THE ENVIRONMENT IS EMPTY, and it is a refusal.
			// SIGNUP_SIGNING_KEY is the one secret a boot cannot go without —
			// spam protection is not a feature a deployment enables or skips —
			// so "nothing set" is not a supported state the way it was before
			// the signed timestamp landed. See REPORT-identity-signuptimestamp-01.md
			// and loadSignupSigningKey's comment for the full argument.
			name:    "defaults without the signup key are refused",
			env:     map[string]string{},
			wantErr: ErrNoSignupSigningKey,
		},
		{
			// The same defaults WITH the one required secret: this is the
			// supported shape of an empty environment.
			name: "defaults with the signup key supplied",
			env:  map[string]string{"SIGNUP_SIGNING_KEY": signupTestKey},
			want: Config{Port: "8080", DatabaseURL: "", LogLevel: "info", SignupSigningKeyValue: signupTestKeyValue},
		},
		{
			name: "every value overridden",
			env: map[string]string{
				"PORT":         "3000",
				"DATABASE_URL": "postgres://identity@localhost:5432/identity",
				"LOG_LEVEL":    "debug",
			},
			want: Config{Port: "3000", DatabaseURL: "postgres://identity@localhost:5432/identity", LogLevel: "debug"},
		},
		{
			name: "empty DATABASE_URL means no database in v0",
			env:  map[string]string{"DATABASE_URL": ""},
			want: Config{Port: "8080", DatabaseURL: "", LogLevel: "info"},
		},
		{
			name: "LOG_LEVEL is normalised to lower case",
			env:  map[string]string{"LOG_LEVEL": "WARN"},
			want: Config{Port: "8080", DatabaseURL: "", LogLevel: "warn"},
		},
		{
			name: "unset values fall back to defaults one at a time",
			env:  map[string]string{"PORT": "9090"},
			want: Config{Port: "9090", DatabaseURL: "", LogLevel: "info"},
		},
		{
			name:    "empty PORT is a misconfiguration, not a default",
			env:     map[string]string{"PORT": ""},
			wantErr: ErrInvalidPort,
		},
		{
			name:    "non numeric PORT is rejected",
			env:     map[string]string{"PORT": "http"},
			wantErr: ErrInvalidPort,
		},
		{
			name:    "PORT zero is rejected",
			env:     map[string]string{"PORT": "0"},
			wantErr: ErrInvalidPort,
		},
		{
			name:    "PORT above the TCP range is rejected",
			env:     map[string]string{"PORT": "70000"},
			wantErr: ErrInvalidPort,
		},
		{
			name:    "negative PORT is rejected",
			env:     map[string]string{"PORT": "-1"},
			wantErr: ErrInvalidPort,
		},
		{
			name:    "unknown LOG_LEVEL is rejected",
			env:     map[string]string{"LOG_LEVEL": "chatty"},
			wantErr: ErrInvalidLogLevel,
		},
		{
			name:    "empty LOG_LEVEL is a misconfiguration",
			env:     map[string]string{"LOG_LEVEL": ""},
			wantErr: ErrInvalidLogLevel,
		},
		{
			name:    "non postgres DATABASE_URL is rejected",
			env:     map[string]string{"DATABASE_URL": "mysql://localhost/identity"},
			wantErr: ErrInvalidDatabaseURL,
		},
		{
			name:    "DATABASE_URL without a scheme is rejected",
			env:     map[string]string{"DATABASE_URL": "localhost:5432/identity"},
			wantErr: ErrInvalidDatabaseURL,
		},
		{
			name: "postgresql scheme is accepted",
			env:  map[string]string{"DATABASE_URL": "postgresql://localhost/identity?sslmode=disable"},
			want: Config{Port: "8080", DatabaseURL: "postgresql://localhost/identity?sslmode=disable", LogLevel: "info"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			env := tt.env
			if tt.wantErr == nil {
				// Every case that expects success supplies the one required
				// secret; see withSignupKey for why it is injected here.
				env = withSignupKey(env)
				if tt.want.SignupSigningKeyValue == nil {
					tt.want.SignupSigningKeyValue = signupTestKeyValue
				}
			}

			got, err := Load(lookupFrom(env))

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Load() error = %v, want errors.Is(_, %v)", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() unexpected error: %v", err)
			}
			// The one field Load fills in on its own is MFAIssuerLabel, and it is
			// set BEFORE the comparison rather than repeated in every table row: a
			// default every case must carry is a default a new case will forget.
			if tt.want.MFAIssuerLabel == "" {
				tt.want.MFAIssuerLabel = DefaultMFAIssuer
			}

			// Compared field by field rather than with ==, because Config carries the
			// decoded MFA key as a []byte and a struct containing a slice is not
			// comparable. Saying so here is better than a test that stopped checking
			// the struct the next time a key appeared in it.
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Load() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestLoadNilLookupReturnsDefaults is the defaults claim, and the nil lookup is
// now a REFUSAL rather than a success.
//
// A nil lookup means "no environment", and SIGNUP_SIGNING_KEY is the one secret
// whose absence is a startup failure rather than a supported state — spam
// protection is not a feature a deployment enables or skips. So the contract
// this test used to assert (empty environment -> defaults) is gone: an empty
// environment is a deployment whose signup form is undefended, and the process
// refuses to start. The defaults themselves are asserted by the table above,
// which supplies the key.
func TestLoadNilLookupReturnsDefaults(t *testing.T) {
	t.Parallel()

	_, err := Load(nil)
	if !errors.Is(err, ErrNoSignupSigningKey) {
		t.Fatalf("Load(nil) error = %v, want errors.Is(_, %v): an empty environment has no "+
			" SIGNUP_SIGNING_KEY, and a boot without it is a startup failure", err, ErrNoSignupSigningKey)
	}
}

// TestTheSignupSigningKeyIsRequiredIsValidatedAndNeverDefaulted is the boot
// contract of the fifth secret, as a table over its three states.
//
// THE THREE STATES, and why each is what it is:
//
//	absent      a startup failure. Spam protection is not a feature a deployment
//	            enables or skips, so there is no configuration in which this
//	            process starts without the key. ErrNoSignupSigningKey names the
//	            variable, because that is the whole of the fix.
//	present     the key, decoded and carried. base64url without padding, the
//	            same shape as MFA_ENCRYPTION_KEY, so an operator pasting from the
//	            same secret store does not have to think about it.
//	unreadable  a startup failure, and a DISTINCT sentinel. An operator who
//	            pasted a 16-byte key has configured half the entropy they think
//	            they have, and a timestamp signed under a short key is a
//	            timestamp anybody can forge. "Not configured" and "invalid" lead
//	            to different fixes, so they are different errors.
func TestTheSignupSigningKeyIsRequiredIsValidatedAndNeverDefaulted(t *testing.T) {
	t.Parallel()

	t.Run("absent is a startup failure that names the variable", func(t *testing.T) {
		t.Parallel()

		_, err := Load(lookupFrom(map[string]string{}))
		if !errors.Is(err, ErrNoSignupSigningKey) {
			t.Fatalf("Load() error = %v, want errors.Is(_, %v)", err, ErrNoSignupSigningKey)
		}
		if !strings.Contains(err.Error(), "SIGNUP_SIGNING_KEY") {
			t.Errorf("the refusal does not name SIGNUP_SIGNING_KEY: %v", err)
		}
	})

	t.Run("present and valid is decoded and carried", func(t *testing.T) {
		t.Parallel()

		cfg, err := Load(lookupFrom(map[string]string{"SIGNUP_SIGNING_KEY": signupTestKey}))
		if err != nil {
			t.Fatalf("Load() unexpected error: %v", err)
		}
		if !bytes.Equal(cfg.SignupSigningKeyValue, signupTestKeyValue) {
			t.Errorf("SignupSigningKeyValue = %v, want the 32 decoded bytes", cfg.SignupSigningKeyValue)
		}
	})

	t.Run("a key that is not base64url is a startup failure", func(t *testing.T) {
		t.Parallel()

		_, err := Load(lookupFrom(map[string]string{"SIGNUP_SIGNING_KEY": "not base64url!"}))
		if !errors.Is(err, ErrInvalidSignupSigningKey) {
			t.Fatalf("Load() error = %v, want errors.Is(_, %v)", err, ErrInvalidSignupSigningKey)
		}
	})

	t.Run("a key of the wrong length is a startup failure, never stretched", func(t *testing.T) {
		t.Parallel()

		// 16 bytes: the mistake an operator makes by halving a key they were
		// given, and the reason the refusal exists — a stretched key would
		// verify timestamps signed under entropy the operator does not have.
		short := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
		_, err := Load(lookupFrom(map[string]string{"SIGNUP_SIGNING_KEY": short}))
		if !errors.Is(err, ErrInvalidSignupSigningKey) {
			t.Fatalf("Load() error = %v, want errors.Is(_, %v)", err, ErrInvalidSignupSigningKey)
		}
		if !strings.Contains(err.Error(), "16") {
			t.Errorf("the refusal does not say how many bytes the key decoded to: %v", err)
		}
	})

	t.Run("an empty value is absent, not a zero-length key", func(t *testing.T) {
		t.Parallel()

		// Present-but-empty is the state a deployment reaches by setting the
		// variable to nothing, and it must read as ABSENT: the fix is to
		// provide a key, not to wonder why an empty one was rejected.
		_, err := Load(lookupFrom(map[string]string{"SIGNUP_SIGNING_KEY": ""}))
		if !errors.Is(err, ErrNoSignupSigningKey) {
			t.Fatalf("Load() error = %v, want errors.Is(_, %v)", err, ErrNoSignupSigningKey)
		}
	})
}

func TestConfigAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		port string
		want string
	}{
		{name: "default port", port: "8080", want: ":8080"},
		{name: "explicit port", port: "3000", want: ":3000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := (Config{Port: tt.port}).Addr(); got != tt.want {
				t.Errorf("Addr() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConfigSlogLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		logLevel string
		want     slog.Level
	}{
		{logLevel: "debug", want: slog.LevelDebug},
		{logLevel: "info", want: slog.LevelInfo},
		{logLevel: "warn", want: slog.LevelWarn},
		{logLevel: "error", want: slog.LevelError},
	}

	for _, tt := range tests {
		t.Run(tt.logLevel, func(t *testing.T) {
			t.Parallel()

			if got := (Config{LogLevel: tt.logLevel}).SlogLevel(); got != tt.want {
				t.Errorf("SlogLevel() = %v, want %v", got, tt.want)
			}
		})
	}
}
