package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"
)

func lookupFrom(env map[string]string) Lookup {
	return func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}
}

var signupTestKey = base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

var signupTestKeyValue = []byte("0123456789abcdef0123456789abcdef")

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
			name:    "defaults without the signup key are refused",
			env:     map[string]string{},
			wantErr: ErrNoSignupSigningKey,
		},
		{
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
		{
			name: "NATS_URL is read when set",
			env:  map[string]string{"NATS_URL": "nats://localhost:4222"},
			want: Config{Port: "8080", DatabaseURL: "", LogLevel: "info", NATSURL: "nats://localhost:4222"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			env := tt.env
			if tt.wantErr == nil {
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
			if tt.want.MFAIssuerLabel == "" {
				tt.want.MFAIssuerLabel = DefaultMFAIssuer
			}
			if tt.want.RateLimit == (RateLimit{}) {
				tt.want.RateLimit = RateLimit{
					Window:          defaultRateLimitWindow,
					Signup:          defaultRateLimitSignup,
					Signin:          defaultRateLimitSignin,
					SignupTimestamp: defaultRateLimitSignupTimestamp,
					Recovery:        defaultRateLimitRecovery,
					AgentRegister:   defaultRateLimitAgentRegister,
				}
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Load() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestConfigNATSEnabled(t *testing.T) {
	t.Parallel()

	if (Config{}).NATSEnabled() {
		t.Error("an empty config reports NATS enabled; the publisher loop would start with no broker")
	}
	if !(Config{NATSURL: "nats://localhost:4222"}).NATSEnabled() {
		t.Error("a config with NATS_URL reports NATS disabled; the outbox would never drain")
	}
}

func TestLoadNilLookupReturnsDefaults(t *testing.T) {
	t.Parallel()

	_, err := Load(nil)
	if !errors.Is(err, ErrNoSignupSigningKey) {
		t.Fatalf("Load(nil) error = %v, want errors.Is(_, %v): an empty environment has no "+
			" SIGNUP_SIGNING_KEY, and a boot without it is a startup failure", err, ErrNoSignupSigningKey)
	}
}

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

func TestRequireEmailVerificationDefaultsOffAndParses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		env     map[string]string
		want    bool
		wantErr bool
	}{
		{
			name: "unset is false (parity)",
			want: false,
		},
		{
			name: "true is true",
			env:  map[string]string{"REQUIRE_EMAIL_VERIFICATION": "true"},
			want: true,
		},
		{
			name: "TRUE with whitespace is true",
			env:  map[string]string{"REQUIRE_EMAIL_VERIFICATION": "  TRUE  "},
			want: true,
		},
		{
			name: "false is false",
			env:  map[string]string{"REQUIRE_EMAIL_VERIFICATION": "false"},
			want: false,
		},
		{
			name: "empty is false",
			env:  map[string]string{"REQUIRE_EMAIL_VERIFICATION": ""},
			want: false,
		},
		{
			name:    "unreadable is a startup failure",
			env:     map[string]string{"REQUIRE_EMAIL_VERIFICATION": "please"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Load(lookupFrom(withSignupKey(tt.env)))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Load() = nil error, want a startup failure naming %s", RequireEmailVerificationVar)
				}
				if !strings.Contains(err.Error(), RequireEmailVerificationVar) {
					t.Errorf("Load() error = %v, want it to name %s", err, RequireEmailVerificationVar)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() unexpected error: %v", err)
			}
			if got.RequireEmailVerification != tt.want {
				t.Errorf("RequireEmailVerification = %v, want %v", got.RequireEmailVerification, tt.want)
			}
		})
	}
}

func TestRateLimitBlockDefaultsAndOverrides(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		env  map[string]string
		want RateLimit
	}{
		{
			name: "unset gets every default",
			want: RateLimit{
				Window:          time.Minute,
				Signup:          10,
				Signin:          20,
				SignupTimestamp: 30,
				Recovery:        5,
				AgentRegister:   5,
			},
		},
		{
			name: "the window overrides for every route at once",
			env:  map[string]string{"RATE_LIMIT_WINDOW": "5m"},
			want: RateLimit{
				Window:          5 * time.Minute,
				Signup:          10,
				Signin:          20,
				SignupTimestamp: 30,
				Recovery:        5,
				AgentRegister:   5,
			},
		},
		{
			name: "each route overrides its own limit",
			env: map[string]string{
				"RATE_LIMIT_SIGNUP":           "50",
				"RATE_LIMIT_SIGNIN":           "100",
				"RATE_LIMIT_SIGNUP_TIMESTAMP": "200",
				"RATE_LIMIT_AGENT_REGISTER":   "40",
				"RATE_LIMIT_RECOVERY":         "25",
			},
			want: RateLimit{
				Window:          time.Minute,
				Signup:          50,
				Signin:          100,
				SignupTimestamp: 200,
				Recovery:        25,
				AgentRegister:   40,
			},
		},
		{
			name: "one route tuned leaves the rest at their defaults",
			env:  map[string]string{"RATE_LIMIT_RECOVERY": "1"},
			want: RateLimit{
				Window:          time.Minute,
				Signup:          10,
				Signin:          20,
				SignupTimestamp: 30,
				Recovery:        1,
				AgentRegister:   5,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Load(lookupFrom(withSignupKey(tt.env)))
			if err != nil {
				t.Fatalf("Load() unexpected error: %v", err)
			}
			if got.RateLimit != tt.want {
				t.Errorf("RateLimit = %+v, want %+v", got.RateLimit, tt.want)
			}
		})
	}
}

func TestRateLimitZeroOrUnparseableIsAStartupError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		env  map[string]string
	}{
		{
			name: "a count of zero is refused, not read as unlimited",
			env:  map[string]string{"RATE_LIMIT_SIGNIN": "0"},
		},
		{
			name: "a negative count is refused",
			env:  map[string]string{"RATE_LIMIT_SIGNUP": "-5"},
		},
		{
			name: "an unparseable count is refused",
			env:  map[string]string{"RATE_LIMIT_RECOVERY": "ten"},
		},
		{
			name: "a zero window is refused",
			env:  map[string]string{"RATE_LIMIT_WINDOW": "0s"},
		},
		{
			name: "a negative window is refused",
			env:  map[string]string{"RATE_LIMIT_WINDOW": "-1m"},
		},
		{
			name: "an unparseable window is refused",
			env:  map[string]string{"RATE_LIMIT_WINDOW": "one minute"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := Load(lookupFrom(withSignupKey(tt.env)))
			if !errors.Is(err, ErrInvalidRateLimit) {
				t.Fatalf("Load() error = %v, want errors.Is(_, %v)", err, ErrInvalidRateLimit)
			}
			for variable := range tt.env {
				if !strings.Contains(err.Error(), variable) {
					t.Errorf("Load() error = %v, want it to name %s", err, variable)
				}
			}
		})
	}
}
